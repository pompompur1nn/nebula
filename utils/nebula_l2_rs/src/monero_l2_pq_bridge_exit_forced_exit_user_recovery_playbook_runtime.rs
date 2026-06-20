use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::{
        ReleaseReadinessDimension, ReleaseReadinessStatus, State as ReleaseReadinessState,
    },
    monero_l2_pq_bridge_exit_release_remediation_planner_runtime::{
        RemediationActionKind, RemediationPlanStatus, State as RemediationPlannerState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitForcedExitUserRecoveryPlaybookRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FORCED_EXIT_USER_RECOVERY_PLAYBOOK_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-forced-exit-user-recovery-playbook-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FORCED_EXIT_USER_RECOVERY_PLAYBOOK_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FORCED_EXIT_USER_RECOVERY_PLAYBOOK_SUITE: &str =
    "monero-l2-pq-bridge-exit-forced-exit-user-recovery-playbook-v1";
pub const DEFAULT_MIN_PLAYBOOK_STEPS: u64 = 5;
pub const DEFAULT_MIN_WALLET_SCAN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    SequencerUnavailable,
    WatcherUnavailable,
    SequencerWatcherUnavailable,
    RemediationBlocked,
}

impl FailureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerUnavailable => "sequencer_unavailable",
            Self::WatcherUnavailable => "watcher_unavailable",
            Self::SequencerWatcherUnavailable => "sequencer_watcher_unavailable",
            Self::RemediationBlocked => "remediation_blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookStepKind {
    Evidence,
    Preconditions,
    OperatorActions,
    WalletScanning,
    SettlementReceipts,
}

impl PlaybookStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Preconditions => "preconditions",
            Self::OperatorActions => "operator_actions",
            Self::WalletScanning => "wallet_scanning",
            Self::SettlementReceipts => "settlement_receipts",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookStepStatus {
    Ready,
    WaitingOnOperator,
    WaitingOnWallet,
    WaitingOnSettlement,
    Blocked,
}

impl PlaybookStepStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::WaitingOnOperator => "waiting_on_operator",
            Self::WaitingOnWallet => "waiting_on_wallet",
            Self::WaitingOnSettlement => "waiting_on_settlement",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookStatus {
    ReadyForUser,
    OperatorActionRequired,
    WalletScanRequired,
    SettlementPending,
    Blocked,
}

impl PlaybookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForUser => "ready_for_user",
            Self::OperatorActionRequired => "operator_action_required",
            Self::WalletScanRequired => "wallet_scan_required",
            Self::SettlementPending => "settlement_pending",
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
    pub playbook_suite: String,
    pub min_playbook_steps: u64,
    pub min_wallet_scan_confirmations: u64,
    pub require_readiness_alignment: bool,
    pub require_remediation_alignment: bool,
    pub publish_user_copy: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            playbook_suite: FORCED_EXIT_USER_RECOVERY_PLAYBOOK_SUITE.to_string(),
            min_playbook_steps: DEFAULT_MIN_PLAYBOOK_STEPS,
            min_wallet_scan_confirmations: DEFAULT_MIN_WALLET_SCAN_CONFIRMATIONS,
            require_readiness_alignment: true,
            require_remediation_alignment: true,
            publish_user_copy: true,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "playbook_suite": self.playbook_suite,
            "min_playbook_steps": self.min_playbook_steps,
            "min_wallet_scan_confirmations": self.min_wallet_scan_confirmations,
            "require_readiness_alignment": self.require_readiness_alignment,
            "require_remediation_alignment": self.require_remediation_alignment,
            "publish_user_copy": self.publish_user_copy,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryStep {
    pub step_id: String,
    pub kind: PlaybookStepKind,
    pub status: PlaybookStepStatus,
    pub title: String,
    pub user_instruction: String,
    pub operator_instruction: String,
    pub evidence_required: String,
    pub acceptance_criteria: String,
    pub source_root: String,
    pub action_root: String,
    pub step_root: String,
    pub blocks_user_recovery: bool,
}

impl RecoveryStep {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: PlaybookStepKind,
        status: PlaybookStepStatus,
        title: impl Into<String>,
        user_instruction: impl Into<String>,
        operator_instruction: impl Into<String>,
        evidence_required: impl Into<String>,
        acceptance_criteria: impl Into<String>,
        source_root: impl Into<String>,
        blocks_user_recovery: bool,
    ) -> Self {
        let title = title.into();
        let user_instruction = user_instruction.into();
        let operator_instruction = operator_instruction.into();
        let evidence_required = evidence_required.into();
        let acceptance_criteria = acceptance_criteria.into();
        let source_root = source_root.into();
        let action_root = recovery_action_root(
            kind,
            status,
            &operator_instruction,
            &evidence_required,
            &acceptance_criteria,
            &source_root,
        );
        let step_root = recovery_step_root(
            kind,
            status,
            &title,
            &user_instruction,
            &action_root,
            blocks_user_recovery,
        );
        let step_id = recovery_step_id(kind, &step_root);
        Self {
            step_id,
            kind,
            status,
            title,
            user_instruction,
            operator_instruction,
            evidence_required,
            acceptance_criteria,
            source_root,
            action_root,
            step_root,
            blocks_user_recovery,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "title": self.title,
            "user_instruction": self.user_instruction,
            "operator_instruction": self.operator_instruction,
            "evidence_required": self.evidence_required,
            "acceptance_criteria": self.acceptance_criteria,
            "source_root": self.source_root,
            "action_root": self.action_root,
            "step_root": self.step_root,
            "blocks_user_recovery": self.blocks_user_recovery,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("recovery_step", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletScanPlan {
    pub scan_id: String,
    pub wallet_label: String,
    pub start_height: u64,
    pub finality_height: u64,
    pub min_confirmations: u64,
    pub view_tag_root: String,
    pub output_note_root: String,
    pub key_image_root: String,
    pub scan_root: String,
}

impl WalletScanPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_label: impl Into<String>,
        start_height: u64,
        finality_height: u64,
        min_confirmations: u64,
        view_tag_root: impl Into<String>,
        output_note_root: impl Into<String>,
        key_image_root: impl Into<String>,
    ) -> Self {
        let wallet_label = wallet_label.into();
        let view_tag_root = view_tag_root.into();
        let output_note_root = output_note_root.into();
        let key_image_root = key_image_root.into();
        let scan_root = wallet_scan_root(
            &wallet_label,
            start_height,
            finality_height,
            min_confirmations,
            &view_tag_root,
            &output_note_root,
            &key_image_root,
        );
        let scan_id = wallet_scan_id(&wallet_label, &scan_root);
        Self {
            scan_id,
            wallet_label,
            start_height,
            finality_height,
            min_confirmations,
            view_tag_root,
            output_note_root,
            key_image_root,
            scan_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scan_id": self.scan_id,
            "wallet_label": self.wallet_label,
            "start_height": self.start_height,
            "finality_height": self.finality_height,
            "min_confirmations": self.min_confirmations,
            "view_tag_root": self.view_tag_root,
            "output_note_root": self.output_note_root,
            "key_image_root": self.key_image_root,
            "scan_root": self.scan_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet_scan_plan", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceiptChecklist {
    pub checklist_id: String,
    pub release_claim_id: String,
    pub custody_receipt_root: String,
    pub exit_claim_receipt_root: String,
    pub wallet_scan_root: String,
    pub settlement_receipt_root: String,
    pub receipt_count: u64,
    pub checklist_root: String,
}

impl SettlementReceiptChecklist {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        release_claim_id: impl Into<String>,
        custody_receipt_root: impl Into<String>,
        exit_claim_receipt_root: impl Into<String>,
        wallet_scan_root: impl Into<String>,
        settlement_receipt_root: impl Into<String>,
        receipt_count: u64,
    ) -> Self {
        let release_claim_id = release_claim_id.into();
        let custody_receipt_root = custody_receipt_root.into();
        let exit_claim_receipt_root = exit_claim_receipt_root.into();
        let wallet_scan_root = wallet_scan_root.into();
        let settlement_receipt_root = settlement_receipt_root.into();
        let checklist_root = settlement_checklist_root(
            &release_claim_id,
            &custody_receipt_root,
            &exit_claim_receipt_root,
            &wallet_scan_root,
            &settlement_receipt_root,
            receipt_count,
        );
        let checklist_id = settlement_checklist_id(&release_claim_id, &checklist_root);
        Self {
            checklist_id,
            release_claim_id,
            custody_receipt_root,
            exit_claim_receipt_root,
            wallet_scan_root,
            settlement_receipt_root,
            receipt_count,
            checklist_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "checklist_id": self.checklist_id,
            "release_claim_id": self.release_claim_id,
            "custody_receipt_root": self.custody_receipt_root,
            "exit_claim_receipt_root": self.exit_claim_receipt_root,
            "wallet_scan_root": self.wallet_scan_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "receipt_count": self.receipt_count,
            "checklist_root": self.checklist_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("settlement_receipt_checklist", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryPlaybookRoots {
    pub readiness_root: String,
    pub remediation_root: String,
    pub evidence_root: String,
    pub precondition_root: String,
    pub operator_action_root: String,
    pub wallet_scan_root: String,
    pub settlement_receipt_root: String,
    pub step_root: String,
    pub playbook_root: String,
}

impl RecoveryPlaybookRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "readiness_root": self.readiness_root,
            "remediation_root": self.remediation_root,
            "evidence_root": self.evidence_root,
            "precondition_root": self.precondition_root,
            "operator_action_root": self.operator_action_root,
            "wallet_scan_root": self.wallet_scan_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "step_root": self.step_root,
            "playbook_root": self.playbook_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("recovery_playbook_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitRecoveryPlaybook {
    pub playbook_id: String,
    pub status: PlaybookStatus,
    pub failure_mode: FailureMode,
    pub release_claim_id: String,
    pub readiness_receipt_id: String,
    pub remediation_plan_id: String,
    pub user_summary: String,
    pub readiness_status: ReleaseReadinessStatus,
    pub remediation_status: RemediationPlanStatus,
    pub steps_total: u64,
    pub steps_ready: u64,
    pub steps_blocked: u64,
    pub operator_actions: u64,
    pub wallet_scan_actions: u64,
    pub settlement_receipts_required: u64,
    pub steps: BTreeMap<String, RecoveryStep>,
    pub wallet_scan: WalletScanPlan,
    pub settlement_checklist: SettlementReceiptChecklist,
    pub roots: RecoveryPlaybookRoots,
}

impl ForcedExitRecoveryPlaybook {
    pub fn public_record(&self) -> Value {
        json!({
            "playbook_id": self.playbook_id,
            "status": self.status.as_str(),
            "failure_mode": self.failure_mode.as_str(),
            "release_claim_id": self.release_claim_id,
            "readiness_receipt_id": self.readiness_receipt_id,
            "remediation_plan_id": self.remediation_plan_id,
            "user_summary": self.user_summary,
            "readiness_status": self.readiness_status.as_str(),
            "remediation_status": self.remediation_status.as_str(),
            "steps_total": self.steps_total,
            "steps_ready": self.steps_ready,
            "steps_blocked": self.steps_blocked,
            "operator_actions": self.operator_actions,
            "wallet_scan_actions": self.wallet_scan_actions,
            "settlement_receipts_required": self.settlement_receipts_required,
            "steps": self.steps.values().map(RecoveryStep::public_record).collect::<Vec<_>>(),
            "wallet_scan": self.wallet_scan.public_record(),
            "settlement_checklist": self.settlement_checklist.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.playbook_root.clone()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub playbooks_run: u64,
    pub playbooks_ready: u64,
    pub playbooks_operator_action_required: u64,
    pub playbooks_wallet_scan_required: u64,
    pub playbooks_settlement_pending: u64,
    pub playbooks_blocked: u64,
    pub steps_total: u64,
    pub steps_blocked: u64,
    pub operator_actions: u64,
    pub wallet_scan_actions: u64,
    pub settlement_receipts_required: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "playbooks_run": self.playbooks_run,
            "playbooks_ready": self.playbooks_ready,
            "playbooks_operator_action_required": self.playbooks_operator_action_required,
            "playbooks_wallet_scan_required": self.playbooks_wallet_scan_required,
            "playbooks_settlement_pending": self.playbooks_settlement_pending,
            "playbooks_blocked": self.playbooks_blocked,
            "steps_total": self.steps_total,
            "steps_blocked": self.steps_blocked,
            "operator_actions": self.operator_actions,
            "wallet_scan_actions": self.wallet_scan_actions,
            "settlement_receipts_required": self.settlement_receipts_required,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub playbook_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            playbook_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-PLAYBOOKS",
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
            "playbook_root": self.playbook_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.playbook_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_playbook: Option<ForcedExitRecoveryPlaybook>,
    pub playbook_history: Vec<ForcedExitRecoveryPlaybook>,
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
            latest_playbook: None,
            playbook_history: Vec::new(),
            counters,
            roots,
        };
        let readiness =
            crate::monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::devnet();
        let planner = crate::monero_l2_pq_bridge_exit_release_remediation_planner_runtime::devnet();
        let _ = state.build_user_recovery_playbook(&readiness, &planner);
        state
    }

    pub fn build_user_recovery_playbook(
        &mut self,
        readiness: &ReleaseReadinessState,
        planner: &RemediationPlannerState,
    ) -> Result<String> {
        let readiness_receipt = readiness
            .latest_receipt
            .as_ref()
            .ok_or_else(|| "release readiness integrator has no latest receipt".to_string())?;
        let remediation_plan = planner
            .latest_plan
            .as_ref()
            .ok_or_else(|| "release remediation planner has no latest plan".to_string())?;
        ensure(
            !self.config.require_readiness_alignment
                || readiness_receipt
                    .items
                    .values()
                    .any(|item| item.dimension == ReleaseReadinessDimension::ForcedExitUserAnswer),
            "forced-exit recovery playbook missing readiness user-answer alignment",
        )?;
        ensure(
            !self.config.require_remediation_alignment
                || remediation_plan.actions.values().any(|action| {
                    action.kind == RemediationActionKind::ResolveForcedExitUserAnswer
                }),
            "forced-exit recovery playbook missing remediation user-answer alignment",
        )?;
        let failure_mode = failure_mode(
            readiness_receipt.items_blocked,
            remediation_plan.actions_blocked,
        );
        let status = playbook_status(remediation_plan.status, remediation_plan.actions_blocked);
        let steps = build_steps(
            status,
            failure_mode,
            &readiness.state_root(),
            &readiness_receipt.state_root(),
            &planner.state_root(),
            &remediation_plan.state_root(),
        );
        ensure(
            steps.len() as u64 >= self.config.min_playbook_steps,
            "forced-exit recovery playbook omitted required user steps",
        )?;
        let wallet_scan = WalletScanPlan::new(
            "user-forced-exit-wallet",
            1_920_000,
            1_920_000 + self.config.min_wallet_scan_confirmations,
            self.config.min_wallet_scan_confirmations,
            roots_by_kind(&steps, PlaybookStepKind::WalletScanning),
            readiness_receipt.roots.item_root.clone(),
            remediation_plan.roots.action_root.clone(),
        );
        let settlement_checklist = SettlementReceiptChecklist::new(
            readiness_receipt.release_claim_id.clone(),
            readiness_receipt.settlement_report_root.clone(),
            readiness_receipt.roots.blocker_root.clone(),
            wallet_scan.state_root(),
            remediation_plan.roots.priority_root.clone(),
            settlement_receipt_count(status),
        );
        let steps_total = steps.len() as u64;
        let steps_ready = steps
            .values()
            .filter(|step| step.status == PlaybookStepStatus::Ready)
            .count() as u64;
        let steps_blocked = steps
            .values()
            .filter(|step| step.status == PlaybookStepStatus::Blocked)
            .count() as u64;
        let operator_actions = steps
            .values()
            .filter(|step| step.kind == PlaybookStepKind::OperatorActions)
            .count() as u64;
        let wallet_scan_actions = steps
            .values()
            .filter(|step| step.kind == PlaybookStepKind::WalletScanning)
            .count() as u64;
        let settlement_receipts_required = settlement_checklist.receipt_count;
        let step_records = steps
            .values()
            .map(RecoveryStep::public_record)
            .collect::<Vec<_>>();
        let step_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-STEPS",
            &step_records,
        );
        let evidence_root = roots_by_kind(&steps, PlaybookStepKind::Evidence);
        let precondition_root = roots_by_kind(&steps, PlaybookStepKind::Preconditions);
        let operator_action_root = roots_by_kind(&steps, PlaybookStepKind::OperatorActions);
        let wallet_scan_root = wallet_scan.state_root();
        let settlement_receipt_root = settlement_checklist.state_root();
        let playbook_root = recovery_playbook_root(
            status,
            failure_mode,
            &readiness_receipt.release_claim_id,
            &readiness.state_root(),
            &planner.state_root(),
            &step_root,
            &wallet_scan_root,
            &settlement_receipt_root,
            steps_blocked,
        );
        let playbook_id = recovery_playbook_id(&readiness_receipt.release_claim_id, &playbook_root);
        let playbook = ForcedExitRecoveryPlaybook {
            playbook_id: playbook_id.clone(),
            status,
            failure_mode,
            release_claim_id: readiness_receipt.release_claim_id.clone(),
            readiness_receipt_id: readiness_receipt.receipt_id.clone(),
            remediation_plan_id: remediation_plan.plan_id.clone(),
            user_summary: user_summary(status, failure_mode).to_string(),
            readiness_status: readiness_receipt.status,
            remediation_status: remediation_plan.status,
            steps_total,
            steps_ready,
            steps_blocked,
            operator_actions,
            wallet_scan_actions,
            settlement_receipts_required,
            steps,
            wallet_scan,
            settlement_checklist,
            roots: RecoveryPlaybookRoots {
                readiness_root: readiness.state_root(),
                remediation_root: planner.state_root(),
                evidence_root,
                precondition_root,
                operator_action_root,
                wallet_scan_root,
                settlement_receipt_root,
                step_root,
                playbook_root,
            },
        };
        self.record_playbook(playbook);
        Ok(playbook_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "playbook_suite": self.config.playbook_suite,
            "latest_playbook": self.latest_playbook.as_ref().map(ForcedExitRecoveryPlaybook::public_record),
            "playbook_history_len": self.playbook_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_playbook(&mut self, playbook: ForcedExitRecoveryPlaybook) {
        self.counters.playbooks_run += 1;
        self.counters.steps_total += playbook.steps_total;
        self.counters.steps_blocked += playbook.steps_blocked;
        self.counters.operator_actions += playbook.operator_actions;
        self.counters.wallet_scan_actions += playbook.wallet_scan_actions;
        self.counters.settlement_receipts_required += playbook.settlement_receipts_required;
        match playbook.status {
            PlaybookStatus::ReadyForUser => self.counters.playbooks_ready += 1,
            PlaybookStatus::OperatorActionRequired => {
                self.counters.playbooks_operator_action_required += 1;
            }
            PlaybookStatus::WalletScanRequired => self.counters.playbooks_wallet_scan_required += 1,
            PlaybookStatus::SettlementPending => self.counters.playbooks_settlement_pending += 1,
            PlaybookStatus::Blocked => self.counters.playbooks_blocked += 1,
        }
        self.latest_playbook = Some(playbook.clone());
        self.playbook_history.push(playbook);
        if self.playbook_history.len() > self.config.max_reports {
            self.playbook_history.remove(0);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let playbook_records = self
            .playbook_history
            .iter()
            .map(ForcedExitRecoveryPlaybook::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            playbook_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-PLAYBOOKS",
                &playbook_records,
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

fn build_steps(
    status: PlaybookStatus,
    failure_mode: FailureMode,
    readiness_state_root: &str,
    readiness_receipt_root: &str,
    remediation_state_root: &str,
    remediation_plan_root: &str,
) -> BTreeMap<String, RecoveryStep> {
    let blocked = status == PlaybookStatus::Blocked;
    let mut steps = BTreeMap::new();
    for step in [
        RecoveryStep::new(
            PlaybookStepKind::Evidence,
            step_status(status, PlaybookStepKind::Evidence),
            "Collect bridge-exit evidence",
            user_evidence_instruction(failure_mode),
            "Publish the readiness receipt, remediation plan, exit claim, watcher quorum trace, and custody release roots.",
            "readiness receipt root, remediation plan root, exit claim id, watcher evidence root",
            "user can verify the release claim and failure mode without trusting a sequencer response",
            evidence_source_root(readiness_state_root, readiness_receipt_root),
            blocked,
        ),
        RecoveryStep::new(
            PlaybookStepKind::Preconditions,
            step_status(status, PlaybookStepKind::Preconditions),
            "Check forced-exit preconditions",
            "Confirm that the claim id matches the wallet, the dispute window has opened, and no duplicate settlement receipt exists.",
            "Freeze duplicate claim admission and mark the claim queue for forced-exit recovery handling.",
            "claim queue root, nullifier root, dispute window root",
            "only the intended claim remains recoverable and duplicate settlement is excluded",
            readiness_receipt_root,
            blocked,
        ),
        RecoveryStep::new(
            PlaybookStepKind::OperatorActions,
            step_status(status, PlaybookStepKind::OperatorActions),
            "Run operator recovery actions",
            "Wait for the operator-posted forced-exit bundle before rescanning wallet outputs.",
            "Post the forced-exit bundle, custody release proof, watcher absence evidence, and remediation acceptance record.",
            "operator bundle root, custody release root, watcher absence root, remediation acceptance root",
            "operator evidence is available before the user scans or submits final settlement receipts",
            remediation_source_root(remediation_state_root, remediation_plan_root),
            status == PlaybookStatus::OperatorActionRequired || blocked,
        ),
        RecoveryStep::new(
            PlaybookStepKind::WalletScanning,
            step_status(status, PlaybookStepKind::WalletScanning),
            "Rescan wallet recovery range",
            "Scan from the recovery start height through finality height, matching view tags, output notes, and key images for the claim.",
            "Keep wallet scan roots stable and expose only commitment roots needed for user confirmation.",
            "view tag root, output note root, key image root, scan finality height",
            "wallet finds the forced-exit output or proves it absent across the recovery range",
            wallet_source_root(readiness_receipt_root, remediation_plan_root),
            status == PlaybookStatus::WalletScanRequired || blocked,
        ),
        RecoveryStep::new(
            PlaybookStepKind::SettlementReceipts,
            step_status(status, PlaybookStepKind::SettlementReceipts),
            "Verify settlement receipts",
            "Retain custody, exit claim, wallet scan, and settlement receipt ids until the receipt root is final.",
            "Anchor final settlement receipt roots and reconcile them against the release claim queue.",
            "custody receipt root, exit claim receipt root, wallet scan root, final settlement receipt root",
            "user holds enough receipts to prove recovery or escalate a missing settlement",
            settlement_source_root(readiness_receipt_root, remediation_plan_root),
            status == PlaybookStatus::SettlementPending || blocked,
        ),
    ] {
        steps.insert(step.kind.as_str().to_string(), step);
    }
    steps
}

fn failure_mode(readiness_blockers: u64, remediation_blockers: u64) -> FailureMode {
    if remediation_blockers > 0 {
        FailureMode::RemediationBlocked
    } else if readiness_blockers > 1 {
        FailureMode::SequencerWatcherUnavailable
    } else if readiness_blockers == 1 {
        FailureMode::SequencerUnavailable
    } else {
        FailureMode::WatcherUnavailable
    }
}

fn playbook_status(
    remediation_status: RemediationPlanStatus,
    remediation_blockers: u64,
) -> PlaybookStatus {
    if remediation_status == RemediationPlanStatus::Blocked || remediation_blockers > 0 {
        PlaybookStatus::Blocked
    } else if remediation_status == RemediationPlanStatus::Active {
        PlaybookStatus::OperatorActionRequired
    } else {
        PlaybookStatus::WalletScanRequired
    }
}

fn step_status(status: PlaybookStatus, kind: PlaybookStepKind) -> PlaybookStepStatus {
    match (status, kind) {
        (PlaybookStatus::Blocked, _) => PlaybookStepStatus::Blocked,
        (PlaybookStatus::OperatorActionRequired, PlaybookStepKind::OperatorActions) => {
            PlaybookStepStatus::WaitingOnOperator
        }
        (PlaybookStatus::WalletScanRequired, PlaybookStepKind::WalletScanning) => {
            PlaybookStepStatus::WaitingOnWallet
        }
        (PlaybookStatus::SettlementPending, PlaybookStepKind::SettlementReceipts) => {
            PlaybookStepStatus::WaitingOnSettlement
        }
        _ => PlaybookStepStatus::Ready,
    }
}

fn user_summary(status: PlaybookStatus, failure_mode: FailureMode) -> &'static str {
    match (status, failure_mode) {
        (PlaybookStatus::Blocked, _) => {
            "Forced-exit recovery is blocked until remediation evidence is accepted."
        }
        (_, FailureMode::SequencerWatcherUnavailable) => {
            "Sequencer and watcher paths are unavailable; use the forced-exit evidence bundle and wallet scan receipts."
        }
        (_, FailureMode::SequencerUnavailable) => {
            "Sequencer path is unavailable; recover through claim evidence, operator bundle, wallet scan, and settlement receipts."
        }
        (_, FailureMode::WatcherUnavailable) => {
            "Watcher path is unavailable; verify custody release evidence before wallet scanning."
        }
        (_, FailureMode::RemediationBlocked) => {
            "Recovery depends on completing the forced-exit remediation action."
        }
    }
}

fn user_evidence_instruction(failure_mode: FailureMode) -> &'static str {
    match failure_mode {
        FailureMode::SequencerUnavailable => {
            "Save the release claim id, readiness receipt, and sequencer unavailability evidence root."
        }
        FailureMode::WatcherUnavailable => {
            "Save the release claim id, watcher absence evidence root, and custody release proof root."
        }
        FailureMode::SequencerWatcherUnavailable => {
            "Save both sequencer and watcher failure evidence roots before accepting operator instructions."
        }
        FailureMode::RemediationBlocked => {
            "Save the remediation blocker evidence root and wait for an accepted recovery action."
        }
    }
}

fn settlement_receipt_count(status: PlaybookStatus) -> u64 {
    match status {
        PlaybookStatus::Blocked => 0,
        PlaybookStatus::OperatorActionRequired => 2,
        PlaybookStatus::WalletScanRequired => 3,
        PlaybookStatus::SettlementPending => 4,
        PlaybookStatus::ReadyForUser => 4,
    }
}

fn roots_by_kind(steps: &BTreeMap<String, RecoveryStep>, kind: PlaybookStepKind) -> String {
    let records = steps
        .values()
        .filter(|step| step.kind == kind)
        .map(RecoveryStep::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-KIND",
        &records,
    )
}

pub fn recovery_action_root(
    kind: PlaybookStepKind,
    status: PlaybookStepStatus,
    operator_instruction: &str,
    evidence_required: &str,
    acceptance_criteria: &str,
    source_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-ACTION",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(operator_instruction),
            HashPart::Str(evidence_required),
            HashPart::Str(acceptance_criteria),
            HashPart::Str(source_root),
        ],
        32,
    )
}

pub fn recovery_step_root(
    kind: PlaybookStepKind,
    status: PlaybookStepStatus,
    title: &str,
    user_instruction: &str,
    action_root: &str,
    blocks_user_recovery: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-STEP",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(title),
            HashPart::Str(user_instruction),
            HashPart::Str(action_root),
            HashPart::Str(bool_str(blocks_user_recovery)),
        ],
        32,
    )
}

pub fn recovery_step_id(kind: PlaybookStepKind, step_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-STEP-ID",
        &[HashPart::Str(kind.as_str()), HashPart::Str(step_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn wallet_scan_root(
    wallet_label: &str,
    start_height: u64,
    finality_height: u64,
    min_confirmations: u64,
    view_tag_root: &str,
    output_note_root: &str,
    key_image_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-WALLET-SCAN",
        &[
            HashPart::Str(wallet_label),
            HashPart::U64(start_height),
            HashPart::U64(finality_height),
            HashPart::U64(min_confirmations),
            HashPart::Str(view_tag_root),
            HashPart::Str(output_note_root),
            HashPart::Str(key_image_root),
        ],
        32,
    )
}

pub fn wallet_scan_id(wallet_label: &str, scan_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-WALLET-SCAN-ID",
        &[HashPart::Str(wallet_label), HashPart::Str(scan_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn settlement_checklist_root(
    release_claim_id: &str,
    custody_receipt_root: &str,
    exit_claim_receipt_root: &str,
    wallet_scan_root: &str,
    settlement_receipt_root: &str,
    receipt_count: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-SETTLEMENT-CHECKLIST",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(custody_receipt_root),
            HashPart::Str(exit_claim_receipt_root),
            HashPart::Str(wallet_scan_root),
            HashPart::Str(settlement_receipt_root),
            HashPart::U64(receipt_count),
        ],
        32,
    )
}

pub fn settlement_checklist_id(release_claim_id: &str, checklist_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-SETTLEMENT-CHECKLIST-ID",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(checklist_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn recovery_playbook_root(
    status: PlaybookStatus,
    failure_mode: FailureMode,
    release_claim_id: &str,
    readiness_root: &str,
    remediation_root: &str,
    step_root: &str,
    wallet_scan_root: &str,
    settlement_receipt_root: &str,
    steps_blocked: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-PLAYBOOK",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(failure_mode.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(readiness_root),
            HashPart::Str(remediation_root),
            HashPart::Str(step_root),
            HashPart::Str(wallet_scan_root),
            HashPart::Str(settlement_receipt_root),
            HashPart::U64(steps_blocked),
        ],
        32,
    )
}

pub fn recovery_playbook_id(release_claim_id: &str, playbook_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-PLAYBOOK-ID",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(playbook_root),
        ],
        32,
    )
}

pub fn evidence_source_root(readiness_state_root: &str, readiness_receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-EVIDENCE-SOURCE",
        &[
            HashPart::Str(readiness_state_root),
            HashPart::Str(readiness_receipt_root),
        ],
        32,
    )
}

pub fn remediation_source_root(
    remediation_state_root: &str,
    remediation_plan_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-REMEDIATION-SOURCE",
        &[
            HashPart::Str(remediation_state_root),
            HashPart::Str(remediation_plan_root),
        ],
        32,
    )
}

pub fn wallet_source_root(readiness_receipt_root: &str, remediation_plan_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-WALLET-SOURCE",
        &[
            HashPart::Str(readiness_receipt_root),
            HashPart::Str(remediation_plan_root),
        ],
        32,
    )
}

pub fn settlement_source_root(readiness_receipt_root: &str, remediation_plan_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-SETTLEMENT-SOURCE",
        &[
            HashPart::Str(readiness_receipt_root),
            HashPart::Str(remediation_plan_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FORCED-EXIT-USER-RECOVERY-RECORD",
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
