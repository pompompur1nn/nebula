use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_forced_exit_user_recovery_playbook_runtime::{
        ForcedExitRecoveryPlaybook, State as ForcedExitRecoveryPlaybookState,
    },
    monero_l2_pq_bridge_exit_live_settlement_execution_contract_runtime::{
        LiveSettlementExecutionReport, State as LiveSettlementExecutionContractState,
    },
    monero_l2_pq_bridge_exit_pq_authority_verification_contract_runtime::{
        State as PqAuthorityVerificationContractState, VerificationContractReport,
    },
    monero_l2_pq_bridge_exit_release_blocker_clearinghouse_runtime::{
        ClearingBatch, State as ReleaseBlockerClearinghouseState,
    },
    monero_l2_pq_bridge_exit_release_remediation_fixture_manifest_runtime::{
        RemediationFixtureManifestReport, State as RemediationFixtureManifestState,
    },
    monero_l2_pq_bridge_exit_security_audit_signoff_manifest_runtime::{
        AuditSignoffManifest, State as SecurityAuditSignoffManifestState,
    },
    monero_l2_pq_bridge_exit_vertical_slice_scenario_runtime::{
        ScenarioTranscript, State as VerticalSliceScenarioState,
    },
    monero_l2_pq_bridge_exit_wallet_receipt_privacy_fixture_runtime::{
        State as WalletReceiptPrivacyFixtureState, WalletReceiptPrivacyFixtureReceipt,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitAdversarialVerticalSliceCorridorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_ADVERSARIAL_VERTICAL_SLICE_CORRIDOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-adversarial-vertical-slice-corridor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_ADVERSARIAL_VERTICAL_SLICE_CORRIDOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ADVERSARIAL_VERTICAL_SLICE_CORRIDOR_SUITE: &str =
    "monero-l2-pq-bridge-exit-adversarial-vertical-slice-corridor-v1";
pub const DEFAULT_MIN_CORRIDOR_SEGMENTS: u64 = 9;
pub const DEFAULT_MIN_PROVEN_CLAIMS: u64 = 7;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorridorSegmentKind {
    DepositAdmission,
    PrivateNoteTransition,
    RemediationFixtureContract,
    LiveSettlementExecution,
    PqAuthorityControlPlane,
    WalletReceiptPrivacy,
    ForcedExitUserRecovery,
    ReleaseBlockerClearing,
    SecurityPrivacySignoff,
}

impl CorridorSegmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositAdmission => "deposit_admission",
            Self::PrivateNoteTransition => "private_note_transition",
            Self::RemediationFixtureContract => "remediation_fixture_contract",
            Self::LiveSettlementExecution => "live_settlement_execution",
            Self::PqAuthorityControlPlane => "pq_authority_control_plane",
            Self::WalletReceiptPrivacy => "wallet_receipt_privacy",
            Self::ForcedExitUserRecovery => "forced_exit_user_recovery",
            Self::ReleaseBlockerClearing => "release_blocker_clearing",
            Self::SecurityPrivacySignoff => "security_privacy_signoff",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorridorSegmentStatus {
    Proven,
    Watch,
    Blocked,
}

impl CorridorSegmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorridorReportStatus {
    ReadyForExecution,
    Watch,
    Blocked,
}

impl CorridorReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForExecution => "ready_for_execution",
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
    pub corridor_suite: String,
    pub min_corridor_segments: u64,
    pub min_proven_claims: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub cargo_checks_deferred: bool,
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
            corridor_suite: ADVERSARIAL_VERTICAL_SLICE_CORRIDOR_SUITE.to_string(),
            min_corridor_segments: DEFAULT_MIN_CORRIDOR_SEGMENTS,
            min_proven_claims: DEFAULT_MIN_PROVEN_CLAIMS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            cargo_checks_deferred: true,
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
            "corridor_suite": self.corridor_suite,
            "min_corridor_segments": self.min_corridor_segments,
            "min_proven_claims": self.min_proven_claims,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CorridorSegment {
    pub segment_id: String,
    pub kind: CorridorSegmentKind,
    pub status: CorridorSegmentStatus,
    pub release_claim_id: String,
    pub requirement: String,
    pub observed: String,
    pub source_status: String,
    pub source_id: String,
    pub primary_root: String,
    pub evidence_root: String,
    pub public_commitment_root: String,
    pub private_commitment_root: String,
    pub blocks_user_exit: bool,
    pub blocks_production: bool,
    pub cargo_execution_required: bool,
    pub segment_root: String,
}

impl CorridorSegment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: CorridorSegmentKind,
        status: CorridorSegmentStatus,
        release_claim_id: impl Into<String>,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        source_status: impl Into<String>,
        source_id: impl Into<String>,
        primary_root: impl Into<String>,
        evidence_root: impl Into<String>,
        blocks_user_exit: bool,
        blocks_production: bool,
        cargo_execution_required: bool,
    ) -> Self {
        let release_claim_id = release_claim_id.into();
        let requirement = requirement.into();
        let observed = observed.into();
        let source_status = source_status.into();
        let source_id = source_id.into();
        let primary_root = primary_root.into();
        let evidence_root = evidence_root.into();
        let public_commitment_root = public_commitment_root(
            kind,
            status,
            &release_claim_id,
            &primary_root,
            &evidence_root,
            blocks_user_exit,
            blocks_production,
        );
        let private_commitment_root = private_commitment_root(
            kind,
            &release_claim_id,
            &requirement,
            &observed,
            cargo_execution_required,
        );
        let segment_root = corridor_segment_root(
            kind,
            status,
            &release_claim_id,
            &source_status,
            &source_id,
            &public_commitment_root,
            &private_commitment_root,
            blocks_user_exit,
            blocks_production,
        );
        let segment_id = corridor_segment_id(kind, &release_claim_id, &segment_root);
        Self {
            segment_id,
            kind,
            status,
            release_claim_id,
            requirement,
            observed,
            source_status,
            source_id,
            primary_root,
            evidence_root,
            public_commitment_root,
            private_commitment_root,
            blocks_user_exit,
            blocks_production,
            cargo_execution_required,
            segment_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "segment_id": self.segment_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "requirement": self.requirement,
            "observed": self.observed,
            "source_status": self.source_status,
            "source_id": self.source_id,
            "primary_root": self.primary_root,
            "evidence_root": self.evidence_root,
            "public_commitment_root": self.public_commitment_root,
            "private_commitment_root": self.private_commitment_root,
            "blocks_user_exit": self.blocks_user_exit,
            "blocks_production": self.blocks_production,
            "cargo_execution_required": self.cargo_execution_required,
            "segment_root": self.segment_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.segment_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CorridorReport {
    pub report_id: String,
    pub status: CorridorReportStatus,
    pub release_claim_id: String,
    pub scenario_id: String,
    pub scenario_status: String,
    pub readiness_label: String,
    pub vertical_slice_state_root: String,
    pub vertical_slice_transcript_root: String,
    pub initial_spine_root: String,
    pub final_spine_root: String,
    pub fixture_manifest_state_root: String,
    pub fixture_manifest_report_root: String,
    pub live_settlement_state_root: String,
    pub live_settlement_report_root: String,
    pub pq_verification_state_root: String,
    pub pq_verification_report_root: String,
    pub wallet_privacy_state_root: String,
    pub wallet_privacy_receipt_root: String,
    pub recovery_playbook_state_root: String,
    pub recovery_playbook_root: String,
    pub clearinghouse_state_root: String,
    pub clearing_batch_root: String,
    pub audit_signoff_state_root: String,
    pub audit_signoff_manifest_root: String,
    pub segments_total: u64,
    pub segments_proven: u64,
    pub segments_watch: u64,
    pub segments_blocked: u64,
    pub user_exit_blockers: u64,
    pub production_blockers: u64,
    pub cargo_execution_required: u64,
    pub proven_claims: u64,
    pub watch_claims: u64,
    pub failed_claims: u64,
    pub max_user_fee_bps_observed: u64,
    pub privacy_set_size_observed: u64,
    pub forced_exit_available_before_timeout: bool,
    pub forced_exit_available_after_timeout: bool,
    pub segments: BTreeMap<String, CorridorSegment>,
    pub roots: CorridorRoots,
}

impl CorridorReport {
    pub fn public_record(&self) -> Value {
        let segments = self
            .segments
            .values()
            .map(CorridorSegment::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "scenario_id": self.scenario_id,
            "scenario_status": self.scenario_status,
            "readiness_label": self.readiness_label,
            "vertical_slice_state_root": self.vertical_slice_state_root,
            "vertical_slice_transcript_root": self.vertical_slice_transcript_root,
            "initial_spine_root": self.initial_spine_root,
            "final_spine_root": self.final_spine_root,
            "fixture_manifest_state_root": self.fixture_manifest_state_root,
            "fixture_manifest_report_root": self.fixture_manifest_report_root,
            "live_settlement_state_root": self.live_settlement_state_root,
            "live_settlement_report_root": self.live_settlement_report_root,
            "pq_verification_state_root": self.pq_verification_state_root,
            "pq_verification_report_root": self.pq_verification_report_root,
            "wallet_privacy_state_root": self.wallet_privacy_state_root,
            "wallet_privacy_receipt_root": self.wallet_privacy_receipt_root,
            "recovery_playbook_state_root": self.recovery_playbook_state_root,
            "recovery_playbook_root": self.recovery_playbook_root,
            "clearinghouse_state_root": self.clearinghouse_state_root,
            "clearing_batch_root": self.clearing_batch_root,
            "audit_signoff_state_root": self.audit_signoff_state_root,
            "audit_signoff_manifest_root": self.audit_signoff_manifest_root,
            "segments_total": self.segments_total,
            "segments_proven": self.segments_proven,
            "segments_watch": self.segments_watch,
            "segments_blocked": self.segments_blocked,
            "user_exit_blockers": self.user_exit_blockers,
            "production_blockers": self.production_blockers,
            "cargo_execution_required": self.cargo_execution_required,
            "proven_claims": self.proven_claims,
            "watch_claims": self.watch_claims,
            "failed_claims": self.failed_claims,
            "max_user_fee_bps_observed": self.max_user_fee_bps_observed,
            "privacy_set_size_observed": self.privacy_set_size_observed,
            "forced_exit_available_before_timeout": self.forced_exit_available_before_timeout,
            "forced_exit_available_after_timeout": self.forced_exit_available_after_timeout,
            "segments": segments,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CorridorRoots {
    pub segment_root: String,
    pub requirement_root: String,
    pub source_root: String,
    pub blocker_root: String,
    pub report_root: String,
}

impl CorridorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "segment_root": self.segment_root,
            "requirement_root": self.requirement_root,
            "source_root": self.source_root,
            "blocker_root": self.blocker_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub reports_run: u64,
    pub reports_ready: u64,
    pub reports_watch: u64,
    pub reports_blocked: u64,
    pub segments_total: u64,
    pub segments_proven: u64,
    pub segments_watch: u64,
    pub segments_blocked: u64,
    pub user_exit_blockers: u64,
    pub production_blockers: u64,
    pub cargo_execution_required: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_ready": self.reports_ready,
            "reports_watch": self.reports_watch,
            "reports_blocked": self.reports_blocked,
            "segments_total": self.segments_total,
            "segments_proven": self.segments_proven,
            "segments_watch": self.segments_watch,
            "segments_blocked": self.segments_blocked,
            "user_exit_blockers": self.user_exit_blockers,
            "production_blockers": self.production_blockers,
            "cargo_execution_required": self.cargo_execution_required,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub report_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-EMPTY-REPORTS",
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
            "report_root": self.report_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.report_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_report: Option<CorridorReport>,
    pub report_history: Vec<CorridorReport>,
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
            latest_report: None,
            report_history: Vec::new(),
            counters,
            roots,
        };
        let vertical_slice =
            crate::monero_l2_pq_bridge_exit_vertical_slice_scenario_runtime::devnet();
        let fixture_manifest =
            crate::monero_l2_pq_bridge_exit_release_remediation_fixture_manifest_runtime::devnet();
        let live_settlement =
            crate::monero_l2_pq_bridge_exit_live_settlement_execution_contract_runtime::devnet();
        let pq_verification =
            crate::monero_l2_pq_bridge_exit_pq_authority_verification_contract_runtime::devnet();
        let wallet_privacy =
            crate::monero_l2_pq_bridge_exit_wallet_receipt_privacy_fixture_runtime::devnet();
        let recovery_playbook =
            crate::monero_l2_pq_bridge_exit_forced_exit_user_recovery_playbook_runtime::devnet();
        let clearinghouse =
            crate::monero_l2_pq_bridge_exit_release_blocker_clearinghouse_runtime::devnet();
        let audit_signoff =
            crate::monero_l2_pq_bridge_exit_security_audit_signoff_manifest_runtime::devnet();
        state
            .build_corridor_report(
                &vertical_slice,
                &fixture_manifest,
                &live_settlement,
                &pq_verification,
                &wallet_privacy,
                &recovery_playbook,
                &clearinghouse,
                &audit_signoff,
            )
            .expect("devnet adversarial bridge exit corridor");
        state
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_corridor_report(
        &mut self,
        vertical_slice: &VerticalSliceScenarioState,
        fixture_manifest: &RemediationFixtureManifestState,
        live_settlement: &LiveSettlementExecutionContractState,
        pq_verification: &PqAuthorityVerificationContractState,
        wallet_privacy: &WalletReceiptPrivacyFixtureState,
        recovery_playbook: &ForcedExitRecoveryPlaybookState,
        clearinghouse: &ReleaseBlockerClearinghouseState,
        audit_signoff: &SecurityAuditSignoffManifestState,
    ) -> Result<String> {
        let transcript = vertical_slice
            .transcripts
            .values()
            .next_back()
            .ok_or_else(|| "vertical slice scenario has no transcript".to_string())?;
        let fixture_report = fixture_manifest
            .latest_report
            .as_ref()
            .ok_or_else(|| "remediation fixture manifest has no latest report".to_string())?;
        let live_report = live_settlement
            .latest_report
            .as_ref()
            .ok_or_else(|| "live settlement execution contract has no latest report".to_string())?;
        let pq_report = pq_verification
            .latest_report
            .as_ref()
            .ok_or_else(|| "PQ verification contract has no latest report".to_string())?;
        let wallet_receipt = wallet_privacy
            .latest_receipt
            .as_ref()
            .ok_or_else(|| "wallet receipt privacy fixture has no latest receipt".to_string())?;
        let playbook = recovery_playbook
            .latest_playbook
            .as_ref()
            .ok_or_else(|| "forced-exit recovery playbook has no latest playbook".to_string())?;
        let clearing_batch = clearinghouse
            .latest_batch
            .as_ref()
            .ok_or_else(|| "release blocker clearinghouse has no latest batch".to_string())?;
        let audit_manifest = audit_signoff
            .latest_manifest
            .as_ref()
            .ok_or_else(|| "security audit signoff manifest has no latest manifest".to_string())?;
        let release_claim_id = fixture_report.release_claim_id.clone();
        ensure_release_claim(
            &release_claim_id,
            live_report,
            pq_report,
            wallet_receipt,
            playbook,
            clearing_batch,
            audit_manifest,
        )?;
        let segments = build_segments(
            &self.config,
            &release_claim_id,
            transcript,
            fixture_report,
            live_report,
            pq_report,
            wallet_receipt,
            playbook,
            clearing_batch,
            audit_manifest,
        );
        ensure(
            segments.len() as u64 >= self.config.min_corridor_segments,
            "adversarial corridor omitted required vertical-slice segments",
        )?;
        let segments_total = segments.len() as u64;
        let segments_proven = count_segments(&segments, CorridorSegmentStatus::Proven);
        let segments_watch = count_segments(&segments, CorridorSegmentStatus::Watch);
        let segments_blocked = count_segments(&segments, CorridorSegmentStatus::Blocked);
        let user_exit_blockers = segments
            .values()
            .filter(|segment| segment.blocks_user_exit)
            .count() as u64;
        let production_blockers = segments
            .values()
            .filter(|segment| segment.blocks_production)
            .count() as u64;
        let cargo_execution_required = segments
            .values()
            .filter(|segment| segment.cargo_execution_required)
            .count() as u64;
        let status = report_status(
            segments_blocked,
            segments_watch,
            user_exit_blockers,
            transcript.forced_exit_available_after_timeout,
        );
        let readiness_label = readiness_label(status, cargo_execution_required).to_string();
        let segment_records = segments
            .values()
            .map(CorridorSegment::public_record)
            .collect::<Vec<_>>();
        let segment_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-SEGMENTS",
            &segment_records,
        );
        let requirement_root = requirement_root(&segments);
        let source_root = source_root(
            &vertical_slice.state_root(),
            &transcript.state_root(),
            &fixture_manifest.state_root(),
            &fixture_report.state_root(),
            &live_settlement.state_root(),
            &live_report.state_root(),
            &pq_verification.state_root(),
            &pq_report.state_root(),
            &wallet_privacy.state_root(),
            &wallet_receipt.state_root(),
            &recovery_playbook.state_root(),
            &playbook.state_root(),
            &clearinghouse.state_root(),
            &clearing_batch.state_root(),
            &audit_signoff.state_root(),
            &audit_manifest.state_root(),
            &release_claim_id,
        );
        let blocker_root = blocker_root(&segments);
        let report_root = corridor_report_root(
            status,
            &readiness_label,
            &release_claim_id,
            &transcript.scenario_id,
            &segment_root,
            &requirement_root,
            &source_root,
            &blocker_root,
            segments_proven,
            segments_watch,
            segments_blocked,
            user_exit_blockers,
            production_blockers,
        );
        let report_id =
            corridor_report_id(&release_claim_id, &transcript.scenario_id, &report_root);
        let report = CorridorReport {
            report_id: report_id.clone(),
            status,
            release_claim_id,
            scenario_id: transcript.scenario_id.clone(),
            scenario_status: transcript.status.as_str().to_string(),
            readiness_label,
            vertical_slice_state_root: vertical_slice.state_root(),
            vertical_slice_transcript_root: transcript.state_root(),
            initial_spine_root: transcript.initial_spine_root.clone(),
            final_spine_root: transcript.final_spine_root.clone(),
            fixture_manifest_state_root: fixture_manifest.state_root(),
            fixture_manifest_report_root: fixture_report.state_root(),
            live_settlement_state_root: live_settlement.state_root(),
            live_settlement_report_root: live_report.state_root(),
            pq_verification_state_root: pq_verification.state_root(),
            pq_verification_report_root: pq_report.state_root(),
            wallet_privacy_state_root: wallet_privacy.state_root(),
            wallet_privacy_receipt_root: wallet_receipt.state_root(),
            recovery_playbook_state_root: recovery_playbook.state_root(),
            recovery_playbook_root: playbook.state_root(),
            clearinghouse_state_root: clearinghouse.state_root(),
            clearing_batch_root: clearing_batch.state_root(),
            audit_signoff_state_root: audit_signoff.state_root(),
            audit_signoff_manifest_root: audit_manifest.state_root(),
            segments_total,
            segments_proven,
            segments_watch,
            segments_blocked,
            user_exit_blockers,
            production_blockers,
            cargo_execution_required,
            proven_claims: transcript.proven_claim_count,
            watch_claims: transcript.watch_claim_count,
            failed_claims: transcript.failed_claim_count,
            max_user_fee_bps_observed: transcript.max_user_fee_bps_observed,
            privacy_set_size_observed: transcript.privacy_set_size_observed,
            forced_exit_available_before_timeout: transcript.forced_exit_available_before_timeout,
            forced_exit_available_after_timeout: transcript.forced_exit_available_after_timeout,
            segments,
            roots: CorridorRoots {
                segment_root,
                requirement_root,
                source_root,
                blocker_root,
                report_root,
            },
        };
        self.record_report(report);
        Ok(report_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "corridor_suite": self.config.corridor_suite,
            "latest_report": self.latest_report.as_ref().map(CorridorReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: CorridorReport) {
        self.counters.reports_run += 1;
        self.counters.segments_total += report.segments_total;
        self.counters.segments_proven += report.segments_proven;
        self.counters.segments_watch += report.segments_watch;
        self.counters.segments_blocked += report.segments_blocked;
        self.counters.user_exit_blockers += report.user_exit_blockers;
        self.counters.production_blockers += report.production_blockers;
        self.counters.cargo_execution_required += report.cargo_execution_required;
        match report.status {
            CorridorReportStatus::ReadyForExecution => self.counters.reports_ready += 1,
            CorridorReportStatus::Watch => self.counters.reports_watch += 1,
            CorridorReportStatus::Blocked => self.counters.reports_blocked += 1,
        }
        self.latest_report = Some(report.clone());
        self.report_history.push(report);
        if self.report_history.len() > self.config.max_reports {
            self.report_history.remove(0);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let report_records = self
            .report_history
            .iter()
            .map(CorridorReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

#[allow(clippy::too_many_arguments)]
fn ensure_release_claim(
    release_claim_id: &str,
    live_report: &LiveSettlementExecutionReport,
    pq_report: &VerificationContractReport,
    wallet_receipt: &WalletReceiptPrivacyFixtureReceipt,
    playbook: &ForcedExitRecoveryPlaybook,
    clearing_batch: &ClearingBatch,
    audit_manifest: &AuditSignoffManifest,
) -> Result<()> {
    for (label, observed) in [
        ("live settlement", live_report.release_claim_id.as_str()),
        ("PQ verification", pq_report.release_claim_id.as_str()),
        ("wallet privacy", wallet_receipt.release_claim_id.as_str()),
        ("recovery playbook", playbook.release_claim_id.as_str()),
        ("clearinghouse", clearing_batch.release_claim_id.as_str()),
        ("audit signoff", audit_manifest.release_claim_id.as_str()),
    ] {
        ensure(
            observed == release_claim_id,
            &format!("{label} release claim does not match adversarial corridor"),
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_segments(
    config: &Config,
    release_claim_id: &str,
    transcript: &ScenarioTranscript,
    fixture_report: &RemediationFixtureManifestReport,
    live_report: &LiveSettlementExecutionReport,
    pq_report: &VerificationContractReport,
    wallet_receipt: &WalletReceiptPrivacyFixtureReceipt,
    playbook: &ForcedExitRecoveryPlaybook,
    clearing_batch: &ClearingBatch,
    audit_manifest: &AuditSignoffManifest,
) -> BTreeMap<String, CorridorSegment> {
    let mut segments = BTreeMap::new();
    for segment in [
        deposit_admission_segment(config, release_claim_id, transcript),
        private_note_transition_segment(config, release_claim_id, transcript, wallet_receipt),
        remediation_fixture_segment(fixture_report),
        live_settlement_segment(live_report),
        pq_authority_segment(pq_report),
        wallet_privacy_segment(wallet_receipt),
        forced_exit_recovery_segment(playbook),
        release_clearing_segment(clearing_batch),
        security_signoff_segment(audit_manifest),
    ] {
        segments.insert(segment.segment_id.clone(), segment);
    }
    segments
}

fn deposit_admission_segment(
    config: &Config,
    release_claim_id: &str,
    transcript: &ScenarioTranscript,
) -> CorridorSegment {
    let fee_ok = transcript.max_user_fee_bps_observed <= config.max_user_fee_bps;
    let privacy_ok = transcript.privacy_set_size_observed >= config.min_privacy_set_size;
    let claims_ok = transcript.proven_claim_count >= config.min_proven_claims;
    let status = if fee_ok && privacy_ok && claims_ok {
        CorridorSegmentStatus::Proven
    } else {
        CorridorSegmentStatus::Watch
    };
    CorridorSegment::new(
        CorridorSegmentKind::DepositAdmission,
        status,
        release_claim_id,
        "Monero deposit must be admitted only after finality, watcher evidence, fee, and privacy-set gates",
        format!(
            "claims={} fee_bps={} privacy_set={} before_timeout={}",
            transcript.proven_claim_count,
            transcript.max_user_fee_bps_observed,
            transcript.privacy_set_size_observed,
            transcript.forced_exit_available_before_timeout
        ),
        transcript.status.as_str(),
        transcript.scenario_id.clone(),
        transcript.initial_spine_root.clone(),
        transcript.step_root.clone(),
        false,
        false,
        false,
    )
}

fn private_note_transition_segment(
    config: &Config,
    release_claim_id: &str,
    transcript: &ScenarioTranscript,
    wallet_receipt: &WalletReceiptPrivacyFixtureReceipt,
) -> CorridorSegment {
    let privacy_ok = transcript.privacy_set_size_observed >= config.min_privacy_set_size
        && wallet_receipt.fixtures_blocked == 0;
    let status = if privacy_ok && wallet_receipt.fixtures_ready > 0 {
        CorridorSegmentStatus::Proven
    } else if wallet_receipt.fixtures_blocked > 0 {
        CorridorSegmentStatus::Blocked
    } else {
        CorridorSegmentStatus::Watch
    };
    CorridorSegment::new(
        CorridorSegmentKind::PrivateNoteTransition,
        status,
        release_claim_id,
        "Private L2 note movement must preserve wallet scan continuity, bounded metadata, and forced-exit proof roots",
        format!(
            "wallet_fixtures={} ready={} blocked={} metadata_fields={} forced_exit_roots={}",
            wallet_receipt.fixtures_total,
            wallet_receipt.fixtures_ready,
            wallet_receipt.fixtures_blocked,
            wallet_receipt.metadata_fields_total,
            wallet_receipt.forced_exit_roots_total
        ),
        wallet_receipt.status.as_str(),
        wallet_receipt.receipt_id.clone(),
        wallet_receipt.roots.wallet_scan_root.clone(),
        transcript.claim_root.clone(),
        status == CorridorSegmentStatus::Blocked,
        false,
        false,
    )
}

fn remediation_fixture_segment(
    fixture_report: &RemediationFixtureManifestReport,
) -> CorridorSegment {
    let status = if fixture_report.contracts_blocked > 0 {
        CorridorSegmentStatus::Blocked
    } else if fixture_report.deferred_cargo_contracts > 0 || fixture_report.contracts_deferred > 0 {
        CorridorSegmentStatus::Watch
    } else {
        CorridorSegmentStatus::Proven
    };
    CorridorSegment::new(
        CorridorSegmentKind::RemediationFixtureContract,
        status,
        fixture_report.release_claim_id.clone(),
        "Remediation actions must be materialized as fixture, request, cargo-index, assertion, and manual-gate contracts",
        format!(
            "contracts={} ready={} deferred={} blocked={} manual={} cargo_deferred={}",
            fixture_report.contracts_total,
            fixture_report.contracts_ready,
            fixture_report.contracts_deferred,
            fixture_report.contracts_blocked,
            fixture_report.manual_contracts,
            fixture_report.deferred_cargo_contracts
        ),
        fixture_report.status.as_str(),
        fixture_report.report_id.clone(),
        fixture_report.roots.contract_root.clone(),
        fixture_report.roots.assertion_root.clone(),
        fixture_report.user_release_contracts > 0 && fixture_report.contracts_blocked > 0,
        fixture_report.production_contracts > 0,
        fixture_report.deferred_cargo_contracts > 0,
    )
}

fn live_settlement_segment(live_report: &LiveSettlementExecutionReport) -> CorridorSegment {
    let status = if live_report.contracts_held_readiness > 0
        || live_report.contracts_held_remediation > 0
        || live_report.contracts_cancelled > 0
    {
        CorridorSegmentStatus::Blocked
    } else if live_report.contracts_executable == 0 {
        CorridorSegmentStatus::Watch
    } else {
        CorridorSegmentStatus::Proven
    };
    CorridorSegment::new(
        CorridorSegmentKind::LiveSettlementExecution,
        status,
        live_report.release_claim_id.clone(),
        "Forced-exit settlement contracts must have executable payloads and receipt roots before live release",
        format!(
            "contracts={} executable={} readiness_holds={} remediation_holds={} payloads={}",
            live_report.contracts_total,
            live_report.contracts_executable,
            live_report.contracts_held_readiness,
            live_report.contracts_held_remediation,
            live_report.execution_payloads_ready
        ),
        live_report.status.as_str(),
        live_report.report_id.clone(),
        live_report.roots.payload_root.clone(),
        live_report.roots.receipt_root.clone(),
        status == CorridorSegmentStatus::Blocked,
        status != CorridorSegmentStatus::Proven,
        live_report.contracts_executable == 0,
    )
}

fn pq_authority_segment(pq_report: &VerificationContractReport) -> CorridorSegment {
    let failures = pq_report.signer_freshness_failures
        + pq_report.rotation_failures
        + pq_report.epoch_binding_failures
        + pq_report.withdrawal_authorization_failures;
    let status = if failures > 0 || pq_report.contracts_blocked > 0 {
        CorridorSegmentStatus::Blocked
    } else if pq_report.contracts_deferred > 0 || pq_report.contracts_enforced == 0 {
        CorridorSegmentStatus::Watch
    } else {
        CorridorSegmentStatus::Proven
    };
    CorridorSegment::new(
        CorridorSegmentKind::PqAuthorityControlPlane,
        status,
        pq_report.release_claim_id.clone(),
        "PQ signer freshness, rotation continuity, epoch binding, and withdrawal authorization must gate release",
        format!(
            "enforced={} deferred={} blocked={} signer_fail={} rotation_fail={} epoch_fail={} withdraw_fail={}",
            pq_report.contracts_enforced,
            pq_report.contracts_deferred,
            pq_report.contracts_blocked,
            pq_report.signer_freshness_failures,
            pq_report.rotation_failures,
            pq_report.epoch_binding_failures,
            pq_report.withdrawal_authorization_failures
        ),
        pq_report.status.as_str(),
        pq_report.report_id.clone(),
        pq_report.roots.control_plane_root.clone(),
        pq_report.roots.contract_root.clone(),
        pq_report.user_release_blocks > 0,
        pq_report.production_blocks > 0,
        pq_report.contracts_deferred > 0,
    )
}

fn wallet_privacy_segment(wallet_receipt: &WalletReceiptPrivacyFixtureReceipt) -> CorridorSegment {
    let status = if wallet_receipt.fixtures_blocked > 0 {
        CorridorSegmentStatus::Blocked
    } else if wallet_receipt.fixtures_watch > 0 {
        CorridorSegmentStatus::Watch
    } else {
        CorridorSegmentStatus::Proven
    };
    CorridorSegment::new(
        CorridorSegmentKind::WalletReceiptPrivacy,
        status,
        wallet_receipt.release_claim_id.clone(),
        "Wallet scanning must use committed hints, bounded metadata, and forced-exit roots without leaking receipt linkage",
        format!(
            "fixtures={} hints={} metadata_fields={} forced_exit_roots={}",
            wallet_receipt.fixtures_total,
            wallet_receipt.committed_hints_total,
            wallet_receipt.metadata_fields_total,
            wallet_receipt.forced_exit_roots_total
        ),
        wallet_receipt.status.as_str(),
        wallet_receipt.receipt_id.clone(),
        wallet_receipt.roots.committed_hint_root.clone(),
        wallet_receipt.roots.bounded_metadata_root.clone(),
        wallet_receipt.fixtures_blocked > 0,
        false,
        false,
    )
}

fn forced_exit_recovery_segment(playbook: &ForcedExitRecoveryPlaybook) -> CorridorSegment {
    let status = if playbook.steps_blocked > 0 {
        CorridorSegmentStatus::Blocked
    } else if playbook.operator_actions > 0
        || playbook.wallet_scan_actions > 0
        || playbook.settlement_receipts_required > 0
    {
        CorridorSegmentStatus::Watch
    } else {
        CorridorSegmentStatus::Proven
    };
    CorridorSegment::new(
        CorridorSegmentKind::ForcedExitUserRecovery,
        status,
        playbook.release_claim_id.clone(),
        "A user must have a concrete recovery playbook under sequencer or watcher failure",
        format!(
            "steps={} ready={} blocked={} operator_actions={} wallet_actions={} receipts_required={}",
            playbook.steps_total,
            playbook.steps_ready,
            playbook.steps_blocked,
            playbook.operator_actions,
            playbook.wallet_scan_actions,
            playbook.settlement_receipts_required
        ),
        playbook.status.as_str(),
        playbook.playbook_id.clone(),
        playbook.roots.playbook_root.clone(),
        playbook.roots.wallet_scan_root.clone(),
        playbook.steps_blocked > 0,
        false,
        playbook.settlement_receipts_required > 0,
    )
}

fn release_clearing_segment(clearing_batch: &ClearingBatch) -> CorridorSegment {
    let status = if clearing_batch.records_blocked > 0 {
        CorridorSegmentStatus::Blocked
    } else if clearing_batch.records_waiting > 0 || clearing_batch.records_ready > 0 {
        CorridorSegmentStatus::Watch
    } else {
        CorridorSegmentStatus::Proven
    };
    CorridorSegment::new(
        CorridorSegmentKind::ReleaseBlockerClearing,
        status,
        clearing_batch.release_claim_id.clone(),
        "Release blockers must have a deterministic clearing order across settlement, PQ, cargo, audit, privacy, and production lanes",
        format!(
            "records={} clear={} ready={} waiting={} blocked={} user_blockers={} production_blockers={}",
            clearing_batch.records_total,
            clearing_batch.records_clear,
            clearing_batch.records_ready,
            clearing_batch.records_waiting,
            clearing_batch.records_blocked,
            clearing_batch.user_release_blockers,
            clearing_batch.production_blockers
        ),
        clearing_batch.status.as_str(),
        clearing_batch.batch_id.clone(),
        clearing_batch.roots.clearing_order_root.clone(),
        clearing_batch.roots.committed_evidence_root.clone(),
        clearing_batch.user_release_blockers > 0,
        clearing_batch.production_blockers > 0,
        false,
    )
}

fn security_signoff_segment(audit_manifest: &AuditSignoffManifest) -> CorridorSegment {
    let status = if audit_manifest.signoffs_blocked > 0 || audit_manifest.release_blockers > 0 {
        CorridorSegmentStatus::Blocked
    } else if audit_manifest.signoffs_conditional > 0 || audit_manifest.manual_actions > 0 {
        CorridorSegmentStatus::Watch
    } else {
        CorridorSegmentStatus::Proven
    };
    CorridorSegment::new(
        CorridorSegmentKind::SecurityPrivacySignoff,
        status,
        audit_manifest.release_claim_id.clone(),
        "Security and privacy signoff must cover PQ, settlement, privacy, forced-exit, and production-release blockers",
        format!(
            "signoffs={} accepted={} conditional={} blocked={} release_blockers={} production_blockers={} manual={}",
            audit_manifest.signoffs_total,
            audit_manifest.signoffs_accepted,
            audit_manifest.signoffs_conditional,
            audit_manifest.signoffs_blocked,
            audit_manifest.release_blockers,
            audit_manifest.production_blockers,
            audit_manifest.manual_actions
        ),
        audit_manifest.status.as_str(),
        audit_manifest.manifest_id.clone(),
        audit_manifest.roots.signoff_root.clone(),
        audit_manifest.roots.blocker_root.clone(),
        audit_manifest.release_blockers > 0,
        audit_manifest.production_blockers > 0,
        audit_manifest.manual_actions > 0,
    )
}

fn report_status(
    segments_blocked: u64,
    segments_watch: u64,
    user_exit_blockers: u64,
    forced_exit_available_after_timeout: bool,
) -> CorridorReportStatus {
    if segments_blocked > 0 || user_exit_blockers > 0 || !forced_exit_available_after_timeout {
        CorridorReportStatus::Blocked
    } else if segments_watch > 0 {
        CorridorReportStatus::Watch
    } else {
        CorridorReportStatus::ReadyForExecution
    }
}

fn readiness_label(status: CorridorReportStatus, cargo_execution_required: u64) -> &'static str {
    match status {
        CorridorReportStatus::ReadyForExecution => "adversarial_corridor_ready_for_execution",
        CorridorReportStatus::Watch if cargo_execution_required > 0 => {
            "adversarial_corridor_waiting_on_runtime_execution"
        }
        CorridorReportStatus::Watch => "adversarial_corridor_watch",
        CorridorReportStatus::Blocked => "adversarial_corridor_blocked",
    }
}

fn count_segments(
    segments: &BTreeMap<String, CorridorSegment>,
    status: CorridorSegmentStatus,
) -> u64 {
    segments
        .values()
        .filter(|segment| segment.status == status)
        .count() as u64
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
pub fn public_commitment_root(
    kind: CorridorSegmentKind,
    status: CorridorSegmentStatus,
    release_claim_id: &str,
    primary_root: &str,
    evidence_root: &str,
    blocks_user_exit: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-PUBLIC-COMMITMENT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(primary_root),
            HashPart::Str(evidence_root),
            HashPart::Str(bool_str(blocks_user_exit)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

pub fn private_commitment_root(
    kind: CorridorSegmentKind,
    release_claim_id: &str,
    requirement: &str,
    observed: &str,
    cargo_execution_required: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-PRIVATE-COMMITMENT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(requirement),
            HashPart::Str(observed),
            HashPart::Str(bool_str(cargo_execution_required)),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn corridor_segment_root(
    kind: CorridorSegmentKind,
    status: CorridorSegmentStatus,
    release_claim_id: &str,
    source_status: &str,
    source_id: &str,
    public_commitment_root: &str,
    private_commitment_root: &str,
    blocks_user_exit: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-SEGMENT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(source_status),
            HashPart::Str(source_id),
            HashPart::Str(public_commitment_root),
            HashPart::Str(private_commitment_root),
            HashPart::Str(bool_str(blocks_user_exit)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

pub fn corridor_segment_id(
    kind: CorridorSegmentKind,
    release_claim_id: &str,
    segment_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-SEGMENT-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(segment_root),
        ],
        32,
    )
}

pub fn requirement_root(segments: &BTreeMap<String, CorridorSegment>) -> String {
    let records = segments
        .values()
        .map(|segment| {
            json!({
                "segment_id": segment.segment_id,
                "kind": segment.kind.as_str(),
                "requirement": segment.requirement,
                "observed": segment.observed,
                "cargo_execution_required": segment.cargo_execution_required,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-REQUIREMENTS",
        &records,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    vertical_slice_state_root: &str,
    vertical_slice_transcript_root: &str,
    fixture_manifest_state_root: &str,
    fixture_manifest_report_root: &str,
    live_settlement_state_root: &str,
    live_settlement_report_root: &str,
    pq_verification_state_root: &str,
    pq_verification_report_root: &str,
    wallet_privacy_state_root: &str,
    wallet_privacy_receipt_root: &str,
    recovery_playbook_state_root: &str,
    recovery_playbook_root: &str,
    clearinghouse_state_root: &str,
    clearing_batch_root: &str,
    audit_signoff_state_root: &str,
    audit_signoff_manifest_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-SOURCE",
        &[
            HashPart::Str(vertical_slice_state_root),
            HashPart::Str(vertical_slice_transcript_root),
            HashPart::Str(fixture_manifest_state_root),
            HashPart::Str(fixture_manifest_report_root),
            HashPart::Str(live_settlement_state_root),
            HashPart::Str(live_settlement_report_root),
            HashPart::Str(pq_verification_state_root),
            HashPart::Str(pq_verification_report_root),
            HashPart::Str(wallet_privacy_state_root),
            HashPart::Str(wallet_privacy_receipt_root),
            HashPart::Str(recovery_playbook_state_root),
            HashPart::Str(recovery_playbook_root),
            HashPart::Str(clearinghouse_state_root),
            HashPart::Str(clearing_batch_root),
            HashPart::Str(audit_signoff_state_root),
            HashPart::Str(audit_signoff_manifest_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn blocker_root(segments: &BTreeMap<String, CorridorSegment>) -> String {
    let records = segments
        .values()
        .filter(|segment| segment.blocks_user_exit || segment.blocks_production)
        .map(|segment| {
            json!({
                "segment_id": segment.segment_id,
                "kind": segment.kind.as_str(),
                "status": segment.status.as_str(),
                "blocks_user_exit": segment.blocks_user_exit,
                "blocks_production": segment.blocks_production,
                "primary_root": segment.primary_root,
                "evidence_root": segment.evidence_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-BLOCKERS",
        &records,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn corridor_report_root(
    status: CorridorReportStatus,
    readiness_label: &str,
    release_claim_id: &str,
    scenario_id: &str,
    segment_root: &str,
    requirement_root: &str,
    source_root: &str,
    blocker_root: &str,
    segments_proven: u64,
    segments_watch: u64,
    segments_blocked: u64,
    user_exit_blockers: u64,
    production_blockers: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-REPORT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(release_claim_id),
            HashPart::Str(scenario_id),
            HashPart::Str(segment_root),
            HashPart::Str(requirement_root),
            HashPart::Str(source_root),
            HashPart::Str(blocker_root),
            HashPart::U64(segments_proven),
            HashPart::U64(segments_watch),
            HashPart::U64(segments_blocked),
            HashPart::U64(user_exit_blockers),
            HashPart::U64(production_blockers),
        ],
        32,
    )
}

pub fn corridor_report_id(release_claim_id: &str, scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-REPORT-ID",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(scenario_id),
            HashPart::Str(report_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-ADVERSARIAL-CORRIDOR-RECORD",
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
