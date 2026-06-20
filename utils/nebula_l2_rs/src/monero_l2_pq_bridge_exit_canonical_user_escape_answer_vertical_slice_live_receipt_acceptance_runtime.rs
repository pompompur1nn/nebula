use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_canonical_user_escape_answer_vertical_slice_live_evidence_replacement_runtime as live_replacement,
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceLiveReceiptAcceptanceRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_LIVE_RECEIPT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-live-receipt-acceptance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_LIVE_RECEIPT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LIVE_RECEIPT_ACCEPTANCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-live-receipt-acceptance-v1";
pub const DEFAULT_MIN_ACCEPTANCE_CASES: u64 = 9;
pub const DEFAULT_MIN_LIVE_ACCEPTED_CASES: u64 = 9;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub acceptance_suite: String,
    pub min_acceptance_cases: u64,
    pub min_live_accepted_cases: u64,
    pub require_wallet_visibility: bool,
    pub require_pq_authority: bool,
    pub require_privacy_boundary: bool,
    pub require_cargo_runtime_gate: bool,
    pub require_security_audit_gate: bool,
    pub fail_closed_on_missing_receipt: bool,
    pub hold_production_until_live_receipts: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            acceptance_suite: LIVE_RECEIPT_ACCEPTANCE_SUITE.to_string(),
            min_acceptance_cases: DEFAULT_MIN_ACCEPTANCE_CASES,
            min_live_accepted_cases: DEFAULT_MIN_LIVE_ACCEPTED_CASES,
            require_wallet_visibility: true,
            require_pq_authority: true,
            require_privacy_boundary: true,
            require_cargo_runtime_gate: true,
            require_security_audit_gate: true,
            fail_closed_on_missing_receipt: true,
            hold_production_until_live_receipts: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "acceptance_suite": self.acceptance_suite,
            "min_acceptance_cases": self.min_acceptance_cases,
            "min_live_accepted_cases": self.min_live_accepted_cases,
            "require_wallet_visibility": self.require_wallet_visibility,
            "require_pq_authority": self.require_pq_authority,
            "require_privacy_boundary": self.require_privacy_boundary,
            "require_cargo_runtime_gate": self.require_cargo_runtime_gate,
            "require_security_audit_gate": self.require_security_audit_gate,
            "fail_closed_on_missing_receipt": self.fail_closed_on_missing_receipt,
            "hold_production_until_live_receipts": self.hold_production_until_live_receipts,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveReceiptKind {
    MoneroHeaderCanonicality,
    DepositLockWatcher,
    PrivateNoteState,
    TransferOrContractExecution,
    SettlementReceiptExecutor,
    ReserveLiquidity,
    PqAuthorityQuorum,
    WalletScannerPrivacy,
    ReleaseBlockerClearing,
}

impl LiveReceiptKind {
    pub fn from_replacement(kind: live_replacement::ReplacementLaneKind) -> Self {
        match kind {
            live_replacement::ReplacementLaneKind::MoneroHeaderCanonicality => {
                Self::MoneroHeaderCanonicality
            }
            live_replacement::ReplacementLaneKind::DepositLockWatcher => Self::DepositLockWatcher,
            live_replacement::ReplacementLaneKind::PrivateNoteState => Self::PrivateNoteState,
            live_replacement::ReplacementLaneKind::TransferOrContractExecution => {
                Self::TransferOrContractExecution
            }
            live_replacement::ReplacementLaneKind::SettlementReceiptExecutor => {
                Self::SettlementReceiptExecutor
            }
            live_replacement::ReplacementLaneKind::ReserveLiquidity => Self::ReserveLiquidity,
            live_replacement::ReplacementLaneKind::PqAuthorityQuorum => Self::PqAuthorityQuorum,
            live_replacement::ReplacementLaneKind::WalletScannerPrivacy => {
                Self::WalletScannerPrivacy
            }
            live_replacement::ReplacementLaneKind::ReleaseBlockerClearing => {
                Self::ReleaseBlockerClearing
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroHeaderCanonicality => "monero_header_canonicality",
            Self::DepositLockWatcher => "deposit_lock_watcher",
            Self::PrivateNoteState => "private_note_state",
            Self::TransferOrContractExecution => "transfer_or_contract_execution",
            Self::SettlementReceiptExecutor => "settlement_receipt_executor",
            Self::ReserveLiquidity => "reserve_liquidity",
            Self::PqAuthorityQuorum => "pq_authority_quorum",
            Self::WalletScannerPrivacy => "wallet_scanner_privacy",
            Self::ReleaseBlockerClearing => "release_blocker_clearing",
        }
    }

    pub fn required_receipt(self) -> &'static str {
        match self {
            Self::MoneroHeaderCanonicality => {
                "canonical_monero_header_receipt_with_reorg_depth_and_finality_checkpoint"
            }
            Self::DepositLockWatcher => {
                "finalized_deposit_lock_receipt_with_watcher_quorum_and_amount_commitment"
            }
            Self::PrivateNoteState => {
                "private_note_state_receipt_with_encrypted_witness_and_wallet_commitment"
            }
            Self::TransferOrContractExecution => {
                "transfer_or_contract_execution_receipt_bound_to_private_state_transition"
            }
            Self::SettlementReceiptExecutor => {
                "settlement_execution_receipt_with_exit_claim_nullifier_and_batch_roots"
            }
            Self::ReserveLiquidity => {
                "reserve_liquidity_receipt_with_monero_reserve_and_l2_liability_roots"
            }
            Self::PqAuthorityQuorum => {
                "post_quantum_authority_receipt_with_watcher_bridge_upgrade_and_withdrawal_quorum"
            }
            Self::WalletScannerPrivacy => {
                "wallet_scanner_privacy_receipt_with_roots_only_note_discovery_and_no_metadata_leak"
            }
            Self::ReleaseBlockerClearing => {
                "release_blocker_clearing_receipt_with_user_release_first_and_production_hold_roots"
            }
        }
    }

    pub fn critical_for_user_escape(self) -> bool {
        matches!(
            self,
            Self::DepositLockWatcher
                | Self::PrivateNoteState
                | Self::SettlementReceiptExecutor
                | Self::ReserveLiquidity
                | Self::WalletScannerPrivacy
                | Self::ReleaseBlockerClearing
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveReceiptAcceptanceStatus {
    Accepted,
    DeferredUntilLiveReceipt,
    ProductionHold,
    FailClosed,
}

impl LiveReceiptAcceptanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::DeferredUntilLiveReceipt => "deferred_until_live_receipt",
            Self::ProductionHold => "production_hold",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceBundle {
    pub replacement_state_root: String,
    pub replacement_lane_root: String,
    pub live_evidence_root: String,
    pub replacement_fail_closed_root: String,
    pub replacement_production_hold_root: String,
    pub replacement_status: String,
    pub replacement_user_escape_answer: String,
    pub replacement_production_answer: String,
    pub replacement_lane_count: u64,
    pub ready_replacement_count: u64,
    pub deferred_replacement_count: u64,
    pub failed_closed_count: u64,
    pub replacement_user_release_blockers: u64,
    pub replacement_production_blockers: u64,
    pub live_feeds_connected: bool,
    pub cargo_checks_required: bool,
    pub runtime_tests_required: bool,
    pub security_audit_required: bool,
    pub replacement_production_blocked: bool,
}

impl SourceBundle {
    pub fn from_replacement(state: &live_replacement::State) -> Self {
        Self {
            replacement_state_root: state.state_root(),
            replacement_lane_root: state.replacement_lane_root.clone(),
            live_evidence_root: state.live_evidence_root.clone(),
            replacement_fail_closed_root: state.fail_closed_root.clone(),
            replacement_production_hold_root: state.production_hold_root.clone(),
            replacement_status: state.verdict.replacement_status.clone(),
            replacement_user_escape_answer: state.verdict.user_escape_answer.clone(),
            replacement_production_answer: state.verdict.production_answer.clone(),
            replacement_lane_count: state.verdict.replacement_lane_count,
            ready_replacement_count: state.verdict.ready_replacement_count,
            deferred_replacement_count: state.verdict.deferred_replacement_count,
            failed_closed_count: state.verdict.failed_closed_count,
            replacement_user_release_blockers: state.verdict.user_release_blocker_count,
            replacement_production_blockers: state.verdict.production_blocker_count,
            live_feeds_connected: state.verdict.live_feeds_connected,
            cargo_checks_required: state.verdict.cargo_checks_required,
            runtime_tests_required: state.verdict.runtime_tests_required,
            security_audit_required: state.verdict.security_audit_required,
            replacement_production_blocked: state.verdict.production_blocked,
        }
    }

    pub fn devnet() -> Self {
        let replacement = live_replacement::devnet();
        Self::from_replacement(&replacement)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "replacement_state_root": self.replacement_state_root,
            "replacement_lane_root": self.replacement_lane_root,
            "live_evidence_root": self.live_evidence_root,
            "replacement_fail_closed_root": self.replacement_fail_closed_root,
            "replacement_production_hold_root": self.replacement_production_hold_root,
            "replacement_status": self.replacement_status,
            "replacement_user_escape_answer": self.replacement_user_escape_answer,
            "replacement_production_answer": self.replacement_production_answer,
            "replacement_lane_count": self.replacement_lane_count,
            "ready_replacement_count": self.ready_replacement_count,
            "deferred_replacement_count": self.deferred_replacement_count,
            "failed_closed_count": self.failed_closed_count,
            "replacement_user_release_blockers": self.replacement_user_release_blockers,
            "replacement_production_blockers": self.replacement_production_blockers,
            "live_feeds_connected": self.live_feeds_connected,
            "cargo_checks_required": self.cargo_checks_required,
            "runtime_tests_required": self.runtime_tests_required,
            "security_audit_required": self.security_audit_required,
            "replacement_production_blocked": self.replacement_production_blocked,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("source-bundle", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveReceiptAcceptanceCase {
    pub case_id: String,
    pub ordinal: u64,
    pub receipt_kind: LiveReceiptKind,
    pub replacement_lane_id: String,
    pub replacement_status: String,
    pub replacement_root: String,
    pub expected_source_root: String,
    pub required_live_receipt_root: String,
    pub observed_live_receipt_root: String,
    pub wallet_visibility_root: String,
    pub pq_authority_root: String,
    pub privacy_boundary_root: String,
    pub cargo_runtime_gate_root: String,
    pub security_audit_gate_root: String,
    pub acceptance_root: String,
    pub release_hold_root: String,
    pub status: LiveReceiptAcceptanceStatus,
    pub user_escape_critical: bool,
    pub blocks_user_release: bool,
    pub blocks_production: bool,
    pub acceptance_condition: String,
    pub operator_action: String,
}

impl LiveReceiptAcceptanceCase {
    pub fn devnet(
        config: &Config,
        source: &SourceBundle,
        lane: &live_replacement::EvidenceReplacementLane,
    ) -> Self {
        let receipt_kind = LiveReceiptKind::from_replacement(lane.kind);
        let status = acceptance_status(config, source, lane);
        let expected_source_root = expected_source_root(source, lane);
        let required_live_receipt_root =
            required_live_receipt_root(config, source, lane, receipt_kind);
        let observed_live_receipt_root =
            observed_live_receipt_root(source, lane, status, &required_live_receipt_root);
        let wallet_visibility_root = wallet_visibility_root(config, source, lane, receipt_kind);
        let pq_authority_root = pq_authority_root(config, source, lane, receipt_kind);
        let privacy_boundary_root = privacy_boundary_root(config, source, lane, receipt_kind);
        let cargo_runtime_gate_root = cargo_runtime_gate_root(config, source, lane, receipt_kind);
        let security_audit_gate_root = security_audit_gate_root(config, source, lane, receipt_kind);
        let acceptance_root = acceptance_case_root(
            config,
            source,
            lane,
            receipt_kind,
            status,
            &expected_source_root,
            &required_live_receipt_root,
            &observed_live_receipt_root,
            &wallet_visibility_root,
            &pq_authority_root,
            &privacy_boundary_root,
            &cargo_runtime_gate_root,
            &security_audit_gate_root,
        );
        let user_escape_critical = receipt_kind.critical_for_user_escape();
        let blocks_user_release =
            lane.blocks_user_release || status == LiveReceiptAcceptanceStatus::FailClosed;
        let blocks_production =
            lane.blocks_production || status != LiveReceiptAcceptanceStatus::Accepted;
        let release_hold_root = release_hold_root(
            source,
            lane,
            status,
            &acceptance_root,
            blocks_user_release,
            blocks_production,
        );
        let case_id = case_id(receipt_kind, lane.ordinal, &acceptance_root);
        Self {
            case_id,
            ordinal: lane.ordinal,
            receipt_kind,
            replacement_lane_id: lane.lane_id.clone(),
            replacement_status: lane.status.as_str().to_string(),
            replacement_root: lane.replacement_root.clone(),
            expected_source_root,
            required_live_receipt_root,
            observed_live_receipt_root,
            wallet_visibility_root,
            pq_authority_root,
            privacy_boundary_root,
            cargo_runtime_gate_root,
            security_audit_gate_root,
            acceptance_root,
            release_hold_root,
            status,
            user_escape_critical,
            blocks_user_release,
            blocks_production,
            acceptance_condition: receipt_kind.required_receipt().to_string(),
            operator_action: operator_action(status, receipt_kind).to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "ordinal": self.ordinal,
            "receipt_kind": self.receipt_kind.as_str(),
            "replacement_lane_id": self.replacement_lane_id,
            "replacement_status": self.replacement_status,
            "replacement_root": self.replacement_root,
            "expected_source_root": self.expected_source_root,
            "required_live_receipt_root": self.required_live_receipt_root,
            "observed_live_receipt_root": self.observed_live_receipt_root,
            "wallet_visibility_root": self.wallet_visibility_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_boundary_root": self.privacy_boundary_root,
            "cargo_runtime_gate_root": self.cargo_runtime_gate_root,
            "security_audit_gate_root": self.security_audit_gate_root,
            "acceptance_root": self.acceptance_root,
            "release_hold_root": self.release_hold_root,
            "status": self.status.as_str(),
            "user_escape_critical": self.user_escape_critical,
            "blocks_user_release": self.blocks_user_release,
            "blocks_production": self.blocks_production,
            "acceptance_condition": self.acceptance_condition,
            "operator_action": self.operator_action,
        })
    }

    pub fn state_root(&self) -> String {
        self.acceptance_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveReceiptAcceptanceVerdict {
    pub acceptance_case_count: u64,
    pub accepted_case_count: u64,
    pub deferred_case_count: u64,
    pub production_hold_case_count: u64,
    pub fail_closed_case_count: u64,
    pub user_escape_critical_case_count: u64,
    pub user_release_blocker_count: u64,
    pub production_blocker_count: u64,
    pub replacement_lane_count: u64,
    pub replacement_deferred_count: u64,
    pub replacement_failed_closed_count: u64,
    pub cargo_checks_required: bool,
    pub runtime_tests_required: bool,
    pub security_audit_required: bool,
    pub wallet_visibility_present: bool,
    pub pq_authority_present: bool,
    pub privacy_boundary_present: bool,
    pub reserve_receipt_present: bool,
    pub settlement_receipt_present: bool,
    pub all_acceptance_cases_present: bool,
    pub live_receipts_sufficient: bool,
    pub user_escape_receipts_sufficient: bool,
    pub production_blocked: bool,
    pub acceptance_status: String,
    pub user_escape_answer: String,
    pub production_answer: String,
    pub verdict_root: String,
}

impl LiveReceiptAcceptanceVerdict {
    pub fn new(
        config: &Config,
        source: &SourceBundle,
        cases: &[LiveReceiptAcceptanceCase],
    ) -> Self {
        let acceptance_case_count = cases.len() as u64;
        let accepted_case_count = count_status(cases, LiveReceiptAcceptanceStatus::Accepted);
        let deferred_case_count =
            count_status(cases, LiveReceiptAcceptanceStatus::DeferredUntilLiveReceipt);
        let production_hold_case_count =
            count_status(cases, LiveReceiptAcceptanceStatus::ProductionHold);
        let fail_closed_case_count = count_status(cases, LiveReceiptAcceptanceStatus::FailClosed);
        let user_escape_critical_case_count = cases
            .iter()
            .filter(|case| case.user_escape_critical)
            .count() as u64;
        let user_release_blocker_count =
            cases.iter().filter(|case| case.blocks_user_release).count() as u64;
        let production_blocker_count =
            cases.iter().filter(|case| case.blocks_production).count() as u64;
        let replacement_lane_count = source.replacement_lane_count;
        let replacement_deferred_count = source.deferred_replacement_count;
        let replacement_failed_closed_count = source.failed_closed_count;
        let cargo_checks_required = source.cargo_checks_required;
        let runtime_tests_required = source.runtime_tests_required;
        let security_audit_required = source.security_audit_required;
        let wallet_visibility_present = has_receipt(cases, LiveReceiptKind::WalletScannerPrivacy);
        let pq_authority_present = has_receipt(cases, LiveReceiptKind::PqAuthorityQuorum);
        let privacy_boundary_present = cases
            .iter()
            .any(|case| !case.privacy_boundary_root.is_empty());
        let reserve_receipt_present = has_receipt(cases, LiveReceiptKind::ReserveLiquidity);
        let settlement_receipt_present =
            has_receipt(cases, LiveReceiptKind::SettlementReceiptExecutor);
        let all_acceptance_cases_present = acceptance_case_count >= config.min_acceptance_cases
            && acceptance_case_count == source.replacement_lane_count;
        let live_receipts_sufficient = accepted_case_count >= config.min_live_accepted_cases
            && deferred_case_count == 0
            && production_hold_case_count == 0
            && fail_closed_case_count == 0
            && source.live_feeds_connected;
        let user_escape_receipts_sufficient = all_acceptance_cases_present
            && user_release_blocker_count == 0
            && wallet_visibility_present
            && settlement_receipt_present
            && reserve_receipt_present
            && pq_authority_present;
        let production_blocked = source.replacement_production_blocked
            || production_blocker_count > 0
            || !live_receipts_sufficient
            || (config.require_cargo_runtime_gate && cargo_checks_required)
            || (config.require_security_audit_gate && security_audit_required);
        let acceptance_status = if fail_closed_case_count > 0 {
            "fail_closed"
        } else if production_hold_case_count > 0 {
            "production_hold"
        } else if deferred_case_count > 0 {
            "live_receipts_deferred"
        } else if live_receipts_sufficient {
            "live_receipts_accepted"
        } else {
            "incomplete"
        }
        .to_string();
        let user_escape_answer = if user_escape_receipts_sufficient {
            "user escape receipts are structurally specified; live execution remains required before treating the path as fully observed"
        } else {
            "user escape still needs live receipt acceptance for deposit lock, private note, settlement, reserve, PQ, wallet privacy, and release-blocker lanes"
        }
        .to_string();
        let production_answer = if production_blocked {
            "production release remains blocked until all live receipt acceptance cases are observed, cargo/runtime gates run, and security audits pass"
        } else {
            "bounded bridge/exit live receipts are accepted for production release review"
        }
        .to_string();
        let verdict_root = verdict_root(
            config,
            source,
            acceptance_case_count,
            accepted_case_count,
            deferred_case_count,
            production_hold_case_count,
            fail_closed_case_count,
            user_release_blocker_count,
            production_blocker_count,
            all_acceptance_cases_present,
            live_receipts_sufficient,
            user_escape_receipts_sufficient,
            production_blocked,
            &acceptance_status,
            &user_escape_answer,
            &production_answer,
        );
        Self {
            acceptance_case_count,
            accepted_case_count,
            deferred_case_count,
            production_hold_case_count,
            fail_closed_case_count,
            user_escape_critical_case_count,
            user_release_blocker_count,
            production_blocker_count,
            replacement_lane_count,
            replacement_deferred_count,
            replacement_failed_closed_count,
            cargo_checks_required,
            runtime_tests_required,
            security_audit_required,
            wallet_visibility_present,
            pq_authority_present,
            privacy_boundary_present,
            reserve_receipt_present,
            settlement_receipt_present,
            all_acceptance_cases_present,
            live_receipts_sufficient,
            user_escape_receipts_sufficient,
            production_blocked,
            acceptance_status,
            user_escape_answer,
            production_answer,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "acceptance_case_count": self.acceptance_case_count,
            "accepted_case_count": self.accepted_case_count,
            "deferred_case_count": self.deferred_case_count,
            "production_hold_case_count": self.production_hold_case_count,
            "fail_closed_case_count": self.fail_closed_case_count,
            "user_escape_critical_case_count": self.user_escape_critical_case_count,
            "user_release_blocker_count": self.user_release_blocker_count,
            "production_blocker_count": self.production_blocker_count,
            "replacement_lane_count": self.replacement_lane_count,
            "replacement_deferred_count": self.replacement_deferred_count,
            "replacement_failed_closed_count": self.replacement_failed_closed_count,
            "cargo_checks_required": self.cargo_checks_required,
            "runtime_tests_required": self.runtime_tests_required,
            "security_audit_required": self.security_audit_required,
            "wallet_visibility_present": self.wallet_visibility_present,
            "pq_authority_present": self.pq_authority_present,
            "privacy_boundary_present": self.privacy_boundary_present,
            "reserve_receipt_present": self.reserve_receipt_present,
            "settlement_receipt_present": self.settlement_receipt_present,
            "all_acceptance_cases_present": self.all_acceptance_cases_present,
            "live_receipts_sufficient": self.live_receipts_sufficient,
            "user_escape_receipts_sufficient": self.user_escape_receipts_sufficient,
            "production_blocked": self.production_blocked,
            "acceptance_status": self.acceptance_status,
            "user_escape_answer": self.user_escape_answer,
            "production_answer": self.production_answer,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub source: SourceBundle,
    pub acceptance_cases: Vec<LiveReceiptAcceptanceCase>,
    pub verdict: LiveReceiptAcceptanceVerdict,
    pub acceptance_case_root: String,
    pub observed_receipt_acceptance_root: String,
    pub user_escape_receipt_root: String,
    pub production_hold_root: String,
    pub state_commitment_root: String,
}

impl State {
    pub fn new(config: Config, replacement_state: live_replacement::State) -> Result<Self> {
        validate_config(&config)?;
        let source = SourceBundle::from_replacement(&replacement_state);
        validate_source(&source)?;
        let acceptance_cases = replacement_state
            .replacement_lanes
            .iter()
            .map(|lane| LiveReceiptAcceptanceCase::devnet(&config, &source, lane))
            .collect::<Vec<_>>();
        let verdict = LiveReceiptAcceptanceVerdict::new(&config, &source, &acceptance_cases);
        let acceptance_case_root = acceptance_case_vector_root(&acceptance_cases);
        let observed_receipt_acceptance_root =
            observed_receipt_acceptance_root(&config, &source, &acceptance_case_root, &verdict);
        let user_escape_receipt_root =
            user_escape_receipt_root(&config, &source, &acceptance_cases, &verdict);
        let production_hold_root =
            production_hold_root(&config, &source, &acceptance_cases, &verdict);
        let state_commitment_root = state_commitment_root(
            &config,
            &source,
            &acceptance_case_root,
            &observed_receipt_acceptance_root,
            &user_escape_receipt_root,
            &production_hold_root,
            &verdict,
        );
        Ok(Self {
            config,
            source,
            acceptance_cases,
            verdict,
            acceptance_case_root,
            observed_receipt_acceptance_root,
            user_escape_receipt_root,
            production_hold_root,
            state_commitment_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::default(), live_replacement::devnet()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_answer_vertical_slice_live_receipt_acceptance_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source": self.source.public_record(),
            "acceptance_case_root": self.acceptance_case_root,
            "observed_receipt_acceptance_root": self.observed_receipt_acceptance_root,
            "user_escape_receipt_root": self.user_escape_receipt_root,
            "production_hold_root": self.production_hold_root,
            "state_commitment_root": self.state_commitment_root,
            "verdict": self.verdict.public_record(),
            "acceptance_cases": self
                .acceptance_cases
                .iter()
                .map(LiveReceiptAcceptanceCase::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.state_commitment_root.clone()
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

fn acceptance_status(
    _config: &Config,
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
) -> LiveReceiptAcceptanceStatus {
    match lane.status {
        live_replacement::EvidenceReplacementStatus::FailedClosed => {
            LiveReceiptAcceptanceStatus::FailClosed
        }
        live_replacement::EvidenceReplacementStatus::ProductionHold => {
            LiveReceiptAcceptanceStatus::ProductionHold
        }
        live_replacement::EvidenceReplacementStatus::LiveReplacementReady => {
            if source.live_feeds_connected && !lane.blocks_production {
                LiveReceiptAcceptanceStatus::Accepted
            } else {
                LiveReceiptAcceptanceStatus::DeferredUntilLiveReceipt
            }
        }
        live_replacement::EvidenceReplacementStatus::LiveReplacementDeferred => {
            LiveReceiptAcceptanceStatus::DeferredUntilLiveReceipt
        }
    }
}

fn expected_source_root(
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-EXPECTED-SOURCE",
        &[
            HashPart::Str(&source.replacement_state_root),
            HashPart::Str(&lane.replacement_root),
            HashPart::Str(&lane.source_receipt_root),
            HashPart::Str(&lane.acceptance_root),
        ],
        32,
    )
}

fn required_live_receipt_root(
    config: &Config,
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
    receipt_kind: LiveReceiptKind,
) -> String {
    record_root(
        "required-live-receipt",
        &json!({
            "acceptance_suite": config.acceptance_suite,
            "receipt_kind": receipt_kind.as_str(),
            "required_receipt": receipt_kind.required_receipt(),
            "replacement_lane_id": lane.lane_id,
            "replacement_root": lane.replacement_root,
            "source_receipt_root": lane.source_receipt_root,
            "live_evidence_root": source.live_evidence_root,
            "wallet_visibility_required": config.require_wallet_visibility,
            "pq_authority_required": config.require_pq_authority,
            "privacy_boundary_required": config.require_privacy_boundary,
        }),
    )
}

fn observed_live_receipt_root(
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
    status: LiveReceiptAcceptanceStatus,
    required_live_receipt_root: &str,
) -> String {
    if status == LiveReceiptAcceptanceStatus::Accepted {
        required_live_receipt_root.to_string()
    } else {
        record_root(
            "deferred-observed-live-receipt",
            &json!({
                "replacement_lane_id": lane.lane_id,
                "replacement_root": lane.replacement_root,
                "status": status.as_str(),
                "live_evidence_root": source.live_evidence_root,
                "production_hold_root": source.replacement_production_hold_root,
                "reason": "live receipt not yet observed under deferred heavy-gate workflow",
            }),
        )
    }
}

fn wallet_visibility_root(
    config: &Config,
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
    receipt_kind: LiveReceiptKind,
) -> String {
    record_root(
        "wallet-visibility",
        &json!({
            "required": config.require_wallet_visibility,
            "receipt_kind": receipt_kind.as_str(),
            "replacement_lane_id": lane.lane_id,
            "wallet_related": receipt_kind.critical_for_user_escape(),
            "live_evidence_root": source.live_evidence_root,
            "expected_wallet_outcome": "wallet_can_scan_roots_without_metadata_leak",
        }),
    )
}

fn pq_authority_root(
    config: &Config,
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
    receipt_kind: LiveReceiptKind,
) -> String {
    record_root(
        "pq-authority",
        &json!({
            "required": config.require_pq_authority,
            "receipt_kind": receipt_kind.as_str(),
            "replacement_lane_id": lane.lane_id,
            "source_receipt_root": lane.source_receipt_root,
            "replacement_state_root": source.replacement_state_root,
            "authority_scope": "sequencer_watcher_bridge_upgrade_withdrawal",
        }),
    )
}

fn privacy_boundary_root(
    config: &Config,
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
    receipt_kind: LiveReceiptKind,
) -> String {
    record_root(
        "privacy-boundary",
        &json!({
            "required": config.require_privacy_boundary,
            "receipt_kind": receipt_kind.as_str(),
            "replacement_lane_id": lane.lane_id,
            "replacement_privacy_root": lane.privacy_root,
            "live_evidence_root": source.live_evidence_root,
            "metadata_policy": "roots_only_no_deposit_exit_linkage_export",
        }),
    )
}

fn cargo_runtime_gate_root(
    config: &Config,
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
    receipt_kind: LiveReceiptKind,
) -> String {
    record_root(
        "cargo-runtime-gate",
        &json!({
            "required": config.require_cargo_runtime_gate,
            "deferred": source.cargo_checks_required || source.runtime_tests_required,
            "receipt_kind": receipt_kind.as_str(),
            "replacement_lane_id": lane.lane_id,
            "replacement_state_root": source.replacement_state_root,
            "gate": "cargo_check_test_clippy_runtime_execution",
        }),
    )
}

fn security_audit_gate_root(
    config: &Config,
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
    receipt_kind: LiveReceiptKind,
) -> String {
    record_root(
        "security-audit-gate",
        &json!({
            "required": config.require_security_audit_gate,
            "deferred": source.security_audit_required,
            "receipt_kind": receipt_kind.as_str(),
            "replacement_lane_id": lane.lane_id,
            "replacement_production_hold_root": source.replacement_production_hold_root,
            "gate": "adversarial_security_privacy_review",
        }),
    )
}

fn acceptance_case_root(
    config: &Config,
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
    receipt_kind: LiveReceiptKind,
    status: LiveReceiptAcceptanceStatus,
    expected_source_root: &str,
    required_live_receipt_root: &str,
    observed_live_receipt_root: &str,
    wallet_visibility_root: &str,
    pq_authority_root: &str,
    privacy_boundary_root: &str,
    cargo_runtime_gate_root: &str,
    security_audit_gate_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-CASE",
        &[
            HashPart::Str(&config.acceptance_suite),
            HashPart::Str(&source.replacement_state_root),
            HashPart::Str(receipt_kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(&lane.lane_id),
            HashPart::Str(&lane.replacement_root),
            HashPart::Str(expected_source_root),
            HashPart::Str(required_live_receipt_root),
            HashPart::Str(observed_live_receipt_root),
            HashPart::Str(wallet_visibility_root),
            HashPart::Str(pq_authority_root),
            HashPart::Str(privacy_boundary_root),
            HashPart::Str(cargo_runtime_gate_root),
            HashPart::Str(security_audit_gate_root),
        ],
        32,
    )
}

fn release_hold_root(
    source: &SourceBundle,
    lane: &live_replacement::EvidenceReplacementLane,
    status: LiveReceiptAcceptanceStatus,
    acceptance_root: &str,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-RELEASE-HOLD",
        &[
            HashPart::Str(&source.replacement_production_hold_root),
            HashPart::Str(&lane.lane_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(acceptance_root),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

fn case_id(receipt_kind: LiveReceiptKind, ordinal: u64, acceptance_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-CASE-ID",
        &[
            HashPart::Str(receipt_kind.as_str()),
            HashPart::U64(ordinal),
            HashPart::Str(acceptance_root),
        ],
        16,
    )
}

fn operator_action(
    status: LiveReceiptAcceptanceStatus,
    receipt_kind: LiveReceiptKind,
) -> &'static str {
    match status {
        LiveReceiptAcceptanceStatus::Accepted => {
            "record observed live receipt as accepted for the bounded bridge/exit slice"
        }
        LiveReceiptAcceptanceStatus::DeferredUntilLiveReceipt => match receipt_kind {
            LiveReceiptKind::MoneroHeaderCanonicality => {
                "connect canonical Monero header receipt and replay finality checks"
            }
            LiveReceiptKind::DepositLockWatcher => {
                "connect finalized deposit lock watcher receipt before accepting user entry"
            }
            LiveReceiptKind::SettlementReceiptExecutor => {
                "connect settlement executor receipt before accepting withdrawal evidence"
            }
            LiveReceiptKind::WalletScannerPrivacy => {
                "connect wallet-visible roots-only scan receipt before claiming user escape readiness"
            }
            LiveReceiptKind::PqAuthorityQuorum => {
                "connect PQ authority receipt across watcher, bridge, upgrade, and withdrawal scopes"
            }
            _ => "replace deferred placeholder with observed live receipt and replay against replacement root",
        },
        LiveReceiptAcceptanceStatus::ProductionHold => {
            "keep production held and require blocker-clearing receipt before release review"
        }
        LiveReceiptAcceptanceStatus::FailClosed => {
            "fail closed, preserve wallet escape evidence, and repair missing live receipt source"
        }
    }
}

fn acceptance_case_vector_root(cases: &[LiveReceiptAcceptanceCase]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-CASES",
        &cases
            .iter()
            .map(LiveReceiptAcceptanceCase::public_record)
            .collect::<Vec<_>>(),
    )
}

fn observed_receipt_acceptance_root(
    config: &Config,
    source: &SourceBundle,
    acceptance_case_root: &str,
    verdict: &LiveReceiptAcceptanceVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-OBSERVED",
        &[
            HashPart::Str(&config.acceptance_suite),
            HashPart::Str(&source.live_evidence_root),
            HashPart::Str(acceptance_case_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.accepted_case_count),
            HashPart::U64(verdict.deferred_case_count),
        ],
        32,
    )
}

fn user_escape_receipt_root(
    config: &Config,
    source: &SourceBundle,
    cases: &[LiveReceiptAcceptanceCase],
    verdict: &LiveReceiptAcceptanceVerdict,
) -> String {
    let user_cases = cases
        .iter()
        .filter(|case| case.user_escape_critical)
        .map(|case| {
            json!({
                "case_id": case.case_id,
                "receipt_kind": case.receipt_kind.as_str(),
                "status": case.status.as_str(),
                "acceptance_root": case.acceptance_root,
                "blocks_user_release": case.blocks_user_release,
            })
        })
        .collect::<Vec<_>>();
    let user_case_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-USER-CASES",
        &user_cases,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-USER-ESCAPE",
        &[
            HashPart::Str(&config.acceptance_suite),
            HashPart::Str(&source.replacement_user_escape_answer),
            HashPart::Str(&user_case_root),
            HashPart::U64(verdict.user_release_blocker_count),
            HashPart::Str(bool_str(verdict.user_escape_receipts_sufficient)),
        ],
        32,
    )
}

fn production_hold_root(
    config: &Config,
    source: &SourceBundle,
    cases: &[LiveReceiptAcceptanceCase],
    verdict: &LiveReceiptAcceptanceVerdict,
) -> String {
    let blockers = cases
        .iter()
        .filter(|case| case.blocks_production)
        .map(|case| {
            json!({
                "case_id": case.case_id,
                "receipt_kind": case.receipt_kind.as_str(),
                "status": case.status.as_str(),
                "release_hold_root": case.release_hold_root,
                "operator_action": case.operator_action,
            })
        })
        .collect::<Vec<_>>();
    let blocker_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-PRODUCTION-BLOCKERS",
        &blockers,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-PRODUCTION-HOLD",
        &[
            HashPart::Str(&config.acceptance_suite),
            HashPart::Str(&source.replacement_production_hold_root),
            HashPart::Str(&blocker_root),
            HashPart::U64(verdict.production_blocker_count),
            HashPart::Str(bool_str(verdict.production_blocked)),
        ],
        32,
    )
}

fn state_commitment_root(
    config: &Config,
    source: &SourceBundle,
    acceptance_case_root: &str,
    observed_receipt_acceptance_root: &str,
    user_escape_receipt_root: &str,
    production_hold_root: &str,
    verdict: &LiveReceiptAcceptanceVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&source.state_root()),
            HashPart::Str(acceptance_case_root),
            HashPart::Str(observed_receipt_acceptance_root),
            HashPart::Str(user_escape_receipt_root),
            HashPart::Str(production_hold_root),
            HashPart::Str(&verdict.verdict_root),
        ],
        32,
    )
}

fn verdict_root(
    config: &Config,
    source: &SourceBundle,
    acceptance_case_count: u64,
    accepted_case_count: u64,
    deferred_case_count: u64,
    production_hold_case_count: u64,
    fail_closed_case_count: u64,
    user_release_blocker_count: u64,
    production_blocker_count: u64,
    all_acceptance_cases_present: bool,
    live_receipts_sufficient: bool,
    user_escape_receipts_sufficient: bool,
    production_blocked: bool,
    acceptance_status: &str,
    user_escape_answer: &str,
    production_answer: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-VERDICT",
        &[
            HashPart::Str(&config.acceptance_suite),
            HashPart::Str(&source.replacement_state_root),
            HashPart::Str(&source.live_evidence_root),
            HashPart::U64(acceptance_case_count),
            HashPart::U64(accepted_case_count),
            HashPart::U64(deferred_case_count),
            HashPart::U64(production_hold_case_count),
            HashPart::U64(fail_closed_case_count),
            HashPart::U64(user_release_blocker_count),
            HashPart::U64(production_blocker_count),
            HashPart::Str(bool_str(all_acceptance_cases_present)),
            HashPart::Str(bool_str(live_receipts_sufficient)),
            HashPart::Str(bool_str(user_escape_receipts_sufficient)),
            HashPart::Str(bool_str(production_blocked)),
            HashPart::Str(acceptance_status),
            HashPart::Str(user_escape_answer),
            HashPart::Str(production_answer),
        ],
        32,
    )
}

fn count_status(cases: &[LiveReceiptAcceptanceCase], status: LiveReceiptAcceptanceStatus) -> u64 {
    cases.iter().filter(|case| case.status == status).count() as u64
}

fn has_receipt(cases: &[LiveReceiptAcceptanceCase], kind: LiveReceiptKind) -> bool {
    cases.iter().any(|case| case.receipt_kind == kind)
}

fn validate_config(config: &Config) -> Result<()> {
    ensure(
        config.chain_id == CHAIN_ID,
        "live receipt acceptance chain mismatch",
    )?;
    ensure(
        config.protocol_version == PROTOCOL_VERSION,
        "live receipt acceptance protocol mismatch",
    )?;
    ensure(
        config.min_acceptance_cases > 0,
        "live receipt acceptance requires at least one case",
    )?;
    ensure(
        config.min_live_accepted_cases > 0,
        "live receipt acceptance requires accepted case threshold",
    )?;
    Ok(())
}

fn validate_source(source: &SourceBundle) -> Result<()> {
    ensure(
        !source.replacement_state_root.is_empty(),
        "live receipt acceptance missing replacement state root",
    )?;
    ensure(
        !source.live_evidence_root.is_empty(),
        "live receipt acceptance missing live evidence root",
    )?;
    ensure(
        source.replacement_lane_count > 0,
        "live receipt acceptance missing replacement lanes",
    )?;
    Ok(())
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let source = SourceBundle {
        replacement_state_root: record_root(
            "fallback-replacement-state",
            &json!({"reason": &reason}),
        ),
        replacement_lane_root: record_root(
            "fallback-replacement-lane",
            &json!({"reason": &reason}),
        ),
        live_evidence_root: record_root("fallback-live-evidence", &json!({"reason": &reason})),
        replacement_fail_closed_root: record_root(
            "fallback-fail-closed",
            &json!({"reason": &reason}),
        ),
        replacement_production_hold_root: record_root(
            "fallback-production-hold",
            &json!({"reason": &reason}),
        ),
        replacement_status: "fallback".to_string(),
        replacement_user_escape_answer: reason.clone(),
        replacement_production_answer: "fallback".to_string(),
        replacement_lane_count: 1,
        ready_replacement_count: 0,
        deferred_replacement_count: 0,
        failed_closed_count: 1,
        replacement_user_release_blockers: 1,
        replacement_production_blockers: 1,
        live_feeds_connected: false,
        cargo_checks_required: true,
        runtime_tests_required: true,
        security_audit_required: true,
        replacement_production_blocked: true,
    };
    let acceptance_root = record_root("fallback-acceptance", &json!({"reason": &reason}));
    let fallback_case = LiveReceiptAcceptanceCase {
        case_id: case_id(LiveReceiptKind::ReleaseBlockerClearing, 1, &acceptance_root),
        ordinal: 1,
        receipt_kind: LiveReceiptKind::ReleaseBlockerClearing,
        replacement_lane_id: "fallback".to_string(),
        replacement_status: "fallback".to_string(),
        replacement_root: source.replacement_lane_root.clone(),
        expected_source_root: source.replacement_state_root.clone(),
        required_live_receipt_root: source.live_evidence_root.clone(),
        observed_live_receipt_root: source.replacement_fail_closed_root.clone(),
        wallet_visibility_root: source.live_evidence_root.clone(),
        pq_authority_root: source.replacement_state_root.clone(),
        privacy_boundary_root: source.live_evidence_root.clone(),
        cargo_runtime_gate_root: source.replacement_state_root.clone(),
        security_audit_gate_root: source.replacement_production_hold_root.clone(),
        acceptance_root,
        release_hold_root: source.replacement_production_hold_root.clone(),
        status: LiveReceiptAcceptanceStatus::FailClosed,
        user_escape_critical: true,
        blocks_user_release: true,
        blocks_production: true,
        acceptance_condition: reason.clone(),
        operator_action: "fallback state keeps live receipt acceptance failed closed".to_string(),
    };
    let acceptance_cases = vec![fallback_case];
    let verdict = LiveReceiptAcceptanceVerdict::new(&config, &source, &acceptance_cases);
    let acceptance_case_root = acceptance_case_vector_root(&acceptance_cases);
    let observed_receipt_acceptance_root =
        observed_receipt_acceptance_root(&config, &source, &acceptance_case_root, &verdict);
    let user_escape_receipt_root =
        user_escape_receipt_root(&config, &source, &acceptance_cases, &verdict);
    let production_hold_root = production_hold_root(&config, &source, &acceptance_cases, &verdict);
    let state_commitment_root = state_commitment_root(
        &config,
        &source,
        &acceptance_case_root,
        &observed_receipt_acceptance_root,
        &user_escape_receipt_root,
        &production_hold_root,
        &verdict,
    );
    State {
        config,
        source,
        acceptance_cases,
        verdict,
        acceptance_case_root,
        observed_receipt_acceptance_root,
        user_escape_receipt_root,
        production_hold_root,
        state_commitment_root,
    }
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-RECEIPT-ACCEPTANCE-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
