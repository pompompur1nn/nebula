use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_canonical_live_feed_stub_swap_plan_runtime as stub_swap,
    monero_l2_pq_bridge_exit_canonical_user_escape_answer_vertical_slice_replay_plan_execution_receipt_runtime as receipt_binding,
    monero_l2_pq_bridge_exit_release_blocker_clearinghouse_runtime as clearinghouse, CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceLiveEvidenceReplacementRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_LIVE_EVIDENCE_REPLACEMENT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-live-evidence-replacement-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_LIVE_EVIDENCE_REPLACEMENT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LIVE_EVIDENCE_REPLACEMENT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-live-evidence-replacement-v1";
pub const DEFAULT_MIN_REPLACEMENT_LANES: u64 = 9;
pub const DEFAULT_MIN_LIVE_FEED_LANES: u64 = 5;
pub const DEFAULT_MIN_RECEIPT_BOUND_LANES: u64 = 8;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub replacement_suite: String,
    pub min_replacement_lanes: u64,
    pub min_live_feed_lanes: u64,
    pub min_receipt_bound_lanes: u64,
    pub max_unresolved_release_blockers: u64,
    pub fail_closed_required: bool,
    pub privacy_redaction_required: bool,
    pub live_execution_required_for_production: bool,
    pub cargo_checks_required_for_production: bool,
    pub runtime_tests_required_for_production: bool,
    pub security_audit_required_for_production: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            replacement_suite: LIVE_EVIDENCE_REPLACEMENT_SUITE.to_string(),
            min_replacement_lanes: DEFAULT_MIN_REPLACEMENT_LANES,
            min_live_feed_lanes: DEFAULT_MIN_LIVE_FEED_LANES,
            min_receipt_bound_lanes: DEFAULT_MIN_RECEIPT_BOUND_LANES,
            max_unresolved_release_blockers: 0,
            fail_closed_required: true,
            privacy_redaction_required: true,
            live_execution_required_for_production: true,
            cargo_checks_required_for_production: true,
            runtime_tests_required_for_production: true,
            security_audit_required_for_production: true,
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
            "replacement_suite": self.replacement_suite,
            "min_replacement_lanes": self.min_replacement_lanes,
            "min_live_feed_lanes": self.min_live_feed_lanes,
            "min_receipt_bound_lanes": self.min_receipt_bound_lanes,
            "max_unresolved_release_blockers": self.max_unresolved_release_blockers,
            "fail_closed_required": self.fail_closed_required,
            "privacy_redaction_required": self.privacy_redaction_required,
            "live_execution_required_for_production": self.live_execution_required_for_production,
            "cargo_checks_required_for_production": self.cargo_checks_required_for_production,
            "runtime_tests_required_for_production": self.runtime_tests_required_for_production,
            "security_audit_required_for_production": self.security_audit_required_for_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplacementLaneKind {
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

impl ReplacementLaneKind {
    pub fn ordered() -> &'static [Self] {
        &[
            Self::MoneroHeaderCanonicality,
            Self::DepositLockWatcher,
            Self::PrivateNoteState,
            Self::TransferOrContractExecution,
            Self::SettlementReceiptExecutor,
            Self::ReserveLiquidity,
            Self::PqAuthorityQuorum,
            Self::WalletScannerPrivacy,
            Self::ReleaseBlockerClearing,
        ]
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

    pub fn source_domain(self) -> Option<stub_swap::FeedDomain> {
        match self {
            Self::MoneroHeaderCanonicality => Some(stub_swap::FeedDomain::MoneroHeader),
            Self::DepositLockWatcher => Some(stub_swap::FeedDomain::DepositLock),
            Self::SettlementReceiptExecutor => Some(stub_swap::FeedDomain::SettlementReceipt),
            Self::ReserveLiquidity => Some(stub_swap::FeedDomain::ReserveProof),
            Self::ReleaseBlockerClearing => Some(stub_swap::FeedDomain::ReorgNotice),
            Self::PrivateNoteState
            | Self::TransferOrContractExecution
            | Self::PqAuthorityQuorum
            | Self::WalletScannerPrivacy => None,
        }
    }

    pub fn evidence_contract(self) -> &'static str {
        match self {
            Self::MoneroHeaderCanonicality => {
                "live Monero header feed must prove canonical height, reorg depth, and finality checkpoint before replacing fixture header roots"
            }
            Self::DepositLockWatcher => {
                "deposit watcher feed must bind finalized lock txids, amount commitments, and watcher quorum roots to the replay receipt"
            }
            Self::PrivateNoteState => {
                "private state transition must replace fixture note roots with encrypted witness roots and wallet-scannable note commitments"
            }
            Self::TransferOrContractExecution => {
                "transfer or contract action must produce a bound execution receipt before exit evidence can rely on live state"
            }
            Self::SettlementReceiptExecutor => {
                "settlement executor must publish exit claim, nullifier, batch, and executor attestation roots accepted by the receipt binding"
            }
            Self::ReserveLiquidity => {
                "reserve adapter must prove Monero reserve, L2 liability, and liquidity release roots before production exit liquidity is trusted"
            }
            Self::PqAuthorityQuorum => {
                "post-quantum watcher and authority quorum attestations must cover bridge release, upgrades, and withdrawal authorization"
            }
            Self::WalletScannerPrivacy => {
                "wallet scanner path must keep metadata redacted while proving users can find notes, claims, and settlement receipts"
            }
            Self::ReleaseBlockerClearing => {
                "release blocker clearinghouse must clear user-facing blockers first and keep production held until all evidence is green"
            }
        }
    }

    pub fn user_critical(self) -> bool {
        matches!(
            self,
            Self::DepositLockWatcher
                | Self::PrivateNoteState
                | Self::SettlementReceiptExecutor
                | Self::ReserveLiquidity
                | Self::ReleaseBlockerClearing
        )
    }

    pub fn production_critical(self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceReplacementStatus {
    LiveReplacementReady,
    LiveReplacementDeferred,
    ProductionHold,
    FailedClosed,
}

impl EvidenceReplacementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveReplacementReady => "live_replacement_ready",
            Self::LiveReplacementDeferred => "live_replacement_deferred",
            Self::ProductionHold => "production_hold",
            Self::FailedClosed => "failed_closed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceBundle {
    pub receipt_execution_root: String,
    pub observed_receipt_root: String,
    pub wallet_receipt_root: String,
    pub production_hold_root: String,
    pub receipt_status: String,
    pub receipt_user_escape_answer: String,
    pub receipt_production_answer: String,
    pub receipt_lane_count: u64,
    pub receipt_bound_lane_count: u64,
    pub receipt_release_blocker_count: u64,
    pub receipt_heavy_gate_deferred_count: u64,
    pub receipt_cargo_deferred_count: u64,
    pub receipt_audit_deferred_count: u64,
    pub stub_handoff_root: String,
    pub stub_lane_root: String,
    pub live_lane_root: String,
    pub freshness_sla_root: String,
    pub replay_compatibility_root: String,
    pub privacy_redaction_root: String,
    pub fail_closed_root: String,
    pub stub_readiness_status: String,
    pub live_feed_execution_enabled: bool,
    pub stub_lane_count: u64,
    pub live_lane_count: u64,
    pub clearinghouse_state_root: String,
    pub clearinghouse_batch_root: String,
    pub clearinghouse_status: String,
    pub clearinghouse_records_total: u64,
    pub clearinghouse_records_blocked: u64,
    pub clearinghouse_user_release_blockers: u64,
    pub clearinghouse_production_blockers: u64,
}

impl SourceBundle {
    pub fn devnet() -> Self {
        let receipt = receipt_binding::devnet();
        let stub = stub_swap::devnet();
        let clearing = clearinghouse::devnet();
        let latest_batch = clearing.latest_batch.as_ref();
        Self {
            receipt_execution_root: receipt.execution_receipt_binding_root.clone(),
            observed_receipt_root: receipt.observed_receipt_root.clone(),
            wallet_receipt_root: receipt.wallet_receipt_root.clone(),
            production_hold_root: receipt.production_hold_root.clone(),
            receipt_status: receipt.verdict.receipt_status.clone(),
            receipt_user_escape_answer: receipt.verdict.user_escape_answer.clone(),
            receipt_production_answer: receipt.verdict.production_answer.clone(),
            receipt_lane_count: receipt.verdict.receipt_lane_count,
            receipt_bound_lane_count: receipt.verdict.expected_bound_count,
            receipt_release_blocker_count: receipt.verdict.release_blocker_count,
            receipt_heavy_gate_deferred_count: receipt.verdict.heavy_gate_deferred_count,
            receipt_cargo_deferred_count: receipt.verdict.cargo_deferred_count,
            receipt_audit_deferred_count: receipt.verdict.audit_deferred_count,
            stub_handoff_root: stub.handoff_plan.handoff_root.clone(),
            stub_lane_root: stub.handoff_plan.stub_lane_root.clone(),
            live_lane_root: stub.handoff_plan.live_lane_root.clone(),
            freshness_sla_root: stub.handoff_plan.freshness_sla_root.clone(),
            replay_compatibility_root: stub.handoff_plan.replay_compatibility_root.clone(),
            privacy_redaction_root: stub.handoff_plan.privacy_redaction_root.clone(),
            fail_closed_root: stub.handoff_plan.fail_closed_root.clone(),
            stub_readiness_status: stub.handoff_plan.readiness_status.as_str().to_string(),
            live_feed_execution_enabled: stub.config.live_feed_execution_enabled,
            stub_lane_count: stub.stub_lanes.len() as u64,
            live_lane_count: stub.live_lanes.len() as u64,
            clearinghouse_state_root: clearing.state_root(),
            clearinghouse_batch_root: latest_batch
                .map(|batch| batch.roots.batch_root.clone())
                .unwrap_or_else(|| record_root("missing-clearing-batch", &json!({}))),
            clearinghouse_status: latest_batch
                .map(|batch| batch.status.as_str().to_string())
                .unwrap_or_else(|| "missing".to_string()),
            clearinghouse_records_total: latest_batch
                .map(|batch| batch.records_total)
                .unwrap_or_default(),
            clearinghouse_records_blocked: latest_batch
                .map(|batch| batch.records_blocked)
                .unwrap_or_default(),
            clearinghouse_user_release_blockers: latest_batch
                .map(|batch| batch.user_release_blockers)
                .unwrap_or_default(),
            clearinghouse_production_blockers: latest_batch
                .map(|batch| batch.production_blockers)
                .unwrap_or_default(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_execution_root": self.receipt_execution_root,
            "observed_receipt_root": self.observed_receipt_root,
            "wallet_receipt_root": self.wallet_receipt_root,
            "production_hold_root": self.production_hold_root,
            "receipt_status": self.receipt_status,
            "receipt_user_escape_answer": self.receipt_user_escape_answer,
            "receipt_production_answer": self.receipt_production_answer,
            "receipt_lane_count": self.receipt_lane_count,
            "receipt_bound_lane_count": self.receipt_bound_lane_count,
            "receipt_release_blocker_count": self.receipt_release_blocker_count,
            "receipt_heavy_gate_deferred_count": self.receipt_heavy_gate_deferred_count,
            "receipt_cargo_deferred_count": self.receipt_cargo_deferred_count,
            "receipt_audit_deferred_count": self.receipt_audit_deferred_count,
            "stub_handoff_root": self.stub_handoff_root,
            "stub_lane_root": self.stub_lane_root,
            "live_lane_root": self.live_lane_root,
            "freshness_sla_root": self.freshness_sla_root,
            "replay_compatibility_root": self.replay_compatibility_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "fail_closed_root": self.fail_closed_root,
            "stub_readiness_status": self.stub_readiness_status,
            "live_feed_execution_enabled": self.live_feed_execution_enabled,
            "stub_lane_count": self.stub_lane_count,
            "live_lane_count": self.live_lane_count,
            "clearinghouse_state_root": self.clearinghouse_state_root,
            "clearinghouse_batch_root": self.clearinghouse_batch_root,
            "clearinghouse_status": self.clearinghouse_status,
            "clearinghouse_records_total": self.clearinghouse_records_total,
            "clearinghouse_records_blocked": self.clearinghouse_records_blocked,
            "clearinghouse_user_release_blockers": self.clearinghouse_user_release_blockers,
            "clearinghouse_production_blockers": self.clearinghouse_production_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("source-bundle", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceReplacementLane {
    pub lane_id: String,
    pub ordinal: u64,
    pub kind: ReplacementLaneKind,
    pub source_domain: String,
    pub source_stub_lane_id: String,
    pub source_live_lane_id: String,
    pub source_fixture_root: String,
    pub source_live_feed_root: String,
    pub required_payload_root: String,
    pub source_receipt_root: String,
    pub acceptance_root: String,
    pub replacement_root: String,
    pub freshness_root: String,
    pub privacy_root: String,
    pub fail_closed_root: String,
    pub status: EvidenceReplacementStatus,
    pub blocks_user_release: bool,
    pub blocks_production: bool,
    pub operator_action: String,
    pub evidence_contract: String,
}

impl EvidenceReplacementLane {
    pub fn devnet(
        config: &Config,
        source: &SourceBundle,
        stub: &stub_swap::State,
        kind: ReplacementLaneKind,
        ordinal: u64,
    ) -> Self {
        let domain = kind.source_domain();
        let stub_lane = domain.and_then(|value| select_stub_lane(stub, value));
        let live_lane = domain.and_then(|value| select_live_lane(stub, value));
        let source_domain = domain
            .map(stub_swap::FeedDomain::as_str)
            .unwrap_or("vertical_slice_receipt")
            .to_string();
        let source_stub_lane_id = stub_lane
            .map(|lane| lane.lane_id.clone())
            .unwrap_or_else(|| synthetic_lane_id(kind, "receipt-stub"));
        let source_live_lane_id = live_lane
            .map(|lane| lane.lane_id.clone())
            .unwrap_or_else(|| synthetic_lane_id(kind, "receipt-live"));
        let source_fixture_root = stub_lane
            .map(|lane| lane.fixture_root.clone())
            .unwrap_or_else(|| synthetic_fixture_root(kind, source));
        let source_live_feed_root = live_lane
            .map(|lane| lane.live_feed_root.clone())
            .unwrap_or_else(|| synthetic_live_feed_root(kind, source));
        let required_payload_root = live_lane
            .map(|lane| lane.required_payload_root.clone())
            .unwrap_or_else(|| synthetic_required_payload_root(kind, source));
        let privacy_root = match kind {
            ReplacementLaneKind::WalletScannerPrivacy => wallet_privacy_replacement_root(source),
            _ => stub_lane
                .map(|lane| lane.privacy_redaction_root.clone())
                .unwrap_or_else(|| synthetic_privacy_root(kind, source)),
        };
        let fail_closed_root = stub_lane
            .map(|lane| lane.fail_closed_root.clone())
            .unwrap_or_else(|| synthetic_fail_closed_root(kind, source));
        let freshness_root = live_lane
            .map(|lane| record_root("freshness-sla", &lane.freshness_sla.public_record()))
            .unwrap_or_else(|| synthetic_freshness_root(kind, source));
        let source_receipt_root = source_receipt_root(kind, source);
        let acceptance_root = lane_acceptance_root(
            config,
            source,
            kind,
            &source_domain,
            &source_stub_lane_id,
            &source_live_lane_id,
            &source_fixture_root,
            &source_live_feed_root,
            &required_payload_root,
            &source_receipt_root,
            &freshness_root,
            &privacy_root,
            &fail_closed_root,
        );
        let status = lane_status(config, source, kind, live_lane.is_some());
        let blocks_user_release = lane_blocks_user_release(source, kind, status);
        let blocks_production = lane_blocks_production(config, source, kind, status);
        let replacement_root = lane_replacement_root(
            kind,
            status,
            &acceptance_root,
            &source_receipt_root,
            &source_live_feed_root,
            &privacy_root,
            &fail_closed_root,
            blocks_user_release,
            blocks_production,
        );
        let lane_id = lane_id(kind, &replacement_root);
        Self {
            lane_id,
            ordinal,
            kind,
            source_domain,
            source_stub_lane_id,
            source_live_lane_id,
            source_fixture_root,
            source_live_feed_root,
            required_payload_root,
            source_receipt_root,
            acceptance_root,
            replacement_root,
            freshness_root,
            privacy_root,
            fail_closed_root,
            status,
            blocks_user_release,
            blocks_production,
            operator_action: lane_operator_action(kind, status).to_string(),
            evidence_contract: kind.evidence_contract().to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "ordinal": self.ordinal,
            "kind": self.kind.as_str(),
            "source_domain": self.source_domain,
            "source_stub_lane_id": self.source_stub_lane_id,
            "source_live_lane_id": self.source_live_lane_id,
            "source_fixture_root": self.source_fixture_root,
            "source_live_feed_root": self.source_live_feed_root,
            "required_payload_root": self.required_payload_root,
            "source_receipt_root": self.source_receipt_root,
            "acceptance_root": self.acceptance_root,
            "replacement_root": self.replacement_root,
            "freshness_root": self.freshness_root,
            "privacy_root": self.privacy_root,
            "fail_closed_root": self.fail_closed_root,
            "status": self.status.as_str(),
            "blocks_user_release": self.blocks_user_release,
            "blocks_production": self.blocks_production,
            "operator_action": self.operator_action,
            "evidence_contract": self.evidence_contract,
        })
    }

    pub fn state_root(&self) -> String {
        self.replacement_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceReplacementVerdict {
    pub replacement_lane_count: u64,
    pub live_feed_lane_count: u64,
    pub fixture_stub_lane_count: u64,
    pub receipt_lane_count: u64,
    pub receipt_bound_lane_count: u64,
    pub ready_replacement_count: u64,
    pub deferred_replacement_count: u64,
    pub failed_closed_count: u64,
    pub production_hold_count: u64,
    pub user_release_blocker_count: u64,
    pub production_blocker_count: u64,
    pub clearinghouse_blocker_count: u64,
    pub heavy_gate_deferred_count: u64,
    pub cargo_deferred_count: u64,
    pub audit_deferred_count: u64,
    pub all_fixture_paths_mapped: bool,
    pub receipt_binding_sufficient: bool,
    pub live_feeds_connected: bool,
    pub private_state_lane_present: bool,
    pub pq_authority_lane_present: bool,
    pub privacy_lane_present: bool,
    pub release_hold_bound: bool,
    pub cargo_checks_required: bool,
    pub runtime_tests_required: bool,
    pub security_audit_required: bool,
    pub production_blocked: bool,
    pub replacement_status: String,
    pub user_escape_answer: String,
    pub production_answer: String,
    pub verdict_root: String,
}

impl EvidenceReplacementVerdict {
    pub fn new(config: &Config, source: &SourceBundle, lanes: &[EvidenceReplacementLane]) -> Self {
        let replacement_lane_count = lanes.len() as u64;
        let live_feed_lane_count = source.live_lane_count;
        let fixture_stub_lane_count = source.stub_lane_count;
        let receipt_lane_count = source.receipt_lane_count;
        let receipt_bound_lane_count = source.receipt_bound_lane_count;
        let ready_replacement_count =
            count_status(lanes, EvidenceReplacementStatus::LiveReplacementReady);
        let deferred_replacement_count =
            count_status(lanes, EvidenceReplacementStatus::LiveReplacementDeferred);
        let failed_closed_count = count_status(lanes, EvidenceReplacementStatus::FailedClosed);
        let production_hold_count = count_status(lanes, EvidenceReplacementStatus::ProductionHold);
        let user_release_blocker_count =
            lanes.iter().filter(|lane| lane.blocks_user_release).count() as u64;
        let production_blocker_count =
            lanes.iter().filter(|lane| lane.blocks_production).count() as u64;
        let clearinghouse_blocker_count = source.clearinghouse_records_blocked;
        let heavy_gate_deferred_count = source.receipt_heavy_gate_deferred_count;
        let cargo_deferred_count = source.receipt_cargo_deferred_count;
        let audit_deferred_count = source.receipt_audit_deferred_count;
        let all_fixture_paths_mapped = replacement_lane_count >= config.min_replacement_lanes
            && fixture_stub_lane_count >= config.min_live_feed_lanes
            && live_feed_lane_count >= config.min_live_feed_lanes
            && lanes
                .iter()
                .all(|lane| !lane.source_live_feed_root.is_empty());
        let receipt_binding_sufficient = receipt_bound_lane_count >= config.min_receipt_bound_lanes
            && source
                .receipt_status
                .contains("replay_plan_execution_receipt_bound");
        let live_feeds_connected = source.live_feed_execution_enabled
            && deferred_replacement_count == 0
            && failed_closed_count == 0;
        let private_state_lane_present = has_lane(lanes, ReplacementLaneKind::PrivateNoteState);
        let pq_authority_lane_present = has_lane(lanes, ReplacementLaneKind::PqAuthorityQuorum);
        let privacy_lane_present = has_lane(lanes, ReplacementLaneKind::WalletScannerPrivacy);
        let release_hold_bound = !source.production_hold_root.is_empty()
            && source
                .receipt_production_answer
                .contains("production_release_blocked");
        let cargo_checks_required =
            config.cargo_checks_required_for_production && cargo_deferred_count > 0;
        let runtime_tests_required =
            config.runtime_tests_required_for_production && heavy_gate_deferred_count > 0;
        let security_audit_required =
            config.security_audit_required_for_production && audit_deferred_count > 0;
        let production_blocked = production_blocker_count > 0
            || clearinghouse_blocker_count > config.max_unresolved_release_blockers
            || !live_feeds_connected
            || cargo_checks_required
            || runtime_tests_required
            || security_audit_required;
        let replacement_status = if failed_closed_count > 0 {
            "failed_closed"
        } else if production_blocked {
            "fixture_bound_live_replacement_deferred"
        } else if ready_replacement_count >= config.min_replacement_lanes && live_feeds_connected {
            "live_evidence_replacement_ready"
        } else {
            "incomplete"
        }
        .to_string();
        let user_escape_answer = if receipt_binding_sufficient
            && all_fixture_paths_mapped
            && user_release_blocker_count == 0
        {
            "fixture-backed user escape remains answerable; live evidence replacement is explicitly deferred until provider feeds, runtime tests, and audits are green"
        } else {
            "user escape answer is not yet proven because receipt binding or fixture-to-live lane mapping is incomplete"
        }
        .to_string();
        let production_answer = if production_blocked {
            "do not treat the bridge/exit vertical slice as production ready; live feed execution, cargo/runtime gates, and audits remain required"
        } else {
            "production release may proceed only for the bounded bridge/exit vertical slice"
        }
        .to_string();
        let verdict_root = verdict_root(
            config,
            source,
            replacement_lane_count,
            live_feed_lane_count,
            receipt_bound_lane_count,
            ready_replacement_count,
            deferred_replacement_count,
            failed_closed_count,
            user_release_blocker_count,
            production_blocker_count,
            all_fixture_paths_mapped,
            receipt_binding_sufficient,
            live_feeds_connected,
            production_blocked,
            &replacement_status,
            &user_escape_answer,
            &production_answer,
        );
        Self {
            replacement_lane_count,
            live_feed_lane_count,
            fixture_stub_lane_count,
            receipt_lane_count,
            receipt_bound_lane_count,
            ready_replacement_count,
            deferred_replacement_count,
            failed_closed_count,
            production_hold_count,
            user_release_blocker_count,
            production_blocker_count,
            clearinghouse_blocker_count,
            heavy_gate_deferred_count,
            cargo_deferred_count,
            audit_deferred_count,
            all_fixture_paths_mapped,
            receipt_binding_sufficient,
            live_feeds_connected,
            private_state_lane_present,
            pq_authority_lane_present,
            privacy_lane_present,
            release_hold_bound,
            cargo_checks_required,
            runtime_tests_required,
            security_audit_required,
            production_blocked,
            replacement_status,
            user_escape_answer,
            production_answer,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "replacement_lane_count": self.replacement_lane_count,
            "live_feed_lane_count": self.live_feed_lane_count,
            "fixture_stub_lane_count": self.fixture_stub_lane_count,
            "receipt_lane_count": self.receipt_lane_count,
            "receipt_bound_lane_count": self.receipt_bound_lane_count,
            "ready_replacement_count": self.ready_replacement_count,
            "deferred_replacement_count": self.deferred_replacement_count,
            "failed_closed_count": self.failed_closed_count,
            "production_hold_count": self.production_hold_count,
            "user_release_blocker_count": self.user_release_blocker_count,
            "production_blocker_count": self.production_blocker_count,
            "clearinghouse_blocker_count": self.clearinghouse_blocker_count,
            "heavy_gate_deferred_count": self.heavy_gate_deferred_count,
            "cargo_deferred_count": self.cargo_deferred_count,
            "audit_deferred_count": self.audit_deferred_count,
            "all_fixture_paths_mapped": self.all_fixture_paths_mapped,
            "receipt_binding_sufficient": self.receipt_binding_sufficient,
            "live_feeds_connected": self.live_feeds_connected,
            "private_state_lane_present": self.private_state_lane_present,
            "pq_authority_lane_present": self.pq_authority_lane_present,
            "privacy_lane_present": self.privacy_lane_present,
            "release_hold_bound": self.release_hold_bound,
            "cargo_checks_required": self.cargo_checks_required,
            "runtime_tests_required": self.runtime_tests_required,
            "security_audit_required": self.security_audit_required,
            "production_blocked": self.production_blocked,
            "replacement_status": self.replacement_status,
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
    pub replacement_lanes: Vec<EvidenceReplacementLane>,
    pub verdict: EvidenceReplacementVerdict,
    pub replacement_lane_root: String,
    pub live_evidence_root: String,
    pub fail_closed_root: String,
    pub production_hold_root: String,
    pub state_commitment_root: String,
}

impl State {
    pub fn new(config: Config, source: SourceBundle, stub: stub_swap::State) -> Result<Self> {
        validate_config(&config)?;
        validate_source(&source)?;
        let replacement_lanes = ReplacementLaneKind::ordered()
            .iter()
            .enumerate()
            .map(|(index, kind)| {
                EvidenceReplacementLane::devnet(&config, &source, &stub, *kind, index as u64 + 1)
            })
            .collect::<Vec<_>>();
        let verdict = EvidenceReplacementVerdict::new(&config, &source, &replacement_lanes);
        let replacement_lane_root = replacement_lane_root(&replacement_lanes);
        let live_evidence_root =
            live_evidence_root(&config, &source, &replacement_lane_root, &verdict);
        let fail_closed_root =
            fail_closed_vector_root(&config, &source, &replacement_lanes, &verdict);
        let production_hold_root =
            production_hold_vector_root(&config, &source, &replacement_lanes, &verdict);
        let state_commitment_root = state_commitment_root(
            &config,
            &source,
            &replacement_lane_root,
            &live_evidence_root,
            &fail_closed_root,
            &production_hold_root,
            &verdict,
        );
        Ok(Self {
            config,
            source,
            replacement_lanes,
            verdict,
            replacement_lane_root,
            live_evidence_root,
            fail_closed_root,
            production_hold_root,
            state_commitment_root,
        })
    }

    pub fn devnet() -> Self {
        let stub = stub_swap::devnet();
        match Self::new(Config::default(), SourceBundle::devnet(), stub) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_answer_vertical_slice_live_evidence_replacement_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source": self.source.public_record(),
            "replacement_lane_root": self.replacement_lane_root,
            "live_evidence_root": self.live_evidence_root,
            "fail_closed_root": self.fail_closed_root,
            "production_hold_root": self.production_hold_root,
            "state_commitment_root": self.state_commitment_root,
            "verdict": self.verdict.public_record(),
            "replacement_lanes": self
                .replacement_lanes
                .iter()
                .map(EvidenceReplacementLane::public_record)
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

fn select_stub_lane(
    stub: &stub_swap::State,
    domain: stub_swap::FeedDomain,
) -> Option<&stub_swap::FeedStubLane> {
    stub.stub_lanes.iter().find(|lane| lane.domain == domain)
}

fn select_live_lane(
    stub: &stub_swap::State,
    domain: stub_swap::FeedDomain,
) -> Option<&stub_swap::LiveFeedLane> {
    stub.live_lanes.iter().find(|lane| lane.domain == domain)
}

fn synthetic_lane_id(kind: ReplacementLaneKind, suffix: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-SYNTHETIC-LANE-ID",
        &[HashPart::Str(kind.as_str()), HashPart::Str(suffix)],
        16,
    )
}

fn synthetic_fixture_root(kind: ReplacementLaneKind, source: &SourceBundle) -> String {
    record_root(
        "synthetic-fixture-root",
        &json!({
            "kind": kind.as_str(),
            "receipt_execution_root": source.receipt_execution_root,
            "wallet_receipt_root": source.wallet_receipt_root,
            "observed_receipt_root": source.observed_receipt_root,
        }),
    )
}

fn synthetic_live_feed_root(kind: ReplacementLaneKind, source: &SourceBundle) -> String {
    record_root(
        "synthetic-live-feed-root",
        &json!({
            "kind": kind.as_str(),
            "receipt_execution_root": source.receipt_execution_root,
            "live_lane_root": source.live_lane_root,
            "clearinghouse_state_root": source.clearinghouse_state_root,
        }),
    )
}

fn synthetic_required_payload_root(kind: ReplacementLaneKind, source: &SourceBundle) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-SYNTHETIC-PAYLOAD",
        &[
            json!({
                "kind": kind.as_str(),
                "receipt_execution_root": source.receipt_execution_root,
            }),
            json!({
                "wallet_receipt_root": source.wallet_receipt_root,
                "production_hold_root": source.production_hold_root,
            }),
        ],
    )
}

fn synthetic_privacy_root(kind: ReplacementLaneKind, source: &SourceBundle) -> String {
    record_root(
        "synthetic-privacy-root",
        &json!({
            "kind": kind.as_str(),
            "privacy_redaction_root": source.privacy_redaction_root,
            "wallet_receipt_root": source.wallet_receipt_root,
        }),
    )
}

fn wallet_privacy_replacement_root(source: &SourceBundle) -> String {
    record_root(
        "wallet-privacy-replacement-root",
        &json!({
            "wallet_receipt_root": source.wallet_receipt_root,
            "privacy_redaction_root": source.privacy_redaction_root,
            "observed_receipt_root": source.observed_receipt_root,
            "metadata_policy": "redacted_wallet_scan_roots_only",
        }),
    )
}

fn synthetic_fail_closed_root(kind: ReplacementLaneKind, source: &SourceBundle) -> String {
    record_root(
        "synthetic-fail-closed-root",
        &json!({
            "kind": kind.as_str(),
            "fail_closed_root": source.fail_closed_root,
            "production_hold_root": source.production_hold_root,
            "policy": "missing_or_stale_live_evidence_keeps_release_held",
        }),
    )
}

fn synthetic_freshness_root(kind: ReplacementLaneKind, source: &SourceBundle) -> String {
    record_root(
        "synthetic-freshness-root",
        &json!({
            "kind": kind.as_str(),
            "freshness_sla_root": source.freshness_sla_root,
            "live_feed_execution_enabled": source.live_feed_execution_enabled,
        }),
    )
}

fn source_receipt_root(kind: ReplacementLaneKind, source: &SourceBundle) -> String {
    match kind {
        ReplacementLaneKind::WalletScannerPrivacy | ReplacementLaneKind::PrivateNoteState => {
            source.wallet_receipt_root.clone()
        }
        ReplacementLaneKind::ReleaseBlockerClearing => source.production_hold_root.clone(),
        ReplacementLaneKind::ReserveLiquidity => source.clearinghouse_batch_root.clone(),
        _ => source.observed_receipt_root.clone(),
    }
}

fn lane_status(
    _config: &Config,
    source: &SourceBundle,
    kind: ReplacementLaneKind,
    live_lane_present: bool,
) -> EvidenceReplacementStatus {
    if !live_lane_present
        && matches!(
            kind,
            ReplacementLaneKind::MoneroHeaderCanonicality
                | ReplacementLaneKind::DepositLockWatcher
                | ReplacementLaneKind::SettlementReceiptExecutor
                | ReplacementLaneKind::ReserveLiquidity
                | ReplacementLaneKind::ReleaseBlockerClearing
        )
    {
        return EvidenceReplacementStatus::FailedClosed;
    }
    if source.clearinghouse_records_blocked > 0
        && kind == ReplacementLaneKind::ReleaseBlockerClearing
    {
        return EvidenceReplacementStatus::ProductionHold;
    }
    if source.live_feed_execution_enabled {
        EvidenceReplacementStatus::LiveReplacementReady
    } else {
        EvidenceReplacementStatus::LiveReplacementDeferred
    }
}

fn lane_blocks_user_release(
    source: &SourceBundle,
    kind: ReplacementLaneKind,
    status: EvidenceReplacementStatus,
) -> bool {
    status == EvidenceReplacementStatus::FailedClosed
        || (kind == ReplacementLaneKind::ReleaseBlockerClearing
            && source.clearinghouse_user_release_blockers > 0)
}

fn lane_blocks_production(
    config: &Config,
    source: &SourceBundle,
    kind: ReplacementLaneKind,
    status: EvidenceReplacementStatus,
) -> bool {
    if status != EvidenceReplacementStatus::LiveReplacementReady {
        return kind.production_critical();
    }
    if config.live_execution_required_for_production && !source.live_feed_execution_enabled {
        return true;
    }
    kind == ReplacementLaneKind::ReleaseBlockerClearing
        && source.clearinghouse_production_blockers > config.max_unresolved_release_blockers
}

fn lane_operator_action(
    kind: ReplacementLaneKind,
    status: EvidenceReplacementStatus,
) -> &'static str {
    match status {
        EvidenceReplacementStatus::LiveReplacementReady => {
            "accept live evidence root as replacement candidate for the bounded bridge/exit slice"
        }
        EvidenceReplacementStatus::LiveReplacementDeferred => match kind {
            ReplacementLaneKind::PqAuthorityQuorum => {
                "connect PQ authority attestations to the replay receipt before unholding production"
            }
            ReplacementLaneKind::WalletScannerPrivacy => {
                "connect wallet scanner privacy receipts without exposing note metadata"
            }
            ReplacementLaneKind::PrivateNoteState => {
                "replace private note fixtures with encrypted witness and note commitment receipts"
            }
            _ => "replace fixture lane with provider-attested live feed and replay against the receipt binding",
        },
        EvidenceReplacementStatus::ProductionHold => {
            "clear release blockers and keep production held until all live evidence roots are green"
        }
        EvidenceReplacementStatus::FailedClosed => {
            "fail closed, preserve user escape evidence, and repair missing live replacement lane"
        }
    }
}

fn lane_acceptance_root(
    config: &Config,
    source: &SourceBundle,
    kind: ReplacementLaneKind,
    source_domain: &str,
    source_stub_lane_id: &str,
    source_live_lane_id: &str,
    source_fixture_root: &str,
    source_live_feed_root: &str,
    required_payload_root: &str,
    source_receipt_root: &str,
    freshness_root: &str,
    privacy_root: &str,
    fail_closed_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-LANE-ACCEPTANCE",
        &[
            HashPart::Str(&config.replacement_suite),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_domain),
            HashPart::Str(source_stub_lane_id),
            HashPart::Str(source_live_lane_id),
            HashPart::Str(source_fixture_root),
            HashPart::Str(source_live_feed_root),
            HashPart::Str(required_payload_root),
            HashPart::Str(source_receipt_root),
            HashPart::Str(freshness_root),
            HashPart::Str(privacy_root),
            HashPart::Str(fail_closed_root),
            HashPart::Str(&source.receipt_execution_root),
            HashPart::Str(bool_str(config.fail_closed_required)),
            HashPart::Str(bool_str(config.privacy_redaction_required)),
        ],
        32,
    )
}

fn lane_replacement_root(
    kind: ReplacementLaneKind,
    status: EvidenceReplacementStatus,
    acceptance_root: &str,
    source_receipt_root: &str,
    source_live_feed_root: &str,
    privacy_root: &str,
    fail_closed_root: &str,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-LANE",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(acceptance_root),
            HashPart::Str(source_receipt_root),
            HashPart::Str(source_live_feed_root),
            HashPart::Str(privacy_root),
            HashPart::Str(fail_closed_root),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

fn lane_id(kind: ReplacementLaneKind, replacement_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-LANE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(replacement_root),
        ],
        16,
    )
}

fn replacement_lane_root(lanes: &[EvidenceReplacementLane]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-LANES",
        &lanes
            .iter()
            .map(EvidenceReplacementLane::public_record)
            .collect::<Vec<_>>(),
    )
}

fn live_evidence_root(
    config: &Config,
    source: &SourceBundle,
    replacement_lane_root: &str,
    verdict: &EvidenceReplacementVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-LIVE-EVIDENCE",
        &[
            HashPart::Str(&config.replacement_suite),
            HashPart::Str(&source.live_lane_root),
            HashPart::Str(&source.observed_receipt_root),
            HashPart::Str(&source.wallet_receipt_root),
            HashPart::Str(replacement_lane_root),
            HashPart::Str(&verdict.verdict_root),
        ],
        32,
    )
}

fn fail_closed_vector_root(
    config: &Config,
    source: &SourceBundle,
    lanes: &[EvidenceReplacementLane],
    verdict: &EvidenceReplacementVerdict,
) -> String {
    let records = lanes
        .iter()
        .filter(|lane| {
            lane.status == EvidenceReplacementStatus::FailedClosed || lane.blocks_user_release
        })
        .map(|lane| {
            json!({
                "lane_id": lane.lane_id,
                "kind": lane.kind.as_str(),
                "status": lane.status.as_str(),
                "fail_closed_root": lane.fail_closed_root,
                "blocks_user_release": lane.blocks_user_release,
            })
        })
        .collect::<Vec<_>>();
    let vector_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-FAIL-CLOSED-VECTOR",
        &records,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-FAIL-CLOSED",
        &[
            HashPart::Str(&config.replacement_suite),
            HashPart::Str(&source.fail_closed_root),
            HashPart::Str(&source.production_hold_root),
            HashPart::Str(&vector_root),
            HashPart::U64(verdict.user_release_blocker_count),
        ],
        32,
    )
}

fn production_hold_vector_root(
    config: &Config,
    source: &SourceBundle,
    lanes: &[EvidenceReplacementLane],
    verdict: &EvidenceReplacementVerdict,
) -> String {
    let records = lanes
        .iter()
        .filter(|lane| lane.blocks_production)
        .map(|lane| {
            json!({
                "lane_id": lane.lane_id,
                "kind": lane.kind.as_str(),
                "status": lane.status.as_str(),
                "replacement_root": lane.replacement_root,
                "operator_action": lane.operator_action,
            })
        })
        .collect::<Vec<_>>();
    let blocker_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-PRODUCTION-BLOCKERS",
        &records,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-PRODUCTION-HOLD",
        &[
            HashPart::Str(&config.replacement_suite),
            HashPart::Str(&source.production_hold_root),
            HashPart::Str(&source.clearinghouse_batch_root),
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
    replacement_lane_root: &str,
    live_evidence_root: &str,
    fail_closed_root: &str,
    production_hold_root: &str,
    verdict: &EvidenceReplacementVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&source.state_root()),
            HashPart::Str(replacement_lane_root),
            HashPart::Str(live_evidence_root),
            HashPart::Str(fail_closed_root),
            HashPart::Str(production_hold_root),
            HashPart::Str(&verdict.verdict_root),
        ],
        32,
    )
}

fn verdict_root(
    config: &Config,
    source: &SourceBundle,
    replacement_lane_count: u64,
    live_feed_lane_count: u64,
    receipt_bound_lane_count: u64,
    ready_replacement_count: u64,
    deferred_replacement_count: u64,
    failed_closed_count: u64,
    user_release_blocker_count: u64,
    production_blocker_count: u64,
    all_fixture_paths_mapped: bool,
    receipt_binding_sufficient: bool,
    live_feeds_connected: bool,
    production_blocked: bool,
    replacement_status: &str,
    user_escape_answer: &str,
    production_answer: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-VERDICT",
        &[
            HashPart::Str(&config.replacement_suite),
            HashPart::Str(&source.receipt_execution_root),
            HashPart::Str(&source.stub_handoff_root),
            HashPart::U64(replacement_lane_count),
            HashPart::U64(live_feed_lane_count),
            HashPart::U64(receipt_bound_lane_count),
            HashPart::U64(ready_replacement_count),
            HashPart::U64(deferred_replacement_count),
            HashPart::U64(failed_closed_count),
            HashPart::U64(user_release_blocker_count),
            HashPart::U64(production_blocker_count),
            HashPart::Str(bool_str(all_fixture_paths_mapped)),
            HashPart::Str(bool_str(receipt_binding_sufficient)),
            HashPart::Str(bool_str(live_feeds_connected)),
            HashPart::Str(bool_str(production_blocked)),
            HashPart::Str(replacement_status),
            HashPart::Str(user_escape_answer),
            HashPart::Str(production_answer),
        ],
        32,
    )
}

fn count_status(lanes: &[EvidenceReplacementLane], status: EvidenceReplacementStatus) -> u64 {
    lanes.iter().filter(|lane| lane.status == status).count() as u64
}

fn has_lane(lanes: &[EvidenceReplacementLane], kind: ReplacementLaneKind) -> bool {
    lanes.iter().any(|lane| lane.kind == kind)
}

fn validate_config(config: &Config) -> Result<()> {
    ensure(
        config.chain_id == CHAIN_ID,
        "live evidence replacement chain mismatch",
    )?;
    ensure(
        config.protocol_version == PROTOCOL_VERSION,
        "live evidence replacement protocol mismatch",
    )?;
    ensure(
        config.min_replacement_lanes > 0,
        "live evidence replacement requires at least one lane",
    )?;
    ensure(
        config.min_live_feed_lanes > 0,
        "live evidence replacement requires at least one live feed lane",
    )?;
    ensure(
        config.min_receipt_bound_lanes > 0,
        "live evidence replacement requires receipt-bound lanes",
    )?;
    Ok(())
}

fn validate_source(source: &SourceBundle) -> Result<()> {
    ensure(
        !source.receipt_execution_root.is_empty(),
        "live evidence replacement missing receipt execution root",
    )?;
    ensure(
        !source.stub_handoff_root.is_empty(),
        "live evidence replacement missing stub handoff root",
    )?;
    ensure(
        !source.production_hold_root.is_empty(),
        "live evidence replacement missing production hold root",
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
        receipt_execution_root: record_root("fallback-receipt", &json!({"reason": &reason})),
        observed_receipt_root: record_root("fallback-observed", &json!({"reason": &reason})),
        wallet_receipt_root: record_root("fallback-wallet", &json!({"reason": &reason})),
        production_hold_root: record_root("fallback-hold", &json!({"reason": &reason})),
        receipt_status: "fallback".to_string(),
        receipt_user_escape_answer: reason.clone(),
        receipt_production_answer: "fallback".to_string(),
        receipt_lane_count: 0,
        receipt_bound_lane_count: 0,
        receipt_release_blocker_count: 1,
        receipt_heavy_gate_deferred_count: 1,
        receipt_cargo_deferred_count: 1,
        receipt_audit_deferred_count: 1,
        stub_handoff_root: record_root("fallback-stub-handoff", &json!({"reason": &reason})),
        stub_lane_root: record_root("fallback-stub-lane", &json!({"reason": &reason})),
        live_lane_root: record_root("fallback-live-lane", &json!({"reason": &reason})),
        freshness_sla_root: record_root("fallback-freshness", &json!({"reason": &reason})),
        replay_compatibility_root: record_root(
            "fallback-replay-compatibility",
            &json!({"reason": &reason}),
        ),
        privacy_redaction_root: record_root("fallback-privacy", &json!({"reason": &reason})),
        fail_closed_root: record_root("fallback-fail-closed", &json!({"reason": &reason})),
        stub_readiness_status: "fallback".to_string(),
        live_feed_execution_enabled: false,
        stub_lane_count: 0,
        live_lane_count: 0,
        clearinghouse_state_root: record_root(
            "fallback-clearinghouse",
            &json!({"reason": &reason}),
        ),
        clearinghouse_batch_root: record_root(
            "fallback-clearinghouse-batch",
            &json!({"reason": &reason}),
        ),
        clearinghouse_status: "fallback".to_string(),
        clearinghouse_records_total: 0,
        clearinghouse_records_blocked: 1,
        clearinghouse_user_release_blockers: 1,
        clearinghouse_production_blockers: 1,
    };
    let fallback_lane = EvidenceReplacementLane {
        lane_id: synthetic_lane_id(ReplacementLaneKind::ReleaseBlockerClearing, "fallback"),
        ordinal: 1,
        kind: ReplacementLaneKind::ReleaseBlockerClearing,
        source_domain: "fallback".to_string(),
        source_stub_lane_id: "fallback".to_string(),
        source_live_lane_id: "fallback".to_string(),
        source_fixture_root: source.stub_lane_root.clone(),
        source_live_feed_root: source.live_lane_root.clone(),
        required_payload_root: source.live_lane_root.clone(),
        source_receipt_root: source.production_hold_root.clone(),
        acceptance_root: record_root("fallback-acceptance", &json!({"reason": &reason})),
        replacement_root: record_root("fallback-replacement", &json!({"reason": &reason})),
        freshness_root: source.freshness_sla_root.clone(),
        privacy_root: source.privacy_redaction_root.clone(),
        fail_closed_root: source.fail_closed_root.clone(),
        status: EvidenceReplacementStatus::FailedClosed,
        blocks_user_release: true,
        blocks_production: true,
        operator_action: "fallback state keeps release held until source construction succeeds"
            .to_string(),
        evidence_contract: reason,
    };
    let replacement_lanes = vec![fallback_lane];
    let verdict = EvidenceReplacementVerdict::new(&config, &source, &replacement_lanes);
    let replacement_lane_root = replacement_lane_root(&replacement_lanes);
    let live_evidence_root = live_evidence_root(&config, &source, &replacement_lane_root, &verdict);
    let fail_closed_root = fail_closed_vector_root(&config, &source, &replacement_lanes, &verdict);
    let production_hold_root =
        production_hold_vector_root(&config, &source, &replacement_lanes, &verdict);
    let state_commitment_root = state_commitment_root(
        &config,
        &source,
        &replacement_lane_root,
        &live_evidence_root,
        &fail_closed_root,
        &production_hold_root,
        &verdict,
    );
    State {
        config,
        source,
        replacement_lanes,
        verdict,
        replacement_lane_root,
        live_evidence_root,
        fail_closed_root,
        production_hold_root,
        state_commitment_root,
    }
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-EVIDENCE-REPLACEMENT-RECORD",
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
