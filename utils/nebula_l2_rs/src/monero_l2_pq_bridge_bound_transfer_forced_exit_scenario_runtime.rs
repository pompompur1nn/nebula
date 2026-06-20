use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_private_transfer_receipt_runtime::{
        BridgeBoundTransferRequest, ReportStatus as TransferReportStatus,
        State as BridgeBoundTransferRuntimeState, TransferLane, DEFAULT_DEVNET_CHANGE_AMOUNT,
        DEFAULT_DEVNET_EXIT_AMOUNT, DEFAULT_DEVNET_SOURCE_AMOUNT, DEFAULT_DEVNET_TRANSFER_AMOUNT,
    },
    monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::{
        BridgeLane, ChallengeKind, ChallengeRequest, ChallengeResolutionRequest, ChallengeStatus,
        DepositCertificateRequest, DepositLockRequest, ExitSettlementRequest, ForcedExitRequest,
        MintPrivateNoteRequest, State as BridgeExitSpineState, DEVNET_HEIGHT,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeBoundTransferForcedExitScenarioRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_SCENARIO_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-bound-transfer-forced-exit-scenario-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_SCENARIO_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SCENARIO_SUITE: &str =
    "monero-l2-pq-bridge-bound-private-transfer-to-forced-exit-vertical-slice-v1";
pub const DEFAULT_SCENARIO_LABEL: &str = "devnet-bridge-bound-private-transfer-forced-exit";
pub const DEFAULT_MIN_STEPS: u64 = 12;
pub const DEFAULT_MIN_PROVEN_CLAIMS: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_TRANSCRIPTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStatus {
    Proven,
    Watch,
    Failed,
}

impl ScenarioStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    SpineSeeded,
    TransferSourceDepositOpened,
    TransferSourceCertified,
    TransferSourceNoteMinted,
    BridgeBoundTransferSubmitted,
    TransferReceiptAnchored,
    ExitClaimPrepared,
    ForcedExitRequestedFromTransferClaim,
    ForcedExitLivenessObserved,
    ForcedExitArmed,
    ChallengeOpened,
    ChallengeResolved,
    ExitSettled,
    TransferReadinessRechecked,
    ScenarioTranscriptSealed,
}

impl StepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpineSeeded => "spine_seeded",
            Self::TransferSourceDepositOpened => "transfer_source_deposit_opened",
            Self::TransferSourceCertified => "transfer_source_certified",
            Self::TransferSourceNoteMinted => "transfer_source_note_minted",
            Self::BridgeBoundTransferSubmitted => "bridge_bound_transfer_submitted",
            Self::TransferReceiptAnchored => "transfer_receipt_anchored",
            Self::ExitClaimPrepared => "exit_claim_prepared",
            Self::ForcedExitRequestedFromTransferClaim => {
                "forced_exit_requested_from_transfer_claim"
            }
            Self::ForcedExitLivenessObserved => "forced_exit_liveness_observed",
            Self::ForcedExitArmed => "forced_exit_armed",
            Self::ChallengeOpened => "challenge_opened",
            Self::ChallengeResolved => "challenge_resolved",
            Self::ExitSettled => "exit_settled",
            Self::TransferReadinessRechecked => "transfer_readiness_rechecked",
            Self::ScenarioTranscriptSealed => "scenario_transcript_sealed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    BridgeMintedNoteConsumed,
    TransferReceiptRecordedBySpine,
    TransferReceiptAnchoredBySpine,
    ExitClaimMatchesTransferReceipt,
    ForcedExitRequestDerivedFromClaim,
    LivenessFailureCanArmForcedExit,
    ChallengeWindowDoesNotBlockSettlement,
    SettlementReleasesAfterChallengeResolution,
    LowFeePrivacyPqBounds,
    RootsOnlyTranscript,
}

impl ClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeMintedNoteConsumed => "bridge_minted_note_consumed",
            Self::TransferReceiptRecordedBySpine => "transfer_receipt_recorded_by_spine",
            Self::TransferReceiptAnchoredBySpine => "transfer_receipt_anchored_by_spine",
            Self::ExitClaimMatchesTransferReceipt => "exit_claim_matches_transfer_receipt",
            Self::ForcedExitRequestDerivedFromClaim => "forced_exit_request_derived_from_claim",
            Self::LivenessFailureCanArmForcedExit => "liveness_failure_can_arm_forced_exit",
            Self::ChallengeWindowDoesNotBlockSettlement => {
                "challenge_window_does_not_block_settlement"
            }
            Self::SettlementReleasesAfterChallengeResolution => {
                "settlement_releases_after_challenge_resolution"
            }
            Self::LowFeePrivacyPqBounds => "low_fee_privacy_pq_bounds",
            Self::RootsOnlyTranscript => "roots_only_transcript",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Proven,
    Watch,
    Failed,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub scenario_suite: String,
    pub scenario_label: String,
    pub min_steps: u64,
    pub min_proven_claims: u64,
    pub min_privacy_set_size: u64,
    pub max_transcripts: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            scenario_suite: SCENARIO_SUITE.to_string(),
            scenario_label: DEFAULT_SCENARIO_LABEL.to_string(),
            min_steps: DEFAULT_MIN_STEPS,
            min_proven_claims: DEFAULT_MIN_PROVEN_CLAIMS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_transcripts: DEFAULT_MAX_TRANSCRIPTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "scenario_suite": self.scenario_suite,
            "scenario_label": self.scenario_label,
            "min_steps": self.min_steps,
            "min_proven_claims": self.min_proven_claims,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_transcripts": self.max_transcripts,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScenarioStep {
    pub step_id: String,
    pub scenario_id: String,
    pub sequence: u64,
    pub kind: StepKind,
    pub actor: String,
    pub height: u64,
    pub path_id: Option<String>,
    pub transfer_id: Option<String>,
    pub challenge_id: Option<String>,
    pub settlement_id: Option<String>,
    pub private_root: String,
    pub evidence_root: String,
    pub spine_root_after: String,
    pub transfer_runtime_root_after: String,
}

impl ScenarioStep {
    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "scenario_id": self.scenario_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "actor": self.actor,
            "height": self.height,
            "path_id": self.path_id,
            "transfer_id": self.transfer_id,
            "challenge_id": self.challenge_id,
            "settlement_id": self.settlement_id,
            "private_root": self.private_root,
            "evidence_root": self.evidence_root,
            "spine_root_after": self.spine_root_after,
            "transfer_runtime_root_after": self.transfer_runtime_root_after,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("scenario_step", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScenarioClaim {
    pub claim_id: String,
    pub scenario_id: String,
    pub kind: ClaimKind,
    pub status: ClaimStatus,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
}

impl ScenarioClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("scenario_claim", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScenarioTranscript {
    pub transcript_id: String,
    pub scenario_id: String,
    pub status: ScenarioStatus,
    pub step_count: u64,
    pub proven_claim_count: u64,
    pub watch_claim_count: u64,
    pub failed_claim_count: u64,
    pub step_root: String,
    pub claim_root: String,
    pub final_spine_root: String,
    pub final_transfer_runtime_root: String,
    pub transfer_id: String,
    pub path_id: String,
    pub settlement_id: String,
    pub privacy_set_size_observed: u64,
    pub transcript_root: String,
}

impl ScenarioTranscript {
    pub fn public_record(&self) -> Value {
        json!({
            "transcript_id": self.transcript_id,
            "scenario_id": self.scenario_id,
            "status": self.status.as_str(),
            "step_count": self.step_count,
            "proven_claim_count": self.proven_claim_count,
            "watch_claim_count": self.watch_claim_count,
            "failed_claim_count": self.failed_claim_count,
            "step_root": self.step_root,
            "claim_root": self.claim_root,
            "final_spine_root": self.final_spine_root,
            "final_transfer_runtime_root": self.final_transfer_runtime_root,
            "transfer_id": self.transfer_id,
            "path_id": self.path_id,
            "settlement_id": self.settlement_id,
            "privacy_set_size_observed": self.privacy_set_size_observed,
            "transcript_root": self.transcript_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("scenario_transcript", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub scenarios_run: u64,
    pub steps_recorded: u64,
    pub claims_recorded: u64,
    pub bridge_bound_transfers_submitted: u64,
    pub exit_claims_consumed: u64,
    pub forced_exits_requested: u64,
    pub forced_exits_armed: u64,
    pub challenges_resolved: u64,
    pub exits_settled: u64,
    pub transcripts_sealed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scenarios_run": self.scenarios_run,
            "steps_recorded": self.steps_recorded,
            "claims_recorded": self.claims_recorded,
            "bridge_bound_transfers_submitted": self.bridge_bound_transfers_submitted,
            "exit_claims_consumed": self.exit_claims_consumed,
            "forced_exits_requested": self.forced_exits_requested,
            "forced_exits_armed": self.forced_exits_armed,
            "challenges_resolved": self.challenges_resolved,
            "exits_settled": self.exits_settled,
            "transcripts_sealed": self.transcripts_sealed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub spine_root: String,
    pub transfer_runtime_root: String,
    pub step_root: String,
    pub claim_root: String,
    pub transcript_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            spine_root: String::new(),
            transfer_runtime_root: String::new(),
            step_root: merkle_root("MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EXIT-STEPS", &[]),
            claim_root: merkle_root("MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EXIT-CLAIMS", &[]),
            transcript_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EXIT-TRANSCRIPTS",
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
            "spine_root": self.spine_root,
            "transfer_runtime_root": self.transfer_runtime_root,
            "step_root": self.step_root,
            "claim_root": self.claim_root,
            "transcript_root": self.transcript_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SCENARIO-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.spine_root),
                HashPart::Str(&self.transfer_runtime_root),
                HashPart::Str(&self.step_root),
                HashPart::Str(&self.claim_root),
                HashPart::Str(&self.transcript_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub spine: BridgeExitSpineState,
    pub transfer_runtime: BridgeBoundTransferRuntimeState,
    pub steps: Vec<ScenarioStep>,
    pub claims: BTreeMap<String, ScenarioClaim>,
    pub transcripts: BTreeMap<String, ScenarioTranscript>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let mut state = Self {
            roots: Roots::empty(&config, &counters),
            config,
            spine: BridgeExitSpineState::devnet(),
            transfer_runtime: BridgeBoundTransferRuntimeState::new(
                crate::monero_l2_pq_bridge_bound_private_transfer_receipt_runtime::Config::devnet(),
            ),
            steps: Vec::new(),
            claims: BTreeMap::new(),
            transcripts: BTreeMap::new(),
            counters,
        };
        state
            .run_devnet_transfer_forced_exit_scenario()
            .expect("devnet bridge-bound transfer forced-exit scenario");
        state
    }

    pub fn run_devnet_transfer_forced_exit_scenario(&mut self) -> Result<String> {
        let scenario_id = scenario_id(&self.config.scenario_label, &self.spine.state_root());
        self.counters.scenarios_run += 1;
        self.record_step(
            &scenario_id,
            StepKind::SpineSeeded,
            "operator",
            DEVNET_HEIGHT,
            None,
            None,
            None,
            None,
            json!({ "initial_spine_root": self.spine.state_root() }),
        );

        let (path_id, watcher_quorum_id) = self.open_transfer_source_path(&scenario_id)?;
        self.record_step(
            &scenario_id,
            StepKind::TransferSourceDepositOpened,
            "wallet",
            DEVNET_HEIGHT + self.spine.config.monero_finality_depth + 21,
            Some(path_id.clone()),
            None,
            None,
            None,
            json!({ "path_id": path_id, "watcher_quorum_id": watcher_quorum_id }),
        );
        self.certify_transfer_source_path(&path_id, &watcher_quorum_id)?;
        self.record_step(
            &scenario_id,
            StepKind::TransferSourceCertified,
            "pq_watcher_quorum",
            DEVNET_HEIGHT + self.spine.config.monero_finality_depth + 22,
            Some(path_id.clone()),
            None,
            None,
            None,
            json!({ "path_id": path_id, "watcher_quorum_id": watcher_quorum_id }),
        );
        self.mint_transfer_source_note(&path_id)?;
        self.record_step(
            &scenario_id,
            StepKind::TransferSourceNoteMinted,
            "bridge_minter",
            DEVNET_HEIGHT + self.spine.config.monero_finality_depth + 23,
            Some(path_id.clone()),
            None,
            None,
            None,
            json!({ "path_id": path_id, "input_note_commitment": scenario_root("input-note", &path_id) }),
        );

        let transfer_request = self.transfer_request(&path_id);
        let transfer_id = self
            .transfer_runtime
            .submit_bridge_bound_transfer(&mut self.spine, transfer_request)?;
        let receipt = self
            .transfer_runtime
            .receipts
            .get(&transfer_id)
            .cloned()
            .ok_or_else(|| "bridge-bound transfer receipt missing".to_string())?;
        let readiness_report = self
            .transfer_runtime
            .verify_transfer_exit_readiness(&self.spine, &transfer_id)?;
        require(
            readiness_report.status == TransferReportStatus::Passed,
            "bridge-bound transfer readiness report did not pass",
        )?;
        self.counters.bridge_bound_transfers_submitted += 1;
        self.record_step(
            &scenario_id,
            StepKind::BridgeBoundTransferSubmitted,
            "private_transfer_runtime",
            DEVNET_HEIGHT + 168,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            None,
            None,
            json!({
                "transfer_id": transfer_id,
                "action_receipt_id": receipt.action_receipt_id,
                "readiness_report_id": readiness_report.report_id,
                "readiness_status": readiness_report.status.as_str(),
            }),
        );
        self.record_step(
            &scenario_id,
            StepKind::TransferReceiptAnchored,
            "sequencer_checkpoint",
            DEVNET_HEIGHT + 169,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            None,
            None,
            json!({
                "receipt_root": receipt.receipt_root,
                "bridge_checkpoint_root": receipt.bridge_checkpoint_root,
                "spine_root_after_anchor": receipt.spine_root_after_anchor,
            }),
        );
        self.record_step(
            &scenario_id,
            StepKind::ExitClaimPrepared,
            "recipient_wallet",
            DEVNET_HEIGHT + 170,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            None,
            None,
            json!({
                "exit_claim_id": receipt.exit_claim_id,
                "exit_claim_root": receipt.exit_claim_root,
            }),
        );

        let withdrawal_request = self
            .transfer_runtime
            .prepare_exit_request(&transfer_id, DEVNET_HEIGHT + 208)?;
        let exit_id = self.spine.request_exit(withdrawal_request)?;
        self.counters.exit_claims_consumed += 1;
        self.counters.forced_exits_requested += 1;
        self.record_step(
            &scenario_id,
            StepKind::ForcedExitRequestedFromTransferClaim,
            "recipient_wallet",
            DEVNET_HEIGHT + 208,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            None,
            None,
            json!({ "exit_id": exit_id, "exit_claim_id": receipt.exit_claim_id }),
        );

        let liveness_height = DEVNET_HEIGHT + 208 + self.spine.config.exit_liveness_window_blocks;
        let forced_exit_available = self.spine.forced_exit_available(&path_id, liveness_height);
        require(
            forced_exit_available,
            "forced exit should be available after liveness window",
        )?;
        self.record_step(
            &scenario_id,
            StepKind::ForcedExitLivenessObserved,
            "watcher",
            liveness_height,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            None,
            None,
            json!({ "forced_exit_available": forced_exit_available }),
        );

        let armed_height = liveness_height + 4;
        self.spine.arm_forced_exit(ForcedExitRequest {
            path_id: path_id.clone(),
            censorship_evidence_root: evidence_root(
                &scenario_id,
                "sequencer-censorship-after-transfer",
                &json!({ "transfer_id": transfer_id, "exit_claim_id": receipt.exit_claim_id }),
            ),
            liveness_failure_root: evidence_root(
                &scenario_id,
                "liveness-failure-after-transfer",
                &json!({ "path_id": path_id, "liveness_height": liveness_height }),
            ),
            watcher_quorum_id: watcher_quorum_id.clone(),
            armed_height,
        })?;
        self.counters.forced_exits_armed += 1;
        self.record_step(
            &scenario_id,
            StepKind::ForcedExitArmed,
            "pq_watcher_quorum",
            armed_height,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            None,
            None,
            json!({ "watcher_quorum_id": watcher_quorum_id, "armed_height": armed_height }),
        );

        let challenge_id = self.spine.challenge_path(ChallengeRequest {
            path_id: path_id.clone(),
            challenger_commitment: scenario_root("challenge-commitment", &transfer_id),
            kind: ChallengeKind::SequencerCensorship,
            evidence_root: evidence_root(
                &scenario_id,
                "challenge-transfer-forced-exit",
                &json!({ "transfer_id": transfer_id, "receipt_root": receipt.receipt_root }),
            ),
            opened_height: armed_height + 2,
        })?;
        self.record_step(
            &scenario_id,
            StepKind::ChallengeOpened,
            "challenger",
            armed_height + 2,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            Some(challenge_id.clone()),
            None,
            json!({ "challenge_id": challenge_id, "kind": ChallengeKind::SequencerCensorship.as_str() }),
        );

        let challenge_resolved_height =
            armed_height + self.spine.config.challenge_window_blocks + 6;
        self.spine.resolve_challenge(ChallengeResolutionRequest {
            challenge_id: challenge_id.clone(),
            status: ChallengeStatus::Rejected,
            resolution_root: evidence_root(
                &scenario_id,
                "challenge-rejected-transfer-receipt-valid",
                &json!({ "challenge_id": challenge_id, "receipt_root": receipt.receipt_root }),
            ),
            resolved_height: challenge_resolved_height,
        })?;
        self.counters.challenges_resolved += 1;
        self.record_step(
            &scenario_id,
            StepKind::ChallengeResolved,
            "challenge_arbiter",
            challenge_resolved_height,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            Some(challenge_id.clone()),
            None,
            json!({ "challenge_id": challenge_id, "status": ChallengeStatus::Rejected.as_str() }),
        );

        let final_readiness = self
            .transfer_runtime
            .verify_transfer_exit_readiness(&self.spine, &transfer_id)?;
        self.record_step(
            &scenario_id,
            StepKind::TransferReadinessRechecked,
            "static_verifier",
            challenge_resolved_height + 1,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            None,
            None,
            json!({
                "readiness_report_id": final_readiness.report_id,
                "readiness_status": final_readiness.status.as_str(),
                "passed_checks": final_readiness.passed_checks,
                "failed_checks": final_readiness.failed_checks,
            }),
        );

        let settled_height =
            challenge_resolved_height + self.spine.config.forced_exit_delay_blocks + 4;
        let settlement_id = self.spine.settle_exit(ExitSettlementRequest {
            path_id: path_id.clone(),
            settlement_tx_root: scenario_root("settlement-tx", &transfer_id),
            release_certificate_root: scenario_root(
                "release-certificate",
                &receipt.exit_claim_root,
            ),
            final_private_state_root: scenario_root(
                "final-private-state",
                &receipt.private_state_root_after,
            ),
            settled_height,
        })?;
        self.counters.exits_settled += 1;
        self.record_step(
            &scenario_id,
            StepKind::ExitSettled,
            "settlement_adapter",
            settled_height,
            Some(path_id.clone()),
            Some(transfer_id.clone()),
            None,
            Some(settlement_id.clone()),
            json!({ "settlement_id": settlement_id, "settled_height": settled_height }),
        );

        self.record_claims(
            &scenario_id,
            &path_id,
            &transfer_id,
            &settlement_id,
            &receipt,
            &final_readiness,
        );
        let transcript_id = self.seal_transcript(
            &scenario_id,
            &path_id,
            &transfer_id,
            &settlement_id,
            receipt.privacy_set_size,
        )?;
        self.record_step(
            &scenario_id,
            StepKind::ScenarioTranscriptSealed,
            "transcript_sealer",
            settled_height + 2,
            Some(path_id),
            Some(transfer_id),
            None,
            Some(settlement_id),
            json!({ "transcript_id": transcript_id }),
        );
        self.refresh_roots();
        Ok(transcript_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "scenario_suite": self.config.scenario_suite,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "steps": self.steps.len(),
            "claims": self.claims.len(),
            "transcripts": self.transcripts.len(),
            "latest_transcript": self.transcripts.values().next_back().map(ScenarioTranscript::public_record),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn open_transfer_source_path(&mut self, scenario_id: &str) -> Result<(String, String)> {
        let watcher_quorum_id = self
            .spine
            .watcher_quorums
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet spine has no watcher quorum".to_string())?;
        let lock_txid = format!("{scenario_id}-transfer-lock");
        let path_id = self.spine.open_deposit_path(DepositLockRequest {
            monero_lock_txid: lock_txid.clone(),
            deposit_commitment: scenario_root("transfer-source-deposit", &lock_txid),
            amount: DEFAULT_DEVNET_SOURCE_AMOUNT,
            sender_viewtag_commitment: scenario_root("transfer-source-viewtag", &lock_txid),
            deposit_subaddress_commitment: scenario_root("transfer-source-subaddress", &lock_txid),
            privacy_set_size: self.config.min_privacy_set_size * 2,
            pq_authorization_root: scenario_root("transfer-source-pq-auth", &lock_txid),
            watcher_quorum_id: watcher_quorum_id.clone(),
            observed_monero_height: DEVNET_HEIGHT + self.spine.config.monero_finality_depth + 21,
            lane: BridgeLane::LowFee,
            user_fee_bps: self.transfer_runtime.config.max_transfer_fee_bps,
        })?;
        Ok((path_id, watcher_quorum_id))
    }

    fn certify_transfer_source_path(
        &mut self,
        path_id: &str,
        watcher_quorum_id: &str,
    ) -> Result<()> {
        self.spine.certify_deposit_lock(DepositCertificateRequest {
            path_id: path_id.to_string(),
            watcher_quorum_id: watcher_quorum_id.to_string(),
            certificate_root: scenario_root("transfer-source-certificate", path_id),
            monero_finality_depth: self.spine.config.monero_finality_depth,
            certified_height: DEVNET_HEIGHT + self.spine.config.monero_finality_depth + 22,
        })
    }

    fn mint_transfer_source_note(&mut self, path_id: &str) -> Result<()> {
        self.spine.mint_private_note(MintPrivateNoteRequest {
            path_id: path_id.to_string(),
            private_note_commitment: scenario_root("input-note", path_id),
            note_membership_root: scenario_root("input-membership", path_id),
            wallet_scan_hint_root: scenario_root("input-wallet-scan-hint", path_id),
            privacy_set_size: self.config.min_privacy_set_size * 2,
        })
    }

    fn transfer_request(&self, path_id: &str) -> BridgeBoundTransferRequest {
        BridgeBoundTransferRequest {
            path_id: path_id.to_string(),
            lane: TransferLane::ExitPrepared,
            input_note_commitment: scenario_root("input-note", path_id),
            input_note_membership_root: scenario_root("input-membership", path_id),
            input_note_nullifier: scenario_root("input-nullifier", path_id),
            sender_pq_authorization_root: scenario_root("sender-pq-auth", path_id),
            sender_view_key_policy_root: scenario_root("sender-view-policy", path_id),
            recipient_note_commitment: scenario_root("recipient-note", path_id),
            recipient_scan_hint_root: scenario_root("recipient-scan-hint", path_id),
            change_note_commitment: scenario_root("change-note", path_id),
            change_scan_hint_root: scenario_root("change-scan-hint", path_id),
            encrypted_amount_root: scenario_root("encrypted-amounts", path_id),
            balance_proof_root: scenario_root("balance-proof", path_id),
            transfer_amount: DEFAULT_DEVNET_TRANSFER_AMOUNT,
            change_amount: DEFAULT_DEVNET_CHANGE_AMOUNT,
            fee_amount: 21_000,
            fee_sponsor_root: scenario_root("fee-sponsor", path_id),
            sequencer_pq_root: scenario_root("sequencer-pq", path_id),
            proof_transcript_root: scenario_root("proof-transcript", path_id),
            payout_subaddress_commitment: scenario_root("payout-subaddress", path_id),
            exit_withdrawal_commitment: scenario_root("exit-withdrawal", path_id),
            exit_burn_nullifier: scenario_root("exit-burn-nullifier", path_id),
            exit_liquidity_root: scenario_root("exit-liquidity", path_id),
            exit_pq_authorization_root: scenario_root("exit-pq-auth", path_id),
            exit_amount: DEFAULT_DEVNET_EXIT_AMOUNT,
            privacy_set_size: self.config.min_privacy_set_size * 2,
            user_fee_bps: self.transfer_runtime.config.max_transfer_fee_bps,
            settlement_height: DEVNET_HEIGHT + 167,
        }
    }

    fn record_step(
        &mut self,
        scenario_id: &str,
        kind: StepKind,
        actor: &str,
        height: u64,
        path_id: Option<String>,
        transfer_id: Option<String>,
        challenge_id: Option<String>,
        settlement_id: Option<String>,
        evidence: Value,
    ) {
        let sequence = self.steps.len() as u64 + 1;
        let evidence_root = evidence_root(scenario_id, kind.as_str(), &evidence);
        let private_root = private_root(scenario_id, kind.as_str(), sequence);
        let step_id = step_id(scenario_id, kind, sequence, &evidence_root);
        self.steps.push(ScenarioStep {
            step_id,
            scenario_id: scenario_id.to_string(),
            sequence,
            kind,
            actor: actor.to_string(),
            height,
            path_id,
            transfer_id,
            challenge_id,
            settlement_id,
            private_root,
            evidence_root,
            spine_root_after: self.spine.state_root(),
            transfer_runtime_root_after: self.transfer_runtime.state_root(),
        });
        self.counters.steps_recorded += 1;
        self.refresh_roots();
    }

    fn record_claims(
        &mut self,
        scenario_id: &str,
        path_id: &str,
        transfer_id: &str,
        settlement_id: &str,
        receipt: &crate::monero_l2_pq_bridge_bound_private_transfer_receipt_runtime::PrivateTransferReceipt,
        readiness: &crate::monero_l2_pq_bridge_bound_private_transfer_receipt_runtime::TransferReadinessReport,
    ) {
        let path = self.spine.bridge_paths.get(path_id);
        let spine_receipt = self.spine.receipts.get(&receipt.action_receipt_id);
        let claim = self
            .transfer_runtime
            .exit_claims
            .get(&receipt.exit_claim_id);
        let claim_specs = [
            (
                ClaimKind::BridgeMintedNoteConsumed,
                self.transfer_runtime
                    .spent_input_nullifiers
                    .contains(&receipt.input_note_nullifier),
                "bridge-minted input note nullifier must be consumed by the transfer runtime",
                format!("nullifier_consumed={}", self.transfer_runtime.spent_input_nullifiers.contains(&receipt.input_note_nullifier)),
            ),
            (
                ClaimKind::TransferReceiptRecordedBySpine,
                spine_receipt
                    .map(|item| item.receipt_root == receipt.receipt_root)
                    .unwrap_or(false),
                "spine receipt table must contain the bridge-bound transfer receipt",
                format!("spine_receipt_present={}", spine_receipt.is_some()),
            ),
            (
                ClaimKind::TransferReceiptAnchoredBySpine,
                path.and_then(|item| item.bridge_checkpoint_root.as_ref())
                    == Some(&receipt.bridge_checkpoint_root),
                "bridge path checkpoint root must anchor the transfer receipt",
                format!(
                    "checkpoint_match={}",
                    path.and_then(|item| item.bridge_checkpoint_root.as_ref())
                        == Some(&receipt.bridge_checkpoint_root)
                ),
            ),
            (
                ClaimKind::ExitClaimMatchesTransferReceipt,
                claim
                    .map(|item| item.receipt_root == receipt.receipt_root)
                    .unwrap_or(false),
                "prepared exit claim must bind to the transfer receipt root",
                format!("exit_claim_present={}", claim.is_some()),
            ),
            (
                ClaimKind::ForcedExitRequestDerivedFromClaim,
                path.and_then(|item| item.withdrawal_commitment.as_ref())
                    == claim.map(|item| &item.withdrawal_commitment),
                "spine withdrawal request must be derived from the transfer exit claim",
                "withdrawal commitment matches prepared claim".to_string(),
            ),
            (
                ClaimKind::LivenessFailureCanArmForcedExit,
                path.and_then(|item| item.forced_exit_evidence_root.as_ref()).is_some(),
                "forced-exit liveness evidence must be recorded on the bridge path",
                format!(
                    "forced_exit_evidence_present={}",
                    path.and_then(|item| item.forced_exit_evidence_root.as_ref()).is_some()
                ),
            ),
            (
                ClaimKind::ChallengeWindowDoesNotBlockSettlement,
                self.spine
                    .challenges
                    .values()
                    .any(|item| item.path_id == path_id && item.status == ChallengeStatus::Rejected),
                "resolved rejected challenge must not block later forced-exit settlement",
                "rejected challenge found for transfer path".to_string(),
            ),
            (
                ClaimKind::SettlementReleasesAfterChallengeResolution,
                path.and_then(|item| item.settlement_id.as_deref()) == Some(settlement_id),
                "settlement id must be recorded after the challenge is resolved",
                format!("settlement_id={settlement_id}"),
            ),
            (
                ClaimKind::LowFeePrivacyPqBounds,
                receipt.privacy_set_size >= self.config.min_privacy_set_size
                    && receipt.user_fee_bps <= self.transfer_runtime.config.max_transfer_fee_bps
                    && readiness.status == TransferReportStatus::Passed,
                "transfer receipt must preserve privacy floor, low-fee cap, and PQ readiness",
                format!(
                    "privacy_set={}, fee_bps={}, readiness={}",
                    receipt.privacy_set_size,
                    receipt.user_fee_bps,
                    readiness.status.as_str()
                ),
            ),
            (
                ClaimKind::RootsOnlyTranscript,
                !receipt.receipt_root.is_empty()
                    && !receipt.output_note_root.is_empty()
                    && !receipt.exit_claim_root.is_empty(),
                "scenario transcript must expose roots and commitments, not plaintext wallet metadata",
                "receipt, output, and exit-claim roots are present".to_string(),
            ),
        ];
        for (kind, ok, requirement, observed) in claim_specs {
            let status = if ok {
                ClaimStatus::Proven
            } else {
                ClaimStatus::Failed
            };
            self.record_claim(
                scenario_id,
                kind,
                status,
                requirement,
                observed,
                json!({
                    "path_id": path_id,
                    "transfer_id": transfer_id,
                    "settlement_id": settlement_id,
                    "receipt_root": receipt.receipt_root,
                    "exit_claim_root": receipt.exit_claim_root,
                }),
            );
        }
    }

    fn record_claim(
        &mut self,
        scenario_id: &str,
        kind: ClaimKind,
        status: ClaimStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence: Value,
    ) {
        let evidence_root = evidence_root(scenario_id, kind.as_str(), &evidence);
        let claim_id = claim_id(scenario_id, kind, &evidence_root);
        let claim = ScenarioClaim {
            claim_id: claim_id.clone(),
            scenario_id: scenario_id.to_string(),
            kind,
            status,
            requirement: requirement.into(),
            observed: observed.into(),
            evidence_root,
        };
        self.claims.insert(claim_id, claim);
        self.counters.claims_recorded += 1;
        self.refresh_roots();
    }

    fn seal_transcript(
        &mut self,
        scenario_id: &str,
        path_id: &str,
        transfer_id: &str,
        settlement_id: &str,
        privacy_set_size: u64,
    ) -> Result<String> {
        let step_root = self.step_root_for_scenario(scenario_id);
        let claim_root = self.claim_root_for_scenario(scenario_id);
        let proven_claim_count = self
            .claims
            .values()
            .filter(|claim| claim.scenario_id == scenario_id && claim.status == ClaimStatus::Proven)
            .count() as u64;
        let watch_claim_count = self
            .claims
            .values()
            .filter(|claim| claim.scenario_id == scenario_id && claim.status == ClaimStatus::Watch)
            .count() as u64;
        let failed_claim_count = self
            .claims
            .values()
            .filter(|claim| claim.scenario_id == scenario_id && claim.status == ClaimStatus::Failed)
            .count() as u64;
        let step_count = self
            .steps
            .iter()
            .filter(|step| step.scenario_id == scenario_id)
            .count() as u64;
        let status = if failed_claim_count > 0 || step_count < self.config.min_steps {
            ScenarioStatus::Failed
        } else if watch_claim_count > 0 || proven_claim_count < self.config.min_proven_claims {
            ScenarioStatus::Watch
        } else {
            ScenarioStatus::Proven
        };
        let transcript_seed = json!({
            "scenario_id": scenario_id,
            "status": status.as_str(),
            "step_count": step_count,
            "proven_claim_count": proven_claim_count,
            "watch_claim_count": watch_claim_count,
            "failed_claim_count": failed_claim_count,
            "step_root": step_root,
            "claim_root": claim_root,
            "final_spine_root": self.spine.state_root(),
            "final_transfer_runtime_root": self.transfer_runtime.state_root(),
            "transfer_id": transfer_id,
            "path_id": path_id,
            "settlement_id": settlement_id,
        });
        let transcript_root = record_root("transcript_seed", &transcript_seed);
        let transcript_id = transcript_id(scenario_id, &transcript_root);
        let transcript = ScenarioTranscript {
            transcript_id: transcript_id.clone(),
            scenario_id: scenario_id.to_string(),
            status,
            step_count,
            proven_claim_count,
            watch_claim_count,
            failed_claim_count,
            step_root,
            claim_root,
            final_spine_root: self.spine.state_root(),
            final_transfer_runtime_root: self.transfer_runtime.state_root(),
            transfer_id: transfer_id.to_string(),
            path_id: path_id.to_string(),
            settlement_id: settlement_id.to_string(),
            privacy_set_size_observed: privacy_set_size,
            transcript_root,
        };
        self.transcripts.insert(transcript_id.clone(), transcript);
        if self.transcripts.len() > self.config.max_transcripts {
            if let Some(oldest) = self.transcripts.keys().next().cloned() {
                self.transcripts.remove(&oldest);
            }
        }
        self.counters.transcripts_sealed += 1;
        self.refresh_roots();
        Ok(transcript_id)
    }

    fn step_root_for_scenario(&self, scenario_id: &str) -> String {
        let records = self
            .steps
            .iter()
            .filter(|step| step.scenario_id == scenario_id)
            .map(ScenarioStep::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SCENARIO-STEPS",
            &records,
        )
    }

    fn claim_root_for_scenario(&self, scenario_id: &str) -> String {
        let records = self
            .claims
            .values()
            .filter(|claim| claim.scenario_id == scenario_id)
            .map(ScenarioClaim::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SCENARIO-CLAIMS",
            &records,
        )
    }

    fn refresh_roots(&mut self) {
        let step_records = self
            .steps
            .iter()
            .map(ScenarioStep::public_record)
            .collect::<Vec<_>>();
        let claim_records = self
            .claims
            .values()
            .map(ScenarioClaim::public_record)
            .collect::<Vec<_>>();
        let transcript_records = self
            .transcripts
            .values()
            .map(ScenarioTranscript::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            spine_root: self.spine.state_root(),
            transfer_runtime_root: self.transfer_runtime.state_root(),
            step_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EXIT-STEPS",
                &step_records,
            ),
            claim_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EXIT-CLAIMS",
                &claim_records,
            ),
            transcript_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-EXIT-TRANSCRIPTS",
                &transcript_records,
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

pub fn scenario_id(label: &str, initial_spine_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SCENARIO-ID",
        &[HashPart::Str(label), HashPart::Str(initial_spine_root)],
        32,
    )
}

pub fn step_id(scenario_id: &str, kind: StepKind, sequence: u64, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STEP-ID",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn claim_id(scenario_id: &str, kind: ClaimKind, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-CLAIM-ID",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn transcript_id(scenario_id: &str, transcript_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-TRANSCRIPT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(transcript_root)],
        32,
    )
}

pub fn scenario_root(label: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SCENARIO-ROOT",
        &[HashPart::Str(label), HashPart::Str(seed)],
        32,
    )
}

pub fn private_root(scenario_id: &str, label: &str, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-PRIVATE-ROOT",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn evidence_root(scenario_id: &str, label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-EVIDENCE-ROOT",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
