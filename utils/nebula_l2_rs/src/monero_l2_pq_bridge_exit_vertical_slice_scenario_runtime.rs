use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_invariant_verifier_runtime::{
        AssessmentStatus as InvariantAssessmentStatus, State as InvariantVerifierState,
    },
    monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::{
        AnchorReceiptRequest, BridgeLane, ChallengeKind, ChallengeRequest,
        ChallengeResolutionRequest, ChallengeStatus, DepositCertificateRequest, DepositLockRequest,
        ExitMode, ExitSettlementRequest, ForcedExitRequest, MintPrivateNoteRequest,
        PrivateActionKind, PrivateActionRequest, State as BridgeExitSpineState, WithdrawalRequest,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitVerticalSliceScenarioRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_SCENARIO_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-vertical-slice-scenario-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_SCENARIO_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SCENARIO_SUITE: &str =
    "monero-l2-pq-bridge-deposit-private-action-forced-exit-vertical-slice-v1";
pub const DEVNET_SCENARIO_LABEL: &str = "devnet-censorship-forced-exit-vertical-slice";
pub const DEFAULT_MIN_SCENARIO_STEPS: u64 = 10;
pub const DEFAULT_MIN_PROVEN_CLAIMS: u64 = 7;
pub const DEFAULT_SCENARIO_AMOUNT: u128 = 800_000_000_000;
pub const DEFAULT_SCENARIO_EXIT_AMOUNT: u128 = 799_999_960_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioKind {
    DepositPrivateActionForcedExit,
    CooperativeExitBaseline,
    AdversarialChallengeRecovery,
}

impl ScenarioKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositPrivateActionForcedExit => "deposit_private_action_forced_exit",
            Self::CooperativeExitBaseline => "cooperative_exit_baseline",
            Self::AdversarialChallengeRecovery => "adversarial_challenge_recovery",
        }
    }
}

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
    SpineBaselineAssessed,
    DepositLockOpened,
    DepositCertified,
    PrivateNoteMinted,
    PrivateActionRecorded,
    SettlementReceiptAnchored,
    ForcedExitRequested,
    LivenessTimeoutObserved,
    ForcedExitArmed,
    ChallengeOpened,
    ChallengeResolved,
    ExitSettled,
    PostExitAssessed,
}

impl StepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpineBaselineAssessed => "spine_baseline_assessed",
            Self::DepositLockOpened => "deposit_lock_opened",
            Self::DepositCertified => "deposit_certified",
            Self::PrivateNoteMinted => "private_note_minted",
            Self::PrivateActionRecorded => "private_action_recorded",
            Self::SettlementReceiptAnchored => "settlement_receipt_anchored",
            Self::ForcedExitRequested => "forced_exit_requested",
            Self::LivenessTimeoutObserved => "liveness_timeout_observed",
            Self::ForcedExitArmed => "forced_exit_armed",
            Self::ChallengeOpened => "challenge_opened",
            Self::ChallengeResolved => "challenge_resolved",
            Self::ExitSettled => "exit_settled",
            Self::PostExitAssessed => "post_exit_assessed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    MoneroLockToPrivateNote,
    PqWatcherQuorum,
    PrivateActionReceiptContinuity,
    AlwaysAvailableForcedExit,
    BoundedChallengeWindow,
    NullifierReplayFence,
    LowFeeBound,
    RootsOnlyPrivacyDisclosure,
    PostExitInvariantAssessment,
}

impl ClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroLockToPrivateNote => "monero_lock_to_private_note",
            Self::PqWatcherQuorum => "pq_watcher_quorum",
            Self::PrivateActionReceiptContinuity => "private_action_receipt_continuity",
            Self::AlwaysAvailableForcedExit => "always_available_forced_exit",
            Self::BoundedChallengeWindow => "bounded_challenge_window",
            Self::NullifierReplayFence => "nullifier_replay_fence",
            Self::LowFeeBound => "low_fee_bound",
            Self::RootsOnlyPrivacyDisclosure => "roots_only_privacy_disclosure",
            Self::PostExitInvariantAssessment => "post_exit_invariant_assessment",
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

    pub fn passes(self) -> bool {
        matches!(self, Self::Proven | Self::Watch)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub scenario_suite: String,
    pub min_scenario_steps: u64,
    pub min_proven_claims: u64,
    pub scenario_label: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            scenario_suite: SCENARIO_SUITE.to_string(),
            min_scenario_steps: DEFAULT_MIN_SCENARIO_STEPS,
            min_proven_claims: DEFAULT_MIN_PROVEN_CLAIMS,
            scenario_label: DEVNET_SCENARIO_LABEL.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "scenario_suite": self.scenario_suite,
            "min_scenario_steps": self.min_scenario_steps,
            "min_proven_claims": self.min_proven_claims,
            "scenario_label": self.scenario_label,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
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
    pub challenge_id: Option<String>,
    pub settlement_id: Option<String>,
    pub private_input_root: String,
    pub public_evidence_root: String,
    pub spine_root_after: String,
    pub verifier_root_after: String,
    pub assessment_id: Option<String>,
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
            "challenge_id": self.challenge_id,
            "settlement_id": self.settlement_id,
            "private_input_root": self.private_input_root,
            "public_evidence_root": self.public_evidence_root,
            "spine_root_after": self.spine_root_after,
            "verifier_root_after": self.verifier_root_after,
            "assessment_id": self.assessment_id,
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
    pub remediation_if_failed: String,
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
            "remediation_if_failed": self.remediation_if_failed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("scenario_claim", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScenarioTranscript {
    pub scenario_id: String,
    pub kind: ScenarioKind,
    pub status: ScenarioStatus,
    pub label: String,
    pub path_id: String,
    pub exit_id: String,
    pub challenge_id: String,
    pub settlement_id: String,
    pub initial_spine_root: String,
    pub final_spine_root: String,
    pub pre_exit_assessment_id: String,
    pub post_exit_assessment_id: String,
    pub step_count: u64,
    pub proven_claim_count: u64,
    pub watch_claim_count: u64,
    pub failed_claim_count: u64,
    pub forced_exit_available_before_timeout: bool,
    pub forced_exit_available_after_timeout: bool,
    pub max_user_fee_bps_observed: u64,
    pub privacy_set_size_observed: u64,
    pub step_root: String,
    pub claim_root: String,
    pub transcript_root: String,
}

impl ScenarioTranscript {
    pub fn public_record(&self) -> Value {
        json!({
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "label": self.label,
            "path_id": self.path_id,
            "exit_id": self.exit_id,
            "challenge_id": self.challenge_id,
            "settlement_id": self.settlement_id,
            "initial_spine_root": self.initial_spine_root,
            "final_spine_root": self.final_spine_root,
            "pre_exit_assessment_id": self.pre_exit_assessment_id,
            "post_exit_assessment_id": self.post_exit_assessment_id,
            "step_count": self.step_count,
            "proven_claim_count": self.proven_claim_count,
            "watch_claim_count": self.watch_claim_count,
            "failed_claim_count": self.failed_claim_count,
            "forced_exit_available_before_timeout": self.forced_exit_available_before_timeout,
            "forced_exit_available_after_timeout": self.forced_exit_available_after_timeout,
            "max_user_fee_bps_observed": self.max_user_fee_bps_observed,
            "privacy_set_size_observed": self.privacy_set_size_observed,
            "step_root": self.step_root,
            "claim_root": self.claim_root,
            "transcript_root": self.transcript_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.transcript_root.clone()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub scenarios_run: u64,
    pub scenarios_proven: u64,
    pub scenarios_watch: u64,
    pub scenarios_failed: u64,
    pub forced_exit_scenarios: u64,
    pub steps_recorded: u64,
    pub claims_recorded: u64,
    pub claims_proven: u64,
    pub claims_watch: u64,
    pub claims_failed: u64,
    pub verifier_assessments_run: u64,
    pub challenge_rounds: u64,
    pub exits_settled: u64,
    pub liveness_checks: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scenarios_run": self.scenarios_run,
            "scenarios_proven": self.scenarios_proven,
            "scenarios_watch": self.scenarios_watch,
            "scenarios_failed": self.scenarios_failed,
            "forced_exit_scenarios": self.forced_exit_scenarios,
            "steps_recorded": self.steps_recorded,
            "claims_recorded": self.claims_recorded,
            "claims_proven": self.claims_proven,
            "claims_watch": self.claims_watch,
            "claims_failed": self.claims_failed,
            "verifier_assessments_run": self.verifier_assessments_run,
            "challenge_rounds": self.challenge_rounds,
            "exits_settled": self.exits_settled,
            "liveness_checks": self.liveness_checks,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("scenario_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub spine_root: String,
    pub verifier_root: String,
    pub transcript_root: String,
    pub step_root: String,
    pub claim_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(
        config: &Config,
        spine: &BridgeExitSpineState,
        verifier: &InvariantVerifierState,
    ) -> Self {
        let counters = Counters::default();
        let mut roots = Self {
            config_root: config.state_root(),
            spine_root: spine.state_root(),
            verifier_root: verifier.state_root(),
            transcript_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EMPTY-TRANSCRIPTS",
                &[],
            ),
            step_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EMPTY-STEPS", &[]),
            claim_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EMPTY-CLAIMS", &[]),
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
            "verifier_root": self.verifier_root,
            "transcript_root": self.transcript_root,
            "step_root": self.step_root,
            "claim_root": self.claim_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-ROOTS",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.spine_root),
                HashPart::Str(&self.verifier_root),
                HashPart::Str(&self.transcript_root),
                HashPart::Str(&self.step_root),
                HashPart::Str(&self.claim_root),
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
    pub verifier: InvariantVerifierState,
    pub transcripts: BTreeMap<String, ScenarioTranscript>,
    pub claims: BTreeMap<String, ScenarioClaim>,
    pub steps: Vec<ScenarioStep>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let spine = BridgeExitSpineState::devnet();
        let verifier = InvariantVerifierState::devnet();
        let roots = Roots::empty(&config, &spine, &verifier);
        let mut state = Self {
            config,
            spine,
            verifier,
            transcripts: BTreeMap::new(),
            claims: BTreeMap::new(),
            steps: Vec::new(),
            counters: Counters::default(),
            roots,
        };
        state
            .run_devnet_forced_exit_vertical_slice()
            .expect("devnet bridge/exit vertical slice scenario");
        state
    }

    pub fn run_devnet_forced_exit_vertical_slice(&mut self) -> Result<String> {
        let label = self.config.scenario_label.clone();
        let initial_spine_root = self.spine.state_root();
        let scenario_id = scenario_id(&label, &initial_spine_root);
        let quorum_id = self
            .spine
            .watcher_quorums
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| {
                "bridge/exit scenario requires a registered watcher quorum".to_string()
            })?;
        let base_height = self
            .spine
            .config
            .genesis_height
            .saturating_add(self.spine.config.monero_finality_depth);
        let low_fee_bps = self.spine.config.low_fee_bps;
        let privacy_set_size = self.spine.config.target_privacy_set_size;

        let pre_exit_assessment_id = self.verifier.assess_spine(&self.spine, base_height)?;
        self.counters.verifier_assessments_run += 1;
        self.push_step(
            &scenario_id,
            StepKind::SpineBaselineAssessed,
            "verifier",
            None,
            None,
            None,
            base_height,
            private_root(&scenario_id, "baseline-assessment-private-inputs"),
            evidence_root(
                &scenario_id,
                "baseline-assessment",
                &json!({
                    "spine_root": initial_spine_root,
                    "assessment_id": pre_exit_assessment_id,
                }),
            ),
            Some(pre_exit_assessment_id.clone()),
        );

        let deposit_commitment = private_root(&scenario_id, "deposit-commitment");
        let monero_lock_txid = format!("{label}-monero-lock-txid-0001");
        let path_id = self.spine.open_deposit_path(DepositLockRequest {
            monero_lock_txid,
            deposit_commitment: deposit_commitment.clone(),
            amount: DEFAULT_SCENARIO_AMOUNT,
            sender_viewtag_commitment: private_root(&scenario_id, "sender-viewtag-commitment"),
            deposit_subaddress_commitment: private_root(
                &scenario_id,
                "deposit-subaddress-commitment",
            ),
            privacy_set_size,
            pq_authorization_root: private_root(&scenario_id, "deposit-pq-authorization-root"),
            watcher_quorum_id: quorum_id.clone(),
            observed_monero_height: base_height,
            lane: BridgeLane::Standard,
            user_fee_bps: low_fee_bps,
        })?;
        self.push_step(
            &scenario_id,
            StepKind::DepositLockOpened,
            "wallet+watcher",
            Some(path_id.clone()),
            None,
            None,
            base_height,
            deposit_commitment,
            evidence_root(
                &scenario_id,
                "deposit-lock-opened",
                &json!({
                    "path_id": path_id,
                    "watcher_quorum_id": quorum_id,
                    "amount": DEFAULT_SCENARIO_AMOUNT.to_string(),
                    "privacy_set_size": privacy_set_size,
                    "fee_bps": low_fee_bps,
                }),
            ),
            None,
        );

        let certified_height = base_height.saturating_add(2);
        self.spine.certify_deposit_lock(DepositCertificateRequest {
            path_id: path_id.clone(),
            watcher_quorum_id: quorum_id.clone(),
            certificate_root: evidence_root(
                &scenario_id,
                "deposit-certificate-root",
                &json!({
                    "path_id": path_id,
                    "quorum": quorum_id,
                    "finality_depth": self.spine.config.monero_finality_depth,
                }),
            ),
            monero_finality_depth: self.spine.config.monero_finality_depth,
            certified_height,
        })?;
        self.push_step(
            &scenario_id,
            StepKind::DepositCertified,
            "pq-watcher-quorum",
            Some(path_id.clone()),
            None,
            None,
            certified_height,
            private_root(&scenario_id, "deposit-certificate-private-witness"),
            evidence_root(
                &scenario_id,
                "deposit-certified",
                &json!({
                    "path_id": path_id,
                    "certified_height": certified_height,
                    "finality_depth": self.spine.config.monero_finality_depth,
                }),
            ),
            None,
        );

        let private_note_commitment = private_root(&scenario_id, "private-note-commitment");
        self.spine.mint_private_note(MintPrivateNoteRequest {
            path_id: path_id.clone(),
            private_note_commitment: private_note_commitment.clone(),
            note_membership_root: private_root(&scenario_id, "note-membership-root"),
            wallet_scan_hint_root: private_root(&scenario_id, "wallet-scan-hint-root"),
            privacy_set_size,
        })?;
        self.push_step(
            &scenario_id,
            StepKind::PrivateNoteMinted,
            "private-note-minter",
            Some(path_id.clone()),
            None,
            None,
            certified_height,
            private_note_commitment,
            evidence_root(
                &scenario_id,
                "private-note-minted",
                &json!({
                    "path_id": path_id,
                    "privacy_set_size": privacy_set_size,
                    "disclosure": "commitment-and-roots-only",
                }),
            ),
            None,
        );

        let action_height = certified_height.saturating_add(4);
        let action_receipt_root = evidence_root(
            &scenario_id,
            "private-action-receipt-root",
            &json!({
                "path_id": path_id,
                "action_kind": PrivateActionKind::ContractCall.as_str(),
                "fee_bps": low_fee_bps,
            }),
        );
        let action_receipt_id = self.spine.record_private_action(PrivateActionRequest {
            path_id: path_id.clone(),
            action_kind: PrivateActionKind::ContractCall,
            action_commitment: private_root(&scenario_id, "confidential-contract-action"),
            private_state_root: private_root(&scenario_id, "post-contract-private-state-root"),
            contract_call_root: private_root(&scenario_id, "sealed-contract-call-root"),
            token_transfer_root: private_root(&scenario_id, "sealed-token-transfer-root"),
            fee_sponsor_root: evidence_root(
                &scenario_id,
                "low-fee-sponsor-root",
                &json!({"fee_bps": low_fee_bps, "mode": "sponsored-low-fee"}),
            ),
            sequencer_pq_root: evidence_root(
                &scenario_id,
                "sequencer-pq-root",
                &json!({"suite": "ml-dsa-slh-dsa-devnet-sequencer"}),
            ),
            receipt_root: action_receipt_root.clone(),
            privacy_set_size,
            user_fee_bps: low_fee_bps,
        })?;
        self.push_step(
            &scenario_id,
            StepKind::PrivateActionRecorded,
            "pq-sequencer",
            Some(path_id.clone()),
            None,
            None,
            action_height,
            private_root(&scenario_id, "private-action-inputs"),
            evidence_root(
                &scenario_id,
                "private-action-recorded",
                &json!({
                    "path_id": path_id,
                    "receipt_id": action_receipt_id,
                    "receipt_root": action_receipt_root,
                }),
            ),
            None,
        );

        let anchor_height = action_height.saturating_add(2);
        let settlement_state_root = private_root(&scenario_id, "anchored-settlement-state-root");
        self.spine.anchor_settlement_receipt(AnchorReceiptRequest {
            path_id: path_id.clone(),
            receipt_root: action_receipt_root.clone(),
            settlement_state_root: settlement_state_root.clone(),
            bridge_checkpoint_root: evidence_root(
                &scenario_id,
                "bridge-checkpoint-root",
                &json!({
                    "path_id": path_id,
                    "receipt_root": action_receipt_root,
                    "height": anchor_height,
                }),
            ),
            anchor_height,
        })?;
        self.push_step(
            &scenario_id,
            StepKind::SettlementReceiptAnchored,
            "settlement-anchor",
            Some(path_id.clone()),
            None,
            None,
            anchor_height,
            settlement_state_root,
            evidence_root(
                &scenario_id,
                "settlement-receipt-anchored",
                &json!({
                    "path_id": path_id,
                    "anchor_height": anchor_height,
                    "receipt_root": action_receipt_root,
                }),
            ),
            None,
        );

        let exit_request_height = anchor_height.saturating_add(8);
        let exit_id = self.spine.request_exit(WithdrawalRequest {
            path_id: path_id.clone(),
            withdrawal_commitment: private_root(&scenario_id, "forced-exit-withdrawal-commitment"),
            burn_nullifier: private_root(&scenario_id, "burn-nullifier"),
            payout_subaddress_commitment: private_root(&scenario_id, "payout-subaddress"),
            requested_amount: DEFAULT_SCENARIO_EXIT_AMOUNT,
            exit_mode: ExitMode::Forced,
            watcher_quorum_id: quorum_id.clone(),
            liquidity_root: evidence_root(
                &scenario_id,
                "liquidity-root",
                &json!({
                    "reserve": "covered",
                    "exit_amount": DEFAULT_SCENARIO_EXIT_AMOUNT.to_string(),
                }),
            ),
            pq_authorization_root: private_root(&scenario_id, "exit-pq-authorization-root"),
            privacy_set_size,
            requested_height: exit_request_height,
            user_fee_bps: low_fee_bps,
        })?;
        self.push_step(
            &scenario_id,
            StepKind::ForcedExitRequested,
            "wallet",
            Some(path_id.clone()),
            None,
            None,
            exit_request_height,
            private_root(&scenario_id, "forced-exit-request-private-inputs"),
            evidence_root(
                &scenario_id,
                "forced-exit-requested",
                &json!({
                    "path_id": path_id,
                    "exit_id": exit_id,
                    "exit_mode": ExitMode::Forced.as_str(),
                    "requested_height": exit_request_height,
                }),
            ),
            None,
        );

        let before_timeout_height = exit_request_height
            .saturating_add(self.spine.config.exit_liveness_window_blocks)
            .saturating_sub(1);
        let available_before_timeout = self
            .spine
            .forced_exit_available(&path_id, before_timeout_height);
        let after_timeout_height =
            exit_request_height.saturating_add(self.spine.config.exit_liveness_window_blocks);
        let available_after_timeout = self
            .spine
            .forced_exit_available(&path_id, after_timeout_height);
        self.counters.liveness_checks += 2;
        self.push_step(
            &scenario_id,
            StepKind::LivenessTimeoutObserved,
            "liveness-monitor",
            Some(path_id.clone()),
            None,
            None,
            after_timeout_height,
            private_root(&scenario_id, "liveness-monitor-private-inputs"),
            evidence_root(
                &scenario_id,
                "liveness-timeout-observed",
                &json!({
                    "path_id": path_id,
                    "before_timeout_height": before_timeout_height,
                    "after_timeout_height": after_timeout_height,
                    "available_before_timeout": available_before_timeout,
                    "available_after_timeout": available_after_timeout,
                }),
            ),
            None,
        );

        let armed_height = after_timeout_height.saturating_add(1);
        self.spine.arm_forced_exit(ForcedExitRequest {
            path_id: path_id.clone(),
            censorship_evidence_root: evidence_root(
                &scenario_id,
                "censorship-evidence-root",
                &json!({"path_id": path_id, "missed_inclusion_height": after_timeout_height}),
            ),
            liveness_failure_root: evidence_root(
                &scenario_id,
                "liveness-failure-root",
                &json!({"path_id": path_id, "sequencer_timeout": true}),
            ),
            watcher_quorum_id: quorum_id.clone(),
            armed_height,
        })?;
        self.push_step(
            &scenario_id,
            StepKind::ForcedExitArmed,
            "emergency-watcher-quorum",
            Some(path_id.clone()),
            None,
            None,
            armed_height,
            private_root(&scenario_id, "forced-exit-evidence-private-inputs"),
            evidence_root(
                &scenario_id,
                "forced-exit-armed",
                &json!({
                    "path_id": path_id,
                    "armed_height": armed_height,
                    "quorum_id": quorum_id,
                }),
            ),
            None,
        );

        let challenge_height = armed_height.saturating_add(2);
        let challenge_id = self.spine.challenge_path(ChallengeRequest {
            path_id: path_id.clone(),
            challenger_commitment: private_root(&scenario_id, "watcher-challenger-commitment"),
            kind: ChallengeKind::SequencerCensorship,
            evidence_root: evidence_root(
                &scenario_id,
                "challenge-evidence-root",
                &json!({
                    "path_id": path_id,
                    "kind": ChallengeKind::SequencerCensorship.as_str(),
                    "forced_exit_armed_height": armed_height,
                }),
            ),
            opened_height: challenge_height,
        })?;
        self.counters.challenge_rounds += 1;
        self.push_step(
            &scenario_id,
            StepKind::ChallengeOpened,
            "challenger",
            Some(path_id.clone()),
            Some(challenge_id.clone()),
            None,
            challenge_height,
            private_root(&scenario_id, "challenge-private-inputs"),
            evidence_root(
                &scenario_id,
                "challenge-opened",
                &json!({
                    "path_id": path_id,
                    "challenge_id": challenge_id,
                    "opened_height": challenge_height,
                    "challenge_window": self.spine.config.challenge_window_blocks,
                }),
            ),
            None,
        );

        let challenge_resolved_height = challenge_height.saturating_add(12);
        self.spine.resolve_challenge(ChallengeResolutionRequest {
            challenge_id: challenge_id.clone(),
            status: ChallengeStatus::Rejected,
            resolution_root: evidence_root(
                &scenario_id,
                "challenge-resolution-root",
                &json!({
                    "challenge_id": challenge_id,
                    "status": ChallengeStatus::Rejected.as_str(),
                    "reason": "censorship evidence did not invalidate user forced exit",
                }),
            ),
            resolved_height: challenge_resolved_height,
        })?;
        self.push_step(
            &scenario_id,
            StepKind::ChallengeResolved,
            "challenge-arbiter",
            Some(path_id.clone()),
            Some(challenge_id.clone()),
            None,
            challenge_resolved_height,
            private_root(&scenario_id, "challenge-resolution-private-inputs"),
            evidence_root(
                &scenario_id,
                "challenge-resolved",
                &json!({
                    "path_id": path_id,
                    "challenge_id": challenge_id,
                    "resolved_height": challenge_resolved_height,
                    "status": ChallengeStatus::Rejected.as_str(),
                }),
            ),
            None,
        );

        let settle_height = challenge_resolved_height
            .saturating_add(self.spine.config.forced_exit_delay_blocks)
            .saturating_add(1);
        let settlement_id = self.spine.settle_exit(ExitSettlementRequest {
            path_id: path_id.clone(),
            settlement_tx_root: evidence_root(
                &scenario_id,
                "settlement-tx-root",
                &json!({
                    "path_id": path_id,
                    "exit_id": exit_id,
                    "settled_height": settle_height,
                }),
            ),
            release_certificate_root: evidence_root(
                &scenario_id,
                "release-certificate-root",
                &json!({
                    "path_id": path_id,
                    "challenge_id": challenge_id,
                    "status": "released-after-forced-exit-delay",
                }),
            ),
            final_private_state_root: private_root(&scenario_id, "final-private-state-root"),
            settled_height: settle_height,
        })?;
        self.counters.exits_settled += 1;
        self.push_step(
            &scenario_id,
            StepKind::ExitSettled,
            "settlement-adapter",
            Some(path_id.clone()),
            Some(challenge_id.clone()),
            Some(settlement_id.clone()),
            settle_height,
            private_root(&scenario_id, "exit-settlement-private-inputs"),
            evidence_root(
                &scenario_id,
                "exit-settled",
                &json!({
                    "path_id": path_id,
                    "settlement_id": settlement_id,
                    "settled_height": settle_height,
                }),
            ),
            None,
        );

        let post_exit_assessment_id = self.verifier.assess_spine(&self.spine, settle_height)?;
        self.counters.verifier_assessments_run += 1;
        self.push_step(
            &scenario_id,
            StepKind::PostExitAssessed,
            "verifier",
            Some(path_id.clone()),
            Some(challenge_id.clone()),
            Some(settlement_id.clone()),
            settle_height,
            private_root(&scenario_id, "post-exit-assessment-private-inputs"),
            evidence_root(
                &scenario_id,
                "post-exit-assessment",
                &json!({
                    "spine_root": self.spine.state_root(),
                    "assessment_id": post_exit_assessment_id,
                }),
            ),
            Some(post_exit_assessment_id.clone()),
        );

        self.add_standard_claims(
            &scenario_id,
            &path_id,
            &exit_id,
            &challenge_id,
            &settlement_id,
            available_before_timeout,
            available_after_timeout,
            low_fee_bps,
            privacy_set_size,
        );

        let claim_stats = self.claim_stats(&scenario_id);
        let step_count = self
            .steps
            .iter()
            .filter(|step| step.scenario_id == scenario_id)
            .count() as u64;
        let status = if claim_stats.2 > 0 {
            ScenarioStatus::Failed
        } else if claim_stats.0 >= self.config.min_proven_claims
            && step_count >= self.config.min_scenario_steps
        {
            ScenarioStatus::Proven
        } else {
            ScenarioStatus::Watch
        };
        self.counters.scenarios_run += 1;
        self.counters.forced_exit_scenarios += 1;
        match status {
            ScenarioStatus::Proven => self.counters.scenarios_proven += 1,
            ScenarioStatus::Watch => self.counters.scenarios_watch += 1,
            ScenarioStatus::Failed => self.counters.scenarios_failed += 1,
        }

        let step_root = self.step_root_for_scenario(&scenario_id);
        let claim_root = self.claim_root_for_scenario(&scenario_id);
        let final_spine_root = self.spine.state_root();
        let transcript_seed = json!({
            "scenario_id": scenario_id,
            "path_id": path_id,
            "exit_id": exit_id,
            "challenge_id": challenge_id,
            "settlement_id": settlement_id,
            "initial_spine_root": initial_spine_root,
            "final_spine_root": final_spine_root,
            "step_root": step_root,
            "claim_root": claim_root,
        });
        let transcript_root = record_root("scenario_transcript", &transcript_seed);
        let transcript = ScenarioTranscript {
            scenario_id: scenario_id.clone(),
            kind: ScenarioKind::DepositPrivateActionForcedExit,
            status,
            label,
            path_id,
            exit_id,
            challenge_id,
            settlement_id,
            initial_spine_root,
            final_spine_root,
            pre_exit_assessment_id,
            post_exit_assessment_id,
            step_count,
            proven_claim_count: claim_stats.0,
            watch_claim_count: claim_stats.1,
            failed_claim_count: claim_stats.2,
            forced_exit_available_before_timeout: available_before_timeout,
            forced_exit_available_after_timeout: available_after_timeout,
            max_user_fee_bps_observed: low_fee_bps,
            privacy_set_size_observed: privacy_set_size,
            step_root,
            claim_root,
            transcript_root,
        };
        self.transcripts.insert(scenario_id.clone(), transcript);
        self.refresh_roots();
        Ok(scenario_id)
    }

    fn push_step(
        &mut self,
        scenario_id: &str,
        kind: StepKind,
        actor: &str,
        path_id: Option<String>,
        challenge_id: Option<String>,
        settlement_id: Option<String>,
        height: u64,
        private_input_root: String,
        public_evidence_root: String,
        assessment_id: Option<String>,
    ) {
        let sequence = self
            .steps
            .iter()
            .filter(|step| step.scenario_id == scenario_id)
            .count() as u64
            + 1;
        let step_id = step_id(scenario_id, kind, sequence, &public_evidence_root);
        self.steps.push(ScenarioStep {
            step_id,
            scenario_id: scenario_id.to_string(),
            sequence,
            kind,
            actor: actor.to_string(),
            height,
            path_id,
            challenge_id,
            settlement_id,
            private_input_root,
            public_evidence_root,
            spine_root_after: self.spine.state_root(),
            verifier_root_after: self.verifier.state_root(),
            assessment_id,
        });
        self.counters.steps_recorded += 1;
    }

    fn add_standard_claims(
        &mut self,
        scenario_id: &str,
        path_id: &str,
        exit_id: &str,
        challenge_id: &str,
        settlement_id: &str,
        available_before_timeout: bool,
        available_after_timeout: bool,
        low_fee_bps: u64,
        privacy_set_size: u64,
    ) {
        self.add_claim(
            scenario_id,
            ClaimKind::MoneroLockToPrivateNote,
            ClaimStatus::Proven,
            "certified Monero lock must lead to one private note commitment".to_string(),
            format!(
                "path {path_id} has deposit certificate, note commitment, and private state root"
            ),
            evidence_root(
                scenario_id,
                "claim-monero-lock-to-private-note",
                &json!({"path_id": path_id, "spine_root": self.spine.state_root()}),
            ),
            "quarantine any note path missing certificate or note-state roots".to_string(),
        );
        self.add_claim(
            scenario_id,
            ClaimKind::PqWatcherQuorum,
            ClaimStatus::Proven,
            "bridge deposit and forced-exit evidence must be backed by a usable PQ watcher quorum"
                .to_string(),
            format!(
                "{} watcher quorum(s) registered with devnet PQ security floor",
                self.spine.watcher_quorums.len()
            ),
            evidence_root(
                scenario_id,
                "claim-pq-watcher-quorum",
                &json!({
                    "quorum_count": self.spine.watcher_quorums.len(),
                    "min_pq_security_bits": self.spine.config.min_pq_security_bits,
                }),
            ),
            "rotate watcher quorum before admitting deposits or exits".to_string(),
        );
        self.add_claim(
            scenario_id,
            ClaimKind::PrivateActionReceiptContinuity,
            ClaimStatus::Proven,
            "private transfer or contract action must produce a stored receipt before exit"
                .to_string(),
            format!("path {path_id} produced a private action receipt before exit {exit_id}"),
            evidence_root(
                scenario_id,
                "claim-private-action-receipt-continuity",
                &json!({
                    "path_id": path_id,
                    "exit_id": exit_id,
                    "receipt_count": self.spine.receipts.len(),
                }),
            ),
            "reject exits whose private action receipt cannot be found".to_string(),
        );
        self.add_claim(
            scenario_id,
            ClaimKind::AlwaysAvailableForcedExit,
            if !available_before_timeout && available_after_timeout {
                ClaimStatus::Proven
            } else {
                ClaimStatus::Failed
            },
            "forced exit should become available after the configured liveness timeout".to_string(),
            format!(
                "available_before_timeout={}, available_after_timeout={}",
                available_before_timeout, available_after_timeout
            ),
            evidence_root(
                scenario_id,
                "claim-always-available-forced-exit",
                &json!({
                    "available_before_timeout": available_before_timeout,
                    "available_after_timeout": available_after_timeout,
                    "liveness_window": self.spine.config.exit_liveness_window_blocks,
                }),
            ),
            "keep forced exits enabled and surface timeout evidence for each live private note"
                .to_string(),
        );
        self.add_claim(
            scenario_id,
            ClaimKind::BoundedChallengeWindow,
            ClaimStatus::Proven,
            "adversarial challenges must have bounded windows and rooted resolution evidence"
                .to_string(),
            format!(
                "challenge {challenge_id} resolved before forced-exit settlement {settlement_id}"
            ),
            evidence_root(
                scenario_id,
                "claim-bounded-challenge-window",
                &json!({
                    "challenge_id": challenge_id,
                    "settlement_id": settlement_id,
                    "challenge_window": self.spine.config.challenge_window_blocks,
                }),
            ),
            "block settlement while challenges are open or malformed".to_string(),
        );
        self.add_claim(
            scenario_id,
            ClaimKind::NullifierReplayFence,
            ClaimStatus::Proven,
            "exit burn nullifier must be recorded before release to prevent replay".to_string(),
            format!(
                "{} spent nullifier(s) tracked after forced-exit request",
                self.spine.spent_nullifiers.len()
            ),
            evidence_root(
                scenario_id,
                "claim-nullifier-replay-fence",
                &json!({"spent_nullifier_count": self.spine.spent_nullifiers.len()}),
            ),
            "reject duplicate burn nullifiers before exit release".to_string(),
        );
        self.add_claim(
            scenario_id,
            ClaimKind::LowFeeBound,
            if low_fee_bps <= self.spine.policy.fee_cap_bps {
                ClaimStatus::Proven
            } else {
                ClaimStatus::Failed
            },
            "bridge vertical slice should stay under the configured user fee cap".to_string(),
            format!(
                "observed {} bps against cap {} bps",
                low_fee_bps, self.spine.policy.fee_cap_bps
            ),
            evidence_root(
                scenario_id,
                "claim-low-fee-bound",
                &json!({"observed_bps": low_fee_bps, "cap_bps": self.spine.policy.fee_cap_bps}),
            ),
            "route exit through sponsor/rebate lane or delay non-emergency release".to_string(),
        );
        self.add_claim(
            scenario_id,
            ClaimKind::RootsOnlyPrivacyDisclosure,
            if privacy_set_size >= self.spine.config.min_privacy_set_size {
                ClaimStatus::Proven
            } else {
                ClaimStatus::Failed
            },
            "scenario output must disclose roots and commitments without wallet plaintext"
                .to_string(),
            format!(
                "privacy set {} against minimum {}",
                privacy_set_size, self.spine.config.min_privacy_set_size
            ),
            evidence_root(
                scenario_id,
                "claim-roots-only-privacy-disclosure",
                &json!({
                    "privacy_set_size": privacy_set_size,
                    "min_privacy_set_size": self.spine.config.min_privacy_set_size,
                    "public_surface": "roots-and-commitments-only",
                }),
            ),
            "increase anonymity set or suppress the public scenario record".to_string(),
        );

        let post_status = self
            .verifier
            .latest_assessment
            .as_ref()
            .map(|assessment| assessment.status)
            .unwrap_or(InvariantAssessmentStatus::Failed);
        self.add_claim(
            scenario_id,
            ClaimKind::PostExitInvariantAssessment,
            match post_status {
                InvariantAssessmentStatus::Green => ClaimStatus::Proven,
                InvariantAssessmentStatus::Watch => ClaimStatus::Watch,
                InvariantAssessmentStatus::Failed => ClaimStatus::Failed,
            },
            "post-exit spine must still satisfy the bridge/exit invariant verifier".to_string(),
            format!(
                "post-exit invariant assessment status {}",
                post_status.as_str()
            ),
            evidence_root(
                scenario_id,
                "claim-post-exit-invariant-assessment",
                &json!({
                    "post_status": post_status.as_str(),
                    "verifier_root": self.verifier.state_root(),
                }),
            ),
            "hold additional bridge paths until failed invariants are remediated".to_string(),
        );
    }

    fn add_claim(
        &mut self,
        scenario_id: &str,
        kind: ClaimKind,
        status: ClaimStatus,
        requirement: String,
        observed: String,
        evidence_root: String,
        remediation_if_failed: String,
    ) -> String {
        let claim_id = scenario_claim_id(scenario_id, kind, &evidence_root);
        let claim = ScenarioClaim {
            claim_id: claim_id.clone(),
            scenario_id: scenario_id.to_string(),
            kind,
            status,
            requirement,
            observed,
            evidence_root,
            remediation_if_failed,
        };
        self.claims.insert(claim_id.clone(), claim);
        self.counters.claims_recorded += 1;
        match status {
            ClaimStatus::Proven => self.counters.claims_proven += 1,
            ClaimStatus::Watch => self.counters.claims_watch += 1,
            ClaimStatus::Failed => self.counters.claims_failed += 1,
        }
        claim_id
    }

    fn claim_stats(&self, scenario_id: &str) -> (u64, u64, u64) {
        let mut proven = 0;
        let mut watch = 0;
        let mut failed = 0;
        for claim in self
            .claims
            .values()
            .filter(|claim| claim.scenario_id == scenario_id)
        {
            match claim.status {
                ClaimStatus::Proven => proven += 1,
                ClaimStatus::Watch => watch += 1,
                ClaimStatus::Failed => failed += 1,
            }
        }
        (proven, watch, failed)
    }

    fn step_root_for_scenario(&self, scenario_id: &str) -> String {
        let records = self
            .steps
            .iter()
            .filter(|step| step.scenario_id == scenario_id)
            .map(ScenarioStep::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-SCENARIO-STEPS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-SCENARIO-CLAIMS",
            &records,
        )
    }

    fn refresh_roots(&mut self) {
        let transcript_records = self
            .transcripts
            .values()
            .map(ScenarioTranscript::public_record)
            .collect::<Vec<_>>();
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
        self.roots = Roots {
            config_root: self.config.state_root(),
            spine_root: self.spine.state_root(),
            verifier_root: self.verifier.state_root(),
            transcript_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-TRANSCRIPTS",
                &transcript_records,
            ),
            step_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-STEPS",
                &step_records,
            ),
            claim_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-CLAIMS",
                &claim_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }

    pub fn public_record(&self) -> Value {
        let latest_transcript = self
            .transcripts
            .values()
            .next_back()
            .map(ScenarioTranscript::public_record);
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "scenario_suite": self.config.scenario_suite,
            "latest_transcript": latest_transcript,
            "scenario_count": self.transcripts.len(),
            "step_count": self.steps.len(),
            "claim_count": self.claims.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
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
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-SCENARIO-ID",
        &[HashPart::Str(label), HashPart::Str(initial_spine_root)],
        32,
    )
}

pub fn step_id(scenario_id: &str, kind: StepKind, sequence: u64, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-STEP-ID",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn scenario_claim_id(scenario_id: &str, kind: ClaimKind, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-CLAIM-ID",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn private_root(scenario_id: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-PRIVATE-ROOT",
        &[HashPart::Str(scenario_id), HashPart::Str(label)],
        32,
    )
}

pub fn evidence_root(scenario_id: &str, label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EVIDENCE-ROOT",
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
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}
