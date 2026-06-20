use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeForcedExitVerticalDryRunRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_FORCED_EXIT_VERTICAL_DRY_RUN_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-forced-exit-vertical-dry-run-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_FORCED_EXIT_VERTICAL_DRY_RUN_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str = "monero-l2-pq-bridge-exit-canonical-user-escape-forced-exit-vertical-dry-run";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub lane_id: String,
    pub dry_run_suite: String,
    pub bridge_asset_id: String,
    pub min_evidence_count: u64,
    pub min_transition_count: u64,
    pub require_process_feed_handoff: u64,
    pub require_mismatch_fixture_hold: u64,
    pub require_wallet_action: u64,
    pub require_privacy_boundary: u64,
    pub expected_release_allowed: u64,
    pub hold_release_until_heavy_gate: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            lane_id: "canonical_user_escape_forced_exit_vertical_dry_run".to_string(),
            dry_run_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-forced-exit-dry-run-suite-v1"
                    .to_string(),
            bridge_asset_id: "wxmr-devnet".to_string(),
            min_evidence_count: 8,
            min_transition_count: 7,
            require_process_feed_handoff: 1,
            require_mismatch_fixture_hold: 1,
            require_wallet_action: 1,
            require_privacy_boundary: 1,
            expected_release_allowed: 0,
            hold_release_until_heavy_gate: 1,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "lane_id": self.lane_id,
            "dry_run_suite": self.dry_run_suite,
            "bridge_asset_id": self.bridge_asset_id,
            "min_evidence_count": self.min_evidence_count,
            "min_transition_count": self.min_transition_count,
            "require_process_feed_handoff": self.require_process_feed_handoff,
            "require_mismatch_fixture_hold": self.require_mismatch_fixture_hold,
            "require_wallet_action": self.require_wallet_action,
            "require_privacy_boundary": self.require_privacy_boundary,
            "expected_release_allowed": self.expected_release_allowed,
            "hold_release_until_heavy_gate": self.hold_release_until_heavy_gate,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerticalStep {
    DepositLock,
    PrivateNote,
    SettlementReceipt,
    ReleaseVerification,
    ProcessFeedHandoff,
    AdversarialMismatch,
    WalletRunbook,
    ReleaseHold,
}

impl VerticalStep {
    pub fn ordered() -> [Self; 8] {
        [
            Self::DepositLock,
            Self::PrivateNote,
            Self::SettlementReceipt,
            Self::ReleaseVerification,
            Self::ProcessFeedHandoff,
            Self::AdversarialMismatch,
            Self::WalletRunbook,
            Self::ReleaseHold,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::PrivateNote => "private_note",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ReleaseVerification => "release_verification",
            Self::ProcessFeedHandoff => "process_feed_handoff",
            Self::AdversarialMismatch => "adversarial_mismatch",
            Self::WalletRunbook => "wallet_runbook",
            Self::ReleaseHold => "release_hold",
        }
    }

    pub fn module_name(self) -> &'static str {
        match self {
            Self::DepositLock => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_deposit_lock_proof_runtime"
            }
            Self::PrivateNote => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_private_note_transfer_proof_runtime"
            }
            Self::SettlementReceipt => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_proof_runtime"
            }
            Self::ReleaseVerification => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime"
            }
            Self::ProcessFeedHandoff => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime"
            }
            Self::AdversarialMismatch => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_mismatch_fixture_runtime"
            }
            Self::WalletRunbook => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_proof_runtime"
            }
            Self::ReleaseHold => {
                "monero_l2_pq_bridge_exit_canonical_user_escape_forced_exit_release_hold_composite"
            }
        }
    }

    pub fn evidence_role(self) -> &'static str {
        match self {
            Self::DepositLock => "monero_lock_and_watcher_quorum_evidence",
            Self::PrivateNote => "private_l2_note_transfer_evidence",
            Self::SettlementReceipt => "settlement_receipt_binding_evidence",
            Self::ReleaseVerification => "release_authorization_evidence",
            Self::ProcessFeedHandoff => "process_feed_to_reconciliation_handoff_evidence",
            Self::AdversarialMismatch => "mismatch_fixture_release_hold_evidence",
            Self::WalletRunbook => "wallet_visible_user_escape_evidence",
            Self::ReleaseHold => "fail_closed_release_hold_evidence",
        }
    }

    pub fn privacy_boundary(self) -> &'static str {
        match self {
            Self::DepositLock => "amount_and_address_commitments_only",
            Self::PrivateNote => "encrypted_note_roots_only",
            Self::SettlementReceipt => "receipt_roots_without_spend_graph",
            Self::ReleaseVerification => "pq_authorization_root_without_secret_key",
            Self::ProcessFeedHandoff => "feed_roots_without_raw_wallet_observations",
            Self::AdversarialMismatch => "fault_digest_roots_without_user_linkage",
            Self::WalletRunbook => "wallet_action_roots_without_view_key_material",
            Self::ReleaseHold => "decision_roots_without_raw_bridge_metadata",
        }
    }

    pub fn wallet_visible(self) -> u64 {
        match self {
            Self::WalletRunbook | Self::ReleaseHold => 1,
            Self::DepositLock
            | Self::PrivateNote
            | Self::SettlementReceipt
            | Self::ReleaseVerification
            | Self::ProcessFeedHandoff
            | Self::AdversarialMismatch => 0,
        }
    }

    pub fn release_hold_required(self) -> u64 {
        match self {
            Self::AdversarialMismatch | Self::ReleaseHold => 1,
            Self::DepositLock
            | Self::PrivateNote
            | Self::SettlementReceipt
            | Self::ReleaseVerification
            | Self::ProcessFeedHandoff
            | Self::WalletRunbook => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunEvidence {
    pub ordinal: u64,
    pub step: VerticalStep,
    pub step_id: String,
    pub module_name: String,
    pub evidence_role: String,
    pub state_root: String,
    pub public_record_root: String,
    pub privacy_boundary: String,
    pub wallet_visible: u64,
    pub required: u64,
    pub release_hold_required: u64,
    pub evidence_root: String,
}

impl DryRunEvidence {
    pub fn devnet(step: VerticalStep, ordinal: u64) -> Self {
        let state_root = step_state_root(step);
        let public_record_root = record_root(
            &format!("{}-public-record", step.as_str()),
            &step_public_record(step),
        );
        let evidence_root = domain_hash(
            &format!("{DOMAIN}:evidence"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(ordinal),
                HashPart::Str(step.as_str()),
                HashPart::Str(step.module_name()),
                HashPart::Str(step.evidence_role()),
                HashPart::Str(&state_root),
                HashPart::Str(&public_record_root),
                HashPart::Str(step.privacy_boundary()),
                HashPart::U64(step.wallet_visible()),
                HashPart::U64(1),
                HashPart::U64(step.release_hold_required()),
            ],
            32,
        );

        Self {
            ordinal,
            step,
            step_id: step.as_str().to_string(),
            module_name: step.module_name().to_string(),
            evidence_role: step.evidence_role().to_string(),
            state_root,
            public_record_root,
            privacy_boundary: step.privacy_boundary().to_string(),
            wallet_visible: step.wallet_visible(),
            required: 1,
            release_hold_required: step.release_hold_required(),
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "step": self.step.as_str(),
            "step_id": self.step_id,
            "module_name": self.module_name,
            "evidence_role": self.evidence_role,
            "state_root": self.state_root,
            "public_record_root": self.public_record_root,
            "privacy_boundary": self.privacy_boundary,
            "wallet_visible": self.wallet_visible,
            "required": self.required,
            "release_hold_required": self.release_hold_required,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunTransition {
    pub ordinal: u64,
    pub from_step: VerticalStep,
    pub to_step: VerticalStep,
    pub from_evidence_root: String,
    pub to_evidence_root: String,
    pub transition_kind: String,
    pub required: u64,
    pub transition_root: String,
}

impl DryRunTransition {
    pub fn devnet(ordinal: u64, from: &DryRunEvidence, to: &DryRunEvidence) -> Self {
        let transition_kind = transition_kind(from.step, to.step).to_string();
        let transition_root = domain_hash(
            &format!("{DOMAIN}:transition"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(ordinal),
                HashPart::Str(from.step.as_str()),
                HashPart::Str(to.step.as_str()),
                HashPart::Str(&from.evidence_root),
                HashPart::Str(&to.evidence_root),
                HashPart::Str(&transition_kind),
                HashPart::U64(1),
            ],
            32,
        );

        Self {
            ordinal,
            from_step: from.step,
            to_step: to.step,
            from_evidence_root: from.evidence_root.clone(),
            to_evidence_root: to.evidence_root.clone(),
            transition_kind,
            required: 1,
            transition_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "from_step": self.from_step.as_str(),
            "to_step": self.to_step.as_str(),
            "from_evidence_root": self.from_evidence_root,
            "to_evidence_root": self.to_evidence_root,
            "transition_kind": self.transition_kind,
            "required": self.required,
            "transition_root": self.transition_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedExitDecision {
    pub evidence_count: u64,
    pub transition_count: u64,
    pub process_feed_handoff_present: u64,
    pub mismatch_fixture_present: u64,
    pub wallet_action_present: u64,
    pub privacy_boundary_present: u64,
    pub release_hold_present: u64,
    pub release_allowed: u64,
    pub dry_run_status: String,
    pub release_hold_reason: String,
    pub decision_root: String,
}

impl ForcedExitDecision {
    pub fn new(
        config: &Config,
        evidence: &[DryRunEvidence],
        transitions: &[DryRunTransition],
    ) -> Self {
        let evidence_count = evidence.len() as u64;
        let transition_count = transitions.len() as u64;
        let process_feed_handoff_present = present_flag(evidence_has_step(
            evidence,
            VerticalStep::ProcessFeedHandoff,
        ));
        let mismatch_fixture_present = present_flag(evidence_has_step(
            evidence,
            VerticalStep::AdversarialMismatch,
        ));
        let wallet_action_present = present_flag(evidence_has_wallet_action(evidence));
        let privacy_boundary_present = present_flag(evidence_has_privacy_boundary(evidence));
        let release_hold_present = present_flag(evidence_has_release_hold(evidence));
        let evidence_bound = present_flag(evidence_count >= config.min_evidence_count);
        let transitions_bound = present_flag(transition_count >= config.min_transition_count);
        let release_allowed = 0;
        let dry_run_status = if evidence_bound == 1
            && transitions_bound == 1
            && process_feed_handoff_present >= config.require_process_feed_handoff
            && mismatch_fixture_present >= config.require_mismatch_fixture_hold
            && wallet_action_present >= config.require_wallet_action
            && privacy_boundary_present >= config.require_privacy_boundary
            && release_hold_present == 1
            && release_allowed == config.expected_release_allowed
        {
            "dry_run_bound_release_held"
        } else {
            "dry_run_gap_release_held"
        }
        .to_string();
        let release_hold_reason =
            "forced exit dry run binds evidence roots, process feeds, mismatch fixtures, and wallet-visible action; release remains held until heavy runtime gates execute"
                .to_string();
        let decision_root = domain_hash(
            &format!("{DOMAIN}:decision"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.lane_id),
                HashPart::U64(evidence_count),
                HashPart::U64(transition_count),
                HashPart::U64(process_feed_handoff_present),
                HashPart::U64(mismatch_fixture_present),
                HashPart::U64(wallet_action_present),
                HashPart::U64(privacy_boundary_present),
                HashPart::U64(release_hold_present),
                HashPart::U64(release_allowed),
                HashPart::Str(&dry_run_status),
                HashPart::Str(&release_hold_reason),
            ],
            32,
        );

        Self {
            evidence_count,
            transition_count,
            process_feed_handoff_present,
            mismatch_fixture_present,
            wallet_action_present,
            privacy_boundary_present,
            release_hold_present,
            release_allowed,
            dry_run_status,
            release_hold_reason,
            decision_root,
        }
    }

    pub fn fallback(config: &Config, reason: &str) -> Self {
        let dry_run_status = "dry_run_construction_gap_release_held".to_string();
        let release_hold_reason = format!(
            "forced exit dry run construction gap was recorded with release held: {}",
            reason
        );
        let decision_root = domain_hash(
            &format!("{DOMAIN}:fallback-decision"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.lane_id),
                HashPart::Str(&dry_run_status),
                HashPart::Str(&release_hold_reason),
            ],
            32,
        );

        Self {
            evidence_count: 0,
            transition_count: 0,
            process_feed_handoff_present: 0,
            mismatch_fixture_present: 0,
            wallet_action_present: 0,
            privacy_boundary_present: 0,
            release_hold_present: 1,
            release_allowed: 0,
            dry_run_status,
            release_hold_reason,
            decision_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_count": self.evidence_count,
            "transition_count": self.transition_count,
            "process_feed_handoff_present": self.process_feed_handoff_present,
            "mismatch_fixture_present": self.mismatch_fixture_present,
            "wallet_action_present": self.wallet_action_present,
            "privacy_boundary_present": self.privacy_boundary_present,
            "release_hold_present": self.release_hold_present,
            "release_allowed": self.release_allowed,
            "dry_run_status": self.dry_run_status,
            "release_hold_reason": self.release_hold_reason,
            "decision_root": self.decision_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub evidence: Vec<DryRunEvidence>,
    pub transitions: Vec<DryRunTransition>,
    pub decision: ForcedExitDecision,
    pub evidence_root: String,
    pub transition_root: String,
    pub wallet_action_root: String,
    pub privacy_boundary_root: String,
    pub release_hold_root: String,
    pub vertical_dry_run_root: String,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        validate_config(&config)?;

        let evidence = VerticalStep::ordered()
            .iter()
            .enumerate()
            .map(|(index, step)| DryRunEvidence::devnet(*step, index as u64 + 1))
            .collect::<Vec<_>>();
        let transitions = evidence
            .windows(2)
            .enumerate()
            .map(|(index, pair)| DryRunTransition::devnet(index as u64 + 1, &pair[0], &pair[1]))
            .collect::<Vec<_>>();
        let decision = ForcedExitDecision::new(&config, &evidence, &transitions);
        let evidence_root = evidence_vector_root(&evidence);
        let transition_root = transition_vector_root(&transitions);
        let wallet_action_root = wallet_action_root(&config, &evidence, &decision);
        let privacy_boundary_root = privacy_boundary_root(&config, &evidence, &decision);
        let release_hold_root =
            release_hold_root(&config, &decision, &evidence_root, &transition_root);
        let vertical_dry_run_root = vertical_dry_run_root(
            &config,
            &decision,
            &evidence_root,
            &transition_root,
            &wallet_action_root,
            &privacy_boundary_root,
            &release_hold_root,
        );

        Ok(Self {
            config,
            evidence,
            transitions,
            decision,
            evidence_root,
            transition_root,
            wallet_action_root,
            privacy_boundary_root,
            release_hold_root,
            vertical_dry_run_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::default()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_forced_exit_vertical_dry_run_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "evidence_root": self.evidence_root,
            "transition_root": self.transition_root,
            "wallet_action_root": self.wallet_action_root,
            "privacy_boundary_root": self.privacy_boundary_root,
            "release_hold_root": self.release_hold_root,
            "vertical_dry_run_root": self.vertical_dry_run_root,
            "decision": self.decision.public_record(),
            "evidence": self
                .evidence
                .iter()
                .map(DryRunEvidence::public_record)
                .collect::<Vec<_>>(),
            "transitions": self
                .transitions
                .iter()
                .map(DryRunTransition::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "state",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "config_root": self.config.state_root(),
                "evidence_root": self.evidence_root,
                "transition_root": self.transition_root,
                "wallet_action_root": self.wallet_action_root,
                "privacy_boundary_root": self.privacy_boundary_root,
                "release_hold_root": self.release_hold_root,
                "vertical_dry_run_root": self.vertical_dry_run_root,
                "decision_root": self.decision.decision_root,
            }),
        )
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

fn step_state_root(step: VerticalStep) -> String {
    match step {
        VerticalStep::DepositLock => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_deposit_lock_proof_runtime::state_root()
        }
        VerticalStep::PrivateNote => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_private_note_transfer_proof_runtime::state_root()
        }
        VerticalStep::SettlementReceipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_proof_runtime::state_root()
        }
        VerticalStep::ReleaseVerification => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime::state_root()
        }
        VerticalStep::ProcessFeedHandoff => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime::state_root()
        }
        VerticalStep::AdversarialMismatch => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_mismatch_fixture_runtime::state_root()
        }
        VerticalStep::WalletRunbook => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_proof_runtime::state_root()
        }
        VerticalStep::ReleaseHold => release_hold_composite_source_root(),
    }
}

fn step_public_record(step: VerticalStep) -> Value {
    match step {
        VerticalStep::DepositLock => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_deposit_lock_proof_runtime::public_record()
        }
        VerticalStep::PrivateNote => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_private_note_transfer_proof_runtime::public_record()
        }
        VerticalStep::SettlementReceipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_settlement_receipt_proof_runtime::public_record()
        }
        VerticalStep::ReleaseVerification => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime::public_record()
        }
        VerticalStep::ProcessFeedHandoff => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime::public_record()
        }
        VerticalStep::AdversarialMismatch => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_mismatch_fixture_runtime::public_record()
        }
        VerticalStep::WalletRunbook => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_proof_runtime::public_record()
        }
        VerticalStep::ReleaseHold => release_hold_composite_public_record(),
    }
}

fn release_hold_composite_source_root() -> String {
    domain_hash(
        &format!("{DOMAIN}:release-hold-composite-source"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime::state_root()),
            HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime::state_root()),
            HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_mismatch_fixture_runtime::state_root()),
            HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_proof_runtime::state_root()),
            HashPart::U64(0),
        ],
        32,
    )
}

fn release_hold_composite_public_record() -> Value {
    json!({
        "kind": "forced_exit_release_hold_composite",
        "release_allowed": 0,
        "release_verification_root": crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime::state_root(),
        "process_feed_handoff_root": crate::monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime::state_root(),
        "adversarial_mismatch_root": crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_mismatch_fixture_runtime::state_root(),
        "wallet_runbook_root": crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_proof_runtime::state_root(),
    })
}

fn transition_kind(from: VerticalStep, to: VerticalStep) -> &'static str {
    match (from, to) {
        (VerticalStep::DepositLock, VerticalStep::PrivateNote) => {
            "locked_xmr_mints_private_l2_note_commitment"
        }
        (VerticalStep::PrivateNote, VerticalStep::SettlementReceipt) => {
            "private_note_action_emits_settlement_receipt"
        }
        (VerticalStep::SettlementReceipt, VerticalStep::ReleaseVerification) => {
            "settlement_receipt_binds_release_verification"
        }
        (VerticalStep::ReleaseVerification, VerticalStep::ProcessFeedHandoff) => {
            "release_verification_crosschecks_process_feed_handoff"
        }
        (VerticalStep::ProcessFeedHandoff, VerticalStep::AdversarialMismatch) => {
            "process_feed_handoff_faces_mismatch_fixture"
        }
        (VerticalStep::AdversarialMismatch, VerticalStep::WalletRunbook) => {
            "mismatch_fixture_routes_wallet_escape_action"
        }
        (VerticalStep::WalletRunbook, VerticalStep::ReleaseHold) => {
            "wallet_escape_action_keeps_release_held_until_heavy_gate"
        }
        _ => "noncanonical_transition_release_held",
    }
}

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id != CHAIN_ID {
        return Err("config chain_id must match crate chain id".to_string());
    }
    if config.min_evidence_count < VerticalStep::ordered().len() as u64 {
        return Err("min evidence count must cover all dry-run evidence steps".to_string());
    }
    if config.min_transition_count < VerticalStep::ordered().len() as u64 - 1 {
        return Err("min transition count must cover the full dry-run path".to_string());
    }
    if config.expected_release_allowed != 0 {
        return Err("dry run must keep release disallowed until heavy gates execute".to_string());
    }
    if config.hold_release_until_heavy_gate != 1 {
        return Err("dry run must hold release until heavy gates execute".to_string());
    }
    Ok(())
}

fn evidence_has_step(evidence: &[DryRunEvidence], step: VerticalStep) -> bool {
    evidence.iter().any(|item| item.step == step)
}

fn evidence_has_wallet_action(evidence: &[DryRunEvidence]) -> bool {
    evidence.iter().any(|item| item.wallet_visible == 1)
}

fn evidence_has_privacy_boundary(evidence: &[DryRunEvidence]) -> bool {
    evidence
        .iter()
        .all(|item| non_empty_flag(&item.privacy_boundary) == 1)
}

fn evidence_has_release_hold(evidence: &[DryRunEvidence]) -> bool {
    evidence.iter().any(|item| item.release_hold_required == 1)
}

fn present_flag(value: bool) -> u64 {
    if value {
        1
    } else {
        0
    }
}

fn non_empty_flag(value: &str) -> u64 {
    if value.is_empty() {
        0
    } else {
        1
    }
}

fn evidence_vector_root(evidence: &[DryRunEvidence]) -> String {
    let leaves = evidence
        .iter()
        .map(DryRunEvidence::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:evidence-root"), &leaves)
}

fn transition_vector_root(transitions: &[DryRunTransition]) -> String {
    let leaves = transitions
        .iter()
        .map(DryRunTransition::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:transition-root"), &leaves)
}

fn wallet_action_root(
    config: &Config,
    evidence: &[DryRunEvidence],
    decision: &ForcedExitDecision,
) -> String {
    let wallet_evidence_roots = evidence
        .iter()
        .filter(|item| item.wallet_visible == 1)
        .map(|item| item.evidence_root.clone())
        .collect::<Vec<_>>();
    let wallet_leaf_root = merkle_root(
        &format!("{DOMAIN}:wallet-action-leaf-root"),
        &wallet_evidence_roots
            .iter()
            .map(|root| json!({ "wallet_visible_evidence_root": root }))
            .collect::<Vec<_>>(),
    );

    domain_hash(
        &format!("{DOMAIN}:wallet-action"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.lane_id),
            HashPart::Str(&wallet_leaf_root),
            HashPart::U64(decision.wallet_action_present),
            HashPart::U64(config.require_wallet_action),
        ],
        32,
    )
}

fn privacy_boundary_root(
    config: &Config,
    evidence: &[DryRunEvidence],
    decision: &ForcedExitDecision,
) -> String {
    let leaves = evidence
        .iter()
        .map(|item| {
            json!({
                "step": item.step.as_str(),
                "privacy_boundary": item.privacy_boundary,
                "public_record_root": item.public_record_root,
            })
        })
        .collect::<Vec<_>>();
    let boundary_leaf_root = merkle_root(&format!("{DOMAIN}:privacy-boundary-leaf-root"), &leaves);

    domain_hash(
        &format!("{DOMAIN}:privacy-boundary"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.lane_id),
            HashPart::Str(&boundary_leaf_root),
            HashPart::U64(decision.privacy_boundary_present),
            HashPart::U64(config.require_privacy_boundary),
        ],
        32,
    )
}

fn release_hold_root(
    config: &Config,
    decision: &ForcedExitDecision,
    evidence_root: &str,
    transition_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.lane_id),
            HashPart::Str(evidence_root),
            HashPart::Str(transition_root),
            HashPart::Str(&decision.decision_root),
            HashPart::U64(decision.release_hold_present),
            HashPart::U64(decision.release_allowed),
            HashPart::U64(config.hold_release_until_heavy_gate),
        ],
        32,
    )
}

fn vertical_dry_run_root(
    config: &Config,
    decision: &ForcedExitDecision,
    evidence_root: &str,
    transition_root: &str,
    wallet_action_root: &str,
    privacy_boundary_root: &str,
    release_hold_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:vertical-dry-run"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.lane_id),
            HashPart::Str(&config.dry_run_suite),
            HashPart::Str(evidence_root),
            HashPart::Str(transition_root),
            HashPart::Str(wallet_action_root),
            HashPart::Str(privacy_boundary_root),
            HashPart::Str(release_hold_root),
            HashPart::Str(&decision.decision_root),
            HashPart::U64(decision.release_allowed),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:record"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let evidence = Vec::new();
    let transitions = Vec::new();
    let decision = ForcedExitDecision::fallback(&config, &reason);
    let evidence_root = evidence_vector_root(&evidence);
    let transition_root = transition_vector_root(&transitions);
    let wallet_action_root = wallet_action_root(&config, &evidence, &decision);
    let privacy_boundary_root = privacy_boundary_root(&config, &evidence, &decision);
    let release_hold_root = release_hold_root(&config, &decision, &evidence_root, &transition_root);
    let vertical_dry_run_root = vertical_dry_run_root(
        &config,
        &decision,
        &evidence_root,
        &transition_root,
        &wallet_action_root,
        &privacy_boundary_root,
        &release_hold_root,
    );

    State {
        config,
        evidence,
        transitions,
        decision,
        evidence_root,
        transition_root,
        wallet_action_root,
        privacy_boundary_root,
        release_hold_root,
        vertical_dry_run_root,
    }
}
