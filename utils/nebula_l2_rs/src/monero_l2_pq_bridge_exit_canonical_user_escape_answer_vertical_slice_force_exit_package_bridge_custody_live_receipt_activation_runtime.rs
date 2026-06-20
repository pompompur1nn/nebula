use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageBridgeCustodyLiveReceiptActivationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-bridge-custody-live-receipt-activation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_LIVE_RECEIPT_ACTIVATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ACTIVATION_SUITE: &str =
    "monero-l2-pq-force-exit-package-bridge-custody-live-receipt-activation-v1";
pub const DEFAULT_MIN_CUSTODY_SIGNERS: u64 = 4;
pub const DEFAULT_MIN_MONERO_OBSERVERS: u64 = 3;
pub const DEFAULT_MIN_RESERVE_HANDOFFS: u64 = 2;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REQUIRED_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MAX_OBSERVATION_LAG: u64 = 12;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub activation_suite: String,
    pub min_custody_signers: u64,
    pub min_monero_observers: u64,
    pub min_reserve_handoffs: u64,
    pub challenge_window_blocks: u64,
    pub required_confirmations: u64,
    pub max_observation_lag: u64,
    pub require_signer_custody_quorum: bool,
    pub require_monero_release_observation: bool,
    pub require_reserve_handoff: bool,
    pub require_challenge_window_lock: bool,
    pub require_zero_mismatch_holds: bool,
    pub fail_closed_on_missing_root: bool,
    pub fail_closed_on_any_mismatch: bool,
    pub hold_release_until_activation: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            activation_suite: ACTIVATION_SUITE.to_string(),
            min_custody_signers: DEFAULT_MIN_CUSTODY_SIGNERS,
            min_monero_observers: DEFAULT_MIN_MONERO_OBSERVERS,
            min_reserve_handoffs: DEFAULT_MIN_RESERVE_HANDOFFS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            required_confirmations: DEFAULT_REQUIRED_CONFIRMATIONS,
            max_observation_lag: DEFAULT_MAX_OBSERVATION_LAG,
            require_signer_custody_quorum: true,
            require_monero_release_observation: true,
            require_reserve_handoff: true,
            require_challenge_window_lock: true,
            require_zero_mismatch_holds: true,
            fail_closed_on_missing_root: true,
            fail_closed_on_any_mismatch: true,
            hold_release_until_activation: true,
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
            "activation_suite": self.activation_suite,
            "min_custody_signers": self.min_custody_signers,
            "min_monero_observers": self.min_monero_observers,
            "min_reserve_handoffs": self.min_reserve_handoffs,
            "challenge_window_blocks": self.challenge_window_blocks,
            "required_confirmations": self.required_confirmations,
            "max_observation_lag": self.max_observation_lag,
            "require_signer_custody_quorum": self.require_signer_custody_quorum,
            "require_monero_release_observation": self.require_monero_release_observation,
            "require_reserve_handoff": self.require_reserve_handoff,
            "require_challenge_window_lock": self.require_challenge_window_lock,
            "require_zero_mismatch_holds": self.require_zero_mismatch_holds,
            "fail_closed_on_missing_root": self.fail_closed_on_missing_root,
            "fail_closed_on_any_mismatch": self.fail_closed_on_any_mismatch,
            "hold_release_until_activation": self.hold_release_until_activation,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    Activated,
    Held,
    Rejected,
}

impl ActivationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activated => "activated",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldKind {
    None,
    MissingSignerQuorum,
    MissingMoneroObservation,
    ReserveHandoffGap,
    ChallengeWindowLocked,
    MismatchDetected,
}

impl HoldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MissingSignerQuorum => "missing_signer_quorum",
            Self::MissingMoneroObservation => "missing_monero_observation",
            Self::ReserveHandoffGap => "reserve_handoff_gap",
            Self::ChallengeWindowLocked => "challenge_window_locked",
            Self::MismatchDetected => "mismatch_detected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedVerdict {
    Clear,
    Engaged,
}

impl FailClosedVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Engaged => "engaged",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodySignerAttestation {
    pub signer_id: String,
    pub release_id: String,
    pub custody_epoch: u64,
    pub signer_commitment_root: String,
    pub custody_receipt_root: String,
    pub pq_signature_root: String,
    pub key_rotation_root: String,
    pub accepted: bool,
}

impl CustodySignerAttestation {
    pub fn new(
        signer_label: &str,
        release_id: &str,
        custody_epoch: u64,
        signer_commitment_root: &str,
        custody_receipt_root: &str,
        pq_signature_root: &str,
        key_rotation_root: &str,
        accepted: bool,
    ) -> Self {
        Self {
            signer_id: deterministic_id(
                "custody-signer",
                &[signer_label, release_id, signer_commitment_root],
            ),
            release_id: release_id.to_string(),
            custody_epoch,
            signer_commitment_root: signer_commitment_root.to_string(),
            custody_receipt_root: custody_receipt_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            key_rotation_root: key_rotation_root.to_string(),
            accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "release_id": self.release_id,
            "custody_epoch": self.custody_epoch,
            "signer_commitment_root": self.signer_commitment_root,
            "custody_receipt_root": self.custody_receipt_root,
            "pq_signature_root": self.pq_signature_root,
            "key_rotation_root": self.key_rotation_root,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroReleaseObservation {
    pub observation_id: String,
    pub observer_id: String,
    pub release_id: String,
    pub monero_network: String,
    pub txid_root: String,
    pub destination_view_root: String,
    pub amount_commitment_root: String,
    pub observed_height: u64,
    pub confirmed_height: u64,
    pub confirmations: u64,
    pub accepted: bool,
}

impl MoneroReleaseObservation {
    pub fn new(
        observer_label: &str,
        release_id: &str,
        monero_network: &str,
        txid_root: &str,
        destination_view_root: &str,
        amount_commitment_root: &str,
        observed_height: u64,
        confirmed_height: u64,
        confirmations: u64,
        accepted: bool,
    ) -> Self {
        Self {
            observation_id: deterministic_id(
                "monero-observation",
                &[observer_label, release_id, txid_root],
            ),
            observer_id: deterministic_id("monero-observer", &[observer_label, monero_network]),
            release_id: release_id.to_string(),
            monero_network: monero_network.to_string(),
            txid_root: txid_root.to_string(),
            destination_view_root: destination_view_root.to_string(),
            amount_commitment_root: amount_commitment_root.to_string(),
            observed_height,
            confirmed_height,
            confirmations,
            accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "observer_id": self.observer_id,
            "release_id": self.release_id,
            "monero_network": self.monero_network,
            "txid_root": self.txid_root,
            "destination_view_root": self.destination_view_root,
            "amount_commitment_root": self.amount_commitment_root,
            "observed_height": self.observed_height,
            "confirmed_height": self.confirmed_height,
            "confirmations": self.confirmations,
            "observation_lag": self.confirmed_height.saturating_sub(self.observed_height),
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveHandoff {
    pub handoff_id: String,
    pub release_id: String,
    pub source_reserve_root: String,
    pub destination_reserve_root: String,
    pub liability_root: String,
    pub handoff_receipt_root: String,
    pub activated_at_height: u64,
    pub accepted: bool,
}

impl ReserveHandoff {
    pub fn new(
        release_id: &str,
        source_reserve_root: &str,
        destination_reserve_root: &str,
        liability_root: &str,
        handoff_receipt_root: &str,
        activated_at_height: u64,
        accepted: bool,
    ) -> Self {
        Self {
            handoff_id: deterministic_id(
                "reserve-handoff",
                &[release_id, source_reserve_root, destination_reserve_root],
            ),
            release_id: release_id.to_string(),
            source_reserve_root: source_reserve_root.to_string(),
            destination_reserve_root: destination_reserve_root.to_string(),
            liability_root: liability_root.to_string(),
            handoff_receipt_root: handoff_receipt_root.to_string(),
            activated_at_height,
            accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handoff_id": self.handoff_id,
            "release_id": self.release_id,
            "source_reserve_root": self.source_reserve_root,
            "destination_reserve_root": self.destination_reserve_root,
            "liability_root": self.liability_root,
            "handoff_receipt_root": self.handoff_receipt_root,
            "activated_at_height": self.activated_at_height,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeWindowCustodyLock {
    pub lock_id: String,
    pub release_id: String,
    pub custody_lock_root: String,
    pub challenge_root: String,
    pub opened_at_height: u64,
    pub unlock_height: u64,
    pub observed_height: u64,
    pub lock_active: bool,
}

impl ChallengeWindowCustodyLock {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "release_id": self.release_id,
            "custody_lock_root": self.custody_lock_root,
            "challenge_root": self.challenge_root,
            "opened_at_height": self.opened_at_height,
            "unlock_height": self.unlock_height,
            "observed_height": self.observed_height,
            "lock_active": self.lock_active,
            "window_elapsed": self.observed_height >= self.unlock_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MismatchHold {
    pub hold_id: String,
    pub release_id: String,
    pub hold_kind: HoldKind,
    pub policy_root: String,
    pub observed_root: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub active: bool,
}

impl MismatchHold {
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "release_id": self.release_id,
            "hold_kind": self.hold_kind.as_str(),
            "policy_root": self.policy_root,
            "observed_root": self.observed_root,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub custody_signer_count: u64,
    pub accepted_custody_signer_count: u64,
    pub monero_observation_count: u64,
    pub accepted_monero_observation_count: u64,
    pub reserve_handoff_count: u64,
    pub accepted_reserve_handoff_count: u64,
    pub challenge_lock_count: u64,
    pub active_challenge_lock_count: u64,
    pub mismatch_hold_count: u64,
    pub active_mismatch_hold_count: u64,
}

impl Counters {
    pub fn new(
        custody_signers: &[CustodySignerAttestation],
        monero_observations: &[MoneroReleaseObservation],
        reserve_handoffs: &[ReserveHandoff],
        challenge_locks: &[ChallengeWindowCustodyLock],
        mismatch_holds: &[MismatchHold],
    ) -> Self {
        Self {
            custody_signer_count: custody_signers.len() as u64,
            accepted_custody_signer_count: count_where(custody_signers, |item| item.accepted),
            monero_observation_count: monero_observations.len() as u64,
            accepted_monero_observation_count: count_where(monero_observations, |item| {
                item.accepted
            }),
            reserve_handoff_count: reserve_handoffs.len() as u64,
            accepted_reserve_handoff_count: count_where(reserve_handoffs, |item| item.accepted),
            challenge_lock_count: challenge_locks.len() as u64,
            active_challenge_lock_count: count_where(challenge_locks, |item| item.lock_active),
            mismatch_hold_count: mismatch_holds.len() as u64,
            active_mismatch_hold_count: count_where(mismatch_holds, |item| item.active),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "custody_signer_count": self.custody_signer_count,
            "accepted_custody_signer_count": self.accepted_custody_signer_count,
            "monero_observation_count": self.monero_observation_count,
            "accepted_monero_observation_count": self.accepted_monero_observation_count,
            "reserve_handoff_count": self.reserve_handoff_count,
            "accepted_reserve_handoff_count": self.accepted_reserve_handoff_count,
            "challenge_lock_count": self.challenge_lock_count,
            "active_challenge_lock_count": self.active_challenge_lock_count,
            "mismatch_hold_count": self.mismatch_hold_count,
            "active_mismatch_hold_count": self.active_mismatch_hold_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub custody_signer_root: String,
    pub monero_release_observation_root: String,
    pub reserve_handoff_root: String,
    pub challenge_window_lock_root: String,
    pub mismatch_hold_root: String,
    pub activation_verdict_root: String,
    pub fail_closed_root: String,
    pub live_receipt_activation_root: String,
}

impl Roots {
    pub fn new(
        custody_signers: &[CustodySignerAttestation],
        monero_observations: &[MoneroReleaseObservation],
        reserve_handoffs: &[ReserveHandoff],
        challenge_locks: &[ChallengeWindowCustodyLock],
        mismatch_holds: &[MismatchHold],
    ) -> Self {
        Self {
            custody_signer_root: vector_record_root(
                "custody-signer-attestations",
                &custody_signers
                    .iter()
                    .map(CustodySignerAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            monero_release_observation_root: vector_record_root(
                "monero-release-observations",
                &monero_observations
                    .iter()
                    .map(MoneroReleaseObservation::public_record)
                    .collect::<Vec<_>>(),
            ),
            reserve_handoff_root: vector_record_root(
                "reserve-handoffs",
                &reserve_handoffs
                    .iter()
                    .map(ReserveHandoff::public_record)
                    .collect::<Vec<_>>(),
            ),
            challenge_window_lock_root: vector_record_root(
                "challenge-window-custody-locks",
                &challenge_locks
                    .iter()
                    .map(ChallengeWindowCustodyLock::public_record)
                    .collect::<Vec<_>>(),
            ),
            mismatch_hold_root: vector_record_root(
                "mismatch-holds",
                &mismatch_holds
                    .iter()
                    .map(MismatchHold::public_record)
                    .collect::<Vec<_>>(),
            ),
            activation_verdict_root: String::new(),
            fail_closed_root: String::new(),
            live_receipt_activation_root: String::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "custody_signer_root": self.custody_signer_root,
            "monero_release_observation_root": self.monero_release_observation_root,
            "reserve_handoff_root": self.reserve_handoff_root,
            "challenge_window_lock_root": self.challenge_window_lock_root,
            "mismatch_hold_root": self.mismatch_hold_root,
            "activation_verdict_root": self.activation_verdict_root,
            "fail_closed_root": self.fail_closed_root,
            "live_receipt_activation_root": self.live_receipt_activation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActivationVerdict {
    pub signer_quorum_met: bool,
    pub monero_observation_met: bool,
    pub reserve_handoff_met: bool,
    pub challenge_window_clear: bool,
    pub mismatch_holds_clear: bool,
    pub fail_closed_verdict: FailClosedVerdict,
    pub activation_status: ActivationStatus,
    pub release_authorized: bool,
    pub hold_kind: HoldKind,
    pub production_answer: String,
    pub user_escape_answer: String,
    pub verdict_root: String,
}

impl ActivationVerdict {
    pub fn new(config: &Config, roots: &Roots, counters: &Counters) -> Self {
        let signer_quorum_met =
            counters.accepted_custody_signer_count >= config.min_custody_signers;
        let monero_observation_met =
            counters.accepted_monero_observation_count >= config.min_monero_observers;
        let reserve_handoff_met =
            counters.accepted_reserve_handoff_count >= config.min_reserve_handoffs;
        let challenge_window_clear = counters.active_challenge_lock_count == 0;
        let mismatch_holds_clear = counters.active_mismatch_hold_count == 0;
        let required_roots_present = !roots.custody_signer_root.is_empty()
            && !roots.monero_release_observation_root.is_empty()
            && !roots.reserve_handoff_root.is_empty()
            && !roots.challenge_window_lock_root.is_empty()
            && !roots.mismatch_hold_root.is_empty();
        let required_checks_met =
            optional_requirement(config.require_signer_custody_quorum, signer_quorum_met)
                && optional_requirement(
                    config.require_monero_release_observation,
                    monero_observation_met,
                )
                && optional_requirement(config.require_reserve_handoff, reserve_handoff_met)
                && optional_requirement(
                    config.require_challenge_window_lock,
                    challenge_window_clear,
                )
                && optional_requirement(config.require_zero_mismatch_holds, mismatch_holds_clear);
        let fail_closed = (config.fail_closed_on_missing_root && !required_roots_present)
            || (config.fail_closed_on_any_mismatch && !mismatch_holds_clear)
            || !required_checks_met;
        let fail_closed_verdict = if fail_closed {
            FailClosedVerdict::Engaged
        } else {
            FailClosedVerdict::Clear
        };
        let release_authorized = required_checks_met && !fail_closed;
        let activation_status = if release_authorized {
            ActivationStatus::Activated
        } else if fail_closed {
            ActivationStatus::Rejected
        } else {
            ActivationStatus::Held
        };
        let hold_kind = first_hold_kind(
            signer_quorum_met,
            monero_observation_met,
            reserve_handoff_met,
            challenge_window_clear,
            mismatch_holds_clear,
        );
        let production_answer = if release_authorized {
            "activate_bridge_custody_live_receipt".to_string()
        } else {
            "hold_bridge_custody_live_receipt_activation".to_string()
        };
        let user_escape_answer = if release_authorized {
            "force_exit_release_policy_may_release_after_live_receipt_activation".to_string()
        } else {
            "force_exit_release_policy_remains_fail_closed_for_user_escape".to_string()
        };
        let verdict_root = activation_verdict_root(
            config,
            roots,
            counters,
            fail_closed_verdict,
            activation_status,
            hold_kind,
            release_authorized,
        );
        Self {
            signer_quorum_met,
            monero_observation_met,
            reserve_handoff_met,
            challenge_window_clear,
            mismatch_holds_clear,
            fail_closed_verdict,
            activation_status,
            release_authorized,
            hold_kind,
            production_answer,
            user_escape_answer,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signer_quorum_met": self.signer_quorum_met,
            "monero_observation_met": self.monero_observation_met,
            "reserve_handoff_met": self.reserve_handoff_met,
            "challenge_window_clear": self.challenge_window_clear,
            "mismatch_holds_clear": self.mismatch_holds_clear,
            "fail_closed_verdict": self.fail_closed_verdict.as_str(),
            "activation_status": self.activation_status.as_str(),
            "release_authorized": self.release_authorized,
            "hold_kind": self.hold_kind.as_str(),
            "production_answer": self.production_answer,
            "user_escape_answer": self.user_escape_answer,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub custody_signers: Vec<CustodySignerAttestation>,
    pub monero_observations: Vec<MoneroReleaseObservation>,
    pub reserve_handoffs: Vec<ReserveHandoff>,
    pub challenge_locks: Vec<ChallengeWindowCustodyLock>,
    pub mismatch_holds: Vec<MismatchHold>,
    pub roots: Roots,
    pub counters: Counters,
    pub verdict: ActivationVerdict,
}

impl State {
    pub fn new(
        config: Config,
        custody_signers: Vec<CustodySignerAttestation>,
        monero_observations: Vec<MoneroReleaseObservation>,
        reserve_handoffs: Vec<ReserveHandoff>,
        challenge_locks: Vec<ChallengeWindowCustodyLock>,
        mismatch_holds: Vec<MismatchHold>,
    ) -> Result<Self> {
        validate_config(&config)?;
        let counters = Counters::new(
            &custody_signers,
            &monero_observations,
            &reserve_handoffs,
            &challenge_locks,
            &mismatch_holds,
        );
        let mut roots = Roots::new(
            &custody_signers,
            &monero_observations,
            &reserve_handoffs,
            &challenge_locks,
            &mismatch_holds,
        );
        let verdict = ActivationVerdict::new(&config, &roots, &counters);
        roots.activation_verdict_root = record_root("activation-verdict", &verdict.public_record());
        roots.fail_closed_root = record_root(
            "fail-closed",
            &json!({
                "fail_closed_verdict": verdict.fail_closed_verdict.as_str(),
                "activation_status": verdict.activation_status.as_str(),
                "hold_kind": verdict.hold_kind.as_str(),
                "release_authorized": verdict.release_authorized,
            }),
        );
        roots.live_receipt_activation_root =
            live_receipt_activation_root(&config, &roots, &counters, &verdict);
        Ok(Self {
            config,
            custody_signers,
            monero_observations,
            reserve_handoffs,
            challenge_locks,
            mismatch_holds,
            roots,
            counters,
            verdict,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "custody_signers": self.custody_signers.iter().map(CustodySignerAttestation::public_record).collect::<Vec<_>>(),
            "monero_observations": self.monero_observations.iter().map(MoneroReleaseObservation::public_record).collect::<Vec<_>>(),
            "reserve_handoffs": self.reserve_handoffs.iter().map(ReserveHandoff::public_record).collect::<Vec<_>>(),
            "challenge_locks": self.challenge_locks.iter().map(ChallengeWindowCustodyLock::public_record).collect::<Vec<_>>(),
            "mismatch_holds": self.mismatch_holds.iter().map(MismatchHold::public_record).collect::<Vec<_>>(),
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "verdict": self.verdict.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-CUSTODY-LIVE-RECEIPT-ACTIVATION-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let release_id = deterministic_id("devnet-release", &["force-exit-package", "bridge-custody"]);
    let custody_signers = ["alpha", "bravo", "charlie", "delta"]
        .iter()
        .map(|label| {
            CustodySignerAttestation::new(
                label,
                &release_id,
                78,
                &sample_root("signer-commitment", label),
                &sample_root("custody-receipt", label),
                &sample_root("pq-signature", label),
                &sample_root("key-rotation", label),
                true,
            )
        })
        .collect::<Vec<_>>();
    let monero_observations = ["watcher-a", "watcher-b", "watcher-c"]
        .iter()
        .map(|label| {
            MoneroReleaseObservation::new(
                label,
                &release_id,
                "stagenet",
                &sample_root("release-txid", "0001"),
                &sample_root("destination-view", "user-escape"),
                &sample_root("amount-commitment", "release"),
                452_100,
                452_118,
                18,
                true,
            )
        })
        .collect::<Vec<_>>();
    let reserve_handoffs = ["primary-reserve", "fallback-reserve"]
        .iter()
        .map(|label| {
            ReserveHandoff::new(
                &release_id,
                &sample_root("source-reserve", label),
                &sample_root("destination-reserve", label),
                &sample_root("liability", label),
                &sample_root("handoff-receipt", label),
                91_240,
                true,
            )
        })
        .collect::<Vec<_>>();
    let custody_lock_root = sample_root("custody-lock", "release");
    let challenge_root = sample_root("challenge-root", "clear");
    let challenge_locks = vec![ChallengeWindowCustodyLock {
        lock_id: deterministic_id(
            "challenge-lock",
            &[&release_id, &custody_lock_root, &challenge_root],
        ),
        release_id: release_id.clone(),
        custody_lock_root,
        challenge_root,
        opened_at_height: 90_500,
        unlock_height: 91_220,
        observed_height: 91_240,
        lock_active: false,
    }];
    let mismatch_holds = Vec::new();
    let counters = Counters::new(
        &custody_signers,
        &monero_observations,
        &reserve_handoffs,
        &challenge_locks,
        &mismatch_holds,
    );
    let mut roots = Roots::new(
        &custody_signers,
        &monero_observations,
        &reserve_handoffs,
        &challenge_locks,
        &mismatch_holds,
    );
    let verdict = ActivationVerdict::new(&config, &roots, &counters);
    roots.activation_verdict_root = record_root("activation-verdict", &verdict.public_record());
    roots.fail_closed_root = record_root("fail-closed", &verdict.public_record());
    roots.live_receipt_activation_root =
        live_receipt_activation_root(&config, &roots, &counters, &verdict);
    State {
        config,
        custody_signers,
        monero_observations,
        reserve_handoffs,
        challenge_locks,
        mismatch_holds,
        roots,
        counters,
        verdict,
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-LIVE-RECEIPT-ACTIVATION-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn vector_record_root(kind: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            json!({
                "chain_id": CHAIN_ID,
                "kind": kind,
                "index": index,
                "record": record,
                "record_root": record_root(kind, record),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-LIVE-RECEIPT-ACTIVATION-VECTOR",
        &leaves,
    )
}

fn activation_verdict_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    fail_closed_verdict: FailClosedVerdict,
    activation_status: ActivationStatus,
    hold_kind: HoldKind,
    release_authorized: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-LIVE-RECEIPT-ACTIVATION-VERDICT",
        &[
            HashPart::Str(&config.activation_suite),
            HashPart::Str(&roots.custody_signer_root),
            HashPart::Str(&roots.monero_release_observation_root),
            HashPart::Str(&roots.reserve_handoff_root),
            HashPart::Str(&roots.challenge_window_lock_root),
            HashPart::Str(&roots.mismatch_hold_root),
            HashPart::U64(counters.accepted_custody_signer_count),
            HashPart::U64(counters.accepted_monero_observation_count),
            HashPart::U64(counters.accepted_reserve_handoff_count),
            HashPart::U64(counters.active_challenge_lock_count),
            HashPart::U64(counters.active_mismatch_hold_count),
            HashPart::Str(fail_closed_verdict.as_str()),
            HashPart::Str(activation_status.as_str()),
            HashPart::Str(hold_kind.as_str()),
            HashPart::Str(bool_str(release_authorized)),
        ],
        32,
    )
}

fn live_receipt_activation_root(
    config: &Config,
    roots: &Roots,
    counters: &Counters,
    verdict: &ActivationVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-LIVE-RECEIPT-ACTIVATION-COMMITMENT",
        &[
            HashPart::Str(&record_root("config", &config.public_record())),
            HashPart::Str(&record_root("roots", &roots.public_record())),
            HashPart::Str(&record_root("counters", &counters.public_record())),
            HashPart::Str(&verdict.verdict_root),
            HashPart::Str(verdict.fail_closed_verdict.as_str()),
            HashPart::Str(verdict.activation_status.as_str()),
            HashPart::Str(bool_str(verdict.release_authorized)),
        ],
        32,
    )
}

fn deterministic_id(kind: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .enumerate()
        .map(|(index, part)| json!({ "index": index, "part": part }))
        .collect::<Vec<_>>();
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-LIVE-RECEIPT-ACTIVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(&merkle_root(
                "MONERO-L2-PQ-BRIDGE-CUSTODY-LIVE-RECEIPT-ACTIVATION-ID-PARTS",
                &leaves,
            )),
        ],
        32,
    )
}

fn sample_root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-LIVE-RECEIPT-ACTIVATION-DEVNET-SAMPLE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn first_hold_kind(
    signer_quorum_met: bool,
    monero_observation_met: bool,
    reserve_handoff_met: bool,
    challenge_window_clear: bool,
    mismatch_holds_clear: bool,
) -> HoldKind {
    if !signer_quorum_met {
        HoldKind::MissingSignerQuorum
    } else if !monero_observation_met {
        HoldKind::MissingMoneroObservation
    } else if !reserve_handoff_met {
        HoldKind::ReserveHandoffGap
    } else if !challenge_window_clear {
        HoldKind::ChallengeWindowLocked
    } else if !mismatch_holds_clear {
        HoldKind::MismatchDetected
    } else {
        HoldKind::None
    }
}

fn validate_config(config: &Config) -> Result<()> {
    let valid = config.chain_id == CHAIN_ID
        && config.protocol_version == PROTOCOL_VERSION
        && config.schema_version == SCHEMA_VERSION
        && config.min_custody_signers > 0
        && config.min_monero_observers > 0
        && config.min_reserve_handoffs > 0
        && config.challenge_window_blocks > 0
        && config.required_confirmations > 0;
    if valid {
        Ok(())
    } else {
        Err("bridge custody live receipt activation config invalid".to_string())
    }
}

fn count_where<T>(items: &[T], predicate: impl Fn(&T) -> bool) -> u64 {
    items.iter().filter(|item| predicate(item)).count() as u64
}

fn optional_requirement(required: bool, satisfied: bool) -> bool {
    !required || satisfied
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
