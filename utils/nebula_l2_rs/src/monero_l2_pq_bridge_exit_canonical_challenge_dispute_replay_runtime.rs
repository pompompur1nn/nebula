use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalChallengeDisputeReplayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_CHALLENGE_DISPUTE_REPLAY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-challenge-dispute-replay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_CHALLENGE_DISPUTE_REPLAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DISPUTE_REPLAY_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-challenge-dispute-replay-v1";
pub const DEFAULT_CURRENT_HEIGHT: u64 = 4_272_880;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RESPONSE_DEADLINE_BLOCKS: u64 = 96;
pub const DEFAULT_TIMEOUT_RELEASE_GRACE_BLOCKS: u64 = 24;
pub const DEFAULT_WATCHER_SILENCE_BLOCKS: u64 = 36;
pub const DEFAULT_SEQUENCER_CENSORSHIP_BLOCKS: u64 = 18;
pub const DEFAULT_PQ_OVERRIDE_WEIGHT: u64 = 67;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Admitted,
    Quarantined,
    Released,
    Rejected,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Quarantined => "quarantined",
            Self::Released => "released",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeKind {
    None,
    DuplicateNullifier,
    InvalidWalletAuthorization,
    InvalidMoneroFinality,
    AmountMismatch,
    MalformedEvidence,
    LateSubmission,
    UnauthorizedWatcher,
}

impl DisputeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::InvalidWalletAuthorization => "invalid_wallet_authorization",
            Self::InvalidMoneroFinality => "invalid_monero_finality",
            Self::AmountMismatch => "amount_mismatch",
            Self::MalformedEvidence => "malformed_evidence",
            Self::LateSubmission => "late_submission",
            Self::UnauthorizedWatcher => "unauthorized_watcher",
        }
    }

    pub fn can_block_release(self) -> bool {
        matches!(
            self,
            Self::DuplicateNullifier
                | Self::InvalidWalletAuthorization
                | Self::InvalidMoneroFinality
                | Self::AmountMismatch
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeOutcome {
    NoDispute,
    ValidBlocksExit,
    InvalidSlashesWatcher,
    ExpiredReleasedByTimeout,
    FailClosedEscalated,
}

impl DisputeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoDispute => "no_dispute",
            Self::ValidBlocksExit => "valid_blocks_exit",
            Self::InvalidSlashesWatcher => "invalid_slashes_watcher",
            Self::ExpiredReleasedByTimeout => "expired_released_by_timeout",
            Self::FailClosedEscalated => "fail_closed_escalated",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LivenessFault {
    None,
    WatcherSilence,
    SequencerCensorship,
    WatcherSilenceAndSequencerCensorship,
}

impl LivenessFault {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WatcherSilence => "watcher_silence",
            Self::SequencerCensorship => "sequencer_censorship",
            Self::WatcherSilenceAndSequencerCensorship => {
                "watcher_silence_and_sequencer_censorship"
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub dispute_replay_suite: String,
    pub current_height: u64,
    pub challenge_window_blocks: u64,
    pub response_deadline_blocks: u64,
    pub timeout_release_grace_blocks: u64,
    pub watcher_silence_blocks: u64,
    pub sequencer_censorship_blocks: u64,
    pub pq_override_weight: u64,
    pub fail_closed_on_unresolved_dispute: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            dispute_replay_suite: DISPUTE_REPLAY_SUITE.to_string(),
            current_height: DEFAULT_CURRENT_HEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            response_deadline_blocks: DEFAULT_RESPONSE_DEADLINE_BLOCKS,
            timeout_release_grace_blocks: DEFAULT_TIMEOUT_RELEASE_GRACE_BLOCKS,
            watcher_silence_blocks: DEFAULT_WATCHER_SILENCE_BLOCKS,
            sequencer_censorship_blocks: DEFAULT_SEQUENCER_CENSORSHIP_BLOCKS,
            pq_override_weight: DEFAULT_PQ_OVERRIDE_WEIGHT,
            fail_closed_on_unresolved_dispute: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "dispute_replay_suite": self.dispute_replay_suite,
            "current_height": self.current_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "response_deadline_blocks": self.response_deadline_blocks,
            "timeout_release_grace_blocks": self.timeout_release_grace_blocks,
            "watcher_silence_blocks": self.watcher_silence_blocks,
            "sequencer_censorship_blocks": self.sequencer_censorship_blocks,
            "pq_override_weight": self.pq_override_weight,
            "fail_closed_on_unresolved_dispute": self.fail_closed_on_unresolved_dispute,
        })
    }

    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalClaim {
    pub claim_id: String,
    pub owner_commitment: String,
    pub exit_nullifier_root: String,
    pub amount_piconero: u64,
    pub admitted_at_height: u64,
    pub challenge_window_end: u64,
    pub status: ClaimStatus,
    pub evidence_root: String,
    pub claim_root: String,
}

impl CanonicalClaim {
    pub fn new(
        config: &Config,
        label: &str,
        owner_commitment: &str,
        amount_piconero: u64,
        admitted_at_height: u64,
    ) -> Self {
        let seed = seed_root(label);
        let exit_nullifier_root = labeled_root("exit-nullifier", &seed);
        let evidence_root = labeled_root("canonical-exit-evidence", &seed);
        let claim_id = domain_hash(
            "CANONICAL-CHALLENGE-DISPUTE-CLAIM-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(owner_commitment),
                HashPart::Str(&exit_nullifier_root),
                HashPart::U64(amount_piconero),
                HashPart::U64(admitted_at_height),
            ],
            16,
        );
        let mut claim = Self {
            claim_id,
            owner_commitment: owner_commitment.to_string(),
            exit_nullifier_root,
            amount_piconero,
            admitted_at_height,
            challenge_window_end: admitted_at_height + config.challenge_window_blocks,
            status: ClaimStatus::Admitted,
            evidence_root,
            claim_root: String::new(),
        };
        claim.claim_root = claim.compute_root();
        claim
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "owner_commitment": self.owner_commitment,
            "exit_nullifier_root": self.exit_nullifier_root,
            "amount_piconero": self.amount_piconero,
            "admitted_at_height": self.admitted_at_height,
            "challenge_window_end": self.challenge_window_end,
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "claim_root": self.claim_root,
        })
    }

    pub fn compute_root(&self) -> String {
        record_root(
            "CLAIM",
            &json!({
                "claim_id": self.claim_id,
                "owner_commitment": self.owner_commitment,
                "exit_nullifier_root": self.exit_nullifier_root,
                "amount_piconero": self.amount_piconero,
                "admitted_at_height": self.admitted_at_height,
                "challenge_window_end": self.challenge_window_end,
                "status": self.status.as_str(),
                "evidence_root": self.evidence_root,
            }),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Dispute {
    pub dispute_id: String,
    pub claim_id: String,
    pub watcher_id: String,
    pub kind: DisputeKind,
    pub submitted_at_height: u64,
    pub response_deadline_height: u64,
    pub evidence_root: String,
    pub operator_response_root: String,
    pub valid: bool,
    pub resolved: bool,
    pub outcome: DisputeOutcome,
    pub dispute_root: String,
}

impl Dispute {
    pub fn evaluate(
        config: &Config,
        claim: &CanonicalClaim,
        watcher_id: &str,
        kind: DisputeKind,
        submitted_at_height: u64,
        evidence_root: &str,
        operator_response_root: &str,
    ) -> Self {
        let in_window = submitted_at_height <= claim.challenge_window_end;
        let response_deadline_height = submitted_at_height + config.response_deadline_blocks;
        let valid = in_window && kind.can_block_release() && !evidence_root.is_empty();
        let resolved = !operator_response_root.is_empty()
            || valid
            || config.current_height > response_deadline_height;
        let outcome = if kind == DisputeKind::None {
            DisputeOutcome::NoDispute
        } else if valid {
            DisputeOutcome::ValidBlocksExit
        } else if config.current_height > response_deadline_height {
            DisputeOutcome::ExpiredReleasedByTimeout
        } else if resolved {
            DisputeOutcome::InvalidSlashesWatcher
        } else {
            DisputeOutcome::FailClosedEscalated
        };
        let dispute_id = domain_hash(
            "CANONICAL-CHALLENGE-DISPUTE-ID",
            &[
                HashPart::Str(&claim.claim_id),
                HashPart::Str(watcher_id),
                HashPart::Str(kind.as_str()),
                HashPart::U64(submitted_at_height),
                HashPart::Str(evidence_root),
            ],
            16,
        );
        let mut dispute = Self {
            dispute_id,
            claim_id: claim.claim_id.clone(),
            watcher_id: watcher_id.to_string(),
            kind,
            submitted_at_height,
            response_deadline_height,
            evidence_root: evidence_root.to_string(),
            operator_response_root: operator_response_root.to_string(),
            valid,
            resolved,
            outcome,
            dispute_root: String::new(),
        };
        dispute.dispute_root = dispute.compute_root();
        dispute
    }

    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "claim_id": self.claim_id,
            "watcher_id": self.watcher_id,
            "kind": self.kind.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "response_deadline_height": self.response_deadline_height,
            "evidence_root": self.evidence_root,
            "operator_response_root": self.operator_response_root,
            "valid": self.valid,
            "resolved": self.resolved,
            "outcome": self.outcome.as_str(),
            "dispute_root": self.dispute_root,
        })
    }

    pub fn compute_root(&self) -> String {
        record_root(
            "DISPUTE",
            &json!({
                "dispute_id": self.dispute_id,
                "claim_id": self.claim_id,
                "watcher_id": self.watcher_id,
                "kind": self.kind.as_str(),
                "submitted_at_height": self.submitted_at_height,
                "response_deadline_height": self.response_deadline_height,
                "evidence_root": self.evidence_root,
                "operator_response_root": self.operator_response_root,
                "valid": self.valid,
                "resolved": self.resolved,
                "outcome": self.outcome.as_str(),
            }),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LivenessReplay {
    pub claim_id: String,
    pub watcher_silence_observed_blocks: u64,
    pub sequencer_censorship_observed_blocks: u64,
    pub user_fallback_broadcast_root: String,
    pub fault: LivenessFault,
    pub liveness_root: String,
}

impl LivenessReplay {
    pub fn evaluate(
        config: &Config,
        claim: &CanonicalClaim,
        watcher_silence_observed_blocks: u64,
        sequencer_censorship_observed_blocks: u64,
        user_fallback_broadcast_root: &str,
    ) -> Self {
        let watcher_fault = watcher_silence_observed_blocks >= config.watcher_silence_blocks;
        let sequencer_fault =
            sequencer_censorship_observed_blocks >= config.sequencer_censorship_blocks;
        let fault = match (watcher_fault, sequencer_fault) {
            (true, true) => LivenessFault::WatcherSilenceAndSequencerCensorship,
            (true, false) => LivenessFault::WatcherSilence,
            (false, true) => LivenessFault::SequencerCensorship,
            (false, false) => LivenessFault::None,
        };
        let mut replay = Self {
            claim_id: claim.claim_id.clone(),
            watcher_silence_observed_blocks,
            sequencer_censorship_observed_blocks,
            user_fallback_broadcast_root: user_fallback_broadcast_root.to_string(),
            fault,
            liveness_root: String::new(),
        };
        replay.liveness_root = replay.compute_root();
        replay
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "watcher_silence_observed_blocks": self.watcher_silence_observed_blocks,
            "sequencer_censorship_observed_blocks": self.sequencer_censorship_observed_blocks,
            "user_fallback_broadcast_root": self.user_fallback_broadcast_root,
            "fault": self.fault.as_str(),
            "liveness_root": self.liveness_root,
        })
    }

    pub fn compute_root(&self) -> String {
        record_root(
            "LIVENESS",
            &json!({
                "claim_id": self.claim_id,
                "watcher_silence_observed_blocks": self.watcher_silence_observed_blocks,
                "sequencer_censorship_observed_blocks": self.sequencer_censorship_observed_blocks,
                "user_fallback_broadcast_root": self.user_fallback_broadcast_root,
                "fault": self.fault.as_str(),
            }),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseReplay {
    pub claim_id: String,
    pub challenge_window_elapsed: bool,
    pub timeout_release_eligible: bool,
    pub pq_override_weight: u64,
    pub pq_release_override: bool,
    pub valid_dispute_count: u64,
    pub unresolved_dispute_count: u64,
    pub fail_closed: bool,
    pub can_exit_after_challenge_window: bool,
    pub release_root: String,
}

impl ReleaseReplay {
    pub fn evaluate(
        config: &Config,
        claim: &CanonicalClaim,
        disputes: &[Dispute],
        liveness: &LivenessReplay,
        pq_override_weight: u64,
    ) -> Self {
        let challenge_window_elapsed = config.current_height > claim.challenge_window_end;
        let valid_dispute_count = disputes
            .iter()
            .filter(|dispute| dispute.claim_id == claim.claim_id && dispute.valid)
            .count() as u64;
        let unresolved_dispute_count = disputes
            .iter()
            .filter(|dispute| {
                dispute.claim_id == claim.claim_id
                    && !dispute.resolved
                    && dispute.kind != DisputeKind::None
            })
            .count() as u64;
        let timeout_release_eligible = challenge_window_elapsed
            && config.current_height
                > claim.challenge_window_end + config.timeout_release_grace_blocks
            && valid_dispute_count == 0;
        let pq_release_override = pq_override_weight >= config.pq_override_weight
            && !matches!(liveness.fault, LivenessFault::None)
            && valid_dispute_count == 0;
        let fail_closed = config.fail_closed_on_unresolved_dispute && unresolved_dispute_count > 0;
        let can_exit_after_challenge_window = claim.status == ClaimStatus::Admitted
            && challenge_window_elapsed
            && valid_dispute_count == 0
            && !fail_closed
            && (timeout_release_eligible || pq_release_override);
        let mut replay = Self {
            claim_id: claim.claim_id.clone(),
            challenge_window_elapsed,
            timeout_release_eligible,
            pq_override_weight,
            pq_release_override,
            valid_dispute_count,
            unresolved_dispute_count,
            fail_closed,
            can_exit_after_challenge_window,
            release_root: String::new(),
        };
        replay.release_root = replay.compute_root();
        replay
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "challenge_window_elapsed": self.challenge_window_elapsed,
            "timeout_release_eligible": self.timeout_release_eligible,
            "pq_override_weight": self.pq_override_weight,
            "pq_release_override": self.pq_release_override,
            "valid_dispute_count": self.valid_dispute_count,
            "unresolved_dispute_count": self.unresolved_dispute_count,
            "fail_closed": self.fail_closed,
            "can_exit_after_challenge_window": self.can_exit_after_challenge_window,
            "release_root": self.release_root,
        })
    }

    pub fn compute_root(&self) -> String {
        record_root(
            "RELEASE",
            &json!({
                "claim_id": self.claim_id,
                "challenge_window_elapsed": self.challenge_window_elapsed,
                "timeout_release_eligible": self.timeout_release_eligible,
                "pq_override_weight": self.pq_override_weight,
                "pq_release_override": self.pq_release_override,
                "valid_dispute_count": self.valid_dispute_count,
                "unresolved_dispute_count": self.unresolved_dispute_count,
                "fail_closed": self.fail_closed,
                "can_exit_after_challenge_window": self.can_exit_after_challenge_window,
            }),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingReplay {
    pub invalid_dispute_slashing_root: String,
    pub operator_nonresponse_slashing_root: String,
    pub censorship_slashing_root: String,
    pub watcher_silence_slashing_root: String,
    pub slashing_root: String,
}

impl SlashingReplay {
    pub fn evaluate(disputes: &[Dispute], liveness: &LivenessReplay) -> Self {
        let invalid_dispute_records = disputes
            .iter()
            .filter(|dispute| matches!(dispute.outcome, DisputeOutcome::InvalidSlashesWatcher))
            .map(Dispute::public_record)
            .collect::<Vec<_>>();
        let operator_nonresponse_records = disputes
            .iter()
            .filter(|dispute| matches!(dispute.outcome, DisputeOutcome::ExpiredReleasedByTimeout))
            .map(Dispute::public_record)
            .collect::<Vec<_>>();
        let censorship_records = if matches!(
            liveness.fault,
            LivenessFault::SequencerCensorship
                | LivenessFault::WatcherSilenceAndSequencerCensorship
        ) {
            vec![liveness.public_record()]
        } else {
            Vec::new()
        };
        let watcher_silence_records = if matches!(
            liveness.fault,
            LivenessFault::WatcherSilence | LivenessFault::WatcherSilenceAndSequencerCensorship
        ) {
            vec![liveness.public_record()]
        } else {
            Vec::new()
        };
        let invalid_dispute_slashing_root = merkle_root(
            "CANONICAL-CHALLENGE-DISPUTE-INVALID-SLASHING",
            &invalid_dispute_records,
        );
        let operator_nonresponse_slashing_root = merkle_root(
            "CANONICAL-CHALLENGE-DISPUTE-NONRESPONSE-SLASHING",
            &operator_nonresponse_records,
        );
        let censorship_slashing_root = merkle_root(
            "CANONICAL-CHALLENGE-DISPUTE-CENSORSHIP-SLASHING",
            &censorship_records,
        );
        let watcher_silence_slashing_root = merkle_root(
            "CANONICAL-CHALLENGE-DISPUTE-WATCHER-SILENCE-SLASHING",
            &watcher_silence_records,
        );
        let mut replay = Self {
            invalid_dispute_slashing_root,
            operator_nonresponse_slashing_root,
            censorship_slashing_root,
            watcher_silence_slashing_root,
            slashing_root: String::new(),
        };
        replay.slashing_root = replay.compute_root();
        replay
    }

    pub fn public_record(&self) -> Value {
        json!({
            "invalid_dispute_slashing_root": self.invalid_dispute_slashing_root,
            "operator_nonresponse_slashing_root": self.operator_nonresponse_slashing_root,
            "censorship_slashing_root": self.censorship_slashing_root,
            "watcher_silence_slashing_root": self.watcher_silence_slashing_root,
            "slashing_root": self.slashing_root,
        })
    }

    pub fn compute_root(&self) -> String {
        record_root(
            "SLASHING",
            &json!({
                "invalid_dispute_slashing_root": self.invalid_dispute_slashing_root,
                "operator_nonresponse_slashing_root": self.operator_nonresponse_slashing_root,
                "censorship_slashing_root": self.censorship_slashing_root,
                "watcher_silence_slashing_root": self.watcher_silence_slashing_root,
            }),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub claims: Vec<CanonicalClaim>,
    pub disputes: Vec<Dispute>,
    pub liveness: LivenessReplay,
    pub release: ReleaseReplay,
    pub slashing: SlashingReplay,
    pub claim_root: String,
    pub dispute_root: String,
    pub answer: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let claim = CanonicalClaim::new(
            &config,
            "devnet-user-exit-after-operator-misbehavior",
            "owner_commitment_devnet_forced_exit_user",
            8_400_000_000,
            config.current_height - config.challenge_window_blocks - 48,
        );
        let blocked_claim = CanonicalClaim::new(
            &config,
            "devnet-valid-dispute-blocks-release",
            "owner_commitment_devnet_blocked_exit_user",
            6_125_000_000,
            config.current_height - 120,
        );
        let dispute_evidence = labeled_root("malformed-dispute-evidence", &claim.claim_root);
        let valid_blocker_evidence =
            labeled_root("duplicate-nullifier-evidence", &claim.claim_root);
        let blocked_claim_evidence =
            labeled_root("valid-amount-mismatch-evidence", &blocked_claim.claim_root);
        let disputes = vec![
            Dispute::evaluate(
                &config,
                &claim,
                "watcher_alpha",
                DisputeKind::MalformedEvidence,
                claim.admitted_at_height + 18,
                &dispute_evidence,
                &labeled_root("operator-rejects-malformed-dispute", &claim.claim_root),
            ),
            Dispute::evaluate(
                &config,
                &claim,
                "watcher_beta",
                DisputeKind::LateSubmission,
                claim.challenge_window_end + 3,
                &valid_blocker_evidence,
                "",
            ),
            Dispute::evaluate(
                &config,
                &blocked_claim,
                "watcher_gamma",
                DisputeKind::AmountMismatch,
                blocked_claim.admitted_at_height + 11,
                &blocked_claim_evidence,
                "",
            ),
        ];
        let liveness = LivenessReplay::evaluate(
            &config,
            &claim,
            config.watcher_silence_blocks + 7,
            config.sequencer_censorship_blocks + 4,
            &labeled_root("user-fallback-broadcast", &claim.claim_root),
        );
        let release = ReleaseReplay::evaluate(
            &config,
            &claim,
            &disputes,
            &liveness,
            config.pq_override_weight + 8,
        );
        let slashing = SlashingReplay::evaluate(&disputes, &liveness);
        let claims = vec![claim, blocked_claim];
        let claim_records = claims
            .iter()
            .map(CanonicalClaim::public_record)
            .collect::<Vec<_>>();
        let dispute_records = disputes
            .iter()
            .map(Dispute::public_record)
            .collect::<Vec<_>>();
        let claim_root = merkle_root("CANONICAL-CHALLENGE-DISPUTE-CLAIMS", &claim_records);
        let dispute_root = merkle_root("CANONICAL-CHALLENGE-DISPUTE-DISPUTES", &dispute_records);
        let answer = if release.can_exit_after_challenge_window {
            "yes: the admitted canonical forced-exit claim can exit after the challenge window by timeout release plus PQ override, even with watcher silence and sequencer censorship"
        } else {
            "no: release remains fail-closed until a valid dispute is cleared or timeout policy becomes eligible"
        }
        .to_string();
        Self {
            config,
            claims,
            disputes,
            liveness,
            release,
            slashing,
            claim_root,
            dispute_root,
            answer,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "claim_root": self.claim_root,
            "dispute_root": self.dispute_root,
            "liveness": self.liveness.public_record(),
            "release": self.release.public_record(),
            "slashing": self.slashing.public_record(),
            "answer": self.answer,
            "privacy_note": "public replay exposes roots, deadlines, counters, and outcomes only",
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-CHALLENGE-DISPUTE-REPLAY-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

pub fn seed_root(seed: &str) -> String {
    domain_hash(
        "CANONICAL-CHALLENGE-DISPUTE-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn labeled_root(label: &str, seed: &str) -> String {
    domain_hash(
        "CANONICAL-CHALLENGE-DISPUTE-LABELED-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "CANONICAL-CHALLENGE-DISPUTE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
