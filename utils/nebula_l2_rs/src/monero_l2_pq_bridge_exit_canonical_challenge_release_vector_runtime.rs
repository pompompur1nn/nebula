use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalChallengeReleaseVectorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_CHALLENGE_RELEASE_VECTOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-challenge-release-vector-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_CHALLENGE_RELEASE_VECTOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VECTOR_SUITE: &str =
    "monero-l2-pq-bridge-forced-exit-canonical-challenge-release-vector-v1";
pub const DEFAULT_CURRENT_HEIGHT: u64 = 4_260_144;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_WATCHER_SILENCE_BLOCKS: u64 = 36;
pub const DEFAULT_SEQUENCER_CENSORSHIP_BLOCKS: u64 = 18;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 6;
pub const DEFAULT_MIN_PQ_QUORUM_WEIGHT: u64 = 67;
pub const DEFAULT_MAX_CHALLENGE_AGE_BLOCKS: u64 = 720;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAdmissionStatus {
    Admitted,
    Rejected,
    Quarantined,
}

impl ClaimAdmissionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Rejected => "rejected",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeCaseKind {
    None,
    DoubleSpendNullifier,
    InvalidExitWitness,
    StaleMoneroFinality,
    AmountMismatch,
    RecipientMismatch,
    QueueReplay,
    CensorshipProof,
    WatcherSilenceProof,
    MalformedEvidence,
    LateChallenge,
    UnauthorizedChallenger,
}

impl ChallengeCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::InvalidExitWitness => "invalid_exit_witness",
            Self::StaleMoneroFinality => "stale_monero_finality",
            Self::AmountMismatch => "amount_mismatch",
            Self::RecipientMismatch => "recipient_mismatch",
            Self::QueueReplay => "queue_replay",
            Self::CensorshipProof => "censorship_proof",
            Self::WatcherSilenceProof => "watcher_silence_proof",
            Self::MalformedEvidence => "malformed_evidence",
            Self::LateChallenge => "late_challenge",
            Self::UnauthorizedChallenger => "unauthorized_challenger",
        }
    }

    pub fn is_valid_blocker(self) -> bool {
        matches!(
            self,
            Self::DoubleSpendNullifier
                | Self::InvalidExitWitness
                | Self::StaleMoneroFinality
                | Self::AmountMismatch
                | Self::RecipientMismatch
                | Self::QueueReplay
                | Self::CensorshipProof
                | Self::WatcherSilenceProof
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeDisposition {
    NoChallenge,
    Accepted,
    Rejected,
    Expired,
}

impl ChallengeDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoChallenge => "no_challenge",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseEligibility {
    Eligible,
    WaitingForWindow,
    BlockedByChallenge,
    BlockedByCensorship,
    BlockedByWatcherSilence,
    BlockedByPqAuthorization,
    RejectedClaim,
}

impl ReleaseEligibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::WaitingForWindow => "waiting_for_window",
            Self::BlockedByChallenge => "blocked_by_challenge",
            Self::BlockedByCensorship => "blocked_by_censorship",
            Self::BlockedByWatcherSilence => "blocked_by_watcher_silence",
            Self::BlockedByPqAuthorization => "blocked_by_pq_authorization",
            Self::RejectedClaim => "rejected_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationStatus {
    Authorized,
    InsufficientWeight,
    KeyEpochMismatch,
    MissingTranscript,
    RevokedSigner,
}

impl PqAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::InsufficientWeight => "insufficient_weight",
            Self::KeyEpochMismatch => "key_epoch_mismatch",
            Self::MissingTranscript => "missing_transcript",
            Self::RevokedSigner => "revoked_signer",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub vector_suite: String,
    pub current_height: u64,
    pub challenge_window_blocks: u64,
    pub watcher_silence_blocks: u64,
    pub sequencer_censorship_blocks: u64,
    pub release_delay_blocks: u64,
    pub min_pq_quorum_weight: u64,
    pub max_challenge_age_blocks: u64,
    pub fail_closed_on_watcher_silence: bool,
    pub fail_closed_on_censorship: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            vector_suite: VECTOR_SUITE.to_string(),
            current_height: DEFAULT_CURRENT_HEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            watcher_silence_blocks: DEFAULT_WATCHER_SILENCE_BLOCKS,
            sequencer_censorship_blocks: DEFAULT_SEQUENCER_CENSORSHIP_BLOCKS,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            min_pq_quorum_weight: DEFAULT_MIN_PQ_QUORUM_WEIGHT,
            max_challenge_age_blocks: DEFAULT_MAX_CHALLENGE_AGE_BLOCKS,
            fail_closed_on_watcher_silence: true,
            fail_closed_on_censorship: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "vector_suite": self.vector_suite,
            "current_height": self.current_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "watcher_silence_blocks": self.watcher_silence_blocks,
            "sequencer_censorship_blocks": self.sequencer_censorship_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "min_pq_quorum_weight": self.min_pq_quorum_weight,
            "max_challenge_age_blocks": self.max_challenge_age_blocks,
            "fail_closed_on_watcher_silence": self.fail_closed_on_watcher_silence,
            "fail_closed_on_censorship": self.fail_closed_on_censorship,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitClaim {
    pub claim_id: String,
    pub owner_commitment: String,
    pub exit_nullifier: String,
    pub withdrawal_address_commitment: String,
    pub amount_piconero: u64,
    pub admission_height: u64,
    pub source_state_root: String,
    pub monero_finality_root: String,
    pub witness_root: String,
    pub admission_status: ClaimAdmissionStatus,
    pub rejection_reason: String,
    pub claim_root: String,
}

impl ForcedExitClaim {
    pub fn new(
        label: &str,
        owner_commitment: &str,
        exit_nullifier: &str,
        amount_piconero: u64,
        admission_height: u64,
        source_state_root: &str,
        monero_finality_root: &str,
        witness_root: &str,
    ) -> Self {
        let withdrawal_address_commitment = domain_hash(
            "MONERO-L2-PQ-CANONICAL-EXIT-WITHDRAWAL-COMMITMENT",
            &[
                HashPart::Str(owner_commitment),
                HashPart::Str(exit_nullifier),
                HashPart::U64(amount_piconero),
            ],
            32,
        );
        let claim_id = forced_exit_claim_id(
            owner_commitment,
            exit_nullifier,
            amount_piconero,
            admission_height,
            source_state_root,
        );
        let mut claim = Self {
            claim_id,
            owner_commitment: owner_commitment.to_string(),
            exit_nullifier: exit_nullifier.to_string(),
            withdrawal_address_commitment,
            amount_piconero,
            admission_height,
            source_state_root: source_state_root.to_string(),
            monero_finality_root: monero_finality_root.to_string(),
            witness_root: witness_root.to_string(),
            admission_status: ClaimAdmissionStatus::Admitted,
            rejection_reason: label.to_string(),
            claim_root: String::new(),
        };
        claim.claim_root = claim.compute_root();
        claim
    }

    pub fn reject(mut self, reason: &str) -> Self {
        self.admission_status = ClaimAdmissionStatus::Rejected;
        self.rejection_reason = reason.to_string();
        self.claim_root = self.compute_root();
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "owner_commitment": self.owner_commitment,
            "exit_nullifier": self.exit_nullifier,
            "withdrawal_address_commitment": self.withdrawal_address_commitment,
            "amount_piconero": self.amount_piconero,
            "admission_height": self.admission_height,
            "source_state_root": self.source_state_root,
            "monero_finality_root": self.monero_finality_root,
            "witness_root": self.witness_root,
            "admission_status": self.admission_status.as_str(),
            "rejection_reason": self.rejection_reason,
            "claim_root": self.claim_root,
        })
    }

    pub fn compute_root(&self) -> String {
        forced_exit_claim_root(
            self.admission_status,
            &self.claim_id,
            &self.owner_commitment,
            &self.exit_nullifier,
            &self.withdrawal_address_commitment,
            self.amount_piconero,
            self.admission_height,
            &self.source_state_root,
            &self.monero_finality_root,
            &self.witness_root,
            &self.rejection_reason,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeWindow {
    pub claim_id: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub release_after_height: u64,
    pub current_height: u64,
    pub window_elapsed: bool,
    pub timeout_release_eligible: bool,
    pub window_root: String,
}

impl ChallengeWindow {
    pub fn for_claim(config: &Config, claim: &ForcedExitClaim) -> Self {
        let opens_at_height = claim.admission_height;
        let closes_at_height = opens_at_height.saturating_add(config.challenge_window_blocks);
        let release_after_height = closes_at_height.saturating_add(config.release_delay_blocks);
        let window_elapsed = config.current_height >= closes_at_height;
        let timeout_release_eligible = config.current_height >= release_after_height;
        let mut window = Self {
            claim_id: claim.claim_id.clone(),
            opens_at_height,
            closes_at_height,
            release_after_height,
            current_height: config.current_height,
            window_elapsed,
            timeout_release_eligible,
            window_root: String::new(),
        };
        window.window_root = window.compute_root();
        window
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "release_after_height": self.release_after_height,
            "current_height": self.current_height,
            "window_elapsed": self.window_elapsed,
            "timeout_release_eligible": self.timeout_release_eligible,
            "window_root": self.window_root,
        })
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-CHALLENGE-WINDOW",
            &[
                HashPart::Str(&self.claim_id),
                HashPart::U64(self.opens_at_height),
                HashPart::U64(self.closes_at_height),
                HashPart::U64(self.release_after_height),
                HashPart::U64(self.current_height),
                HashPart::Str(bool_str(self.window_elapsed)),
                HashPart::Str(bool_str(self.timeout_release_eligible)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeCase {
    pub challenge_id: String,
    pub claim_id: String,
    pub challenger_id: String,
    pub case_kind: ChallengeCaseKind,
    pub disposition: ChallengeDisposition,
    pub submitted_at_height: u64,
    pub evidence_root: String,
    pub challenge_transcript_root: String,
    pub rejection_reason: String,
    pub blocks_release: bool,
    pub challenge_root: String,
}

impl ChallengeCase {
    pub fn evaluate(
        config: &Config,
        claim: &ForcedExitClaim,
        challenger_id: &str,
        case_kind: ChallengeCaseKind,
        submitted_at_height: u64,
        evidence_root: &str,
    ) -> Self {
        let window = ChallengeWindow::for_claim(config, claim);
        let in_window = submitted_at_height >= window.opens_at_height
            && submitted_at_height <= window.closes_at_height;
        let age_ok = submitted_at_height.saturating_sub(window.opens_at_height)
            <= config.max_challenge_age_blocks;
        let authorized = !challenger_id.is_empty() && challenger_id != "revoked";
        let disposition = if case_kind == ChallengeCaseKind::None {
            ChallengeDisposition::NoChallenge
        } else if !in_window || !age_ok {
            ChallengeDisposition::Expired
        } else if case_kind.is_valid_blocker() && authorized && !evidence_root.is_empty() {
            ChallengeDisposition::Accepted
        } else {
            ChallengeDisposition::Rejected
        };
        let rejection_reason = challenge_rejection_reason(
            case_kind,
            disposition,
            in_window,
            age_ok,
            authorized,
            evidence_root,
        );
        let challenge_transcript_root =
            challenge_transcript_root(&claim.claim_id, challenger_id, case_kind, evidence_root);
        let challenge_id = challenge_case_id(
            &claim.claim_id,
            challenger_id,
            case_kind,
            submitted_at_height,
            evidence_root,
        );
        let blocks_release = disposition == ChallengeDisposition::Accepted;
        let mut challenge = Self {
            challenge_id,
            claim_id: claim.claim_id.clone(),
            challenger_id: challenger_id.to_string(),
            case_kind,
            disposition,
            submitted_at_height,
            evidence_root: evidence_root.to_string(),
            challenge_transcript_root,
            rejection_reason,
            blocks_release,
            challenge_root: String::new(),
        };
        challenge.challenge_root = challenge.compute_root();
        challenge
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "claim_id": self.claim_id,
            "challenger_id": self.challenger_id,
            "case_kind": self.case_kind.as_str(),
            "disposition": self.disposition.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "evidence_root": self.evidence_root,
            "challenge_transcript_root": self.challenge_transcript_root,
            "rejection_reason": self.rejection_reason,
            "blocks_release": self.blocks_release,
            "challenge_root": self.challenge_root,
        })
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-CHALLENGE-CASE",
            &[
                HashPart::Str(&self.challenge_id),
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.challenger_id),
                HashPart::Str(self.case_kind.as_str()),
                HashPart::Str(self.disposition.as_str()),
                HashPart::U64(self.submitted_at_height),
                HashPart::Str(&self.evidence_root),
                HashPart::Str(&self.challenge_transcript_root),
                HashPart::Str(&self.rejection_reason),
                HashPart::Str(bool_str(self.blocks_release)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LivenessObservation {
    pub claim_id: String,
    pub sequencer_last_inclusion_height: u64,
    pub watcher_last_attestation_height: u64,
    pub sequencer_censorship_detected: bool,
    pub watcher_silence_detected: bool,
    pub censorship_evidence_root: String,
    pub watcher_silence_root: String,
    pub liveness_root: String,
}

impl LivenessObservation {
    pub fn evaluate(
        config: &Config,
        claim: &ForcedExitClaim,
        sequencer_last_inclusion_height: u64,
        watcher_last_attestation_height: u64,
    ) -> Self {
        let sequencer_gap = config
            .current_height
            .saturating_sub(sequencer_last_inclusion_height);
        let watcher_gap = config
            .current_height
            .saturating_sub(watcher_last_attestation_height);
        let sequencer_censorship_detected = sequencer_gap >= config.sequencer_censorship_blocks;
        let watcher_silence_detected = watcher_gap >= config.watcher_silence_blocks;
        let censorship_evidence_root = domain_hash(
            "MONERO-L2-PQ-CANONICAL-SEQUENCER-CENSORSHIP",
            &[
                HashPart::Str(&claim.claim_id),
                HashPart::U64(config.current_height),
                HashPart::U64(sequencer_last_inclusion_height),
                HashPart::U64(sequencer_gap),
            ],
            32,
        );
        let watcher_silence_root = domain_hash(
            "MONERO-L2-PQ-CANONICAL-WATCHER-SILENCE",
            &[
                HashPart::Str(&claim.claim_id),
                HashPart::U64(config.current_height),
                HashPart::U64(watcher_last_attestation_height),
                HashPart::U64(watcher_gap),
            ],
            32,
        );
        let mut observation = Self {
            claim_id: claim.claim_id.clone(),
            sequencer_last_inclusion_height,
            watcher_last_attestation_height,
            sequencer_censorship_detected,
            watcher_silence_detected,
            censorship_evidence_root,
            watcher_silence_root,
            liveness_root: String::new(),
        };
        observation.liveness_root = observation.compute_root();
        observation
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "sequencer_last_inclusion_height": self.sequencer_last_inclusion_height,
            "watcher_last_attestation_height": self.watcher_last_attestation_height,
            "sequencer_censorship_detected": self.sequencer_censorship_detected,
            "watcher_silence_detected": self.watcher_silence_detected,
            "censorship_evidence_root": self.censorship_evidence_root,
            "watcher_silence_root": self.watcher_silence_root,
            "liveness_root": self.liveness_root,
        })
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-LIVENESS-OBSERVATION",
            &[
                HashPart::Str(&self.claim_id),
                HashPart::U64(self.sequencer_last_inclusion_height),
                HashPart::U64(self.watcher_last_attestation_height),
                HashPart::Str(bool_str(self.sequencer_censorship_detected)),
                HashPart::Str(bool_str(self.watcher_silence_detected)),
                HashPart::Str(&self.censorship_evidence_root),
                HashPart::Str(&self.watcher_silence_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqReleaseAuthorization {
    pub authorization_id: String,
    pub claim_id: String,
    pub key_epoch: u64,
    pub expected_key_epoch: u64,
    pub quorum_weight: u64,
    pub min_quorum_weight: u64,
    pub signer_set_root: String,
    pub signature_transcript_root: String,
    pub status: PqAuthorizationStatus,
    pub authorization_root: String,
}

impl PqReleaseAuthorization {
    pub fn evaluate(
        config: &Config,
        claim: &ForcedExitClaim,
        key_epoch: u64,
        expected_key_epoch: u64,
        quorum_weight: u64,
        signer_set_root: &str,
        signature_transcript_root: &str,
    ) -> Self {
        let status = if key_epoch != expected_key_epoch {
            PqAuthorizationStatus::KeyEpochMismatch
        } else if quorum_weight < config.min_pq_quorum_weight {
            PqAuthorizationStatus::InsufficientWeight
        } else if signature_transcript_root.is_empty() {
            PqAuthorizationStatus::MissingTranscript
        } else if signer_set_root == "revoked" {
            PqAuthorizationStatus::RevokedSigner
        } else {
            PqAuthorizationStatus::Authorized
        };
        let authorization_id = pq_release_authorization_id(
            &claim.claim_id,
            key_epoch,
            quorum_weight,
            signer_set_root,
            signature_transcript_root,
        );
        let mut authorization = Self {
            authorization_id,
            claim_id: claim.claim_id.clone(),
            key_epoch,
            expected_key_epoch,
            quorum_weight,
            min_quorum_weight: config.min_pq_quorum_weight,
            signer_set_root: signer_set_root.to_string(),
            signature_transcript_root: signature_transcript_root.to_string(),
            status,
            authorization_root: String::new(),
        };
        authorization.authorization_root = authorization.compute_root();
        authorization
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "claim_id": self.claim_id,
            "key_epoch": self.key_epoch,
            "expected_key_epoch": self.expected_key_epoch,
            "quorum_weight": self.quorum_weight,
            "min_quorum_weight": self.min_quorum_weight,
            "signer_set_root": self.signer_set_root,
            "signature_transcript_root": self.signature_transcript_root,
            "status": self.status.as_str(),
            "authorization_root": self.authorization_root,
        })
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-RELEASE-AUTHORIZATION",
            &[
                HashPart::Str(&self.authorization_id),
                HashPart::Str(&self.claim_id),
                HashPart::U64(self.key_epoch),
                HashPart::U64(self.expected_key_epoch),
                HashPart::U64(self.quorum_weight),
                HashPart::U64(self.min_quorum_weight),
                HashPart::Str(&self.signer_set_root),
                HashPart::Str(&self.signature_transcript_root),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseDecision {
    pub claim_id: String,
    pub eligibility: ReleaseEligibility,
    pub timeout_release_eligible: bool,
    pub pq_authorized: bool,
    pub accepted_challenge_count: u64,
    pub rejected_challenge_count: u64,
    pub release_height: u64,
    pub release_certificate_root: String,
    pub decision_root: String,
}

impl ReleaseDecision {
    pub fn evaluate(
        config: &Config,
        claim: &ForcedExitClaim,
        window: &ChallengeWindow,
        challenges: &[ChallengeCase],
        liveness: &LivenessObservation,
        authorization: &PqReleaseAuthorization,
    ) -> Self {
        let accepted_challenge_count = challenges
            .iter()
            .filter(|challenge| challenge.disposition == ChallengeDisposition::Accepted)
            .count() as u64;
        let rejected_challenge_count = challenges
            .iter()
            .filter(|challenge| challenge.disposition == ChallengeDisposition::Rejected)
            .count() as u64;
        let pq_authorized = authorization.status == PqAuthorizationStatus::Authorized;
        let eligibility = release_eligibility(
            config,
            claim,
            window,
            accepted_challenge_count,
            liveness,
            pq_authorized,
        );
        let release_height = if eligibility == ReleaseEligibility::Eligible {
            config.current_height
        } else {
            window.release_after_height
        };
        let release_certificate_root = release_certificate_root(
            &claim.claim_id,
            eligibility,
            window,
            accepted_challenge_count,
            authorization,
        );
        let mut decision = Self {
            claim_id: claim.claim_id.clone(),
            eligibility,
            timeout_release_eligible: window.timeout_release_eligible,
            pq_authorized,
            accepted_challenge_count,
            rejected_challenge_count,
            release_height,
            release_certificate_root,
            decision_root: String::new(),
        };
        decision.decision_root = decision.compute_root();
        decision
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "eligibility": self.eligibility.as_str(),
            "timeout_release_eligible": self.timeout_release_eligible,
            "pq_authorized": self.pq_authorized,
            "accepted_challenge_count": self.accepted_challenge_count,
            "rejected_challenge_count": self.rejected_challenge_count,
            "release_height": self.release_height,
            "release_certificate_root": self.release_certificate_root,
            "decision_root": self.decision_root,
        })
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-RELEASE-DECISION",
            &[
                HashPart::Str(&self.claim_id),
                HashPart::Str(self.eligibility.as_str()),
                HashPart::Str(bool_str(self.timeout_release_eligible)),
                HashPart::Str(bool_str(self.pq_authorized)),
                HashPart::U64(self.accepted_challenge_count),
                HashPart::U64(self.rejected_challenge_count),
                HashPart::U64(self.release_height),
                HashPart::Str(&self.release_certificate_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayRoots {
    pub claim_root: String,
    pub challenge_window_root: String,
    pub challenge_case_root: String,
    pub liveness_root: String,
    pub authorization_root: String,
    pub release_decision_root: String,
    pub deterministic_replay_root: String,
}

impl ReplayRoots {
    pub fn from_state_parts(
        claims: &[ForcedExitClaim],
        windows: &[ChallengeWindow],
        challenges: &[ChallengeCase],
        liveness: &[LivenessObservation],
        authorizations: &[PqReleaseAuthorization],
        decisions: &[ReleaseDecision],
    ) -> Self {
        let claim_records = claims
            .iter()
            .map(ForcedExitClaim::public_record)
            .collect::<Vec<_>>();
        let window_records = windows
            .iter()
            .map(ChallengeWindow::public_record)
            .collect::<Vec<_>>();
        let challenge_records = challenges
            .iter()
            .map(ChallengeCase::public_record)
            .collect::<Vec<_>>();
        let liveness_records = liveness
            .iter()
            .map(LivenessObservation::public_record)
            .collect::<Vec<_>>();
        let authorization_records = authorizations
            .iter()
            .map(PqReleaseAuthorization::public_record)
            .collect::<Vec<_>>();
        let decision_records = decisions
            .iter()
            .map(ReleaseDecision::public_record)
            .collect::<Vec<_>>();
        let mut roots = Self {
            claim_root: merkle_root("MONERO-L2-PQ-CANONICAL-CLAIM", &claim_records),
            challenge_window_root: merkle_root(
                "MONERO-L2-PQ-CANONICAL-CHALLENGE-WINDOW",
                &window_records,
            ),
            challenge_case_root: merkle_root(
                "MONERO-L2-PQ-CANONICAL-CHALLENGE-CASE",
                &challenge_records,
            ),
            liveness_root: merkle_root("MONERO-L2-PQ-CANONICAL-LIVENESS", &liveness_records),
            authorization_root: merkle_root(
                "MONERO-L2-PQ-CANONICAL-AUTHORIZATION",
                &authorization_records,
            ),
            release_decision_root: merkle_root(
                "MONERO-L2-PQ-CANONICAL-RELEASE-DECISION",
                &decision_records,
            ),
            deterministic_replay_root: String::new(),
        };
        roots.deterministic_replay_root = roots.compute_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_root": self.claim_root,
            "challenge_window_root": self.challenge_window_root,
            "challenge_case_root": self.challenge_case_root,
            "liveness_root": self.liveness_root,
            "authorization_root": self.authorization_root,
            "release_decision_root": self.release_decision_root,
            "deterministic_replay_root": self.deterministic_replay_root,
        })
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-DETERMINISTIC-REPLAY",
            &[
                HashPart::Str(&self.claim_root),
                HashPart::Str(&self.challenge_window_root),
                HashPart::Str(&self.challenge_case_root),
                HashPart::Str(&self.liveness_root),
                HashPart::Str(&self.authorization_root),
                HashPart::Str(&self.release_decision_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub claims: Vec<ForcedExitClaim>,
    pub challenge_windows: Vec<ChallengeWindow>,
    pub challenges: Vec<ChallengeCase>,
    pub liveness_observations: Vec<LivenessObservation>,
    pub pq_authorizations: Vec<PqReleaseAuthorization>,
    pub release_decisions: Vec<ReleaseDecision>,
    pub replay_roots: ReplayRoots,
    pub counters: BTreeMap<String, u64>,
    pub state_root: String,
}

impl State {
    pub fn new(
        config: Config,
        claims: Vec<ForcedExitClaim>,
        challenges: Vec<ChallengeCase>,
        liveness_observations: Vec<LivenessObservation>,
        pq_authorizations: Vec<PqReleaseAuthorization>,
    ) -> Result<Self> {
        if claims.is_empty() {
            return Err("canonical vector requires at least one forced-exit claim".to_string());
        }
        let challenge_windows = claims
            .iter()
            .map(|claim| ChallengeWindow::for_claim(&config, claim))
            .collect::<Vec<_>>();
        let mut release_decisions = Vec::with_capacity(claims.len());
        for claim in &claims {
            let window = challenge_windows
                .iter()
                .find(|window| window.claim_id == claim.claim_id)
                .ok_or_else(|| format!("missing challenge window for {}", claim.claim_id))?;
            let claim_challenges = challenges
                .iter()
                .filter(|challenge| challenge.claim_id == claim.claim_id)
                .cloned()
                .collect::<Vec<_>>();
            let liveness = liveness_observations
                .iter()
                .find(|observation| observation.claim_id == claim.claim_id)
                .ok_or_else(|| format!("missing liveness observation for {}", claim.claim_id))?;
            let authorization = pq_authorizations
                .iter()
                .find(|authorization| authorization.claim_id == claim.claim_id)
                .ok_or_else(|| format!("missing pq authorization for {}", claim.claim_id))?;
            release_decisions.push(ReleaseDecision::evaluate(
                &config,
                claim,
                window,
                &claim_challenges,
                liveness,
                authorization,
            ));
        }
        Ok(Self::from_parts(
            config,
            claims,
            challenge_windows,
            challenges,
            liveness_observations,
            pq_authorizations,
            release_decisions,
        ))
    }

    pub fn from_parts(
        config: Config,
        claims: Vec<ForcedExitClaim>,
        challenge_windows: Vec<ChallengeWindow>,
        challenges: Vec<ChallengeCase>,
        liveness_observations: Vec<LivenessObservation>,
        pq_authorizations: Vec<PqReleaseAuthorization>,
        release_decisions: Vec<ReleaseDecision>,
    ) -> Self {
        let replay_roots = ReplayRoots::from_state_parts(
            &claims,
            &challenge_windows,
            &challenges,
            &liveness_observations,
            &pq_authorizations,
            &release_decisions,
        );
        let counters = counters(
            &claims,
            &challenges,
            &liveness_observations,
            &pq_authorizations,
            &release_decisions,
        );
        let mut state = Self {
            config,
            claims,
            challenge_windows,
            challenges,
            liveness_observations,
            pq_authorizations,
            release_decisions,
            replay_roots,
            counters,
            state_root: String::new(),
        };
        state.state_root = state.compute_root();
        state
    }

    pub fn admit_claim(&mut self, claim: ForcedExitClaim) -> Result<()> {
        if self
            .claims
            .iter()
            .any(|existing| existing.claim_id == claim.claim_id)
        {
            return Err(format!("claim already admitted: {}", claim.claim_id));
        }
        let window = ChallengeWindow::for_claim(&self.config, &claim);
        self.claims.push(claim);
        self.challenge_windows.push(window);
        self.refresh();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "claims": self.claims.iter().map(ForcedExitClaim::public_record).collect::<Vec<_>>(),
            "challenge_windows": self.challenge_windows.iter().map(ChallengeWindow::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.iter().map(ChallengeCase::public_record).collect::<Vec<_>>(),
            "liveness_observations": self.liveness_observations.iter().map(LivenessObservation::public_record).collect::<Vec<_>>(),
            "pq_authorizations": self.pq_authorizations.iter().map(PqReleaseAuthorization::public_record).collect::<Vec<_>>(),
            "release_decisions": self.release_decisions.iter().map(ReleaseDecision::public_record).collect::<Vec<_>>(),
            "replay_roots": self.replay_roots.public_record(),
            "counters": &self.counters,
            "state_root": self.state_root,
        })
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-CHALLENGE-RELEASE-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.replay_roots.deterministic_replay_root),
                HashPart::Json(&json!(&self.counters)),
            ],
            32,
        )
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn refresh(&mut self) {
        self.replay_roots = ReplayRoots::from_state_parts(
            &self.claims,
            &self.challenge_windows,
            &self.challenges,
            &self.liveness_observations,
            &self.pq_authorizations,
            &self.release_decisions,
        );
        self.counters = counters(
            &self.claims,
            &self.challenges,
            &self.liveness_observations,
            &self.pq_authorizations,
            &self.release_decisions,
        );
        self.state_root = self.compute_root();
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let source_state_root = domain_hash(
        "MONERO-L2-PQ-CANONICAL-DEVNET-SOURCE-STATE",
        &[HashPart::Str("forced-exit-heavy-gate")],
        32,
    );
    let monero_finality_root = domain_hash(
        "MONERO-L2-PQ-CANONICAL-DEVNET-MONERO-FINALITY",
        &[HashPart::U64(3_144_200)],
        32,
    );
    let witness_root = domain_hash(
        "MONERO-L2-PQ-CANONICAL-DEVNET-WITNESS",
        &[HashPart::Str("note-membership-and-nullifier")],
        32,
    );
    let claim_ready = ForcedExitClaim::new(
        "canonical-ready",
        "owner_commitment_ready",
        "exit_nullifier_ready",
        12_500_000_000,
        config.current_height - DEFAULT_CHALLENGE_WINDOW_BLOCKS - DEFAULT_RELEASE_DELAY_BLOCKS - 4,
        &source_state_root,
        &monero_finality_root,
        &witness_root,
    );
    let claim_challenged = ForcedExitClaim::new(
        "canonical-challenged",
        "owner_commitment_challenged",
        "exit_nullifier_challenged",
        4_200_000_000,
        config.current_height - 96,
        &source_state_root,
        &monero_finality_root,
        &witness_root,
    );
    let claim_rejected = ForcedExitClaim::new(
        "canonical-rejected",
        "owner_commitment_rejected",
        "exit_nullifier_rejected",
        7_700_000_000,
        config.current_height - 33,
        &source_state_root,
        &monero_finality_root,
        &witness_root,
    )
    .reject("duplicate_exit_nullifier");
    let claims = vec![claim_ready, claim_challenged, claim_rejected];
    let challenges = vec![
        ChallengeCase::evaluate(
            &config,
            &claims[0],
            "watcher_alpha",
            ChallengeCaseKind::MalformedEvidence,
            claims[0].admission_height + 9,
            "",
        ),
        ChallengeCase::evaluate(
            &config,
            &claims[1],
            "watcher_beta",
            ChallengeCaseKind::DoubleSpendNullifier,
            claims[1].admission_height + 22,
            &domain_hash(
                "MONERO-L2-PQ-CANONICAL-DEVNET-DOUBLE-SPEND",
                &[HashPart::Str(&claims[1].exit_nullifier)],
                32,
            ),
        ),
        ChallengeCase::evaluate(
            &config,
            &claims[1],
            "revoked",
            ChallengeCaseKind::UnauthorizedChallenger,
            claims[1].admission_height + 30,
            &domain_hash(
                "MONERO-L2-PQ-CANONICAL-DEVNET-UNAUTHORIZED",
                &[HashPart::Str(&claims[1].claim_id)],
                32,
            ),
        ),
    ];
    let liveness_observations = vec![
        LivenessObservation::evaluate(
            &config,
            &claims[0],
            config.current_height - 3,
            config.current_height - 2,
        ),
        LivenessObservation::evaluate(
            &config,
            &claims[1],
            config.current_height - 31,
            config.current_height - 7,
        ),
        LivenessObservation::evaluate(
            &config,
            &claims[2],
            config.current_height - 2,
            config.current_height - 44,
        ),
    ];
    let pq_authorizations = claims
        .iter()
        .enumerate()
        .map(|(index, claim)| {
            let quorum_weight = if index == 2 { 55 } else { 72 };
            PqReleaseAuthorization::evaluate(
                &config,
                claim,
                4,
                4,
                quorum_weight,
                &domain_hash(
                    "MONERO-L2-PQ-CANONICAL-DEVNET-SIGNER-SET",
                    &[HashPart::U64(index as u64)],
                    32,
                ),
                &domain_hash(
                    "MONERO-L2-PQ-CANONICAL-DEVNET-PQ-TRANSCRIPT",
                    &[HashPart::Str(&claim.claim_id)],
                    32,
                ),
            )
        })
        .collect::<Vec<_>>();
    State::new(
        config,
        claims,
        challenges,
        liveness_observations,
        pq_authorizations,
    )
    .unwrap_or_else(devnet_fallback)
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn forced_exit_claim_id(
    owner_commitment: &str,
    exit_nullifier: &str,
    amount_piconero: u64,
    admission_height: u64,
    source_state_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-CANONICAL-FORCED-EXIT-CLAIM-ID",
        &[
            HashPart::Str(owner_commitment),
            HashPart::Str(exit_nullifier),
            HashPart::U64(amount_piconero),
            HashPart::U64(admission_height),
            HashPart::Str(source_state_root),
        ],
        32,
    )
}

pub fn forced_exit_claim_root(
    admission_status: ClaimAdmissionStatus,
    claim_id: &str,
    owner_commitment: &str,
    exit_nullifier: &str,
    withdrawal_address_commitment: &str,
    amount_piconero: u64,
    admission_height: u64,
    source_state_root: &str,
    monero_finality_root: &str,
    witness_root: &str,
    rejection_reason: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-CANONICAL-FORCED-EXIT-CLAIM",
        &[
            HashPart::Str(admission_status.as_str()),
            HashPart::Str(claim_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(exit_nullifier),
            HashPart::Str(withdrawal_address_commitment),
            HashPart::U64(amount_piconero),
            HashPart::U64(admission_height),
            HashPart::Str(source_state_root),
            HashPart::Str(monero_finality_root),
            HashPart::Str(witness_root),
            HashPart::Str(rejection_reason),
        ],
        32,
    )
}

pub fn challenge_case_id(
    claim_id: &str,
    challenger_id: &str,
    case_kind: ChallengeCaseKind,
    submitted_at_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-CANONICAL-CHALLENGE-ID",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(challenger_id),
            HashPart::Str(case_kind.as_str()),
            HashPart::U64(submitted_at_height),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn challenge_transcript_root(
    claim_id: &str,
    challenger_id: &str,
    case_kind: ChallengeCaseKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-CANONICAL-CHALLENGE-TRANSCRIPT",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(challenger_id),
            HashPart::Str(case_kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn pq_release_authorization_id(
    claim_id: &str,
    key_epoch: u64,
    quorum_weight: u64,
    signer_set_root: &str,
    signature_transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-CANONICAL-PQ-RELEASE-AUTHORIZATION-ID",
        &[
            HashPart::Str(claim_id),
            HashPart::U64(key_epoch),
            HashPart::U64(quorum_weight),
            HashPart::Str(signer_set_root),
            HashPart::Str(signature_transcript_root),
        ],
        32,
    )
}

fn release_eligibility(
    config: &Config,
    claim: &ForcedExitClaim,
    window: &ChallengeWindow,
    accepted_challenge_count: u64,
    liveness: &LivenessObservation,
    pq_authorized: bool,
) -> ReleaseEligibility {
    if claim.admission_status == ClaimAdmissionStatus::Rejected {
        return ReleaseEligibility::RejectedClaim;
    }
    if accepted_challenge_count > 0 {
        return ReleaseEligibility::BlockedByChallenge;
    }
    if config.fail_closed_on_censorship && liveness.sequencer_censorship_detected {
        return ReleaseEligibility::BlockedByCensorship;
    }
    if config.fail_closed_on_watcher_silence && liveness.watcher_silence_detected {
        return ReleaseEligibility::BlockedByWatcherSilence;
    }
    if !window.timeout_release_eligible {
        return ReleaseEligibility::WaitingForWindow;
    }
    if !pq_authorized {
        return ReleaseEligibility::BlockedByPqAuthorization;
    }
    ReleaseEligibility::Eligible
}

fn release_certificate_root(
    claim_id: &str,
    eligibility: ReleaseEligibility,
    window: &ChallengeWindow,
    accepted_challenge_count: u64,
    authorization: &PqReleaseAuthorization,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-CANONICAL-RELEASE-CERTIFICATE",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(eligibility.as_str()),
            HashPart::Str(&window.window_root),
            HashPart::U64(accepted_challenge_count),
            HashPart::Str(&authorization.authorization_root),
        ],
        32,
    )
}

fn challenge_rejection_reason(
    case_kind: ChallengeCaseKind,
    disposition: ChallengeDisposition,
    in_window: bool,
    age_ok: bool,
    authorized: bool,
    evidence_root: &str,
) -> String {
    if disposition == ChallengeDisposition::Accepted
        || disposition == ChallengeDisposition::NoChallenge
    {
        return "none".to_string();
    }
    if !in_window {
        return "outside_challenge_window".to_string();
    }
    if !age_ok {
        return "challenge_age_exceeded".to_string();
    }
    if !authorized {
        return "unauthorized_challenger".to_string();
    }
    if evidence_root.is_empty() {
        return "missing_evidence_root".to_string();
    }
    if !case_kind.is_valid_blocker() {
        return "non_blocking_case_kind".to_string();
    }
    "rejected_by_policy".to_string()
}

fn counters(
    claims: &[ForcedExitClaim],
    challenges: &[ChallengeCase],
    liveness: &[LivenessObservation],
    authorizations: &[PqReleaseAuthorization],
    decisions: &[ReleaseDecision],
) -> BTreeMap<String, u64> {
    let mut counters = BTreeMap::new();
    counters.insert("claims_total".to_string(), claims.len() as u64);
    counters.insert(
        "claims_admitted".to_string(),
        claims
            .iter()
            .filter(|claim| claim.admission_status == ClaimAdmissionStatus::Admitted)
            .count() as u64,
    );
    counters.insert(
        "claims_rejected".to_string(),
        claims
            .iter()
            .filter(|claim| claim.admission_status == ClaimAdmissionStatus::Rejected)
            .count() as u64,
    );
    counters.insert("challenges_total".to_string(), challenges.len() as u64);
    counters.insert(
        "challenges_accepted".to_string(),
        challenges
            .iter()
            .filter(|challenge| challenge.disposition == ChallengeDisposition::Accepted)
            .count() as u64,
    );
    counters.insert(
        "challenges_rejected".to_string(),
        challenges
            .iter()
            .filter(|challenge| challenge.disposition == ChallengeDisposition::Rejected)
            .count() as u64,
    );
    counters.insert(
        "sequencer_censorship_cases".to_string(),
        liveness
            .iter()
            .filter(|observation| observation.sequencer_censorship_detected)
            .count() as u64,
    );
    counters.insert(
        "watcher_silence_cases".to_string(),
        liveness
            .iter()
            .filter(|observation| observation.watcher_silence_detected)
            .count() as u64,
    );
    counters.insert(
        "pq_authorized".to_string(),
        authorizations
            .iter()
            .filter(|authorization| authorization.status == PqAuthorizationStatus::Authorized)
            .count() as u64,
    );
    counters.insert(
        "release_eligible".to_string(),
        decisions
            .iter()
            .filter(|decision| decision.eligibility == ReleaseEligibility::Eligible)
            .count() as u64,
    );
    counters
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-CANONICAL-RECORD",
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

fn devnet_fallback(_: String) -> State {
    let config = Config::devnet();
    let claim = ForcedExitClaim::new(
        "fallback",
        "owner_commitment_fallback",
        "exit_nullifier_fallback",
        1,
        config
            .current_height
            .saturating_sub(DEFAULT_CHALLENGE_WINDOW_BLOCKS + DEFAULT_RELEASE_DELAY_BLOCKS),
        "fallback_source_state_root",
        "fallback_monero_finality_root",
        "fallback_witness_root",
    );
    let window = ChallengeWindow::for_claim(&config, &claim);
    let liveness = LivenessObservation::evaluate(
        &config,
        &claim,
        config.current_height,
        config.current_height,
    );
    let authorization = PqReleaseAuthorization::evaluate(
        &config,
        &claim,
        1,
        1,
        config.min_pq_quorum_weight,
        "fallback_signer_set_root",
        "fallback_signature_transcript_root",
    );
    let decision =
        ReleaseDecision::evaluate(&config, &claim, &window, &[], &liveness, &authorization);
    State::from_parts(
        config,
        vec![claim],
        vec![window],
        Vec::new(),
        vec![liveness],
        vec![authorization],
        vec![decision],
    )
}
