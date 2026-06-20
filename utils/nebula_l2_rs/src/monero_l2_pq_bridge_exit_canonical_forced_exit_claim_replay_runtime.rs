use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalForcedExitClaimReplayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_FORCED_EXIT_CLAIM_REPLAY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-forced-exit-claim-replay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_FORCED_EXIT_CLAIM_REPLAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CLAIM_REPLAY_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-claim-replay-v1";
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_OPERATOR_SILENCE_BLOCKS: u64 = 16;
pub const DEFAULT_MAX_PUBLIC_METADATA_FIELDS: u16 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStage {
    ClaimAdmitted,
    EvidenceReconstructed,
    OperatorSilentCensoring,
    ChallengeWindow,
    ReleaseAuthorization,
    ReplayVerdict,
}

impl ReplayStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaimAdmitted => "claim_admitted",
            Self::EvidenceReconstructed => "evidence_reconstructed",
            Self::OperatorSilentCensoring => "operator_silent_censoring",
            Self::ChallengeWindow => "challenge_window",
            Self::ReleaseAuthorization => "release_authorization",
            Self::ReplayVerdict => "replay_verdict",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorCondition {
    Cooperative,
    Silent,
    Censoring,
    WithheldRelease,
    InvalidCounterclaim,
}

impl OperatorCondition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cooperative => "cooperative",
            Self::Silent => "silent",
            Self::Censoring => "censoring",
            Self::WithheldRelease => "withheld_release",
            Self::InvalidCounterclaim => "invalid_counterclaim",
        }
    }

    pub fn is_adversarial(self) -> bool {
        !matches!(self, Self::Cooperative)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayVerdict {
    ForceExitWithoutOperator,
    WaitingChallengeWindow,
    BlockedByChallenge,
    BlockedByEvidence,
    BlockedByPrivacy,
}

impl ReplayVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForceExitWithoutOperator => "force_exit_without_operator",
            Self::WaitingChallengeWindow => "waiting_challenge_window",
            Self::BlockedByChallenge => "blocked_by_challenge",
            Self::BlockedByEvidence => "blocked_by_evidence",
            Self::BlockedByPrivacy => "blocked_by_privacy",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub replay_suite: String,
    pub challenge_window_blocks: u64,
    pub min_monero_confirmations: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_operator_silence_blocks: u64,
    pub max_public_metadata_fields: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            replay_suite: CLAIM_REPLAY_SUITE.to_string(),
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_operator_silence_blocks: DEFAULT_MAX_OPERATOR_SILENCE_BLOCKS,
            max_public_metadata_fields: DEFAULT_MAX_PUBLIC_METADATA_FIELDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "replay_suite": self.replay_suite,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_monero_confirmations": self.min_monero_confirmations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_operator_silence_blocks": self.max_operator_silence_blocks,
            "max_public_metadata_fields": self.max_public_metadata_fields,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "FORCED-EXIT-CLAIM-REPLAY-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimAdmission {
    pub claim_id: String,
    pub deposit_commitment_root: String,
    pub exit_nullifier_root: String,
    pub wallet_authorization_root: String,
    pub admitted_at_l2_height: u64,
    pub monero_confirmations: u64,
    pub duplicate_nullifier_seen: bool,
}

impl ClaimAdmission {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "deposit_commitment_root": self.deposit_commitment_root,
            "exit_nullifier_root": self.exit_nullifier_root,
            "wallet_authorization_root": self.wallet_authorization_root,
            "admitted_at_l2_height": self.admitted_at_l2_height,
            "monero_confirmations": self.monero_confirmations,
            "duplicate_nullifier_seen": self.duplicate_nullifier_seen,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "FORCED-EXIT-CLAIM-REPLAY-CLAIM-ADMITTED",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceReconstruction {
    pub transcript_anchor_root: String,
    pub receipt_shard_root: String,
    pub private_note_set_root: String,
    pub redacted_wallet_state_root: String,
    pub reconstructed: bool,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub public_metadata_fields: u16,
}

impl EvidenceReconstruction {
    pub fn public_record(&self) -> Value {
        json!({
            "transcript_anchor_root": self.transcript_anchor_root,
            "receipt_shard_root": self.receipt_shard_root,
            "private_note_set_root": self.private_note_set_root,
            "redacted_wallet_state_root": self.redacted_wallet_state_root,
            "reconstructed": self.reconstructed,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "public_metadata_fields": self.public_metadata_fields,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "FORCED-EXIT-CLAIM-REPLAY-EVIDENCE-RECONSTRUCTED",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorAdversaryReplay {
    pub condition: OperatorCondition,
    pub silence_blocks: u64,
    pub censored_mempool_attempts: u64,
    pub operator_response_root: String,
    pub fallback_broadcast_root: String,
}

impl OperatorAdversaryReplay {
    pub fn public_record(&self) -> Value {
        json!({
            "condition": self.condition.as_str(),
            "silence_blocks": self.silence_blocks,
            "censored_mempool_attempts": self.censored_mempool_attempts,
            "operator_response_root": self.operator_response_root,
            "fallback_broadcast_root": self.fallback_broadcast_root,
            "adversarial": self.condition.is_adversarial(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "FORCED-EXIT-CLAIM-REPLAY-OPERATOR-ADVERSARY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeWindowReplay {
    pub opened_at_l2_height: u64,
    pub closed_at_l2_height: u64,
    pub replayed_at_l2_height: u64,
    pub challenge_root: String,
    pub counterclaim_root: String,
    pub valid_challenge_count: u64,
}

impl ChallengeWindowReplay {
    pub fn is_closed(&self) -> bool {
        self.replayed_at_l2_height >= self.closed_at_l2_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "opened_at_l2_height": self.opened_at_l2_height,
            "closed_at_l2_height": self.closed_at_l2_height,
            "replayed_at_l2_height": self.replayed_at_l2_height,
            "challenge_root": self.challenge_root,
            "counterclaim_root": self.counterclaim_root,
            "valid_challenge_count": self.valid_challenge_count,
            "closed": self.is_closed(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "FORCED-EXIT-CLAIM-REPLAY-CHALLENGE-WINDOW",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseAuthorizationReplay {
    pub release_authority_root: String,
    pub release_batch_root: String,
    pub replay_proof_root: String,
    pub user_payout_commitment_root: String,
    pub authorized: bool,
}

impl ReleaseAuthorizationReplay {
    pub fn public_record(&self) -> Value {
        json!({
            "release_authority_root": self.release_authority_root,
            "release_batch_root": self.release_batch_root,
            "replay_proof_root": self.replay_proof_root,
            "user_payout_commitment_root": self.user_payout_commitment_root,
            "authorized": self.authorized,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "FORCED-EXIT-CLAIM-REPLAY-RELEASE-AUTHORIZATION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StageRecord {
    pub stage: ReplayStage,
    pub stage_root: String,
    pub accepted: bool,
    pub privacy_preserving: bool,
}

impl StageRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "stage": self.stage.as_str(),
            "stage_root": self.stage_root,
            "accepted": self.accepted,
            "privacy_preserving": self.privacy_preserving,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub claim_admitted: ClaimAdmission,
    pub evidence_reconstructed: EvidenceReconstruction,
    pub operator_adversary: OperatorAdversaryReplay,
    pub challenge_window: ChallengeWindowReplay,
    pub release_authorization: ReleaseAuthorizationReplay,
    pub verdict: ReplayVerdict,
    pub can_force_exit_without_operator: bool,
    pub answer: String,
    pub stage_records: Vec<StageRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let claim_seed = replay_seed_root("devnet-canonical-forced-exit-claim");
        let admission = ClaimAdmission {
            claim_id: domain_hash(
                "FORCED-EXIT-CLAIM-REPLAY-CLAIM-ID",
                &[HashPart::Str(CHAIN_ID), HashPart::Str(&claim_seed)],
                16,
            ),
            deposit_commitment_root: labeled_root("deposit-commitment", &claim_seed),
            exit_nullifier_root: labeled_root("exit-nullifier", &claim_seed),
            wallet_authorization_root: labeled_root("wallet-pq-authorization", &claim_seed),
            admitted_at_l2_height: 88_000,
            monero_confirmations: 32,
            duplicate_nullifier_seen: false,
        };
        let evidence = EvidenceReconstruction {
            transcript_anchor_root: labeled_root("canonical-transcript-anchor", &claim_seed),
            receipt_shard_root: labeled_root("receipt-shard-threshold", &claim_seed),
            private_note_set_root: labeled_root("private-note-set", &claim_seed),
            redacted_wallet_state_root: labeled_root("redacted-wallet-state", &claim_seed),
            reconstructed: true,
            privacy_set_size: 131_072,
            pq_security_bits: 256,
            public_metadata_fields: 2,
        };
        let operator = OperatorAdversaryReplay {
            condition: OperatorCondition::Censoring,
            silence_blocks: 64,
            censored_mempool_attempts: 3,
            operator_response_root: empty_root("operator-response"),
            fallback_broadcast_root: labeled_root("fallback-user-broadcast", &claim_seed),
        };
        let challenge = ChallengeWindowReplay {
            opened_at_l2_height: admission.admitted_at_l2_height,
            closed_at_l2_height: admission.admitted_at_l2_height + config.challenge_window_blocks,
            replayed_at_l2_height: admission.admitted_at_l2_height
                + config.challenge_window_blocks
                + 12,
            challenge_root: empty_root("valid-challenges"),
            counterclaim_root: empty_root("operator-counterclaims"),
            valid_challenge_count: 0,
        };
        let release = ReleaseAuthorizationReplay {
            release_authority_root: labeled_root("release-authority-quorum", &claim_seed),
            release_batch_root: labeled_root("release-batch", &claim_seed),
            replay_proof_root: labeled_root("claim-replay-proof", &claim_seed),
            user_payout_commitment_root: labeled_root("user-payout-commitment", &claim_seed),
            authorized: true,
        };
        let verdict = derive_verdict(
            &config, &admission, &evidence, &operator, &challenge, &release,
        );
        let can_force_exit_without_operator = verdict == ReplayVerdict::ForceExitWithoutOperator;
        let answer = force_exit_answer(verdict, &operator);
        let stage_records = derive_stage_records(
            verdict, &admission, &evidence, &operator, &challenge, &release,
        );

        Self {
            config,
            claim_admitted: admission,
            evidence_reconstructed: evidence,
            operator_adversary: operator,
            challenge_window: challenge,
            release_authorization: release,
            verdict,
            can_force_exit_without_operator,
            answer,
            stage_records,
        }
    }

    pub fn public_record(&self) -> Value {
        let stage_records = self
            .stage_records
            .iter()
            .map(StageRecord::public_record)
            .collect::<Vec<_>>();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config_root": self.config.root(),
            "claim_admitted_root": self.claim_admitted.root(),
            "evidence_reconstructed_root": self.evidence_reconstructed.root(),
            "operator_adversary_root": self.operator_adversary.root(),
            "challenge_window_root": self.challenge_window.root(),
            "release_authorization_root": self.release_authorization.root(),
            "stage_root": merkle_root("FORCED-EXIT-CLAIM-REPLAY-STAGES", &stage_records),
            "verdict": self.verdict.as_str(),
            "can_force_exit_without_operator": self.can_force_exit_without_operator,
            "answer": self.answer,
            "privacy_note": "public record contains roots and policy counters only",
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "FORCED-EXIT-CLAIM-REPLAY-STATE",
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

pub fn replay_seed_root(seed: &str) -> String {
    domain_hash(
        "FORCED-EXIT-CLAIM-REPLAY-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn labeled_root(label: &str, seed_root: &str) -> String {
    domain_hash(
        "FORCED-EXIT-CLAIM-REPLAY-LABELED-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(seed_root),
        ],
        32,
    )
}

pub fn empty_root(label: &str) -> String {
    merkle_root(
        "FORCED-EXIT-CLAIM-REPLAY-EMPTY-ROOT",
        &[json!({
            "chain_id": CHAIN_ID,
            "label": label,
            "protocol_version": PROTOCOL_VERSION,
        })],
    )
}

pub fn derive_verdict(
    config: &Config,
    claim: &ClaimAdmission,
    evidence: &EvidenceReconstruction,
    operator: &OperatorAdversaryReplay,
    challenge: &ChallengeWindowReplay,
    release: &ReleaseAuthorizationReplay,
) -> ReplayVerdict {
    if claim.duplicate_nullifier_seen
        || claim.monero_confirmations < config.min_monero_confirmations
        || !evidence.reconstructed
    {
        return ReplayVerdict::BlockedByEvidence;
    }
    if evidence.privacy_set_size < config.min_privacy_set_size
        || evidence.pq_security_bits < config.min_pq_security_bits
        || evidence.public_metadata_fields > config.max_public_metadata_fields
    {
        return ReplayVerdict::BlockedByPrivacy;
    }
    if !challenge.is_closed() {
        return ReplayVerdict::WaitingChallengeWindow;
    }
    if challenge.valid_challenge_count > 0 {
        return ReplayVerdict::BlockedByChallenge;
    }
    if release.authorized
        && (operator.condition.is_adversarial()
            || operator.silence_blocks >= config.max_operator_silence_blocks)
    {
        return ReplayVerdict::ForceExitWithoutOperator;
    }
    if release.authorized {
        return ReplayVerdict::ForceExitWithoutOperator;
    }
    ReplayVerdict::BlockedByEvidence
}

pub fn derive_stage_records(
    verdict: ReplayVerdict,
    claim: &ClaimAdmission,
    evidence: &EvidenceReconstruction,
    operator: &OperatorAdversaryReplay,
    challenge: &ChallengeWindowReplay,
    release: &ReleaseAuthorizationReplay,
) -> Vec<StageRecord> {
    let verdict_root = domain_hash(
        "FORCED-EXIT-CLAIM-REPLAY-VERDICT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(verdict.as_str()),
        ],
        32,
    );
    vec![
        stage_record(ReplayStage::ClaimAdmitted, claim.root(), true, true),
        stage_record(
            ReplayStage::EvidenceReconstructed,
            evidence.root(),
            evidence.reconstructed,
            true,
        ),
        stage_record(
            ReplayStage::OperatorSilentCensoring,
            operator.root(),
            operator.condition.is_adversarial(),
            true,
        ),
        stage_record(
            ReplayStage::ChallengeWindow,
            challenge.root(),
            challenge.is_closed() && challenge.valid_challenge_count == 0,
            true,
        ),
        stage_record(
            ReplayStage::ReleaseAuthorization,
            release.root(),
            release.authorized,
            true,
        ),
        stage_record(
            ReplayStage::ReplayVerdict,
            verdict_root,
            verdict == ReplayVerdict::ForceExitWithoutOperator,
            true,
        ),
    ]
}

pub fn stage_record(
    stage: ReplayStage,
    stage_root: String,
    accepted: bool,
    privacy_preserving: bool,
) -> StageRecord {
    StageRecord {
        stage,
        stage_root,
        accepted,
        privacy_preserving,
    }
}

pub fn force_exit_answer(verdict: ReplayVerdict, operator: &OperatorAdversaryReplay) -> String {
    match verdict {
        ReplayVerdict::ForceExitWithoutOperator => format!(
            "yes: canonical replay authorizes release while operator condition is {}",
            operator.condition.as_str()
        ),
        ReplayVerdict::WaitingChallengeWindow => {
            "not yet: the canonical challenge window is still open".to_string()
        }
        ReplayVerdict::BlockedByChallenge => {
            "no: a valid challenge prevents forced-exit release".to_string()
        }
        ReplayVerdict::BlockedByEvidence => {
            "no: claim replay lacks sufficient canonical evidence".to_string()
        }
        ReplayVerdict::BlockedByPrivacy => {
            "no: replay would exceed privacy or PQ disclosure policy".to_string()
        }
    }
}
