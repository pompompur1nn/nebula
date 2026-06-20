use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitForcedExitChallengeWindowFixtureRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FORCED_EXIT_CHALLENGE_WINDOW_FIXTURE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-forced-exit-challenge-window-fixture-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FORCED_EXIT_CHALLENGE_WINDOW_FIXTURE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FIXTURE_SUITE: &str = "monero-l2-pq-bridge-exit-forced-exit-challenge-window-fixtures-v1";
pub const CLAIM_ADMISSION_SUITE: &str = "forced-exit-claim-admission-under-censorship-fixtures-v1";
pub const CHALLENGE_WINDOW_SUITE: &str = "forced-exit-challenge-window-timing-fixtures-v1";
pub const USER_EVIDENCE_PACKAGE_SUITE: &str = "forced-exit-user-local-evidence-package-fixtures-v1";
pub const DETERMINISTIC_REPLAY_SUITE: &str =
    "forced-exit-challenge-window-deterministic-replay-roots-v1";
pub const DEFAULT_CURRENT_HEIGHT: u64 = 9_420_240;
pub const DEFAULT_CLAIM_ADMISSION_WINDOW_BLOCKS: u64 = 18;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_RESPONSE_WINDOW_BLOCKS: u64 = 36;
pub const DEFAULT_TIMEOUT_RELEASE_GRACE_BLOCKS: u64 = 12;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 4;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u64 = 2;
pub const DEFAULT_MAX_FIXTURES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAdmissionStatus {
    Admitted,
    Censored,
    Rejected,
}

impl ClaimAdmissionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Censored => "censored",
            Self::Rejected => "rejected",
        }
    }

    pub fn admits_claim(self) -> bool {
        matches!(self, Self::Admitted | Self::Censored)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    None,
    Open,
    InvalidRejected,
    Responded,
    TimedOut,
    Sustained,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Open => "open",
            Self::InvalidRejected => "invalid_rejected",
            Self::Responded => "responded",
            Self::TimedOut => "timed_out",
            Self::Sustained => "sustained",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidContinuity,
    InvalidPqAuthorization,
    SequencerCensorshipClaim,
    WatcherSilenceClaim,
    MaliciousEvidence,
    FeeCapExceeded,
    PrivacyLeakage,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidContinuity => "invalid_continuity",
            Self::InvalidPqAuthorization => "invalid_pq_authorization",
            Self::SequencerCensorshipClaim => "sequencer_censorship_claim",
            Self::WatcherSilenceClaim => "watcher_silence_claim",
            Self::MaliciousEvidence => "malicious_evidence",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::PrivacyLeakage => "privacy_leakage",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversaryBehavior {
    Honest,
    SequencerCensorsAdmission,
    WatchersSilent,
    MaliciousWatcherChallenges,
    SequencerAndWatchersCollude,
}

impl AdversaryBehavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Honest => "honest",
            Self::SequencerCensorsAdmission => "sequencer_censors_admission",
            Self::WatchersSilent => "watchers_silent",
            Self::MaliciousWatcherChallenges => "malicious_watcher_challenges",
            Self::SequencerAndWatchersCollude => "sequencer_and_watchers_collude",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementEligibility {
    Eligible,
    WaitingChallengeWindow,
    WaitingResponseWindow,
    Blocked,
}

impl SettlementEligibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::WaitingChallengeWindow => "waiting_challenge_window",
            Self::WaitingResponseWindow => "waiting_response_window",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBlocker {
    None,
    ClaimNotAdmitted,
    ChallengeWindowOpen,
    ResponseWindowOpen,
    SustainedChallenge,
    InvalidPqAuthorization,
    ContinuityBroken,
    FeeAboveCap,
    PrivacyFloorMissing,
    MetadataLeakageExceeded,
}

impl ReleaseBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClaimNotAdmitted => "claim_not_admitted",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::ResponseWindowOpen => "response_window_open",
            Self::SustainedChallenge => "sustained_challenge",
            Self::InvalidPqAuthorization => "invalid_pq_authorization",
            Self::ContinuityBroken => "continuity_broken",
            Self::FeeAboveCap => "fee_above_cap",
            Self::PrivacyFloorMissing => "privacy_floor_missing",
            Self::MetadataLeakageExceeded => "metadata_leakage_exceeded",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub fixture_suite: String,
    pub claim_admission_suite: String,
    pub challenge_window_suite: String,
    pub user_evidence_package_suite: String,
    pub deterministic_replay_suite: String,
    pub current_height: u64,
    pub claim_admission_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub response_window_blocks: u64,
    pub timeout_release_grace_blocks: u64,
    pub min_watcher_quorum: u64,
    pub min_privacy_set_size: u64,
    pub low_fee_cap_atomic: u128,
    pub max_metadata_leakage_units: u64,
    pub reject_invalid_challenges: bool,
    pub allow_timeout_release: bool,
    pub require_pq_authorization: bool,
    pub require_exit_claim_continuity: bool,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_fixtures: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            fixture_suite: FIXTURE_SUITE.to_string(),
            claim_admission_suite: CLAIM_ADMISSION_SUITE.to_string(),
            challenge_window_suite: CHALLENGE_WINDOW_SUITE.to_string(),
            user_evidence_package_suite: USER_EVIDENCE_PACKAGE_SUITE.to_string(),
            deterministic_replay_suite: DETERMINISTIC_REPLAY_SUITE.to_string(),
            current_height: DEFAULT_CURRENT_HEIGHT,
            claim_admission_window_blocks: DEFAULT_CLAIM_ADMISSION_WINDOW_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            response_window_blocks: DEFAULT_RESPONSE_WINDOW_BLOCKS,
            timeout_release_grace_blocks: DEFAULT_TIMEOUT_RELEASE_GRACE_BLOCKS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            reject_invalid_challenges: true,
            allow_timeout_release: true,
            require_pq_authorization: true,
            require_exit_claim_continuity: true,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_fixtures: DEFAULT_MAX_FIXTURES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "fixture_suite": self.fixture_suite,
            "claim_admission_suite": self.claim_admission_suite,
            "challenge_window_suite": self.challenge_window_suite,
            "user_evidence_package_suite": self.user_evidence_package_suite,
            "deterministic_replay_suite": self.deterministic_replay_suite,
            "current_height": self.current_height,
            "claim_admission_window_blocks": self.claim_admission_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "response_window_blocks": self.response_window_blocks,
            "timeout_release_grace_blocks": self.timeout_release_grace_blocks,
            "min_watcher_quorum": self.min_watcher_quorum,
            "min_privacy_set_size": self.min_privacy_set_size,
            "low_fee_cap_atomic": self.low_fee_cap_atomic.to_string(),
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "reject_invalid_challenges": self.reject_invalid_challenges,
            "allow_timeout_release": self.allow_timeout_release,
            "require_pq_authorization": self.require_pq_authorization,
            "require_exit_claim_continuity": self.require_exit_claim_continuity,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_fixtures": self.max_fixtures,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitClaimFixture {
    pub claim_id: String,
    pub user_id: String,
    pub transfer_id: String,
    pub admission_status: ClaimAdmissionStatus,
    pub adversary_behavior: AdversaryBehavior,
    pub claim_height: u64,
    pub admitted_height: u64,
    pub amount_commitment_root: String,
    pub exit_claim_root: String,
    pub continuity_root: String,
    pub pq_authorization_root: String,
    pub wallet_evidence_root: String,
    pub fee_cap_atomic: u128,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u64,
    pub watcher_quorum: u64,
    pub sequencer_inclusion_root: String,
    pub censorship_evidence_root: String,
}

impl ForcedExitClaimFixture {
    pub fn new(
        config: &Config,
        user_id: &str,
        transfer_id: &str,
        adversary_behavior: AdversaryBehavior,
        claim_height: u64,
    ) -> Self {
        let admitted_height = admitted_height(config, adversary_behavior, claim_height);
        let admission_status = admission_status(adversary_behavior);
        let amount_commitment_root = label_root("amount_commitment", transfer_id);
        let continuity_root = continuity_root(user_id, transfer_id, claim_height);
        let pq_authorization_root = pq_authorization_root(user_id, transfer_id, &continuity_root);
        let wallet_evidence_root =
            wallet_evidence_root(user_id, transfer_id, &pq_authorization_root);
        let exit_claim_root = exit_claim_root(
            user_id,
            transfer_id,
            &amount_commitment_root,
            &continuity_root,
            &pq_authorization_root,
        );
        let censorship_evidence_root =
            censorship_evidence_root(user_id, transfer_id, adversary_behavior, claim_height);
        let sequencer_inclusion_root = sequencer_inclusion_root(
            transfer_id,
            admission_status,
            admitted_height,
            &censorship_evidence_root,
        );
        let claim_id = claim_id(transfer_id, &exit_claim_root);
        Self {
            claim_id,
            user_id: user_id.to_string(),
            transfer_id: transfer_id.to_string(),
            admission_status,
            adversary_behavior,
            claim_height,
            admitted_height,
            amount_commitment_root,
            exit_claim_root,
            continuity_root,
            pq_authorization_root,
            wallet_evidence_root,
            fee_cap_atomic: config.low_fee_cap_atomic,
            privacy_set_size: config.min_privacy_set_size,
            metadata_leakage_units: config.max_metadata_leakage_units,
            watcher_quorum: config.min_watcher_quorum,
            sequencer_inclusion_root,
            censorship_evidence_root,
        }
    }

    pub fn with_bad_pq_authorization(mut self) -> Self {
        self.pq_authorization_root = format!(
            "invalid_pq_authorization:{}",
            label_root("invalid_pq_authorization", &self.claim_id)
        );
        self.exit_claim_root = exit_claim_root(
            &self.user_id,
            &self.transfer_id,
            &self.amount_commitment_root,
            &self.continuity_root,
            &self.pq_authorization_root,
        );
        self
    }

    pub fn with_continuity_gap(mut self) -> Self {
        self.continuity_root = format!(
            "broken_continuity:{}",
            label_root("broken_continuity", &self.claim_id)
        );
        self.exit_claim_root = exit_claim_root(
            &self.user_id,
            &self.transfer_id,
            &self.amount_commitment_root,
            &self.continuity_root,
            &self.pq_authorization_root,
        );
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "user_id": self.user_id,
            "transfer_id": self.transfer_id,
            "admission_status": self.admission_status.as_str(),
            "adversary_behavior": self.adversary_behavior.as_str(),
            "claim_height": self.claim_height,
            "admitted_height": self.admitted_height,
            "amount_commitment_root": self.amount_commitment_root,
            "exit_claim_root": self.exit_claim_root,
            "continuity_root": self.continuity_root,
            "pq_authorization_root": self.pq_authorization_root,
            "wallet_evidence_root": self.wallet_evidence_root,
            "fee_cap_atomic": self.fee_cap_atomic.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "watcher_quorum": self.watcher_quorum,
            "sequencer_inclusion_root": self.sequencer_inclusion_root,
            "censorship_evidence_root": self.censorship_evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("forced_exit_claim_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeWindowFixture {
    pub challenge_id: String,
    pub claim_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub opened_height: u64,
    pub response_due_height: u64,
    pub challenge_window_end_height: u64,
    pub timeout_release_height: u64,
    pub challenger_root: String,
    pub challenge_evidence_root: String,
    pub response_root: String,
    pub invalidity_reason_root: String,
    pub watcher_silence_root: String,
    pub malicious_evidence_root: String,
}

impl ChallengeWindowFixture {
    pub fn none(config: &Config, claim: &ForcedExitClaimFixture) -> Self {
        Self::new(
            config,
            claim,
            ChallengeKind::SequencerCensorshipClaim,
            ChallengeStatus::None,
        )
    }

    pub fn invalid_malicious(config: &Config, claim: &ForcedExitClaimFixture) -> Self {
        Self::new(
            config,
            claim,
            ChallengeKind::MaliciousEvidence,
            ChallengeStatus::InvalidRejected,
        )
    }

    pub fn watcher_silence_timeout(config: &Config, claim: &ForcedExitClaimFixture) -> Self {
        Self::new(
            config,
            claim,
            ChallengeKind::WatcherSilenceClaim,
            ChallengeStatus::TimedOut,
        )
    }

    pub fn sustained_pq(config: &Config, claim: &ForcedExitClaimFixture) -> Self {
        Self::new(
            config,
            claim,
            ChallengeKind::InvalidPqAuthorization,
            ChallengeStatus::Sustained,
        )
    }

    pub fn new(
        config: &Config,
        claim: &ForcedExitClaimFixture,
        kind: ChallengeKind,
        status: ChallengeStatus,
    ) -> Self {
        let opened_height = claim.admitted_height.saturating_add(1);
        let response_due_height = opened_height.saturating_add(config.response_window_blocks);
        let challenge_window_end_height = claim
            .admitted_height
            .saturating_add(config.challenge_window_blocks);
        let timeout_release_height =
            response_due_height.saturating_add(config.timeout_release_grace_blocks);
        let challenger_root = challenger_root(&claim.claim_id, kind);
        let challenge_evidence_root = challenge_evidence_root(&claim.claim_id, kind, status);
        let response_root = response_root(&claim.claim_id, status, response_due_height);
        let invalidity_reason_root = invalidity_reason_root(&claim.claim_id, kind, status);
        let watcher_silence_root = watcher_silence_root(
            &claim.claim_id,
            claim.watcher_quorum,
            config.min_watcher_quorum,
            status,
        );
        let malicious_evidence_root =
            malicious_evidence_root(&claim.claim_id, kind, &challenge_evidence_root);
        let challenge_id = challenge_id(&claim.claim_id, kind, &challenge_evidence_root);
        Self {
            challenge_id,
            claim_id: claim.claim_id.clone(),
            kind,
            status,
            opened_height,
            response_due_height,
            challenge_window_end_height,
            timeout_release_height,
            challenger_root,
            challenge_evidence_root,
            response_root,
            invalidity_reason_root,
            watcher_silence_root,
            malicious_evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "claim_id": self.claim_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "response_due_height": self.response_due_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "timeout_release_height": self.timeout_release_height,
            "challenger_root": self.challenger_root,
            "challenge_evidence_root": self.challenge_evidence_root,
            "response_root": self.response_root,
            "invalidity_reason_root": self.invalidity_reason_root,
            "watcher_silence_root": self.watcher_silence_root,
            "malicious_evidence_root": self.malicious_evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("challenge_window_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserLocalEvidencePackage {
    pub package_id: String,
    pub claim_id: String,
    pub transfer_id: String,
    pub redacted_user_root: String,
    pub local_wallet_root: String,
    pub encrypted_opening_root: String,
    pub pq_authorization_root: String,
    pub continuity_root: String,
    pub censorship_evidence_root: String,
    pub challenge_response_root: String,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u64,
    pub package_root: String,
}

impl UserLocalEvidencePackage {
    pub fn for_claim(claim: &ForcedExitClaimFixture, challenge: &ChallengeWindowFixture) -> Self {
        let redacted_user_root = label_root("redacted_user", &claim.user_id);
        let local_wallet_root = local_wallet_root(
            &claim.user_id,
            &claim.transfer_id,
            &claim.wallet_evidence_root,
        );
        let encrypted_opening_root =
            encrypted_opening_root(&claim.claim_id, &challenge.challenge_id);
        let challenge_response_root = challenge.response_root.clone();
        let package_root = user_package_root(
            &claim.claim_id,
            &redacted_user_root,
            &local_wallet_root,
            &encrypted_opening_root,
            &claim.pq_authorization_root,
            &claim.continuity_root,
            &challenge_response_root,
        );
        let package_id = package_id(&claim.claim_id, &package_root);
        Self {
            package_id,
            claim_id: claim.claim_id.clone(),
            transfer_id: claim.transfer_id.clone(),
            redacted_user_root,
            local_wallet_root,
            encrypted_opening_root,
            pq_authorization_root: claim.pq_authorization_root.clone(),
            continuity_root: claim.continuity_root.clone(),
            censorship_evidence_root: claim.censorship_evidence_root.clone(),
            challenge_response_root,
            privacy_set_size: claim.privacy_set_size,
            metadata_leakage_units: claim.metadata_leakage_units,
            package_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "package_id": self.package_id,
            "claim_id": self.claim_id,
            "transfer_id": self.transfer_id,
            "redacted_user_root": self.redacted_user_root,
            "local_wallet_root": self.local_wallet_root,
            "encrypted_opening_root": self.encrypted_opening_root,
            "pq_authorization_root": self.pq_authorization_root,
            "continuity_root": self.continuity_root,
            "censorship_evidence_root": self.censorship_evidence_root,
            "challenge_response_root": self.challenge_response_root,
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "package_root": self.package_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.package_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementDecision {
    pub decision_id: String,
    pub claim_id: String,
    pub eligibility: SettlementEligibility,
    pub release_blocker: ReleaseBlocker,
    pub release_height: u64,
    pub timeout_release_allowed: bool,
    pub invalid_challenge_rejected: bool,
    pub low_fee_cap_satisfied: bool,
    pub pq_authorization_satisfied: bool,
    pub continuity_satisfied: bool,
    pub privacy_satisfied: bool,
    pub decision_root: String,
}

impl SettlementDecision {
    pub fn evaluate(
        config: &Config,
        claim: &ForcedExitClaimFixture,
        challenge: &ChallengeWindowFixture,
    ) -> Self {
        let low_fee_cap_satisfied = claim.fee_cap_atomic <= config.low_fee_cap_atomic;
        let pq_authorization_satisfied = !claim
            .pq_authorization_root
            .contains("invalid_pq_authorization");
        let continuity_satisfied = !claim.continuity_root.contains("broken_continuity");
        let privacy_satisfied = claim.privacy_set_size >= config.min_privacy_set_size
            && claim.metadata_leakage_units <= config.max_metadata_leakage_units;
        let invalid_challenge_rejected = config.reject_invalid_challenges
            && challenge.status == ChallengeStatus::InvalidRejected;
        let release_blocker = release_blocker(
            config,
            claim,
            challenge,
            low_fee_cap_satisfied,
            pq_authorization_satisfied,
            continuity_satisfied,
            privacy_satisfied,
        );
        let eligibility = eligibility(config, claim, challenge, release_blocker);
        let release_height = release_height(config, claim, challenge, eligibility);
        let timeout_release_allowed =
            config.allow_timeout_release && challenge.status == ChallengeStatus::TimedOut;
        let decision_root = settlement_decision_root(
            &claim.claim_id,
            eligibility,
            release_blocker,
            release_height,
            invalid_challenge_rejected,
            timeout_release_allowed,
        );
        let decision_id = decision_id(&claim.claim_id, &decision_root);
        Self {
            decision_id,
            claim_id: claim.claim_id.clone(),
            eligibility,
            release_blocker,
            release_height,
            timeout_release_allowed,
            invalid_challenge_rejected,
            low_fee_cap_satisfied,
            pq_authorization_satisfied,
            continuity_satisfied,
            privacy_satisfied,
            decision_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "claim_id": self.claim_id,
            "eligibility": self.eligibility.as_str(),
            "release_blocker": self.release_blocker.as_str(),
            "release_height": self.release_height,
            "timeout_release_allowed": self.timeout_release_allowed,
            "invalid_challenge_rejected": self.invalid_challenge_rejected,
            "low_fee_cap_satisfied": self.low_fee_cap_satisfied,
            "pq_authorization_satisfied": self.pq_authorization_satisfied,
            "continuity_satisfied": self.continuity_satisfied,
            "privacy_satisfied": self.privacy_satisfied,
            "decision_root": self.decision_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.decision_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitChallengeWindowScenario {
    pub scenario_id: String,
    pub label: String,
    pub claim: ForcedExitClaimFixture,
    pub challenge: ChallengeWindowFixture,
    pub user_evidence_package: UserLocalEvidencePackage,
    pub settlement_decision: SettlementDecision,
    pub replay_root: String,
}

impl ForcedExitChallengeWindowScenario {
    pub fn new(
        label: &str,
        claim: ForcedExitClaimFixture,
        challenge: ChallengeWindowFixture,
        config: &Config,
    ) -> Self {
        let user_evidence_package = UserLocalEvidencePackage::for_claim(&claim, &challenge);
        let settlement_decision = SettlementDecision::evaluate(config, &claim, &challenge);
        let replay_root = replay_root(
            label,
            &claim.state_root(),
            &challenge.state_root(),
            &user_evidence_package.state_root(),
            &settlement_decision.state_root(),
        );
        let scenario_id = scenario_id(label, &replay_root);
        Self {
            scenario_id,
            label: label.to_string(),
            claim,
            challenge,
            user_evidence_package,
            settlement_decision,
            replay_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scenario_id": self.scenario_id,
            "label": self.label,
            "claim": self.claim.public_record(),
            "challenge": self.challenge.public_record(),
            "user_evidence_package": self.user_evidence_package.public_record(),
            "settlement_decision": self.settlement_decision.public_record(),
            "replay_root": self.replay_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.replay_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub scenarios: BTreeMap<String, ForcedExitChallengeWindowScenario>,
    pub claim_root: String,
    pub challenge_root: String,
    pub user_evidence_package_root: String,
    pub settlement_decision_root: String,
    pub deterministic_replay_root: String,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            scenarios: BTreeMap::new(),
            claim_root: empty_root("claims"),
            challenge_root: empty_root("challenges"),
            user_evidence_package_root: empty_root("user_evidence_packages"),
            settlement_decision_root: empty_root("settlement_decisions"),
            deterministic_replay_root: empty_root("deterministic_replay"),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone());
        let honest_claim = ForcedExitClaimFixture::new(
            &config,
            "devnet-user-honest",
            "devnet-forced-exit-honest",
            AdversaryBehavior::Honest,
            config.current_height - 240,
        );
        let honest_challenge = ChallengeWindowFixture::none(&config, &honest_claim);
        let _ = state.insert_scenario(ForcedExitChallengeWindowScenario::new(
            "honest-time-window-release",
            honest_claim,
            honest_challenge,
            &config,
        ));

        let censored_claim = ForcedExitClaimFixture::new(
            &config,
            "devnet-user-censored",
            "devnet-forced-exit-censored",
            AdversaryBehavior::SequencerCensorsAdmission,
            config.current_height - 220,
        );
        let censored_challenge =
            ChallengeWindowFixture::invalid_malicious(&config, &censored_claim);
        let _ = state.insert_scenario(ForcedExitChallengeWindowScenario::new(
            "sequencer-censorship-invalid-challenge-rejected",
            censored_claim,
            censored_challenge,
            &config,
        ));

        let silent_claim = ForcedExitClaimFixture::new(
            &config,
            "devnet-user-watcher-silence",
            "devnet-forced-exit-watcher-silence",
            AdversaryBehavior::WatchersSilent,
            config.current_height - 196,
        );
        let silent_challenge =
            ChallengeWindowFixture::watcher_silence_timeout(&config, &silent_claim);
        let _ = state.insert_scenario(ForcedExitChallengeWindowScenario::new(
            "watcher-silence-timeout-release",
            silent_claim,
            silent_challenge,
            &config,
        ));

        let bad_pq_claim = ForcedExitClaimFixture::new(
            &config,
            "devnet-user-bad-pq",
            "devnet-forced-exit-bad-pq",
            AdversaryBehavior::MaliciousWatcherChallenges,
            config.current_height - 188,
        )
        .with_bad_pq_authorization();
        let bad_pq_challenge = ChallengeWindowFixture::sustained_pq(&config, &bad_pq_claim);
        let _ = state.insert_scenario(ForcedExitChallengeWindowScenario::new(
            "invalid-pq-authorization-blocked",
            bad_pq_claim,
            bad_pq_challenge,
            &config,
        ));
        state
    }

    pub fn insert_scenario(&mut self, scenario: ForcedExitChallengeWindowScenario) -> Result<()> {
        if self.scenarios.len() >= self.config.max_fixtures {
            return Err("forced exit challenge-window fixture capacity exceeded".to_string());
        }
        if self.scenarios.contains_key(&scenario.scenario_id) {
            return Err(format!(
                "duplicate forced exit challenge-window scenario {}",
                scenario.scenario_id
            ));
        }
        self.scenarios
            .insert(scenario.scenario_id.clone(), scenario);
        self.recompute_roots();
        Ok(())
    }

    pub fn recompute_roots(&mut self) {
        self.claim_root = merkle_root(
            "forced-exit-challenge-window-fixture:claims",
            self.scenarios
                .values()
                .map(|scenario| scenario.claim.state_root())
                .collect::<Vec<_>>(),
        );
        self.challenge_root = merkle_root(
            "forced-exit-challenge-window-fixture:challenges",
            self.scenarios
                .values()
                .map(|scenario| scenario.challenge.state_root())
                .collect::<Vec<_>>(),
        );
        self.user_evidence_package_root = merkle_root(
            "forced-exit-challenge-window-fixture:user-evidence-packages",
            self.scenarios
                .values()
                .map(|scenario| scenario.user_evidence_package.state_root())
                .collect::<Vec<_>>(),
        );
        self.settlement_decision_root = merkle_root(
            "forced-exit-challenge-window-fixture:settlement-decisions",
            self.scenarios
                .values()
                .map(|scenario| scenario.settlement_decision.state_root())
                .collect::<Vec<_>>(),
        );
        self.deterministic_replay_root = merkle_root(
            "forced-exit-challenge-window-fixture:deterministic-replay",
            self.scenarios
                .values()
                .map(ForcedExitChallengeWindowScenario::state_root)
                .collect::<Vec<_>>(),
        );
    }

    pub fn admitted_claims(&self) -> Vec<&ForcedExitClaimFixture> {
        self.scenarios
            .values()
            .map(|scenario| &scenario.claim)
            .filter(|claim| claim.admission_status.admits_claim())
            .collect()
    }

    pub fn settlement_ready_scenarios(&self) -> Vec<&ForcedExitChallengeWindowScenario> {
        self.scenarios
            .values()
            .filter(|scenario| {
                scenario.settlement_decision.eligibility == SettlementEligibility::Eligible
            })
            .collect()
    }

    pub fn public_record(&self) -> Value {
        let scenarios = self
            .scenarios
            .values()
            .map(ForcedExitChallengeWindowScenario::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "scenario_count": self.scenarios.len(),
            "scenarios": scenarios,
            "claim_root": self.claim_root,
            "challenge_root": self.challenge_root,
            "user_evidence_package_root": self.user_evidence_package_root,
            "settlement_decision_root": self.settlement_decision_root,
            "deterministic_replay_root": self.deterministic_replay_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
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

fn admission_status(adversary_behavior: AdversaryBehavior) -> ClaimAdmissionStatus {
    match adversary_behavior {
        AdversaryBehavior::SequencerCensorsAdmission
        | AdversaryBehavior::SequencerAndWatchersCollude => ClaimAdmissionStatus::Censored,
        _ => ClaimAdmissionStatus::Admitted,
    }
}

fn admitted_height(
    config: &Config,
    adversary_behavior: AdversaryBehavior,
    claim_height: u64,
) -> u64 {
    match adversary_behavior {
        AdversaryBehavior::SequencerCensorsAdmission
        | AdversaryBehavior::SequencerAndWatchersCollude => {
            claim_height.saturating_add(config.claim_admission_window_blocks)
        }
        _ => claim_height.saturating_add(1),
    }
}

fn release_blocker(
    config: &Config,
    claim: &ForcedExitClaimFixture,
    challenge: &ChallengeWindowFixture,
    low_fee_cap_satisfied: bool,
    pq_authorization_satisfied: bool,
    continuity_satisfied: bool,
    privacy_satisfied: bool,
) -> ReleaseBlocker {
    if !claim.admission_status.admits_claim() {
        return ReleaseBlocker::ClaimNotAdmitted;
    }
    if !low_fee_cap_satisfied {
        return ReleaseBlocker::FeeAboveCap;
    }
    if config.require_pq_authorization && !pq_authorization_satisfied {
        return ReleaseBlocker::InvalidPqAuthorization;
    }
    if config.require_exit_claim_continuity && !continuity_satisfied {
        return ReleaseBlocker::ContinuityBroken;
    }
    if claim.privacy_set_size < config.min_privacy_set_size {
        return ReleaseBlocker::PrivacyFloorMissing;
    }
    if !privacy_satisfied {
        return ReleaseBlocker::MetadataLeakageExceeded;
    }
    match challenge.status {
        ChallengeStatus::Open => ReleaseBlocker::ResponseWindowOpen,
        ChallengeStatus::Sustained => ReleaseBlocker::SustainedChallenge,
        _ => ReleaseBlocker::None,
    }
}

fn eligibility(
    config: &Config,
    claim: &ForcedExitClaimFixture,
    challenge: &ChallengeWindowFixture,
    blocker: ReleaseBlocker,
) -> SettlementEligibility {
    if blocker != ReleaseBlocker::None {
        return SettlementEligibility::Blocked;
    }
    if config.current_height
        < claim
            .admitted_height
            .saturating_add(config.challenge_window_blocks)
    {
        return SettlementEligibility::WaitingChallengeWindow;
    }
    if challenge.status == ChallengeStatus::Open
        && config.current_height < challenge.response_due_height
    {
        return SettlementEligibility::WaitingResponseWindow;
    }
    SettlementEligibility::Eligible
}

fn release_height(
    config: &Config,
    claim: &ForcedExitClaimFixture,
    challenge: &ChallengeWindowFixture,
    eligibility: SettlementEligibility,
) -> u64 {
    match eligibility {
        SettlementEligibility::Eligible if challenge.status == ChallengeStatus::TimedOut => {
            challenge.timeout_release_height
        }
        SettlementEligibility::Eligible => claim
            .admitted_height
            .saturating_add(config.challenge_window_blocks),
        _ => 0,
    }
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-forced-exit-challenge-window:{domain}"),
        &[HashPart::Str(&record.to_string())],
        32,
    )
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:empty-root",
        &[HashPart::Str(label)],
        32,
    )
}

fn label_root(kind: &str, label: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:label-root",
        &[HashPart::Str(kind), HashPart::Str(label)],
        32,
    )
}

fn continuity_root(user_id: &str, transfer_id: &str, claim_height: u64) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:continuity-root",
        &[
            HashPart::Str(user_id),
            HashPart::Str(transfer_id),
            HashPart::U64(claim_height),
        ],
        32,
    )
}

fn pq_authorization_root(user_id: &str, transfer_id: &str, continuity_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:pq-authorization-root",
        &[
            HashPart::Str(user_id),
            HashPart::Str(transfer_id),
            HashPart::Str(continuity_root),
        ],
        32,
    )
}

fn wallet_evidence_root(user_id: &str, transfer_id: &str, pq_authorization_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:wallet-evidence-root",
        &[
            HashPart::Str(user_id),
            HashPart::Str(transfer_id),
            HashPart::Str(pq_authorization_root),
        ],
        32,
    )
}

fn exit_claim_root(
    user_id: &str,
    transfer_id: &str,
    amount_commitment_root: &str,
    continuity_root: &str,
    pq_authorization_root: &str,
) -> String {
    merkle_root(
        "monero-l2-pq-forced-exit-challenge-window:exit-claim-root",
        vec![
            label_root("user", user_id),
            label_root("transfer", transfer_id),
            amount_commitment_root.to_string(),
            continuity_root.to_string(),
            pq_authorization_root.to_string(),
        ],
    )
}

fn censorship_evidence_root(
    user_id: &str,
    transfer_id: &str,
    adversary_behavior: AdversaryBehavior,
    claim_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:censorship-evidence-root",
        &[
            HashPart::Str(user_id),
            HashPart::Str(transfer_id),
            HashPart::Str(adversary_behavior.as_str()),
            HashPart::U64(claim_height),
        ],
        32,
    )
}

fn sequencer_inclusion_root(
    transfer_id: &str,
    admission_status: ClaimAdmissionStatus,
    admitted_height: u64,
    censorship_evidence_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:sequencer-inclusion-root",
        &[
            HashPart::Str(transfer_id),
            HashPart::Str(admission_status.as_str()),
            HashPart::U64(admitted_height),
            HashPart::Str(censorship_evidence_root),
        ],
        32,
    )
}

fn claim_id(transfer_id: &str, exit_claim_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:claim-id",
        &[HashPart::Str(transfer_id), HashPart::Str(exit_claim_root)],
        16,
    )
}

fn challenger_root(claim_id: &str, kind: ChallengeKind) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:challenger-root",
        &[HashPart::Str(claim_id), HashPart::Str(kind.as_str())],
        32,
    )
}

fn challenge_evidence_root(claim_id: &str, kind: ChallengeKind, status: ChallengeStatus) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:challenge-evidence-root",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

fn response_root(claim_id: &str, status: ChallengeStatus, response_due_height: u64) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:response-root",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(status.as_str()),
            HashPart::U64(response_due_height),
        ],
        32,
    )
}

fn invalidity_reason_root(claim_id: &str, kind: ChallengeKind, status: ChallengeStatus) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:invalidity-reason-root",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

fn watcher_silence_root(
    claim_id: &str,
    watcher_quorum: u64,
    min_watcher_quorum: u64,
    status: ChallengeStatus,
) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:watcher-silence-root",
        &[
            HashPart::Str(claim_id),
            HashPart::U64(watcher_quorum),
            HashPart::U64(min_watcher_quorum),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

fn malicious_evidence_root(
    claim_id: &str,
    kind: ChallengeKind,
    challenge_evidence_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:malicious-evidence-root",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(challenge_evidence_root),
        ],
        32,
    )
}

fn challenge_id(claim_id: &str, kind: ChallengeKind, challenge_evidence_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:challenge-id",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(challenge_evidence_root),
        ],
        16,
    )
}

fn local_wallet_root(user_id: &str, transfer_id: &str, wallet_evidence_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:local-wallet-root",
        &[
            HashPart::Str(user_id),
            HashPart::Str(transfer_id),
            HashPart::Str(wallet_evidence_root),
        ],
        32,
    )
}

fn encrypted_opening_root(claim_id: &str, challenge_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:encrypted-opening-root",
        &[HashPart::Str(claim_id), HashPart::Str(challenge_id)],
        32,
    )
}

fn user_package_root(
    claim_id: &str,
    redacted_user_root: &str,
    local_wallet_root: &str,
    encrypted_opening_root: &str,
    pq_authorization_root: &str,
    continuity_root: &str,
    challenge_response_root: &str,
) -> String {
    merkle_root(
        "monero-l2-pq-forced-exit-challenge-window:user-package-root",
        vec![
            label_root("claim", claim_id),
            redacted_user_root.to_string(),
            local_wallet_root.to_string(),
            encrypted_opening_root.to_string(),
            pq_authorization_root.to_string(),
            continuity_root.to_string(),
            challenge_response_root.to_string(),
        ],
    )
}

fn package_id(claim_id: &str, package_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:package-id",
        &[HashPart::Str(claim_id), HashPart::Str(package_root)],
        16,
    )
}

fn settlement_decision_root(
    claim_id: &str,
    eligibility: SettlementEligibility,
    release_blocker: ReleaseBlocker,
    release_height: u64,
    invalid_challenge_rejected: bool,
    timeout_release_allowed: bool,
) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:settlement-decision-root",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(eligibility.as_str()),
            HashPart::Str(release_blocker.as_str()),
            HashPart::U64(release_height),
            HashPart::Str(if invalid_challenge_rejected { "1" } else { "0" }),
            HashPart::Str(if timeout_release_allowed { "1" } else { "0" }),
        ],
        32,
    )
}

fn decision_id(claim_id: &str, decision_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:decision-id",
        &[HashPart::Str(claim_id), HashPart::Str(decision_root)],
        16,
    )
}

fn replay_root(
    label: &str,
    claim_root: &str,
    challenge_root: &str,
    user_package_root: &str,
    settlement_decision_root: &str,
) -> String {
    merkle_root(
        "monero-l2-pq-forced-exit-challenge-window:replay-root",
        vec![
            label_root("scenario", label),
            claim_root.to_string(),
            challenge_root.to_string(),
            user_package_root.to_string(),
            settlement_decision_root.to_string(),
        ],
    )
}

fn scenario_id(label: &str, replay_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-forced-exit-challenge-window:scenario-id",
        &[HashPart::Str(label), HashPart::Str(replay_root)],
        16,
    )
}
