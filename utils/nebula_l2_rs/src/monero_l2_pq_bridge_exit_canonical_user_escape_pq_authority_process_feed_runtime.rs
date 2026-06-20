use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapePqAuthorityProcessFeedRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PQ_AUTHORITY_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-pq-authority-process-feed-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PQ_AUTHORITY_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PROCESS_FEED_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-pq-authority-process-feed-v1";
pub const DEFAULT_ESCAPE_ID: &str = "canonical-user-escape-pq-authority-process-feed-devnet-0001";
pub const DEFAULT_CURRENT_KEY_EPOCH: u64 = 144;
pub const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u16 = 6_700;
pub const DEFAULT_MIN_BRIDGE_WEIGHT_BPS: u16 = 7_200;
pub const DEFAULT_MIN_ROTATION_WEIGHT_BPS: u16 = 8_000;
pub const DEFAULT_MAX_SIGNATURE_AGE_BLOCKS: u64 = 36;
pub const DEFAULT_HOLD_REVIEW_BLOCKS: u64 = 18;
pub const DEFAULT_L2_HEIGHT: u64 = 4_240_080;
pub const DEFAULT_MONERO_HEIGHT: u64 = 1_934_760;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqScheme {
    MlDsa87,
    SlhDsaShake256f,
    HybridMlDsaSlhDsaShake,
}

impl PqScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridMlDsaSlhDsaShake => "hybrid_ml_dsa_slh_dsa_shake",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedObservationKind {
    WatcherCertificate,
    BridgeAttestation,
    KeyEpoch,
    RotationEvidence,
}

impl FeedObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatcherCertificate => "watcher_certificate",
            Self::BridgeAttestation => "bridge_attestation",
            Self::KeyEpoch => "key_epoch",
            Self::RotationEvidence => "rotation_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationDecision {
    Accepted,
    Blocked,
    Held,
}

impl ObservationDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Blocked => "blocked",
            Self::Held => "held",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerReason {
    None,
    StaleSignature,
    InsufficientWatcherWeight,
    InsufficientBridgeWeight,
    InsufficientRotationWeight,
    KeyEpochMismatch,
    RotationEvidenceMissing,
    WatcherCertificateMissing,
    BridgeAttestationMissing,
    ReleaseHoldActive,
}

impl BlockerReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StaleSignature => "stale_signature",
            Self::InsufficientWatcherWeight => "insufficient_watcher_weight",
            Self::InsufficientBridgeWeight => "insufficient_bridge_weight",
            Self::InsufficientRotationWeight => "insufficient_rotation_weight",
            Self::KeyEpochMismatch => "key_epoch_mismatch",
            Self::RotationEvidenceMissing => "rotation_evidence_missing",
            Self::WatcherCertificateMissing => "watcher_certificate_missing",
            Self::BridgeAttestationMissing => "bridge_attestation_missing",
            Self::ReleaseHoldActive => "release_hold_active",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldStatus {
    Clear,
    Active,
}

impl HoldStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Active => "active",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub process_feed_suite: String,
    pub current_key_epoch: u64,
    pub min_watcher_weight_bps: u16,
    pub min_bridge_weight_bps: u16,
    pub min_rotation_weight_bps: u16,
    pub max_signature_age_blocks: u64,
    pub hold_review_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            process_feed_suite: PROCESS_FEED_SUITE.to_string(),
            current_key_epoch: DEFAULT_CURRENT_KEY_EPOCH,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            min_bridge_weight_bps: DEFAULT_MIN_BRIDGE_WEIGHT_BPS,
            min_rotation_weight_bps: DEFAULT_MIN_ROTATION_WEIGHT_BPS,
            max_signature_age_blocks: DEFAULT_MAX_SIGNATURE_AGE_BLOCKS,
            hold_review_blocks: DEFAULT_HOLD_REVIEW_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "process_feed_suite": self.process_feed_suite,
            "current_key_epoch": self.current_key_epoch,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "min_bridge_weight_bps": self.min_bridge_weight_bps,
            "min_rotation_weight_bps": self.min_rotation_weight_bps,
            "max_signature_age_blocks": self.max_signature_age_blocks,
            "hold_review_blocks": self.hold_review_blocks
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorityProcessObservation {
    pub observation_id: String,
    pub escape_id: String,
    pub authority_id: String,
    pub operator_id: String,
    pub kind: FeedObservationKind,
    pub scheme: PqScheme,
    pub key_epoch: u64,
    pub threshold_weight_bps: u16,
    pub signed_at_l2_height: u64,
    pub observed_at_l2_height: u64,
    pub monero_height: u64,
    pub payload_root: String,
    pub transcript_root: String,
    pub signature_commitment: String,
    pub rotation_evidence_root: String,
}

impl AuthorityProcessObservation {
    pub fn signature_age_blocks(&self) -> u64 {
        self.observed_at_l2_height
            .saturating_sub(self.signed_at_l2_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "escape_id": self.escape_id,
            "authority_id": self.authority_id,
            "operator_id": self.operator_id,
            "kind": self.kind.as_str(),
            "scheme": self.scheme.as_str(),
            "key_epoch": self.key_epoch,
            "threshold_weight_bps": self.threshold_weight_bps,
            "signed_at_l2_height": self.signed_at_l2_height,
            "observed_at_l2_height": self.observed_at_l2_height,
            "signature_age_blocks": self.signature_age_blocks(),
            "monero_height": self.monero_height,
            "payload_root": self.payload_root,
            "transcript_root": self.transcript_root,
            "signature_commitment": self.signature_commitment,
            "rotation_evidence_root": self.rotation_evidence_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority-process-observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservationEvaluation {
    pub observation_id: String,
    pub kind: FeedObservationKind,
    pub decision: ObservationDecision,
    pub blocker_reason: BlockerReason,
    pub accepted_weight_bps: u16,
    pub required_weight_bps: u16,
    pub key_epoch: u64,
    pub signature_age_blocks: u64,
    pub evidence_root: String,
}

impl ObservationEvaluation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "kind": self.kind.as_str(),
            "decision": self.decision.as_str(),
            "blocker_reason": self.blocker_reason.as_str(),
            "accepted_weight_bps": self.accepted_weight_bps,
            "required_weight_bps": self.required_weight_bps,
            "key_epoch": self.key_epoch,
            "signature_age_blocks": self.signature_age_blocks,
            "evidence_root": self.evidence_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observation-evaluation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseAuthorizationHold {
    pub hold_id: String,
    pub escape_id: String,
    pub status: HoldStatus,
    pub reason: BlockerReason,
    pub opened_at_l2_height: u64,
    pub review_not_before_l2_height: u64,
    pub blocker_root: String,
    pub release_authorization_root: String,
}

impl ReleaseAuthorizationHold {
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "escape_id": self.escape_id,
            "status": self.status.as_str(),
            "reason": self.reason.as_str(),
            "opened_at_l2_height": self.opened_at_l2_height,
            "review_not_before_l2_height": self.review_not_before_l2_height,
            "blocker_root": self.blocker_root,
            "release_authorization_root": self.release_authorization_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-authorization-hold", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProcessFeedSummary {
    pub escape_id: String,
    pub watcher_certificate_count: u64,
    pub bridge_attestation_count: u64,
    pub key_epoch_observation_count: u64,
    pub rotation_evidence_count: u64,
    pub accepted_observation_count: u64,
    pub blocked_observation_count: u64,
    pub held_observation_count: u64,
    pub watcher_weight_bps: u16,
    pub bridge_weight_bps: u16,
    pub rotation_weight_bps: u16,
    pub stale_signature_count: u64,
    pub release_hold_count: u64,
    pub release_authorized: bool,
    pub canonical_release_authorization_root: String,
}

impl ProcessFeedSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "watcher_certificate_count": self.watcher_certificate_count,
            "bridge_attestation_count": self.bridge_attestation_count,
            "key_epoch_observation_count": self.key_epoch_observation_count,
            "rotation_evidence_count": self.rotation_evidence_count,
            "accepted_observation_count": self.accepted_observation_count,
            "blocked_observation_count": self.blocked_observation_count,
            "held_observation_count": self.held_observation_count,
            "watcher_weight_bps": self.watcher_weight_bps,
            "bridge_weight_bps": self.bridge_weight_bps,
            "rotation_weight_bps": self.rotation_weight_bps,
            "stale_signature_count": self.stale_signature_count,
            "release_hold_count": self.release_hold_count,
            "release_authorized": self.release_authorized,
            "canonical_release_authorization_root": self.canonical_release_authorization_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("process-feed-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub observations: Vec<AuthorityProcessObservation>,
    pub evaluations: Vec<ObservationEvaluation>,
    pub release_holds: Vec<ReleaseAuthorizationHold>,
    pub summary: ProcessFeedSummary,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let observations = devnet_observations(&config);
        let evaluations = evaluate_observations(&config, &observations);
        let blocker_records = evaluations
            .iter()
            .filter(|evaluation| evaluation.blocker_reason != BlockerReason::None)
            .map(ObservationEvaluation::public_record)
            .collect::<Vec<_>>();
        let blocker_root = merkle_root(
            "monero-l2-pq-bridge-exit-user-escape-pq-authority-process-feed-blockers",
            &blocker_records,
        );
        let release_authorization_root =
            release_authorization_root(&config, &observations, &evaluations, &blocker_root);
        let release_holds = devnet_release_holds(
            &config,
            &evaluations,
            &blocker_root,
            &release_authorization_root,
        );
        let summary = summarize_process_feed(
            &config,
            &observations,
            &evaluations,
            &release_holds,
            &release_authorization_root,
        );

        Self {
            config,
            observations,
            evaluations,
            release_holds,
            summary,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "process_feed_suite": PROCESS_FEED_SUITE,
            "config": self.config.public_record(),
            "observations": records_from_observations(&self.observations),
            "evaluations": records_from_evaluations(&self.evaluations),
            "release_holds": records_from_holds(&self.release_holds),
            "summary": self.summary.public_record(),
            "roots": self.roots_record()
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record_without_state_root())
    }

    pub fn roots_record(&self) -> Value {
        let observation_records = records_from_observations(&self.observations);
        let evaluation_records = records_from_evaluations(&self.evaluations);
        let hold_records = records_from_holds(&self.release_holds);

        json!({
            "config_root": self.config.state_root(),
            "observation_root": merkle_root(
                "monero-l2-pq-bridge-exit-user-escape-pq-authority-process-feed-observations",
                &observation_records
            ),
            "evaluation_root": merkle_root(
                "monero-l2-pq-bridge-exit-user-escape-pq-authority-process-feed-evaluations",
                &evaluation_records
            ),
            "release_hold_root": merkle_root(
                "monero-l2-pq-bridge-exit-user-escape-pq-authority-process-feed-release-holds",
                &hold_records
            ),
            "summary_root": self.summary.state_root()
        })
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

fn evaluate_observations(
    config: &Config,
    observations: &[AuthorityProcessObservation],
) -> Vec<ObservationEvaluation> {
    observations
        .iter()
        .map(|observation| {
            let required_weight_bps = required_weight(config, observation.kind);
            let signature_age_blocks = observation.signature_age_blocks();
            let blocker_reason = blocker_reason(config, observation, required_weight_bps);
            let decision = match blocker_reason {
                BlockerReason::None => ObservationDecision::Accepted,
                BlockerReason::ReleaseHoldActive => ObservationDecision::Held,
                _ => ObservationDecision::Blocked,
            };
            let evidence_root = evaluation_evidence_root(observation, blocker_reason);

            ObservationEvaluation {
                observation_id: observation.observation_id.clone(),
                kind: observation.kind,
                decision,
                blocker_reason,
                accepted_weight_bps: observation.threshold_weight_bps,
                required_weight_bps,
                key_epoch: observation.key_epoch,
                signature_age_blocks,
                evidence_root,
            }
        })
        .collect()
}

fn blocker_reason(
    config: &Config,
    observation: &AuthorityProcessObservation,
    required_weight_bps: u16,
) -> BlockerReason {
    if observation.signature_age_blocks() > config.max_signature_age_blocks {
        return BlockerReason::StaleSignature;
    }
    if observation.key_epoch != config.current_key_epoch {
        return BlockerReason::KeyEpochMismatch;
    }
    if observation.kind == FeedObservationKind::RotationEvidence
        && observation.rotation_evidence_root == empty_root("rotation-evidence")
    {
        return BlockerReason::RotationEvidenceMissing;
    }
    if observation.threshold_weight_bps < required_weight_bps {
        return match observation.kind {
            FeedObservationKind::WatcherCertificate => BlockerReason::InsufficientWatcherWeight,
            FeedObservationKind::BridgeAttestation => BlockerReason::InsufficientBridgeWeight,
            FeedObservationKind::KeyEpoch | FeedObservationKind::RotationEvidence => {
                BlockerReason::InsufficientRotationWeight
            }
        };
    }
    if observation.kind == FeedObservationKind::BridgeAttestation
        && observation.authority_id == "pq-authority-release-hold-delta"
    {
        return BlockerReason::ReleaseHoldActive;
    }
    BlockerReason::None
}

fn required_weight(config: &Config, kind: FeedObservationKind) -> u16 {
    match kind {
        FeedObservationKind::WatcherCertificate => config.min_watcher_weight_bps,
        FeedObservationKind::BridgeAttestation => config.min_bridge_weight_bps,
        FeedObservationKind::KeyEpoch | FeedObservationKind::RotationEvidence => {
            config.min_rotation_weight_bps
        }
    }
}

fn summarize_process_feed(
    config: &Config,
    observations: &[AuthorityProcessObservation],
    evaluations: &[ObservationEvaluation],
    release_holds: &[ReleaseAuthorizationHold],
    release_authorization_root: &str,
) -> ProcessFeedSummary {
    let watcher_weight_bps =
        accepted_weight_for_kind(evaluations, FeedObservationKind::WatcherCertificate);
    let bridge_weight_bps =
        accepted_weight_for_kind(evaluations, FeedObservationKind::BridgeAttestation);
    let rotation_weight_bps =
        accepted_weight_for_kind(evaluations, FeedObservationKind::RotationEvidence);
    let stale_signature_count = evaluations
        .iter()
        .filter(|evaluation| evaluation.blocker_reason == BlockerReason::StaleSignature)
        .count() as u64;
    let release_hold_count = release_holds
        .iter()
        .filter(|hold| hold.status == HoldStatus::Active)
        .count() as u64;
    let accepted_observation_count = evaluations
        .iter()
        .filter(|evaluation| evaluation.decision == ObservationDecision::Accepted)
        .count() as u64;
    let blocked_observation_count = evaluations
        .iter()
        .filter(|evaluation| evaluation.decision == ObservationDecision::Blocked)
        .count() as u64;
    let held_observation_count = evaluations
        .iter()
        .filter(|evaluation| evaluation.decision == ObservationDecision::Held)
        .count() as u64;

    ProcessFeedSummary {
        escape_id: DEFAULT_ESCAPE_ID.to_string(),
        watcher_certificate_count: count_kind(
            observations,
            FeedObservationKind::WatcherCertificate,
        ),
        bridge_attestation_count: count_kind(observations, FeedObservationKind::BridgeAttestation),
        key_epoch_observation_count: count_kind(observations, FeedObservationKind::KeyEpoch),
        rotation_evidence_count: count_kind(observations, FeedObservationKind::RotationEvidence),
        accepted_observation_count,
        blocked_observation_count,
        held_observation_count,
        watcher_weight_bps,
        bridge_weight_bps,
        rotation_weight_bps,
        stale_signature_count,
        release_hold_count,
        release_authorized: watcher_weight_bps >= config.min_watcher_weight_bps
            && bridge_weight_bps >= config.min_bridge_weight_bps
            && rotation_weight_bps >= config.min_rotation_weight_bps
            && stale_signature_count == 0
            && release_hold_count == 0,
        canonical_release_authorization_root: release_authorization_root.to_string(),
    }
}

fn accepted_weight_for_kind(
    evaluations: &[ObservationEvaluation],
    kind: FeedObservationKind,
) -> u16 {
    evaluations
        .iter()
        .filter(|evaluation| {
            evaluation.kind == kind && evaluation.decision == ObservationDecision::Accepted
        })
        .map(|evaluation| evaluation.accepted_weight_bps)
        .sum()
}

fn count_kind(observations: &[AuthorityProcessObservation], kind: FeedObservationKind) -> u64 {
    observations
        .iter()
        .filter(|observation| observation.kind == kind)
        .count() as u64
}

fn devnet_release_holds(
    config: &Config,
    evaluations: &[ObservationEvaluation],
    blocker_root: &str,
    release_authorization_root: &str,
) -> Vec<ReleaseAuthorizationHold> {
    evaluations
        .iter()
        .filter(|evaluation| evaluation.blocker_reason != BlockerReason::None)
        .map(|evaluation| {
            let hold_id = domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-HOLD-ID",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&evaluation.observation_id),
                    HashPart::Str(evaluation.blocker_reason.as_str()),
                ],
                32,
            );

            ReleaseAuthorizationHold {
                hold_id,
                escape_id: DEFAULT_ESCAPE_ID.to_string(),
                status: HoldStatus::Active,
                reason: evaluation.blocker_reason,
                opened_at_l2_height: DEFAULT_L2_HEIGHT,
                review_not_before_l2_height: DEFAULT_L2_HEIGHT + config.hold_review_blocks,
                blocker_root: blocker_root.to_string(),
                release_authorization_root: release_authorization_root.to_string(),
            }
        })
        .collect()
}

fn release_authorization_root(
    config: &Config,
    observations: &[AuthorityProcessObservation],
    evaluations: &[ObservationEvaluation],
    blocker_root: &str,
) -> String {
    let observation_records = records_from_observations(observations);
    let evaluation_records = records_from_evaluations(evaluations);
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-RELEASE-AUTHORIZATION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.current_key_epoch),
            HashPart::Str(&merkle_root(
                "monero-l2-pq-bridge-exit-user-escape-pq-authority-process-feed-authorization-observations",
                &observation_records,
            )),
            HashPart::Str(&merkle_root(
                "monero-l2-pq-bridge-exit-user-escape-pq-authority-process-feed-authorization-evaluations",
                &evaluation_records,
            )),
            HashPart::Str(blocker_root),
        ],
        32,
    )
}

fn evaluation_evidence_root(
    observation: &AuthorityProcessObservation,
    blocker_reason: BlockerReason,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-EVALUATION-EVIDENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&observation.observation_id),
            HashPart::Str(observation.kind.as_str()),
            HashPart::Str(blocker_reason.as_str()),
            HashPart::Str(&observation.payload_root),
            HashPart::Str(&observation.transcript_root),
            HashPart::Str(&observation.rotation_evidence_root),
        ],
        32,
    )
}

fn devnet_observations(config: &Config) -> Vec<AuthorityProcessObservation> {
    Vec::from([
        make_observation(
            "pq-authority-alpha",
            "operator-north",
            FeedObservationKind::WatcherCertificate,
            PqScheme::HybridMlDsaSlhDsaShake,
            config.current_key_epoch,
            3_400,
            12,
            0,
        ),
        make_observation(
            "pq-authority-beta",
            "operator-south",
            FeedObservationKind::WatcherCertificate,
            PqScheme::MlDsa87,
            config.current_key_epoch,
            3_400,
            10,
            1,
        ),
        make_observation(
            "pq-authority-gamma",
            "operator-west",
            FeedObservationKind::BridgeAttestation,
            PqScheme::SlhDsaShake256f,
            config.current_key_epoch,
            3_700,
            8,
            2,
        ),
        make_observation(
            "pq-authority-theta",
            "operator-east",
            FeedObservationKind::BridgeAttestation,
            PqScheme::HybridMlDsaSlhDsaShake,
            config.current_key_epoch,
            3_700,
            7,
            3,
        ),
        make_observation(
            "pq-authority-epoch-council",
            "operator-ceremony",
            FeedObservationKind::KeyEpoch,
            PqScheme::HybridMlDsaSlhDsaShake,
            config.current_key_epoch,
            8_200,
            6,
            4,
        ),
        make_observation(
            "pq-authority-rotation-council",
            "operator-ceremony",
            FeedObservationKind::RotationEvidence,
            PqScheme::HybridMlDsaSlhDsaShake,
            config.current_key_epoch,
            8_200,
            6,
            5,
        ),
        make_observation(
            "pq-authority-stale-sigma",
            "operator-archive",
            FeedObservationKind::BridgeAttestation,
            PqScheme::MlDsa87,
            config.current_key_epoch,
            7_300,
            config.max_signature_age_blocks + 9,
            6,
        ),
        make_observation(
            "pq-authority-release-hold-delta",
            "operator-review",
            FeedObservationKind::BridgeAttestation,
            PqScheme::HybridMlDsaSlhDsaShake,
            config.current_key_epoch,
            7_300,
            4,
            7,
        ),
    ])
}

fn make_observation(
    authority_id: &str,
    operator_id: &str,
    kind: FeedObservationKind,
    scheme: PqScheme,
    key_epoch: u64,
    threshold_weight_bps: u16,
    age_blocks: u64,
    ordinal: u64,
) -> AuthorityProcessObservation {
    let signed_at_l2_height = DEFAULT_L2_HEIGHT.saturating_sub(age_blocks);
    let payload_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(DEFAULT_ESCAPE_ID),
            HashPart::Str(authority_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(key_epoch),
        ],
        32,
    );
    let transcript_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(&payload_root),
            HashPart::U64(signed_at_l2_height),
        ],
        32,
    );
    let signature_commitment = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-SIGNATURE",
        &[
            HashPart::Str(authority_id),
            HashPart::Str(operator_id),
            HashPart::Str(&transcript_root),
            HashPart::U64(ordinal),
        ],
        32,
    );
    let rotation_evidence_root = if kind == FeedObservationKind::RotationEvidence {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-ROTATION",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(authority_id),
                HashPart::Str(&signature_commitment),
            ],
            32,
        )
    } else {
        empty_root("rotation-evidence")
    };
    let observation_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(authority_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(&signature_commitment),
        ],
        32,
    );

    AuthorityProcessObservation {
        observation_id,
        escape_id: DEFAULT_ESCAPE_ID.to_string(),
        authority_id: authority_id.to_string(),
        operator_id: operator_id.to_string(),
        kind,
        scheme,
        key_epoch,
        threshold_weight_bps,
        signed_at_l2_height,
        observed_at_l2_height: DEFAULT_L2_HEIGHT,
        monero_height: DEFAULT_MONERO_HEIGHT + ordinal,
        payload_root,
        transcript_root,
        signature_commitment,
        rotation_evidence_root,
    }
}

fn records_from_observations(observations: &[AuthorityProcessObservation]) -> Vec<Value> {
    observations
        .iter()
        .map(AuthorityProcessObservation::public_record)
        .collect()
}

fn records_from_evaluations(evaluations: &[ObservationEvaluation]) -> Vec<Value> {
    evaluations
        .iter()
        .map(ObservationEvaluation::public_record)
        .collect()
}

fn records_from_holds(holds: &[ReleaseAuthorizationHold]) -> Vec<Value> {
    holds
        .iter()
        .map(ReleaseAuthorizationHold::public_record)
        .collect()
}

fn empty_root(kind: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-EMPTY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PQ-AUTHORITY-PROCESS-FEED-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
