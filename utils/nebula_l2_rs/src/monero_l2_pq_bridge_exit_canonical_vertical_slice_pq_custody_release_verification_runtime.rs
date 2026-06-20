use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePqCustodyReleaseVerificationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_CUSTODY_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-pq-custody-release-verification-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_CUSTODY_RELEASE_VERIFICATION_RUNTIME_PROTOCOL_VERSION;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const STRONG_PQ_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-release-verification-v1";
pub const WEAK_PQ_SUITE: &str = "ed25519-legacy-non-pq";
pub const CHALLENGE_DOMAIN: &str = "forced-exit-custody-release-challenge-v1";
pub const AUTHORITY_GUARD: &str = "pq-custody-release-authority-guard-root-v1";
pub const DEVNET_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEVNET_RELEASE_ID: &str = "forced-exit-release-verification-devnet-0001";
pub const DEVNET_EXPECTED_AUTHORITY: &str = "pq-custody-release-council-devnet-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationState {
    Active,
    Grace,
    Scheduled,
    Retired,
    Revoked,
}

impl RotationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Scheduled => "scheduled",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    Release,
    Hold,
}

impl VerificationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Hold => "hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    StaleEpoch,
    BadTranscriptBinding,
    WeakPqSuite,
    QuorumShortfall,
    DuplicateNonce,
    AuthorityMismatch,
    RotationClosed,
    BadAuthorizationRoot,
    BadSignatureReceiptRoot,
    BadKeyEpochRoot,
}

impl HoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleEpoch => "stale_epoch",
            Self::BadTranscriptBinding => "bad_transcript_binding",
            Self::WeakPqSuite => "weak_pq_suite",
            Self::QuorumShortfall => "quorum_shortfall",
            Self::DuplicateNonce => "duplicate_nonce",
            Self::AuthorityMismatch => "authority_mismatch",
            Self::RotationClosed => "rotation_closed",
            Self::BadAuthorizationRoot => "bad_authorization_root",
            Self::BadSignatureReceiptRoot => "bad_signature_receipt_root",
            Self::BadKeyEpochRoot => "bad_key_epoch_root",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub min_pq_security_bits: u16,
    pub min_signer_quorum_weight: u64,
    pub max_epoch_lag: u64,
    pub expected_algorithm_suite: String,
    pub expected_challenge_domain: String,
    pub expected_authority_guard: String,
    pub expected_upgrade_authority: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            min_pq_security_bits: 256,
            min_signer_quorum_weight: 67,
            max_epoch_lag: 1,
            expected_algorithm_suite: STRONG_PQ_SUITE.to_string(),
            expected_challenge_domain: CHALLENGE_DOMAIN.to_string(),
            expected_authority_guard: AUTHORITY_GUARD.to_string(),
            expected_upgrade_authority: DEVNET_EXPECTED_AUTHORITY.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_signer_quorum_weight": self.min_signer_quorum_weight,
            "max_epoch_lag": self.max_epoch_lag,
            "expected_algorithm_suite": self.expected_algorithm_suite,
            "expected_challenge_domain": self.expected_challenge_domain,
            "expected_authority_guard": self.expected_authority_guard,
            "expected_upgrade_authority": self.expected_upgrade_authority,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationEvidence {
    pub release_id: String,
    pub vertical_slice_id: String,
    pub authorization_root: String,
    pub expected_authorization_root: String,
    pub signature_receipt_root: String,
    pub expected_signature_receipt_root: String,
    pub key_epoch_root: String,
    pub expected_key_epoch_root: String,
    pub signer_quorum_weight: u64,
    pub algorithm_suite: String,
    pub pq_security_bits: u16,
    pub transcript_binding: String,
    pub expected_transcript_binding: String,
    pub challenge_domain: String,
    pub replay_nonce: String,
    pub upgrade_authority_guard: String,
    pub upgrade_authority: String,
    pub current_epoch: u64,
    pub evidence_epoch: u64,
    pub rotation_state: RotationState,
}

impl VerificationEvidence {
    pub fn devnet(config: &Config) -> Self {
        let key_epoch_root = key_epoch_root(
            DEVNET_RELEASE_ID,
            73,
            RotationState::Active,
            &config.expected_upgrade_authority,
        );
        let transcript_binding = transcript_binding_root(
            DEVNET_RELEASE_ID,
            DEVNET_VERTICAL_SLICE_ID,
            &key_epoch_root,
            config.expected_challenge_domain.as_str(),
        );
        let authorization_root = authorization_root(
            DEVNET_RELEASE_ID,
            DEVNET_VERTICAL_SLICE_ID,
            &transcript_binding,
            config.expected_upgrade_authority.as_str(),
            73,
        );
        let signature_receipt_root = signature_receipt_root(
            DEVNET_RELEASE_ID,
            &authorization_root,
            &transcript_binding,
            config.expected_algorithm_suite.as_str(),
            74,
            config.min_signer_quorum_weight,
        );

        Self {
            release_id: DEVNET_RELEASE_ID.to_string(),
            vertical_slice_id: DEVNET_VERTICAL_SLICE_ID.to_string(),
            authorization_root: authorization_root.clone(),
            expected_authorization_root: authorization_root,
            signature_receipt_root: signature_receipt_root.clone(),
            expected_signature_receipt_root: signature_receipt_root,
            key_epoch_root: key_epoch_root.clone(),
            expected_key_epoch_root: key_epoch_root,
            signer_quorum_weight: config.min_signer_quorum_weight,
            algorithm_suite: config.expected_algorithm_suite.clone(),
            pq_security_bits: config.min_pq_security_bits,
            transcript_binding: transcript_binding.clone(),
            expected_transcript_binding: transcript_binding,
            challenge_domain: config.expected_challenge_domain.clone(),
            replay_nonce: nonce_root(DEVNET_RELEASE_ID, "nonce-0001"),
            upgrade_authority_guard: config.expected_authority_guard.clone(),
            upgrade_authority: config.expected_upgrade_authority.clone(),
            current_epoch: 74,
            evidence_epoch: 73,
            rotation_state: RotationState::Active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "release_id": self.release_id,
            "vertical_slice_id": self.vertical_slice_id,
            "authorization_root": self.authorization_root,
            "expected_authorization_root": self.expected_authorization_root,
            "signature_receipt_root": self.signature_receipt_root,
            "expected_signature_receipt_root": self.expected_signature_receipt_root,
            "key_epoch_root": self.key_epoch_root,
            "expected_key_epoch_root": self.expected_key_epoch_root,
            "signer_quorum_weight": self.signer_quorum_weight,
            "algorithm_suite": self.algorithm_suite,
            "pq_security_bits": self.pq_security_bits,
            "transcript_binding": self.transcript_binding,
            "expected_transcript_binding": self.expected_transcript_binding,
            "challenge_domain": self.challenge_domain,
            "replay_nonce": self.replay_nonce,
            "upgrade_authority_guard": self.upgrade_authority_guard,
            "upgrade_authority": self.upgrade_authority,
            "current_epoch": self.current_epoch,
            "evidence_epoch": self.evidence_epoch,
            "rotation_state": self.rotation_state.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("verification-evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationReport {
    pub verdict: VerificationVerdict,
    pub hold_reasons: Vec<HoldReason>,
    pub authorization_root: String,
    pub signature_receipt_root: String,
    pub key_epoch_root: String,
    pub transcript_binding: String,
    pub challenge_domain: String,
    pub replay_nonce_root: String,
    pub quorum_weight: u64,
    pub report_root: String,
}

impl VerificationReport {
    pub fn public_record(&self) -> Value {
        let hold_reasons = self
            .hold_reasons
            .iter()
            .map(|reason| reason.as_str())
            .collect::<Vec<_>>();

        json!({
            "verdict": self.verdict.as_str(),
            "hold_reasons": hold_reasons,
            "authorization_root": self.authorization_root,
            "signature_receipt_root": self.signature_receipt_root,
            "key_epoch_root": self.key_epoch_root,
            "transcript_binding": self.transcript_binding,
            "challenge_domain": self.challenge_domain,
            "replay_nonce_root": self.replay_nonce_root,
            "quorum_weight": self.quorum_weight,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub evidence: VerificationEvidence,
    pub consumed_nonces: Vec<String>,
    pub report: VerificationReport,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let evidence = VerificationEvidence::devnet(&config);
        let consumed_nonces = vec![nonce_root("settled-forced-exit-release", "nonce-archived")];
        let report = verify_release(&config, &evidence, &consumed_nonces);

        Self {
            config,
            evidence,
            consumed_nonces,
            report,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "evidence": self.evidence.public_record(),
            "consumed_nonces": self.consumed_nonces,
            "consumed_nonce_root": nonce_set_root(&self.consumed_nonces),
            "report": self.report.public_record(),
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

pub fn verify_release(
    config: &Config,
    evidence: &VerificationEvidence,
    consumed_nonces: &[String],
) -> VerificationReport {
    let mut hold_reasons = Vec::new();

    if evidence
        .current_epoch
        .saturating_sub(evidence.evidence_epoch)
        > config.max_epoch_lag
    {
        hold_reasons.push(HoldReason::StaleEpoch);
    }

    if evidence.transcript_binding != evidence.expected_transcript_binding {
        hold_reasons.push(HoldReason::BadTranscriptBinding);
    }

    if evidence.algorithm_suite != config.expected_algorithm_suite
        || evidence.algorithm_suite == WEAK_PQ_SUITE
        || evidence.pq_security_bits < config.min_pq_security_bits
    {
        hold_reasons.push(HoldReason::WeakPqSuite);
    }

    if evidence.signer_quorum_weight < config.min_signer_quorum_weight {
        hold_reasons.push(HoldReason::QuorumShortfall);
    }

    if has_duplicate_nonce(&evidence.replay_nonce, consumed_nonces) {
        hold_reasons.push(HoldReason::DuplicateNonce);
    }

    if evidence.upgrade_authority_guard != config.expected_authority_guard
        || evidence.upgrade_authority != config.expected_upgrade_authority
    {
        hold_reasons.push(HoldReason::AuthorityMismatch);
    }

    if !evidence.rotation_state.permits_release() {
        hold_reasons.push(HoldReason::RotationClosed);
    }

    if evidence.authorization_root != evidence.expected_authorization_root {
        hold_reasons.push(HoldReason::BadAuthorizationRoot);
    }

    if evidence.signature_receipt_root != evidence.expected_signature_receipt_root {
        hold_reasons.push(HoldReason::BadSignatureReceiptRoot);
    }

    if evidence.key_epoch_root != evidence.expected_key_epoch_root {
        hold_reasons.push(HoldReason::BadKeyEpochRoot);
    }

    if evidence.challenge_domain != config.expected_challenge_domain {
        hold_reasons.push(HoldReason::BadTranscriptBinding);
    }

    let verdict = if hold_reasons.is_empty() {
        VerificationVerdict::Release
    } else {
        VerificationVerdict::Hold
    };
    let report_root = verification_report_root(config, evidence, verdict, &hold_reasons);

    VerificationReport {
        verdict,
        hold_reasons,
        authorization_root: evidence.authorization_root.clone(),
        signature_receipt_root: evidence.signature_receipt_root.clone(),
        key_epoch_root: evidence.key_epoch_root.clone(),
        transcript_binding: evidence.transcript_binding.clone(),
        challenge_domain: evidence.challenge_domain.clone(),
        replay_nonce_root: evidence.replay_nonce.clone(),
        quorum_weight: evidence.signer_quorum_weight,
        report_root,
    }
}

pub fn authorization_root(
    release_id: &str,
    vertical_slice_id: &str,
    transcript_binding: &str,
    authority: &str,
    evidence_epoch: u64,
) -> String {
    domain_hash(
        "PQ-CUSTODY-RELEASE-VERIFICATION-AUTHORIZATION",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(release_id),
            HashPart::Str(vertical_slice_id),
            HashPart::Str(transcript_binding),
            HashPart::Str(authority),
            HashPart::U64(evidence_epoch),
        ],
        32,
    )
}

pub fn signature_receipt_root(
    release_id: &str,
    authorization_root: &str,
    transcript_binding: &str,
    algorithm_suite: &str,
    current_epoch: u64,
    signer_quorum_weight: u64,
) -> String {
    domain_hash(
        "PQ-CUSTODY-RELEASE-VERIFICATION-SIGNATURE-RECEIPT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(release_id),
            HashPart::Str(authorization_root),
            HashPart::Str(transcript_binding),
            HashPart::Str(algorithm_suite),
            HashPart::U64(current_epoch),
            HashPart::U64(signer_quorum_weight),
        ],
        32,
    )
}

pub fn key_epoch_root(
    release_id: &str,
    evidence_epoch: u64,
    rotation_state: RotationState,
    authority: &str,
) -> String {
    domain_hash(
        "PQ-CUSTODY-RELEASE-VERIFICATION-KEY-EPOCH",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(release_id),
            HashPart::U64(evidence_epoch),
            HashPart::Str(rotation_state.as_str()),
            HashPart::Str(authority),
        ],
        32,
    )
}

pub fn transcript_binding_root(
    release_id: &str,
    vertical_slice_id: &str,
    key_epoch_root: &str,
    challenge_domain: &str,
) -> String {
    domain_hash(
        "PQ-CUSTODY-RELEASE-VERIFICATION-TRANSCRIPT-BINDING",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(release_id),
            HashPart::Str(vertical_slice_id),
            HashPart::Str(key_epoch_root),
            HashPart::Str(challenge_domain),
        ],
        32,
    )
}

pub fn nonce_root(release_id: &str, nonce: &str) -> String {
    domain_hash(
        "PQ-CUSTODY-RELEASE-VERIFICATION-REPLAY-NONCE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(release_id),
            HashPart::Str(nonce),
        ],
        32,
    )
}

fn has_duplicate_nonce(replay_nonce: &str, consumed_nonces: &[String]) -> bool {
    let mut seen = BTreeSet::new();

    for nonce in consumed_nonces {
        if nonce == replay_nonce {
            return true;
        }

        if !seen.insert(nonce.as_str()) {
            return true;
        }
    }

    false
}

fn nonce_set_root(consumed_nonces: &[String]) -> String {
    let leaves = consumed_nonces
        .iter()
        .map(|nonce| json!({ "replay_nonce": nonce }))
        .collect::<Vec<_>>();

    merkle_root(
        "PQ-CUSTODY-RELEASE-VERIFICATION-CONSUMED-NONCE-SET",
        &leaves,
    )
}

fn verification_report_root(
    config: &Config,
    evidence: &VerificationEvidence,
    verdict: VerificationVerdict,
    hold_reasons: &[HoldReason],
) -> String {
    let reasons = hold_reasons
        .iter()
        .map(|reason| reason.as_str())
        .collect::<Vec<_>>()
        .join("|");

    domain_hash(
        "PQ-CUSTODY-RELEASE-VERIFICATION-REPORT",
        &[
            HashPart::Str(config.chain_id.as_str()),
            HashPart::Str(config.protocol_version.as_str()),
            HashPart::Str(evidence.release_id.as_str()),
            HashPart::Str(evidence.authorization_root.as_str()),
            HashPart::Str(evidence.signature_receipt_root.as_str()),
            HashPart::Str(evidence.key_epoch_root.as_str()),
            HashPart::Str(evidence.transcript_binding.as_str()),
            HashPart::Str(evidence.challenge_domain.as_str()),
            HashPart::Str(evidence.replay_nonce.as_str()),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(reasons.as_str()),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "PQ-CUSTODY-RELEASE-VERIFICATION-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
