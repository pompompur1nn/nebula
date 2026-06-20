use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalPqReleaseAuthorityQuorumReplayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PQ_RELEASE_AUTHORITY_QUORUM_REPLAY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-pq-release-authority-quorum-replay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PQ_RELEASE_AUTHORITY_QUORUM_REPLAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const QUORUM_REPLAY_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-pq-release-authority-quorum-replay-v1";
pub const ML_DSA_RELEASE_DOMAIN: &str =
    "ML-DSA-87:nebula:monero-l2:forced-exit-release-authority:v1";
pub const SLH_DSA_RELEASE_DOMAIN: &str =
    "SLH-DSA-SHAKE-256f:nebula:monero-l2:forced-exit-release-authority:v1";
pub const RELEASE_AUTHORIZATION_DOMAIN: &str =
    "SHAKE256:nebula:monero-l2:forced-exit-release-authorization-root:v1";
pub const DEFAULT_RELEASE_EPOCH: u64 = 144;
pub const DEFAULT_EXIT_HEIGHT: u64 = 1_934_720;
pub const DEFAULT_MAX_EPOCH_LAG: u64 = 1;
pub const DEFAULT_QUARANTINE_EPOCHS: u64 = 4;
pub const DEFAULT_MIN_RELEASE_WEIGHT_BPS: u16 = 7_200;
pub const DEFAULT_MAX_COLLUSION_CLUSTER_BPS: u16 = 3_300;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa87,
    SlhDsaShake256f,
    HybridMlDsaSlhDsaShake,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridMlDsaSlhDsaShake => "hybrid_ml_dsa_slh_dsa_shake",
        }
    }

    pub fn domain_label(self) -> &'static str {
        match self {
            Self::MlDsa87 => ML_DSA_RELEASE_DOMAIN,
            Self::SlhDsaShake256f => SLH_DSA_RELEASE_DOMAIN,
            Self::HybridMlDsaSlhDsaShake => RELEASE_AUTHORIZATION_DOMAIN,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    Active,
    Retiring,
    Quarantined,
    Revoked,
}

impl AuthorityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_authorize(self) -> bool {
        matches!(self, Self::Active | Self::Retiring)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDecision {
    Accepted,
    Rejected,
}

impl ReplayDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    None,
    UnknownAuthority,
    DuplicateAuthority,
    StaleEpoch,
    FutureEpoch,
    QuarantinedAuthority,
    RevokedAuthority,
    MissingMlDsaDomain,
    MissingSlhDsaDomain,
    AuthorizationRootMismatch,
    SlashingEvidenceLinked,
    CollusionClusterExceeded,
    PqSecurityTooLow,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::UnknownAuthority => "unknown_authority",
            Self::DuplicateAuthority => "duplicate_authority",
            Self::StaleEpoch => "stale_epoch",
            Self::FutureEpoch => "future_epoch",
            Self::QuarantinedAuthority => "quarantined_authority",
            Self::RevokedAuthority => "revoked_authority",
            Self::MissingMlDsaDomain => "missing_ml_dsa_domain",
            Self::MissingSlhDsaDomain => "missing_slh_dsa_domain",
            Self::AuthorizationRootMismatch => "authorization_root_mismatch",
            Self::SlashingEvidenceLinked => "slashing_evidence_linked",
            Self::CollusionClusterExceeded => "collusion_cluster_exceeded",
            Self::PqSecurityTooLow => "pq_security_too_low",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub quorum_replay_suite: String,
    pub ml_dsa_domain: String,
    pub slh_dsa_domain: String,
    pub release_authorization_domain: String,
    pub release_epoch: u64,
    pub max_epoch_lag: u64,
    pub quarantine_epochs: u64,
    pub min_release_weight_bps: u16,
    pub max_collusion_cluster_bps: u16,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            quorum_replay_suite: QUORUM_REPLAY_SUITE.to_string(),
            ml_dsa_domain: ML_DSA_RELEASE_DOMAIN.to_string(),
            slh_dsa_domain: SLH_DSA_RELEASE_DOMAIN.to_string(),
            release_authorization_domain: RELEASE_AUTHORIZATION_DOMAIN.to_string(),
            release_epoch: DEFAULT_RELEASE_EPOCH,
            max_epoch_lag: DEFAULT_MAX_EPOCH_LAG,
            quarantine_epochs: DEFAULT_QUARANTINE_EPOCHS,
            min_release_weight_bps: DEFAULT_MIN_RELEASE_WEIGHT_BPS,
            max_collusion_cluster_bps: DEFAULT_MAX_COLLUSION_CLUSTER_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "quorum_replay_suite": self.quorum_replay_suite,
            "ml_dsa_domain": self.ml_dsa_domain,
            "slh_dsa_domain": self.slh_dsa_domain,
            "release_authorization_domain": self.release_authorization_domain,
            "release_epoch": self.release_epoch,
            "max_epoch_lag": self.max_epoch_lag,
            "quarantine_epochs": self.quarantine_epochs,
            "min_release_weight_bps": self.min_release_weight_bps,
            "max_collusion_cluster_bps": self.max_collusion_cluster_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseAuthority {
    pub authority_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub scheme: PqSignatureScheme,
    pub status: AuthorityStatus,
    pub weight_bps: u16,
    pub pq_security_bits: u16,
    pub public_key_commitment: String,
    pub key_ceremony_root: String,
    pub quarantine_until_epoch: Option<u64>,
}

impl ReleaseAuthority {
    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "scheme": self.scheme.as_str(),
            "status": self.status.as_str(),
            "weight_bps": self.weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "public_key_commitment": self.public_key_commitment,
            "key_ceremony_root": self.key_ceremony_root,
            "quarantine_until_epoch": self.quarantine_until_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitRelease {
    pub exit_id: String,
    pub claimant_view_tag: String,
    pub monero_lock_root: String,
    pub l2_exit_nullifier_root: String,
    pub withdrawal_note_root: String,
    pub destination_commitment: String,
    pub amount_commitment: String,
    pub exit_height: u64,
    pub release_epoch: u64,
    pub release_authorization_root: String,
}

impl ForcedExitRelease {
    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "claimant_view_tag": self.claimant_view_tag,
            "monero_lock_root": self.monero_lock_root,
            "l2_exit_nullifier_root": self.l2_exit_nullifier_root,
            "withdrawal_note_root": self.withdrawal_note_root,
            "destination_commitment": self.destination_commitment,
            "amount_commitment": self.amount_commitment,
            "exit_height": self.exit_height,
            "release_epoch": self.release_epoch,
            "release_authorization_root": self.release_authorization_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("forced-exit-release", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseSignature {
    pub signature_id: String,
    pub authority_id: String,
    pub signer_epoch: u64,
    pub scheme: PqSignatureScheme,
    pub operator_id: String,
    pub weight_bps: u16,
    pub ml_dsa_domain_bound: bool,
    pub slh_dsa_domain_bound: bool,
    pub release_authorization_root: String,
    pub signature_commitment: String,
    pub transcript_root: String,
}

impl ReleaseSignature {
    pub fn public_record(&self) -> Value {
        json!({
            "signature_id": self.signature_id,
            "authority_id": self.authority_id,
            "signer_epoch": self.signer_epoch,
            "scheme": self.scheme.as_str(),
            "operator_id": self.operator_id,
            "weight_bps": self.weight_bps,
            "ml_dsa_domain_bound": self.ml_dsa_domain_bound,
            "slh_dsa_domain_bound": self.slh_dsa_domain_bound,
            "release_authorization_root": self.release_authorization_root,
            "signature_commitment": self.signature_commitment,
            "transcript_root": self.transcript_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub authority_id: String,
    pub operator_id: String,
    pub signer_epoch: u64,
    pub conflicting_release_root: String,
    pub evidence_root: String,
    pub quarantine_until_epoch: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "authority_id": self.authority_id,
            "operator_id": self.operator_id,
            "signer_epoch": self.signer_epoch,
            "conflicting_release_root": self.conflicting_release_root,
            "evidence_root": self.evidence_root,
            "quarantine_until_epoch": self.quarantine_until_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayTrace {
    pub signature_id: String,
    pub authority_id: String,
    pub operator_id: String,
    pub decision: ReplayDecision,
    pub reason: RejectionReason,
    pub accepted_weight_bps: u16,
    pub signer_epoch: u64,
    pub scheme: PqSignatureScheme,
    pub authorization_root: String,
}

impl ReplayTrace {
    pub fn public_record(&self) -> Value {
        json!({
            "signature_id": self.signature_id,
            "authority_id": self.authority_id,
            "operator_id": self.operator_id,
            "decision": self.decision.as_str(),
            "reason": self.reason.as_str(),
            "accepted_weight_bps": self.accepted_weight_bps,
            "signer_epoch": self.signer_epoch,
            "scheme": self.scheme.as_str(),
            "authorization_root": self.authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuorumReplaySummary {
    pub release_authorization_pq_sound: bool,
    pub answer: String,
    pub accepted_weight_bps: u16,
    pub rejected_weight_bps: u16,
    pub required_weight_bps: u16,
    pub accepted_authority_count: usize,
    pub rejected_signature_count: usize,
    pub accepted_root: String,
    pub rejected_root: String,
    pub slashing_evidence_root: String,
    pub authority_set_root: String,
    pub replay_trace_root: String,
    pub release_authorization_root: String,
}

impl QuorumReplaySummary {
    pub fn public_record(&self) -> Value {
        json!({
            "release_authorization_pq_sound": self.release_authorization_pq_sound,
            "answer": self.answer,
            "accepted_weight_bps": self.accepted_weight_bps,
            "rejected_weight_bps": self.rejected_weight_bps,
            "required_weight_bps": self.required_weight_bps,
            "accepted_authority_count": self.accepted_authority_count,
            "rejected_signature_count": self.rejected_signature_count,
            "accepted_root": self.accepted_root,
            "rejected_root": self.rejected_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "authority_set_root": self.authority_set_root,
            "replay_trace_root": self.replay_trace_root,
            "release_authorization_root": self.release_authorization_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub forced_exit: ForcedExitRelease,
    pub authorities: Vec<ReleaseAuthority>,
    pub signatures: Vec<ReleaseSignature>,
    pub slashing_evidence: Vec<SlashingEvidence>,
    pub replay_trace: Vec<ReplayTrace>,
    pub summary: QuorumReplaySummary,
    pub config_root: String,
    pub forced_exit_root: String,
    pub authority_set_root: String,
    pub signature_set_root: String,
    pub slashing_evidence_root: String,
    pub replay_trace_root: String,
    pub summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl State {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": self.config.hash_suite,
            "quorum_replay_suite": self.config.quorum_replay_suite,
            "forced_exit": self.forced_exit.public_record(),
            "summary": self.summary.public_record(),
            "config_root": self.config_root,
            "forced_exit_root": self.forced_exit_root,
            "authority_set_root": self.authority_set_root,
            "signature_set_root": self.signature_set_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "replay_trace_root": self.replay_trace_root,
            "summary_root": self.summary_root,
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    build_state(config)
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn build_state(config: Config) -> State {
    let forced_exit = devnet_forced_exit(&config);
    let authorities = devnet_authorities(&config);
    let slashing_evidence = devnet_slashing_evidence(&config, &forced_exit, &authorities);
    let signatures = devnet_signatures(&config, &forced_exit, &authorities);
    let replay_trace = replay_quorum(
        &config,
        &forced_exit,
        &authorities,
        &signatures,
        &slashing_evidence,
    );

    let config_root = config.state_root();
    let forced_exit_root = forced_exit.state_root();
    let authority_set_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-AUTHORITY-SET",
        &records_from_authorities(&authorities),
    );
    let signature_set_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-SIGNATURE-SET",
        &records_from_signatures(&signatures),
    );
    let slashing_evidence_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-SLASHING-EVIDENCE",
        &records_from_slashing(&slashing_evidence),
    );
    let replay_trace_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-REPLAY-TRACE",
        &records_from_trace(&replay_trace),
    );
    let summary = summarize_replay(
        &config,
        &forced_exit,
        &authorities,
        &slashing_evidence_root,
        &authority_set_root,
        &replay_trace_root,
        &replay_trace,
    );
    let summary_root = summary.state_root();
    let public_record_root = record_root("public-record", &summary.public_record());
    let state_root = quorum_state_root(
        &config_root,
        &forced_exit_root,
        &authority_set_root,
        &signature_set_root,
        &slashing_evidence_root,
        &replay_trace_root,
        &summary_root,
        &public_record_root,
    );

    State {
        config,
        forced_exit,
        authorities,
        signatures,
        slashing_evidence,
        replay_trace,
        summary,
        config_root,
        forced_exit_root,
        authority_set_root,
        signature_set_root,
        slashing_evidence_root,
        replay_trace_root,
        summary_root,
        public_record_root,
        state_root,
    }
}

fn replay_quorum(
    config: &Config,
    forced_exit: &ForcedExitRelease,
    authorities: &[ReleaseAuthority],
    signatures: &[ReleaseSignature],
    slashing_evidence: &[SlashingEvidence],
) -> Vec<ReplayTrace> {
    let authority_index = authorities
        .iter()
        .map(|authority| (authority.authority_id.clone(), authority))
        .collect::<BTreeMap<_, _>>();
    let slashed = slashing_evidence
        .iter()
        .map(|evidence| evidence.authority_id.clone())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut operator_weights = BTreeMap::<String, u16>::new();

    signatures
        .iter()
        .map(|signature| {
            let reason = signature_rejection_reason(
                config,
                forced_exit,
                signature,
                &authority_index,
                &slashed,
                &seen,
                &operator_weights,
            );
            let decision = if reason == RejectionReason::None {
                ReplayDecision::Accepted
            } else {
                ReplayDecision::Rejected
            };
            let accepted_weight_bps = if decision == ReplayDecision::Accepted {
                seen.insert(signature.authority_id.clone());
                let next_weight = operator_weights
                    .get(&signature.operator_id)
                    .copied()
                    .unwrap_or_default()
                    .saturating_add(signature.weight_bps);
                operator_weights.insert(signature.operator_id.clone(), next_weight);
                signature.weight_bps
            } else {
                0
            };
            ReplayTrace {
                signature_id: signature.signature_id.clone(),
                authority_id: signature.authority_id.clone(),
                operator_id: signature.operator_id.clone(),
                decision,
                reason,
                accepted_weight_bps,
                signer_epoch: signature.signer_epoch,
                scheme: signature.scheme,
                authorization_root: signature.release_authorization_root.clone(),
            }
        })
        .collect()
}

fn signature_rejection_reason(
    config: &Config,
    forced_exit: &ForcedExitRelease,
    signature: &ReleaseSignature,
    authority_index: &BTreeMap<String, &ReleaseAuthority>,
    slashed: &BTreeSet<String>,
    seen: &BTreeSet<String>,
    operator_weights: &BTreeMap<String, u16>,
) -> RejectionReason {
    let Some(authority) = authority_index.get(&signature.authority_id) else {
        return RejectionReason::UnknownAuthority;
    };
    if seen.contains(&signature.authority_id) {
        return RejectionReason::DuplicateAuthority;
    }
    if signature.signer_epoch + config.max_epoch_lag < config.release_epoch {
        return RejectionReason::StaleEpoch;
    }
    if signature.signer_epoch > config.release_epoch {
        return RejectionReason::FutureEpoch;
    }
    if !authority.status.can_authorize() {
        return match authority.status {
            AuthorityStatus::Quarantined => RejectionReason::QuarantinedAuthority,
            AuthorityStatus::Revoked => RejectionReason::RevokedAuthority,
            AuthorityStatus::Active | AuthorityStatus::Retiring => RejectionReason::None,
        };
    }
    if authority.pq_security_bits < config.min_pq_security_bits {
        return RejectionReason::PqSecurityTooLow;
    }
    if slashed.contains(&signature.authority_id) {
        return RejectionReason::SlashingEvidenceLinked;
    }
    if signature.scheme != authority.scheme {
        return RejectionReason::AuthorizationRootMismatch;
    }
    if signature.scheme != PqSignatureScheme::SlhDsaShake256f && !signature.ml_dsa_domain_bound {
        return RejectionReason::MissingMlDsaDomain;
    }
    if signature.scheme != PqSignatureScheme::MlDsa87 && !signature.slh_dsa_domain_bound {
        return RejectionReason::MissingSlhDsaDomain;
    }
    if signature.release_authorization_root != forced_exit.release_authorization_root {
        return RejectionReason::AuthorizationRootMismatch;
    }
    let cluster_weight = operator_weights
        .get(&signature.operator_id)
        .copied()
        .unwrap_or_default()
        .saturating_add(signature.weight_bps);
    if cluster_weight > config.max_collusion_cluster_bps {
        return RejectionReason::CollusionClusterExceeded;
    }
    RejectionReason::None
}

fn summarize_replay(
    config: &Config,
    forced_exit: &ForcedExitRelease,
    authorities: &[ReleaseAuthority],
    slashing_evidence_root: &str,
    authority_set_root: &str,
    replay_trace_root: &str,
    replay_trace: &[ReplayTrace],
) -> QuorumReplaySummary {
    let accepted = replay_trace
        .iter()
        .filter(|trace| trace.decision == ReplayDecision::Accepted)
        .collect::<Vec<_>>();
    let rejected = replay_trace
        .iter()
        .filter(|trace| trace.decision == ReplayDecision::Rejected)
        .collect::<Vec<_>>();
    let accepted_weight_bps = accepted.iter().fold(0_u16, |total, trace| {
        total.saturating_add(trace.accepted_weight_bps)
    });
    let signed_weight_bps = replay_trace.iter().fold(0_u16, |total, trace| {
        let weight = authorities
            .iter()
            .find(|authority| authority.authority_id == trace.authority_id)
            .map(|authority| authority.weight_bps)
            .unwrap_or_default();
        total.saturating_add(weight)
    });
    let rejected_weight_bps = signed_weight_bps.saturating_sub(accepted_weight_bps);
    let accepted_records = accepted
        .iter()
        .map(|trace| trace.public_record())
        .collect::<Vec<_>>();
    let rejected_records = rejected
        .iter()
        .map(|trace| trace.public_record())
        .collect::<Vec<_>>();
    let release_authorization_pq_sound = accepted_weight_bps >= config.min_release_weight_bps;

    QuorumReplaySummary {
        release_authorization_pq_sound,
        answer: if release_authorization_pq_sound {
            "yes: accepted release-authority PQ weight satisfies forced-exit quorum after stale, quarantined, slashed, and colluding signers are rejected"
        } else {
            "no: accepted release-authority PQ weight does not satisfy forced-exit quorum"
        }
        .to_string(),
        accepted_weight_bps,
        rejected_weight_bps,
        required_weight_bps: config.min_release_weight_bps,
        accepted_authority_count: accepted.len(),
        rejected_signature_count: rejected.len(),
        accepted_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-ACCEPTED-AUTHORITY",
            &accepted_records,
        ),
        rejected_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-REJECTED-AUTHORITY",
            &rejected_records,
        ),
        slashing_evidence_root: slashing_evidence_root.to_string(),
        authority_set_root: authority_set_root.to_string(),
        replay_trace_root: replay_trace_root.to_string(),
        release_authorization_root: forced_exit.release_authorization_root.clone(),
    }
}

fn devnet_forced_exit(config: &Config) -> ForcedExitRelease {
    let exit_id = label_root("exit", "forced-release-devnet", config.release_epoch);
    let claimant_view_tag = label_root("claimant-view-tag", "canonical", config.release_epoch);
    let monero_lock_root = label_root("monero-lock-root", "ringct-lock", DEFAULT_EXIT_HEIGHT);
    let l2_exit_nullifier_root =
        label_root("l2-exit-nullifier", "forced-exit", DEFAULT_EXIT_HEIGHT);
    let withdrawal_note_root =
        label_root("withdrawal-note-root", "release-note", DEFAULT_EXIT_HEIGHT);
    let destination_commitment = label_root("destination", "stealth-address", DEFAULT_EXIT_HEIGHT);
    let amount_commitment = label_root("amount", "confidential-amount", DEFAULT_EXIT_HEIGHT);
    let release_authorization_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-AUTHORIZATION",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(&exit_id),
            HashPart::Str(&monero_lock_root),
            HashPart::Str(&l2_exit_nullifier_root),
            HashPart::Str(&withdrawal_note_root),
            HashPart::Str(&destination_commitment),
            HashPart::Str(&amount_commitment),
            HashPart::U64(DEFAULT_EXIT_HEIGHT),
            HashPart::U64(config.release_epoch),
        ],
        32,
    );
    ForcedExitRelease {
        exit_id,
        claimant_view_tag,
        monero_lock_root,
        l2_exit_nullifier_root,
        withdrawal_note_root,
        destination_commitment,
        amount_commitment,
        exit_height: DEFAULT_EXIT_HEIGHT,
        release_epoch: config.release_epoch,
        release_authorization_root,
    }
}

fn devnet_authorities(config: &Config) -> Vec<ReleaseAuthority> {
    let rows = [
        (
            "release-authority-alpha",
            "operator-north",
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            AuthorityStatus::Active,
            2_000,
            256,
        ),
        (
            "release-authority-beta",
            "operator-east",
            PqSignatureScheme::MlDsa87,
            AuthorityStatus::Active,
            1_800,
            256,
        ),
        (
            "release-authority-gamma",
            "operator-west",
            PqSignatureScheme::SlhDsaShake256f,
            AuthorityStatus::Active,
            1_700,
            256,
        ),
        (
            "release-authority-delta",
            "operator-south",
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            AuthorityStatus::Retiring,
            1_800,
            256,
        ),
        (
            "release-authority-epsilon",
            "operator-archive",
            PqSignatureScheme::MlDsa87,
            AuthorityStatus::Active,
            1_200,
            256,
        ),
        (
            "release-authority-zeta",
            "operator-east",
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            AuthorityStatus::Active,
            1_100,
            256,
        ),
        (
            "release-authority-eta",
            "operator-quarantine",
            PqSignatureScheme::SlhDsaShake256f,
            AuthorityStatus::Quarantined,
            900,
            256,
        ),
        (
            "release-authority-theta",
            "operator-revoked",
            PqSignatureScheme::MlDsa87,
            AuthorityStatus::Revoked,
            700,
            192,
        ),
        (
            "release-authority-iota",
            "operator-north",
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            AuthorityStatus::Active,
            1_600,
            256,
        ),
    ];

    rows.iter()
        .enumerate()
        .map(
            |(index, (authority_id, operator_id, scheme, status, weight_bps, pq_security_bits))| {
                ReleaseAuthority {
                    authority_id: (*authority_id).to_string(),
                    operator_id: (*operator_id).to_string(),
                    epoch: config.release_epoch,
                    scheme: *scheme,
                    status: *status,
                    weight_bps: *weight_bps,
                    pq_security_bits: *pq_security_bits,
                    public_key_commitment: label_root("public-key", authority_id, index as u64),
                    key_ceremony_root: label_root(
                        "key-ceremony",
                        operator_id,
                        config.release_epoch + index as u64,
                    ),
                    quarantine_until_epoch: if *status == AuthorityStatus::Quarantined {
                        Some(config.release_epoch + config.quarantine_epochs)
                    } else {
                        None
                    },
                }
            },
        )
        .collect()
}

fn devnet_signatures(
    config: &Config,
    forced_exit: &ForcedExitRelease,
    authorities: &[ReleaseAuthority],
) -> Vec<ReleaseSignature> {
    let mut signatures = authorities
        .iter()
        .enumerate()
        .map(|(index, authority)| {
            let signer_epoch = if authority.authority_id == "release-authority-epsilon" {
                config.release_epoch.saturating_sub(3)
            } else {
                config.release_epoch
            };
            let release_authorization_root = if authority.authority_id == "release-authority-zeta" {
                label_root(
                    "conflicting-release-root",
                    &authority.authority_id,
                    index as u64,
                )
            } else {
                forced_exit.release_authorization_root.clone()
            };
            signature_from_authority(
                authority,
                forced_exit,
                signer_epoch,
                &release_authorization_root,
                index as u64,
            )
        })
        .collect::<Vec<_>>();

    if let Some(alpha) = authorities.first() {
        signatures.push(signature_from_authority(
            alpha,
            forced_exit,
            config.release_epoch,
            &forced_exit.release_authorization_root,
            99,
        ));
    }
    signatures
}

fn signature_from_authority(
    authority: &ReleaseAuthority,
    forced_exit: &ForcedExitRelease,
    signer_epoch: u64,
    release_authorization_root: &str,
    ordinal: u64,
) -> ReleaseSignature {
    let ml_dsa_domain_bound = matches!(
        authority.scheme,
        PqSignatureScheme::MlDsa87 | PqSignatureScheme::HybridMlDsaSlhDsaShake
    );
    let slh_dsa_domain_bound = matches!(
        authority.scheme,
        PqSignatureScheme::SlhDsaShake256f | PqSignatureScheme::HybridMlDsaSlhDsaShake
    );
    let transcript_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-SIGNATURE-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(authority.scheme.domain_label()),
            HashPart::Str(&authority.authority_id),
            HashPart::Str(&forced_exit.exit_id),
            HashPart::Str(release_authorization_root),
            HashPart::U64(signer_epoch),
        ],
        32,
    );
    let signature_commitment = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-SIGNATURE-COMMITMENT",
        &[
            HashPart::Str(&authority.public_key_commitment),
            HashPart::Str(&transcript_root),
            HashPart::U64(ordinal),
        ],
        32,
    );
    let signature_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-SIGNATURE-ID",
        &[
            HashPart::Str(&authority.authority_id),
            HashPart::Str(&signature_commitment),
            HashPart::U64(ordinal),
        ],
        32,
    );

    ReleaseSignature {
        signature_id,
        authority_id: authority.authority_id.clone(),
        signer_epoch,
        scheme: authority.scheme,
        operator_id: authority.operator_id.clone(),
        weight_bps: authority.weight_bps,
        ml_dsa_domain_bound,
        slh_dsa_domain_bound,
        release_authorization_root: release_authorization_root.to_string(),
        signature_commitment,
        transcript_root,
    }
}

fn devnet_slashing_evidence(
    config: &Config,
    forced_exit: &ForcedExitRelease,
    authorities: &[ReleaseAuthority],
) -> Vec<SlashingEvidence> {
    authorities
        .iter()
        .filter(|authority| authority.authority_id == "release-authority-zeta")
        .map(|authority| {
            let conflicting_release_root =
                label_root("conflicting-release-root", &authority.authority_id, 5);
            let evidence_root = domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-SLASHING-LINK",
                &[
                    HashPart::Str(&config.chain_id),
                    HashPart::Str(&authority.authority_id),
                    HashPart::Str(&forced_exit.release_authorization_root),
                    HashPart::Str(&conflicting_release_root),
                    HashPart::U64(config.release_epoch),
                ],
                32,
            );
            let evidence_id = domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-SLASHING-ID",
                &[
                    HashPart::Str(&evidence_root),
                    HashPart::Str(&authority.operator_id),
                ],
                32,
            );
            SlashingEvidence {
                evidence_id,
                authority_id: authority.authority_id.clone(),
                operator_id: authority.operator_id.clone(),
                signer_epoch: config.release_epoch,
                conflicting_release_root,
                evidence_root,
                quarantine_until_epoch: config.release_epoch + config.quarantine_epochs,
            }
        })
        .collect()
}

fn records_from_authorities(authorities: &[ReleaseAuthority]) -> Vec<Value> {
    authorities
        .iter()
        .map(ReleaseAuthority::public_record)
        .collect()
}

fn records_from_signatures(signatures: &[ReleaseSignature]) -> Vec<Value> {
    signatures
        .iter()
        .map(ReleaseSignature::public_record)
        .collect()
}

fn records_from_slashing(evidence: &[SlashingEvidence]) -> Vec<Value> {
    evidence
        .iter()
        .map(SlashingEvidence::public_record)
        .collect()
}

fn records_from_trace(trace: &[ReplayTrace]) -> Vec<Value> {
    trace.iter().map(ReplayTrace::public_record).collect()
}

fn quorum_state_root(
    config_root: &str,
    forced_exit_root: &str,
    authority_set_root: &str,
    signature_set_root: &str,
    slashing_evidence_root: &str,
    replay_trace_root: &str,
    summary_root: &str,
    public_record_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-QUORUM-REPLAY-STATE",
        &[
            HashPart::Str(config_root),
            HashPart::Str(forced_exit_root),
            HashPart::Str(authority_set_root),
            HashPart::Str(signature_set_root),
            HashPart::Str(slashing_evidence_root),
            HashPart::Str(replay_trace_root),
            HashPart::Str(summary_root),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-QUORUM-REPLAY-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn label_root(domain: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PQ-RELEASE-QUORUM-REPLAY-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}
