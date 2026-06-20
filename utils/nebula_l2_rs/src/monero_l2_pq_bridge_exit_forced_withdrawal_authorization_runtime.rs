use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitForcedWithdrawalAuthorizationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FORCED_WITHDRAWAL_AUTHORIZATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-forced-withdrawal-authorization-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FORCED_WITHDRAWAL_AUTHORIZATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const AUTHORIZATION_SUITE: &str =
    "monero-l2-pq-bridge-forced-withdrawal-authorization-and-denial-spine-v1";
pub const DEFAULT_MIN_USER_SIGNATURES: u16 = 1;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u16 = 67;
pub const DEFAULT_MIN_EMERGENCY_WEIGHT: u16 = 80;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_NULLIFIER_RETENTION_EPOCHS: u64 = 64;
pub const DEFAULT_MAX_REQUESTS: usize = 256;
pub const DEFAULT_MAX_DECISIONS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationActor {
    UserWallet,
    RecoveryKey,
    WatcherQuorum,
    EmergencyWatcherQuorum,
    ChallengeArbiter,
    ReserveCouncil,
    SettlementAdapter,
}

impl AuthorizationActor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserWallet => "user_wallet",
            Self::RecoveryKey => "recovery_key",
            Self::WatcherQuorum => "watcher_quorum",
            Self::EmergencyWatcherQuorum => "emergency_watcher_quorum",
            Self::ChallengeArbiter => "challenge_arbiter",
            Self::ReserveCouncil => "reserve_council",
            Self::SettlementAdapter => "settlement_adapter",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationPathKind {
    UserForcedWithdrawal,
    RecoveryForcedWithdrawal,
    WatcherCensorshipEscape,
    EmergencyLivenessEscape,
    ChallengeResolvedRelease,
}

impl AuthorizationPathKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserForcedWithdrawal => "user_forced_withdrawal",
            Self::RecoveryForcedWithdrawal => "recovery_forced_withdrawal",
            Self::WatcherCensorshipEscape => "watcher_censorship_escape",
            Self::EmergencyLivenessEscape => "emergency_liveness_escape",
            Self::ChallengeResolvedRelease => "challenge_resolved_release",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    NoteCommitmentRoot,
    PrivateBalanceCommitment,
    WithdrawalIntentRoot,
    BurnNullifier,
    ExitNullifier,
    MoneroAddressCommitment,
    UserPqSignature,
    RecoveryPqSignature,
    WatcherQuorumAttestation,
    EmergencyQuorumAttestation,
    CensorshipTranscriptRoot,
    LivenessFailureRoot,
    ChallengeWindowRoot,
    ChallengeResolutionRoot,
    ReserveSolvencyRoot,
    ReplayFenceRoot,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoteCommitmentRoot => "note_commitment_root",
            Self::PrivateBalanceCommitment => "private_balance_commitment",
            Self::WithdrawalIntentRoot => "withdrawal_intent_root",
            Self::BurnNullifier => "burn_nullifier",
            Self::ExitNullifier => "exit_nullifier",
            Self::MoneroAddressCommitment => "monero_address_commitment",
            Self::UserPqSignature => "user_pq_signature",
            Self::RecoveryPqSignature => "recovery_pq_signature",
            Self::WatcherQuorumAttestation => "watcher_quorum_attestation",
            Self::EmergencyQuorumAttestation => "emergency_quorum_attestation",
            Self::CensorshipTranscriptRoot => "censorship_transcript_root",
            Self::LivenessFailureRoot => "liveness_failure_root",
            Self::ChallengeWindowRoot => "challenge_window_root",
            Self::ChallengeResolutionRoot => "challenge_resolution_root",
            Self::ReserveSolvencyRoot => "reserve_solvency_root",
            Self::ReplayFenceRoot => "replay_fence_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    MlDsa87,
    SlhDsaSha256f,
    HybridMlDsaEd25519Binding,
}

impl SignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaSha256f => "slh_dsa_sha256f",
            Self::HybridMlDsaEd25519Binding => "hybrid_ml_dsa_ed25519_binding",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    Authorized,
    Denied,
    Quarantined,
}

impl DecisionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Denied => "denied",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    MissingUserLocalEvidence,
    MissingPqSignature,
    InsufficientQuorumWeight,
    StaleEpoch,
    ReplayNullifierSeen,
    AmountExceedsPrivateBalance,
    OpenChallenge,
    ReserveProofMissing,
    DestinationCommitmentMismatch,
    PolicyProductionReleaseDisabled,
}

impl DenialReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingUserLocalEvidence => "missing_user_local_evidence",
            Self::MissingPqSignature => "missing_pq_signature",
            Self::InsufficientQuorumWeight => "insufficient_quorum_weight",
            Self::StaleEpoch => "stale_epoch",
            Self::ReplayNullifierSeen => "replay_nullifier_seen",
            Self::AmountExceedsPrivateBalance => "amount_exceeds_private_balance",
            Self::OpenChallenge => "open_challenge",
            Self::ReserveProofMissing => "reserve_proof_missing",
            Self::DestinationCommitmentMismatch => "destination_commitment_mismatch",
            Self::PolicyProductionReleaseDisabled => "policy_production_release_disabled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub authorization_suite: String,
    pub min_user_signatures: u16,
    pub min_watcher_weight: u16,
    pub min_emergency_weight: u16,
    pub min_pq_security_bits: u16,
    pub challenge_window_blocks: u64,
    pub nullifier_retention_epochs: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_requests: usize,
    pub max_decisions: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            authorization_suite: AUTHORIZATION_SUITE.to_string(),
            min_user_signatures: DEFAULT_MIN_USER_SIGNATURES,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            min_emergency_weight: DEFAULT_MIN_EMERGENCY_WEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            nullifier_retention_epochs: DEFAULT_NULLIFIER_RETENTION_EPOCHS,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_requests: DEFAULT_MAX_REQUESTS,
            max_decisions: DEFAULT_MAX_DECISIONS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "authorization_suite": self.authorization_suite,
            "min_user_signatures": self.min_user_signatures,
            "min_watcher_weight": self.min_watcher_weight,
            "min_emergency_weight": self.min_emergency_weight,
            "min_pq_security_bits": self.min_pq_security_bits,
            "challenge_window_blocks": self.challenge_window_blocks,
            "nullifier_retention_epochs": self.nullifier_retention_epochs,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_requests": self.max_requests,
            "max_decisions": self.max_decisions,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationRule {
    pub path_id: String,
    pub kind: AuthorizationPathKind,
    pub required_actors: Vec<AuthorizationActor>,
    pub required_evidence: Vec<EvidenceKind>,
    pub min_user_signatures: u16,
    pub min_watcher_weight: u16,
    pub min_emergency_weight: u16,
    pub sequencer_can_authorize: bool,
    pub release_requires_reserve: bool,
    pub open_challenge_denies_release: bool,
    pub root: String,
}

impl AuthorizationRule {
    pub fn new(
        kind: AuthorizationPathKind,
        required_actors: Vec<AuthorizationActor>,
        required_evidence: Vec<EvidenceKind>,
        min_user_signatures: u16,
        min_watcher_weight: u16,
        min_emergency_weight: u16,
    ) -> Self {
        let record = json!({
            "kind": kind.as_str(),
            "required_actors": actor_names(&required_actors),
            "required_evidence": evidence_names(&required_evidence),
            "min_user_signatures": min_user_signatures,
            "min_watcher_weight": min_watcher_weight,
            "min_emergency_weight": min_emergency_weight,
            "sequencer_can_authorize": false,
            "release_requires_reserve": true,
            "open_challenge_denies_release": true,
        });
        let root = record_root("authorization_rule", &record);
        Self {
            path_id: authorization_id("path", kind.as_str(), &root),
            kind,
            required_actors,
            required_evidence,
            min_user_signatures,
            min_watcher_weight,
            min_emergency_weight,
            sequencer_can_authorize: false,
            release_requires_reserve: true,
            open_challenge_denies_release: true,
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "path_id": self.path_id,
            "kind": self.kind.as_str(),
            "required_actors": actor_names(&self.required_actors),
            "required_evidence": evidence_names(&self.required_evidence),
            "min_user_signatures": self.min_user_signatures,
            "min_watcher_weight": self.min_watcher_weight,
            "min_emergency_weight": self.min_emergency_weight,
            "sequencer_can_authorize": self.sequencer_can_authorize,
            "release_requires_reserve": self.release_requires_reserve,
            "open_challenge_denies_release": self.open_challenge_denies_release,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignature {
    pub signature_id: String,
    pub actor: AuthorizationActor,
    pub scheme: SignatureScheme,
    pub signer_key_root: String,
    pub signed_intent_root: String,
    pub security_bits: u16,
    pub key_epoch: u64,
    pub signature_root: String,
}

impl PqSignature {
    pub fn new(
        actor: AuthorizationActor,
        scheme: SignatureScheme,
        signer_key_root: impl Into<String>,
        signed_intent_root: impl Into<String>,
        security_bits: u16,
        key_epoch: u64,
    ) -> Self {
        let signer_key_root = signer_key_root.into();
        let signed_intent_root = signed_intent_root.into();
        let record = json!({
            "actor": actor.as_str(),
            "scheme": scheme.as_str(),
            "signer_key_root": signer_key_root,
            "signed_intent_root": signed_intent_root,
            "security_bits": security_bits,
            "key_epoch": key_epoch,
        });
        let signature_root = record_root("pq_signature", &record);
        Self {
            signature_id: authorization_id("pq_signature", actor.as_str(), &signature_root),
            actor,
            scheme,
            signer_key_root,
            signed_intent_root,
            security_bits,
            key_epoch,
            signature_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signature_id": self.signature_id,
            "actor": self.actor.as_str(),
            "scheme": self.scheme.as_str(),
            "signer_key_root": self.signer_key_root,
            "signed_intent_root": self.signed_intent_root,
            "security_bits": self.security_bits,
            "key_epoch": self.key_epoch,
            "signature_root": self.signature_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuorumAttestation {
    pub attestation_id: String,
    pub actor: AuthorizationActor,
    pub scheme: SignatureScheme,
    pub quorum_root: String,
    pub signed_request_root: String,
    pub weight: u16,
    pub threshold: u16,
    pub key_epoch: u64,
    pub attestation_root: String,
}

impl QuorumAttestation {
    pub fn new(
        actor: AuthorizationActor,
        quorum_root: impl Into<String>,
        signed_request_root: impl Into<String>,
        weight: u16,
        threshold: u16,
        key_epoch: u64,
    ) -> Self {
        let quorum_root = quorum_root.into();
        let signed_request_root = signed_request_root.into();
        let record = json!({
            "actor": actor.as_str(),
            "scheme": SignatureScheme::MlDsa87.as_str(),
            "quorum_root": quorum_root,
            "signed_request_root": signed_request_root,
            "weight": weight,
            "threshold": threshold,
            "key_epoch": key_epoch,
        });
        let attestation_root = record_root("quorum_attestation", &record);
        Self {
            attestation_id: authorization_id(
                "quorum_attestation",
                actor.as_str(),
                &attestation_root,
            ),
            actor,
            scheme: SignatureScheme::MlDsa87,
            quorum_root,
            signed_request_root,
            weight,
            threshold,
            key_epoch,
            attestation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "actor": self.actor.as_str(),
            "scheme": self.scheme.as_str(),
            "quorum_root": self.quorum_root,
            "signed_request_root": self.signed_request_root,
            "weight": self.weight,
            "threshold": self.threshold,
            "key_epoch": self.key_epoch,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserLocalEvidence {
    pub evidence_id: String,
    pub note_commitment_root: String,
    pub private_balance_commitment: String,
    pub withdrawal_intent_root: String,
    pub burn_nullifier: String,
    pub exit_nullifier: String,
    pub monero_address_commitment: String,
    pub amount_atomic: u64,
    pub epoch: u64,
    pub evidence_root: String,
}

impl UserLocalEvidence {
    pub fn new(
        note_commitment_root: impl Into<String>,
        private_balance_commitment: impl Into<String>,
        withdrawal_intent_root: impl Into<String>,
        burn_nullifier: impl Into<String>,
        exit_nullifier: impl Into<String>,
        monero_address_commitment: impl Into<String>,
        amount_atomic: u64,
        epoch: u64,
    ) -> Self {
        let note_commitment_root = note_commitment_root.into();
        let private_balance_commitment = private_balance_commitment.into();
        let withdrawal_intent_root = withdrawal_intent_root.into();
        let burn_nullifier = burn_nullifier.into();
        let exit_nullifier = exit_nullifier.into();
        let monero_address_commitment = monero_address_commitment.into();
        let record = json!({
            "note_commitment_root": note_commitment_root,
            "private_balance_commitment": private_balance_commitment,
            "withdrawal_intent_root": withdrawal_intent_root,
            "burn_nullifier": burn_nullifier,
            "exit_nullifier": exit_nullifier,
            "monero_address_commitment": monero_address_commitment,
            "amount_atomic": amount_atomic,
            "epoch": epoch,
        });
        let evidence_root = record_root("user_local_evidence", &record);
        Self {
            evidence_id: authorization_id("user_local_evidence", &exit_nullifier, &evidence_root),
            note_commitment_root,
            private_balance_commitment,
            withdrawal_intent_root,
            burn_nullifier,
            exit_nullifier,
            monero_address_commitment,
            amount_atomic,
            epoch,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "note_commitment_root": self.note_commitment_root,
            "private_balance_commitment": self.private_balance_commitment,
            "withdrawal_intent_root": self.withdrawal_intent_root,
            "burn_nullifier": self.burn_nullifier,
            "exit_nullifier": self.exit_nullifier,
            "monero_address_commitment": self.monero_address_commitment,
            "amount_atomic": self.amount_atomic,
            "epoch": self.epoch,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedWithdrawalRequest {
    pub request_id: String,
    pub path: AuthorizationPathKind,
    pub user_evidence: UserLocalEvidence,
    pub user_signatures: Vec<PqSignature>,
    pub quorum_attestations: Vec<QuorumAttestation>,
    pub censorship_transcript_root: String,
    pub liveness_failure_root: String,
    pub challenge_window_root: String,
    pub challenge_resolution_root: String,
    pub reserve_solvency_root: String,
    pub requested_at_block: u64,
    pub request_root: String,
}

impl ForcedWithdrawalRequest {
    pub fn new(
        path: AuthorizationPathKind,
        user_evidence: UserLocalEvidence,
        user_signatures: Vec<PqSignature>,
        quorum_attestations: Vec<QuorumAttestation>,
        context: RequestContext,
    ) -> Self {
        let signature_roots = user_signatures
            .iter()
            .map(|signature| Value::String(signature.signature_root.clone()))
            .collect::<Vec<_>>();
        let attestation_roots = quorum_attestations
            .iter()
            .map(|attestation| Value::String(attestation.attestation_root.clone()))
            .collect::<Vec<_>>();
        let signature_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-SIGNATURES",
            &signature_roots,
        );
        let attestation_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-ATTESTATIONS",
            &attestation_roots,
        );
        let record = json!({
            "path": path.as_str(),
            "user_evidence_root": user_evidence.evidence_root,
            "signature_root": signature_root,
            "attestation_root": attestation_root,
            "censorship_transcript_root": context.censorship_transcript_root,
            "liveness_failure_root": context.liveness_failure_root,
            "challenge_window_root": context.challenge_window_root,
            "challenge_resolution_root": context.challenge_resolution_root,
            "reserve_solvency_root": context.reserve_solvency_root,
            "requested_at_block": context.requested_at_block,
        });
        let request_root = record_root("forced_withdrawal_request", &record);
        Self {
            request_id: authorization_id("request", path.as_str(), &request_root),
            path,
            user_evidence,
            user_signatures,
            quorum_attestations,
            censorship_transcript_root: context.censorship_transcript_root,
            liveness_failure_root: context.liveness_failure_root,
            challenge_window_root: context.challenge_window_root,
            challenge_resolution_root: context.challenge_resolution_root,
            reserve_solvency_root: context.reserve_solvency_root,
            requested_at_block: context.requested_at_block,
            request_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "path": self.path.as_str(),
            "user_evidence": self.user_evidence.public_record(),
            "user_signatures": self.user_signatures.iter().map(PqSignature::public_record).collect::<Vec<_>>(),
            "quorum_attestations": self.quorum_attestations.iter().map(QuorumAttestation::public_record).collect::<Vec<_>>(),
            "censorship_transcript_root": self.censorship_transcript_root,
            "liveness_failure_root": self.liveness_failure_root,
            "challenge_window_root": self.challenge_window_root,
            "challenge_resolution_root": self.challenge_resolution_root,
            "reserve_solvency_root": self.reserve_solvency_root,
            "requested_at_block": self.requested_at_block,
            "request_root": self.request_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestContext {
    pub censorship_transcript_root: String,
    pub liveness_failure_root: String,
    pub challenge_window_root: String,
    pub challenge_resolution_root: String,
    pub reserve_solvency_root: String,
    pub requested_at_block: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationDecision {
    pub decision_id: String,
    pub request_id: String,
    pub path: AuthorizationPathKind,
    pub status: DecisionStatus,
    pub denial_reasons: Vec<DenialReason>,
    pub release_certificate_root: String,
    pub replay_fence_root: String,
    pub decision_root: String,
}

impl AuthorizationDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "request_id": self.request_id,
            "path": self.path.as_str(),
            "status": self.status.as_str(),
            "denial_reasons": self.denial_reasons.iter().map(|reason| reason.as_str()).collect::<Vec<_>>(),
            "release_certificate_root": self.release_certificate_root,
            "replay_fence_root": self.replay_fence_root,
            "decision_root": self.decision_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub epoch: u64,
    pub burn_nullifier: String,
    pub exit_nullifier: String,
    pub request_root: String,
    pub consumed: bool,
    pub fence_root: String,
}

impl NullifierFence {
    pub fn new(request: &ForcedWithdrawalRequest, consumed: bool) -> Self {
        let burn_nullifier = request.user_evidence.burn_nullifier.clone();
        let exit_nullifier = request.user_evidence.exit_nullifier.clone();
        let record = json!({
            "epoch": request.user_evidence.epoch,
            "burn_nullifier": burn_nullifier,
            "exit_nullifier": exit_nullifier,
            "request_root": request.request_root,
            "consumed": consumed,
        });
        let fence_root = record_root("nullifier_fence", &record);
        Self {
            fence_id: authorization_id("nullifier_fence", &exit_nullifier, &fence_root),
            epoch: request.user_evidence.epoch,
            burn_nullifier,
            exit_nullifier,
            request_root: request.request_root.clone(),
            consumed,
            fence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "epoch": self.epoch,
            "burn_nullifier": self.burn_nullifier,
            "exit_nullifier": self.exit_nullifier,
            "request_root": self.request_root,
            "consumed": self.consumed,
            "fence_root": self.fence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub rules: BTreeMap<String, AuthorizationRule>,
    pub requests: BTreeMap<String, ForcedWithdrawalRequest>,
    pub decisions: BTreeMap<String, AuthorizationDecision>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub current_epoch: u64,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config: config.clone(),
            rules: default_rules(&config),
            requests: BTreeMap::new(),
            decisions: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            current_epoch: 42,
        };
        let request = devnet_request(&config, state.current_epoch);
        let _ = state.submit_request(request);
        state
    }

    pub fn submit_request(
        &mut self,
        request: ForcedWithdrawalRequest,
    ) -> Result<AuthorizationDecision> {
        ensure(
            self.requests.len() < self.config.max_requests,
            "forced withdrawal request capacity exceeded",
        )?;
        ensure(
            self.decisions.len() < self.config.max_decisions,
            "forced withdrawal decision capacity exceeded",
        )?;
        let decision = self.evaluate_request(&request)?;
        let fence = NullifierFence::new(&request, decision.status == DecisionStatus::Authorized);
        self.nullifier_fences
            .insert(request.user_evidence.exit_nullifier.clone(), fence);
        self.decisions
            .insert(decision.decision_id.clone(), decision.clone());
        self.requests.insert(request.request_id.clone(), request);
        Ok(decision)
    }

    pub fn evaluate_request(
        &self,
        request: &ForcedWithdrawalRequest,
    ) -> Result<AuthorizationDecision> {
        let rule = self
            .rule_for_path(request.path)
            .ok_or_else(|| format!("missing authorization rule for {}", request.path.as_str()))?;
        let mut denial_reasons = Vec::new();

        if !self.user_evidence_complete(&request.user_evidence) {
            denial_reasons.push(DenialReason::MissingUserLocalEvidence);
        }
        if self.valid_user_signature_count(request) < rule.min_user_signatures {
            denial_reasons.push(DenialReason::MissingPqSignature);
        }
        if self.required_quorum_weight(request, AuthorizationActor::WatcherQuorum)
            < rule.min_watcher_weight
        {
            denial_reasons.push(DenialReason::InsufficientQuorumWeight);
        }
        if rule.min_emergency_weight > 0
            && self.required_quorum_weight(request, AuthorizationActor::EmergencyWatcherQuorum)
                < rule.min_emergency_weight
        {
            denial_reasons.push(DenialReason::InsufficientQuorumWeight);
        }
        if request.user_evidence.epoch + self.config.nullifier_retention_epochs < self.current_epoch
        {
            denial_reasons.push(DenialReason::StaleEpoch);
        }
        if self.nullifier_seen(&request.user_evidence.exit_nullifier) {
            denial_reasons.push(DenialReason::ReplayNullifierSeen);
        }
        if request.user_evidence.amount_atomic == 0 {
            denial_reasons.push(DenialReason::AmountExceedsPrivateBalance);
        }
        if rule.open_challenge_denies_release && request.challenge_resolution_root.is_empty() {
            denial_reasons.push(DenialReason::OpenChallenge);
        }
        if rule.release_requires_reserve && request.reserve_solvency_root.is_empty() {
            denial_reasons.push(DenialReason::ReserveProofMissing);
        }
        if request.user_evidence.monero_address_commitment.is_empty() {
            denial_reasons.push(DenialReason::DestinationCommitmentMismatch);
        }
        if !self.config.production_release_allowed {
            denial_reasons.push(DenialReason::PolicyProductionReleaseDisabled);
        }

        let status = if denial_reasons.is_empty() {
            DecisionStatus::Authorized
        } else if denial_reasons
            .iter()
            .any(|reason| *reason == DenialReason::ReplayNullifierSeen)
        {
            DecisionStatus::Denied
        } else {
            DecisionStatus::Quarantined
        };
        let replay_fence_root = replay_fence_root(
            &request.user_evidence.burn_nullifier,
            &request.user_evidence.exit_nullifier,
            request.user_evidence.epoch,
            &request.request_root,
        );
        let release_certificate_root = if status == DecisionStatus::Authorized {
            release_certificate_root(request, &replay_fence_root)
        } else {
            String::new()
        };
        let decision_record = json!({
            "request_id": request.request_id,
            "path": request.path.as_str(),
            "status": status.as_str(),
            "denial_reasons": denial_reasons.iter().map(|reason| reason.as_str()).collect::<Vec<_>>(),
            "release_certificate_root": release_certificate_root,
            "replay_fence_root": replay_fence_root,
        });
        let decision_root = record_root("authorization_decision", &decision_record);
        Ok(AuthorizationDecision {
            decision_id: authorization_id("decision", &request.request_id, &decision_root),
            request_id: request.request_id.clone(),
            path: request.path,
            status,
            denial_reasons,
            release_certificate_root,
            replay_fence_root,
            decision_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "rules": self.rules.values().map(AuthorizationRule::public_record).collect::<Vec<_>>(),
            "requests": self.requests.values().map(ForcedWithdrawalRequest::public_record).collect::<Vec<_>>(),
            "decisions": self.decisions.values().map(AuthorizationDecision::public_record).collect::<Vec<_>>(),
            "nullifier_fences": self.nullifier_fences.values().map(NullifierFence::public_record).collect::<Vec<_>>(),
            "current_epoch": self.current_epoch,
            "rule_root": self.rule_root(),
            "request_root": self.request_root(),
            "decision_root": self.decision_root(),
            "nullifier_fence_root": self.nullifier_fence_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.rule_root()),
                HashPart::Str(&self.request_root()),
                HashPart::Str(&self.decision_root()),
                HashPart::Str(&self.nullifier_fence_root()),
                HashPart::U64(self.current_epoch),
            ],
            32,
        )
    }

    pub fn rule_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-RULES",
            &self
                .rules
                .values()
                .map(AuthorizationRule::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn request_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-REQUESTS",
            &self
                .requests
                .values()
                .map(ForcedWithdrawalRequest::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn decision_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-DECISIONS",
            &self
                .decisions
                .values()
                .map(AuthorizationDecision::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn nullifier_fence_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-NULLIFIER-FENCES",
            &self
                .nullifier_fences
                .values()
                .map(NullifierFence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn rule_for_path(&self, path: AuthorizationPathKind) -> Option<&AuthorizationRule> {
        self.rules.values().find(|rule| rule.kind == path)
    }

    pub fn denial_reasons_for(&self, request_id: &str) -> Option<Vec<DenialReason>> {
        self.decisions
            .values()
            .find(|decision| decision.request_id == request_id)
            .map(|decision| decision.denial_reasons.clone())
    }

    pub fn release_denied(&self, request_id: &str) -> bool {
        self.decisions
            .values()
            .find(|decision| decision.request_id == request_id)
            .is_some_and(|decision| decision.status != DecisionStatus::Authorized)
    }

    pub fn nullifier_seen(&self, exit_nullifier: &str) -> bool {
        self.nullifier_fences.contains_key(exit_nullifier)
    }

    fn user_evidence_complete(&self, evidence: &UserLocalEvidence) -> bool {
        !evidence.note_commitment_root.is_empty()
            && !evidence.private_balance_commitment.is_empty()
            && !evidence.withdrawal_intent_root.is_empty()
            && !evidence.burn_nullifier.is_empty()
            && !evidence.exit_nullifier.is_empty()
            && !evidence.monero_address_commitment.is_empty()
    }

    fn valid_user_signature_count(&self, request: &ForcedWithdrawalRequest) -> u16 {
        request
            .user_signatures
            .iter()
            .filter(|signature| {
                matches!(
                    signature.actor,
                    AuthorizationActor::UserWallet | AuthorizationActor::RecoveryKey
                ) && signature.signed_intent_root == request.user_evidence.withdrawal_intent_root
                    && signature.security_bits >= self.config.min_pq_security_bits
            })
            .count() as u16
    }

    fn required_quorum_weight(
        &self,
        request: &ForcedWithdrawalRequest,
        actor: AuthorizationActor,
    ) -> u16 {
        request
            .quorum_attestations
            .iter()
            .filter(|attestation| {
                attestation.actor == actor
                    && attestation.signed_request_root == request.request_root
                    && attestation.weight >= attestation.threshold
            })
            .map(|attestation| attestation.weight)
            .max()
            .unwrap_or(0)
    }
}

fn default_rules(config: &Config) -> BTreeMap<String, AuthorizationRule> {
    let mut rules = BTreeMap::new();
    let entries = [
        AuthorizationRule::new(
            AuthorizationPathKind::UserForcedWithdrawal,
            vec![
                AuthorizationActor::UserWallet,
                AuthorizationActor::WatcherQuorum,
            ],
            vec![
                EvidenceKind::NoteCommitmentRoot,
                EvidenceKind::PrivateBalanceCommitment,
                EvidenceKind::WithdrawalIntentRoot,
                EvidenceKind::BurnNullifier,
                EvidenceKind::ExitNullifier,
                EvidenceKind::MoneroAddressCommitment,
                EvidenceKind::UserPqSignature,
                EvidenceKind::WatcherQuorumAttestation,
                EvidenceKind::ReserveSolvencyRoot,
                EvidenceKind::ReplayFenceRoot,
            ],
            config.min_user_signatures,
            config.min_watcher_weight,
            0,
        ),
        AuthorizationRule::new(
            AuthorizationPathKind::EmergencyLivenessEscape,
            vec![
                AuthorizationActor::UserWallet,
                AuthorizationActor::WatcherQuorum,
                AuthorizationActor::EmergencyWatcherQuorum,
            ],
            vec![
                EvidenceKind::WithdrawalIntentRoot,
                EvidenceKind::BurnNullifier,
                EvidenceKind::ExitNullifier,
                EvidenceKind::UserPqSignature,
                EvidenceKind::WatcherQuorumAttestation,
                EvidenceKind::EmergencyQuorumAttestation,
                EvidenceKind::LivenessFailureRoot,
                EvidenceKind::ReserveSolvencyRoot,
            ],
            config.min_user_signatures,
            config.min_watcher_weight,
            config.min_emergency_weight,
        ),
        AuthorizationRule::new(
            AuthorizationPathKind::ChallengeResolvedRelease,
            vec![
                AuthorizationActor::UserWallet,
                AuthorizationActor::ChallengeArbiter,
                AuthorizationActor::ReserveCouncil,
            ],
            vec![
                EvidenceKind::WithdrawalIntentRoot,
                EvidenceKind::ChallengeWindowRoot,
                EvidenceKind::ChallengeResolutionRoot,
                EvidenceKind::ReserveSolvencyRoot,
                EvidenceKind::ReplayFenceRoot,
            ],
            config.min_user_signatures,
            config.min_watcher_weight,
            0,
        ),
    ];
    for rule in entries {
        rules.insert(rule.path_id.clone(), rule);
    }
    rules
}

fn devnet_request(config: &Config, epoch: u64) -> ForcedWithdrawalRequest {
    let evidence = UserLocalEvidence::new(
        root("note_commitment", "devnet-user-note-set"),
        root("private_balance", "devnet-balance-commitment"),
        root("withdrawal_intent", "devnet-forced-withdrawal-intent"),
        root("burn_nullifier", "devnet-burn-nullifier"),
        root("exit_nullifier", "devnet-exit-nullifier"),
        root("monero_address_commitment", "devnet-destination"),
        1_250_000_000_000,
        epoch,
    );
    let signature = PqSignature::new(
        AuthorizationActor::UserWallet,
        SignatureScheme::MlDsa87,
        root("user_key", "devnet-wallet-key"),
        evidence.withdrawal_intent_root.clone(),
        config.min_pq_security_bits,
        epoch,
    );
    let context = RequestContext {
        censorship_transcript_root: root("censorship_transcript", "devnet-observed-delay"),
        liveness_failure_root: root("liveness_failure", "devnet-liveness-watch"),
        challenge_window_root: root("challenge_window", "devnet-window-expired"),
        challenge_resolution_root: root("challenge_resolution", "devnet-no-open-challenge"),
        reserve_solvency_root: root("reserve_solvency", "devnet-reserve-proof"),
        requested_at_block: 7_200,
    };
    let provisional = record_root(
        "devnet_request_preimage",
        &json!({
            "evidence_root": evidence.evidence_root,
            "path": AuthorizationPathKind::UserForcedWithdrawal.as_str(),
            "block": context.requested_at_block,
        }),
    );
    let attestation = QuorumAttestation::new(
        AuthorizationActor::WatcherQuorum,
        root("watcher_quorum", "devnet-watchers"),
        provisional.clone(),
        config.min_watcher_weight,
        config.min_watcher_weight,
        epoch,
    );
    let mut request = ForcedWithdrawalRequest::new(
        AuthorizationPathKind::UserForcedWithdrawal,
        evidence,
        vec![signature],
        vec![attestation],
        context,
    );
    let fixed_attestation = QuorumAttestation::new(
        AuthorizationActor::WatcherQuorum,
        root("watcher_quorum", "devnet-watchers"),
        request.request_root.clone(),
        config.min_watcher_weight,
        config.min_watcher_weight,
        epoch,
    );
    request.quorum_attestations = vec![fixed_attestation];
    request
}

fn actor_names(actors: &[AuthorizationActor]) -> Vec<&'static str> {
    actors.iter().map(|actor| actor.as_str()).collect()
}

fn evidence_names(evidence: &[EvidenceKind]) -> Vec<&'static str> {
    evidence.iter().map(|kind| kind.as_str()).collect()
}

fn release_certificate_root(request: &ForcedWithdrawalRequest, replay_fence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-RELEASE-CERTIFICATE",
        &[
            HashPart::Str(&request.request_id),
            HashPart::Str(&request.user_evidence.withdrawal_intent_root),
            HashPart::Str(&request.user_evidence.monero_address_commitment),
            HashPart::Str(replay_fence_root),
            HashPart::U64(request.requested_at_block),
        ],
        32,
    )
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

pub fn authorization_id(kind: &str, label: &str, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-ID",
        &[
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::Str(root),
        ],
        32,
    )
}

pub fn replay_fence_root(
    burn_nullifier: &str,
    exit_nullifier: &str,
    epoch: u64,
    request_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-REPLAY-FENCE",
        &[
            HashPart::Str(burn_nullifier),
            HashPart::Str(exit_nullifier),
            HashPart::U64(epoch),
            HashPart::Str(request_root),
        ],
        32,
    )
}

pub fn root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-ROOT",
        &[HashPart::Str(kind), HashPart::Str(label)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCED-WITHDRAWAL-AUTHORIZATION-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn required_user_local_evidence() -> BTreeSet<EvidenceKind> {
    [
        EvidenceKind::NoteCommitmentRoot,
        EvidenceKind::PrivateBalanceCommitment,
        EvidenceKind::WithdrawalIntentRoot,
        EvidenceKind::BurnNullifier,
        EvidenceKind::ExitNullifier,
        EvidenceKind::MoneroAddressCommitment,
    ]
    .into_iter()
    .collect()
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
