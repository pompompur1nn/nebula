use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqSessionResult<T> = Result<T, String>;

pub const PQ_SESSION_PROTOCOL_VERSION: &str = "nebula-l2-pq-session-v1";
pub const PQ_SESSION_SECURITY_MODEL: &str = "deterministic-devnet-model-not-real-crypto";
pub const PQ_SESSION_COMMITMENT_SCHEME: &str = "shake256-domain-separated-devnet-commitment";
pub const PQ_SESSION_TRANSCRIPT_SCHEME: &str = "shake256-canonical-json-transcript";
pub const PQ_ML_KEM_SCHEME: &str = "ML-KEM-768";
pub const PQ_ML_DSA_SCHEME: &str = "ML-DSA-65";
pub const PQ_SLH_DSA_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_HYBRID_CLASSIC_KEM_SCHEME: &str = "X25519-devnet-fallback";
pub const PQ_HYBRID_CLASSIC_SIGNATURE_SCHEME: &str = "Ed25519-devnet-fallback";
pub const PQ_HANDSHAKE_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const PQ_AUTH_REQUIRED_SET: &str = "ml_dsa_online_and_slh_dsa_recovery_witness";
pub const PQ_MEMPOOL_ENCRYPTION_SCHEME: &str = "ML-KEM-768-devnet-sealed-mempool-grant";
pub const PQ_OPERATOR_ATTESTATION_SCHEME: &str = "ML-DSA-65-devnet-operator-attestation";
pub const PQ_QUARANTINE_SCHEME: &str = "deterministic-devnet-quarantine-v1";
pub const PQ_MIGRATION_SCHEDULE_VERSION: &str = "pq-crypto-agility-schedule-v1";
pub const PQ_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const PQ_DEFAULT_HANDSHAKE_TTL_BLOCKS: u64 = 12;
pub const PQ_DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 192;
pub const PQ_DEFAULT_ROTATION_INTERVAL_BLOCKS: u64 = 720;
pub const PQ_DEFAULT_ROTATION_OVERLAP_BLOCKS: u64 = 48;
pub const PQ_DEFAULT_ROTATION_NOTICE_BLOCKS: u64 = 96;
pub const PQ_DEFAULT_MEMPOOL_GRANT_TTL_BLOCKS: u64 = 24;
pub const PQ_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const PQ_DEFAULT_QUARANTINE_BLOCKS: u64 = 1_440;
pub const PQ_DEFAULT_COMPROMISE_REVIEW_BLOCKS: u64 = 288;
pub const PQ_MAX_DEVNET_HANDSHAKES: usize = 16;
pub const PQ_MAX_DEVNET_TRANSCRIPTS: usize = 32;
pub const PQ_MAX_DEVNET_REPLAY_NONCES: usize = 256;
pub const PQ_MAX_DEVNET_MEMPOOL_GRANTS: usize = 64;
pub const PQ_MAX_DEVNET_ATTESTATIONS: usize = 64;
pub const PQ_MAX_DEVNET_COMPROMISES: usize = 32;
pub const PQ_MAX_DEVNET_MIGRATION_STEPS: usize = 32;
pub const PQ_STATUS_ACTIVE: &str = "active";
pub const PQ_STATUS_PENDING: &str = "pending";
pub const PQ_STATUS_ROTATING: &str = "rotating";
pub const PQ_STATUS_EXPIRED: &str = "expired";
pub const PQ_STATUS_REJECTED: &str = "rejected";
pub const PQ_STATUS_QUARANTINED: &str = "quarantined";
pub const PQ_STATUS_COMPROMISED: &str = "compromised";
pub const PQ_STATUS_REVOKED: &str = "revoked";
pub const PQ_STATUS_MIGRATING: &str = "migrating";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqKeyAlgorithm {
    MlKem768,
    MlDsa65,
    SlhDsaShake128s,
    HybridClassicKem,
    HybridClassicSignature,
}

impl PqKeyAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MlKem768 => PQ_ML_KEM_SCHEME,
            Self::MlDsa65 => PQ_ML_DSA_SCHEME,
            Self::SlhDsaShake128s => PQ_SLH_DSA_SCHEME,
            Self::HybridClassicKem => PQ_HYBRID_CLASSIC_KEM_SCHEME,
            Self::HybridClassicSignature => PQ_HYBRID_CLASSIC_SIGNATURE_SCHEME,
        }
    }

    pub fn family(&self) -> &'static str {
        match self {
            Self::MlKem768 | Self::HybridClassicKem => "key_establishment",
            Self::MlDsa65 | Self::SlhDsaShake128s | Self::HybridClassicSignature => "signature",
        }
    }

    pub fn standard(&self) -> &'static str {
        match self {
            Self::MlKem768 => "NIST FIPS 203",
            Self::MlDsa65 => "NIST FIPS 204",
            Self::SlhDsaShake128s => "NIST FIPS 205",
            Self::HybridClassicKem => "devnet-classic-fallback",
            Self::HybridClassicSignature => "devnet-classic-fallback",
        }
    }

    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::MlKem768 | Self::MlDsa65 | Self::SlhDsaShake128s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqKeyPurpose {
    SessionKem,
    OnlineAuth,
    RecoveryAuth,
    MempoolEncryption,
    OperatorAttestation,
    RotationWitness,
    CompromiseWitness,
    MigrationWitness,
}

impl PqKeyPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SessionKem => "session_kem",
            Self::OnlineAuth => "online_auth",
            Self::RecoveryAuth => "recovery_auth",
            Self::MempoolEncryption => "mempool_encryption",
            Self::OperatorAttestation => "operator_attestation",
            Self::RotationWitness => "rotation_witness",
            Self::CompromiseWitness => "compromise_witness",
            Self::MigrationWitness => "migration_witness",
        }
    }

    pub fn default_algorithm(&self) -> PqKeyAlgorithm {
        match self {
            Self::SessionKem | Self::MempoolEncryption => PqKeyAlgorithm::MlKem768,
            Self::RecoveryAuth | Self::CompromiseWitness => PqKeyAlgorithm::SlhDsaShake128s,
            Self::OnlineAuth
            | Self::OperatorAttestation
            | Self::RotationWitness
            | Self::MigrationWitness => PqKeyAlgorithm::MlDsa65,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqHandshakeRole {
    Initiator,
    Responder,
    Observer,
    Sequencer,
    Watchtower,
}

impl PqHandshakeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
            Self::Observer => "observer",
            Self::Sequencer => "sequencer",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqHandshakeStage {
    Offered,
    Encapsulated,
    Authenticated,
    Confirmed,
    Rejected,
    Expired,
    Quarantined,
}

impl PqHandshakeStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Encapsulated => "encapsulated",
            Self::Authenticated => "authenticated",
            Self::Confirmed => "confirmed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::Rejected | Self::Expired | Self::Quarantined
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqAuthTranscriptKind {
    MlDsaOnline,
    SlhDsaRecovery,
    DualSignature,
    OperatorAttestation,
    RotationWitness,
    CompromiseWitness,
    MigrationWitness,
}

impl PqAuthTranscriptKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MlDsaOnline => "ml_dsa_online",
            Self::SlhDsaRecovery => "slh_dsa_recovery",
            Self::DualSignature => "dual_signature",
            Self::OperatorAttestation => "operator_attestation",
            Self::RotationWitness => "rotation_witness",
            Self::CompromiseWitness => "compromise_witness",
            Self::MigrationWitness => "migration_witness",
        }
    }

    pub fn primary_scheme(&self) -> &'static str {
        match self {
            Self::SlhDsaRecovery | Self::CompromiseWitness => PQ_SLH_DSA_SCHEME,
            Self::DualSignature => PQ_HANDSHAKE_SUITE,
            _ => PQ_ML_DSA_SCHEME,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqRotationStage {
    Announced,
    DualPublishing,
    DualSigning,
    Activating,
    Active,
    RetiringPrevious,
    Complete,
    Cancelled,
}

impl PqRotationStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::DualPublishing => "dual_publishing",
            Self::DualSigning => "dual_signing",
            Self::Activating => "activating",
            Self::Active => "active",
            Self::RetiringPrevious => "retiring_previous",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqHybridFallbackMode {
    Disabled,
    AuditOnly,
    RequirePqPreferClassic,
    RequireClassicPreferPq,
    RequireBoth,
    EmergencyClassicOnly,
}

impl PqHybridFallbackMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AuditOnly => "audit_only",
            Self::RequirePqPreferClassic => "require_pq_prefer_classic",
            Self::RequireClassicPreferPq => "require_classic_prefer_pq",
            Self::RequireBoth => "require_both",
            Self::EmergencyClassicOnly => "emergency_classic_only",
        }
    }

    pub fn permits_classic_only(&self) -> bool {
        matches!(self, Self::EmergencyClassicOnly)
    }

    pub fn requires_pq(&self) -> bool {
        matches!(
            self,
            Self::Disabled | Self::AuditOnly | Self::RequirePqPreferClassic | Self::RequireBoth
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqReplayStatus {
    Observed,
    Accepted,
    RejectedDuplicate,
    RejectedExpired,
    RejectedDomainMismatch,
    Quarantined,
}

impl PqReplayStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Accepted => "accepted",
            Self::RejectedDuplicate => "rejected_duplicate",
            Self::RejectedExpired => "rejected_expired",
            Self::RejectedDomainMismatch => "rejected_domain_mismatch",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqMempoolGrantScope {
    SubmitPrivateTx,
    SubmitBundle,
    ReadEncryptedLane,
    Preconfirm,
    CancelPending,
    SequencerDrain,
}

impl PqMempoolGrantScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SubmitPrivateTx => "submit_private_tx",
            Self::SubmitBundle => "submit_bundle",
            Self::ReadEncryptedLane => "read_encrypted_lane",
            Self::Preconfirm => "preconfirm",
            Self::CancelPending => "cancel_pending",
            Self::SequencerDrain => "sequencer_drain",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqAttestationKind {
    OperatorBoot,
    EpochHealth,
    RotationReadiness,
    MempoolLane,
    QuarantineAction,
    MigrationReadiness,
}

impl PqAttestationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OperatorBoot => "operator_boot",
            Self::EpochHealth => "epoch_health",
            Self::RotationReadiness => "rotation_readiness",
            Self::MempoolLane => "mempool_lane",
            Self::QuarantineAction => "quarantine_action",
            Self::MigrationReadiness => "migration_readiness",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqCompromiseKind {
    KemDecapsulationLeak,
    SignatureKeyDisclosure,
    TranscriptReplay,
    NonceReuse,
    OperatorReport,
    WatchtowerFinding,
    MigrationRegression,
}

impl PqCompromiseKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KemDecapsulationLeak => "kem_decapsulation_leak",
            Self::SignatureKeyDisclosure => "signature_key_disclosure",
            Self::TranscriptReplay => "transcript_replay",
            Self::NonceReuse => "nonce_reuse",
            Self::OperatorReport => "operator_report",
            Self::WatchtowerFinding => "watchtower_finding",
            Self::MigrationRegression => "migration_regression",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqRiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl PqRiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn freezes_sessions(&self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqQuarantineAction {
    Observe,
    RejectNewSessions,
    RevokeGrants,
    FreezePeer,
    RequireRotation,
    EmergencyClassicFallback,
    FullIsolation,
}

impl PqQuarantineAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::RejectNewSessions => "reject_new_sessions",
            Self::RevokeGrants => "revoke_grants",
            Self::FreezePeer => "freeze_peer",
            Self::RequireRotation => "require_rotation",
            Self::EmergencyClassicFallback => "emergency_classic_fallback",
            Self::FullIsolation => "full_isolation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PqMigrationPhase {
    Discover,
    Shadow,
    DualPublish,
    DualSign,
    EnforcePq,
    RetireClassic,
    Complete,
    Rollback,
}

impl PqMigrationPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Shadow => "shadow",
            Self::DualPublish => "dual_publish",
            Self::DualSign => "dual_sign",
            Self::EnforcePq => "enforce_pq",
            Self::RetireClassic => "retire_classic",
            Self::Complete => "complete",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeyCommitment {
    pub key_id: String,
    pub owner_label: String,
    pub purpose: PqKeyPurpose,
    pub algorithm: PqKeyAlgorithm,
    pub scheme: String,
    pub public_key_commitment: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub activates_at_height: u64,
    pub expires_at_height: u64,
    pub rotation_nonce: u64,
    pub status: String,
}

impl PqKeyCommitment {
    pub fn deterministic(
        owner_label: &str,
        purpose: PqKeyPurpose,
        rotation_nonce: u64,
        created_at_height: u64,
        activates_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(owner_label, "pq key owner_label")?;
        if expires_at_height <= activates_at_height {
            return Err("pq key expiry must be after activation".to_string());
        }
        let algorithm = purpose.default_algorithm();
        let public_key_commitment = pq_key_material_commitment(
            owner_label,
            purpose.as_str(),
            algorithm.as_str(),
            rotation_nonce,
        );
        let metadata_root = pq_payload_root("PQ-KEY-METADATA", metadata);
        let key_id = pq_key_id(
            owner_label,
            purpose.as_str(),
            algorithm.as_str(),
            &public_key_commitment,
            rotation_nonce,
        );
        let key = Self {
            key_id,
            owner_label: owner_label.to_string(),
            purpose,
            scheme: algorithm.as_str().to_string(),
            algorithm,
            public_key_commitment,
            metadata_root,
            created_at_height,
            activates_at_height,
            expires_at_height,
            rotation_nonce,
            status: PQ_STATUS_ACTIVE.to_string(),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn with_algorithm(
        owner_label: &str,
        purpose: PqKeyPurpose,
        algorithm: PqKeyAlgorithm,
        rotation_nonce: u64,
        created_at_height: u64,
        activates_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(owner_label, "pq key owner_label")?;
        if algorithm.family() != purpose.default_algorithm().family() {
            return Err("pq key algorithm family does not match purpose".to_string());
        }
        if expires_at_height <= activates_at_height {
            return Err("pq key expiry must be after activation".to_string());
        }
        let public_key_commitment = pq_key_material_commitment(
            owner_label,
            purpose.as_str(),
            algorithm.as_str(),
            rotation_nonce,
        );
        let metadata_root = pq_payload_root("PQ-KEY-METADATA", metadata);
        let key_id = pq_key_id(
            owner_label,
            purpose.as_str(),
            algorithm.as_str(),
            &public_key_commitment,
            rotation_nonce,
        );
        let key = Self {
            key_id,
            owner_label: owner_label.to_string(),
            purpose,
            scheme: algorithm.as_str().to_string(),
            algorithm,
            public_key_commitment,
            metadata_root,
            created_at_height,
            activates_at_height,
            expires_at_height,
            rotation_nonce,
            status: PQ_STATUS_ACTIVE.to_string(),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_key_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "key_id": self.key_id,
            "owner_label": self.owner_label,
            "purpose": self.purpose.as_str(),
            "algorithm": self.algorithm.as_str(),
            "algorithm_family": self.algorithm.family(),
            "standard": self.algorithm.standard(),
            "scheme": self.scheme,
            "public_key_commitment": self.public_key_commitment,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "activates_at_height": self.activates_at_height,
            "expires_at_height": self.expires_at_height,
            "rotation_nonce": self.rotation_nonce,
            "status": self.status,
        })
    }

    pub fn key_root(&self) -> String {
        pq_payload_root("PQ-KEY-COMMITMENT", &self.public_record())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PQ_STATUS_ACTIVE
            && self.activates_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.key_id, "pq key id")?;
        ensure_non_empty(&self.owner_label, "pq key owner_label")?;
        ensure_non_empty(&self.scheme, "pq key scheme")?;
        ensure_non_empty(&self.public_key_commitment, "pq key public commitment")?;
        ensure_non_empty(&self.metadata_root, "pq key metadata root")?;
        if self.scheme != self.algorithm.as_str() {
            return Err("pq key scheme does not match algorithm".to_string());
        }
        if self.expires_at_height <= self.activates_at_height {
            return Err("pq key expiry must be after activation".to_string());
        }
        Ok(self.key_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSessionPeer {
    pub peer_id: String,
    pub label: String,
    pub role: PqHandshakeRole,
    pub kem_key: PqKeyCommitment,
    pub ml_dsa_key: PqKeyCommitment,
    pub slh_dsa_key: PqKeyCommitment,
    pub fallback_kem_key: Option<PqKeyCommitment>,
    pub fallback_signature_key: Option<PqKeyCommitment>,
    pub route_hint_root: String,
    pub policy_root: String,
    pub created_at_height: u64,
    pub status: String,
}

impl PqSessionPeer {
    pub fn deterministic(
        label: &str,
        role: PqHandshakeRole,
        created_at_height: u64,
        rotation_nonce: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(label, "pq peer label")?;
        let metadata = json!({
            "label": label,
            "role": role.as_str(),
            "rotation_nonce": rotation_nonce,
            "model": PQ_SESSION_SECURITY_MODEL,
        });
        let expires_at_height = created_at_height + PQ_DEFAULT_ROTATION_INTERVAL_BLOCKS * 2;
        let kem_key = PqKeyCommitment::deterministic(
            label,
            PqKeyPurpose::SessionKem,
            rotation_nonce,
            created_at_height,
            created_at_height,
            expires_at_height,
            &metadata,
        )?;
        let ml_dsa_key = PqKeyCommitment::deterministic(
            label,
            PqKeyPurpose::OnlineAuth,
            rotation_nonce,
            created_at_height,
            created_at_height,
            expires_at_height,
            &metadata,
        )?;
        let slh_dsa_key = PqKeyCommitment::deterministic(
            label,
            PqKeyPurpose::RecoveryAuth,
            rotation_nonce,
            created_at_height,
            created_at_height,
            expires_at_height,
            &metadata,
        )?;
        let fallback_kem_key = Some(PqKeyCommitment::with_algorithm(
            label,
            PqKeyPurpose::SessionKem,
            PqKeyAlgorithm::HybridClassicKem,
            rotation_nonce,
            created_at_height,
            created_at_height,
            expires_at_height,
            &metadata,
        )?);
        let fallback_signature_key = Some(PqKeyCommitment::with_algorithm(
            label,
            PqKeyPurpose::OnlineAuth,
            PqKeyAlgorithm::HybridClassicSignature,
            rotation_nonce,
            created_at_height,
            created_at_height,
            expires_at_height,
            &metadata,
        )?);
        let route_hint_root = pq_route_hint_root(label, role.as_str(), rotation_nonce);
        let policy_root = pq_peer_policy_root(label, role.as_str(), &route_hint_root);
        let peer_id = pq_peer_id(label, role.as_str(), &kem_key.key_id, &ml_dsa_key.key_id);
        let peer = Self {
            peer_id,
            label: label.to_string(),
            role,
            kem_key,
            ml_dsa_key,
            slh_dsa_key,
            fallback_kem_key,
            fallback_signature_key,
            route_hint_root,
            policy_root,
            created_at_height,
            status: PQ_STATUS_ACTIVE.to_string(),
        };
        peer.validate()?;
        Ok(peer)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_session_peer",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "peer_id": self.peer_id,
            "label": self.label,
            "role": self.role.as_str(),
            "kem_key": self.kem_key.public_record(),
            "ml_dsa_key": self.ml_dsa_key.public_record(),
            "slh_dsa_key": self.slh_dsa_key.public_record(),
            "fallback_kem_key": self.fallback_kem_key.as_ref().map(PqKeyCommitment::public_record),
            "fallback_signature_key": self.fallback_signature_key.as_ref().map(PqKeyCommitment::public_record),
            "route_hint_root": self.route_hint_root,
            "policy_root": self.policy_root,
            "created_at_height": self.created_at_height,
            "status": self.status,
        })
    }

    pub fn peer_root(&self) -> String {
        pq_payload_root("PQ-SESSION-PEER", &self.public_record())
    }

    pub fn active_key_roots(&self) -> Vec<String> {
        let mut roots = vec![
            self.kem_key.key_root(),
            self.ml_dsa_key.key_root(),
            self.slh_dsa_key.key_root(),
        ];
        if let Some(key) = &self.fallback_kem_key {
            roots.push(key.key_root());
        }
        if let Some(key) = &self.fallback_signature_key {
            roots.push(key.key_root());
        }
        roots
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.peer_id, "pq peer id")?;
        ensure_non_empty(&self.label, "pq peer label")?;
        self.kem_key.validate()?;
        self.ml_dsa_key.validate()?;
        self.slh_dsa_key.validate()?;
        ensure_non_empty(&self.route_hint_root, "pq peer route hint root")?;
        ensure_non_empty(&self.policy_root, "pq peer policy root")?;
        Ok(self.peer_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKemCiphertext {
    pub ciphertext_id: String,
    pub encapsulated_to_key_id: String,
    pub ciphertext_commitment: String,
    pub shared_secret_commitment: String,
    pub aad_root: String,
    pub produced_at_height: u64,
    pub nonce: u64,
    pub scheme: String,
}

impl PqKemCiphertext {
    pub fn deterministic(
        recipient_key_id: &str,
        aad: &Value,
        produced_at_height: u64,
        nonce: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(recipient_key_id, "kem ciphertext recipient key id")?;
        let aad_root = pq_payload_root("PQ-KEM-AAD", aad);
        let ciphertext_commitment =
            pq_kem_ciphertext_commitment(recipient_key_id, &aad_root, produced_at_height, nonce);
        let shared_secret_commitment =
            pq_shared_secret_commitment(recipient_key_id, &ciphertext_commitment, nonce);
        let ciphertext_id = pq_kem_ciphertext_id(
            recipient_key_id,
            &ciphertext_commitment,
            &shared_secret_commitment,
            nonce,
        );
        let ciphertext = Self {
            ciphertext_id,
            encapsulated_to_key_id: recipient_key_id.to_string(),
            ciphertext_commitment,
            shared_secret_commitment,
            aad_root,
            produced_at_height,
            nonce,
            scheme: PQ_ML_KEM_SCHEME.to_string(),
        };
        ciphertext.validate()?;
        Ok(ciphertext)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_kem_ciphertext",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "ciphertext_id": self.ciphertext_id,
            "encapsulated_to_key_id": self.encapsulated_to_key_id,
            "ciphertext_commitment": self.ciphertext_commitment,
            "shared_secret_commitment": self.shared_secret_commitment,
            "aad_root": self.aad_root,
            "produced_at_height": self.produced_at_height,
            "nonce": self.nonce,
            "scheme": self.scheme,
        })
    }

    pub fn ciphertext_root(&self) -> String {
        pq_payload_root("PQ-KEM-CIPHERTEXT", &self.public_record())
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.ciphertext_id, "kem ciphertext id")?;
        ensure_non_empty(
            &self.encapsulated_to_key_id,
            "kem ciphertext encapsulated key id",
        )?;
        ensure_non_empty(&self.ciphertext_commitment, "kem ciphertext commitment")?;
        ensure_non_empty(
            &self.shared_secret_commitment,
            "kem shared secret commitment",
        )?;
        ensure_non_empty(&self.aad_root, "kem ciphertext aad root")?;
        if self.scheme != PQ_ML_KEM_SCHEME {
            return Err("kem ciphertext scheme must be ML-KEM-768".to_string());
        }
        Ok(self.ciphertext_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthTranscript {
    pub transcript_id: String,
    pub kind: PqAuthTranscriptKind,
    pub signer_label: String,
    pub signer_key_id: String,
    pub subject_root: String,
    pub context_root: String,
    pub challenge_root: String,
    pub signature_commitment: String,
    pub recovery_signature_commitment: Option<String>,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub scheme: String,
    pub status: String,
}

impl PqAuthTranscript {
    pub fn deterministic(
        kind: PqAuthTranscriptKind,
        signer_label: &str,
        signer_key_id: &str,
        subject: &Value,
        context: &Value,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(signer_label, "auth transcript signer label")?;
        ensure_non_empty(signer_key_id, "auth transcript signer key id")?;
        if expires_at_height <= signed_at_height {
            return Err("auth transcript expiry must be after signing height".to_string());
        }
        let subject_root = pq_payload_root("PQ-AUTH-SUBJECT", subject);
        let context_root = pq_payload_root("PQ-AUTH-CONTEXT", context);
        let challenge_root = pq_auth_challenge_root(
            kind.as_str(),
            signer_label,
            signer_key_id,
            &subject_root,
            &context_root,
            signed_at_height,
        );
        let signature_commitment = pq_signature_commitment(
            kind.primary_scheme(),
            signer_label,
            signer_key_id,
            &challenge_root,
            signed_at_height,
        );
        let scheme = kind.primary_scheme().to_string();
        let recovery_signature_commitment = if matches!(
            &kind,
            PqAuthTranscriptKind::DualSignature
                | PqAuthTranscriptKind::SlhDsaRecovery
                | PqAuthTranscriptKind::CompromiseWitness
        ) {
            Some(pq_signature_commitment(
                PQ_SLH_DSA_SCHEME,
                signer_label,
                signer_key_id,
                &challenge_root,
                signed_at_height + 1,
            ))
        } else {
            None
        };
        let transcript_id = pq_auth_transcript_id(
            kind.as_str(),
            signer_label,
            signer_key_id,
            &challenge_root,
            &signature_commitment,
        );
        let transcript = Self {
            transcript_id,
            kind,
            signer_label: signer_label.to_string(),
            signer_key_id: signer_key_id.to_string(),
            subject_root,
            context_root,
            challenge_root,
            signature_commitment,
            recovery_signature_commitment,
            signed_at_height,
            expires_at_height,
            scheme,
            status: PQ_STATUS_ACTIVE.to_string(),
        };
        transcript.validate()?;
        Ok(transcript)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "pq_auth_transcript",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "transcript_id": self.transcript_id,
            "transcript_kind": self.kind.as_str(),
            "signer_label": self.signer_label,
            "signer_key_id": self.signer_key_id,
            "subject_root": self.subject_root,
            "context_root": self.context_root,
            "challenge_root": self.challenge_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "scheme": self.scheme,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("pq auth transcript object")
            .insert(
                "signature_commitment".to_string(),
                Value::String(self.signature_commitment.clone()),
            );
        if let Some(commitment) = &self.recovery_signature_commitment {
            record
                .as_object_mut()
                .expect("pq auth transcript object")
                .insert(
                    "recovery_signature_commitment".to_string(),
                    Value::String(commitment.clone()),
                );
        }
        record
            .as_object_mut()
            .expect("pq auth transcript object")
            .insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn transcript_root(&self) -> String {
        pq_payload_root("PQ-AUTH-TRANSCRIPT", &self.public_record())
    }

    pub fn is_valid_at(&self, height: u64) -> bool {
        self.status == PQ_STATUS_ACTIVE
            && self.signed_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.transcript_id, "auth transcript id")?;
        ensure_non_empty(&self.signer_label, "auth transcript signer label")?;
        ensure_non_empty(&self.signer_key_id, "auth transcript signer key id")?;
        ensure_non_empty(&self.subject_root, "auth transcript subject root")?;
        ensure_non_empty(&self.context_root, "auth transcript context root")?;
        ensure_non_empty(&self.challenge_root, "auth transcript challenge root")?;
        ensure_non_empty(
            &self.signature_commitment,
            "auth transcript signature commitment",
        )?;
        if self.expires_at_height <= self.signed_at_height {
            return Err("auth transcript expiry must be after signing height".to_string());
        }
        Ok(self.transcript_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqHandshakePacket {
    pub packet_id: String,
    pub session_id: String,
    pub sender_peer_id: String,
    pub receiver_peer_id: String,
    pub sender_role: PqHandshakeRole,
    pub receiver_role: PqHandshakeRole,
    pub stage: PqHandshakeStage,
    pub kem_ciphertext: Option<PqKemCiphertext>,
    pub transcript_root: String,
    pub replay_nonce: String,
    pub previous_packet_root: String,
    pub produced_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqHandshakePacket {
    pub fn offer(
        session_id: &str,
        sender: &PqSessionPeer,
        receiver: &PqSessionPeer,
        produced_at_height: u64,
        nonce: u64,
    ) -> PqSessionResult<Self> {
        Self::build(
            session_id,
            sender,
            receiver,
            PqHandshakeStage::Offered,
            None,
            "",
            produced_at_height,
            produced_at_height + PQ_DEFAULT_HANDSHAKE_TTL_BLOCKS,
            nonce,
        )
    }

    pub fn encapsulated(
        session_id: &str,
        sender: &PqSessionPeer,
        receiver: &PqSessionPeer,
        transcript_root: &str,
        previous_packet_root: &str,
        produced_at_height: u64,
        nonce: u64,
    ) -> PqSessionResult<Self> {
        let aad = json!({
            "session_id": session_id,
            "sender_peer_id": sender.peer_id,
            "receiver_peer_id": receiver.peer_id,
            "transcript_root": transcript_root,
            "previous_packet_root": previous_packet_root,
        });
        let kem_ciphertext = PqKemCiphertext::deterministic(
            &receiver.kem_key.key_id,
            &aad,
            produced_at_height,
            nonce,
        )?;
        Self::build(
            session_id,
            sender,
            receiver,
            PqHandshakeStage::Encapsulated,
            Some(kem_ciphertext),
            previous_packet_root,
            produced_at_height,
            produced_at_height + PQ_DEFAULT_HANDSHAKE_TTL_BLOCKS,
            nonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build(
        session_id: &str,
        sender: &PqSessionPeer,
        receiver: &PqSessionPeer,
        stage: PqHandshakeStage,
        kem_ciphertext: Option<PqKemCiphertext>,
        previous_packet_root: &str,
        produced_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(session_id, "handshake packet session id")?;
        if expires_at_height <= produced_at_height {
            return Err("handshake packet expiry must be after production".to_string());
        }
        let replay_nonce = pq_replay_nonce(
            "handshake_packet",
            session_id,
            &sender.peer_id,
            &receiver.peer_id,
            nonce,
        );
        let transcript_root = pq_handshake_transcript_root(
            session_id,
            &sender.peer_id,
            &receiver.peer_id,
            stage.as_str(),
            kem_ciphertext.as_ref(),
            previous_packet_root,
            produced_at_height,
            &replay_nonce,
        );
        let packet_id = pq_handshake_packet_id(
            session_id,
            &sender.peer_id,
            &receiver.peer_id,
            stage.as_str(),
            &transcript_root,
        );
        let packet = Self {
            packet_id,
            session_id: session_id.to_string(),
            sender_peer_id: sender.peer_id.clone(),
            receiver_peer_id: receiver.peer_id.clone(),
            sender_role: sender.role.clone(),
            receiver_role: receiver.role.clone(),
            stage,
            kem_ciphertext,
            transcript_root,
            replay_nonce,
            previous_packet_root: previous_packet_root.to_string(),
            produced_at_height,
            expires_at_height,
            status: PQ_STATUS_ACTIVE.to_string(),
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_handshake_packet",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "packet_id": self.packet_id,
            "session_id": self.session_id,
            "sender_peer_id": self.sender_peer_id,
            "receiver_peer_id": self.receiver_peer_id,
            "sender_role": self.sender_role.as_str(),
            "receiver_role": self.receiver_role.as_str(),
            "stage": self.stage.as_str(),
            "kem_ciphertext": self.kem_ciphertext.as_ref().map(PqKemCiphertext::public_record),
            "transcript_root": self.transcript_root,
            "replay_nonce": self.replay_nonce,
            "previous_packet_root": self.previous_packet_root,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn packet_root(&self) -> String {
        pq_payload_root("PQ-HANDSHAKE-PACKET", &self.public_record())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == PQ_STATUS_ACTIVE
            && self.produced_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.packet_id, "handshake packet id")?;
        ensure_non_empty(&self.session_id, "handshake packet session id")?;
        ensure_non_empty(&self.sender_peer_id, "handshake packet sender peer id")?;
        ensure_non_empty(&self.receiver_peer_id, "handshake packet receiver peer id")?;
        ensure_non_empty(&self.transcript_root, "handshake packet transcript root")?;
        ensure_non_empty(&self.replay_nonce, "handshake packet replay nonce")?;
        if self.expires_at_height <= self.produced_at_height {
            return Err("handshake packet expiry must be after production".to_string());
        }
        if self.stage == PqHandshakeStage::Encapsulated && self.kem_ciphertext.is_none() {
            return Err("encapsulated handshake packet requires kem ciphertext".to_string());
        }
        if let Some(ciphertext) = &self.kem_ciphertext {
            ciphertext.validate()?;
        }
        Ok(self.packet_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSessionHandshake {
    pub session_id: String,
    pub initiator_peer_id: String,
    pub responder_peer_id: String,
    pub session_purpose: String,
    pub suite: String,
    pub stage: PqHandshakeStage,
    pub offer_packet: PqHandshakePacket,
    pub encapsulation_packet: PqHandshakePacket,
    pub initiator_auth_transcript: PqAuthTranscript,
    pub responder_auth_transcript: PqAuthTranscript,
    pub session_secret_commitment: String,
    pub transcript_root: String,
    pub replay_domain_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub confirmed_at_height: Option<u64>,
    pub status: String,
}

impl PqSessionHandshake {
    pub fn deterministic(
        initiator: &PqSessionPeer,
        responder: &PqSessionPeer,
        session_purpose: &str,
        created_at_height: u64,
        nonce: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(session_purpose, "session purpose")?;
        let session_id = pq_session_id(
            &initiator.peer_id,
            &responder.peer_id,
            session_purpose,
            created_at_height,
            nonce,
        );
        let offer_packet =
            PqHandshakePacket::offer(&session_id, initiator, responder, created_at_height, nonce)?;
        let offer_root = offer_packet.packet_root();
        let auth_context = json!({
            "session_id": session_id,
            "session_purpose": session_purpose,
            "initiator_peer_id": initiator.peer_id,
            "responder_peer_id": responder.peer_id,
            "offer_packet_root": offer_root,
        });
        let initiator_auth_transcript = PqAuthTranscript::deterministic(
            PqAuthTranscriptKind::DualSignature,
            &initiator.label,
            &initiator.ml_dsa_key.key_id,
            &offer_packet.public_record(),
            &auth_context,
            created_at_height,
            created_at_height + PQ_DEFAULT_SESSION_TTL_BLOCKS,
        )?;
        let encapsulation_packet = PqHandshakePacket::encapsulated(
            &session_id,
            responder,
            initiator,
            &initiator_auth_transcript.transcript_root(),
            &offer_root,
            created_at_height + 1,
            nonce + 1,
        )?;
        let responder_auth_transcript = PqAuthTranscript::deterministic(
            PqAuthTranscriptKind::DualSignature,
            &responder.label,
            &responder.ml_dsa_key.key_id,
            &encapsulation_packet.public_record(),
            &auth_context,
            created_at_height + 1,
            created_at_height + PQ_DEFAULT_SESSION_TTL_BLOCKS,
        )?;
        let transcript_root = pq_handshake_root_from_parts(
            &offer_packet.packet_root(),
            &encapsulation_packet.packet_root(),
            &initiator_auth_transcript.transcript_root(),
            &responder_auth_transcript.transcript_root(),
        );
        let session_secret_commitment = pq_session_secret_commitment(
            &session_id,
            &transcript_root,
            &encapsulation_packet
                .kem_ciphertext
                .as_ref()
                .map(|ciphertext| ciphertext.shared_secret_commitment.clone())
                .unwrap_or_default(),
        );
        let replay_domain_root =
            pq_replay_domain_root(&session_id, &initiator.peer_id, &responder.peer_id);
        let handshake = Self {
            session_id,
            initiator_peer_id: initiator.peer_id.clone(),
            responder_peer_id: responder.peer_id.clone(),
            session_purpose: session_purpose.to_string(),
            suite: PQ_HANDSHAKE_SUITE.to_string(),
            stage: PqHandshakeStage::Confirmed,
            offer_packet,
            encapsulation_packet,
            initiator_auth_transcript,
            responder_auth_transcript,
            session_secret_commitment,
            transcript_root,
            replay_domain_root,
            created_at_height,
            expires_at_height: created_at_height + PQ_DEFAULT_SESSION_TTL_BLOCKS,
            confirmed_at_height: Some(created_at_height + 2),
            status: PQ_STATUS_ACTIVE.to_string(),
        };
        handshake.validate()?;
        Ok(handshake)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_session_handshake",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "session_id": self.session_id,
            "initiator_peer_id": self.initiator_peer_id,
            "responder_peer_id": self.responder_peer_id,
            "session_purpose": self.session_purpose,
            "suite": self.suite,
            "stage": self.stage.as_str(),
            "offer_packet": self.offer_packet.public_record(),
            "encapsulation_packet": self.encapsulation_packet.public_record(),
            "initiator_auth_transcript": self.initiator_auth_transcript.public_record(),
            "responder_auth_transcript": self.responder_auth_transcript.public_record(),
            "session_secret_commitment": self.session_secret_commitment,
            "transcript_root": self.transcript_root,
            "replay_domain_root": self.replay_domain_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "confirmed_at_height": self.confirmed_at_height,
            "status": self.status,
        })
    }

    pub fn handshake_root(&self) -> String {
        pq_payload_root("PQ-SESSION-HANDSHAKE", &self.public_record())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == PQ_STATUS_ACTIVE
            && self.created_at_height <= height
            && height < self.expires_at_height
            && self.stage == PqHandshakeStage::Confirmed
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.session_id, "session handshake id")?;
        ensure_non_empty(&self.initiator_peer_id, "session initiator peer id")?;
        ensure_non_empty(&self.responder_peer_id, "session responder peer id")?;
        ensure_non_empty(&self.session_purpose, "session purpose")?;
        ensure_non_empty(&self.suite, "session suite")?;
        self.offer_packet.validate()?;
        self.encapsulation_packet.validate()?;
        self.initiator_auth_transcript.validate()?;
        self.responder_auth_transcript.validate()?;
        ensure_non_empty(&self.session_secret_commitment, "session secret commitment")?;
        ensure_non_empty(&self.transcript_root, "session transcript root")?;
        ensure_non_empty(&self.replay_domain_root, "session replay domain root")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("session expiry must be after creation".to_string());
        }
        Ok(self.handshake_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRotationWindow {
    pub rotation_id: String,
    pub owner_label: String,
    pub purpose: PqKeyPurpose,
    pub previous_key_id: String,
    pub next_key_id: String,
    pub previous_key_root: String,
    pub next_key_root: String,
    pub announcement_height: u64,
    pub dual_publish_height: u64,
    pub dual_sign_start_height: u64,
    pub activation_height: u64,
    pub retire_previous_height: u64,
    pub expires_at_height: u64,
    pub stage: PqRotationStage,
    pub witness_transcript_root: String,
    pub policy_root: String,
    pub status: String,
}

impl PqRotationWindow {
    pub fn deterministic(
        owner_label: &str,
        purpose: PqKeyPurpose,
        previous_key: &PqKeyCommitment,
        announcement_height: u64,
        rotation_nonce: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(owner_label, "rotation owner_label")?;
        let metadata = json!({
            "owner_label": owner_label,
            "purpose": purpose.as_str(),
            "rotation_nonce": rotation_nonce,
            "previous_key_id": previous_key.key_id,
        });
        let dual_publish_height = announcement_height + PQ_DEFAULT_ROTATION_NOTICE_BLOCKS;
        let dual_sign_start_height = dual_publish_height + PQ_DEFAULT_ROTATION_OVERLAP_BLOCKS / 2;
        let activation_height = dual_publish_height + PQ_DEFAULT_ROTATION_OVERLAP_BLOCKS;
        let retire_previous_height = activation_height + PQ_DEFAULT_ROTATION_OVERLAP_BLOCKS;
        let expires_at_height = retire_previous_height + PQ_DEFAULT_ROTATION_NOTICE_BLOCKS;
        let next_key = PqKeyCommitment::deterministic(
            owner_label,
            purpose.clone(),
            rotation_nonce,
            announcement_height,
            activation_height,
            activation_height + PQ_DEFAULT_ROTATION_INTERVAL_BLOCKS * 2,
            &metadata,
        )?;
        let witness_subject = json!({
            "previous_key": previous_key.public_record(),
            "next_key": next_key.public_record(),
            "activation_height": activation_height,
        });
        let witness_transcript = PqAuthTranscript::deterministic(
            PqAuthTranscriptKind::RotationWitness,
            owner_label,
            &previous_key.key_id,
            &witness_subject,
            &metadata,
            announcement_height,
            expires_at_height,
        )?;
        let previous_key_root = previous_key.key_root();
        let next_key_root = next_key.key_root();
        let witness_transcript_root = witness_transcript.transcript_root();
        let policy_root = pq_rotation_policy_root(
            owner_label,
            purpose.as_str(),
            announcement_height,
            activation_height,
            retire_previous_height,
        );
        let rotation_id = pq_rotation_id(
            owner_label,
            purpose.as_str(),
            &previous_key.key_id,
            &next_key.key_id,
            activation_height,
        );
        let window = Self {
            rotation_id,
            owner_label: owner_label.to_string(),
            purpose,
            previous_key_id: previous_key.key_id.clone(),
            next_key_id: next_key.key_id,
            previous_key_root,
            next_key_root,
            announcement_height,
            dual_publish_height,
            dual_sign_start_height,
            activation_height,
            retire_previous_height,
            expires_at_height,
            stage: PqRotationStage::Announced,
            witness_transcript_root,
            policy_root,
            status: PQ_STATUS_PENDING.to_string(),
        };
        window.validate()?;
        Ok(window)
    }

    pub fn stage_at(&self, height: u64) -> PqRotationStage {
        if height < self.dual_publish_height {
            PqRotationStage::Announced
        } else if height < self.dual_sign_start_height {
            PqRotationStage::DualPublishing
        } else if height < self.activation_height {
            PqRotationStage::DualSigning
        } else if height < self.retire_previous_height {
            PqRotationStage::Active
        } else if height < self.expires_at_height {
            PqRotationStage::RetiringPrevious
        } else {
            PqRotationStage::Complete
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_rotation_window",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "rotation_id": self.rotation_id,
            "owner_label": self.owner_label,
            "purpose": self.purpose.as_str(),
            "previous_key_id": self.previous_key_id,
            "next_key_id": self.next_key_id,
            "previous_key_root": self.previous_key_root,
            "next_key_root": self.next_key_root,
            "announcement_height": self.announcement_height,
            "dual_publish_height": self.dual_publish_height,
            "dual_sign_start_height": self.dual_sign_start_height,
            "activation_height": self.activation_height,
            "retire_previous_height": self.retire_previous_height,
            "expires_at_height": self.expires_at_height,
            "stage": self.stage.as_str(),
            "derived_stage_now_hint": self.stage.as_str(),
            "witness_transcript_root": self.witness_transcript_root,
            "policy_root": self.policy_root,
            "status": self.status,
        })
    }

    pub fn rotation_root(&self) -> String {
        pq_payload_root("PQ-ROTATION-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.rotation_id, "rotation id")?;
        ensure_non_empty(&self.owner_label, "rotation owner label")?;
        ensure_non_empty(&self.previous_key_id, "rotation previous key id")?;
        ensure_non_empty(&self.next_key_id, "rotation next key id")?;
        ensure_non_empty(&self.previous_key_root, "rotation previous key root")?;
        ensure_non_empty(&self.next_key_root, "rotation next key root")?;
        ensure_non_empty(
            &self.witness_transcript_root,
            "rotation witness transcript root",
        )?;
        ensure_non_empty(&self.policy_root, "rotation policy root")?;
        if !(self.announcement_height <= self.dual_publish_height
            && self.dual_publish_height <= self.dual_sign_start_height
            && self.dual_sign_start_height <= self.activation_height
            && self.activation_height <= self.retire_previous_height
            && self.retire_previous_height <= self.expires_at_height)
        {
            return Err("rotation heights must be monotonic".to_string());
        }
        Ok(self.rotation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqHybridFallbackPolicy {
    pub policy_id: String,
    pub mode: PqHybridFallbackMode,
    pub require_ml_kem: bool,
    pub require_ml_dsa: bool,
    pub require_slh_dsa_for_recovery: bool,
    pub permit_classic_fallback_until_height: u64,
    pub fallback_activation_delay_blocks: u64,
    pub fallback_max_ttl_blocks: u64,
    pub emergency_contact_root: String,
    pub audit_log_root: String,
    pub created_at_height: u64,
    pub status: String,
}

impl PqHybridFallbackPolicy {
    pub fn deterministic(operator_label: &str, created_at_height: u64) -> PqSessionResult<Self> {
        ensure_non_empty(operator_label, "fallback policy operator label")?;
        let mode = PqHybridFallbackMode::RequireBoth;
        let emergency_contact_root =
            pq_string_commitment("fallback_emergency_contact", operator_label);
        let audit_log_root = pq_payload_root(
            "PQ-FALLBACK-AUDIT-LOG",
            &json!({
                "operator_label": operator_label,
                "created_at_height": created_at_height,
                "policy": "classic is only a bounded availability bridge",
            }),
        );
        let policy_id = pq_fallback_policy_id(
            operator_label,
            mode.as_str(),
            created_at_height,
            &emergency_contact_root,
        );
        let policy = Self {
            policy_id,
            mode,
            require_ml_kem: true,
            require_ml_dsa: true,
            require_slh_dsa_for_recovery: true,
            permit_classic_fallback_until_height: created_at_height + 30_000,
            fallback_activation_delay_blocks: 2,
            fallback_max_ttl_blocks: 8,
            emergency_contact_root,
            audit_log_root,
            created_at_height,
            status: PQ_STATUS_ACTIVE.to_string(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_hybrid_fallback_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "mode": self.mode.as_str(),
            "require_ml_kem": self.require_ml_kem,
            "require_ml_dsa": self.require_ml_dsa,
            "require_slh_dsa_for_recovery": self.require_slh_dsa_for_recovery,
            "permit_classic_fallback_until_height": self.permit_classic_fallback_until_height,
            "fallback_activation_delay_blocks": self.fallback_activation_delay_blocks,
            "fallback_max_ttl_blocks": self.fallback_max_ttl_blocks,
            "emergency_contact_root": self.emergency_contact_root,
            "audit_log_root": self.audit_log_root,
            "created_at_height": self.created_at_height,
            "status": self.status,
        })
    }

    pub fn policy_root(&self) -> String {
        pq_payload_root("PQ-HYBRID-FALLBACK-POLICY", &self.public_record())
    }

    pub fn permits_handshake(&self, has_pq: bool, has_classic: bool, height: u64) -> bool {
        match self.mode {
            PqHybridFallbackMode::Disabled => has_pq && !has_classic,
            PqHybridFallbackMode::AuditOnly => has_pq,
            PqHybridFallbackMode::RequirePqPreferClassic => has_pq,
            PqHybridFallbackMode::RequireClassicPreferPq => has_pq || has_classic,
            PqHybridFallbackMode::RequireBoth => has_pq && has_classic,
            PqHybridFallbackMode::EmergencyClassicOnly => {
                has_classic && height <= self.permit_classic_fallback_until_height
            }
        }
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.policy_id, "fallback policy id")?;
        ensure_non_empty(
            &self.emergency_contact_root,
            "fallback policy emergency contact root",
        )?;
        ensure_non_empty(&self.audit_log_root, "fallback policy audit log root")?;
        if self.fallback_max_ttl_blocks > PQ_DEFAULT_SESSION_TTL_BLOCKS {
            return Err("fallback max ttl exceeds pq session ttl".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReplayNonceRecord {
    pub nonce_id: String,
    pub domain: String,
    pub session_id: String,
    pub peer_id: String,
    pub nonce_commitment: String,
    pub transcript_root: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub status: PqReplayStatus,
}

impl PqReplayNonceRecord {
    pub fn deterministic(
        domain: &str,
        session_id: &str,
        peer_id: &str,
        transcript_root: &str,
        first_seen_height: u64,
        nonce: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(domain, "replay nonce domain")?;
        ensure_non_empty(session_id, "replay nonce session id")?;
        ensure_non_empty(peer_id, "replay nonce peer id")?;
        ensure_non_empty(transcript_root, "replay nonce transcript root")?;
        let nonce_commitment = pq_replay_nonce(domain, session_id, peer_id, transcript_root, nonce);
        let nonce_id = pq_replay_nonce_id(domain, session_id, peer_id, &nonce_commitment);
        let record = Self {
            nonce_id,
            domain: domain.to_string(),
            session_id: session_id.to_string(),
            peer_id: peer_id.to_string(),
            nonce_commitment,
            transcript_root: transcript_root.to_string(),
            first_seen_height,
            expires_at_height: first_seen_height + PQ_DEFAULT_REPLAY_WINDOW_BLOCKS,
            status: PqReplayStatus::Observed,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_replay_nonce",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "nonce_id": self.nonce_id,
            "domain": self.domain,
            "session_id": self.session_id,
            "peer_id": self.peer_id,
            "nonce_commitment": self.nonce_commitment,
            "transcript_root": self.transcript_root,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn nonce_root(&self) -> String {
        pq_payload_root("PQ-REPLAY-NONCE", &self.public_record())
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.nonce_id, "replay nonce id")?;
        ensure_non_empty(&self.domain, "replay nonce domain")?;
        ensure_non_empty(&self.session_id, "replay nonce session id")?;
        ensure_non_empty(&self.peer_id, "replay nonce peer id")?;
        ensure_non_empty(&self.nonce_commitment, "replay nonce commitment")?;
        ensure_non_empty(&self.transcript_root, "replay nonce transcript root")?;
        if self.expires_at_height <= self.first_seen_height {
            return Err("replay nonce expiry must be after first seen height".to_string());
        }
        Ok(self.nonce_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReplayProtectionState {
    pub replay_root_id: String,
    pub current_height: u64,
    pub window_blocks: u64,
    pub accepted_nonce_root: String,
    pub rejected_nonce_root: String,
    pub quarantine_nonce_root: String,
    pub nonces: Vec<PqReplayNonceRecord>,
}

impl PqReplayProtectionState {
    pub fn new(current_height: u64, window_blocks: u64) -> Self {
        let mut replay = Self {
            replay_root_id: String::new(),
            current_height,
            window_blocks,
            accepted_nonce_root: pq_empty_root("PQ-REPLAY-ACCEPTED"),
            rejected_nonce_root: pq_empty_root("PQ-REPLAY-REJECTED"),
            quarantine_nonce_root: pq_empty_root("PQ-REPLAY-QUARANTINE"),
            nonces: Vec::new(),
        };
        replay.recompute_roots();
        replay
    }

    pub fn observe(&mut self, mut record: PqReplayNonceRecord) -> PqSessionResult<String> {
        if record.first_seen_height + self.window_blocks < self.current_height {
            record.status = PqReplayStatus::RejectedExpired;
        } else if self
            .nonces
            .iter()
            .any(|existing| existing.nonce_commitment == record.nonce_commitment)
        {
            record.status = PqReplayStatus::RejectedDuplicate;
        } else {
            record.status = PqReplayStatus::Accepted;
        }
        self.nonces.push(record);
        self.nonces
            .sort_by(|left, right| left.nonce_id.cmp(&right.nonce_id));
        if self.nonces.len() > PQ_MAX_DEVNET_REPLAY_NONCES {
            self.nonces.remove(0);
        }
        self.recompute_roots();
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) -> PqSessionResult<String> {
        self.current_height = height;
        for nonce in &mut self.nonces {
            if nonce.status == PqReplayStatus::Accepted && nonce.is_expired_at(height) {
                nonce.status = PqReplayStatus::RejectedExpired;
            }
        }
        self.recompute_roots();
        self.validate()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_replay_protection_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "replay_root_id": self.replay_root_id,
            "current_height": self.current_height,
            "window_blocks": self.window_blocks,
            "accepted_nonce_root": self.accepted_nonce_root,
            "rejected_nonce_root": self.rejected_nonce_root,
            "quarantine_nonce_root": self.quarantine_nonce_root,
            "nonces": self.nonces.iter().map(PqReplayNonceRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_payload_root("PQ-REPLAY-PROTECTION-STATE", &self.public_record())
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        if self.window_blocks == 0 {
            return Err("replay window blocks cannot be zero".to_string());
        }
        ensure_non_empty(&self.replay_root_id, "replay root id")?;
        for nonce in &self.nonces {
            nonce.validate()?;
        }
        Ok(self.state_root())
    }

    fn recompute_roots(&mut self) {
        let accepted = self
            .nonces
            .iter()
            .filter(|nonce| nonce.status == PqReplayStatus::Accepted)
            .map(PqReplayNonceRecord::public_record)
            .collect::<Vec<_>>();
        let rejected = self
            .nonces
            .iter()
            .filter(|nonce| {
                matches!(
                    nonce.status,
                    PqReplayStatus::RejectedDuplicate
                        | PqReplayStatus::RejectedExpired
                        | PqReplayStatus::RejectedDomainMismatch
                )
            })
            .map(PqReplayNonceRecord::public_record)
            .collect::<Vec<_>>();
        let quarantined = self
            .nonces
            .iter()
            .filter(|nonce| nonce.status == PqReplayStatus::Quarantined)
            .map(PqReplayNonceRecord::public_record)
            .collect::<Vec<_>>();
        self.accepted_nonce_root = merkle_root("PQ-REPLAY-ACCEPTED", &accepted);
        self.rejected_nonce_root = merkle_root("PQ-REPLAY-REJECTED", &rejected);
        self.quarantine_nonce_root = merkle_root("PQ-REPLAY-QUARANTINE", &quarantined);
        self.replay_root_id = domain_hash(
            "PQ-REPLAY-ROOT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.current_height as i128),
                HashPart::Str(&self.accepted_nonce_root),
                HashPart::Str(&self.rejected_nonce_root),
                HashPart::Str(&self.quarantine_nonce_root),
            ],
            32,
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMempoolSessionGrant {
    pub grant_id: String,
    pub session_id: String,
    pub grantee_peer_id: String,
    pub sequencer_peer_id: String,
    pub scope: PqMempoolGrantScope,
    pub encrypted_payload_root: String,
    pub kem_ciphertext: PqKemCiphertext,
    pub lane_commitment: String,
    pub fee_commitment_root: String,
    pub replay_nonce: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub auth_transcript_root: String,
    pub status: String,
}

impl PqMempoolSessionGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        session_id: &str,
        grantee: &PqSessionPeer,
        sequencer: &PqSessionPeer,
        scope: PqMempoolGrantScope,
        encrypted_payload: &Value,
        lane_label: &str,
        issued_at_height: u64,
        nonce: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(session_id, "mempool grant session id")?;
        ensure_non_empty(lane_label, "mempool grant lane label")?;
        let encrypted_payload_root = pq_payload_root("PQ-MEMPOOL-GRANT-PAYLOAD", encrypted_payload);
        let lane_commitment = pq_string_commitment("mempool_lane", lane_label);
        let fee_commitment_root = pq_payload_root(
            "PQ-MEMPOOL-GRANT-FEE",
            &json!({
                "lane": lane_label,
                "scope": scope.as_str(),
                "low_fee_policy": "fee_floor_hidden_commitment",
            }),
        );
        let aad = json!({
            "session_id": session_id,
            "grantee_peer_id": grantee.peer_id,
            "sequencer_peer_id": sequencer.peer_id,
            "scope": scope.as_str(),
            "encrypted_payload_root": encrypted_payload_root,
            "lane_commitment": lane_commitment,
            "fee_commitment_root": fee_commitment_root,
        });
        let kem_ciphertext = PqKemCiphertext::deterministic(
            &sequencer.kem_key.key_id,
            &aad,
            issued_at_height,
            nonce,
        )?;
        let replay_nonce = pq_replay_nonce(
            "mempool_grant",
            session_id,
            &grantee.peer_id,
            &sequencer.peer_id,
            nonce,
        );
        let subject = json!({
            "grant_scope": scope.as_str(),
            "kem_ciphertext": kem_ciphertext.public_record(),
            "lane_commitment": lane_commitment,
            "fee_commitment_root": fee_commitment_root,
        });
        let auth = PqAuthTranscript::deterministic(
            PqAuthTranscriptKind::MlDsaOnline,
            &sequencer.label,
            &sequencer.ml_dsa_key.key_id,
            &subject,
            &aad,
            issued_at_height,
            issued_at_height + PQ_DEFAULT_MEMPOOL_GRANT_TTL_BLOCKS,
        )?;
        let auth_transcript_root = auth.transcript_root();
        let grant_id = pq_mempool_grant_id(
            session_id,
            &grantee.peer_id,
            &sequencer.peer_id,
            scope.as_str(),
            &replay_nonce,
        );
        let grant = Self {
            grant_id,
            session_id: session_id.to_string(),
            grantee_peer_id: grantee.peer_id.clone(),
            sequencer_peer_id: sequencer.peer_id.clone(),
            scope,
            encrypted_payload_root,
            kem_ciphertext,
            lane_commitment,
            fee_commitment_root,
            replay_nonce,
            issued_at_height,
            expires_at_height: issued_at_height + PQ_DEFAULT_MEMPOOL_GRANT_TTL_BLOCKS,
            auth_transcript_root,
            status: PQ_STATUS_ACTIVE.to_string(),
        };
        grant.validate()?;
        Ok(grant)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mempool_session_grant",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "grant_id": self.grant_id,
            "session_id": self.session_id,
            "grantee_peer_id": self.grantee_peer_id,
            "sequencer_peer_id": self.sequencer_peer_id,
            "scope": self.scope.as_str(),
            "encrypted_payload_root": self.encrypted_payload_root,
            "kem_ciphertext": self.kem_ciphertext.public_record(),
            "lane_commitment": self.lane_commitment,
            "fee_commitment_root": self.fee_commitment_root,
            "replay_nonce": self.replay_nonce,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "auth_transcript_root": self.auth_transcript_root,
            "status": self.status,
        })
    }

    pub fn grant_root(&self) -> String {
        pq_payload_root("PQ-MEMPOOL-SESSION-GRANT", &self.public_record())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == PQ_STATUS_ACTIVE
            && self.issued_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.grant_id, "mempool grant id")?;
        ensure_non_empty(&self.session_id, "mempool grant session id")?;
        ensure_non_empty(&self.grantee_peer_id, "mempool grant grantee peer id")?;
        ensure_non_empty(&self.sequencer_peer_id, "mempool grant sequencer peer id")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "mempool grant encrypted payload root",
        )?;
        self.kem_ciphertext.validate()?;
        ensure_non_empty(&self.lane_commitment, "mempool grant lane commitment")?;
        ensure_non_empty(
            &self.fee_commitment_root,
            "mempool grant fee commitment root",
        )?;
        ensure_non_empty(&self.replay_nonce, "mempool grant replay nonce")?;
        ensure_non_empty(
            &self.auth_transcript_root,
            "mempool grant auth transcript root",
        )?;
        if self.expires_at_height <= self.issued_at_height {
            return Err("mempool grant expiry must be after issue height".to_string());
        }
        Ok(self.grant_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOperatorAttestation {
    pub attestation_id: String,
    pub operator_label: String,
    pub kind: PqAttestationKind,
    pub subject_root: String,
    pub session_root: String,
    pub key_root: String,
    pub replay_root: String,
    pub mempool_grant_root: String,
    pub risk_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub auth_transcript: PqAuthTranscript,
    pub status: String,
}

impl PqOperatorAttestation {
    pub fn deterministic(
        operator_label: &str,
        kind: PqAttestationKind,
        operator_peer: &PqSessionPeer,
        subject: &Value,
        roots: &PqOperatorAttestationRoots,
        signed_at_height: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(operator_label, "operator attestation label")?;
        let subject_root = pq_payload_root("PQ-OPERATOR-ATTESTATION-SUBJECT", subject);
        let context = json!({
            "kind": kind.as_str(),
            "session_root": roots.session_root,
            "key_root": roots.key_root,
            "replay_root": roots.replay_root,
            "mempool_grant_root": roots.mempool_grant_root,
            "risk_root": roots.risk_root,
        });
        let auth_transcript = PqAuthTranscript::deterministic(
            PqAuthTranscriptKind::OperatorAttestation,
            operator_label,
            &operator_peer.ml_dsa_key.key_id,
            subject,
            &context,
            signed_at_height,
            signed_at_height + PQ_DEFAULT_ATTESTATION_TTL_BLOCKS,
        )?;
        let attestation_id = pq_operator_attestation_id(
            operator_label,
            kind.as_str(),
            &subject_root,
            signed_at_height,
        );
        let attestation = Self {
            attestation_id,
            operator_label: operator_label.to_string(),
            kind,
            subject_root,
            session_root: roots.session_root.clone(),
            key_root: roots.key_root.clone(),
            replay_root: roots.replay_root.clone(),
            mempool_grant_root: roots.mempool_grant_root.clone(),
            risk_root: roots.risk_root.clone(),
            signed_at_height,
            expires_at_height: signed_at_height + PQ_DEFAULT_ATTESTATION_TTL_BLOCKS,
            auth_transcript,
            status: PQ_STATUS_ACTIVE.to_string(),
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_operator_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "operator_label": self.operator_label,
            "attestation_kind": self.kind.as_str(),
            "subject_root": self.subject_root,
            "session_root": self.session_root,
            "key_root": self.key_root,
            "replay_root": self.replay_root,
            "mempool_grant_root": self.mempool_grant_root,
            "risk_root": self.risk_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "auth_transcript": self.auth_transcript.public_record(),
            "status": self.status,
        })
    }

    pub fn attestation_root(&self) -> String {
        pq_payload_root("PQ-OPERATOR-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.attestation_id, "operator attestation id")?;
        ensure_non_empty(&self.operator_label, "operator attestation label")?;
        ensure_non_empty(&self.subject_root, "operator attestation subject root")?;
        ensure_non_empty(&self.session_root, "operator attestation session root")?;
        ensure_non_empty(&self.key_root, "operator attestation key root")?;
        ensure_non_empty(&self.replay_root, "operator attestation replay root")?;
        ensure_non_empty(
            &self.mempool_grant_root,
            "operator attestation mempool grant root",
        )?;
        ensure_non_empty(&self.risk_root, "operator attestation risk root")?;
        self.auth_transcript.validate()?;
        if self.expires_at_height <= self.signed_at_height {
            return Err("operator attestation expiry must be after signed height".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOperatorAttestationRoots {
    pub session_root: String,
    pub key_root: String,
    pub replay_root: String,
    pub mempool_grant_root: String,
    pub risk_root: String,
}

impl PqOperatorAttestationRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_operator_attestation_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "session_root": self.session_root,
            "key_root": self.key_root,
            "replay_root": self.replay_root,
            "mempool_grant_root": self.mempool_grant_root,
            "risk_root": self.risk_root,
        })
    }

    pub fn root(&self) -> String {
        pq_payload_root("PQ-OPERATOR-ATTESTATION-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCompromiseRecord {
    pub compromise_id: String,
    pub kind: PqCompromiseKind,
    pub affected_peer_id: String,
    pub affected_key_id: String,
    pub evidence_root: String,
    pub reporter_label: String,
    pub risk_level: PqRiskLevel,
    pub detected_at_height: u64,
    pub review_until_height: u64,
    pub witness_transcript_root: String,
    pub recommended_action: PqQuarantineAction,
    pub status: String,
}

impl PqCompromiseRecord {
    pub fn deterministic(
        kind: PqCompromiseKind,
        affected_peer: &PqSessionPeer,
        affected_key_id: &str,
        evidence: &Value,
        reporter_label: &str,
        risk_level: PqRiskLevel,
        detected_at_height: u64,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(affected_key_id, "compromise affected key id")?;
        ensure_non_empty(reporter_label, "compromise reporter label")?;
        let evidence_root = pq_payload_root("PQ-COMPROMISE-EVIDENCE", evidence);
        let witness_subject = json!({
            "kind": kind.as_str(),
            "affected_peer_id": affected_peer.peer_id,
            "affected_key_id": affected_key_id,
            "evidence_root": evidence_root,
            "risk_level": risk_level.as_str(),
        });
        let witness_transcript = PqAuthTranscript::deterministic(
            PqAuthTranscriptKind::CompromiseWitness,
            reporter_label,
            &affected_peer.slh_dsa_key.key_id,
            &witness_subject,
            evidence,
            detected_at_height,
            detected_at_height + PQ_DEFAULT_COMPROMISE_REVIEW_BLOCKS,
        )?;
        let recommended_action = if risk_level.freezes_sessions() {
            PqQuarantineAction::FreezePeer
        } else {
            PqQuarantineAction::Observe
        };
        let witness_transcript_root = witness_transcript.transcript_root();
        let compromise_id = pq_compromise_id(
            kind.as_str(),
            &affected_peer.peer_id,
            affected_key_id,
            &evidence_root,
            detected_at_height,
        );
        let record = Self {
            compromise_id,
            kind,
            affected_peer_id: affected_peer.peer_id.clone(),
            affected_key_id: affected_key_id.to_string(),
            evidence_root,
            reporter_label: reporter_label.to_string(),
            risk_level,
            detected_at_height,
            review_until_height: detected_at_height + PQ_DEFAULT_COMPROMISE_REVIEW_BLOCKS,
            witness_transcript_root,
            recommended_action,
            status: PQ_STATUS_PENDING.to_string(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_compromise_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "compromise_id": self.compromise_id,
            "compromise_kind": self.kind.as_str(),
            "affected_peer_id": self.affected_peer_id,
            "affected_key_id": self.affected_key_id,
            "evidence_root": self.evidence_root,
            "reporter_label": self.reporter_label,
            "risk_level": self.risk_level.as_str(),
            "detected_at_height": self.detected_at_height,
            "review_until_height": self.review_until_height,
            "witness_transcript_root": self.witness_transcript_root,
            "recommended_action": self.recommended_action.as_str(),
            "status": self.status,
        })
    }

    pub fn compromise_root(&self) -> String {
        pq_payload_root("PQ-COMPROMISE-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.compromise_id, "compromise id")?;
        ensure_non_empty(&self.affected_peer_id, "compromise affected peer id")?;
        ensure_non_empty(&self.affected_key_id, "compromise affected key id")?;
        ensure_non_empty(&self.evidence_root, "compromise evidence root")?;
        ensure_non_empty(&self.reporter_label, "compromise reporter label")?;
        ensure_non_empty(
            &self.witness_transcript_root,
            "compromise witness transcript root",
        )?;
        if self.review_until_height <= self.detected_at_height {
            return Err("compromise review window must be after detection".to_string());
        }
        Ok(self.compromise_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqQuarantineRecord {
    pub quarantine_id: String,
    pub compromise_id: String,
    pub affected_peer_id: String,
    pub action: PqQuarantineAction,
    pub reason_root: String,
    pub started_at_height: u64,
    pub expires_at_height: u64,
    pub release_condition_root: String,
    pub operator_attestation_root: String,
    pub status: String,
}

impl PqQuarantineRecord {
    pub fn from_compromise(
        compromise: &PqCompromiseRecord,
        reason: &Value,
        operator_attestation_root: &str,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(
            operator_attestation_root,
            "quarantine operator attestation root",
        )?;
        let reason_root = pq_payload_root("PQ-QUARANTINE-REASON", reason);
        let release_condition_root = pq_payload_root(
            "PQ-QUARANTINE-RELEASE-CONDITION",
            &json!({
                "requires_key_rotation": true,
                "requires_replay_window_flush": true,
                "requires_operator_attestation": true,
                "compromise_id": compromise.compromise_id,
            }),
        );
        let started_at_height = compromise.detected_at_height;
        let expires_at_height = started_at_height + PQ_DEFAULT_QUARANTINE_BLOCKS;
        let quarantine_id = pq_quarantine_id(
            &compromise.compromise_id,
            &compromise.affected_peer_id,
            compromise.recommended_action.as_str(),
            &reason_root,
        );
        let record = Self {
            quarantine_id,
            compromise_id: compromise.compromise_id.clone(),
            affected_peer_id: compromise.affected_peer_id.clone(),
            action: compromise.recommended_action.clone(),
            reason_root,
            started_at_height,
            expires_at_height,
            release_condition_root,
            operator_attestation_root: operator_attestation_root.to_string(),
            status: PQ_STATUS_QUARANTINED.to_string(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_quarantine_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "quarantine_id": self.quarantine_id,
            "compromise_id": self.compromise_id,
            "affected_peer_id": self.affected_peer_id,
            "action": self.action.as_str(),
            "reason_root": self.reason_root,
            "started_at_height": self.started_at_height,
            "expires_at_height": self.expires_at_height,
            "release_condition_root": self.release_condition_root,
            "operator_attestation_root": self.operator_attestation_root,
            "status": self.status,
        })
    }

    pub fn quarantine_root(&self) -> String {
        pq_payload_root("PQ-QUARANTINE-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.quarantine_id, "quarantine id")?;
        ensure_non_empty(&self.compromise_id, "quarantine compromise id")?;
        ensure_non_empty(&self.affected_peer_id, "quarantine affected peer id")?;
        ensure_non_empty(&self.reason_root, "quarantine reason root")?;
        ensure_non_empty(
            &self.release_condition_root,
            "quarantine release condition root",
        )?;
        ensure_non_empty(
            &self.operator_attestation_root,
            "quarantine operator attestation root",
        )?;
        if self.expires_at_height <= self.started_at_height {
            return Err("quarantine expiry must be after start".to_string());
        }
        Ok(self.quarantine_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCryptoAgilityStep {
    pub step_id: String,
    pub phase: PqMigrationPhase,
    pub label: String,
    pub from_scheme: String,
    pub to_scheme: String,
    pub starts_at_height: u64,
    pub enforce_at_height: u64,
    pub completes_at_height: u64,
    pub rollback_until_height: u64,
    pub acceptance_root: String,
    pub operator_attestation_root: String,
    pub status: String,
}

impl PqCryptoAgilityStep {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        phase: PqMigrationPhase,
        label: &str,
        from_scheme: &str,
        to_scheme: &str,
        starts_at_height: u64,
        duration_blocks: u64,
        operator_attestation_root: &str,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(label, "migration step label")?;
        ensure_non_empty(from_scheme, "migration step from scheme")?;
        ensure_non_empty(to_scheme, "migration step to scheme")?;
        ensure_non_empty(
            operator_attestation_root,
            "migration step operator attestation root",
        )?;
        if duration_blocks == 0 {
            return Err("migration step duration cannot be zero".to_string());
        }
        let enforce_at_height = starts_at_height + duration_blocks / 2;
        let completes_at_height = starts_at_height + duration_blocks;
        let rollback_until_height = completes_at_height + duration_blocks / 4 + 1;
        let acceptance_root = pq_payload_root(
            "PQ-MIGRATION-ACCEPTANCE",
            &json!({
                "phase": phase.as_str(),
                "label": label,
                "from_scheme": from_scheme,
                "to_scheme": to_scheme,
                "requires_no_open_critical_quarantine": true,
                "requires_replay_roots_finalized": true,
                "requires_operator_attestation": true,
            }),
        );
        let step_id = pq_migration_step_id(
            phase.as_str(),
            label,
            from_scheme,
            to_scheme,
            starts_at_height,
        );
        let step = Self {
            step_id,
            phase,
            label: label.to_string(),
            from_scheme: from_scheme.to_string(),
            to_scheme: to_scheme.to_string(),
            starts_at_height,
            enforce_at_height,
            completes_at_height,
            rollback_until_height,
            acceptance_root,
            operator_attestation_root: operator_attestation_root.to_string(),
            status: PQ_STATUS_PENDING.to_string(),
        };
        step.validate()?;
        Ok(step)
    }

    pub fn phase_at(&self, height: u64) -> PqMigrationPhase {
        if height < self.starts_at_height {
            PqMigrationPhase::Discover
        } else if height < self.enforce_at_height {
            self.phase.clone()
        } else if height < self.completes_at_height {
            PqMigrationPhase::EnforcePq
        } else if height < self.rollback_until_height {
            PqMigrationPhase::RetireClassic
        } else {
            PqMigrationPhase::Complete
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_crypto_agility_step",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "schedule_version": PQ_MIGRATION_SCHEDULE_VERSION,
            "step_id": self.step_id,
            "phase": self.phase.as_str(),
            "label": self.label,
            "from_scheme": self.from_scheme,
            "to_scheme": self.to_scheme,
            "starts_at_height": self.starts_at_height,
            "enforce_at_height": self.enforce_at_height,
            "completes_at_height": self.completes_at_height,
            "rollback_until_height": self.rollback_until_height,
            "acceptance_root": self.acceptance_root,
            "operator_attestation_root": self.operator_attestation_root,
            "status": self.status,
        })
    }

    pub fn step_root(&self) -> String {
        pq_payload_root("PQ-CRYPTO-AGILITY-STEP", &self.public_record())
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.step_id, "migration step id")?;
        ensure_non_empty(&self.label, "migration step label")?;
        ensure_non_empty(&self.from_scheme, "migration step from scheme")?;
        ensure_non_empty(&self.to_scheme, "migration step to scheme")?;
        ensure_non_empty(&self.acceptance_root, "migration step acceptance root")?;
        ensure_non_empty(
            &self.operator_attestation_root,
            "migration step operator attestation root",
        )?;
        if !(self.starts_at_height <= self.enforce_at_height
            && self.enforce_at_height <= self.completes_at_height
            && self.completes_at_height < self.rollback_until_height)
        {
            return Err("migration step heights must be monotonic".to_string());
        }
        Ok(self.step_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCryptoAgilitySchedule {
    pub schedule_id: String,
    pub operator_label: String,
    pub current_height: u64,
    pub policy_root: String,
    pub steps: Vec<PqCryptoAgilityStep>,
    pub active_phase: PqMigrationPhase,
    pub step_root: String,
    pub status: String,
}

impl PqCryptoAgilitySchedule {
    pub fn devnet(
        operator_label: &str,
        current_height: u64,
        operator_attestation_root: &str,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(operator_label, "migration schedule operator label")?;
        let policy_root = pq_payload_root(
            "PQ-MIGRATION-POLICY",
            &json!({
                "operator_label": operator_label,
                "objective": "retire classic fallback after pq session stability",
                "schedule_version": PQ_MIGRATION_SCHEDULE_VERSION,
            }),
        );
        let steps = vec![
            PqCryptoAgilityStep::deterministic(
                PqMigrationPhase::Discover,
                "inventory_pq_capable_peers",
                PQ_HYBRID_CLASSIC_KEM_SCHEME,
                PQ_ML_KEM_SCHEME,
                current_height,
                240,
                operator_attestation_root,
            )?,
            PqCryptoAgilityStep::deterministic(
                PqMigrationPhase::DualPublish,
                "dual_publish_auth_and_kem_keys",
                PQ_HYBRID_CLASSIC_SIGNATURE_SCHEME,
                PQ_HANDSHAKE_SUITE,
                current_height + 240,
                480,
                operator_attestation_root,
            )?,
            PqCryptoAgilityStep::deterministic(
                PqMigrationPhase::EnforcePq,
                "reject_classic_only_handshakes",
                PQ_HYBRID_CLASSIC_KEM_SCHEME,
                PQ_ML_KEM_SCHEME,
                current_height + 720,
                720,
                operator_attestation_root,
            )?,
            PqCryptoAgilityStep::deterministic(
                PqMigrationPhase::RetireClassic,
                "archive_classic_fallback_commitments",
                PQ_HYBRID_CLASSIC_SIGNATURE_SCHEME,
                PQ_ML_DSA_SCHEME,
                current_height + 1_440,
                720,
                operator_attestation_root,
            )?,
        ];
        let step_root = merkle_root(
            "PQ-CRYPTO-AGILITY-STEPS",
            &steps
                .iter()
                .map(PqCryptoAgilityStep::public_record)
                .collect::<Vec<_>>(),
        );
        let schedule_id = pq_schedule_id(operator_label, &policy_root, &step_root, current_height);
        let schedule = Self {
            schedule_id,
            operator_label: operator_label.to_string(),
            current_height,
            policy_root,
            steps,
            active_phase: PqMigrationPhase::Discover,
            step_root,
            status: PQ_STATUS_MIGRATING.to_string(),
        };
        schedule.validate()?;
        Ok(schedule)
    }

    pub fn set_height(&mut self, height: u64) -> PqSessionResult<String> {
        self.current_height = height;
        self.active_phase = self
            .steps
            .iter()
            .find(|step| height <= step.rollback_until_height)
            .map(|step| step.phase_at(height))
            .unwrap_or(PqMigrationPhase::Complete);
        self.validate()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_crypto_agility_schedule",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "schedule_version": PQ_MIGRATION_SCHEDULE_VERSION,
            "schedule_id": self.schedule_id,
            "operator_label": self.operator_label,
            "current_height": self.current_height,
            "policy_root": self.policy_root,
            "active_phase": self.active_phase.as_str(),
            "step_root": self.step_root,
            "steps": self.steps.iter().map(PqCryptoAgilityStep::public_record).collect::<Vec<_>>(),
            "status": self.status,
        })
    }

    pub fn schedule_root(&self) -> String {
        pq_payload_root("PQ-CRYPTO-AGILITY-SCHEDULE", &self.public_record())
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.schedule_id, "migration schedule id")?;
        ensure_non_empty(&self.operator_label, "migration schedule operator label")?;
        ensure_non_empty(&self.policy_root, "migration schedule policy root")?;
        ensure_non_empty(&self.step_root, "migration schedule step root")?;
        if self.steps.len() > PQ_MAX_DEVNET_MIGRATION_STEPS {
            return Err("migration schedule exceeds devnet step limit".to_string());
        }
        for step in &self.steps {
            step.validate()?;
        }
        Ok(self.schedule_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqDevnetRecord {
    pub record_id: String,
    pub label: String,
    pub category: String,
    pub height: u64,
    pub payload_root: String,
    pub witness_root: String,
    pub notes_root: String,
}

impl PqDevnetRecord {
    pub fn deterministic(
        label: &str,
        category: &str,
        height: u64,
        payload: &Value,
        notes: &str,
    ) -> PqSessionResult<Self> {
        ensure_non_empty(label, "devnet record label")?;
        ensure_non_empty(category, "devnet record category")?;
        let payload_root = pq_payload_root("PQ-DEVNET-RECORD-PAYLOAD", payload);
        let witness_root = pq_payload_root(
            "PQ-DEVNET-RECORD-WITNESS",
            &json!({
                "label": label,
                "category": category,
                "height": height,
                "payload_root": payload_root,
            }),
        );
        let notes_root = pq_string_commitment("devnet_record_notes", notes);
        let record_id = pq_devnet_record_id(label, category, height, &payload_root);
        let record = Self {
            record_id,
            label: label.to_string(),
            category: category.to_string(),
            height,
            payload_root,
            witness_root,
            notes_root,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_devnet_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "label": self.label,
            "category": self.category,
            "height": self.height,
            "payload_root": self.payload_root,
            "witness_root": self.witness_root,
            "notes_root": self.notes_root,
        })
    }

    pub fn record_root(&self) -> String {
        pq_payload_root("PQ-DEVNET-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.record_id, "devnet record id")?;
        ensure_non_empty(&self.label, "devnet record label")?;
        ensure_non_empty(&self.category, "devnet record category")?;
        ensure_non_empty(&self.payload_root, "devnet record payload root")?;
        ensure_non_empty(&self.witness_root, "devnet record witness root")?;
        ensure_non_empty(&self.notes_root, "devnet record notes root")?;
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSessionStateRoots {
    pub peer_root: String,
    pub key_root: String,
    pub handshake_root: String,
    pub transcript_root: String,
    pub rotation_root: String,
    pub replay_root: String,
    pub mempool_grant_root: String,
    pub attestation_root: String,
    pub compromise_root: String,
    pub quarantine_root: String,
    pub migration_root: String,
    pub devnet_record_root: String,
}

impl PqSessionStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_session_state_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
            "peer_root": self.peer_root,
            "key_root": self.key_root,
            "handshake_root": self.handshake_root,
            "transcript_root": self.transcript_root,
            "rotation_root": self.rotation_root,
            "replay_root": self.replay_root,
            "mempool_grant_root": self.mempool_grant_root,
            "attestation_root": self.attestation_root,
            "compromise_root": self.compromise_root,
            "quarantine_root": self.quarantine_root,
            "migration_root": self.migration_root,
            "devnet_record_root": self.devnet_record_root,
        })
    }

    pub fn aggregate_root(&self) -> String {
        pq_payload_root("PQ-SESSION-STATE-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSessionState {
    pub operator_label: String,
    pub height: u64,
    pub protocol_version: String,
    pub security_model: String,
    pub fallback_policy: PqHybridFallbackPolicy,
    pub peers: Vec<PqSessionPeer>,
    pub handshakes: Vec<PqSessionHandshake>,
    pub auth_transcripts: Vec<PqAuthTranscript>,
    pub rotation_windows: Vec<PqRotationWindow>,
    pub replay_protection: PqReplayProtectionState,
    pub mempool_grants: Vec<PqMempoolSessionGrant>,
    pub operator_attestations: Vec<PqOperatorAttestation>,
    pub compromise_records: Vec<PqCompromiseRecord>,
    pub quarantine_records: Vec<PqQuarantineRecord>,
    pub migration_schedule: PqCryptoAgilitySchedule,
    pub devnet_records: Vec<PqDevnetRecord>,
    pub metadata: BTreeMap<String, String>,
}

impl PqSessionState {
    pub fn devnet(operator_label: &str) -> Self {
        Self::try_devnet(operator_label).expect("deterministic pq devnet state")
    }

    pub fn try_devnet(operator_label: &str) -> PqSessionResult<Self> {
        ensure_non_empty(operator_label, "pq session devnet operator label")?;
        let height = 1;
        let operator =
            PqSessionPeer::deterministic(operator_label, PqHandshakeRole::Sequencer, height, 0)?;
        let wallet = PqSessionPeer::deterministic(
            &format!("{operator_label}-wallet"),
            PqHandshakeRole::Initiator,
            height,
            0,
        )?;
        let watchtower = PqSessionPeer::deterministic(
            &format!("{operator_label}-watchtower"),
            PqHandshakeRole::Watchtower,
            height,
            0,
        )?;
        let fallback_policy = PqHybridFallbackPolicy::deterministic(operator_label, height)?;
        let user_handshake = PqSessionHandshake::deterministic(
            &wallet,
            &operator,
            "encrypted_mempool_submission",
            height,
            7,
        )?;
        let watchtower_handshake = PqSessionHandshake::deterministic(
            &watchtower,
            &operator,
            "operator_attestation_stream",
            height,
            11,
        )?;
        let auth_transcripts = vec![
            user_handshake.initiator_auth_transcript.clone(),
            user_handshake.responder_auth_transcript.clone(),
            watchtower_handshake.initiator_auth_transcript.clone(),
            watchtower_handshake.responder_auth_transcript.clone(),
        ];
        let mut replay_protection =
            PqReplayProtectionState::new(height, PQ_DEFAULT_REPLAY_WINDOW_BLOCKS);
        replay_protection.observe(PqReplayNonceRecord::deterministic(
            "handshake_packet",
            &user_handshake.session_id,
            &wallet.peer_id,
            &user_handshake.transcript_root,
            height,
            7,
        )?)?;
        replay_protection.observe(PqReplayNonceRecord::deterministic(
            "handshake_packet",
            &watchtower_handshake.session_id,
            &watchtower.peer_id,
            &watchtower_handshake.transcript_root,
            height,
            11,
        )?)?;
        let mempool_grant = PqMempoolSessionGrant::deterministic(
            &user_handshake.session_id,
            &wallet,
            &operator,
            PqMempoolGrantScope::SubmitPrivateTx,
            &json!({
                "payload": "encrypted-devnet-transfer",
                "asset": "xmr",
                "fee_mode": "low_fee_private_lane",
            }),
            "private-fast-lane",
            height + 2,
            19,
        )?;
        let peers = vec![operator.clone(), wallet.clone(), watchtower.clone()];
        let handshakes = vec![user_handshake.clone(), watchtower_handshake.clone()];
        let rotation_windows = vec![
            PqRotationWindow::deterministic(
                operator_label,
                PqKeyPurpose::SessionKem,
                &operator.kem_key,
                height + PQ_DEFAULT_ROTATION_NOTICE_BLOCKS,
                1,
            )?,
            PqRotationWindow::deterministic(
                operator_label,
                PqKeyPurpose::OnlineAuth,
                &operator.ml_dsa_key,
                height + PQ_DEFAULT_ROTATION_NOTICE_BLOCKS,
                1,
            )?,
        ];
        let key_root = merkle_root(
            "PQ-DEVNET-KEYS",
            &peers
                .iter()
                .flat_map(|peer| peer.active_key_roots())
                .map(Value::String)
                .collect::<Vec<_>>(),
        );
        let session_root = merkle_root(
            "PQ-DEVNET-HANDSHAKES",
            &handshakes
                .iter()
                .map(PqSessionHandshake::public_record)
                .collect::<Vec<_>>(),
        );
        let grant_root = merkle_root("PQ-DEVNET-MEMPOOL-GRANTS", &[mempool_grant.public_record()]);
        let risk_root = pq_payload_root(
            "PQ-DEVNET-RISK",
            &json!({
                "open_critical_compromises": 0,
                "open_quarantines": 0,
                "fallback_mode": fallback_policy.mode.as_str(),
            }),
        );
        let roots = PqOperatorAttestationRoots {
            session_root,
            key_root,
            replay_root: replay_protection.state_root(),
            mempool_grant_root: grant_root,
            risk_root,
        };
        let boot_attestation = PqOperatorAttestation::deterministic(
            operator_label,
            PqAttestationKind::OperatorBoot,
            &operator,
            &json!({
                "operator_label": operator_label,
                "boot_height": height,
                "suite": PQ_HANDSHAKE_SUITE,
            }),
            &roots,
            height + 3,
        )?;
        let lane_attestation = PqOperatorAttestation::deterministic(
            operator_label,
            PqAttestationKind::MempoolLane,
            &operator,
            &mempool_grant.public_record(),
            &roots,
            height + 4,
        )?;
        let operator_attestations = vec![boot_attestation.clone(), lane_attestation.clone()];
        let compromise = PqCompromiseRecord::deterministic(
            PqCompromiseKind::OperatorReport,
            &watchtower,
            &watchtower.kem_key.key_id,
            &json!({
                "finding": "devnet simulated stale kem ciphertext",
                "severity": "low",
                "action": "observe only",
            }),
            operator_label,
            PqRiskLevel::Low,
            height + 5,
        )?;
        let quarantine = PqQuarantineRecord::from_compromise(
            &compromise,
            &json!({
                "note": "low-risk devnet record kept as quarantine model fixture",
                "release": "attested rotation not required for low severity",
            }),
            &lane_attestation.attestation_root(),
        )?;
        let migration_schedule = PqCryptoAgilitySchedule::devnet(
            operator_label,
            height,
            &boot_attestation.attestation_root(),
        )?;
        let devnet_records = vec![
            PqDevnetRecord::deterministic(
                operator_label,
                "handshake",
                height,
                &user_handshake.public_record(),
                "wallet to operator encrypted mempool session",
            )?,
            PqDevnetRecord::deterministic(
                operator_label,
                "attestation",
                height + 3,
                &boot_attestation.public_record(),
                "operator boot roots for pq state",
            )?,
            PqDevnetRecord::deterministic(
                operator_label,
                "migration",
                height,
                &migration_schedule.public_record(),
                "bounded classic fallback retirement path",
            )?,
        ];
        let mut metadata = BTreeMap::new();
        metadata.insert("chain_id".to_string(), CHAIN_ID.to_string());
        metadata.insert("suite".to_string(), PQ_HANDSHAKE_SUITE.to_string());
        metadata.insert(
            "security_model".to_string(),
            PQ_SESSION_SECURITY_MODEL.to_string(),
        );
        metadata.insert(
            "auth_required_set".to_string(),
            PQ_AUTH_REQUIRED_SET.to_string(),
        );
        let state = Self {
            operator_label: operator_label.to_string(),
            height,
            protocol_version: PQ_SESSION_PROTOCOL_VERSION.to_string(),
            security_model: PQ_SESSION_SECURITY_MODEL.to_string(),
            fallback_policy,
            peers,
            handshakes,
            auth_transcripts,
            rotation_windows,
            replay_protection,
            mempool_grants: vec![mempool_grant],
            operator_attestations,
            compromise_records: vec![compromise],
            quarantine_records: vec![quarantine],
            migration_schedule,
            devnet_records,
            metadata,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqSessionResult<String> {
        self.height = height;
        self.replay_protection.set_height(height)?;
        self.migration_schedule.set_height(height)?;
        for handshake in &mut self.handshakes {
            if handshake.status == PQ_STATUS_ACTIVE && height >= handshake.expires_at_height {
                handshake.status = PQ_STATUS_EXPIRED.to_string();
                handshake.stage = PqHandshakeStage::Expired;
            }
        }
        for grant in &mut self.mempool_grants {
            if grant.status == PQ_STATUS_ACTIVE && height >= grant.expires_at_height {
                grant.status = PQ_STATUS_EXPIRED.to_string();
            }
        }
        for transcript in &mut self.auth_transcripts {
            if transcript.status == PQ_STATUS_ACTIVE && height >= transcript.expires_at_height {
                transcript.status = PQ_STATUS_EXPIRED.to_string();
            }
        }
        for rotation in &mut self.rotation_windows {
            rotation.stage = rotation.stage_at(height);
            rotation.status = if rotation.stage == PqRotationStage::Complete {
                PQ_STATUS_ACTIVE.to_string()
            } else {
                PQ_STATUS_ROTATING.to_string()
            };
        }
        self.validate()
    }

    pub fn add_handshake(&mut self, handshake: PqSessionHandshake) -> PqSessionResult<String> {
        handshake.validate()?;
        ensure_unique_id(
            &self
                .handshakes
                .iter()
                .map(|item| item.session_id.clone())
                .collect::<BTreeSet<_>>(),
            &handshake.session_id,
            "session handshake",
        )?;
        self.handshakes.push(handshake);
        self.handshakes
            .sort_by(|left, right| left.session_id.cmp(&right.session_id));
        if self.handshakes.len() > PQ_MAX_DEVNET_HANDSHAKES {
            return Err("pq session state exceeds devnet handshake limit".to_string());
        }
        self.validate()
    }

    pub fn add_auth_transcript(&mut self, transcript: PqAuthTranscript) -> PqSessionResult<String> {
        transcript.validate()?;
        self.auth_transcripts.push(transcript);
        self.auth_transcripts
            .sort_by(|left, right| left.transcript_id.cmp(&right.transcript_id));
        if self.auth_transcripts.len() > PQ_MAX_DEVNET_TRANSCRIPTS {
            return Err("pq session state exceeds devnet transcript limit".to_string());
        }
        self.validate()
    }

    pub fn add_mempool_grant(&mut self, grant: PqMempoolSessionGrant) -> PqSessionResult<String> {
        grant.validate()?;
        self.mempool_grants.push(grant);
        self.mempool_grants
            .sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
        if self.mempool_grants.len() > PQ_MAX_DEVNET_MEMPOOL_GRANTS {
            return Err("pq session state exceeds devnet mempool grant limit".to_string());
        }
        self.validate()
    }

    pub fn record_compromise(&mut self, compromise: PqCompromiseRecord) -> PqSessionResult<String> {
        compromise.validate()?;
        self.compromise_records.push(compromise);
        self.compromise_records
            .sort_by(|left, right| left.compromise_id.cmp(&right.compromise_id));
        if self.compromise_records.len() > PQ_MAX_DEVNET_COMPROMISES {
            return Err("pq session state exceeds devnet compromise limit".to_string());
        }
        self.validate()
    }

    pub fn add_quarantine(&mut self, quarantine: PqQuarantineRecord) -> PqSessionResult<String> {
        quarantine.validate()?;
        self.quarantine_records.push(quarantine);
        self.quarantine_records
            .sort_by(|left, right| left.quarantine_id.cmp(&right.quarantine_id));
        self.validate()
    }

    pub fn roots(&self) -> PqSessionStateRoots {
        let peer_root = merkle_root(
            "PQ-SESSION-PEERS",
            &self
                .peers
                .iter()
                .map(PqSessionPeer::public_record)
                .collect::<Vec<_>>(),
        );
        let key_root = merkle_root(
            "PQ-SESSION-KEYS",
            &self
                .peers
                .iter()
                .flat_map(|peer| peer.active_key_roots())
                .map(Value::String)
                .collect::<Vec<_>>(),
        );
        let handshake_root = merkle_root(
            "PQ-SESSION-HANDSHAKES",
            &self
                .handshakes
                .iter()
                .map(PqSessionHandshake::public_record)
                .collect::<Vec<_>>(),
        );
        let transcript_root = merkle_root(
            "PQ-SESSION-AUTH-TRANSCRIPTS",
            &self
                .auth_transcripts
                .iter()
                .map(PqAuthTranscript::public_record)
                .collect::<Vec<_>>(),
        );
        let rotation_root = merkle_root(
            "PQ-SESSION-ROTATIONS",
            &self
                .rotation_windows
                .iter()
                .map(PqRotationWindow::public_record)
                .collect::<Vec<_>>(),
        );
        let mempool_grant_root = merkle_root(
            "PQ-SESSION-MEMPOOL-GRANTS",
            &self
                .mempool_grants
                .iter()
                .map(PqMempoolSessionGrant::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = merkle_root(
            "PQ-SESSION-OPERATOR-ATTESTATIONS",
            &self
                .operator_attestations
                .iter()
                .map(PqOperatorAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let compromise_root = merkle_root(
            "PQ-SESSION-COMPROMISES",
            &self
                .compromise_records
                .iter()
                .map(PqCompromiseRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let quarantine_root = merkle_root(
            "PQ-SESSION-QUARANTINES",
            &self
                .quarantine_records
                .iter()
                .map(PqQuarantineRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let devnet_record_root = merkle_root(
            "PQ-SESSION-DEVNET-RECORDS",
            &self
                .devnet_records
                .iter()
                .map(PqDevnetRecord::public_record)
                .collect::<Vec<_>>(),
        );
        PqSessionStateRoots {
            peer_root,
            key_root,
            handshake_root,
            transcript_root,
            rotation_root,
            replay_root: self.replay_protection.state_root(),
            mempool_grant_root,
            attestation_root,
            compromise_root,
            quarantine_root,
            migration_root: self.migration_schedule.schedule_root(),
            devnet_record_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root(&roots);
        record
            .as_object_mut()
            .expect("pq session state public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        pq_payload_root(
            "PQ-SESSION-STATE",
            &self.public_record_without_state_root(&roots),
        )
    }

    pub fn operator_attestation_roots(&self) -> PqOperatorAttestationRoots {
        let roots = self.roots();
        PqOperatorAttestationRoots {
            session_root: roots.handshake_root,
            key_root: roots.key_root,
            replay_root: roots.replay_root,
            mempool_grant_root: roots.mempool_grant_root,
            risk_root: pq_payload_root(
                "PQ-SESSION-RISK-SUMMARY",
                &json!({
                    "compromise_root": roots.compromise_root,
                    "quarantine_root": roots.quarantine_root,
                    "fallback_policy_root": self.fallback_policy.policy_root(),
                }),
            ),
        }
    }

    pub fn validate(&self) -> PqSessionResult<String> {
        ensure_non_empty(&self.operator_label, "pq session state operator label")?;
        if self.protocol_version != PQ_SESSION_PROTOCOL_VERSION {
            return Err("pq session state protocol version mismatch".to_string());
        }
        if self.security_model != PQ_SESSION_SECURITY_MODEL {
            return Err("pq session state security model mismatch".to_string());
        }
        self.fallback_policy.validate()?;
        if self.handshakes.len() > PQ_MAX_DEVNET_HANDSHAKES {
            return Err("pq session state exceeds devnet handshake limit".to_string());
        }
        if self.auth_transcripts.len() > PQ_MAX_DEVNET_TRANSCRIPTS {
            return Err("pq session state exceeds devnet transcript limit".to_string());
        }
        if self.mempool_grants.len() > PQ_MAX_DEVNET_MEMPOOL_GRANTS {
            return Err("pq session state exceeds devnet mempool grant limit".to_string());
        }
        if self.operator_attestations.len() > PQ_MAX_DEVNET_ATTESTATIONS {
            return Err("pq session state exceeds devnet attestation limit".to_string());
        }
        if self.compromise_records.len() > PQ_MAX_DEVNET_COMPROMISES {
            return Err("pq session state exceeds devnet compromise limit".to_string());
        }
        for peer in &self.peers {
            peer.validate()?;
        }
        for handshake in &self.handshakes {
            handshake.validate()?;
        }
        for transcript in &self.auth_transcripts {
            transcript.validate()?;
        }
        for rotation in &self.rotation_windows {
            rotation.validate()?;
        }
        self.replay_protection.validate()?;
        for grant in &self.mempool_grants {
            grant.validate()?;
        }
        for attestation in &self.operator_attestations {
            attestation.validate()?;
        }
        for compromise in &self.compromise_records {
            compromise.validate()?;
        }
        for quarantine in &self.quarantine_records {
            quarantine.validate()?;
        }
        self.migration_schedule.validate()?;
        for record in &self.devnet_records {
            record.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self, roots: &PqSessionStateRoots) -> Value {
        json!({
            "kind": "pq_session_state",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "height": self.height,
            "operator_label": self.operator_label,
            "security_model": self.security_model,
            "commitment_scheme": PQ_SESSION_COMMITMENT_SCHEME,
            "transcript_scheme": PQ_SESSION_TRANSCRIPT_SCHEME,
            "handshake_suite": PQ_HANDSHAKE_SUITE,
            "auth_required_set": PQ_AUTH_REQUIRED_SET,
            "fallback_policy": self.fallback_policy.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.aggregate_root(),
            "peers": self.peers.iter().map(PqSessionPeer::public_record).collect::<Vec<_>>(),
            "handshakes": self.handshakes.iter().map(PqSessionHandshake::public_record).collect::<Vec<_>>(),
            "auth_transcripts": self.auth_transcripts.iter().map(PqAuthTranscript::public_record).collect::<Vec<_>>(),
            "rotation_windows": self.rotation_windows.iter().map(PqRotationWindow::public_record).collect::<Vec<_>>(),
            "replay_protection": self.replay_protection.public_record(),
            "mempool_grants": self.mempool_grants.iter().map(PqMempoolSessionGrant::public_record).collect::<Vec<_>>(),
            "operator_attestations": self.operator_attestations.iter().map(PqOperatorAttestation::public_record).collect::<Vec<_>>(),
            "compromise_records": self.compromise_records.iter().map(PqCompromiseRecord::public_record).collect::<Vec<_>>(),
            "quarantine_records": self.quarantine_records.iter().map(PqQuarantineRecord::public_record).collect::<Vec<_>>(),
            "migration_schedule": self.migration_schedule.public_record(),
            "devnet_records": self.devnet_records.iter().map(PqDevnetRecord::public_record).collect::<Vec<_>>(),
            "metadata": self.metadata,
        })
    }
}

pub fn pq_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn pq_empty_root(domain: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID)], 32)
}

pub fn pq_string_commitment(label: &str, value: &str) -> String {
    domain_hash(
        "PQ-STRING-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn pq_key_material_commitment(
    owner_label: &str,
    purpose: &str,
    scheme: &str,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "PQ-KEY-MATERIAL-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(purpose),
            HashPart::Str(scheme),
            HashPart::Int(rotation_nonce as i128),
        ],
        32,
    )
}

pub fn pq_key_id(
    owner_label: &str,
    purpose: &str,
    scheme: &str,
    public_key_commitment: &str,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "PQ-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(purpose),
            HashPart::Str(scheme),
            HashPart::Str(public_key_commitment),
            HashPart::Int(rotation_nonce as i128),
        ],
        32,
    )
}

pub fn pq_peer_id(label: &str, role: &str, kem_key_id: &str, auth_key_id: &str) -> String {
    domain_hash(
        "PQ-PEER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(role),
            HashPart::Str(kem_key_id),
            HashPart::Str(auth_key_id),
        ],
        32,
    )
}

pub fn pq_route_hint_root(label: &str, role: &str, nonce: u64) -> String {
    domain_hash(
        "PQ-ROUTE-HINT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(role),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_peer_policy_root(label: &str, role: &str, route_hint_root: &str) -> String {
    pq_payload_root(
        "PQ-PEER-POLICY",
        &json!({
            "label": label,
            "role": role,
            "route_hint_root": route_hint_root,
            "requires_ml_kem": true,
            "requires_ml_dsa": true,
            "requires_slh_dsa_recovery": true,
        }),
    )
}

pub fn pq_kem_ciphertext_commitment(
    recipient_key_id: &str,
    aad_root: &str,
    produced_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PQ-KEM-CIPHERTEXT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_ML_KEM_SCHEME),
            HashPart::Str(recipient_key_id),
            HashPart::Str(aad_root),
            HashPart::Int(produced_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_shared_secret_commitment(
    recipient_key_id: &str,
    ciphertext_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PQ-SHARED-SECRET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_ML_KEM_SCHEME),
            HashPart::Str(recipient_key_id),
            HashPart::Str(ciphertext_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_kem_ciphertext_id(
    recipient_key_id: &str,
    ciphertext_commitment: &str,
    shared_secret_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PQ-KEM-CIPHERTEXT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(recipient_key_id),
            HashPart::Str(ciphertext_commitment),
            HashPart::Str(shared_secret_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_auth_challenge_root(
    kind: &str,
    signer_label: &str,
    signer_key_id: &str,
    subject_root: &str,
    context_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-AUTH-CHALLENGE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(signer_label),
            HashPart::Str(signer_key_id),
            HashPart::Str(subject_root),
            HashPart::Str(context_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_signature_commitment(
    scheme: &str,
    signer_label: &str,
    signer_key_id: &str,
    challenge_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-SIGNATURE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scheme),
            HashPart::Str(signer_label),
            HashPart::Str(signer_key_id),
            HashPart::Str(challenge_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_auth_transcript_id(
    kind: &str,
    signer_label: &str,
    signer_key_id: &str,
    challenge_root: &str,
    signature_commitment: &str,
) -> String {
    domain_hash(
        "PQ-AUTH-TRANSCRIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(signer_label),
            HashPart::Str(signer_key_id),
            HashPart::Str(challenge_root),
            HashPart::Str(signature_commitment),
        ],
        32,
    )
}

pub fn pq_replay_nonce(
    domain: &str,
    session_id: &str,
    left: &str,
    right: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PQ-REPLAY-NONCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(session_id),
            HashPart::Str(left),
            HashPart::Str(right),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_replay_nonce_id(
    domain: &str,
    session_id: &str,
    peer_id: &str,
    nonce_commitment: &str,
) -> String {
    domain_hash(
        "PQ-REPLAY-NONCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(session_id),
            HashPart::Str(peer_id),
            HashPart::Str(nonce_commitment),
        ],
        32,
    )
}

pub fn pq_session_id(
    initiator_peer_id: &str,
    responder_peer_id: &str,
    purpose: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PQ-SESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(initiator_peer_id),
            HashPart::Str(responder_peer_id),
            HashPart::Str(purpose),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_handshake_transcript_root(
    session_id: &str,
    sender_peer_id: &str,
    receiver_peer_id: &str,
    stage: &str,
    kem_ciphertext: Option<&PqKemCiphertext>,
    previous_packet_root: &str,
    produced_at_height: u64,
    replay_nonce: &str,
) -> String {
    let kem_root = kem_ciphertext
        .map(PqKemCiphertext::ciphertext_root)
        .unwrap_or_else(|| pq_empty_root("PQ-HANDSHAKE-NO-KEM"));
    domain_hash(
        "PQ-HANDSHAKE-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(sender_peer_id),
            HashPart::Str(receiver_peer_id),
            HashPart::Str(stage),
            HashPart::Str(&kem_root),
            HashPart::Str(previous_packet_root),
            HashPart::Int(produced_at_height as i128),
            HashPart::Str(replay_nonce),
        ],
        32,
    )
}

pub fn pq_handshake_packet_id(
    session_id: &str,
    sender_peer_id: &str,
    receiver_peer_id: &str,
    stage: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "PQ-HANDSHAKE-PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(sender_peer_id),
            HashPart::Str(receiver_peer_id),
            HashPart::Str(stage),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn pq_handshake_root_from_parts(
    offer_root: &str,
    encapsulation_root: &str,
    initiator_auth_root: &str,
    responder_auth_root: &str,
) -> String {
    domain_hash(
        "PQ-HANDSHAKE-ROOT-FROM-PARTS",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(offer_root),
            HashPart::Str(encapsulation_root),
            HashPart::Str(initiator_auth_root),
            HashPart::Str(responder_auth_root),
        ],
        32,
    )
}

pub fn pq_session_secret_commitment(
    session_id: &str,
    transcript_root: &str,
    shared_secret_commitment: &str,
) -> String {
    domain_hash(
        "PQ-SESSION-SECRET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(transcript_root),
            HashPart::Str(shared_secret_commitment),
        ],
        32,
    )
}

pub fn pq_replay_domain_root(
    session_id: &str,
    initiator_peer_id: &str,
    responder_peer_id: &str,
) -> String {
    domain_hash(
        "PQ-REPLAY-DOMAIN-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(initiator_peer_id),
            HashPart::Str(responder_peer_id),
        ],
        32,
    )
}

pub fn pq_rotation_policy_root(
    owner_label: &str,
    purpose: &str,
    announcement_height: u64,
    activation_height: u64,
    retire_previous_height: u64,
) -> String {
    pq_payload_root(
        "PQ-ROTATION-POLICY",
        &json!({
            "owner_label": owner_label,
            "purpose": purpose,
            "announcement_height": announcement_height,
            "activation_height": activation_height,
            "retire_previous_height": retire_previous_height,
            "overlap_blocks": PQ_DEFAULT_ROTATION_OVERLAP_BLOCKS,
            "notice_blocks": PQ_DEFAULT_ROTATION_NOTICE_BLOCKS,
        }),
    )
}

pub fn pq_rotation_id(
    owner_label: &str,
    purpose: &str,
    previous_key_id: &str,
    next_key_id: &str,
    activation_height: u64,
) -> String {
    domain_hash(
        "PQ-ROTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(purpose),
            HashPart::Str(previous_key_id),
            HashPart::Str(next_key_id),
            HashPart::Int(activation_height as i128),
        ],
        32,
    )
}

pub fn pq_fallback_policy_id(
    operator_label: &str,
    mode: &str,
    created_at_height: u64,
    emergency_contact_root: &str,
) -> String {
    domain_hash(
        "PQ-FALLBACK-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(mode),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(emergency_contact_root),
        ],
        32,
    )
}

pub fn pq_mempool_grant_id(
    session_id: &str,
    grantee_peer_id: &str,
    sequencer_peer_id: &str,
    scope: &str,
    replay_nonce: &str,
) -> String {
    domain_hash(
        "PQ-MEMPOOL-GRANT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(grantee_peer_id),
            HashPart::Str(sequencer_peer_id),
            HashPart::Str(scope),
            HashPart::Str(replay_nonce),
        ],
        32,
    )
}

pub fn pq_operator_attestation_id(
    operator_label: &str,
    kind: &str,
    subject_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-OPERATOR-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(kind),
            HashPart::Str(subject_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_compromise_id(
    kind: &str,
    affected_peer_id: &str,
    affected_key_id: &str,
    evidence_root: &str,
    detected_at_height: u64,
) -> String {
    domain_hash(
        "PQ-COMPROMISE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(affected_peer_id),
            HashPart::Str(affected_key_id),
            HashPart::Str(evidence_root),
            HashPart::Int(detected_at_height as i128),
        ],
        32,
    )
}

pub fn pq_quarantine_id(
    compromise_id: &str,
    affected_peer_id: &str,
    action: &str,
    reason_root: &str,
) -> String {
    domain_hash(
        "PQ-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(compromise_id),
            HashPart::Str(affected_peer_id),
            HashPart::Str(action),
            HashPart::Str(reason_root),
        ],
        32,
    )
}

pub fn pq_migration_step_id(
    phase: &str,
    label: &str,
    from_scheme: &str,
    to_scheme: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MIGRATION-STEP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(phase),
            HashPart::Str(label),
            HashPart::Str(from_scheme),
            HashPart::Str(to_scheme),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn pq_schedule_id(
    operator_label: &str,
    policy_root: &str,
    step_root: &str,
    current_height: u64,
) -> String {
    domain_hash(
        "PQ-SCHEDULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(policy_root),
            HashPart::Str(step_root),
            HashPart::Int(current_height as i128),
        ],
        32,
    )
}

pub fn pq_devnet_record_id(label: &str, category: &str, height: u64, payload_root: &str) -> String {
    domain_hash(
        "PQ-DEVNET-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(category),
            HashPart::Int(height as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn pq_public_record_root(record: &Value) -> String {
    pq_payload_root("PQ-PUBLIC-RECORD", record)
}

pub fn pq_commitment_manifest(operator_label: &str) -> Value {
    json!({
        "kind": "pq_commitment_manifest",
        "chain_id": CHAIN_ID,
        "protocol_version": PQ_SESSION_PROTOCOL_VERSION,
        "operator_label": operator_label,
        "security_model": PQ_SESSION_SECURITY_MODEL,
        "commitment_scheme": PQ_SESSION_COMMITMENT_SCHEME,
        "transcript_scheme": PQ_SESSION_TRANSCRIPT_SCHEME,
        "kem_scheme": PQ_ML_KEM_SCHEME,
        "online_auth_scheme": PQ_ML_DSA_SCHEME,
        "recovery_auth_scheme": PQ_SLH_DSA_SCHEME,
        "hybrid_classic_kem_scheme": PQ_HYBRID_CLASSIC_KEM_SCHEME,
        "hybrid_classic_signature_scheme": PQ_HYBRID_CLASSIC_SIGNATURE_SCHEME,
        "mempool_encryption_scheme": PQ_MEMPOOL_ENCRYPTION_SCHEME,
        "operator_attestation_scheme": PQ_OPERATOR_ATTESTATION_SCHEME,
        "quarantine_scheme": PQ_QUARANTINE_SCHEME,
        "migration_schedule_version": PQ_MIGRATION_SCHEDULE_VERSION,
    })
}

pub fn pq_devnet_manifest_root(operator_label: &str) -> String {
    pq_payload_root(
        "PQ-DEVNET-MANIFEST",
        &pq_commitment_manifest(operator_label),
    )
}

fn ensure_non_empty(value: &str, label: &str) -> PqSessionResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_unique_id(ids: &BTreeSet<String>, id: &str, label: &str) -> PqSessionResult<()> {
    if ids.contains(id) {
        Err(format!("{label} id already exists: {id}"))
    } else {
        Ok(())
    }
}
