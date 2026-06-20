use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        crypto_policy_root, public_key_for_label, sign_authorization_for_role,
        sign_recovery_authorization, verify_authorization_for_role, verify_recovery_authorization,
        Authorization, CryptoRole, RecoveryAuthorization,
    },
    hash::{domain_hash, merkle_root, HashPart},
    ACCOUNT_SIGNATURE_SCHEME, CHAIN_ID, RECOVERY_SIGNATURE_SCHEME,
};

pub type QuantumResult<T> = Result<T, String>;

pub const QUANTUM_PROTOCOL_VERSION: &str = "nebula-l2-quantum-lifecycle-v1";
pub const QUANTUM_POLICY_VERSION: u64 = 1;
pub const QUANTUM_ML_DSA_SCHEME: &str = ACCOUNT_SIGNATURE_SCHEME;
pub const QUANTUM_SLH_DSA_SCHEME: &str = RECOVERY_SIGNATURE_SCHEME;
pub const QUANTUM_KEM_SCHEME: &str = "ML-KEM-768";
pub const QUANTUM_HYBRID_AUTH_SCHEME: &str = "ML-DSA-65+SLH-DSA-SHAKE-128s+ML-KEM-768";
pub const QUANTUM_PROOF_OF_POSSESSION_SYSTEM: &str = "devnet-pq-proof-of-possession-v1";
pub const QUANTUM_DEVNET_AUDIT_VERSION: &str = "nebula-l2-quantum-devnet-audit-v1";
pub const QUANTUM_DEFAULT_KEY_TTL_BLOCKS: u64 = 20_160;
pub const QUANTUM_DEFAULT_ROTATION_DELAY_BLOCKS: u64 = 20;
pub const QUANTUM_DEFAULT_RECOVERY_DELAY_BLOCKS: u64 = 100;
pub const QUANTUM_DEFAULT_COMPROMISE_FREEZE_BLOCKS: u64 = 720;
pub const QUANTUM_MAX_KEYS_PER_KEYSET: usize = 32;
pub const QUANTUM_MAX_RECOVERY_GUARDIANS: usize = 16;
pub const QUANTUM_MAX_MIGRATION_ROLES: usize = 32;
pub const QUANTUM_MAX_DEVNET_AUDIT_FINDINGS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QuantumKeyAlgorithm {
    MlDsa65,
    SlhDsaShake128s,
    MlKem768,
}

impl QuantumKeyAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MlDsa65 => QUANTUM_ML_DSA_SCHEME,
            Self::SlhDsaShake128s => QUANTUM_SLH_DSA_SCHEME,
            Self::MlKem768 => QUANTUM_KEM_SCHEME,
        }
    }

    pub fn standard(&self) -> &'static str {
        match self {
            Self::MlDsa65 => "NIST FIPS 204",
            Self::SlhDsaShake128s => "NIST FIPS 205",
            Self::MlKem768 => "NIST FIPS 203",
        }
    }

    pub fn key_family(&self) -> &'static str {
        match self {
            Self::MlDsa65 => "signature",
            Self::SlhDsaShake128s => "recovery_signature",
            Self::MlKem768 => "key_establishment",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QuantumKeyRole {
    Account,
    Validator,
    Prover,
    Watchtower,
    Network,
    Recovery,
    KeyEstablishment,
    Governance,
    BridgeSigner,
    Audit,
}

impl QuantumKeyRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Validator => "validator",
            Self::Prover => "prover",
            Self::Watchtower => "watchtower",
            Self::Network => "network",
            Self::Recovery => "recovery",
            Self::KeyEstablishment => "key_establishment",
            Self::Governance => "governance",
            Self::BridgeSigner => "bridge_signer",
            Self::Audit => "audit",
        }
    }

    pub fn default_algorithm(&self) -> QuantumKeyAlgorithm {
        match self {
            Self::Recovery => QuantumKeyAlgorithm::SlhDsaShake128s,
            Self::KeyEstablishment => QuantumKeyAlgorithm::MlKem768,
            _ => QuantumKeyAlgorithm::MlDsa65,
        }
    }

    pub fn crypto_role(&self) -> CryptoRole {
        match self {
            Self::Account => CryptoRole::AccountSignature,
            Self::Validator | Self::Governance => CryptoRole::ValidatorSignature,
            Self::Prover => CryptoRole::ProverSignature,
            Self::Watchtower | Self::Audit => CryptoRole::WatchtowerSignature,
            Self::Network | Self::BridgeSigner => CryptoRole::NetworkSignature,
            Self::Recovery => CryptoRole::RecoverySignature,
            Self::KeyEstablishment => CryptoRole::KeyEstablishment,
        }
    }

    pub fn proof_signing_role(&self) -> Self {
        match self {
            Self::KeyEstablishment => Self::Network,
            Self::BridgeSigner => Self::Network,
            Self::Governance => Self::Validator,
            Self::Audit => Self::Watchtower,
            _ => self.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QuantumRotationStage {
    Proposed,
    DualSigned,
    Accepted,
    Activated,
    Cancelled,
}

impl QuantumRotationStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::DualSigned => "dual_signed",
            Self::Accepted => "accepted",
            Self::Activated => "activated",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QuantumCompromiseEvidenceKind {
    KeyDisclosure,
    SignatureForgery,
    TranscriptReplay,
    KemDecapsulationLeak,
    OperatorReport,
    AuditFinding,
}

impl QuantumCompromiseEvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KeyDisclosure => "key_disclosure",
            Self::SignatureForgery => "signature_forgery",
            Self::TranscriptReplay => "transcript_replay",
            Self::KemDecapsulationLeak => "kem_decapsulation_leak",
            Self::OperatorReport => "operator_report",
            Self::AuditFinding => "audit_finding",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QuantumAuditSeverity {
    Info,
    Warning,
    Critical,
}

impl QuantumAuditSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumPublicKey {
    pub key_id: String,
    pub owner_label: String,
    pub role: QuantumKeyRole,
    pub algorithm: QuantumKeyAlgorithm,
    pub scheme: String,
    pub public_key: String,
    pub source_public_key_root: String,
    pub policy_root: String,
    pub metadata_root: String,
    pub rotation_nonce: u64,
    pub created_at_height: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl QuantumPublicKey {
    pub fn new(
        owner_label: impl Into<String>,
        role: QuantumKeyRole,
        rotation_nonce: u64,
        created_at_height: u64,
        activated_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> QuantumResult<Self> {
        let owner_label = owner_label.into();
        if owner_label.trim().is_empty() {
            return Err("quantum key owner label cannot be empty".to_string());
        }
        let algorithm = role.default_algorithm();
        let source_public_key = if rotation_nonce == 0 {
            public_key_for_label(role.crypto_role(), &owner_label).public_key
        } else {
            deterministic_quantum_public_key(&owner_label, &role, &algorithm, rotation_nonce)
        };
        let policy_root = quantum_policy_root();
        let metadata_root = quantum_payload_root("QUANTUM-KEY-METADATA", metadata);
        let key_id = quantum_key_id(
            &owner_label,
            role.as_str(),
            algorithm.as_str(),
            &source_public_key,
            rotation_nonce,
            &policy_root,
        );
        let source_public_key_root = quantum_string_root("source_public_key", &source_public_key);
        let key = Self {
            key_id,
            owner_label,
            role,
            scheme: algorithm.as_str().to_string(),
            algorithm,
            public_key: source_public_key,
            source_public_key_root,
            policy_root,
            metadata_root,
            rotation_nonce,
            created_at_height,
            activated_at_height,
            expires_at_height,
            status: "active".to_string(),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_public_key",
            "chain_id": CHAIN_ID,
            "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
            "key_id": self.key_id,
            "owner_label": self.owner_label,
            "role": self.role.as_str(),
            "algorithm": self.algorithm.as_str(),
            "scheme": self.scheme,
            "standard": self.algorithm.standard(),
            "key_family": self.algorithm.key_family(),
            "public_key": self.public_key,
            "source_public_key_root": self.source_public_key_root,
            "policy_root": self.policy_root,
            "metadata_root": self.metadata_root,
            "rotation_nonce": self.rotation_nonce,
            "created_at_height": self.created_at_height,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn key_root(&self) -> String {
        quantum_key_root(self)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status == "active"
            && self.activated_at_height <= height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.owner_label, "quantum key owner label")?;
        validate_nonempty(&self.public_key, "quantum public key")?;
        validate_nonempty(
            &self.source_public_key_root,
            "quantum source public key root",
        )?;
        validate_nonempty(&self.policy_root, "quantum policy root")?;
        validate_nonempty(&self.metadata_root, "quantum key metadata root")?;
        if self.scheme != self.algorithm.as_str() {
            return Err("quantum key scheme does not match algorithm".to_string());
        }
        if self.algorithm != self.role.default_algorithm() {
            return Err("quantum key algorithm does not match role".to_string());
        }
        if self.activated_at_height < self.created_at_height {
            return Err("quantum key activation precedes creation".to_string());
        }
        let expected_key_id = quantum_key_id(
            &self.owner_label,
            self.role.as_str(),
            self.algorithm.as_str(),
            &self.public_key,
            self.rotation_nonce,
            &self.policy_root,
        );
        if self.key_id != expected_key_id {
            return Err("quantum key id mismatch".to_string());
        }
        let expected_source_root = quantum_string_root("source_public_key", &self.public_key);
        if self.source_public_key_root != expected_source_root {
            return Err("quantum source public key root mismatch".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.activated_at_height {
            return Err("quantum key expiry must be after activation".to_string());
        }
        validate_status(
            &self.status,
            &["active", "staged", "retired", "compromised", "revoked"],
            "quantum key",
        )?;
        Ok(self.key_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumKeySet {
    pub keyset_id: String,
    pub owner_label: String,
    pub mldsa_keys: Vec<QuantumPublicKey>,
    pub slhdsa_keys: Vec<QuantumPublicKey>,
    pub kem_keys: Vec<QuantumPublicKey>,
    pub policy_root: String,
    pub metadata_root: String,
    pub rotation_nonce: u64,
    pub created_at_height: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl QuantumKeySet {
    pub fn build_default(
        owner_label: impl Into<String>,
        created_at_height: u64,
        metadata: &Value,
    ) -> QuantumResult<Self> {
        Self::build(
            owner_label,
            vec![
                QuantumKeyRole::Account,
                QuantumKeyRole::Validator,
                QuantumKeyRole::Prover,
                QuantumKeyRole::Watchtower,
                QuantumKeyRole::Network,
                QuantumKeyRole::Recovery,
                QuantumKeyRole::KeyEstablishment,
            ],
            0,
            created_at_height,
            created_at_height,
            created_at_height.saturating_add(QUANTUM_DEFAULT_KEY_TTL_BLOCKS),
            metadata,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build(
        owner_label: impl Into<String>,
        roles: Vec<QuantumKeyRole>,
        rotation_nonce: u64,
        created_at_height: u64,
        activated_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> QuantumResult<Self> {
        let owner_label = owner_label.into();
        validate_nonempty(&owner_label, "quantum keyset owner label")?;
        validate_role_list(&roles, "quantum keyset role")?;
        if roles.len() > QUANTUM_MAX_KEYS_PER_KEYSET {
            return Err("quantum keyset has too many keys".to_string());
        }
        let mut mldsa_keys = Vec::new();
        let mut slhdsa_keys = Vec::new();
        let mut kem_keys = Vec::new();
        for role in roles {
            let key = QuantumPublicKey::new(
                owner_label.clone(),
                role,
                rotation_nonce,
                created_at_height,
                activated_at_height,
                expires_at_height,
                metadata,
            )?;
            match key.algorithm {
                QuantumKeyAlgorithm::MlDsa65 => mldsa_keys.push(key),
                QuantumKeyAlgorithm::SlhDsaShake128s => slhdsa_keys.push(key),
                QuantumKeyAlgorithm::MlKem768 => kem_keys.push(key),
            }
        }
        let policy_root = quantum_policy_root();
        let metadata_root = quantum_payload_root("QUANTUM-KEYSET-METADATA", metadata);
        let mut keyset = Self {
            keyset_id: String::new(),
            owner_label,
            mldsa_keys,
            slhdsa_keys,
            kem_keys,
            policy_root,
            metadata_root,
            rotation_nonce,
            created_at_height,
            activated_at_height,
            expires_at_height,
            status: "active".to_string(),
        };
        keyset.keyset_id = quantum_keyset_id(
            &keyset.owner_label,
            &keyset.key_root(),
            &keyset.policy_root,
            keyset.rotation_nonce,
        );
        keyset.validate()?;
        Ok(keyset)
    }

    pub fn all_keys(&self) -> Vec<QuantumPublicKey> {
        self.mldsa_keys
            .iter()
            .chain(self.slhdsa_keys.iter())
            .chain(self.kem_keys.iter())
            .cloned()
            .collect()
    }

    pub fn key_for_role(&self, role: QuantumKeyRole) -> Option<QuantumPublicKey> {
        self.all_keys()
            .into_iter()
            .find(|key| key.role == role && key.status == "active")
    }

    pub fn key_root(&self) -> String {
        let mut keys = self
            .all_keys()
            .into_iter()
            .map(|key| key.public_record())
            .collect::<Vec<_>>();
        keys.sort_by(|left, right| {
            left["key_id"]
                .as_str()
                .unwrap_or_default()
                .cmp(right["key_id"].as_str().unwrap_or_default())
        });
        merkle_root("QUANTUM-KEYSET-KEY", &keys)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_keyset",
            "chain_id": CHAIN_ID,
            "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
            "keyset_id": self.keyset_id,
            "owner_label": self.owner_label,
            "key_root": self.key_root(),
            "mldsa_key_count": self.mldsa_keys.len() as u64,
            "slhdsa_key_count": self.slhdsa_keys.len() as u64,
            "kem_key_count": self.kem_keys.len() as u64,
            "mldsa_root": quantum_key_list_root("QUANTUM-KEYSET-ML-DSA", &self.mldsa_keys),
            "slhdsa_root": quantum_key_list_root("QUANTUM-KEYSET-SLH-DSA", &self.slhdsa_keys),
            "kem_root": quantum_key_list_root("QUANTUM-KEYSET-KEM", &self.kem_keys),
            "policy_root": self.policy_root,
            "metadata_root": self.metadata_root,
            "rotation_nonce": self.rotation_nonce,
            "created_at_height": self.created_at_height,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn keyset_root(&self) -> String {
        domain_hash(
            "QUANTUM-KEYSET",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.owner_label, "quantum keyset owner label")?;
        validate_nonempty(&self.policy_root, "quantum keyset policy root")?;
        validate_nonempty(&self.metadata_root, "quantum keyset metadata root")?;
        validate_status(
            &self.status,
            &["active", "staged", "retired", "compromised", "revoked"],
            "quantum keyset",
        )?;
        let keys = self.all_keys();
        if keys.is_empty() {
            return Err("quantum keyset requires at least one key".to_string());
        }
        if keys.len() > QUANTUM_MAX_KEYS_PER_KEYSET {
            return Err("quantum keyset has too many keys".to_string());
        }
        if self.activated_at_height < self.created_at_height {
            return Err("quantum keyset activation precedes creation".to_string());
        }
        let mut seen_roles = BTreeSet::new();
        let mut seen_ids = BTreeSet::new();
        for key in &keys {
            key.validate()?;
            if key.owner_label != self.owner_label {
                return Err("quantum keyset owner mismatch".to_string());
            }
            if key.policy_root != self.policy_root {
                return Err("quantum keyset policy root mismatch".to_string());
            }
            if key.rotation_nonce != self.rotation_nonce {
                return Err("quantum keyset rotation nonce mismatch".to_string());
            }
            if !seen_roles.insert(key.role.clone()) {
                return Err("quantum keyset contains duplicate role".to_string());
            }
            if !seen_ids.insert(key.key_id.clone()) {
                return Err("quantum keyset contains duplicate key id".to_string());
            }
        }
        let expected_keyset_id = quantum_keyset_id(
            &self.owner_label,
            &self.key_root(),
            &self.policy_root,
            self.rotation_nonce,
        );
        if self.keyset_id != expected_keyset_id {
            return Err("quantum keyset id mismatch".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.activated_at_height {
            return Err("quantum keyset expiry must be after activation".to_string());
        }
        Ok(self.keyset_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumSignatureWitness {
    pub signer_label: String,
    pub signer_role: QuantumKeyRole,
    pub scheme: String,
    pub public_key: String,
    pub transcript_hash: String,
    pub signature: String,
}

impl QuantumSignatureWitness {
    pub fn from_authorization(signer_role: QuantumKeyRole, authorization: Authorization) -> Self {
        Self {
            signer_label: authorization.signer_label,
            signer_role,
            scheme: authorization.auth_scheme,
            public_key: authorization.auth_public_key,
            transcript_hash: authorization.auth_transcript_hash,
            signature: authorization.auth_signature,
        }
    }

    pub fn from_recovery(
        signer_role: QuantumKeyRole,
        authorization: RecoveryAuthorization,
    ) -> Self {
        Self {
            signer_label: authorization.recovery_label,
            signer_role,
            scheme: authorization.recovery_scheme,
            public_key: authorization.recovery_public_key,
            transcript_hash: authorization.recovery_transcript_hash,
            signature: authorization.recovery_signature,
        }
    }

    pub fn authorization(&self) -> Authorization {
        Authorization {
            signer_label: self.signer_label.clone(),
            auth_scheme: self.scheme.clone(),
            auth_public_key: self.public_key.clone(),
            auth_transcript_hash: self.transcript_hash.clone(),
            auth_signature: self.signature.clone(),
        }
    }

    pub fn recovery_authorization(&self) -> RecoveryAuthorization {
        RecoveryAuthorization {
            recovery_label: self.signer_label.clone(),
            recovery_scheme: self.scheme.clone(),
            recovery_public_key: self.public_key.clone(),
            recovery_transcript_hash: self.transcript_hash.clone(),
            recovery_signature: self.signature.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_signature_witness",
            "chain_id": CHAIN_ID,
            "signer_label": self.signer_label,
            "signer_role": self.signer_role.as_str(),
            "scheme": self.scheme,
            "public_key": self.public_key,
            "transcript_hash": self.transcript_hash,
            "signature": self.signature,
        })
    }

    pub fn witness_root(&self) -> String {
        domain_hash(
            "QUANTUM-SIGNATURE-WITNESS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn verify(&self, domain: &str, payload: &Value) -> bool {
        if self.signer_role == QuantumKeyRole::Recovery {
            verify_recovery_authorization(
                &self.signer_label,
                domain,
                payload,
                &self.recovery_authorization(),
            )
        } else {
            verify_authorization_for_role(
                self.signer_role.crypto_role(),
                &self.public_key,
                domain,
                payload,
                &self.authorization(),
            )
        }
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.signer_label, "quantum witness signer label")?;
        validate_nonempty(&self.scheme, "quantum witness scheme")?;
        validate_nonempty(&self.public_key, "quantum witness public key")?;
        validate_nonempty(&self.transcript_hash, "quantum witness transcript hash")?;
        validate_nonempty(&self.signature, "quantum witness signature")?;
        Ok(self.witness_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfPossessionTranscript {
    pub transcript_id: String,
    pub key_id: String,
    pub owner_label: String,
    pub subject_role: QuantumKeyRole,
    pub subject_algorithm: QuantumKeyAlgorithm,
    pub subject_public_key: String,
    pub challenge_root: String,
    pub transcript_hash: String,
    pub proof_system: String,
    pub produced_at_height: u64,
    pub expires_at_height: u64,
    pub signer: QuantumSignatureWitness,
    pub status: String,
}

impl ProofOfPossessionTranscript {
    pub fn build(
        key: &QuantumPublicKey,
        challenge: &Value,
        produced_at_height: u64,
        expires_at_height: u64,
    ) -> QuantumResult<Self> {
        key.validate()?;
        let challenge_root = quantum_payload_root("QUANTUM-POP-CHALLENGE", challenge);
        let transcript_hash = quantum_proof_of_possession_transcript_hash(
            &key.key_id,
            key.role.as_str(),
            key.algorithm.as_str(),
            &key.public_key,
            &challenge_root,
            produced_at_height,
            expires_at_height,
        );
        let mut transcript = Self {
            transcript_id: String::new(),
            key_id: key.key_id.clone(),
            owner_label: key.owner_label.clone(),
            subject_role: key.role.clone(),
            subject_algorithm: key.algorithm.clone(),
            subject_public_key: key.public_key.clone(),
            challenge_root,
            transcript_hash,
            proof_system: QUANTUM_PROOF_OF_POSSESSION_SYSTEM.to_string(),
            produced_at_height,
            expires_at_height,
            signer: empty_quantum_signature_witness(
                &key.owner_label,
                key.role.proof_signing_role(),
            ),
            status: "valid".to_string(),
        };
        let signer_role = key.role.proof_signing_role();
        transcript.signer = quantum_signature_witness(
            &key.owner_label,
            signer_role,
            "quantum_proof_of_possession",
            &transcript.unsigned_record(),
        );
        transcript.transcript_id = quantum_proof_of_possession_id(
            &transcript.key_id,
            &transcript.transcript_hash,
            &transcript.signer.witness_root(),
        );
        transcript.validate()?;
        Ok(transcript)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "quantum_proof_of_possession_transcript",
            "chain_id": CHAIN_ID,
            "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
            "key_id": self.key_id,
            "owner_label": self.owner_label,
            "subject_role": self.subject_role.as_str(),
            "subject_algorithm": self.subject_algorithm.as_str(),
            "subject_public_key": self.subject_public_key,
            "challenge_root": self.challenge_root,
            "transcript_hash": self.transcript_hash,
            "proof_system": self.proof_system,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("proof of possession record object");
        object.insert(
            "transcript_id".to_string(),
            Value::String(self.transcript_id.clone()),
        );
        object.insert("signer".to_string(), self.signer.public_record());
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn transcript_root(&self) -> String {
        domain_hash(
            "QUANTUM-PROOF-OF-POSSESSION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate_for_key(&self, key: &QuantumPublicKey) -> QuantumResult<String> {
        if self.key_id != key.key_id
            || self.owner_label != key.owner_label
            || self.subject_role != key.role
            || self.subject_algorithm != key.algorithm
            || self.subject_public_key != key.public_key
        {
            return Err("quantum proof of possession key mismatch".to_string());
        }
        self.validate()
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.transcript_id, "quantum POP transcript id")?;
        validate_nonempty(&self.key_id, "quantum POP key id")?;
        validate_nonempty(&self.owner_label, "quantum POP owner label")?;
        validate_nonempty(&self.subject_public_key, "quantum POP subject public key")?;
        validate_nonempty(&self.challenge_root, "quantum POP challenge root")?;
        validate_nonempty(&self.transcript_hash, "quantum POP transcript hash")?;
        validate_nonempty(&self.proof_system, "quantum POP proof system")?;
        self.signer.validate()?;
        if self.signer.signer_label != self.owner_label {
            return Err("quantum POP signer label mismatch".to_string());
        }
        if self.signer.signer_role != self.subject_role.proof_signing_role() {
            return Err("quantum POP signer role mismatch".to_string());
        }
        let expected_hash = quantum_proof_of_possession_transcript_hash(
            &self.key_id,
            self.subject_role.as_str(),
            self.subject_algorithm.as_str(),
            &self.subject_public_key,
            &self.challenge_root,
            self.produced_at_height,
            self.expires_at_height,
        );
        if self.transcript_hash != expected_hash {
            return Err("quantum POP transcript hash mismatch".to_string());
        }
        let expected_id = quantum_proof_of_possession_id(
            &self.key_id,
            &self.transcript_hash,
            &self.signer.witness_root(),
        );
        if self.transcript_id != expected_id {
            return Err("quantum POP transcript id mismatch".to_string());
        }
        if !self
            .signer
            .verify("quantum_proof_of_possession", &self.unsigned_record())
        {
            return Err("quantum POP signature verification failed".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.produced_at_height {
            return Err("quantum POP expiry must be after production height".to_string());
        }
        validate_status(
            &self.status,
            &["valid", "revoked", "expired"],
            "quantum POP",
        )?;
        Ok(self.transcript_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumKemEnvelope {
    pub scheme: String,
    pub recipient_key_id: String,
    pub recipient_public_key_root: String,
    pub context_root: String,
    pub ciphertext_hash: String,
    pub shared_secret_commitment: String,
    pub transcript_hash: String,
    pub encapsulated_at_height: u64,
    pub expires_at_height: u64,
    pub policy_root: String,
}

impl QuantumKemEnvelope {
    pub fn build(
        recipient_key_id: impl Into<String>,
        recipient_public_key_root: impl Into<String>,
        context: &Value,
        encapsulated_at_height: u64,
        expires_at_height: u64,
    ) -> QuantumResult<Self> {
        let recipient_key_id = recipient_key_id.into();
        let recipient_public_key_root = recipient_public_key_root.into();
        validate_nonempty(&recipient_key_id, "KEM recipient key id")?;
        validate_nonempty(&recipient_public_key_root, "KEM recipient public key root")?;
        let context_root = quantum_payload_root("QUANTUM-KEM-CONTEXT", context);
        let transcript_hash = quantum_kem_transcript_hash(
            &recipient_key_id,
            &recipient_public_key_root,
            &context_root,
            encapsulated_at_height,
            expires_at_height,
        );
        let ciphertext_hash = quantum_kem_ciphertext_hash(
            &recipient_key_id,
            &recipient_public_key_root,
            &transcript_hash,
        );
        let shared_secret_commitment =
            quantum_kem_shared_secret_commitment(&recipient_key_id, &transcript_hash);
        let envelope = Self {
            scheme: QUANTUM_KEM_SCHEME.to_string(),
            recipient_key_id,
            recipient_public_key_root,
            context_root,
            ciphertext_hash,
            shared_secret_commitment,
            transcript_hash,
            encapsulated_at_height,
            expires_at_height,
            policy_root: quantum_policy_root(),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_kem_envelope",
            "chain_id": CHAIN_ID,
            "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
            "scheme": self.scheme,
            "recipient_key_id": self.recipient_key_id,
            "recipient_public_key_root": self.recipient_public_key_root,
            "context_root": self.context_root,
            "ciphertext_hash": self.ciphertext_hash,
            "shared_secret_commitment": self.shared_secret_commitment,
            "transcript_hash": self.transcript_hash,
            "encapsulated_at_height": self.encapsulated_at_height,
            "expires_at_height": self.expires_at_height,
            "policy_root": self.policy_root,
        })
    }

    pub fn envelope_root(&self) -> String {
        domain_hash(
            "QUANTUM-KEM-ENVELOPE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> QuantumResult<String> {
        if self.scheme != QUANTUM_KEM_SCHEME {
            return Err("quantum KEM envelope scheme mismatch".to_string());
        }
        validate_nonempty(&self.recipient_key_id, "KEM recipient key id")?;
        validate_nonempty(
            &self.recipient_public_key_root,
            "KEM recipient public key root",
        )?;
        validate_nonempty(&self.context_root, "KEM context root")?;
        validate_nonempty(&self.policy_root, "KEM policy root")?;
        let expected_transcript = quantum_kem_transcript_hash(
            &self.recipient_key_id,
            &self.recipient_public_key_root,
            &self.context_root,
            self.encapsulated_at_height,
            self.expires_at_height,
        );
        if self.transcript_hash != expected_transcript {
            return Err("quantum KEM transcript hash mismatch".to_string());
        }
        let expected_ciphertext = quantum_kem_ciphertext_hash(
            &self.recipient_key_id,
            &self.recipient_public_key_root,
            &self.transcript_hash,
        );
        if self.ciphertext_hash != expected_ciphertext {
            return Err("quantum KEM ciphertext hash mismatch".to_string());
        }
        let expected_secret =
            quantum_kem_shared_secret_commitment(&self.recipient_key_id, &self.transcript_hash);
        if self.shared_secret_commitment != expected_secret {
            return Err("quantum KEM shared secret commitment mismatch".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.encapsulated_at_height {
            return Err("quantum KEM expiry must be after encapsulation height".to_string());
        }
        Ok(self.envelope_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridAuthorizationBundle {
    pub authorization_id: String,
    pub scheme: String,
    pub signer_label: String,
    pub domain: String,
    pub payload_root: String,
    pub ml_dsa: QuantumSignatureWitness,
    pub slh_dsa: QuantumSignatureWitness,
    pub kem_envelope: QuantumKemEnvelope,
    pub required_signature_count: u64,
    pub produced_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl HybridAuthorizationBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        signer_label: impl Into<String>,
        domain: impl Into<String>,
        payload: &Value,
        kem_recipient_key_id: &str,
        kem_recipient_public_key_root: &str,
        produced_at_height: u64,
        expires_at_height: u64,
    ) -> QuantumResult<Self> {
        let signer_label = signer_label.into();
        let domain = domain.into();
        validate_nonempty(&signer_label, "hybrid authorization signer label")?;
        validate_nonempty(&domain, "hybrid authorization domain")?;
        let payload_root = quantum_payload_root("QUANTUM-HYBRID-AUTH-PAYLOAD", payload);
        let ml_dsa =
            quantum_signature_witness(&signer_label, QuantumKeyRole::Account, &domain, payload);
        let slh_dsa =
            quantum_signature_witness(&signer_label, QuantumKeyRole::Recovery, &domain, payload);
        let kem_context = json!({
            "kind": "hybrid_authorization_kem_context",
            "chain_id": CHAIN_ID,
            "domain": domain,
            "payload_root": payload_root,
            "ml_dsa_witness_root": ml_dsa.witness_root(),
            "slh_dsa_witness_root": slh_dsa.witness_root(),
        });
        let kem_envelope = QuantumKemEnvelope::build(
            kem_recipient_key_id,
            kem_recipient_public_key_root,
            &kem_context,
            produced_at_height,
            expires_at_height,
        )?;
        let authorization_id = quantum_hybrid_authorization_id(
            &signer_label,
            &domain,
            &payload_root,
            &ml_dsa.witness_root(),
            &slh_dsa.witness_root(),
            &kem_envelope.envelope_root(),
        );
        let bundle = Self {
            authorization_id,
            scheme: QUANTUM_HYBRID_AUTH_SCHEME.to_string(),
            signer_label,
            domain,
            payload_root,
            ml_dsa,
            slh_dsa,
            kem_envelope,
            required_signature_count: 2,
            produced_at_height,
            expires_at_height,
            status: "valid".to_string(),
        };
        bundle.validate_for_payload(payload)?;
        Ok(bundle)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_hybrid_authorization_bundle",
            "chain_id": CHAIN_ID,
            "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "scheme": self.scheme,
            "signer_label": self.signer_label,
            "domain": self.domain,
            "payload_root": self.payload_root,
            "ml_dsa": self.ml_dsa.public_record(),
            "slh_dsa": self.slh_dsa.public_record(),
            "kem_envelope": self.kem_envelope.public_record(),
            "required_signature_count": self.required_signature_count,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn bundle_root(&self) -> String {
        domain_hash(
            "QUANTUM-HYBRID-AUTHORIZATION-BUNDLE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate_for_payload(&self, payload: &Value) -> QuantumResult<String> {
        self.validate()?;
        let expected_payload_root = quantum_payload_root("QUANTUM-HYBRID-AUTH-PAYLOAD", payload);
        if self.payload_root != expected_payload_root {
            return Err("hybrid authorization payload root mismatch".to_string());
        }
        if !self.ml_dsa.verify(&self.domain, payload) {
            return Err("hybrid authorization ML-DSA witness failed".to_string());
        }
        if !self.slh_dsa.verify(&self.domain, payload) {
            return Err("hybrid authorization SLH-DSA witness failed".to_string());
        }
        Ok(self.bundle_root())
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.authorization_id, "hybrid authorization id")?;
        if self.scheme != QUANTUM_HYBRID_AUTH_SCHEME {
            return Err("hybrid authorization scheme mismatch".to_string());
        }
        validate_nonempty(&self.signer_label, "hybrid authorization signer label")?;
        validate_nonempty(&self.domain, "hybrid authorization domain")?;
        validate_nonempty(&self.payload_root, "hybrid authorization payload root")?;
        self.ml_dsa.validate()?;
        self.slh_dsa.validate()?;
        self.kem_envelope.validate()?;
        if self.ml_dsa.signer_label != self.signer_label
            || self.slh_dsa.signer_label != self.signer_label
        {
            return Err("hybrid authorization signer mismatch".to_string());
        }
        if self.ml_dsa.signer_role != QuantumKeyRole::Account {
            return Err("hybrid authorization ML-DSA role mismatch".to_string());
        }
        if self.slh_dsa.signer_role != QuantumKeyRole::Recovery {
            return Err("hybrid authorization SLH-DSA role mismatch".to_string());
        }
        if self.required_signature_count < 2 {
            return Err("hybrid authorization requires both signatures".to_string());
        }
        let expected_id = quantum_hybrid_authorization_id(
            &self.signer_label,
            &self.domain,
            &self.payload_root,
            &self.ml_dsa.witness_root(),
            &self.slh_dsa.witness_root(),
            &self.kem_envelope.envelope_root(),
        );
        if self.authorization_id != expected_id {
            return Err("hybrid authorization id mismatch".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.produced_at_height {
            return Err("hybrid authorization expiry must be after production height".to_string());
        }
        validate_status(
            &self.status,
            &["valid", "spent", "revoked", "expired"],
            "hybrid authorization",
        )?;
        Ok(self.bundle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleKeyRotationCeremony {
    pub ceremony_id: String,
    pub owner_label: String,
    pub role: QuantumKeyRole,
    pub previous_key_id: String,
    pub previous_key_root: String,
    pub next_key: QuantumPublicKey,
    pub proof_of_possession: ProofOfPossessionTranscript,
    pub hybrid_authorization: HybridAuthorizationBundle,
    pub rotation_nonce: u64,
    pub requested_at_height: u64,
    pub activate_at_height: u64,
    pub expires_at_height: u64,
    pub reason_root: String,
    pub stage: QuantumRotationStage,
    pub status: String,
}

impl RoleKeyRotationCeremony {
    pub fn build(
        previous_key: &QuantumPublicKey,
        reason: &Value,
        requested_at_height: u64,
    ) -> QuantumResult<Self> {
        previous_key.validate()?;
        let activate_at_height =
            requested_at_height.saturating_add(QUANTUM_DEFAULT_ROTATION_DELAY_BLOCKS);
        let expires_at_height = activate_at_height.saturating_add(QUANTUM_DEFAULT_KEY_TTL_BLOCKS);
        let next_key = QuantumPublicKey::new(
            previous_key.owner_label.clone(),
            previous_key.role.clone(),
            previous_key.rotation_nonce.saturating_add(1),
            requested_at_height,
            activate_at_height,
            expires_at_height,
            reason,
        )?;
        Self::build_with_next_key(previous_key, next_key, reason, requested_at_height)
    }

    pub fn build_with_next_key(
        previous_key: &QuantumPublicKey,
        next_key: QuantumPublicKey,
        reason: &Value,
        requested_at_height: u64,
    ) -> QuantumResult<Self> {
        previous_key.validate()?;
        next_key.validate()?;
        if next_key.owner_label != previous_key.owner_label {
            return Err("rotation next key owner mismatch".to_string());
        }
        if next_key.role != previous_key.role {
            return Err("rotation next key role mismatch".to_string());
        }
        if next_key.rotation_nonce != previous_key.rotation_nonce.saturating_add(1) {
            return Err("rotation next key nonce mismatch".to_string());
        }
        let reason_root = quantum_payload_root("QUANTUM-ROTATION-REASON", reason);
        let proof_challenge = json!({
            "kind": "role_key_rotation_pop_challenge",
            "previous_key_id": previous_key.key_id,
            "previous_key_root": previous_key.key_root(),
            "next_key_id": next_key.key_id,
            "reason_root": reason_root,
        });
        let proof_of_possession = ProofOfPossessionTranscript::build(
            &next_key,
            &proof_challenge,
            requested_at_height,
            next_key.expires_at_height,
        )?;
        let unsigned = role_key_rotation_unsigned_record(
            &previous_key.owner_label,
            &previous_key.role,
            &previous_key.key_id,
            &previous_key.key_root(),
            &next_key.public_record(),
            &proof_of_possession.transcript_root(),
            next_key.rotation_nonce,
            requested_at_height,
            next_key.activated_at_height,
            next_key.expires_at_height,
            &reason_root,
        );
        let hybrid_authorization = HybridAuthorizationBundle::build(
            &previous_key.owner_label,
            "quantum_role_key_rotation",
            &unsigned,
            &next_key.key_id,
            &next_key.key_root(),
            requested_at_height,
            next_key.expires_at_height,
        )?;
        let ceremony_id = quantum_rotation_ceremony_id(
            &previous_key.owner_label,
            previous_key.role.as_str(),
            &previous_key.key_id,
            &next_key.key_id,
            next_key.rotation_nonce,
        );
        let ceremony = Self {
            ceremony_id,
            owner_label: previous_key.owner_label.clone(),
            role: previous_key.role.clone(),
            previous_key_id: previous_key.key_id.clone(),
            previous_key_root: previous_key.key_root(),
            next_key,
            proof_of_possession,
            hybrid_authorization,
            rotation_nonce: previous_key.rotation_nonce.saturating_add(1),
            requested_at_height,
            activate_at_height: unsigned["activate_at_height"]
                .as_u64()
                .expect("rotation activation height"),
            expires_at_height: unsigned["expires_at_height"]
                .as_u64()
                .expect("rotation expiry height"),
            reason_root,
            stage: QuantumRotationStage::DualSigned,
            status: "pending".to_string(),
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    pub fn unsigned_record(&self) -> Value {
        role_key_rotation_unsigned_record(
            &self.owner_label,
            &self.role,
            &self.previous_key_id,
            &self.previous_key_root,
            &self.next_key.public_record(),
            &self.proof_of_possession.transcript_root(),
            self.rotation_nonce,
            self.requested_at_height,
            self.activate_at_height,
            self.expires_at_height,
            &self.reason_root,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("role key rotation ceremony public record object");
        object.insert(
            "ceremony_id".to_string(),
            Value::String(self.ceremony_id.clone()),
        );
        object.insert(
            "proof_of_possession".to_string(),
            self.proof_of_possession.public_record(),
        );
        object.insert(
            "hybrid_authorization".to_string(),
            self.hybrid_authorization.public_record(),
        );
        object.insert(
            "stage".to_string(),
            Value::String(self.stage.as_str().to_string()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn ceremony_root(&self) -> String {
        domain_hash(
            "QUANTUM-ROLE-KEY-ROTATION-CEREMONY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.ceremony_id, "rotation ceremony id")?;
        validate_nonempty(&self.owner_label, "rotation ceremony owner label")?;
        validate_nonempty(&self.previous_key_id, "rotation previous key id")?;
        validate_nonempty(&self.previous_key_root, "rotation previous key root")?;
        validate_nonempty(&self.reason_root, "rotation reason root")?;
        self.next_key.validate()?;
        if self.next_key.owner_label != self.owner_label {
            return Err("rotation next key owner mismatch".to_string());
        }
        if self.next_key.role != self.role {
            return Err("rotation next key role mismatch".to_string());
        }
        if self.next_key.rotation_nonce != self.rotation_nonce {
            return Err("rotation nonce mismatch".to_string());
        }
        self.proof_of_possession.validate_for_key(&self.next_key)?;
        self.hybrid_authorization
            .validate_for_payload(&self.unsigned_record())?;
        let expected_id = quantum_rotation_ceremony_id(
            &self.owner_label,
            self.role.as_str(),
            &self.previous_key_id,
            &self.next_key.key_id,
            self.rotation_nonce,
        );
        if self.ceremony_id != expected_id {
            return Err("rotation ceremony id mismatch".to_string());
        }
        if self.activate_at_height < self.requested_at_height {
            return Err("rotation activation precedes request height".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.activate_at_height {
            return Err("rotation expiry must be after activation".to_string());
        }
        validate_status(
            &self.status,
            &["pending", "applied", "cancelled"],
            "rotation",
        )?;
        Ok(self.ceremony_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumMigrationEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub migration_name: String,
    pub source_policy_root: String,
    pub target_policy_root: String,
    pub required_roles: Vec<QuantumKeyRole>,
    pub keyset_root: String,
    pub ceremony_root: String,
    pub dual_authorization_start_height: u64,
    pub activation_height: u64,
    pub deprecation_height: u64,
    pub rollback_root: String,
    pub audit_record_root: String,
    pub status: String,
}

impl QuantumMigrationEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_index: u64,
        migration_name: impl Into<String>,
        source_policy_root: impl Into<String>,
        target_policy_root: impl Into<String>,
        required_roles: Vec<QuantumKeyRole>,
        dual_authorization_start_height: u64,
        activation_height: u64,
        deprecation_height: u64,
        rollback: &Value,
    ) -> QuantumResult<Self> {
        let migration_name = migration_name.into();
        let source_policy_root = source_policy_root.into();
        let target_policy_root = target_policy_root.into();
        validate_role_list(&required_roles, "migration role")?;
        let rollback_root = quantum_payload_root("QUANTUM-MIGRATION-ROLLBACK", rollback);
        let epoch_id = quantum_migration_epoch_id(
            epoch_index,
            &migration_name,
            &source_policy_root,
            &target_policy_root,
            &role_list_root(&required_roles),
        );
        let epoch = Self {
            epoch_id,
            epoch_index,
            migration_name,
            source_policy_root,
            target_policy_root,
            required_roles,
            keyset_root: merkle_root("QUANTUM-MIGRATION-EMPTY-KEYSET", &[]),
            ceremony_root: merkle_root("QUANTUM-MIGRATION-EMPTY-CEREMONY", &[]),
            dual_authorization_start_height,
            activation_height,
            deprecation_height,
            rollback_root,
            audit_record_root: merkle_root("QUANTUM-MIGRATION-EMPTY-AUDIT", &[]),
            status: "scheduled".to_string(),
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_migration_epoch",
            "chain_id": CHAIN_ID,
            "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "migration_name": self.migration_name,
            "source_policy_root": self.source_policy_root,
            "target_policy_root": self.target_policy_root,
            "required_role_root": role_list_root(&self.required_roles),
            "required_roles": self.required_roles.iter().map(QuantumKeyRole::as_str).collect::<Vec<_>>(),
            "keyset_root": self.keyset_root,
            "ceremony_root": self.ceremony_root,
            "dual_authorization_start_height": self.dual_authorization_start_height,
            "activation_height": self.activation_height,
            "deprecation_height": self.deprecation_height,
            "rollback_root": self.rollback_root,
            "audit_record_root": self.audit_record_root,
            "status": self.status,
        })
    }

    pub fn epoch_root(&self) -> String {
        domain_hash(
            "QUANTUM-MIGRATION-EPOCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.epoch_id, "migration epoch id")?;
        validate_nonempty(&self.migration_name, "migration name")?;
        validate_nonempty(&self.source_policy_root, "migration source policy root")?;
        validate_nonempty(&self.target_policy_root, "migration target policy root")?;
        validate_nonempty(&self.rollback_root, "migration rollback root")?;
        validate_nonempty(&self.audit_record_root, "migration audit record root")?;
        validate_role_list(&self.required_roles, "migration role")?;
        if self.required_roles.len() > QUANTUM_MAX_MIGRATION_ROLES {
            return Err("migration epoch has too many roles".to_string());
        }
        if self.dual_authorization_start_height > self.activation_height {
            return Err("migration dual authorization starts after activation".to_string());
        }
        if self.activation_height > self.deprecation_height {
            return Err("migration activation exceeds deprecation height".to_string());
        }
        let expected_id = quantum_migration_epoch_id(
            self.epoch_index,
            &self.migration_name,
            &self.source_policy_root,
            &self.target_policy_root,
            &role_list_root(&self.required_roles),
        );
        if self.epoch_id != expected_id {
            return Err("migration epoch id mismatch".to_string());
        }
        validate_status(
            &self.status,
            &[
                "scheduled",
                "dual_authorization",
                "active",
                "deprecated",
                "rolled_back",
            ],
            "migration epoch",
        )?;
        Ok(self.epoch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumCompromiseEvidence {
    pub evidence_id: String,
    pub key_id: String,
    pub keyset_id: String,
    pub owner_label: String,
    pub role: QuantumKeyRole,
    pub evidence_kind: QuantumCompromiseEvidenceKind,
    pub severity: QuantumAuditSeverity,
    pub observed_at_height: u64,
    pub reporter_label: String,
    pub compromised_artifact_root: String,
    pub transcript_root: String,
    pub recommended_response: String,
    pub freeze_until_height: u64,
    pub authorization: QuantumSignatureWitness,
    pub status: String,
}

impl QuantumCompromiseEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        key: &QuantumPublicKey,
        keyset_id: impl Into<String>,
        evidence_kind: QuantumCompromiseEvidenceKind,
        severity: QuantumAuditSeverity,
        reporter_label: impl Into<String>,
        compromised_artifact: &Value,
        transcript: &Value,
        observed_at_height: u64,
    ) -> QuantumResult<Self> {
        key.validate()?;
        let keyset_id = keyset_id.into();
        let reporter_label = reporter_label.into();
        validate_nonempty(&keyset_id, "compromise evidence keyset id")?;
        validate_nonempty(&reporter_label, "compromise evidence reporter label")?;
        let compromised_artifact_root =
            quantum_payload_root("QUANTUM-COMPROMISED-ARTIFACT", compromised_artifact);
        let transcript_root = quantum_payload_root("QUANTUM-COMPROMISE-TRANSCRIPT", transcript);
        let freeze_until_height =
            observed_at_height.saturating_add(QUANTUM_DEFAULT_COMPROMISE_FREEZE_BLOCKS);
        let recommended_response = match severity {
            QuantumAuditSeverity::Critical => "freeze_and_rotate".to_string(),
            QuantumAuditSeverity::Warning => "rotate_before_next_epoch".to_string(),
            QuantumAuditSeverity::Info => "monitor".to_string(),
        };
        let evidence_id = quantum_compromise_evidence_id(
            &key.key_id,
            evidence_kind.as_str(),
            &compromised_artifact_root,
            &transcript_root,
            observed_at_height,
        );
        let mut evidence = Self {
            evidence_id,
            key_id: key.key_id.clone(),
            keyset_id,
            owner_label: key.owner_label.clone(),
            role: key.role.clone(),
            evidence_kind,
            severity,
            observed_at_height,
            reporter_label,
            compromised_artifact_root,
            transcript_root,
            recommended_response,
            freeze_until_height,
            authorization: empty_quantum_signature_witness("", QuantumKeyRole::Watchtower),
            status: "open".to_string(),
        };
        evidence.authorization = quantum_signature_witness(
            &evidence.reporter_label,
            QuantumKeyRole::Watchtower,
            "quantum_compromise_evidence",
            &evidence.unsigned_record(),
        );
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "quantum_compromise_evidence",
            "chain_id": CHAIN_ID,
            "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "key_id": self.key_id,
            "keyset_id": self.keyset_id,
            "owner_label": self.owner_label,
            "role": self.role.as_str(),
            "evidence_kind": self.evidence_kind.as_str(),
            "severity": self.severity.as_str(),
            "observed_at_height": self.observed_at_height,
            "reporter_label": self.reporter_label,
            "compromised_artifact_root": self.compromised_artifact_root,
            "transcript_root": self.transcript_root,
            "recommended_response": self.recommended_response,
            "freeze_until_height": self.freeze_until_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("compromise evidence record object");
        object.insert(
            "authorization".to_string(),
            self.authorization.public_record(),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            "QUANTUM-COMPROMISE-EVIDENCE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.evidence_id, "compromise evidence id")?;
        validate_nonempty(&self.key_id, "compromise evidence key id")?;
        validate_nonempty(&self.keyset_id, "compromise evidence keyset id")?;
        validate_nonempty(&self.owner_label, "compromise evidence owner label")?;
        validate_nonempty(
            &self.compromised_artifact_root,
            "compromise evidence artifact root",
        )?;
        validate_nonempty(&self.transcript_root, "compromise evidence transcript root")?;
        validate_nonempty(&self.recommended_response, "compromise evidence response")?;
        self.authorization.validate()?;
        if self.authorization.signer_label != self.reporter_label {
            return Err("compromise evidence reporter signature mismatch".to_string());
        }
        if !self
            .authorization
            .verify("quantum_compromise_evidence", &self.unsigned_record())
        {
            return Err("compromise evidence authorization failed".to_string());
        }
        let expected_id = quantum_compromise_evidence_id(
            &self.key_id,
            self.evidence_kind.as_str(),
            &self.compromised_artifact_root,
            &self.transcript_root,
            self.observed_at_height,
        );
        if self.evidence_id != expected_id {
            return Err("compromise evidence id mismatch".to_string());
        }
        if self.freeze_until_height < self.observed_at_height {
            return Err("compromise evidence freeze height overflow".to_string());
        }
        validate_status(
            &self.status,
            &["open", "mitigated", "dismissed"],
            "compromise evidence",
        )?;
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumRecoveryGuardian {
    pub guardian_id: String,
    pub guardian_label: String,
    pub recovery_public_key: String,
    pub key_id: String,
    pub weight: u64,
    pub status: String,
}

impl QuantumRecoveryGuardian {
    pub fn new(guardian_label: impl Into<String>, weight: u64) -> QuantumResult<Self> {
        let guardian_label = guardian_label.into();
        validate_nonempty(&guardian_label, "recovery guardian label")?;
        if weight == 0 {
            return Err("recovery guardian weight cannot be zero".to_string());
        }
        let public_key = public_key_for_label(CryptoRole::RecoverySignature, &guardian_label);
        let guardian_id = quantum_recovery_guardian_id(&guardian_label, &public_key.public_key);
        let guardian = Self {
            guardian_id,
            guardian_label,
            recovery_public_key: public_key.public_key,
            key_id: public_key.key_id,
            weight,
            status: "active".to_string(),
        };
        guardian.validate()?;
        Ok(guardian)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_recovery_guardian",
            "chain_id": CHAIN_ID,
            "guardian_id": self.guardian_id,
            "guardian_label": self.guardian_label,
            "recovery_public_key": self.recovery_public_key,
            "key_id": self.key_id,
            "weight": self.weight,
            "status": self.status,
        })
    }

    pub fn guardian_root(&self) -> String {
        domain_hash(
            "QUANTUM-RECOVERY-GUARDIAN",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.guardian_id, "recovery guardian id")?;
        validate_nonempty(&self.guardian_label, "recovery guardian label")?;
        validate_nonempty(&self.recovery_public_key, "recovery guardian public key")?;
        validate_nonempty(&self.key_id, "recovery guardian key id")?;
        if self.weight == 0 {
            return Err("recovery guardian weight cannot be zero".to_string());
        }
        let expected = public_key_for_label(CryptoRole::RecoverySignature, &self.guardian_label);
        if self.recovery_public_key != expected.public_key || self.key_id != expected.key_id {
            return Err("recovery guardian public key mismatch".to_string());
        }
        let expected_id =
            quantum_recovery_guardian_id(&self.guardian_label, &self.recovery_public_key);
        if self.guardian_id != expected_id {
            return Err("recovery guardian id mismatch".to_string());
        }
        validate_status(
            &self.status,
            &["active", "retired", "suspended"],
            "guardian",
        )?;
        Ok(self.guardian_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumRecoveryPolicy {
    pub policy_id: String,
    pub owner_label: String,
    pub guardian_threshold_weight: u64,
    pub recovery_delay_blocks: u64,
    pub compromise_freeze_blocks: u64,
    pub max_active_ceremonies: u64,
    pub emergency_rotation_allowed: bool,
    pub guardians: Vec<QuantumRecoveryGuardian>,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl QuantumRecoveryPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: impl Into<String>,
        guardians: Vec<QuantumRecoveryGuardian>,
        guardian_threshold_weight: u64,
        created_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> QuantumResult<Self> {
        let owner_label = owner_label.into();
        validate_nonempty(&owner_label, "recovery policy owner label")?;
        let metadata_root = quantum_payload_root("QUANTUM-RECOVERY-POLICY-METADATA", metadata);
        let mut policy = Self {
            policy_id: String::new(),
            owner_label,
            guardian_threshold_weight,
            recovery_delay_blocks: QUANTUM_DEFAULT_RECOVERY_DELAY_BLOCKS,
            compromise_freeze_blocks: QUANTUM_DEFAULT_COMPROMISE_FREEZE_BLOCKS,
            max_active_ceremonies: 2,
            emergency_rotation_allowed: true,
            guardians,
            metadata_root,
            created_at_height,
            expires_at_height,
            status: "active".to_string(),
        };
        policy.policy_id = quantum_recovery_policy_id(
            &policy.owner_label,
            &policy.guardian_root(),
            policy.guardian_threshold_weight,
            &policy.metadata_root,
        );
        policy.validate()?;
        Ok(policy)
    }

    pub fn guardian_root(&self) -> String {
        quantum_recovery_guardian_root(&self.guardians)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_recovery_policy",
            "chain_id": CHAIN_ID,
            "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "owner_label": self.owner_label,
            "guardian_threshold_weight": self.guardian_threshold_weight,
            "guardian_total_weight": self.guardian_total_weight(),
            "recovery_delay_blocks": self.recovery_delay_blocks,
            "compromise_freeze_blocks": self.compromise_freeze_blocks,
            "max_active_ceremonies": self.max_active_ceremonies,
            "emergency_rotation_allowed": self.emergency_rotation_allowed,
            "guardian_root": self.guardian_root(),
            "guardian_count": self.guardians.len() as u64,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn guardian_total_weight(&self) -> u64 {
        self.guardians
            .iter()
            .filter(|guardian| guardian.status == "active")
            .map(|guardian| guardian.weight)
            .sum()
    }

    pub fn policy_root(&self) -> String {
        domain_hash(
            "QUANTUM-RECOVERY-POLICY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.policy_id, "recovery policy id")?;
        validate_nonempty(&self.owner_label, "recovery policy owner label")?;
        validate_nonempty(&self.metadata_root, "recovery policy metadata root")?;
        if self.guardians.is_empty() {
            return Err("recovery policy requires at least one guardian".to_string());
        }
        if self.guardians.len() > QUANTUM_MAX_RECOVERY_GUARDIANS {
            return Err("recovery policy has too many guardians".to_string());
        }
        if self.guardian_threshold_weight == 0 {
            return Err("recovery policy threshold cannot be zero".to_string());
        }
        let mut seen = BTreeSet::new();
        for guardian in &self.guardians {
            guardian.validate()?;
            if !seen.insert(guardian.guardian_id.clone()) {
                return Err("recovery policy contains duplicate guardian".to_string());
            }
        }
        if self.guardian_threshold_weight > self.guardian_total_weight() {
            return Err("recovery policy threshold exceeds active guardian weight".to_string());
        }
        if self.recovery_delay_blocks == 0 {
            return Err("recovery policy delay cannot be zero".to_string());
        }
        if self.max_active_ceremonies == 0 {
            return Err("recovery policy max active ceremonies cannot be zero".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.created_at_height {
            return Err("recovery policy expiry must be after creation".to_string());
        }
        let expected_id = quantum_recovery_policy_id(
            &self.owner_label,
            &self.guardian_root(),
            self.guardian_threshold_weight,
            &self.metadata_root,
        );
        if self.policy_id != expected_id {
            return Err("recovery policy id mismatch".to_string());
        }
        validate_status(
            &self.status,
            &["active", "retired", "suspended"],
            "recovery policy",
        )?;
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumDevnetAuditFinding {
    pub finding_id: String,
    pub severity: QuantumAuditSeverity,
    pub category: String,
    pub title: String,
    pub evidence_root: String,
    pub recommendation: String,
    pub score_delta: i64,
}

impl QuantumDevnetAuditFinding {
    pub fn new(
        severity: QuantumAuditSeverity,
        category: impl Into<String>,
        title: impl Into<String>,
        evidence: &Value,
        recommendation: impl Into<String>,
        score_delta: i64,
    ) -> QuantumResult<Self> {
        let category = category.into();
        let title = title.into();
        let recommendation = recommendation.into();
        validate_nonempty(&category, "quantum audit category")?;
        validate_nonempty(&title, "quantum audit title")?;
        validate_nonempty(&recommendation, "quantum audit recommendation")?;
        let evidence_root = quantum_payload_root("QUANTUM-DEVNET-AUDIT-EVIDENCE", evidence);
        let finding_id =
            quantum_devnet_audit_finding_id(severity.as_str(), &category, &title, &evidence_root);
        let finding = Self {
            finding_id,
            severity,
            category,
            title,
            evidence_root,
            recommendation,
            score_delta,
        };
        finding.validate()?;
        Ok(finding)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_devnet_audit_finding",
            "chain_id": CHAIN_ID,
            "quantum_devnet_audit_version": QUANTUM_DEVNET_AUDIT_VERSION,
            "finding_id": self.finding_id,
            "severity": self.severity.as_str(),
            "category": self.category,
            "title": self.title,
            "evidence_root": self.evidence_root,
            "recommendation": self.recommendation,
            "score_delta": self.score_delta,
        })
    }

    pub fn finding_root(&self) -> String {
        domain_hash(
            "QUANTUM-DEVNET-AUDIT-FINDING",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.finding_id, "quantum audit finding id")?;
        validate_nonempty(&self.category, "quantum audit category")?;
        validate_nonempty(&self.title, "quantum audit title")?;
        validate_nonempty(&self.evidence_root, "quantum audit evidence root")?;
        validate_nonempty(&self.recommendation, "quantum audit recommendation")?;
        let expected_id = quantum_devnet_audit_finding_id(
            self.severity.as_str(),
            &self.category,
            &self.title,
            &self.evidence_root,
        );
        if self.finding_id != expected_id {
            return Err("quantum audit finding id mismatch".to_string());
        }
        Ok(self.finding_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumDevnetAuditRecord {
    pub audit_id: String,
    pub run_id: String,
    pub audited_at_height: u64,
    pub keyset_root: String,
    pub public_key_root: String,
    pub proof_of_possession_root: String,
    pub hybrid_authorization_root: String,
    pub rotation_ceremony_root: String,
    pub migration_epoch_root: String,
    pub compromise_evidence_root: String,
    pub recovery_policy_root: String,
    pub finding_root: String,
    pub finding_count: u64,
    pub readiness_score: u64,
    pub auditor_label: String,
    pub authorization: QuantumSignatureWitness,
    pub status: String,
    pub findings: Vec<QuantumDevnetAuditFinding>,
}

impl QuantumDevnetAuditRecord {
    pub fn build(
        run_id: impl Into<String>,
        audited_at_height: u64,
        state: &QuantumLifecycleState,
        findings: Vec<QuantumDevnetAuditFinding>,
        auditor_label: impl Into<String>,
    ) -> QuantumResult<Self> {
        let run_id = run_id.into();
        let auditor_label = auditor_label.into();
        validate_nonempty(&run_id, "quantum devnet audit run id")?;
        validate_nonempty(&auditor_label, "quantum devnet audit auditor label")?;
        let finding_root = quantum_devnet_audit_finding_root(&findings);
        let readiness_score = quantum_readiness_score(&findings);
        let audit_id = quantum_devnet_audit_id(
            &run_id,
            audited_at_height,
            &state.keyset_root(),
            &finding_root,
            readiness_score,
        );
        let mut record = Self {
            audit_id,
            run_id,
            audited_at_height,
            keyset_root: state.keyset_root(),
            public_key_root: state.public_key_root(),
            proof_of_possession_root: state.proof_of_possession_root(),
            hybrid_authorization_root: state.hybrid_authorization_root(),
            rotation_ceremony_root: state.rotation_ceremony_root(),
            migration_epoch_root: state.migration_epoch_root(),
            compromise_evidence_root: state.compromise_evidence_root(),
            recovery_policy_root: state.recovery_policy_root(),
            finding_root,
            finding_count: findings.len() as u64,
            readiness_score,
            auditor_label,
            authorization: empty_quantum_signature_witness("", QuantumKeyRole::Watchtower),
            status: if readiness_score >= 80 {
                "ready"
            } else {
                "needs_attention"
            }
            .to_string(),
            findings,
        };
        record.authorization = quantum_signature_witness(
            &record.auditor_label,
            QuantumKeyRole::Watchtower,
            "quantum_devnet_audit_record",
            &record.unsigned_record(),
        );
        record.validate()?;
        Ok(record)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "quantum_devnet_audit_record",
            "chain_id": CHAIN_ID,
            "quantum_devnet_audit_version": QUANTUM_DEVNET_AUDIT_VERSION,
            "audit_id": self.audit_id,
            "run_id": self.run_id,
            "audited_at_height": self.audited_at_height,
            "keyset_root": self.keyset_root,
            "public_key_root": self.public_key_root,
            "proof_of_possession_root": self.proof_of_possession_root,
            "hybrid_authorization_root": self.hybrid_authorization_root,
            "rotation_ceremony_root": self.rotation_ceremony_root,
            "migration_epoch_root": self.migration_epoch_root,
            "compromise_evidence_root": self.compromise_evidence_root,
            "recovery_policy_root": self.recovery_policy_root,
            "finding_root": self.finding_root,
            "finding_count": self.finding_count,
            "readiness_score": self.readiness_score,
            "auditor_label": self.auditor_label,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record.as_object_mut().expect("devnet audit record object");
        object.insert(
            "authorization".to_string(),
            self.authorization.public_record(),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "findings".to_string(),
            Value::Array(
                self.findings
                    .iter()
                    .map(QuantumDevnetAuditFinding::public_record)
                    .collect(),
            ),
        );
        record
    }

    pub fn audit_root(&self) -> String {
        domain_hash(
            "QUANTUM-DEVNET-AUDIT-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> QuantumResult<String> {
        validate_nonempty(&self.audit_id, "quantum devnet audit id")?;
        validate_nonempty(&self.run_id, "quantum devnet audit run id")?;
        validate_nonempty(&self.keyset_root, "quantum devnet audit keyset root")?;
        validate_nonempty(
            &self.public_key_root,
            "quantum devnet audit public key root",
        )?;
        validate_nonempty(
            &self.proof_of_possession_root,
            "quantum devnet audit POP root",
        )?;
        validate_nonempty(
            &self.hybrid_authorization_root,
            "quantum devnet audit hybrid auth root",
        )?;
        validate_nonempty(
            &self.rotation_ceremony_root,
            "quantum devnet audit rotation root",
        )?;
        validate_nonempty(
            &self.migration_epoch_root,
            "quantum devnet audit migration root",
        )?;
        validate_nonempty(
            &self.compromise_evidence_root,
            "quantum devnet audit compromise root",
        )?;
        validate_nonempty(
            &self.recovery_policy_root,
            "quantum devnet audit recovery policy root",
        )?;
        validate_nonempty(&self.finding_root, "quantum devnet audit finding root")?;
        validate_nonempty(&self.auditor_label, "quantum devnet auditor label")?;
        if self.findings.len() > QUANTUM_MAX_DEVNET_AUDIT_FINDINGS {
            return Err("quantum devnet audit has too many findings".to_string());
        }
        if self.finding_count != self.findings.len() as u64 {
            return Err("quantum devnet audit finding count mismatch".to_string());
        }
        for finding in &self.findings {
            finding.validate()?;
        }
        if self.finding_root != quantum_devnet_audit_finding_root(&self.findings) {
            return Err("quantum devnet audit finding root mismatch".to_string());
        }
        if self.readiness_score != quantum_readiness_score(&self.findings) {
            return Err("quantum devnet audit readiness score mismatch".to_string());
        }
        self.authorization.validate()?;
        if self.authorization.signer_label != self.auditor_label {
            return Err("quantum devnet audit auditor signature mismatch".to_string());
        }
        if !self
            .authorization
            .verify("quantum_devnet_audit_record", &self.unsigned_record())
        {
            return Err("quantum devnet audit authorization failed".to_string());
        }
        let expected_id = quantum_devnet_audit_id(
            &self.run_id,
            self.audited_at_height,
            &self.keyset_root,
            &self.finding_root,
            self.readiness_score,
        );
        if self.audit_id != expected_id {
            return Err("quantum devnet audit id mismatch".to_string());
        }
        validate_status(
            &self.status,
            &["ready", "needs_attention", "blocked"],
            "devnet audit",
        )?;
        Ok(self.audit_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumLifecycleState {
    pub height: u64,
    pub public_keys: BTreeMap<String, QuantumPublicKey>,
    pub keysets: BTreeMap<String, QuantumKeySet>,
    pub active_role_keys: BTreeMap<String, String>,
    pub proof_of_possession: BTreeMap<String, ProofOfPossessionTranscript>,
    pub hybrid_authorizations: BTreeMap<String, HybridAuthorizationBundle>,
    pub rotation_ceremonies: BTreeMap<String, RoleKeyRotationCeremony>,
    pub migration_epochs: BTreeMap<String, QuantumMigrationEpoch>,
    pub compromise_evidence: BTreeMap<String, QuantumCompromiseEvidence>,
    pub recovery_policies: BTreeMap<String, QuantumRecoveryPolicy>,
    pub devnet_audits: BTreeMap<String, QuantumDevnetAuditRecord>,
    pub last_audit_root: String,
}

impl QuantumLifecycleState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) -> QuantumResult<String> {
        self.height = self
            .height
            .checked_add(blocks)
            .ok_or_else(|| "quantum lifecycle height overflow".to_string())?;
        Ok(self.state_root())
    }

    pub fn register_keyset(&mut self, keyset: QuantumKeySet) -> QuantumResult<String> {
        keyset.validate()?;
        if self.keysets.contains_key(&keyset.keyset_id) {
            return Err("quantum keyset already exists".to_string());
        }
        for key in keyset.all_keys() {
            if self.public_keys.contains_key(&key.key_id) {
                return Err("quantum public key already exists".to_string());
            }
            let binding_id = quantum_role_binding_id(&key.owner_label, key.role.as_str());
            if key.is_live_at(self.height) {
                self.active_role_keys.insert(binding_id, key.key_id.clone());
            }
            self.public_keys.insert(key.key_id.clone(), key);
        }
        self.keysets.insert(keyset.keyset_id.clone(), keyset);
        Ok(self.state_root())
    }

    pub fn record_proof_of_possession(
        &mut self,
        transcript: ProofOfPossessionTranscript,
    ) -> QuantumResult<String> {
        transcript.validate()?;
        let key = self
            .public_keys
            .get(&transcript.key_id)
            .ok_or_else(|| "unknown quantum key for proof of possession".to_string())?;
        transcript.validate_for_key(key)?;
        if self
            .proof_of_possession
            .contains_key(&transcript.transcript_id)
        {
            return Err("proof of possession transcript already recorded".to_string());
        }
        self.proof_of_possession
            .insert(transcript.transcript_id.clone(), transcript);
        Ok(self.state_root())
    }

    pub fn record_hybrid_authorization(
        &mut self,
        authorization: HybridAuthorizationBundle,
    ) -> QuantumResult<String> {
        authorization.validate()?;
        if self
            .hybrid_authorizations
            .contains_key(&authorization.authorization_id)
        {
            return Err("hybrid authorization already recorded".to_string());
        }
        self.hybrid_authorizations
            .insert(authorization.authorization_id.clone(), authorization);
        Ok(self.state_root())
    }

    pub fn apply_role_key_rotation(
        &mut self,
        ceremony: RoleKeyRotationCeremony,
    ) -> QuantumResult<String> {
        ceremony.validate()?;
        if self.height < ceremony.activate_at_height {
            return Err("rotation ceremony is not active yet".to_string());
        }
        if self.rotation_ceremonies.contains_key(&ceremony.ceremony_id) {
            return Err("rotation ceremony already applied".to_string());
        }
        let previous_key = self
            .public_keys
            .get_mut(&ceremony.previous_key_id)
            .ok_or_else(|| "rotation previous key is unknown".to_string())?;
        if previous_key.key_root() != ceremony.previous_key_root {
            return Err("rotation previous key root mismatch".to_string());
        }
        if previous_key.owner_label != ceremony.owner_label || previous_key.role != ceremony.role {
            return Err("rotation previous key role mismatch".to_string());
        }
        let binding_id = quantum_role_binding_id(&ceremony.owner_label, ceremony.role.as_str());
        let active_key_id = self
            .active_role_keys
            .get(&binding_id)
            .ok_or_else(|| "rotation active role key is missing".to_string())?;
        if active_key_id != &ceremony.previous_key_id {
            return Err("rotation previous key is not active".to_string());
        }
        previous_key.status = "retired".to_string();
        let mut next_key = ceremony.next_key.clone();
        next_key.status = "active".to_string();
        self.public_keys.insert(next_key.key_id.clone(), next_key);
        self.active_role_keys
            .insert(binding_id, ceremony.next_key.key_id.clone());
        self.proof_of_possession.insert(
            ceremony.proof_of_possession.transcript_id.clone(),
            ceremony.proof_of_possession.clone(),
        );
        self.hybrid_authorizations.insert(
            ceremony.hybrid_authorization.authorization_id.clone(),
            ceremony.hybrid_authorization.clone(),
        );
        let mut applied = ceremony;
        applied.status = "applied".to_string();
        applied.stage = QuantumRotationStage::Activated;
        self.rotation_ceremonies
            .insert(applied.ceremony_id.clone(), applied);
        Ok(self.state_root())
    }

    pub fn apply_migration_epoch(
        &mut self,
        mut epoch: QuantumMigrationEpoch,
    ) -> QuantumResult<String> {
        epoch.validate()?;
        if self.migration_epochs.contains_key(&epoch.epoch_id) {
            return Err("migration epoch already exists".to_string());
        }
        epoch.keyset_root = self.keyset_root();
        epoch.ceremony_root = self.rotation_ceremony_root();
        epoch.audit_record_root = self.devnet_audit_root();
        epoch.status = if self.height >= epoch.deprecation_height {
            "deprecated"
        } else if self.height >= epoch.activation_height {
            "active"
        } else if self.height >= epoch.dual_authorization_start_height {
            "dual_authorization"
        } else {
            "scheduled"
        }
        .to_string();
        epoch.validate()?;
        self.migration_epochs.insert(epoch.epoch_id.clone(), epoch);
        Ok(self.state_root())
    }

    pub fn report_compromise(
        &mut self,
        evidence: QuantumCompromiseEvidence,
    ) -> QuantumResult<String> {
        evidence.validate()?;
        if self.compromise_evidence.contains_key(&evidence.evidence_id) {
            return Err("compromise evidence already exists".to_string());
        }
        let key = self
            .public_keys
            .get_mut(&evidence.key_id)
            .ok_or_else(|| "compromise evidence key is unknown".to_string())?;
        if key.owner_label != evidence.owner_label || key.role != evidence.role {
            return Err("compromise evidence key role mismatch".to_string());
        }
        key.status = "compromised".to_string();
        let binding_id = quantum_role_binding_id(&evidence.owner_label, evidence.role.as_str());
        if self
            .active_role_keys
            .get(&binding_id)
            .map(|key_id| key_id == &evidence.key_id)
            .unwrap_or(false)
        {
            self.active_role_keys.remove(&binding_id);
        }
        self.compromise_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(self.state_root())
    }

    pub fn apply_recovery_policy(
        &mut self,
        policy: QuantumRecoveryPolicy,
    ) -> QuantumResult<String> {
        policy.validate()?;
        self.recovery_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(self.state_root())
    }

    pub fn record_devnet_audit(
        &mut self,
        audit: QuantumDevnetAuditRecord,
    ) -> QuantumResult<String> {
        audit.validate()?;
        if self.devnet_audits.contains_key(&audit.audit_id) {
            return Err("quantum devnet audit already exists".to_string());
        }
        self.last_audit_root = audit.audit_root();
        self.devnet_audits.insert(audit.audit_id.clone(), audit);
        Ok(self.state_root())
    }

    pub fn public_key_root(&self) -> String {
        merkle_root(
            "QUANTUM-PUBLIC-KEY",
            &self
                .public_keys
                .values()
                .map(QuantumPublicKey::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn keyset_root(&self) -> String {
        merkle_root(
            "QUANTUM-KEYSET",
            &self
                .keysets
                .values()
                .map(QuantumKeySet::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn active_role_key_root(&self) -> String {
        let leaves = self
            .active_role_keys
            .iter()
            .map(|(binding_id, key_id)| {
                json!({
                    "binding_id": binding_id,
                    "key_id": key_id,
                })
            })
            .collect::<Vec<_>>();
        merkle_root("QUANTUM-ACTIVE-ROLE-KEY", &leaves)
    }

    pub fn proof_of_possession_root(&self) -> String {
        quantum_proof_of_possession_root(
            &self
                .proof_of_possession
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn hybrid_authorization_root(&self) -> String {
        quantum_hybrid_authorization_root(
            &self
                .hybrid_authorizations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn rotation_ceremony_root(&self) -> String {
        quantum_rotation_ceremony_root(
            &self
                .rotation_ceremonies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn migration_epoch_root(&self) -> String {
        quantum_migration_epoch_root(&self.migration_epochs.values().cloned().collect::<Vec<_>>())
    }

    pub fn compromise_evidence_root(&self) -> String {
        quantum_compromise_evidence_root(
            &self
                .compromise_evidence
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn recovery_policy_root(&self) -> String {
        quantum_recovery_policy_root(&self.recovery_policies.values().cloned().collect::<Vec<_>>())
    }

    pub fn devnet_audit_root(&self) -> String {
        quantum_devnet_audit_root(&self.devnet_audits.values().cloned().collect::<Vec<_>>())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_lifecycle_state",
            "chain_id": CHAIN_ID,
            "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
            "quantum_policy_version": QUANTUM_POLICY_VERSION,
            "height": self.height,
            "crypto_policy_root": crypto_policy_root(),
            "quantum_policy_root": quantum_policy_root(),
            "public_key_root": self.public_key_root(),
            "public_key_count": self.public_keys.len() as u64,
            "keyset_root": self.keyset_root(),
            "keyset_count": self.keysets.len() as u64,
            "active_role_key_root": self.active_role_key_root(),
            "active_role_key_count": self.active_role_keys.len() as u64,
            "proof_of_possession_root": self.proof_of_possession_root(),
            "proof_of_possession_count": self.proof_of_possession.len() as u64,
            "hybrid_authorization_root": self.hybrid_authorization_root(),
            "hybrid_authorization_count": self.hybrid_authorizations.len() as u64,
            "rotation_ceremony_root": self.rotation_ceremony_root(),
            "rotation_ceremony_count": self.rotation_ceremonies.len() as u64,
            "migration_epoch_root": self.migration_epoch_root(),
            "migration_epoch_count": self.migration_epochs.len() as u64,
            "compromise_evidence_root": self.compromise_evidence_root(),
            "compromise_evidence_count": self.compromise_evidence.len() as u64,
            "recovery_policy_root": self.recovery_policy_root(),
            "recovery_policy_count": self.recovery_policies.len() as u64,
            "devnet_audit_root": self.devnet_audit_root(),
            "devnet_audit_count": self.devnet_audits.len() as u64,
            "last_audit_root": self.last_audit_root,
        })
    }

    pub fn state_root(&self) -> String {
        quantum_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> QuantumResult<String> {
        for key in self.public_keys.values() {
            key.validate()?;
        }
        for keyset in self.keysets.values() {
            keyset.validate()?;
            for key in keyset.all_keys() {
                if !self.public_keys.contains_key(&key.key_id) {
                    return Err("quantum keyset key missing from public key index".to_string());
                }
            }
        }
        for (binding_id, key_id) in &self.active_role_keys {
            validate_nonempty(binding_id, "active role key binding id")?;
            let key = self
                .public_keys
                .get(key_id)
                .ok_or_else(|| "active role key references unknown key".to_string())?;
            if !key.is_live_at(self.height) {
                return Err("active role key is not live at current height".to_string());
            }
        }
        for transcript in self.proof_of_possession.values() {
            transcript.validate()?;
        }
        for authorization in self.hybrid_authorizations.values() {
            authorization.validate()?;
        }
        for ceremony in self.rotation_ceremonies.values() {
            ceremony.validate()?;
        }
        for epoch in self.migration_epochs.values() {
            epoch.validate()?;
        }
        for evidence in self.compromise_evidence.values() {
            evidence.validate()?;
        }
        for policy in self.recovery_policies.values() {
            policy.validate()?;
        }
        for audit in self.devnet_audits.values() {
            audit.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn quantum_policy_root() -> String {
    merkle_root(
        "QUANTUM-POLICY",
        &[
            json!({
                "policy_version": QUANTUM_POLICY_VERSION,
                "scheme": QUANTUM_ML_DSA_SCHEME,
                "standard": "NIST FIPS 204",
                "role": "signature",
            }),
            json!({
                "policy_version": QUANTUM_POLICY_VERSION,
                "scheme": QUANTUM_SLH_DSA_SCHEME,
                "standard": "NIST FIPS 205",
                "role": "recovery_signature",
            }),
            json!({
                "policy_version": QUANTUM_POLICY_VERSION,
                "scheme": QUANTUM_KEM_SCHEME,
                "standard": "NIST FIPS 203",
                "role": "key_establishment",
            }),
            json!({
                "policy_version": QUANTUM_POLICY_VERSION,
                "scheme": QUANTUM_HYBRID_AUTH_SCHEME,
                "standard": "devnet-hybrid-lifecycle-bundle",
                "role": "hybrid_authorization",
            }),
            json!({
                "policy_version": QUANTUM_POLICY_VERSION,
                "scheme": QUANTUM_PROOF_OF_POSSESSION_SYSTEM,
                "standard": "devnet-transcript",
                "role": "proof_of_possession",
            }),
        ],
    )
}

pub fn quantum_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(QUANTUM_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn quantum_string_root(label: &str, value: &str) -> String {
    domain_hash(
        "QUANTUM-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn quantum_key_id(
    owner_label: &str,
    role: &str,
    algorithm: &str,
    public_key: &str,
    rotation_nonce: u64,
    policy_root: &str,
) -> String {
    domain_hash(
        "QUANTUM-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(role),
            HashPart::Str(algorithm),
            HashPart::Str(public_key),
            HashPart::Int(rotation_nonce as i128),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn quantum_key_root(key: &QuantumPublicKey) -> String {
    domain_hash(
        "QUANTUM-PUBLIC-KEY",
        &[HashPart::Json(&key.public_record())],
        32,
    )
}

pub fn quantum_keyset_id(
    owner_label: &str,
    key_root: &str,
    policy_root: &str,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "QUANTUM-KEYSET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(key_root),
            HashPart::Str(policy_root),
            HashPart::Int(rotation_nonce as i128),
        ],
        32,
    )
}

pub fn quantum_keyset_root(keysets: &[QuantumKeySet]) -> String {
    merkle_root(
        "QUANTUM-KEYSET",
        &keysets
            .iter()
            .map(QuantumKeySet::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_proof_of_possession_id(
    key_id: &str,
    transcript_hash: &str,
    witness_root: &str,
) -> String {
    domain_hash(
        "QUANTUM-PROOF-OF-POSSESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(key_id),
            HashPart::Str(transcript_hash),
            HashPart::Str(witness_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn quantum_proof_of_possession_transcript_hash(
    key_id: &str,
    role: &str,
    algorithm: &str,
    public_key: &str,
    challenge_root: &str,
    produced_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "QUANTUM-PROOF-OF-POSSESSION-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(key_id),
            HashPart::Str(role),
            HashPart::Str(algorithm),
            HashPart::Str(public_key),
            HashPart::Str(challenge_root),
            HashPart::Int(produced_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn quantum_proof_of_possession_root(transcripts: &[ProofOfPossessionTranscript]) -> String {
    merkle_root(
        "QUANTUM-PROOF-OF-POSSESSION",
        &transcripts
            .iter()
            .map(ProofOfPossessionTranscript::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_kem_transcript_hash(
    recipient_key_id: &str,
    recipient_public_key_root: &str,
    context_root: &str,
    encapsulated_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "QUANTUM-KEM-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(QUANTUM_KEM_SCHEME),
            HashPart::Str(recipient_key_id),
            HashPart::Str(recipient_public_key_root),
            HashPart::Str(context_root),
            HashPart::Int(encapsulated_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn quantum_kem_ciphertext_hash(
    recipient_key_id: &str,
    recipient_public_key_root: &str,
    transcript_hash: &str,
) -> String {
    domain_hash(
        "QUANTUM-KEM-CIPHERTEXT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(QUANTUM_KEM_SCHEME),
            HashPart::Str(recipient_key_id),
            HashPart::Str(recipient_public_key_root),
            HashPart::Str(transcript_hash),
        ],
        32,
    )
}

pub fn quantum_kem_shared_secret_commitment(
    recipient_key_id: &str,
    transcript_hash: &str,
) -> String {
    domain_hash(
        "QUANTUM-KEM-SHARED-SECRET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(recipient_key_id),
            HashPart::Str(transcript_hash),
        ],
        32,
    )
}

pub fn quantum_hybrid_authorization_id(
    signer_label: &str,
    domain: &str,
    payload_root: &str,
    ml_dsa_witness_root: &str,
    slh_dsa_witness_root: &str,
    kem_envelope_root: &str,
) -> String {
    domain_hash(
        "QUANTUM-HYBRID-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_label),
            HashPart::Str(domain),
            HashPart::Str(payload_root),
            HashPart::Str(ml_dsa_witness_root),
            HashPart::Str(slh_dsa_witness_root),
            HashPart::Str(kem_envelope_root),
        ],
        32,
    )
}

pub fn quantum_hybrid_authorization_root(authorizations: &[HybridAuthorizationBundle]) -> String {
    merkle_root(
        "QUANTUM-HYBRID-AUTHORIZATION",
        &authorizations
            .iter()
            .map(HybridAuthorizationBundle::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_rotation_ceremony_id(
    owner_label: &str,
    role: &str,
    previous_key_id: &str,
    next_key_id: &str,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "QUANTUM-ROTATION-CEREMONY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(role),
            HashPart::Str(previous_key_id),
            HashPart::Str(next_key_id),
            HashPart::Int(rotation_nonce as i128),
        ],
        32,
    )
}

pub fn quantum_rotation_ceremony_root(ceremonies: &[RoleKeyRotationCeremony]) -> String {
    merkle_root(
        "QUANTUM-ROTATION-CEREMONY",
        &ceremonies
            .iter()
            .map(RoleKeyRotationCeremony::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_epoch_id(
    epoch_index: u64,
    migration_name: &str,
    source_policy_root: &str,
    target_policy_root: &str,
    role_root: &str,
) -> String {
    domain_hash(
        "QUANTUM-MIGRATION-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_index as i128),
            HashPart::Str(migration_name),
            HashPart::Str(source_policy_root),
            HashPart::Str(target_policy_root),
            HashPart::Str(role_root),
        ],
        32,
    )
}

pub fn quantum_migration_epoch_root(epochs: &[QuantumMigrationEpoch]) -> String {
    merkle_root(
        "QUANTUM-MIGRATION-EPOCH",
        &epochs
            .iter()
            .map(QuantumMigrationEpoch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_compromise_evidence_id(
    key_id: &str,
    evidence_kind: &str,
    compromised_artifact_root: &str,
    transcript_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "QUANTUM-COMPROMISE-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(key_id),
            HashPart::Str(evidence_kind),
            HashPart::Str(compromised_artifact_root),
            HashPart::Str(transcript_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn quantum_compromise_evidence_root(evidence: &[QuantumCompromiseEvidence]) -> String {
    merkle_root(
        "QUANTUM-COMPROMISE-EVIDENCE",
        &evidence
            .iter()
            .map(QuantumCompromiseEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_recovery_guardian_id(guardian_label: &str, recovery_public_key: &str) -> String {
    domain_hash(
        "QUANTUM-RECOVERY-GUARDIAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(guardian_label),
            HashPart::Str(recovery_public_key),
        ],
        32,
    )
}

pub fn quantum_recovery_guardian_root(guardians: &[QuantumRecoveryGuardian]) -> String {
    merkle_root(
        "QUANTUM-RECOVERY-GUARDIAN",
        &guardians
            .iter()
            .map(QuantumRecoveryGuardian::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_recovery_policy_id(
    owner_label: &str,
    guardian_root: &str,
    threshold_weight: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "QUANTUM-RECOVERY-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(guardian_root),
            HashPart::Int(threshold_weight as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn quantum_recovery_policy_root(policies: &[QuantumRecoveryPolicy]) -> String {
    merkle_root(
        "QUANTUM-RECOVERY-POLICY",
        &policies
            .iter()
            .map(QuantumRecoveryPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_devnet_audit_finding_id(
    severity: &str,
    category: &str,
    title: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "QUANTUM-DEVNET-AUDIT-FINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(severity),
            HashPart::Str(category),
            HashPart::Str(title),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn quantum_devnet_audit_finding_root(findings: &[QuantumDevnetAuditFinding]) -> String {
    merkle_root(
        "QUANTUM-DEVNET-AUDIT-FINDING",
        &findings
            .iter()
            .map(QuantumDevnetAuditFinding::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_devnet_audit_id(
    run_id: &str,
    audited_at_height: u64,
    keyset_root: &str,
    finding_root: &str,
    readiness_score: u64,
) -> String {
    domain_hash(
        "QUANTUM-DEVNET-AUDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(run_id),
            HashPart::Int(audited_at_height as i128),
            HashPart::Str(keyset_root),
            HashPart::Str(finding_root),
            HashPart::Int(readiness_score as i128),
        ],
        32,
    )
}

pub fn quantum_devnet_audit_root(records: &[QuantumDevnetAuditRecord]) -> String {
    merkle_root(
        "QUANTUM-DEVNET-AUDIT",
        &records
            .iter()
            .map(QuantumDevnetAuditRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_state_root_from_record(record: &Value) -> String {
    domain_hash("QUANTUM-LIFECYCLE-STATE", &[HashPart::Json(record)], 32)
}

fn deterministic_quantum_public_key(
    owner_label: &str,
    role: &QuantumKeyRole,
    algorithm: &QuantumKeyAlgorithm,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "QUANTUM-DETERMINISTIC-PUBLIC-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(role.as_str()),
            HashPart::Str(algorithm.as_str()),
            HashPart::Int(rotation_nonce as i128),
        ],
        64,
    )
}

fn quantum_signature_witness(
    signer_label: &str,
    signer_role: QuantumKeyRole,
    domain: &str,
    payload: &Value,
) -> QuantumSignatureWitness {
    if signer_role == QuantumKeyRole::Recovery {
        QuantumSignatureWitness::from_recovery(
            signer_role,
            sign_recovery_authorization(signer_label, domain, payload),
        )
    } else {
        QuantumSignatureWitness::from_authorization(
            signer_role.clone(),
            sign_authorization_for_role(signer_role.crypto_role(), signer_label, domain, payload),
        )
    }
}

fn empty_quantum_signature_witness(
    signer_label: &str,
    signer_role: QuantumKeyRole,
) -> QuantumSignatureWitness {
    QuantumSignatureWitness {
        signer_label: signer_label.to_string(),
        scheme: signer_role.default_algorithm().as_str().to_string(),
        signer_role,
        public_key: String::new(),
        transcript_hash: String::new(),
        signature: String::new(),
    }
}

fn quantum_key_list_root(domain: &str, keys: &[QuantumPublicKey]) -> String {
    merkle_root(
        domain,
        &keys
            .iter()
            .map(QuantumPublicKey::public_record)
            .collect::<Vec<_>>(),
    )
}

fn role_list_root(roles: &[QuantumKeyRole]) -> String {
    let mut roles = roles
        .iter()
        .map(|role| Value::String(role.as_str().to_string()))
        .collect::<Vec<_>>();
    roles.sort_by(|left, right| {
        left.as_str()
            .unwrap_or_default()
            .cmp(right.as_str().unwrap_or_default())
    });
    merkle_root("QUANTUM-ROLE-LIST", &roles)
}

fn quantum_role_binding_id(owner_label: &str, role: &str) -> String {
    domain_hash(
        "QUANTUM-ROLE-BINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(role),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn role_key_rotation_unsigned_record(
    owner_label: &str,
    role: &QuantumKeyRole,
    previous_key_id: &str,
    previous_key_root: &str,
    next_key_record: &Value,
    proof_of_possession_root: &str,
    rotation_nonce: u64,
    requested_at_height: u64,
    activate_at_height: u64,
    expires_at_height: u64,
    reason_root: &str,
) -> Value {
    json!({
        "kind": "quantum_role_key_rotation_ceremony",
        "chain_id": CHAIN_ID,
        "quantum_protocol_version": QUANTUM_PROTOCOL_VERSION,
        "owner_label": owner_label,
        "role": role.as_str(),
        "previous_key_id": previous_key_id,
        "previous_key_root": previous_key_root,
        "next_key": next_key_record,
        "proof_of_possession_root": proof_of_possession_root,
        "rotation_nonce": rotation_nonce,
        "requested_at_height": requested_at_height,
        "activate_at_height": activate_at_height,
        "expires_at_height": expires_at_height,
        "reason_root": reason_root,
    })
}

fn quantum_readiness_score(findings: &[QuantumDevnetAuditFinding]) -> u64 {
    let raw_score = findings
        .iter()
        .fold(100_i64, |score, finding| score + finding.score_delta);
    raw_score.clamp(0, 100) as u64
}

fn validate_nonempty(value: &str, label: &str) -> QuantumResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn validate_status(value: &str, allowed: &[&str], label: &str) -> QuantumResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("{label} status is not supported"))
    }
}

fn validate_role_list(values: &[QuantumKeyRole], label: &str) -> QuantumResult<()> {
    if values.is_empty() {
        return Err(format!("{label} list cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("{label} appears more than once"));
        }
    }
    Ok(())
}
