use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ProofCircuitResult<T> = Result<T, String>;

pub const PROOF_CIRCUIT_PROTOCOL_VERSION: &str = "nebula-l2-proof-circuits-v1";
pub const PROOF_CIRCUIT_SCHEMA_VERSION: u64 = 1;
pub const PROOF_CIRCUIT_HASH_SUITE: &str = "SHAKE256";
pub const PROOF_CIRCUIT_COMMITMENT_SCHEME: &str = "SHAKE256-merkle-root-v1";
pub const PROOF_CIRCUIT_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PROOF_CIRCUIT_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PROOF_CIRCUIT_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const PROOF_CIRCUIT_STATE_PROOF_SYSTEM: &str = "nebula-devnet-pq-state-transition-v1";
pub const PROOF_CIRCUIT_PRIVACY_PROOF_SYSTEM: &str = "nebula-devnet-pq-monero-privacy-v1";
pub const PROOF_CIRCUIT_BRIDGE_PROOF_SYSTEM: &str = "nebula-devnet-pq-monero-bridge-v1";
pub const PROOF_CIRCUIT_DA_PROOF_SYSTEM: &str = "nebula-devnet-pq-data-availability-v1";
pub const PROOF_CIRCUIT_RECURSIVE_PROOF_SYSTEM: &str = "nebula-devnet-pq-recursive-aggregation-v1";
pub const PROOF_CIRCUIT_DEFAULT_MANIFEST_VERSION: u64 = 1;
pub const PROOF_CIRCUIT_DEFAULT_SECURITY_BITS: u64 = 128;
pub const PROOF_CIRCUIT_DEFAULT_RECURSION_DEPTH: u64 = 2;
pub const PROOF_CIRCUIT_DEFAULT_MAX_AGGREGATION_CHILDREN: u64 = 64;
pub const PROOF_CIRCUIT_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 8;
pub const PROOF_CIRCUIT_DEFAULT_AUDIT_RETENTION_BLOCKS: u64 = 20_160;

pub const PROOF_CIRCUIT_STATUS_DRAFT: &str = "draft";
pub const PROOF_CIRCUIT_STATUS_STAGED: &str = "staged";
pub const PROOF_CIRCUIT_STATUS_ACTIVE: &str = "active";
pub const PROOF_CIRCUIT_STATUS_DEPRECATED: &str = "deprecated";
pub const PROOF_CIRCUIT_STATUS_RETIRED: &str = "retired";
pub const PROOF_CIRCUIT_STATUS_REVOKED: &str = "revoked";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCircuitFamily {
    StateTransition,
    Privacy,
    Bridge,
    DataAvailability,
    RecursiveAggregation,
}

impl ProofCircuitFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition",
            Self::Privacy => "privacy",
            Self::Bridge => "bridge",
            Self::DataAvailability => "data_availability",
            Self::RecursiveAggregation => "recursive_aggregation",
        }
    }

    pub fn default_proof_system(&self) -> &'static str {
        match self {
            Self::StateTransition => PROOF_CIRCUIT_STATE_PROOF_SYSTEM,
            Self::Privacy => PROOF_CIRCUIT_PRIVACY_PROOF_SYSTEM,
            Self::Bridge => PROOF_CIRCUIT_BRIDGE_PROOF_SYSTEM,
            Self::DataAvailability => PROOF_CIRCUIT_DA_PROOF_SYSTEM,
            Self::RecursiveAggregation => PROOF_CIRCUIT_RECURSIVE_PROOF_SYSTEM,
        }
    }

    pub fn default_transcript_label(&self) -> &'static str {
        match self {
            Self::StateTransition => "state-transition",
            Self::Privacy => "privacy",
            Self::Bridge => "monero-bridge",
            Self::DataAvailability => "data-availability",
            Self::RecursiveAggregation => "recursive-aggregation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqTranscriptPurpose {
    Proving,
    Verification,
    Recursion,
    BridgeFinality,
    DataAvailability,
    Audit,
}

impl PqTranscriptPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proving => "proving",
            Self::Verification => "verification",
            Self::Recursion => "recursion",
            Self::BridgeFinality => "bridge_finality",
            Self::DataAvailability => "data_availability",
            Self::Audit => "audit",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterCeremonyKind {
    Transparent,
    Universal,
    CircuitSpecific,
    Recursive,
    DevnetDeterministic,
}

impl ParameterCeremonyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Transparent => "transparent",
            Self::Universal => "universal",
            Self::CircuitSpecific => "circuit_specific",
            Self::Recursive => "recursive",
            Self::DevnetDeterministic => "devnet_deterministic",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCircuitAuditTarget {
    TranscriptDomain,
    ParameterCeremony,
    VerifierKey,
    CircuitVersion,
    RecursivePlan,
    VerifierManifest,
    ProofCircuitState,
}

impl ProofCircuitAuditTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TranscriptDomain => "transcript_domain",
            Self::ParameterCeremony => "parameter_ceremony",
            Self::VerifierKey => "verifier_key",
            Self::CircuitVersion => "circuit_version",
            Self::RecursivePlan => "recursive_plan",
            Self::VerifierManifest => "verifier_manifest",
            Self::ProofCircuitState => "proof_circuit_state",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCircuitAuditSeverity {
    Info,
    Warning,
    Critical,
}

impl ProofCircuitAuditSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn score_delta(&self) -> i64 {
        match self {
            Self::Info => 0,
            Self::Warning => -10,
            Self::Critical => -50,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqTranscriptDomain {
    pub domain_id: String,
    pub label: String,
    pub family: ProofCircuitFamily,
    pub purpose: PqTranscriptPurpose,
    pub domain_version: u64,
    pub hash_suite: String,
    pub signature_scheme: String,
    pub recovery_scheme: String,
    pub kem_scheme: String,
    pub separation_tag: String,
    pub context_root: String,
    pub metadata_root: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqTranscriptDomain {
    pub fn new(
        label: impl Into<String>,
        family: ProofCircuitFamily,
        purpose: PqTranscriptPurpose,
        domain_version: u64,
        activated_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ProofCircuitResult<Self> {
        let label = normalize_label(label.into());
        ensure_non_empty(&label, "PQ transcript domain label")?;
        if domain_version == 0 {
            return Err("PQ transcript domain version cannot be zero".to_string());
        }
        let separation_tag = format!(
            "nebula_l2:{CHAIN_ID}:{}:{}:v{}",
            family.as_str(),
            purpose.as_str(),
            domain_version
        );
        let metadata_root =
            proof_circuit_payload_root("PROOF-CIRCUIT-TRANSCRIPT-METADATA", metadata);
        let context_root = pq_transcript_context_root(
            &label,
            family.as_str(),
            purpose.as_str(),
            domain_version,
            &metadata_root,
        );
        let domain_id = pq_transcript_domain_id(
            &label,
            family.as_str(),
            purpose.as_str(),
            &separation_tag,
            &context_root,
            domain_version,
        );
        let domain = Self {
            domain_id,
            label,
            family,
            purpose,
            domain_version,
            hash_suite: PROOF_CIRCUIT_HASH_SUITE.to_string(),
            signature_scheme: PROOF_CIRCUIT_PQ_SIGNATURE_SCHEME.to_string(),
            recovery_scheme: PROOF_CIRCUIT_PQ_RECOVERY_SCHEME.to_string(),
            kem_scheme: PROOF_CIRCUIT_PQ_KEM_SCHEME.to_string(),
            separation_tag,
            context_root,
            metadata_root,
            activated_at_height,
            expires_at_height,
            status: PROOF_CIRCUIT_STATUS_ACTIVE.to_string(),
        };
        domain.validate()?;
        Ok(domain)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_CIRCUIT_STATUS_ACTIVE
            && self.activated_at_height <= height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_transcript_domain",
            "chain_id": CHAIN_ID,
            "proof_circuit_protocol_version": PROOF_CIRCUIT_PROTOCOL_VERSION,
            "domain_id": self.domain_id,
            "label": self.label,
            "family": self.family.as_str(),
            "purpose": self.purpose.as_str(),
            "domain_version": self.domain_version,
            "hash_suite": self.hash_suite,
            "signature_scheme": self.signature_scheme,
            "recovery_scheme": self.recovery_scheme,
            "kem_scheme": self.kem_scheme,
            "separation_tag": self.separation_tag,
            "context_root": self.context_root,
            "metadata_root": self.metadata_root,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn domain_root(&self) -> String {
        pq_transcript_domain_root(self)
    }

    pub fn validate(&self) -> ProofCircuitResult<String> {
        ensure_non_empty(&self.domain_id, "PQ transcript domain id")?;
        ensure_non_empty(&self.label, "PQ transcript domain label")?;
        ensure_non_empty(&self.hash_suite, "PQ transcript hash suite")?;
        ensure_non_empty(&self.signature_scheme, "PQ transcript signature scheme")?;
        ensure_non_empty(&self.recovery_scheme, "PQ transcript recovery scheme")?;
        ensure_non_empty(&self.kem_scheme, "PQ transcript KEM scheme")?;
        ensure_non_empty(&self.separation_tag, "PQ transcript separation tag")?;
        ensure_non_empty(&self.context_root, "PQ transcript context root")?;
        ensure_non_empty(&self.metadata_root, "PQ transcript metadata root")?;
        if self.domain_version == 0 {
            return Err("PQ transcript domain version cannot be zero".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.activated_at_height {
            return Err("PQ transcript domain expiry must be after activation".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_CIRCUIT_STATUS_STAGED,
                PROOF_CIRCUIT_STATUS_ACTIVE,
                PROOF_CIRCUIT_STATUS_RETIRED,
                PROOF_CIRCUIT_STATUS_REVOKED,
            ],
            "PQ transcript domain status",
        )?;
        let expected_context = pq_transcript_context_root(
            &self.label,
            self.family.as_str(),
            self.purpose.as_str(),
            self.domain_version,
            &self.metadata_root,
        );
        if self.context_root != expected_context {
            return Err("PQ transcript context root mismatch".to_string());
        }
        let expected_id = pq_transcript_domain_id(
            &self.label,
            self.family.as_str(),
            self.purpose.as_str(),
            &self.separation_tag,
            &self.context_root,
            self.domain_version,
        );
        if self.domain_id != expected_id {
            return Err("PQ transcript domain id mismatch".to_string());
        }
        Ok(self.domain_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParameterCeremony {
    pub ceremony_id: String,
    pub family: ProofCircuitFamily,
    pub circuit_name: String,
    pub ceremony_kind: ParameterCeremonyKind,
    pub participant_labels: Vec<String>,
    pub participant_root: String,
    pub contribution_roots: Vec<String>,
    pub contribution_root: String,
    pub transcript_root: String,
    pub randomness_beacon_root: String,
    pub proving_key_commitment: String,
    pub verifier_key_seed_root: String,
    pub opened_at_height: u64,
    pub closed_at_height: u64,
    pub min_participants: u64,
    pub participant_count: u64,
    pub metadata_root: String,
    pub status: String,
}

impl ParameterCeremony {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: ProofCircuitFamily,
        circuit_name: impl Into<String>,
        ceremony_kind: ParameterCeremonyKind,
        participant_labels: Vec<String>,
        contribution_labels: Vec<String>,
        opened_at_height: u64,
        closed_at_height: u64,
        min_participants: u64,
        metadata: &Value,
    ) -> ProofCircuitResult<Self> {
        let circuit_name = normalize_label(circuit_name.into());
        ensure_non_empty(&circuit_name, "parameter ceremony circuit name")?;
        let participant_labels =
            normalize_unique_strings(participant_labels, "ceremony participant")?;
        if min_participants == 0 {
            return Err("parameter ceremony minimum participants cannot be zero".to_string());
        }
        if (participant_labels.len() as u64) < min_participants {
            return Err("parameter ceremony has fewer participants than required".to_string());
        }
        if closed_at_height < opened_at_height {
            return Err("parameter ceremony closes before it opens".to_string());
        }
        let contribution_labels =
            normalize_unique_strings(contribution_labels, "ceremony contribution")?;
        let participant_root = proof_circuit_string_set_root(
            "PROOF-CIRCUIT-CEREMONY-PARTICIPANT",
            &participant_labels,
        );
        let contribution_roots = contribution_labels
            .iter()
            .map(|label| {
                parameter_contribution_root(family.as_str(), &circuit_name, label, opened_at_height)
            })
            .collect::<Vec<_>>();
        let contribution_root = proof_circuit_string_set_root(
            "PROOF-CIRCUIT-CEREMONY-CONTRIBUTION",
            &contribution_roots,
        );
        let metadata_root = proof_circuit_payload_root("PROOF-CIRCUIT-CEREMONY-METADATA", metadata);
        let transcript_root = parameter_ceremony_transcript_root(
            family.as_str(),
            &circuit_name,
            ceremony_kind.as_str(),
            &participant_root,
            &contribution_root,
            &metadata_root,
        );
        let randomness_beacon_root = parameter_ceremony_beacon_root(
            family.as_str(),
            &circuit_name,
            &transcript_root,
            closed_at_height,
        );
        let proving_key_commitment = parameter_proving_key_commitment(
            family.as_str(),
            &circuit_name,
            &transcript_root,
            &randomness_beacon_root,
        );
        let verifier_key_seed_root = parameter_verifier_key_seed_root(
            family.as_str(),
            &circuit_name,
            &proving_key_commitment,
            &metadata_root,
        );
        let ceremony_id = parameter_ceremony_id(
            family.as_str(),
            &circuit_name,
            ceremony_kind.as_str(),
            &transcript_root,
            opened_at_height,
        );
        let ceremony = Self {
            ceremony_id,
            family,
            circuit_name,
            ceremony_kind,
            participant_count: participant_labels.len() as u64,
            participant_labels,
            participant_root,
            contribution_roots,
            contribution_root,
            transcript_root,
            randomness_beacon_root,
            proving_key_commitment,
            verifier_key_seed_root,
            opened_at_height,
            closed_at_height,
            min_participants,
            metadata_root,
            status: "finalized".to_string(),
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parameter_ceremony",
            "chain_id": CHAIN_ID,
            "proof_circuit_protocol_version": PROOF_CIRCUIT_PROTOCOL_VERSION,
            "ceremony_id": self.ceremony_id,
            "family": self.family.as_str(),
            "circuit_name": self.circuit_name,
            "ceremony_kind": self.ceremony_kind.as_str(),
            "participant_labels": self.participant_labels,
            "participant_root": self.participant_root,
            "contribution_roots": self.contribution_roots,
            "contribution_root": self.contribution_root,
            "transcript_root": self.transcript_root,
            "randomness_beacon_root": self.randomness_beacon_root,
            "proving_key_commitment": self.proving_key_commitment,
            "verifier_key_seed_root": self.verifier_key_seed_root,
            "opened_at_height": self.opened_at_height,
            "closed_at_height": self.closed_at_height,
            "min_participants": self.min_participants,
            "participant_count": self.participant_count,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn ceremony_root(&self) -> String {
        parameter_ceremony_root(self)
    }

    pub fn validate(&self) -> ProofCircuitResult<String> {
        ensure_non_empty(&self.ceremony_id, "parameter ceremony id")?;
        ensure_non_empty(&self.circuit_name, "parameter ceremony circuit name")?;
        ensure_non_empty(
            &self.participant_root,
            "parameter ceremony participant root",
        )?;
        ensure_non_empty(
            &self.contribution_root,
            "parameter ceremony contribution root",
        )?;
        ensure_non_empty(&self.transcript_root, "parameter ceremony transcript root")?;
        ensure_non_empty(
            &self.randomness_beacon_root,
            "parameter ceremony randomness beacon root",
        )?;
        ensure_non_empty(
            &self.proving_key_commitment,
            "parameter ceremony proving key commitment",
        )?;
        ensure_non_empty(
            &self.verifier_key_seed_root,
            "parameter ceremony verifier key seed root",
        )?;
        ensure_non_empty(&self.metadata_root, "parameter ceremony metadata root")?;
        ensure_unique_strings(&self.participant_labels, "parameter ceremony participant")?;
        ensure_unique_strings(
            &self.contribution_roots,
            "parameter ceremony contribution root",
        )?;
        if self.participant_count != self.participant_labels.len() as u64 {
            return Err("parameter ceremony participant count mismatch".to_string());
        }
        if self.min_participants == 0 {
            return Err("parameter ceremony minimum participants cannot be zero".to_string());
        }
        if self.participant_count < self.min_participants {
            return Err("parameter ceremony participant count below minimum".to_string());
        }
        if self.closed_at_height < self.opened_at_height {
            return Err("parameter ceremony closes before it opens".to_string());
        }
        ensure_status(
            &self.status,
            &["open", "finalized", "cancelled", "revoked"],
            "parameter ceremony status",
        )?;
        let expected_participant_root = proof_circuit_string_set_root(
            "PROOF-CIRCUIT-CEREMONY-PARTICIPANT",
            &self.participant_labels,
        );
        if self.participant_root != expected_participant_root {
            return Err("parameter ceremony participant root mismatch".to_string());
        }
        let expected_contribution_root = proof_circuit_string_set_root(
            "PROOF-CIRCUIT-CEREMONY-CONTRIBUTION",
            &self.contribution_roots,
        );
        if self.contribution_root != expected_contribution_root {
            return Err("parameter ceremony contribution root mismatch".to_string());
        }
        let expected_transcript_root = parameter_ceremony_transcript_root(
            self.family.as_str(),
            &self.circuit_name,
            self.ceremony_kind.as_str(),
            &self.participant_root,
            &self.contribution_root,
            &self.metadata_root,
        );
        if self.transcript_root != expected_transcript_root {
            return Err("parameter ceremony transcript root mismatch".to_string());
        }
        let expected_beacon_root = parameter_ceremony_beacon_root(
            self.family.as_str(),
            &self.circuit_name,
            &self.transcript_root,
            self.closed_at_height,
        );
        if self.randomness_beacon_root != expected_beacon_root {
            return Err("parameter ceremony randomness beacon root mismatch".to_string());
        }
        let expected_proving_key_commitment = parameter_proving_key_commitment(
            self.family.as_str(),
            &self.circuit_name,
            &self.transcript_root,
            &self.randomness_beacon_root,
        );
        if self.proving_key_commitment != expected_proving_key_commitment {
            return Err("parameter ceremony proving key commitment mismatch".to_string());
        }
        let expected_verifier_key_seed_root = parameter_verifier_key_seed_root(
            self.family.as_str(),
            &self.circuit_name,
            &self.proving_key_commitment,
            &self.metadata_root,
        );
        if self.verifier_key_seed_root != expected_verifier_key_seed_root {
            return Err("parameter ceremony verifier key seed root mismatch".to_string());
        }
        let expected_id = parameter_ceremony_id(
            self.family.as_str(),
            &self.circuit_name,
            self.ceremony_kind.as_str(),
            &self.transcript_root,
            self.opened_at_height,
        );
        if self.ceremony_id != expected_id {
            return Err("parameter ceremony id mismatch".to_string());
        }
        Ok(self.ceremony_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKeyCommitment {
    pub key_id: String,
    pub family: ProofCircuitFamily,
    pub circuit_name: String,
    pub proof_system: String,
    pub key_format: String,
    pub key_version: u64,
    pub commitment_scheme: String,
    pub verifier_key_root: String,
    pub verifier_key_commitment: String,
    pub transcript_domain_id: String,
    pub transcript_domain_root: String,
    pub ceremony_id: String,
    pub ceremony_root: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl VerifierKeyCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: ProofCircuitFamily,
        circuit_name: impl Into<String>,
        proof_system: impl Into<String>,
        key_format: impl Into<String>,
        key_version: u64,
        transcript_domain: &PqTranscriptDomain,
        ceremony: &ParameterCeremony,
        created_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ProofCircuitResult<Self> {
        let circuit_name = normalize_label(circuit_name.into());
        let proof_system = proof_system.into();
        let key_format = key_format.into();
        ensure_non_empty(&circuit_name, "verifier key circuit name")?;
        ensure_non_empty(&proof_system, "verifier key proof system")?;
        ensure_non_empty(&key_format, "verifier key format")?;
        if key_version == 0 {
            return Err("verifier key version cannot be zero".to_string());
        }
        if family != transcript_domain.family {
            return Err("verifier key transcript domain family mismatch".to_string());
        }
        if family != ceremony.family || circuit_name != ceremony.circuit_name {
            return Err("verifier key ceremony target mismatch".to_string());
        }
        let metadata_root = proof_circuit_payload_root("PROOF-CIRCUIT-VK-METADATA", metadata);
        let transcript_domain_root = transcript_domain.domain_root();
        let ceremony_root = ceremony.ceremony_root();
        let verifier_key_root = deterministic_verifier_key_root(
            family.as_str(),
            &circuit_name,
            &proof_system,
            key_version,
            &ceremony.verifier_key_seed_root,
            &metadata_root,
        );
        let verifier_key_commitment = verifier_key_commitment_hash(
            &proof_system,
            &key_format,
            key_version,
            &verifier_key_root,
            &transcript_domain_root,
            &ceremony_root,
        );
        let key_id = verifier_key_commitment_id(
            family.as_str(),
            &circuit_name,
            &proof_system,
            &verifier_key_commitment,
            &ceremony.ceremony_id,
            key_version,
        );
        let commitment = Self {
            key_id,
            family,
            circuit_name,
            proof_system,
            key_format,
            key_version,
            commitment_scheme: PROOF_CIRCUIT_COMMITMENT_SCHEME.to_string(),
            verifier_key_root,
            verifier_key_commitment,
            transcript_domain_id: transcript_domain.domain_id.clone(),
            transcript_domain_root,
            ceremony_id: ceremony.ceremony_id.clone(),
            ceremony_root,
            metadata_root,
            created_at_height,
            expires_at_height,
            status: PROOF_CIRCUIT_STATUS_ACTIVE.to_string(),
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_CIRCUIT_STATUS_ACTIVE
            && self.created_at_height <= height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_key_commitment",
            "chain_id": CHAIN_ID,
            "proof_circuit_protocol_version": PROOF_CIRCUIT_PROTOCOL_VERSION,
            "key_id": self.key_id,
            "family": self.family.as_str(),
            "circuit_name": self.circuit_name,
            "proof_system": self.proof_system,
            "key_format": self.key_format,
            "key_version": self.key_version,
            "commitment_scheme": self.commitment_scheme,
            "verifier_key_root": self.verifier_key_root,
            "verifier_key_commitment": self.verifier_key_commitment,
            "transcript_domain_id": self.transcript_domain_id,
            "transcript_domain_root": self.transcript_domain_root,
            "ceremony_id": self.ceremony_id,
            "ceremony_root": self.ceremony_root,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn key_root(&self) -> String {
        verifier_key_commitment_root(self)
    }

    pub fn validate(&self) -> ProofCircuitResult<String> {
        ensure_non_empty(&self.key_id, "verifier key id")?;
        ensure_non_empty(&self.circuit_name, "verifier key circuit name")?;
        ensure_non_empty(&self.proof_system, "verifier key proof system")?;
        ensure_non_empty(&self.key_format, "verifier key format")?;
        ensure_non_empty(&self.commitment_scheme, "verifier key commitment scheme")?;
        ensure_non_empty(&self.verifier_key_root, "verifier key root")?;
        ensure_non_empty(&self.verifier_key_commitment, "verifier key commitment")?;
        ensure_non_empty(
            &self.transcript_domain_id,
            "verifier key transcript domain id",
        )?;
        ensure_non_empty(
            &self.transcript_domain_root,
            "verifier key transcript domain root",
        )?;
        ensure_non_empty(&self.ceremony_id, "verifier key ceremony id")?;
        ensure_non_empty(&self.ceremony_root, "verifier key ceremony root")?;
        ensure_non_empty(&self.metadata_root, "verifier key metadata root")?;
        if self.key_version == 0 {
            return Err("verifier key version cannot be zero".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.created_at_height {
            return Err("verifier key expiry must be after creation".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_CIRCUIT_STATUS_STAGED,
                PROOF_CIRCUIT_STATUS_ACTIVE,
                PROOF_CIRCUIT_STATUS_DEPRECATED,
                PROOF_CIRCUIT_STATUS_RETIRED,
                PROOF_CIRCUIT_STATUS_REVOKED,
            ],
            "verifier key status",
        )?;
        let expected_commitment = verifier_key_commitment_hash(
            &self.proof_system,
            &self.key_format,
            self.key_version,
            &self.verifier_key_root,
            &self.transcript_domain_root,
            &self.ceremony_root,
        );
        if self.verifier_key_commitment != expected_commitment {
            return Err("verifier key commitment mismatch".to_string());
        }
        let expected_id = verifier_key_commitment_id(
            self.family.as_str(),
            &self.circuit_name,
            &self.proof_system,
            &self.verifier_key_commitment,
            &self.ceremony_id,
            self.key_version,
        );
        if self.key_id != expected_id {
            return Err("verifier key id mismatch".to_string());
        }
        Ok(self.key_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCircuitVersion {
    pub version_id: String,
    pub family: ProofCircuitFamily,
    pub circuit_name: String,
    pub circuit_version: u64,
    pub proof_system: String,
    pub arithmetization: String,
    pub constraint_system_root: String,
    pub witness_schema_root: String,
    pub public_input_schema_root: String,
    pub verifier_key_id: String,
    pub verifier_key_root: String,
    pub verifier_key_commitment: String,
    pub transcript_domain_id: String,
    pub transcript_domain_root: String,
    pub ceremony_id: String,
    pub ceremony_root: String,
    pub estimated_constraints: u64,
    pub max_public_inputs: u64,
    pub max_witness_bytes: u64,
    pub target_proof_bytes: u64,
    pub recursion_compatible: bool,
    pub security_bits: u64,
    pub introduced_at_height: u64,
    pub activated_at_height: u64,
    pub deprecated_at_height: u64,
    pub metadata_root: String,
    pub status: String,
}

impl ProofCircuitVersion {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: ProofCircuitFamily,
        circuit_name: impl Into<String>,
        circuit_version: u64,
        proof_system: impl Into<String>,
        arithmetization: impl Into<String>,
        verifier_key: &VerifierKeyCommitment,
        transcript_domain: &PqTranscriptDomain,
        ceremony: &ParameterCeremony,
        estimated_constraints: u64,
        max_public_inputs: u64,
        max_witness_bytes: u64,
        target_proof_bytes: u64,
        recursion_compatible: bool,
        security_bits: u64,
        introduced_at_height: u64,
        activated_at_height: u64,
        metadata: &Value,
    ) -> ProofCircuitResult<Self> {
        let circuit_name = normalize_label(circuit_name.into());
        let proof_system = proof_system.into();
        let arithmetization = arithmetization.into();
        ensure_non_empty(&circuit_name, "proof circuit name")?;
        ensure_non_empty(&proof_system, "proof circuit proof system")?;
        ensure_non_empty(&arithmetization, "proof circuit arithmetization")?;
        if circuit_version == 0 {
            return Err("proof circuit version cannot be zero".to_string());
        }
        if estimated_constraints == 0 {
            return Err("proof circuit estimated constraints cannot be zero".to_string());
        }
        if max_witness_bytes == 0 {
            return Err("proof circuit max witness bytes cannot be zero".to_string());
        }
        if target_proof_bytes == 0 {
            return Err("proof circuit target proof bytes cannot be zero".to_string());
        }
        if security_bits < PROOF_CIRCUIT_DEFAULT_SECURITY_BITS {
            return Err("proof circuit security bits below policy minimum".to_string());
        }
        if activated_at_height < introduced_at_height {
            return Err("proof circuit activation precedes introduction".to_string());
        }
        if family != verifier_key.family
            || family != transcript_domain.family
            || family != ceremony.family
            || circuit_name != verifier_key.circuit_name
            || circuit_name != ceremony.circuit_name
        {
            return Err("proof circuit component target mismatch".to_string());
        }
        if proof_system != verifier_key.proof_system {
            return Err("proof circuit verifier key proof system mismatch".to_string());
        }
        let metadata_root = proof_circuit_payload_root("PROOF-CIRCUIT-VERSION-METADATA", metadata);
        let constraint_system_root = circuit_constraint_system_root(
            family.as_str(),
            &circuit_name,
            circuit_version,
            &proof_system,
            estimated_constraints,
            &metadata_root,
        );
        let witness_schema_root = circuit_witness_schema_root(
            family.as_str(),
            &circuit_name,
            circuit_version,
            max_witness_bytes,
            &metadata_root,
        );
        let public_input_schema_root = circuit_public_input_schema_root(
            family.as_str(),
            &circuit_name,
            circuit_version,
            max_public_inputs,
            &metadata_root,
        );
        let version_id = proof_circuit_version_id(
            family.as_str(),
            &circuit_name,
            circuit_version,
            &proof_system,
            &verifier_key.verifier_key_commitment,
            &transcript_domain.domain_id,
        );
        let version = Self {
            version_id,
            family,
            circuit_name,
            circuit_version,
            proof_system,
            arithmetization,
            constraint_system_root,
            witness_schema_root,
            public_input_schema_root,
            verifier_key_id: verifier_key.key_id.clone(),
            verifier_key_root: verifier_key.key_root(),
            verifier_key_commitment: verifier_key.verifier_key_commitment.clone(),
            transcript_domain_id: transcript_domain.domain_id.clone(),
            transcript_domain_root: transcript_domain.domain_root(),
            ceremony_id: ceremony.ceremony_id.clone(),
            ceremony_root: ceremony.ceremony_root(),
            estimated_constraints,
            max_public_inputs,
            max_witness_bytes,
            target_proof_bytes,
            recursion_compatible,
            security_bits,
            introduced_at_height,
            activated_at_height,
            deprecated_at_height: 0,
            metadata_root,
            status: PROOF_CIRCUIT_STATUS_ACTIVE.to_string(),
        };
        version.validate()?;
        Ok(version)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_CIRCUIT_STATUS_ACTIVE
            && self.activated_at_height <= height
            && (self.deprecated_at_height == 0 || height < self.deprecated_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_circuit_version",
            "chain_id": CHAIN_ID,
            "proof_circuit_protocol_version": PROOF_CIRCUIT_PROTOCOL_VERSION,
            "version_id": self.version_id,
            "family": self.family.as_str(),
            "circuit_name": self.circuit_name,
            "circuit_version": self.circuit_version,
            "proof_system": self.proof_system,
            "arithmetization": self.arithmetization,
            "constraint_system_root": self.constraint_system_root,
            "witness_schema_root": self.witness_schema_root,
            "public_input_schema_root": self.public_input_schema_root,
            "verifier_key_id": self.verifier_key_id,
            "verifier_key_root": self.verifier_key_root,
            "verifier_key_commitment": self.verifier_key_commitment,
            "transcript_domain_id": self.transcript_domain_id,
            "transcript_domain_root": self.transcript_domain_root,
            "ceremony_id": self.ceremony_id,
            "ceremony_root": self.ceremony_root,
            "estimated_constraints": self.estimated_constraints,
            "max_public_inputs": self.max_public_inputs,
            "max_witness_bytes": self.max_witness_bytes,
            "target_proof_bytes": self.target_proof_bytes,
            "recursion_compatible": self.recursion_compatible,
            "security_bits": self.security_bits,
            "introduced_at_height": self.introduced_at_height,
            "activated_at_height": self.activated_at_height,
            "deprecated_at_height": self.deprecated_at_height,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn circuit_root(&self) -> String {
        proof_circuit_version_root(self)
    }

    pub fn validate(&self) -> ProofCircuitResult<String> {
        ensure_non_empty(&self.version_id, "proof circuit version id")?;
        ensure_non_empty(&self.circuit_name, "proof circuit name")?;
        ensure_non_empty(&self.proof_system, "proof circuit proof system")?;
        ensure_non_empty(&self.arithmetization, "proof circuit arithmetization")?;
        ensure_non_empty(
            &self.constraint_system_root,
            "proof circuit constraint system root",
        )?;
        ensure_non_empty(
            &self.witness_schema_root,
            "proof circuit witness schema root",
        )?;
        ensure_non_empty(
            &self.public_input_schema_root,
            "proof circuit public input schema root",
        )?;
        ensure_non_empty(&self.verifier_key_id, "proof circuit verifier key id")?;
        ensure_non_empty(&self.verifier_key_root, "proof circuit verifier key root")?;
        ensure_non_empty(
            &self.verifier_key_commitment,
            "proof circuit verifier key commitment",
        )?;
        ensure_non_empty(
            &self.transcript_domain_id,
            "proof circuit transcript domain id",
        )?;
        ensure_non_empty(
            &self.transcript_domain_root,
            "proof circuit transcript domain root",
        )?;
        ensure_non_empty(&self.ceremony_id, "proof circuit ceremony id")?;
        ensure_non_empty(&self.ceremony_root, "proof circuit ceremony root")?;
        ensure_non_empty(&self.metadata_root, "proof circuit metadata root")?;
        if self.circuit_version == 0 {
            return Err("proof circuit version cannot be zero".to_string());
        }
        if self.estimated_constraints == 0 {
            return Err("proof circuit estimated constraints cannot be zero".to_string());
        }
        if self.max_witness_bytes == 0 || self.target_proof_bytes == 0 {
            return Err("proof circuit byte limits cannot be zero".to_string());
        }
        if self.security_bits < PROOF_CIRCUIT_DEFAULT_SECURITY_BITS {
            return Err("proof circuit security bits below policy minimum".to_string());
        }
        if self.activated_at_height < self.introduced_at_height {
            return Err("proof circuit activation precedes introduction".to_string());
        }
        if self.deprecated_at_height != 0 && self.deprecated_at_height <= self.activated_at_height {
            return Err("proof circuit deprecation must be after activation".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_CIRCUIT_STATUS_DRAFT,
                PROOF_CIRCUIT_STATUS_STAGED,
                PROOF_CIRCUIT_STATUS_ACTIVE,
                PROOF_CIRCUIT_STATUS_DEPRECATED,
                PROOF_CIRCUIT_STATUS_RETIRED,
                PROOF_CIRCUIT_STATUS_REVOKED,
            ],
            "proof circuit status",
        )?;
        let expected_constraint_system_root = circuit_constraint_system_root(
            self.family.as_str(),
            &self.circuit_name,
            self.circuit_version,
            &self.proof_system,
            self.estimated_constraints,
            &self.metadata_root,
        );
        if self.constraint_system_root != expected_constraint_system_root {
            return Err("proof circuit constraint system root mismatch".to_string());
        }
        let expected_witness_schema_root = circuit_witness_schema_root(
            self.family.as_str(),
            &self.circuit_name,
            self.circuit_version,
            self.max_witness_bytes,
            &self.metadata_root,
        );
        if self.witness_schema_root != expected_witness_schema_root {
            return Err("proof circuit witness schema root mismatch".to_string());
        }
        let expected_public_input_schema_root = circuit_public_input_schema_root(
            self.family.as_str(),
            &self.circuit_name,
            self.circuit_version,
            self.max_public_inputs,
            &self.metadata_root,
        );
        if self.public_input_schema_root != expected_public_input_schema_root {
            return Err("proof circuit public input schema root mismatch".to_string());
        }
        let expected_id = proof_circuit_version_id(
            self.family.as_str(),
            &self.circuit_name,
            self.circuit_version,
            &self.proof_system,
            &self.verifier_key_commitment,
            &self.transcript_domain_id,
        );
        if self.version_id != expected_id {
            return Err("proof circuit version id mismatch".to_string());
        }
        Ok(self.circuit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveAggregationPlan {
    pub plan_id: String,
    pub plan_name: String,
    pub input_circuit_version_ids: Vec<String>,
    pub input_circuit_root: String,
    pub output_circuit_version_id: String,
    pub output_circuit_root: String,
    pub max_children: u64,
    pub recursion_depth: u64,
    pub batch_window_blocks: u64,
    pub aggregation_policy_root: String,
    pub accumulator_root: String,
    pub transcript_domain_id: String,
    pub transcript_domain_root: String,
    pub verifier_key_id: String,
    pub verifier_key_root: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl RecursiveAggregationPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_name: impl Into<String>,
        input_circuits: &[ProofCircuitVersion],
        output_circuit: &ProofCircuitVersion,
        transcript_domain: &PqTranscriptDomain,
        verifier_key: &VerifierKeyCommitment,
        max_children: u64,
        recursion_depth: u64,
        batch_window_blocks: u64,
        activated_at_height: u64,
        expires_at_height: u64,
        policy: &Value,
    ) -> ProofCircuitResult<Self> {
        let plan_name = normalize_label(plan_name.into());
        ensure_non_empty(&plan_name, "recursive aggregation plan name")?;
        if input_circuits.is_empty() {
            return Err("recursive aggregation plan requires input circuits".to_string());
        }
        if output_circuit.family != ProofCircuitFamily::RecursiveAggregation {
            return Err("recursive aggregation plan output must be recursive".to_string());
        }
        if !output_circuit.recursion_compatible {
            return Err(
                "recursive aggregation output circuit must be recursion compatible".to_string(),
            );
        }
        if transcript_domain.family != ProofCircuitFamily::RecursiveAggregation {
            return Err("recursive aggregation transcript domain family mismatch".to_string());
        }
        if verifier_key.family != ProofCircuitFamily::RecursiveAggregation {
            return Err("recursive aggregation verifier key family mismatch".to_string());
        }
        if max_children == 0 || recursion_depth == 0 || batch_window_blocks == 0 {
            return Err("recursive aggregation plan numeric limits must be nonzero".to_string());
        }
        let mut input_circuit_version_ids = input_circuits
            .iter()
            .map(|circuit| circuit.version_id.clone())
            .collect::<Vec<_>>();
        input_circuit_version_ids.sort();
        ensure_unique_strings(
            &input_circuit_version_ids,
            "recursive aggregation input circuit id",
        )?;
        let input_circuit_root = proof_circuit_version_set_root(input_circuits);
        let output_circuit_root = output_circuit.circuit_root();
        let aggregation_policy_root =
            proof_circuit_payload_root("PROOF-CIRCUIT-AGGREGATION-POLICY", policy);
        let accumulator_root = recursive_accumulator_root(
            &input_circuit_root,
            &output_circuit_root,
            max_children,
            recursion_depth,
            &aggregation_policy_root,
        );
        let transcript_domain_root = transcript_domain.domain_root();
        let verifier_key_root = verifier_key.key_root();
        let plan_id = recursive_aggregation_plan_id(
            &plan_name,
            &input_circuit_root,
            &output_circuit.version_id,
            recursion_depth,
            max_children,
        );
        let plan = Self {
            plan_id,
            plan_name,
            input_circuit_version_ids,
            input_circuit_root,
            output_circuit_version_id: output_circuit.version_id.clone(),
            output_circuit_root,
            max_children,
            recursion_depth,
            batch_window_blocks,
            aggregation_policy_root,
            accumulator_root,
            transcript_domain_id: transcript_domain.domain_id.clone(),
            transcript_domain_root,
            verifier_key_id: verifier_key.key_id.clone(),
            verifier_key_root,
            activated_at_height,
            expires_at_height,
            status: PROOF_CIRCUIT_STATUS_ACTIVE.to_string(),
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_CIRCUIT_STATUS_ACTIVE
            && self.activated_at_height <= height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_aggregation_plan",
            "chain_id": CHAIN_ID,
            "proof_circuit_protocol_version": PROOF_CIRCUIT_PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "plan_name": self.plan_name,
            "input_circuit_version_ids": self.input_circuit_version_ids,
            "input_circuit_root": self.input_circuit_root,
            "output_circuit_version_id": self.output_circuit_version_id,
            "output_circuit_root": self.output_circuit_root,
            "max_children": self.max_children,
            "recursion_depth": self.recursion_depth,
            "batch_window_blocks": self.batch_window_blocks,
            "aggregation_policy_root": self.aggregation_policy_root,
            "accumulator_root": self.accumulator_root,
            "transcript_domain_id": self.transcript_domain_id,
            "transcript_domain_root": self.transcript_domain_root,
            "verifier_key_id": self.verifier_key_id,
            "verifier_key_root": self.verifier_key_root,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn plan_root(&self) -> String {
        recursive_aggregation_plan_root(self)
    }

    pub fn validate(&self) -> ProofCircuitResult<String> {
        ensure_non_empty(&self.plan_id, "recursive aggregation plan id")?;
        ensure_non_empty(&self.plan_name, "recursive aggregation plan name")?;
        ensure_non_empty(
            &self.input_circuit_root,
            "recursive aggregation input circuit root",
        )?;
        ensure_non_empty(
            &self.output_circuit_version_id,
            "recursive aggregation output circuit id",
        )?;
        ensure_non_empty(
            &self.output_circuit_root,
            "recursive aggregation output circuit root",
        )?;
        ensure_non_empty(
            &self.aggregation_policy_root,
            "recursive aggregation policy root",
        )?;
        ensure_non_empty(
            &self.accumulator_root,
            "recursive aggregation accumulator root",
        )?;
        ensure_non_empty(
            &self.transcript_domain_id,
            "recursive aggregation transcript domain id",
        )?;
        ensure_non_empty(
            &self.transcript_domain_root,
            "recursive aggregation transcript domain root",
        )?;
        ensure_non_empty(
            &self.verifier_key_id,
            "recursive aggregation verifier key id",
        )?;
        ensure_non_empty(
            &self.verifier_key_root,
            "recursive aggregation verifier key root",
        )?;
        ensure_unique_strings(
            &self.input_circuit_version_ids,
            "recursive aggregation input circuit id",
        )?;
        if self.input_circuit_version_ids.is_empty() {
            return Err("recursive aggregation plan requires input circuits".to_string());
        }
        if self.max_children == 0 || self.recursion_depth == 0 || self.batch_window_blocks == 0 {
            return Err("recursive aggregation plan numeric limits must be nonzero".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.activated_at_height {
            return Err("recursive aggregation plan expiry must be after activation".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_CIRCUIT_STATUS_STAGED,
                PROOF_CIRCUIT_STATUS_ACTIVE,
                PROOF_CIRCUIT_STATUS_DEPRECATED,
                PROOF_CIRCUIT_STATUS_RETIRED,
                PROOF_CIRCUIT_STATUS_REVOKED,
            ],
            "recursive aggregation plan status",
        )?;
        let expected_plan_id = recursive_aggregation_plan_id(
            &self.plan_name,
            &self.input_circuit_root,
            &self.output_circuit_version_id,
            self.recursion_depth,
            self.max_children,
        );
        if self.plan_id != expected_plan_id {
            return Err("recursive aggregation plan id mismatch".to_string());
        }
        let expected_accumulator_root = recursive_accumulator_root(
            &self.input_circuit_root,
            &self.output_circuit_root,
            self.max_children,
            self.recursion_depth,
            &self.aggregation_policy_root,
        );
        if self.accumulator_root != expected_accumulator_root {
            return Err("recursive aggregation accumulator root mismatch".to_string());
        }
        Ok(self.plan_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitAuditRecord {
    pub audit_id: String,
    pub target_kind: ProofCircuitAuditTarget,
    pub target_id: String,
    pub auditor_label: String,
    pub severity: ProofCircuitAuditSeverity,
    pub category: String,
    pub finding_root: String,
    pub evidence_root: String,
    pub recommendation_root: String,
    pub audited_at_height: u64,
    pub resolved_at_height: u64,
    pub retention_until_height: u64,
    pub metadata_root: String,
    pub status: String,
}

impl CircuitAuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_kind: ProofCircuitAuditTarget,
        target_id: impl Into<String>,
        auditor_label: impl Into<String>,
        severity: ProofCircuitAuditSeverity,
        category: impl Into<String>,
        finding: &Value,
        evidence: &Value,
        recommendation: &Value,
        audited_at_height: u64,
        metadata: &Value,
    ) -> ProofCircuitResult<Self> {
        let target_id = target_id.into();
        let auditor_label = normalize_label(auditor_label.into());
        let category = normalize_label(category.into());
        ensure_non_empty(&target_id, "proof circuit audit target id")?;
        ensure_non_empty(&auditor_label, "proof circuit audit auditor label")?;
        ensure_non_empty(&category, "proof circuit audit category")?;
        let finding_root = proof_circuit_payload_root("PROOF-CIRCUIT-AUDIT-FINDING", finding);
        let evidence_root = proof_circuit_payload_root("PROOF-CIRCUIT-AUDIT-EVIDENCE", evidence);
        let recommendation_root =
            proof_circuit_payload_root("PROOF-CIRCUIT-AUDIT-RECOMMENDATION", recommendation);
        let metadata_root = proof_circuit_payload_root("PROOF-CIRCUIT-AUDIT-METADATA", metadata);
        let audit_id = proof_circuit_audit_id(
            target_kind.as_str(),
            &target_id,
            &auditor_label,
            audited_at_height,
            &evidence_root,
        );
        let record = Self {
            audit_id,
            target_kind,
            target_id,
            auditor_label,
            severity,
            category,
            finding_root,
            evidence_root,
            recommendation_root,
            audited_at_height,
            resolved_at_height: 0,
            retention_until_height: audited_at_height
                .saturating_add(PROOF_CIRCUIT_DEFAULT_AUDIT_RETENTION_BLOCKS),
            metadata_root,
            status: "open".to_string(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn resolve(&mut self, resolved_at_height: u64) -> ProofCircuitResult<()> {
        if resolved_at_height < self.audited_at_height {
            return Err("proof circuit audit resolution precedes audit".to_string());
        }
        self.resolved_at_height = resolved_at_height;
        self.status = "resolved".to_string();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "circuit_audit_record",
            "chain_id": CHAIN_ID,
            "proof_circuit_protocol_version": PROOF_CIRCUIT_PROTOCOL_VERSION,
            "audit_id": self.audit_id,
            "target_kind": self.target_kind.as_str(),
            "target_id": self.target_id,
            "auditor_label": self.auditor_label,
            "severity": self.severity.as_str(),
            "score_delta": self.severity.score_delta(),
            "category": self.category,
            "finding_root": self.finding_root,
            "evidence_root": self.evidence_root,
            "recommendation_root": self.recommendation_root,
            "audited_at_height": self.audited_at_height,
            "resolved_at_height": self.resolved_at_height,
            "retention_until_height": self.retention_until_height,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn audit_root(&self) -> String {
        proof_circuit_audit_record_root(self)
    }

    pub fn validate(&self) -> ProofCircuitResult<String> {
        ensure_non_empty(&self.audit_id, "proof circuit audit id")?;
        ensure_non_empty(&self.target_id, "proof circuit audit target id")?;
        ensure_non_empty(&self.auditor_label, "proof circuit audit auditor label")?;
        ensure_non_empty(&self.category, "proof circuit audit category")?;
        ensure_non_empty(&self.finding_root, "proof circuit audit finding root")?;
        ensure_non_empty(&self.evidence_root, "proof circuit audit evidence root")?;
        ensure_non_empty(
            &self.recommendation_root,
            "proof circuit audit recommendation root",
        )?;
        ensure_non_empty(&self.metadata_root, "proof circuit audit metadata root")?;
        if self.resolved_at_height != 0 && self.resolved_at_height < self.audited_at_height {
            return Err("proof circuit audit resolution precedes audit".to_string());
        }
        if self.retention_until_height <= self.audited_at_height {
            return Err("proof circuit audit retention must extend past audit height".to_string());
        }
        ensure_status(
            &self.status,
            &[
                "open",
                "resolved",
                "accepted_risk",
                "false_positive",
                "superseded",
            ],
            "proof circuit audit status",
        )?;
        let expected_id = proof_circuit_audit_id(
            self.target_kind.as_str(),
            &self.target_id,
            &self.auditor_label,
            self.audited_at_height,
            &self.evidence_root,
        );
        if self.audit_id != expected_id {
            return Err("proof circuit audit id mismatch".to_string());
        }
        Ok(self.audit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierManifest {
    pub manifest_id: String,
    pub manifest_version: u64,
    pub network: String,
    pub circuit_version_ids: Vec<String>,
    pub circuit_version_root: String,
    pub verifier_key_ids: Vec<String>,
    pub verifier_key_root: String,
    pub transcript_domain_root: String,
    pub ceremony_root: String,
    pub recursive_plan_root: String,
    pub audit_root: String,
    pub generated_at_height: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub metadata_root: String,
    pub status: String,
}

impl VerifierManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest_version: u64,
        network: impl Into<String>,
        circuits: &[ProofCircuitVersion],
        verifier_keys: &[VerifierKeyCommitment],
        transcript_domains: &[PqTranscriptDomain],
        ceremonies: &[ParameterCeremony],
        recursive_plans: &[RecursiveAggregationPlan],
        audits: &[CircuitAuditRecord],
        generated_at_height: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        metadata: &Value,
    ) -> ProofCircuitResult<Self> {
        let network = network.into();
        ensure_non_empty(&network, "verifier manifest network")?;
        if manifest_version == 0 {
            return Err("verifier manifest version cannot be zero".to_string());
        }
        if circuits.is_empty() {
            return Err("verifier manifest requires circuits".to_string());
        }
        if verifier_keys.is_empty() {
            return Err("verifier manifest requires verifier keys".to_string());
        }
        if transcript_domains.is_empty() {
            return Err("verifier manifest requires transcript domains".to_string());
        }
        if ceremonies.is_empty() {
            return Err("verifier manifest requires ceremonies".to_string());
        }
        if valid_until_height != 0 && valid_until_height <= valid_from_height {
            return Err("verifier manifest expiry must be after validity start".to_string());
        }
        let mut circuit_version_ids = circuits
            .iter()
            .map(|circuit| circuit.version_id.clone())
            .collect::<Vec<_>>();
        circuit_version_ids.sort();
        ensure_unique_strings(&circuit_version_ids, "verifier manifest circuit version id")?;
        let mut verifier_key_ids = verifier_keys
            .iter()
            .map(|key| key.key_id.clone())
            .collect::<Vec<_>>();
        verifier_key_ids.sort();
        ensure_unique_strings(&verifier_key_ids, "verifier manifest verifier key id")?;
        let circuit_version_root = proof_circuit_version_set_root(circuits);
        let verifier_key_root = verifier_key_commitment_set_root(verifier_keys);
        let transcript_domain_root = pq_transcript_domain_set_root(transcript_domains);
        let ceremony_root = parameter_ceremony_set_root(ceremonies);
        let recursive_plan_root = recursive_aggregation_plan_set_root(recursive_plans);
        let audit_root = proof_circuit_audit_set_root(audits);
        let metadata_root = proof_circuit_payload_root("PROOF-CIRCUIT-MANIFEST-METADATA", metadata);
        let manifest_id = verifier_manifest_id(
            manifest_version,
            &network,
            &circuit_version_root,
            &verifier_key_root,
            &transcript_domain_root,
            valid_from_height,
        );
        let manifest = Self {
            manifest_id,
            manifest_version,
            network,
            circuit_version_ids,
            circuit_version_root,
            verifier_key_ids,
            verifier_key_root,
            transcript_domain_root,
            ceremony_root,
            recursive_plan_root,
            audit_root,
            generated_at_height,
            valid_from_height,
            valid_until_height,
            metadata_root,
            status: PROOF_CIRCUIT_STATUS_ACTIVE.to_string(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_CIRCUIT_STATUS_ACTIVE
            && self.valid_from_height <= height
            && (self.valid_until_height == 0 || height < self.valid_until_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_manifest",
            "chain_id": CHAIN_ID,
            "proof_circuit_protocol_version": PROOF_CIRCUIT_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "network": self.network,
            "circuit_version_ids": self.circuit_version_ids,
            "circuit_version_root": self.circuit_version_root,
            "verifier_key_ids": self.verifier_key_ids,
            "verifier_key_root": self.verifier_key_root,
            "transcript_domain_root": self.transcript_domain_root,
            "ceremony_root": self.ceremony_root,
            "recursive_plan_root": self.recursive_plan_root,
            "audit_root": self.audit_root,
            "generated_at_height": self.generated_at_height,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn manifest_root(&self) -> String {
        verifier_manifest_root(self)
    }

    pub fn validate(&self) -> ProofCircuitResult<String> {
        ensure_non_empty(&self.manifest_id, "verifier manifest id")?;
        ensure_non_empty(&self.network, "verifier manifest network")?;
        ensure_non_empty(
            &self.circuit_version_root,
            "verifier manifest circuit version root",
        )?;
        ensure_non_empty(
            &self.verifier_key_root,
            "verifier manifest verifier key root",
        )?;
        ensure_non_empty(
            &self.transcript_domain_root,
            "verifier manifest transcript domain root",
        )?;
        ensure_non_empty(&self.ceremony_root, "verifier manifest ceremony root")?;
        ensure_non_empty(
            &self.recursive_plan_root,
            "verifier manifest recursive plan root",
        )?;
        ensure_non_empty(&self.audit_root, "verifier manifest audit root")?;
        ensure_non_empty(&self.metadata_root, "verifier manifest metadata root")?;
        ensure_unique_strings(
            &self.circuit_version_ids,
            "verifier manifest circuit version id",
        )?;
        ensure_unique_strings(&self.verifier_key_ids, "verifier manifest verifier key id")?;
        if self.manifest_version == 0 {
            return Err("verifier manifest version cannot be zero".to_string());
        }
        if self.circuit_version_ids.is_empty() || self.verifier_key_ids.is_empty() {
            return Err("verifier manifest cannot be empty".to_string());
        }
        if self.valid_until_height != 0 && self.valid_until_height <= self.valid_from_height {
            return Err("verifier manifest expiry must be after validity start".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_CIRCUIT_STATUS_STAGED,
                PROOF_CIRCUIT_STATUS_ACTIVE,
                PROOF_CIRCUIT_STATUS_DEPRECATED,
                PROOF_CIRCUIT_STATUS_RETIRED,
                PROOF_CIRCUIT_STATUS_REVOKED,
            ],
            "verifier manifest status",
        )?;
        let expected_id = verifier_manifest_id(
            self.manifest_version,
            &self.network,
            &self.circuit_version_root,
            &self.verifier_key_root,
            &self.transcript_domain_root,
            self.valid_from_height,
        );
        if self.manifest_id != expected_id {
            return Err("verifier manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCircuitState {
    pub height: u64,
    pub transcript_domains: BTreeMap<String, PqTranscriptDomain>,
    pub parameter_ceremonies: BTreeMap<String, ParameterCeremony>,
    pub verifier_keys: BTreeMap<String, VerifierKeyCommitment>,
    pub circuit_versions: BTreeMap<String, ProofCircuitVersion>,
    pub recursive_plans: BTreeMap<String, RecursiveAggregationPlan>,
    pub verifier_manifests: BTreeMap<String, VerifierManifest>,
    pub audit_records: BTreeMap<String, CircuitAuditRecord>,
    pub active_manifest_id: Option<String>,
}

impl ProofCircuitState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> ProofCircuitResult<Self> {
        let mut state = Self::new();
        state.set_height(0);

        let state_domain = PqTranscriptDomain::new(
            ProofCircuitFamily::StateTransition.default_transcript_label(),
            ProofCircuitFamily::StateTransition,
            PqTranscriptPurpose::Proving,
            1,
            0,
            0,
            &json!({
                "mode": "deterministic_devnet",
                "public_inputs": ["previous_state_root", "next_state_root", "tx_root", "da_root"],
            }),
        )?;
        let privacy_domain = PqTranscriptDomain::new(
            ProofCircuitFamily::Privacy.default_transcript_label(),
            ProofCircuitFamily::Privacy,
            PqTranscriptPurpose::Proving,
            1,
            0,
            0,
            &json!({
                "mode": "deterministic_devnet",
                "privacy": "note_commitments_and_nullifiers",
            }),
        )?;
        let bridge_domain = PqTranscriptDomain::new(
            ProofCircuitFamily::Bridge.default_transcript_label(),
            ProofCircuitFamily::Bridge,
            PqTranscriptPurpose::BridgeFinality,
            1,
            0,
            0,
            &json!({
                "mode": "deterministic_devnet",
                "settlement": "monero_finality_and_reserve_roots",
            }),
        )?;
        let da_domain = PqTranscriptDomain::new(
            ProofCircuitFamily::DataAvailability.default_transcript_label(),
            ProofCircuitFamily::DataAvailability,
            PqTranscriptPurpose::DataAvailability,
            1,
            0,
            0,
            &json!({
                "mode": "deterministic_devnet",
                "availability": "erasure_commitments_and_sampling",
            }),
        )?;
        let recursive_domain = PqTranscriptDomain::new(
            ProofCircuitFamily::RecursiveAggregation.default_transcript_label(),
            ProofCircuitFamily::RecursiveAggregation,
            PqTranscriptPurpose::Recursion,
            1,
            0,
            0,
            &json!({
                "mode": "deterministic_devnet",
                "aggregation": "recursive_verifier_accumulator",
            }),
        )?;

        state.insert_transcript_domain(state_domain.clone())?;
        state.insert_transcript_domain(privacy_domain.clone())?;
        state.insert_transcript_domain(bridge_domain.clone())?;
        state.insert_transcript_domain(da_domain.clone())?;
        state.insert_transcript_domain(recursive_domain.clone())?;

        install_devnet_circuit(
            &mut state,
            ProofCircuitFamily::StateTransition,
            "state_transition_batch",
            &state_domain,
            3_200_000,
            24,
            8 * 1024 * 1024,
            196_608,
            true,
            &json!({
                "verifies": ["sequencer_batch", "fee_accounting", "state_delta"],
                "rollup_surface": "block_validity",
            }),
        )?;
        install_devnet_circuit(
            &mut state,
            ProofCircuitFamily::Privacy,
            "shielded_transfer",
            &privacy_domain,
            2_400_000,
            32,
            6 * 1024 * 1024,
            131_072,
            true,
            &json!({
                "verifies": ["note_membership", "nullifier_uniqueness", "amount_conservation"],
                "disclosure": "commitment_only",
            }),
        )?;
        install_devnet_circuit(
            &mut state,
            ProofCircuitFamily::Privacy,
            "selective_disclosure",
            &privacy_domain,
            900_000,
            20,
            2 * 1024 * 1024,
            98_304,
            true,
            &json!({
                "verifies": ["viewing_key_policy", "field_commitment", "audit_scope"],
                "disclosure": "scoped",
            }),
        )?;
        install_devnet_circuit(
            &mut state,
            ProofCircuitFamily::Bridge,
            "monero_bridge_deposit",
            &bridge_domain,
            1_600_000,
            28,
            4 * 1024 * 1024,
            114_688,
            true,
            &json!({
                "verifies": ["monero_tx_observation", "confirmation_depth", "deposit_address_commitment"],
                "asset": "xmr",
            }),
        )?;
        install_devnet_circuit(
            &mut state,
            ProofCircuitFamily::Bridge,
            "monero_bridge_withdrawal",
            &bridge_domain,
            1_900_000,
            30,
            4 * 1024 * 1024,
            122_880,
            true,
            &json!({
                "verifies": ["withdrawal_queue", "reserve_release_policy", "monero_address_commitment"],
                "asset": "xmr",
            }),
        )?;
        install_devnet_circuit(
            &mut state,
            ProofCircuitFamily::DataAvailability,
            "erasure_commitment",
            &da_domain,
            1_100_000,
            36,
            3 * 1024 * 1024,
            106_496,
            true,
            &json!({
                "verifies": ["lane_root", "shard_commitment_root", "retention_policy"],
                "sampling": "challenge_seeded",
            }),
        )?;
        install_devnet_circuit(
            &mut state,
            ProofCircuitFamily::DataAvailability,
            "sampling_response",
            &da_domain,
            700_000,
            18,
            2 * 1024 * 1024,
            90_112,
            true,
            &json!({
                "verifies": ["sample_index", "shard_hash", "committee_member"],
                "sampling": "deterministic_indices",
            }),
        )?;
        install_devnet_circuit(
            &mut state,
            ProofCircuitFamily::RecursiveAggregation,
            "block_validity_aggregate",
            &recursive_domain,
            2_800_000,
            40,
            5 * 1024 * 1024,
            147_456,
            true,
            &json!({
                "aggregates": ["state_transition_batch", "shielded_transfer", "bridge", "data_availability"],
                "output": "single_block_verifier_input",
            }),
        )?;
        install_devnet_circuit(
            &mut state,
            ProofCircuitFamily::RecursiveAggregation,
            "epoch_checkpoint_aggregate",
            &recursive_domain,
            3_600_000,
            48,
            7 * 1024 * 1024,
            163_840,
            true,
            &json!({
                "aggregates": ["block_validity_aggregate", "sampling_response"],
                "output": "settlement_checkpoint_verifier_input",
            }),
        )?;

        let block_inputs = state.circuits_by_names(&[
            "state_transition_batch",
            "shielded_transfer",
            "monero_bridge_withdrawal",
            "erasure_commitment",
        ])?;
        let block_output = state.circuit_by_name("block_validity_aggregate")?;
        let block_output_key = state
            .verifier_keys
            .get(&block_output.verifier_key_id)
            .cloned()
            .ok_or_else(|| "block aggregate verifier key missing".to_string())?;
        let block_plan = RecursiveAggregationPlan::new(
            "devnet_block_validity",
            &block_inputs,
            &block_output,
            &recursive_domain,
            &block_output_key,
            PROOF_CIRCUIT_DEFAULT_MAX_AGGREGATION_CHILDREN,
            PROOF_CIRCUIT_DEFAULT_RECURSION_DEPTH,
            PROOF_CIRCUIT_DEFAULT_BATCH_WINDOW_BLOCKS,
            0,
            0,
            &json!({
                "batching": "block",
                "soundness": "all_input_roots_bound",
                "fallback": "per_family_verification",
            }),
        )?;
        state.insert_recursive_plan(block_plan)?;

        let epoch_inputs = state.circuits_by_names(&[
            "block_validity_aggregate",
            "sampling_response",
            "monero_bridge_deposit",
            "selective_disclosure",
        ])?;
        let epoch_output = state.circuit_by_name("epoch_checkpoint_aggregate")?;
        let epoch_output_key = state
            .verifier_keys
            .get(&epoch_output.verifier_key_id)
            .cloned()
            .ok_or_else(|| "epoch aggregate verifier key missing".to_string())?;
        let epoch_plan = RecursiveAggregationPlan::new(
            "devnet_epoch_checkpoint",
            &epoch_inputs,
            &epoch_output,
            &recursive_domain,
            &epoch_output_key,
            PROOF_CIRCUIT_DEFAULT_MAX_AGGREGATION_CHILDREN.saturating_mul(4),
            PROOF_CIRCUIT_DEFAULT_RECURSION_DEPTH.saturating_add(1),
            PROOF_CIRCUIT_DEFAULT_BATCH_WINDOW_BLOCKS.saturating_mul(4),
            0,
            0,
            &json!({
                "batching": "epoch",
                "settlement": "monero_anchor_ready",
                "fallback": "block_validity_manifests",
            }),
        )?;
        state.insert_recursive_plan(epoch_plan)?;

        for circuit in state.circuit_versions.values().cloned().collect::<Vec<_>>() {
            let audit = CircuitAuditRecord::new(
                ProofCircuitAuditTarget::CircuitVersion,
                circuit.version_id,
                "devnet-audit",
                ProofCircuitAuditSeverity::Info,
                "deterministic_registry",
                &json!({
                    "summary": "devnet circuit is deterministically parameterized",
                    "family": circuit.family.as_str(),
                    "circuit_name": circuit.circuit_name,
                }),
                &json!({
                    "constraint_system_root": circuit.constraint_system_root,
                    "verifier_key_commitment": circuit.verifier_key_commitment,
                    "transcript_domain_id": circuit.transcript_domain_id,
                }),
                &json!({
                    "action": "retain active manifest binding and refresh on circuit upgrade",
                }),
                0,
                &json!({
                    "scope": "devnet",
                    "auditor": "deterministic lifecycle check",
                }),
            )?;
            state.insert_audit_record(audit)?;
        }

        let manifest = VerifierManifest::new(
            PROOF_CIRCUIT_DEFAULT_MANIFEST_VERSION,
            CHAIN_ID,
            &state.circuit_versions.values().cloned().collect::<Vec<_>>(),
            &state.verifier_keys.values().cloned().collect::<Vec<_>>(),
            &state
                .transcript_domains
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            &state
                .parameter_ceremonies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
            &state.recursive_plans.values().cloned().collect::<Vec<_>>(),
            &state.audit_records.values().cloned().collect::<Vec<_>>(),
            0,
            0,
            0,
            &json!({
                "profile": "devnet",
                "purpose": "deterministic proof circuit verifier manifest",
                "families": [
                    "state_transition",
                    "privacy",
                    "bridge",
                    "data_availability",
                    "recursive_aggregation"
                ],
            }),
        )?;
        let manifest_id = manifest.manifest_id.clone();
        state.insert_verifier_manifest(manifest)?;
        state.publish_manifest(&manifest_id)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn insert_transcript_domain(
        &mut self,
        domain: PqTranscriptDomain,
    ) -> ProofCircuitResult<String> {
        domain.validate()?;
        insert_unique_record(
            &mut self.transcript_domains,
            domain.domain_id.clone(),
            domain,
            "PQ transcript domain",
        )
    }

    pub fn insert_parameter_ceremony(
        &mut self,
        ceremony: ParameterCeremony,
    ) -> ProofCircuitResult<String> {
        ceremony.validate()?;
        insert_unique_record(
            &mut self.parameter_ceremonies,
            ceremony.ceremony_id.clone(),
            ceremony,
            "parameter ceremony",
        )
    }

    pub fn insert_verifier_key(
        &mut self,
        key: VerifierKeyCommitment,
    ) -> ProofCircuitResult<String> {
        key.validate()?;
        if !self
            .transcript_domains
            .contains_key(&key.transcript_domain_id)
        {
            return Err("verifier key references unknown transcript domain".to_string());
        }
        if !self.parameter_ceremonies.contains_key(&key.ceremony_id) {
            return Err("verifier key references unknown parameter ceremony".to_string());
        }
        insert_unique_record(
            &mut self.verifier_keys,
            key.key_id.clone(),
            key,
            "verifier key",
        )
    }

    pub fn insert_circuit_version(
        &mut self,
        circuit: ProofCircuitVersion,
    ) -> ProofCircuitResult<String> {
        circuit.validate()?;
        if !self.verifier_keys.contains_key(&circuit.verifier_key_id) {
            return Err("proof circuit references unknown verifier key".to_string());
        }
        if !self
            .transcript_domains
            .contains_key(&circuit.transcript_domain_id)
        {
            return Err("proof circuit references unknown transcript domain".to_string());
        }
        if !self.parameter_ceremonies.contains_key(&circuit.ceremony_id) {
            return Err("proof circuit references unknown parameter ceremony".to_string());
        }
        insert_unique_record(
            &mut self.circuit_versions,
            circuit.version_id.clone(),
            circuit,
            "proof circuit version",
        )
    }

    pub fn insert_recursive_plan(
        &mut self,
        plan: RecursiveAggregationPlan,
    ) -> ProofCircuitResult<String> {
        plan.validate()?;
        for circuit_id in &plan.input_circuit_version_ids {
            if !self.circuit_versions.contains_key(circuit_id) {
                return Err(
                    "recursive aggregation plan references unknown input circuit".to_string(),
                );
            }
        }
        if !self
            .circuit_versions
            .contains_key(&plan.output_circuit_version_id)
        {
            return Err("recursive aggregation plan references unknown output circuit".to_string());
        }
        if !self
            .transcript_domains
            .contains_key(&plan.transcript_domain_id)
        {
            return Err(
                "recursive aggregation plan references unknown transcript domain".to_string(),
            );
        }
        if !self.verifier_keys.contains_key(&plan.verifier_key_id) {
            return Err("recursive aggregation plan references unknown verifier key".to_string());
        }
        insert_unique_record(
            &mut self.recursive_plans,
            plan.plan_id.clone(),
            plan,
            "recursive aggregation plan",
        )
    }

    pub fn insert_verifier_manifest(
        &mut self,
        manifest: VerifierManifest,
    ) -> ProofCircuitResult<String> {
        manifest.validate()?;
        for circuit_id in &manifest.circuit_version_ids {
            if !self.circuit_versions.contains_key(circuit_id) {
                return Err("verifier manifest references unknown circuit".to_string());
            }
        }
        for key_id in &manifest.verifier_key_ids {
            if !self.verifier_keys.contains_key(key_id) {
                return Err("verifier manifest references unknown verifier key".to_string());
            }
        }
        insert_unique_record(
            &mut self.verifier_manifests,
            manifest.manifest_id.clone(),
            manifest,
            "verifier manifest",
        )
    }

    pub fn insert_audit_record(&mut self, audit: CircuitAuditRecord) -> ProofCircuitResult<String> {
        audit.validate()?;
        insert_unique_record(
            &mut self.audit_records,
            audit.audit_id.clone(),
            audit,
            "proof circuit audit",
        )
    }

    pub fn activate_circuit_version(
        &mut self,
        version_id: &str,
        activated_at_height: u64,
    ) -> ProofCircuitResult<ProofCircuitVersion> {
        let circuit = self
            .circuit_versions
            .get_mut(version_id)
            .ok_or_else(|| "unknown proof circuit version".to_string())?;
        if activated_at_height < circuit.introduced_at_height {
            return Err("proof circuit activation precedes introduction".to_string());
        }
        circuit.activated_at_height = activated_at_height;
        circuit.status = PROOF_CIRCUIT_STATUS_ACTIVE.to_string();
        circuit.validate()?;
        Ok(circuit.clone())
    }

    pub fn retire_circuit_version(
        &mut self,
        version_id: &str,
        retired_at_height: u64,
    ) -> ProofCircuitResult<ProofCircuitVersion> {
        let circuit = self
            .circuit_versions
            .get_mut(version_id)
            .ok_or_else(|| "unknown proof circuit version".to_string())?;
        if retired_at_height <= circuit.activated_at_height {
            return Err("proof circuit retirement must be after activation".to_string());
        }
        circuit.deprecated_at_height = retired_at_height;
        circuit.status = PROOF_CIRCUIT_STATUS_RETIRED.to_string();
        circuit.validate()?;
        Ok(circuit.clone())
    }

    pub fn publish_manifest(&mut self, manifest_id: &str) -> ProofCircuitResult<VerifierManifest> {
        let manifest = self
            .verifier_manifests
            .get_mut(manifest_id)
            .ok_or_else(|| "unknown verifier manifest".to_string())?;
        if manifest.valid_from_height > self.height
            || (manifest.valid_until_height != 0 && self.height >= manifest.valid_until_height)
        {
            return Err("verifier manifest is outside its validity window".to_string());
        }
        manifest.status = PROOF_CIRCUIT_STATUS_ACTIVE.to_string();
        manifest.validate()?;
        self.active_manifest_id = Some(manifest_id.to_string());
        Ok(manifest.clone())
    }

    pub fn transcript_domain_root(&self) -> String {
        pq_transcript_domain_set_root(
            &self
                .transcript_domains
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn parameter_ceremony_root(&self) -> String {
        parameter_ceremony_set_root(
            &self
                .parameter_ceremonies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn verifier_key_root(&self) -> String {
        verifier_key_commitment_set_root(&self.verifier_keys.values().cloned().collect::<Vec<_>>())
    }

    pub fn circuit_version_root(&self) -> String {
        proof_circuit_version_set_root(&self.circuit_versions.values().cloned().collect::<Vec<_>>())
    }

    pub fn recursive_plan_root(&self) -> String {
        recursive_aggregation_plan_set_root(
            &self.recursive_plans.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn verifier_manifest_root(&self) -> String {
        verifier_manifest_set_root(
            &self
                .verifier_manifests
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn audit_root(&self) -> String {
        proof_circuit_audit_set_root(&self.audit_records.values().cloned().collect::<Vec<_>>())
    }

    pub fn active_circuit_count(&self) -> u64 {
        self.circuit_versions
            .values()
            .filter(|circuit| circuit.is_active_at(self.height))
            .count() as u64
    }

    pub fn active_recursive_plan_count(&self) -> u64 {
        self.recursive_plans
            .values()
            .filter(|plan| plan.is_active_at(self.height))
            .count() as u64
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "proof_circuit_state",
            "chain_id": CHAIN_ID,
            "proof_circuit_protocol_version": PROOF_CIRCUIT_PROTOCOL_VERSION,
            "schema_version": PROOF_CIRCUIT_SCHEMA_VERSION,
            "height": self.height,
            "transcript_domain_root": self.transcript_domain_root(),
            "parameter_ceremony_root": self.parameter_ceremony_root(),
            "verifier_key_root": self.verifier_key_root(),
            "circuit_version_root": self.circuit_version_root(),
            "recursive_plan_root": self.recursive_plan_root(),
            "verifier_manifest_root": self.verifier_manifest_root(),
            "audit_root": self.audit_root(),
            "transcript_domain_count": self.transcript_domains.len() as u64,
            "parameter_ceremony_count": self.parameter_ceremonies.len() as u64,
            "verifier_key_count": self.verifier_keys.len() as u64,
            "circuit_version_count": self.circuit_versions.len() as u64,
            "active_circuit_count": self.active_circuit_count(),
            "recursive_plan_count": self.recursive_plans.len() as u64,
            "active_recursive_plan_count": self.active_recursive_plan_count(),
            "verifier_manifest_count": self.verifier_manifests.len() as u64,
            "audit_record_count": self.audit_records.len() as u64,
            "active_manifest_id": self.active_manifest_id,
        })
    }

    pub fn state_root(&self) -> String {
        proof_circuit_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("proof circuit state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> ProofCircuitResult<String> {
        for domain in self.transcript_domains.values() {
            domain.validate()?;
        }
        for ceremony in self.parameter_ceremonies.values() {
            ceremony.validate()?;
        }
        for key in self.verifier_keys.values() {
            key.validate()?;
            if !self
                .transcript_domains
                .contains_key(&key.transcript_domain_id)
            {
                return Err("verifier key references unknown transcript domain".to_string());
            }
            if !self.parameter_ceremonies.contains_key(&key.ceremony_id) {
                return Err("verifier key references unknown parameter ceremony".to_string());
            }
        }
        for circuit in self.circuit_versions.values() {
            circuit.validate()?;
            if !self.verifier_keys.contains_key(&circuit.verifier_key_id) {
                return Err("proof circuit references unknown verifier key".to_string());
            }
            if !self
                .transcript_domains
                .contains_key(&circuit.transcript_domain_id)
            {
                return Err("proof circuit references unknown transcript domain".to_string());
            }
            if !self.parameter_ceremonies.contains_key(&circuit.ceremony_id) {
                return Err("proof circuit references unknown parameter ceremony".to_string());
            }
        }
        for plan in self.recursive_plans.values() {
            plan.validate()?;
            for circuit_id in &plan.input_circuit_version_ids {
                if !self.circuit_versions.contains_key(circuit_id) {
                    return Err(
                        "recursive aggregation plan references unknown input circuit".to_string(),
                    );
                }
            }
            if !self
                .circuit_versions
                .contains_key(&plan.output_circuit_version_id)
            {
                return Err(
                    "recursive aggregation plan references unknown output circuit".to_string(),
                );
            }
        }
        for manifest in self.verifier_manifests.values() {
            manifest.validate()?;
            for circuit_id in &manifest.circuit_version_ids {
                if !self.circuit_versions.contains_key(circuit_id) {
                    return Err("verifier manifest references unknown circuit".to_string());
                }
            }
            for key_id in &manifest.verifier_key_ids {
                if !self.verifier_keys.contains_key(key_id) {
                    return Err("verifier manifest references unknown verifier key".to_string());
                }
            }
        }
        for audit in self.audit_records.values() {
            audit.validate()?;
        }
        if let Some(active_manifest_id) = &self.active_manifest_id {
            let manifest = self
                .verifier_manifests
                .get(active_manifest_id)
                .ok_or_else(|| "active verifier manifest is missing".to_string())?;
            if !manifest.is_active_at(self.height) {
                return Err("active verifier manifest is not active at current height".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn circuit_by_name(&self, circuit_name: &str) -> ProofCircuitResult<ProofCircuitVersion> {
        self.circuit_versions
            .values()
            .find(|circuit| circuit.circuit_name == circuit_name)
            .cloned()
            .ok_or_else(|| format!("proof circuit not found: {circuit_name}"))
    }

    fn circuits_by_names(
        &self,
        circuit_names: &[&str],
    ) -> ProofCircuitResult<Vec<ProofCircuitVersion>> {
        circuit_names
            .iter()
            .map(|name| self.circuit_by_name(name))
            .collect()
    }
}

pub fn proof_circuit_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROOF_CIRCUIT_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn proof_circuit_string_root(label: &str, value: &str) -> String {
    domain_hash(
        "PROOF-CIRCUIT-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn proof_circuit_string_set_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn pq_transcript_context_root(
    label: &str,
    family: &str,
    purpose: &str,
    domain_version: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PQ-TRANSCRIPT-CONTEXT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(family),
            HashPart::Str(purpose),
            HashPart::Int(domain_version as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn pq_transcript_domain_id(
    label: &str,
    family: &str,
    purpose: &str,
    separation_tag: &str,
    context_root: &str,
    domain_version: u64,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PQ-TRANSCRIPT-DOMAIN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(family),
            HashPart::Str(purpose),
            HashPart::Str(separation_tag),
            HashPart::Str(context_root),
            HashPart::Int(domain_version as i128),
        ],
        32,
    )
}

pub fn pq_transcript_domain_root(domain: &PqTranscriptDomain) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PQ-TRANSCRIPT-DOMAIN",
        &[HashPart::Json(&domain.public_record())],
        32,
    )
}

pub fn pq_transcript_domain_set_root(domains: &[PqTranscriptDomain]) -> String {
    let mut records = domains
        .iter()
        .map(|domain| (domain.domain_id.clone(), domain.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-CIRCUIT-PQ-TRANSCRIPT-DOMAIN",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn parameter_contribution_root(
    family: &str,
    circuit_name: &str,
    contribution_label: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PARAMETER-CONTRIBUTION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Str(contribution_label),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn parameter_ceremony_transcript_root(
    family: &str,
    circuit_name: &str,
    ceremony_kind: &str,
    participant_root: &str,
    contribution_root: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PARAMETER-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Str(ceremony_kind),
            HashPart::Str(participant_root),
            HashPart::Str(contribution_root),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn parameter_ceremony_beacon_root(
    family: &str,
    circuit_name: &str,
    transcript_root: &str,
    closed_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PARAMETER-BEACON",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Str(transcript_root),
            HashPart::Int(closed_at_height as i128),
        ],
        32,
    )
}

pub fn parameter_proving_key_commitment(
    family: &str,
    circuit_name: &str,
    transcript_root: &str,
    randomness_beacon_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PROVING-KEY-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Str(transcript_root),
            HashPart::Str(randomness_beacon_root),
        ],
        32,
    )
}

pub fn parameter_verifier_key_seed_root(
    family: &str,
    circuit_name: &str,
    proving_key_commitment: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-VERIFIER-KEY-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Str(proving_key_commitment),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn parameter_ceremony_id(
    family: &str,
    circuit_name: &str,
    ceremony_kind: &str,
    transcript_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PARAMETER-CEREMONY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Str(ceremony_kind),
            HashPart::Str(transcript_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn parameter_ceremony_root(ceremony: &ParameterCeremony) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PARAMETER-CEREMONY",
        &[HashPart::Json(&ceremony.public_record())],
        32,
    )
}

pub fn parameter_ceremony_set_root(ceremonies: &[ParameterCeremony]) -> String {
    let mut records = ceremonies
        .iter()
        .map(|ceremony| (ceremony.ceremony_id.clone(), ceremony.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-CIRCUIT-PARAMETER-CEREMONY",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn deterministic_verifier_key_root(
    family: &str,
    circuit_name: &str,
    proof_system: &str,
    key_version: u64,
    verifier_key_seed_root: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-DETERMINISTIC-VERIFIER-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Str(proof_system),
            HashPart::Int(key_version as i128),
            HashPart::Str(verifier_key_seed_root),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn verifier_key_commitment_hash(
    proof_system: &str,
    key_format: &str,
    key_version: u64,
    verifier_key_root: &str,
    transcript_domain_root: &str,
    ceremony_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-VERIFIER-KEY-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Str(key_format),
            HashPart::Int(key_version as i128),
            HashPart::Str(verifier_key_root),
            HashPart::Str(transcript_domain_root),
            HashPart::Str(ceremony_root),
        ],
        32,
    )
}

pub fn verifier_key_commitment_id(
    family: &str,
    circuit_name: &str,
    proof_system: &str,
    verifier_key_commitment: &str,
    ceremony_id: &str,
    key_version: u64,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-VERIFIER-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Str(proof_system),
            HashPart::Str(verifier_key_commitment),
            HashPart::Str(ceremony_id),
            HashPart::Int(key_version as i128),
        ],
        32,
    )
}

pub fn verifier_key_commitment_root(key: &VerifierKeyCommitment) -> String {
    domain_hash(
        "PROOF-CIRCUIT-VERIFIER-KEY",
        &[HashPart::Json(&key.public_record())],
        32,
    )
}

pub fn verifier_key_commitment_set_root(keys: &[VerifierKeyCommitment]) -> String {
    let mut records = keys
        .iter()
        .map(|key| (key.key_id.clone(), key.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-CIRCUIT-VERIFIER-KEY",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn circuit_constraint_system_root(
    family: &str,
    circuit_name: &str,
    circuit_version: u64,
    proof_system: &str,
    estimated_constraints: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-CONSTRAINT-SYSTEM",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(circuit_version as i128),
            HashPart::Str(proof_system),
            HashPart::Int(estimated_constraints as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn circuit_witness_schema_root(
    family: &str,
    circuit_name: &str,
    circuit_version: u64,
    max_witness_bytes: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-WITNESS-SCHEMA",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(circuit_version as i128),
            HashPart::Int(max_witness_bytes as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn circuit_public_input_schema_root(
    family: &str,
    circuit_name: &str,
    circuit_version: u64,
    max_public_inputs: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-PUBLIC-INPUT-SCHEMA",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(circuit_version as i128),
            HashPart::Int(max_public_inputs as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn proof_circuit_version_id(
    family: &str,
    circuit_name: &str,
    circuit_version: u64,
    proof_system: &str,
    verifier_key_commitment: &str,
    transcript_domain_id: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-VERSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(circuit_version as i128),
            HashPart::Str(proof_system),
            HashPart::Str(verifier_key_commitment),
            HashPart::Str(transcript_domain_id),
        ],
        32,
    )
}

pub fn proof_circuit_version_root(circuit: &ProofCircuitVersion) -> String {
    domain_hash(
        "PROOF-CIRCUIT-VERSION",
        &[HashPart::Json(&circuit.public_record())],
        32,
    )
}

pub fn proof_circuit_version_set_root(circuits: &[ProofCircuitVersion]) -> String {
    let mut records = circuits
        .iter()
        .map(|circuit| (circuit.version_id.clone(), circuit.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-CIRCUIT-VERSION",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn recursive_accumulator_root(
    input_circuit_root: &str,
    output_circuit_root: &str,
    max_children: u64,
    recursion_depth: u64,
    aggregation_policy_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-RECURSIVE-ACCUMULATOR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(input_circuit_root),
            HashPart::Str(output_circuit_root),
            HashPart::Int(max_children as i128),
            HashPart::Int(recursion_depth as i128),
            HashPart::Str(aggregation_policy_root),
        ],
        32,
    )
}

pub fn recursive_aggregation_plan_id(
    plan_name: &str,
    input_circuit_root: &str,
    output_circuit_version_id: &str,
    recursion_depth: u64,
    max_children: u64,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-RECURSIVE-PLAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(plan_name),
            HashPart::Str(input_circuit_root),
            HashPart::Str(output_circuit_version_id),
            HashPart::Int(recursion_depth as i128),
            HashPart::Int(max_children as i128),
        ],
        32,
    )
}

pub fn recursive_aggregation_plan_root(plan: &RecursiveAggregationPlan) -> String {
    domain_hash(
        "PROOF-CIRCUIT-RECURSIVE-PLAN",
        &[HashPart::Json(&plan.public_record())],
        32,
    )
}

pub fn recursive_aggregation_plan_set_root(plans: &[RecursiveAggregationPlan]) -> String {
    let mut records = plans
        .iter()
        .map(|plan| (plan.plan_id.clone(), plan.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-CIRCUIT-RECURSIVE-PLAN",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn proof_circuit_audit_id(
    target_kind: &str,
    target_id: &str,
    auditor_label: &str,
    audited_at_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-AUDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(auditor_label),
            HashPart::Int(audited_at_height as i128),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn proof_circuit_audit_record_root(audit: &CircuitAuditRecord) -> String {
    domain_hash(
        "PROOF-CIRCUIT-AUDIT-RECORD",
        &[HashPart::Json(&audit.public_record())],
        32,
    )
}

pub fn proof_circuit_audit_set_root(audits: &[CircuitAuditRecord]) -> String {
    let mut records = audits
        .iter()
        .map(|audit| (audit.audit_id.clone(), audit.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-CIRCUIT-AUDIT-RECORD",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn verifier_manifest_id(
    manifest_version: u64,
    network: &str,
    circuit_version_root: &str,
    verifier_key_root: &str,
    transcript_domain_root: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "PROOF-CIRCUIT-VERIFIER-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(manifest_version as i128),
            HashPart::Str(network),
            HashPart::Str(circuit_version_root),
            HashPart::Str(verifier_key_root),
            HashPart::Str(transcript_domain_root),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn verifier_manifest_root(manifest: &VerifierManifest) -> String {
    domain_hash(
        "PROOF-CIRCUIT-VERIFIER-MANIFEST",
        &[HashPart::Json(&manifest.public_record())],
        32,
    )
}

pub fn verifier_manifest_set_root(manifests: &[VerifierManifest]) -> String {
    let mut records = manifests
        .iter()
        .map(|manifest| (manifest.manifest_id.clone(), manifest.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-CIRCUIT-VERIFIER-MANIFEST",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn proof_circuit_state_root_from_record(record: &Value) -> String {
    domain_hash("PROOF-CIRCUIT-STATE", &[HashPart::Json(record)], 32)
}

pub fn proof_circuit_state_root(state: &ProofCircuitState) -> String {
    state.state_root()
}

#[allow(clippy::too_many_arguments)]
fn install_devnet_circuit(
    state: &mut ProofCircuitState,
    family: ProofCircuitFamily,
    circuit_name: &str,
    transcript_domain: &PqTranscriptDomain,
    estimated_constraints: u64,
    max_public_inputs: u64,
    max_witness_bytes: u64,
    target_proof_bytes: u64,
    recursion_compatible: bool,
    metadata: &Value,
) -> ProofCircuitResult<String> {
    let proof_system = family.default_proof_system();
    let participant_labels = vec![
        "devnet-sequencer".to_string(),
        "devnet-prover-a".to_string(),
        "devnet-prover-b".to_string(),
        "devnet-watchtower".to_string(),
    ];
    let contribution_labels = vec![
        format!("{circuit_name}-contribution-a"),
        format!("{circuit_name}-contribution-b"),
        format!("{circuit_name}-beacon"),
    ];
    let ceremony = ParameterCeremony::new(
        family.clone(),
        circuit_name,
        if family == ProofCircuitFamily::RecursiveAggregation {
            ParameterCeremonyKind::Recursive
        } else {
            ParameterCeremonyKind::DevnetDeterministic
        },
        participant_labels,
        contribution_labels,
        0,
        1,
        3,
        metadata,
    )?;
    let verifier_key = VerifierKeyCommitment::new(
        family.clone(),
        circuit_name,
        proof_system,
        "devnet-compact-vk-json",
        1,
        transcript_domain,
        &ceremony,
        0,
        0,
        metadata,
    )?;
    let circuit = ProofCircuitVersion::new(
        family,
        circuit_name,
        1,
        proof_system,
        "plonkish_air_hybrid",
        &verifier_key,
        transcript_domain,
        &ceremony,
        estimated_constraints,
        max_public_inputs,
        max_witness_bytes,
        target_proof_bytes,
        recursion_compatible,
        PROOF_CIRCUIT_DEFAULT_SECURITY_BITS,
        0,
        0,
        metadata,
    )?;
    let version_id = circuit.version_id.clone();
    state.insert_parameter_ceremony(ceremony)?;
    state.insert_verifier_key(verifier_key)?;
    state.insert_circuit_version(circuit)?;
    Ok(version_id)
}

fn normalize_label(value: String) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn normalize_unique_strings(values: Vec<String>, label: &str) -> ProofCircuitResult<Vec<String>> {
    let mut values = values
        .into_iter()
        .map(normalize_label)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    if values.is_empty() {
        return Err(format!("{label} list cannot be empty"));
    }
    Ok(values)
}

fn ensure_non_empty(value: &str, label: &str) -> ProofCircuitResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> ProofCircuitResult<()> {
    if allowed.iter().any(|candidate| candidate == &value) {
        Ok(())
    } else {
        Err(format!("{label} is not supported"))
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> ProofCircuitResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> ProofCircuitResult<String> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id.clone(), record);
    Ok(id)
}
