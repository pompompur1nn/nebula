use crate::hash::{domain_hash, merkle_root, HashPart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVACY_PQ_INVARIANT_MATRIX_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-privacy-pq-invariant-matrix-runtime/v1";

pub type Result<T> = std::result::Result<T, RuntimeError>;
pub type MoneroL2PqBridgeExitCanonicalPrivacyPqInvariantMatrixRuntimeResult<T> = Result<T>;
pub type Runtime = State;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RuntimeError {
    EmptyMatrix,
    InvariantFailed { invariant: String, reason: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Observe,
    Block,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Observe => "observe",
            Self::Block => "block",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum InvariantFamily {
    MetadataDisclosure,
    ScanHints,
    EncryptedReceipts,
    NoteNullifierSeparation,
    WalletReconstruction,
    PqSignerEpochs,
    QuorumWeights,
    SignerQuarantine,
    AuthorityRotation,
    EmergencyRelease,
    ProductionBlockers,
}

impl InvariantFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetadataDisclosure => "metadata_disclosure",
            Self::ScanHints => "scan_hints",
            Self::EncryptedReceipts => "encrypted_receipts",
            Self::NoteNullifierSeparation => "note_nullifier_separation",
            Self::WalletReconstruction => "wallet_reconstruction",
            Self::PqSignerEpochs => "pq_signer_epochs",
            Self::QuorumWeights => "quorum_weights",
            Self::SignerQuarantine => "signer_quarantine",
            Self::AuthorityRotation => "authority_rotation",
            Self::EmergencyRelease => "emergency_release",
            Self::ProductionBlockers => "production_blockers",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub canonical_vector_set: String,
    pub min_quorum_weight: u64,
    pub max_public_metadata_fields: u64,
    pub max_scan_hint_bits: u64,
    pub min_receipt_ciphertext_bytes: u64,
    pub min_wallet_reconstruction_shares: u64,
    pub signer_epoch_lookahead: u64,
    pub quarantine_epochs: u64,
    pub authority_rotation_epochs: u64,
    pub emergency_release_delay: u64,
    pub production_blocker_tolerance: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: "nebula-l2-devnet".to_string(),
            canonical_vector_set: "canonical-bridge-exit-vectors-2026-06".to_string(),
            min_quorum_weight: 67,
            max_public_metadata_fields: 2,
            max_scan_hint_bits: 16,
            min_receipt_ciphertext_bytes: 192,
            min_wallet_reconstruction_shares: 3,
            signer_epoch_lookahead: 2,
            quarantine_epochs: 3,
            authority_rotation_epochs: 12,
            emergency_release_delay: 144,
            production_blocker_tolerance: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanonicalVector {
    pub id: String,
    pub exit_id: String,
    pub note_commitment: String,
    pub nullifier_commitment: String,
    pub wallet_reconstruction_shares: u64,
    pub public_metadata_fields: u64,
    pub scan_hint_bits: u64,
    pub receipt_ciphertext_bytes: u64,
    pub signer_epoch: u64,
    pub signer_weight: u64,
    pub signer_quarantined: bool,
    pub authority_epoch: u64,
    pub emergency_height: Option<u64>,
    pub production_blockers: Vec<String>,
}

impl CanonicalVector {
    pub fn deterministic_id(seed: &str, index: u64) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-VECTOR-ID",
            &[HashPart::Str(seed), HashPart::U64(index)],
            16,
        )
    }

    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "exit_id": self.exit_id,
            "note_commitment": self.note_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "wallet_reconstruction_shares": self.wallet_reconstruction_shares,
            "public_metadata_fields": self.public_metadata_fields,
            "scan_hint_bits": self.scan_hint_bits,
            "receipt_ciphertext_bytes": self.receipt_ciphertext_bytes,
            "signer_epoch": self.signer_epoch,
            "signer_weight": self.signer_weight,
            "signer_quarantined": self.signer_quarantined,
            "authority_epoch": self.authority_epoch,
            "emergency_height": self.emergency_height,
            "production_blockers": self.production_blockers,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-VECTOR",
            &[HashPart::Json(&self.record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Invariant {
    pub id: String,
    pub family: InvariantFamily,
    pub description: String,
    pub observed: u64,
    pub threshold: u64,
    pub verdict: Verdict,
    pub evidence_root: String,
}

impl Invariant {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "family": self.family.as_str(),
            "description": self.description,
            "observed": self.observed,
            "threshold": self.threshold,
            "verdict": self.verdict.as_str(),
            "evidence_root": self.evidence_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-INVARIANT",
            &[HashPart::Json(&self.record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DevnetData {
    pub bridge_height: u64,
    pub release_height: u64,
    pub authority_set_root: String,
    pub signer_set_root: String,
    pub canonical_vector_root: String,
}

impl DevnetData {
    pub fn record(&self) -> Value {
        json!({
            "bridge_height": self.bridge_height,
            "release_height": self.release_height,
            "authority_set_root": self.authority_set_root,
            "signer_set_root": self.signer_set_root,
            "canonical_vector_root": self.canonical_vector_root,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub vectors: Vec<CanonicalVector>,
    pub invariants: Vec<Invariant>,
    pub devnet_data: DevnetData,
}

impl State {
    pub fn new(
        config: Config,
        vectors: Vec<CanonicalVector>,
        devnet_data: DevnetData,
    ) -> Result<Self> {
        if vectors.is_empty() {
            return Err(RuntimeError::EmptyMatrix);
        }
        let invariants = evaluate_invariants(&config, &vectors, &devnet_data);
        Ok(Self {
            config,
            vectors,
            invariants,
            devnet_data,
        })
    }

    pub fn public_record(&self) -> Value {
        let invariant_records = self
            .invariants
            .iter()
            .map(Invariant::record)
            .collect::<Vec<_>>();
        let vector_records = self
            .vectors
            .iter()
            .map(CanonicalVector::record)
            .collect::<Vec<_>>();
        json!({
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVACY_PQ_INVARIANT_MATRIX_RUNTIME_PROTOCOL_VERSION,
            "config": self.config,
            "devnet_data": self.devnet_data.record(),
            "roots": {
                "invariant_root": self.invariant_root(),
                "vector_root": self.vector_root(),
                "devnet_root": self.devnet_root(),
            },
            "verdict": self.verdict().as_str(),
            "invariants": invariant_records,
            "canonical_vectors": vector_records,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn invariant_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-INVARIANT-ROOT",
            &self
                .invariants
                .iter()
                .map(Invariant::record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn vector_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-VECTOR-ROOT",
            &self
                .vectors
                .iter()
                .map(CanonicalVector::record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn devnet_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-DEVNET",
            &[HashPart::Json(&self.devnet_data.record())],
            32,
        )
    }

    pub fn verdict(&self) -> Verdict {
        if self
            .invariants
            .iter()
            .any(|invariant| invariant.verdict == Verdict::Block)
        {
            Verdict::Block
        } else if self
            .invariants
            .iter()
            .any(|invariant| invariant.verdict == Verdict::Observe)
        {
            Verdict::Observe
        } else {
            Verdict::Pass
        }
    }

    pub fn assert_production_ready(&self) -> Result<()> {
        match self.verdict() {
            Verdict::Pass => Ok(()),
            verdict => Err(RuntimeError::InvariantFailed {
                invariant: "matrix".to_string(),
                reason: format!("runtime verdict is {}", verdict.as_str()),
            }),
        }
    }
}

pub fn evaluate_invariants(
    config: &Config,
    vectors: &[CanonicalVector],
    devnet_data: &DevnetData,
) -> Vec<Invariant> {
    let max_public_metadata = vectors
        .iter()
        .map(|vector| vector.public_metadata_fields)
        .max()
        .unwrap_or(0);
    let max_scan_hint_bits = vectors
        .iter()
        .map(|vector| vector.scan_hint_bits)
        .max()
        .unwrap_or(0);
    let min_receipt_ciphertext = vectors
        .iter()
        .map(|vector| vector.receipt_ciphertext_bytes)
        .min()
        .unwrap_or(0);
    let note_nullifier_collisions = vectors
        .iter()
        .filter(|vector| vector.note_commitment == vector.nullifier_commitment)
        .count() as u64;
    let min_wallet_shares = vectors
        .iter()
        .map(|vector| vector.wallet_reconstruction_shares)
        .min()
        .unwrap_or(0);
    let max_epoch_gap = vectors
        .iter()
        .map(|vector| {
            devnet_data
                .release_height
                .saturating_sub(vector.signer_epoch)
        })
        .max()
        .unwrap_or(0);
    let quorum_weight = vectors
        .iter()
        .filter(|vector| !vector.signer_quarantined)
        .map(|vector| vector.signer_weight)
        .sum::<u64>();
    let quarantined_weight = vectors
        .iter()
        .filter(|vector| vector.signer_quarantined)
        .map(|vector| vector.signer_weight)
        .sum::<u64>();
    let authority_epoch_gap = vectors
        .iter()
        .map(|vector| {
            devnet_data
                .release_height
                .saturating_sub(vector.authority_epoch)
        })
        .max()
        .unwrap_or(0);
    let emergency_release_gap = vectors
        .iter()
        .filter_map(|vector| vector.emergency_height)
        .map(|height| devnet_data.release_height.saturating_sub(height))
        .min()
        .unwrap_or(config.emergency_release_delay);
    let production_blockers = vectors
        .iter()
        .map(|vector| vector.production_blockers.len() as u64)
        .sum::<u64>();

    vec![
        invariant(
            "metadata-disclosure-ceiling",
            InvariantFamily::MetadataDisclosure,
            "public metadata disclosure stays below canonical privacy ceiling",
            max_public_metadata,
            config.max_public_metadata_fields,
            max_public_metadata <= config.max_public_metadata_fields,
            evidence_root(vectors, "metadata"),
        ),
        invariant(
            "scan-hint-budget",
            InvariantFamily::ScanHints,
            "scan hint entropy does not over-identify exit notes",
            max_scan_hint_bits,
            config.max_scan_hint_bits,
            max_scan_hint_bits <= config.max_scan_hint_bits,
            evidence_root(vectors, "scan-hints"),
        ),
        invariant(
            "encrypted-receipt-minimum",
            InvariantFamily::EncryptedReceipts,
            "receipt ciphertexts remain encrypted envelopes with minimum payload size",
            min_receipt_ciphertext,
            config.min_receipt_ciphertext_bytes,
            min_receipt_ciphertext >= config.min_receipt_ciphertext_bytes,
            evidence_root(vectors, "receipts"),
        ),
        invariant(
            "note-nullifier-domain-separation",
            InvariantFamily::NoteNullifierSeparation,
            "note commitments and nullifier commitments never share the same domain output",
            note_nullifier_collisions,
            0,
            note_nullifier_collisions == 0,
            evidence_root(vectors, "note-nullifier"),
        ),
        invariant(
            "wallet-reconstruction-threshold",
            InvariantFamily::WalletReconstruction,
            "wallet reconstruction needs the configured share threshold",
            min_wallet_shares,
            config.min_wallet_reconstruction_shares,
            min_wallet_shares >= config.min_wallet_reconstruction_shares,
            evidence_root(vectors, "wallet-reconstruction"),
        ),
        invariant(
            "pq-signer-epoch-freshness",
            InvariantFamily::PqSignerEpochs,
            "post-quantum signer epochs remain within the release lookahead",
            max_epoch_gap,
            config.signer_epoch_lookahead,
            max_epoch_gap <= config.signer_epoch_lookahead,
            evidence_root(vectors, "pq-signer-epochs"),
        ),
        invariant(
            "quorum-weight-floor",
            InvariantFamily::QuorumWeights,
            "non-quarantined signer weight reaches bridge release quorum",
            quorum_weight,
            config.min_quorum_weight,
            quorum_weight >= config.min_quorum_weight,
            evidence_root(vectors, "quorum"),
        ),
        invariant(
            "signer-quarantine-isolation",
            InvariantFamily::SignerQuarantine,
            "quarantined signer weight is excluded from release quorum",
            quarantined_weight,
            33,
            quarantined_weight <= 33,
            evidence_root(vectors, "quarantine"),
        ),
        invariant(
            "authority-rotation-window",
            InvariantFamily::AuthorityRotation,
            "authority rotation age remains within configured devnet window",
            authority_epoch_gap,
            config.authority_rotation_epochs,
            authority_epoch_gap <= config.authority_rotation_epochs,
            evidence_root(vectors, "authority-rotation"),
        ),
        invariant(
            "emergency-release-delay",
            InvariantFamily::EmergencyRelease,
            "emergency release path observes the canonical delay",
            emergency_release_gap,
            config.emergency_release_delay,
            emergency_release_gap >= config.emergency_release_delay,
            evidence_root(vectors, "emergency-release"),
        ),
        invariant(
            "production-blocker-zero",
            InvariantFamily::ProductionBlockers,
            "production release blockers are absent from canonical vectors",
            production_blockers,
            config.production_blocker_tolerance,
            production_blockers <= config.production_blocker_tolerance,
            evidence_root(vectors, "production-blockers"),
        ),
    ]
}

pub fn invariant(
    id: &str,
    family: InvariantFamily,
    description: &str,
    observed: u64,
    threshold: u64,
    passed: bool,
    evidence_root: String,
) -> Invariant {
    let verdict = if passed {
        Verdict::Pass
    } else {
        Verdict::Block
    };
    Invariant {
        id: id.to_string(),
        family,
        description: description.to_string(),
        observed,
        threshold,
        verdict,
        evidence_root,
    }
}

pub fn evidence_root(vectors: &[CanonicalVector], label: &str) -> String {
    let leaves = vectors
        .iter()
        .map(|vector| {
            json!({
                "label": label,
                "vector_id": vector.id,
                "exit_id": vector.exit_id,
                "vector_root": vector.root(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-EVIDENCE", &leaves)
}

pub fn canonical_vector(seed: &str, index: u64, signer_weight: u64) -> CanonicalVector {
    let id = CanonicalVector::deterministic_id(seed, index);
    CanonicalVector {
        exit_id: domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-EXIT-ID",
            &[HashPart::Str(seed), HashPart::U64(index)],
            16,
        ),
        note_commitment: domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-NOTE",
            &[HashPart::Str(seed), HashPart::Str(&id)],
            32,
        ),
        nullifier_commitment: domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-NULLIFIER",
            &[HashPart::Str(seed), HashPart::Str(&id)],
            32,
        ),
        id,
        wallet_reconstruction_shares: 3,
        public_metadata_fields: 1 + (index % 2),
        scan_hint_bits: 8 + (index % 3),
        receipt_ciphertext_bytes: 224 + (index * 16),
        signer_epoch: 254 + index,
        signer_weight,
        signer_quarantined: false,
        authority_epoch: 248 + index,
        emergency_height: Some(100 + index),
        production_blockers: Vec::new(),
    }
}

pub fn devnet_vectors() -> Vec<CanonicalVector> {
    vec![
        canonical_vector("devnet-alpha", 0, 23),
        canonical_vector("devnet-beta", 1, 22),
        canonical_vector("devnet-gamma", 2, 22),
        canonical_vector("devnet-delta", 3, 18),
    ]
}

pub fn devnet_data(vectors: &[CanonicalVector]) -> DevnetData {
    let vector_records = vectors
        .iter()
        .map(CanonicalVector::record)
        .collect::<Vec<_>>();
    DevnetData {
        bridge_height: 4096,
        release_height: 256,
        authority_set_root: domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-AUTHORITY-SET",
            &[HashPart::Str("devnet-authority-set"), HashPart::U64(4)],
            32,
        ),
        signer_set_root: domain_hash(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-SIGNER-SET",
            &[HashPart::Str("devnet-signer-set"), HashPart::U64(85)],
            32,
        ),
        canonical_vector_root: merkle_root(
            "MONERO-L2-PQ-CANONICAL-PRIVACY-PQ-DEVNET-VECTORS",
            &vector_records,
        ),
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let vectors = devnet_vectors();
    let data = devnet_data(&vectors);
    State::new(config, vectors, data).expect("devnet privacy pq invariant matrix")
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}
