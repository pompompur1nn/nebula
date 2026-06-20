use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalPqWatcherAttestationVectorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PQ_WATCHER_ATTESTATION_VECTOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-pq-watcher-attestation-vector-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PQ_WATCHER_ATTESTATION_VECTOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VECTOR_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-pq-watcher-attestation-vector-v1";
pub const ML_DSA_DOMAIN_LABEL: &str =
    "ML-DSA-87:nebula:bridge-exit:canonical-watcher-attestation:v1";
pub const SLH_DSA_DOMAIN_LABEL: &str =
    "SLH-DSA-SHAKE-256f:nebula:bridge-exit:canonical-watcher-attestation:v1";
pub const THRESHOLD_ROOT_DOMAIN_LABEL: &str =
    "SHAKE256:nebula:bridge-exit:watcher-threshold-root:v1";
pub const WITNESS_COMMITMENT_DOMAIN_LABEL: &str =
    "SHAKE256:nebula:bridge-exit:forced-exit-witness-commitment:v1";
pub const DEFAULT_CURRENT_SIGNER_EPOCH: u64 = 144;
pub const DEFAULT_MAX_EPOCH_LAG: u64 = 1;
pub const DEFAULT_QUARANTINE_EPOCHS: u64 = 4;
pub const DEFAULT_MIN_LOCK_WEIGHT_BPS: u16 = 6_700;
pub const DEFAULT_MIN_RELEASE_WEIGHT_BPS: u16 = 7_200;
pub const DEFAULT_MIN_EMERGENCY_WEIGHT_BPS: u16 = 8_500;
pub const DEFAULT_MAX_COLLUSION_CLUSTER_BPS: u16 = 3_400;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 512;
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
            Self::MlDsa87 => ML_DSA_DOMAIN_LABEL,
            Self::SlhDsaShake256f => SLH_DSA_DOMAIN_LABEL,
            Self::HybridMlDsaSlhDsaShake => THRESHOLD_ROOT_DOMAIN_LABEL,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    Lock,
    Release,
    EmergencyEscape,
    EpochRotation,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Release => "release",
            Self::EmergencyEscape => "emergency_escape",
            Self::EpochRotation => "epoch_rotation",
        }
    }

    pub fn threshold_bps(self, config: &Config) -> u16 {
        match self {
            Self::Lock | Self::EpochRotation => config.min_lock_weight_bps,
            Self::Release => config.min_release_weight_bps,
            Self::EmergencyEscape => config.min_emergency_weight_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Active,
    Retiring,
    Quarantined,
    Revoked,
}

impl SignerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_sign(self) -> bool {
        matches!(self, Self::Active | Self::Retiring)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationDecision {
    Accepted,
    Rejected,
    Escalated,
}

impl AttestationDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Escalated => "escalated",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Accepted | Self::Escalated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    None,
    StaleEpoch,
    FutureEpoch,
    UnknownSigner,
    SignerQuarantined,
    SignerRevoked,
    DuplicateSigner,
    MissingDomainBinding,
    MissingWitnessCommitment,
    MissingLockBeforeRelease,
    ThresholdWeightShortfall,
    CollusionClusterExceeded,
    EmergencyAuthorityMissing,
    PublicRecordMismatch,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StaleEpoch => "stale_epoch",
            Self::FutureEpoch => "future_epoch",
            Self::UnknownSigner => "unknown_signer",
            Self::SignerQuarantined => "signer_quarantined",
            Self::SignerRevoked => "signer_revoked",
            Self::DuplicateSigner => "duplicate_signer",
            Self::MissingDomainBinding => "missing_domain_binding",
            Self::MissingWitnessCommitment => "missing_witness_commitment",
            Self::MissingLockBeforeRelease => "missing_lock_before_release",
            Self::ThresholdWeightShortfall => "threshold_weight_shortfall",
            Self::CollusionClusterExceeded => "collusion_cluster_exceeded",
            Self::EmergencyAuthorityMissing => "emergency_authority_missing",
            Self::PublicRecordMismatch => "public_record_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollusionCaseKind {
    SharedOperator,
    SharedKeyCeremony,
    ConflictingLockRelease,
    EpochEquivocation,
    EmergencyOverrideAbuse,
}

impl CollusionCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedOperator => "shared_operator",
            Self::SharedKeyCeremony => "shared_key_ceremony",
            Self::ConflictingLockRelease => "conflicting_lock_release",
            Self::EpochEquivocation => "epoch_equivocation",
            Self::EmergencyOverrideAbuse => "emergency_override_abuse",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub vector_suite: String,
    pub ml_dsa_domain_label: String,
    pub slh_dsa_domain_label: String,
    pub threshold_root_domain_label: String,
    pub witness_commitment_domain_label: String,
    pub current_signer_epoch: u64,
    pub max_epoch_lag: u64,
    pub quarantine_epochs: u64,
    pub min_lock_weight_bps: u16,
    pub min_release_weight_bps: u16,
    pub min_emergency_weight_bps: u16,
    pub max_collusion_cluster_bps: u16,
    pub min_pq_security_bits: u16,
    pub require_lock_before_release: bool,
    pub require_witness_commitment: bool,
    pub fail_closed_on_public_record_mismatch: bool,
    pub max_attestations: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            vector_suite: VECTOR_SUITE.to_string(),
            ml_dsa_domain_label: ML_DSA_DOMAIN_LABEL.to_string(),
            slh_dsa_domain_label: SLH_DSA_DOMAIN_LABEL.to_string(),
            threshold_root_domain_label: THRESHOLD_ROOT_DOMAIN_LABEL.to_string(),
            witness_commitment_domain_label: WITNESS_COMMITMENT_DOMAIN_LABEL.to_string(),
            current_signer_epoch: DEFAULT_CURRENT_SIGNER_EPOCH,
            max_epoch_lag: DEFAULT_MAX_EPOCH_LAG,
            quarantine_epochs: DEFAULT_QUARANTINE_EPOCHS,
            min_lock_weight_bps: DEFAULT_MIN_LOCK_WEIGHT_BPS,
            min_release_weight_bps: DEFAULT_MIN_RELEASE_WEIGHT_BPS,
            min_emergency_weight_bps: DEFAULT_MIN_EMERGENCY_WEIGHT_BPS,
            max_collusion_cluster_bps: DEFAULT_MAX_COLLUSION_CLUSTER_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            require_lock_before_release: true,
            require_witness_commitment: true,
            fail_closed_on_public_record_mismatch: true,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "vector_suite": self.vector_suite,
            "ml_dsa_domain_label": self.ml_dsa_domain_label,
            "slh_dsa_domain_label": self.slh_dsa_domain_label,
            "threshold_root_domain_label": self.threshold_root_domain_label,
            "witness_commitment_domain_label": self.witness_commitment_domain_label,
            "current_signer_epoch": self.current_signer_epoch,
            "max_epoch_lag": self.max_epoch_lag,
            "quarantine_epochs": self.quarantine_epochs,
            "min_lock_weight_bps": self.min_lock_weight_bps,
            "min_release_weight_bps": self.min_release_weight_bps,
            "min_emergency_weight_bps": self.min_emergency_weight_bps,
            "max_collusion_cluster_bps": self.max_collusion_cluster_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "require_lock_before_release": self.require_lock_before_release,
            "require_witness_commitment": self.require_witness_commitment,
            "fail_closed_on_public_record_mismatch": self.fail_closed_on_public_record_mismatch,
            "max_attestations": self.max_attestations,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerEpoch {
    pub epoch: u64,
    pub previous_epoch_root: String,
    pub signer_set_root: String,
    pub threshold_root: String,
    pub activation_height: u64,
    pub retirement_height: u64,
    pub emergency_authority_root: String,
}

impl SignerEpoch {
    pub fn new(
        epoch: u64,
        previous_epoch_root: &str,
        signers: &[WatcherSigner],
        activation_height: u64,
        retirement_height: u64,
        emergency_authority_root: &str,
    ) -> Self {
        let signer_records = signers
            .iter()
            .map(WatcherSigner::public_record)
            .collect::<Vec<_>>();
        let signer_set_root = merkle_records("canonical_signer_set", &signer_records);
        let threshold_root = threshold_root(epoch, &signer_set_root, emergency_authority_root);
        Self {
            epoch,
            previous_epoch_root: previous_epoch_root.to_string(),
            signer_set_root,
            threshold_root,
            activation_height,
            retirement_height,
            emergency_authority_root: emergency_authority_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch": self.epoch,
            "previous_epoch_root": self.previous_epoch_root,
            "signer_set_root": self.signer_set_root,
            "threshold_root": self.threshold_root,
            "activation_height": self.activation_height,
            "retirement_height": self.retirement_height,
            "emergency_authority_root": self.emergency_authority_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("signer_epoch", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherSigner {
    pub watcher_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub scheme: PqSignatureScheme,
    pub status: SignerStatus,
    pub weight_bps: u16,
    pub pq_security_bits: u16,
    pub public_key_commitment: String,
    pub key_ceremony_root: String,
    pub quarantine_until_epoch: Option<u64>,
}

impl WatcherSigner {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
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

    pub fn state_root(&self) -> String {
        record_root("watcher_signer", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessCommitment {
    pub witness_id: String,
    pub exit_id: String,
    pub monero_lock_txid: String,
    pub private_note_root: String,
    pub amount_commitment: String,
    pub destination_commitment: String,
    pub nullifier_commitment: String,
    pub canonical_witness_root: String,
}

impl WitnessCommitment {
    pub fn devnet(exit_id: &str, ordinal: u64) -> Self {
        let monero_lock_txid = label_root("monero_lock_txid", exit_id, ordinal);
        let private_note_root = label_root("private_note", exit_id, ordinal);
        let amount_commitment = label_root("amount", exit_id, ordinal);
        let destination_commitment = label_root("destination", exit_id, ordinal);
        let nullifier_commitment = label_root("nullifier", exit_id, ordinal);
        let canonical_witness_root = domain_hash(
            "CANONICAL-PQ-WATCHER-WITNESS-COMMITMENT",
            &[
                HashPart::Str(WITNESS_COMMITMENT_DOMAIN_LABEL),
                HashPart::Str(exit_id),
                HashPart::Str(&monero_lock_txid),
                HashPart::Str(&private_note_root),
                HashPart::Str(&amount_commitment),
                HashPart::Str(&destination_commitment),
                HashPart::Str(&nullifier_commitment),
            ],
            32,
        );
        let witness_id = domain_hash(
            "CANONICAL-PQ-WATCHER-WITNESS-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(exit_id),
                HashPart::Str(&canonical_witness_root),
            ],
            32,
        );
        Self {
            witness_id,
            exit_id: exit_id.to_string(),
            monero_lock_txid,
            private_note_root,
            amount_commitment,
            destination_commitment,
            nullifier_commitment,
            canonical_witness_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "exit_id": self.exit_id,
            "monero_lock_txid": self.monero_lock_txid,
            "private_note_root": self.private_note_root,
            "amount_commitment": self.amount_commitment,
            "destination_commitment": self.destination_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "canonical_witness_root": self.canonical_witness_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("witness_commitment", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub exit_id: String,
    pub kind: AttestationKind,
    pub signer_epoch: u64,
    pub scheme: PqSignatureScheme,
    pub pq_domain_label: String,
    pub message_root: String,
    pub signature_commitment: String,
    pub witness_commitment_root: String,
    pub lock_root: String,
    pub release_root: String,
    pub public_record_root: String,
}

impl WatcherAttestation {
    pub fn from_signer(
        signer: &WatcherSigner,
        exit_id: &str,
        kind: AttestationKind,
        witness: &WitnessCommitment,
        lock_root: &str,
        release_root: &str,
        public_record_root: &str,
    ) -> Self {
        let pq_domain_label = signer.scheme.domain_label().to_string();
        let message_root = domain_hash(
            "CANONICAL-PQ-WATCHER-ATTESTATION-MESSAGE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(exit_id),
                HashPart::Str(kind.as_str()),
                HashPart::U64(signer.epoch),
                HashPart::Str(&pq_domain_label),
                HashPart::Str(&witness.canonical_witness_root),
                HashPart::Str(lock_root),
                HashPart::Str(release_root),
                HashPart::Str(public_record_root),
            ],
            32,
        );
        let signature_commitment = domain_hash(
            "CANONICAL-PQ-WATCHER-SIGNATURE-COMMITMENT",
            &[
                HashPart::Str(&pq_domain_label),
                HashPart::Str(&signer.public_key_commitment),
                HashPart::Str(&message_root),
            ],
            32,
        );
        let attestation_id = domain_hash(
            "CANONICAL-PQ-WATCHER-ATTESTATION-ID",
            &[
                HashPart::Str(&signer.watcher_id),
                HashPart::Str(exit_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&signature_commitment),
            ],
            32,
        );
        Self {
            attestation_id,
            watcher_id: signer.watcher_id.clone(),
            exit_id: exit_id.to_string(),
            kind,
            signer_epoch: signer.epoch,
            scheme: signer.scheme,
            pq_domain_label,
            message_root,
            signature_commitment,
            witness_commitment_root: witness.canonical_witness_root.clone(),
            lock_root: lock_root.to_string(),
            release_root: release_root.to_string(),
            public_record_root: public_record_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "exit_id": self.exit_id,
            "kind": self.kind.as_str(),
            "signer_epoch": self.signer_epoch,
            "scheme": self.scheme.as_str(),
            "pq_domain_label": self.pq_domain_label,
            "message_root": self.message_root,
            "signature_commitment": self.signature_commitment,
            "witness_commitment_root": self.witness_commitment_root,
            "lock_root": self.lock_root,
            "release_root": self.release_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttestationVector {
    pub vector_id: String,
    pub exit_id: String,
    pub kind: AttestationKind,
    pub signer_epoch: u64,
    pub witness_root: String,
    pub threshold_root: String,
    pub attestations: Vec<WatcherAttestation>,
}

impl AttestationVector {
    pub fn public_record(&self) -> Value {
        json!({
            "vector_id": self.vector_id,
            "exit_id": self.exit_id,
            "kind": self.kind.as_str(),
            "signer_epoch": self.signer_epoch,
            "witness_root": self.witness_root,
            "threshold_root": self.threshold_root,
            "attestations": self.attestations.iter().map(WatcherAttestation::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("attestation_vector", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuarantineRecord {
    pub watcher_id: String,
    pub reason: RejectionReason,
    pub from_epoch: u64,
    pub until_epoch: u64,
    pub evidence_root: String,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "reason": self.reason.as_str(),
            "from_epoch": self.from_epoch,
            "until_epoch": self.until_epoch,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollusionCase {
    pub case_id: String,
    pub kind: CollusionCaseKind,
    pub signer_epoch: u64,
    pub watcher_ids: Vec<String>,
    pub aggregate_weight_bps: u16,
    pub evidence_root: String,
    pub quarantine_recommended: bool,
}

impl CollusionCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "signer_epoch": self.signer_epoch,
            "watcher_ids": self.watcher_ids,
            "aggregate_weight_bps": self.aggregate_weight_bps,
            "evidence_root": self.evidence_root,
            "quarantine_recommended": self.quarantine_recommended,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmergencyEscapeAuthority {
    pub authority_id: String,
    pub signer_epoch: u64,
    pub custody_pause_root: String,
    pub emergency_committee_root: String,
    pub timelock_height: u64,
    pub required_weight_bps: u16,
    pub escape_authority_root: String,
}

impl EmergencyEscapeAuthority {
    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "signer_epoch": self.signer_epoch,
            "custody_pause_root": self.custody_pause_root,
            "emergency_committee_root": self.emergency_committee_root,
            "timelock_height": self.timelock_height,
            "required_weight_bps": self.required_weight_bps,
            "escape_authority_root": self.escape_authority_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VectorEvaluation {
    pub vector_id: String,
    pub decision: AttestationDecision,
    pub reason: RejectionReason,
    pub observed_weight_bps: u16,
    pub required_weight_bps: u16,
    pub signer_count: usize,
    pub accepted_signers: Vec<String>,
    pub rejected_signers: BTreeMap<String, RejectionReason>,
    pub evaluation_root: String,
}

impl VectorEvaluation {
    pub fn public_record(&self) -> Value {
        let rejected = self
            .rejected_signers
            .iter()
            .map(|(watcher_id, reason)| {
                json!({
                    "watcher_id": watcher_id,
                    "reason": reason.as_str(),
                })
            })
            .collect::<Vec<_>>();
        json!({
            "vector_id": self.vector_id,
            "decision": self.decision.as_str(),
            "reason": self.reason.as_str(),
            "observed_weight_bps": self.observed_weight_bps,
            "required_weight_bps": self.required_weight_bps,
            "signer_count": self.signer_count,
            "accepted_signers": self.accepted_signers,
            "rejected_signers": rejected,
            "evaluation_root": self.evaluation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub signer_epochs: Vec<SignerEpoch>,
    pub signers: Vec<WatcherSigner>,
    pub witness_commitments: Vec<WitnessCommitment>,
    pub vectors: Vec<AttestationVector>,
    pub evaluations: Vec<VectorEvaluation>,
    pub quarantines: Vec<QuarantineRecord>,
    pub collusion_cases: Vec<CollusionCase>,
    pub emergency_authority: EmergencyEscapeAuthority,
    pub devnet_data_root: String,
}

impl State {
    pub fn new(
        config: Config,
        signer_epochs: Vec<SignerEpoch>,
        signers: Vec<WatcherSigner>,
        witness_commitments: Vec<WitnessCommitment>,
        vectors: Vec<AttestationVector>,
        quarantines: Vec<QuarantineRecord>,
        collusion_cases: Vec<CollusionCase>,
        emergency_authority: EmergencyEscapeAuthority,
    ) -> Result<Self> {
        if vectors.len() > config.max_attestations {
            return Err("canonical watcher attestation vector capacity exceeded".to_string());
        }
        let mut state = Self {
            config,
            signer_epochs,
            signers,
            witness_commitments,
            vectors,
            evaluations: Vec::new(),
            quarantines,
            collusion_cases,
            emergency_authority,
            devnet_data_root: String::new(),
        };
        state.evaluations = state
            .vectors
            .iter()
            .map(|vector| state.evaluate_vector(vector))
            .collect();
        state.devnet_data_root = state.compute_devnet_data_root();
        Ok(state)
    }

    pub fn evaluate_vector(&self, vector: &AttestationVector) -> VectorEvaluation {
        let required_weight_bps = vector.kind.threshold_bps(&self.config);
        let signer_index = self.signer_index();
        let mut seen = BTreeSet::new();
        let mut accepted_signers = Vec::new();
        let mut rejected_signers = BTreeMap::new();
        let mut observed_weight_bps = 0u16;
        let mut reason = RejectionReason::None;

        for attestation in &vector.attestations {
            let signer = match signer_index.get(&attestation.watcher_id) {
                Some(signer) => signer,
                None => {
                    rejected_signers.insert(
                        attestation.watcher_id.clone(),
                        RejectionReason::UnknownSigner,
                    );
                    reason = RejectionReason::UnknownSigner;
                    continue;
                }
            };
            let signer_reason = self.validate_attestation(vector, attestation, signer, &mut seen);
            if signer_reason == RejectionReason::None {
                observed_weight_bps = observed_weight_bps.saturating_add(signer.weight_bps);
                accepted_signers.push(attestation.watcher_id.clone());
            } else {
                rejected_signers.insert(attestation.watcher_id.clone(), signer_reason);
                if reason == RejectionReason::None {
                    reason = signer_reason;
                }
            }
        }

        let collusion_weight =
            self.max_collusion_weight_for(&accepted_signers, vector.signer_epoch);
        if collusion_weight > self.config.max_collusion_cluster_bps {
            reason = RejectionReason::CollusionClusterExceeded;
        }
        if observed_weight_bps < required_weight_bps && reason == RejectionReason::None {
            reason = RejectionReason::ThresholdWeightShortfall;
        }
        if vector.kind == AttestationKind::EmergencyEscape
            && self.emergency_authority.required_weight_bps > observed_weight_bps
            && reason == RejectionReason::None
        {
            reason = RejectionReason::EmergencyAuthorityMissing;
        }

        let decision = if reason == RejectionReason::None {
            if vector.kind == AttestationKind::EmergencyEscape {
                AttestationDecision::Escalated
            } else {
                AttestationDecision::Accepted
            }
        } else {
            AttestationDecision::Rejected
        };

        let evaluation_seed = json!({
            "vector_id": vector.vector_id,
            "decision": decision.as_str(),
            "reason": reason.as_str(),
            "observed_weight_bps": observed_weight_bps,
            "required_weight_bps": required_weight_bps,
            "accepted_signers": accepted_signers,
        });
        let evaluation_root = record_root("vector_evaluation", &evaluation_seed);
        VectorEvaluation {
            vector_id: vector.vector_id.clone(),
            decision,
            reason,
            observed_weight_bps,
            required_weight_bps,
            signer_count: vector.attestations.len(),
            accepted_signers,
            rejected_signers,
            evaluation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "signer_epochs": self.signer_epochs.iter().map(SignerEpoch::public_record).collect::<Vec<_>>(),
            "signers": self.signers.iter().map(WatcherSigner::public_record).collect::<Vec<_>>(),
            "witness_commitments": self.witness_commitments.iter().map(WitnessCommitment::public_record).collect::<Vec<_>>(),
            "vectors": self.vectors.iter().map(AttestationVector::public_record).collect::<Vec<_>>(),
            "evaluations": self.evaluations.iter().map(VectorEvaluation::public_record).collect::<Vec<_>>(),
            "quarantines": self.quarantines.iter().map(QuarantineRecord::public_record).collect::<Vec<_>>(),
            "collusion_cases": self.collusion_cases.iter().map(CollusionCase::public_record).collect::<Vec<_>>(),
            "emergency_authority": self.emergency_authority.public_record(),
            "devnet_data_root": self.devnet_data_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }

    pub fn threshold_roots(&self) -> Vec<String> {
        self.signer_epochs
            .iter()
            .map(|epoch| epoch.threshold_root.clone())
            .collect()
    }

    pub fn accepted_vectors(&self) -> Vec<&VectorEvaluation> {
        self.evaluations
            .iter()
            .filter(|evaluation| evaluation.decision.passes())
            .collect()
    }

    pub fn quarantined_signers(&self) -> Vec<&WatcherSigner> {
        self.signers
            .iter()
            .filter(|signer| signer.status == SignerStatus::Quarantined)
            .collect()
    }

    fn validate_attestation(
        &self,
        vector: &AttestationVector,
        attestation: &WatcherAttestation,
        signer: &WatcherSigner,
        seen: &mut BTreeSet<String>,
    ) -> RejectionReason {
        if !seen.insert(attestation.watcher_id.clone()) {
            return RejectionReason::DuplicateSigner;
        }
        if signer.status == SignerStatus::Quarantined {
            return RejectionReason::SignerQuarantined;
        }
        if signer.status == SignerStatus::Revoked {
            return RejectionReason::SignerRevoked;
        }
        if !signer.status.can_sign() {
            return RejectionReason::SignerRevoked;
        }
        if attestation.signer_epoch + self.config.max_epoch_lag < self.config.current_signer_epoch {
            return RejectionReason::StaleEpoch;
        }
        if attestation.signer_epoch > self.config.current_signer_epoch {
            return RejectionReason::FutureEpoch;
        }
        if attestation.pq_domain_label != signer.scheme.domain_label() {
            return RejectionReason::MissingDomainBinding;
        }
        if self.config.require_witness_commitment && attestation.witness_commitment_root.is_empty()
        {
            return RejectionReason::MissingWitnessCommitment;
        }
        if self.config.require_lock_before_release
            && vector.kind == AttestationKind::Release
            && attestation.lock_root.is_empty()
        {
            return RejectionReason::MissingLockBeforeRelease;
        }
        if self.config.fail_closed_on_public_record_mismatch
            && attestation.public_record_root != vector.witness_root
        {
            return RejectionReason::PublicRecordMismatch;
        }
        RejectionReason::None
    }

    fn signer_index(&self) -> BTreeMap<String, &WatcherSigner> {
        self.signers
            .iter()
            .map(|signer| (signer.watcher_id.clone(), signer))
            .collect()
    }

    fn max_collusion_weight_for(&self, accepted_signers: &[String], signer_epoch: u64) -> u16 {
        self.collusion_cases
            .iter()
            .filter(|case| case.signer_epoch == signer_epoch)
            .filter(|case| {
                case.watcher_ids
                    .iter()
                    .any(|watcher_id| accepted_signers.contains(watcher_id))
            })
            .map(|case| case.aggregate_weight_bps)
            .max()
            .unwrap_or(0)
    }

    fn compute_devnet_data_root(&self) -> String {
        let records = vec![
            self.config.public_record(),
            json!({"signer_epoch_roots": self.signer_epochs.iter().map(SignerEpoch::state_root).collect::<Vec<_>>()}),
            json!({"signer_roots": self.signers.iter().map(WatcherSigner::state_root).collect::<Vec<_>>()}),
            json!({"witness_roots": self.witness_commitments.iter().map(WitnessCommitment::state_root).collect::<Vec<_>>()}),
            json!({"vector_roots": self.vectors.iter().map(AttestationVector::state_root).collect::<Vec<_>>()}),
        ];
        merkle_records("canonical_devnet_data", &records)
    }
}

pub fn devnet() -> State {
    build_devnet().unwrap_or_else(|error| {
        let fallback_config = Config::devnet();
        let emergency_authority = devnet_emergency_authority(
            fallback_config.current_signer_epoch,
            fallback_config.min_emergency_weight_bps,
        );
        State {
            config: fallback_config,
            signer_epochs: Vec::new(),
            signers: Vec::new(),
            witness_commitments: Vec::new(),
            vectors: Vec::new(),
            evaluations: vec![VectorEvaluation {
                vector_id: "devnet-construction-error".to_string(),
                decision: AttestationDecision::Rejected,
                reason: RejectionReason::PublicRecordMismatch,
                observed_weight_bps: 0,
                required_weight_bps: DEFAULT_MIN_LOCK_WEIGHT_BPS,
                signer_count: 0,
                accepted_signers: Vec::new(),
                rejected_signers: BTreeMap::from([(error, RejectionReason::PublicRecordMismatch)]),
                evaluation_root: label_root("devnet_error", "canonical", 0),
            }],
            quarantines: Vec::new(),
            collusion_cases: Vec::new(),
            emergency_authority,
            devnet_data_root: label_root("devnet_fallback", "canonical", 0),
        }
    })
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn threshold_root(epoch: u64, signer_set_root: &str, emergency_authority_root: &str) -> String {
    domain_hash(
        "CANONICAL-PQ-WATCHER-THRESHOLD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(THRESHOLD_ROOT_DOMAIN_LABEL),
            HashPart::U64(epoch),
            HashPart::Str(signer_set_root),
            HashPart::Str(emergency_authority_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "CANONICAL-PQ-WATCHER-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn merkle_records(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn build_devnet() -> Result<State> {
    let config = Config::devnet();
    let emergency_authority =
        devnet_emergency_authority(config.current_signer_epoch, config.min_emergency_weight_bps);
    let signers = devnet_signers(config.current_signer_epoch, config.quarantine_epochs);
    let previous_epoch_root =
        label_root("previous_epoch", "canonical", config.current_signer_epoch);
    let current_epoch = SignerEpoch::new(
        config.current_signer_epoch,
        &previous_epoch_root,
        &signers,
        18_400,
        22_000,
        &emergency_authority.escape_authority_root,
    );
    let stale_epoch = SignerEpoch::new(
        config.current_signer_epoch - 3,
        &label_root("previous_epoch", "stale", config.current_signer_epoch - 3),
        &signers,
        12_000,
        16_000,
        &emergency_authority.escape_authority_root,
    );
    let lock_witness = WitnessCommitment::devnet("forced-exit-heavy-gate-lock-0001", 1);
    let release_witness = WitnessCommitment::devnet("forced-exit-heavy-gate-release-0001", 2);
    let lock_root = label_root("bridge_lock_root", &lock_witness.exit_id, 1);
    let release_root = label_root("bridge_release_root", &release_witness.exit_id, 2);
    let lock_vector = devnet_vector(
        "canonical-lock-vector-0001",
        AttestationKind::Lock,
        config.current_signer_epoch,
        &current_epoch.threshold_root,
        &lock_witness,
        &lock_root,
        "",
        &signers[0..4],
    );
    let release_vector = devnet_vector(
        "canonical-release-vector-0001",
        AttestationKind::Release,
        config.current_signer_epoch,
        &current_epoch.threshold_root,
        &release_witness,
        &lock_root,
        &release_root,
        &signers[0..5],
    );
    let stale_vector = devnet_vector(
        "canonical-stale-epoch-vector-0001",
        AttestationKind::Release,
        config.current_signer_epoch - 3,
        &stale_epoch.threshold_root,
        &release_witness,
        &lock_root,
        &release_root,
        &signers[0..3],
    );
    let emergency_vector = devnet_vector(
        "canonical-emergency-escape-vector-0001",
        AttestationKind::EmergencyEscape,
        config.current_signer_epoch,
        &current_epoch.threshold_root,
        &release_witness,
        &lock_root,
        &release_root,
        &signers[0..6],
    );
    let quarantines = vec![QuarantineRecord {
        watcher_id: "watcher-devnet-delta".to_string(),
        reason: RejectionReason::CollusionClusterExceeded,
        from_epoch: config.current_signer_epoch,
        until_epoch: config.current_signer_epoch + config.quarantine_epochs,
        evidence_root: label_root("quarantine_evidence", "watcher-devnet-delta", 1),
    }];
    let collusion_cases = vec![
        devnet_collusion_case(
            CollusionCaseKind::SharedOperator,
            config.current_signer_epoch,
            vec!["watcher-devnet-beta", "watcher-devnet-gamma"],
            3_600,
            1,
        ),
        devnet_collusion_case(
            CollusionCaseKind::ConflictingLockRelease,
            config.current_signer_epoch,
            vec!["watcher-devnet-delta", "watcher-devnet-epsilon"],
            3_200,
            2,
        ),
        devnet_collusion_case(
            CollusionCaseKind::EmergencyOverrideAbuse,
            config.current_signer_epoch,
            vec!["watcher-devnet-zeta", "watcher-devnet-eta"],
            2_600,
            3,
        ),
    ];
    State::new(
        config,
        vec![stale_epoch, current_epoch],
        signers,
        vec![lock_witness, release_witness],
        vec![lock_vector, release_vector, stale_vector, emergency_vector],
        quarantines,
        collusion_cases,
        emergency_authority,
    )
}

fn devnet_signers(epoch: u64, quarantine_epochs: u64) -> Vec<WatcherSigner> {
    let rows = [
        (
            "watcher-devnet-alpha",
            "operator-north",
            PqSignatureScheme::MlDsa87,
            SignerStatus::Active,
            1_900,
        ),
        (
            "watcher-devnet-beta",
            "operator-east",
            PqSignatureScheme::SlhDsaShake256f,
            SignerStatus::Active,
            1_800,
        ),
        (
            "watcher-devnet-gamma",
            "operator-east",
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            SignerStatus::Active,
            1_800,
        ),
        (
            "watcher-devnet-delta",
            "operator-west",
            PqSignatureScheme::MlDsa87,
            SignerStatus::Quarantined,
            1_600,
        ),
        (
            "watcher-devnet-epsilon",
            "operator-south",
            PqSignatureScheme::SlhDsaShake256f,
            SignerStatus::Active,
            1_600,
        ),
        (
            "watcher-devnet-zeta",
            "operator-escape",
            PqSignatureScheme::HybridMlDsaSlhDsaShake,
            SignerStatus::Retiring,
            1_300,
        ),
        (
            "watcher-devnet-eta",
            "operator-escape",
            PqSignatureScheme::MlDsa87,
            SignerStatus::Active,
            1_300,
        ),
    ];
    rows.iter()
        .enumerate()
        .map(
            |(index, (watcher_id, operator_id, scheme, status, weight_bps))| WatcherSigner {
                watcher_id: (*watcher_id).to_string(),
                operator_id: (*operator_id).to_string(),
                epoch,
                scheme: *scheme,
                status: *status,
                weight_bps: *weight_bps,
                pq_security_bits: 256,
                public_key_commitment: label_root("public_key", watcher_id, index as u64),
                key_ceremony_root: label_root("key_ceremony", operator_id, epoch + index as u64),
                quarantine_until_epoch: if *status == SignerStatus::Quarantined {
                    Some(epoch + quarantine_epochs)
                } else {
                    None
                },
            },
        )
        .collect()
}

fn devnet_vector(
    vector_id: &str,
    kind: AttestationKind,
    signer_epoch: u64,
    threshold_root: &str,
    witness: &WitnessCommitment,
    lock_root: &str,
    release_root: &str,
    signers: &[WatcherSigner],
) -> AttestationVector {
    let public_record_root = witness.canonical_witness_root.clone();
    let attestations = signers
        .iter()
        .map(|signer| {
            let mut signer = signer.clone();
            signer.epoch = signer_epoch;
            WatcherAttestation::from_signer(
                &signer,
                &witness.exit_id,
                kind,
                witness,
                lock_root,
                release_root,
                &public_record_root,
            )
        })
        .collect::<Vec<_>>();
    AttestationVector {
        vector_id: vector_id.to_string(),
        exit_id: witness.exit_id.clone(),
        kind,
        signer_epoch,
        witness_root: witness.canonical_witness_root.clone(),
        threshold_root: threshold_root.to_string(),
        attestations,
    }
}

fn devnet_emergency_authority(epoch: u64, required_weight_bps: u16) -> EmergencyEscapeAuthority {
    let custody_pause_root = label_root("custody_pause", "emergency", epoch);
    let emergency_committee_root = label_root("emergency_committee", "canonical", epoch);
    let escape_authority_root = domain_hash(
        "CANONICAL-PQ-WATCHER-EMERGENCY-ESCAPE-AUTHORITY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(epoch),
            HashPart::Str(&custody_pause_root),
            HashPart::Str(&emergency_committee_root),
            HashPart::U64(required_weight_bps as u64),
        ],
        32,
    );
    let authority_id = domain_hash(
        "CANONICAL-PQ-WATCHER-EMERGENCY-AUTHORITY-ID",
        &[HashPart::Str(&escape_authority_root), HashPart::U64(epoch)],
        32,
    );
    EmergencyEscapeAuthority {
        authority_id,
        signer_epoch: epoch,
        custody_pause_root,
        emergency_committee_root,
        timelock_height: 21_600,
        required_weight_bps,
        escape_authority_root,
    }
}

fn devnet_collusion_case(
    kind: CollusionCaseKind,
    signer_epoch: u64,
    watcher_ids: Vec<&str>,
    aggregate_weight_bps: u16,
    ordinal: u64,
) -> CollusionCase {
    let watcher_ids = watcher_ids
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let evidence_root = domain_hash(
        "CANONICAL-PQ-WATCHER-COLLUSION-EVIDENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::U64(signer_epoch),
            HashPart::Json(&json!(watcher_ids)),
            HashPart::U64(aggregate_weight_bps as u64),
            HashPart::U64(ordinal),
        ],
        32,
    );
    let case_id = domain_hash(
        "CANONICAL-PQ-WATCHER-COLLUSION-CASE-ID",
        &[HashPart::Str(&evidence_root), HashPart::U64(ordinal)],
        32,
    );
    CollusionCase {
        case_id,
        kind,
        signer_epoch,
        watcher_ids,
        aggregate_weight_bps,
        evidence_root,
        quarantine_recommended: true,
    }
}

fn label_root(domain: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "CANONICAL-PQ-WATCHER-LABEL",
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
