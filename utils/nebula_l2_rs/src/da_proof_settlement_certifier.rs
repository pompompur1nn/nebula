use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DaProofSettlementCertifierResult<T> = Result<T, String>;

pub const DA_PROOF_SETTLEMENT_CERTIFIER_PROTOCOL_VERSION: &str =
    "nebula-da-proof-settlement-certifier-v1";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_SCHEMA_VERSION: u64 = 1;
pub const DA_PROOF_SETTLEMENT_CERTIFIER_HASH_SUITE: &str = "SHAKE256";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DA_PROOF_SYSTEM: &str =
    "nebula-devnet-da-sample-availability-v1";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_VALIDITY_PROOF_SYSTEM: &str =
    "nebula-devnet-private-state-validity-v1";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_RECURSIVE_PROOF_SYSTEM: &str =
    "nebula-devnet-recursive-settlement-aggregation-v1";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_ANCHOR_SCHEME: &str = "monero-viewtag-anchor-reference-v1";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_SAMPLE_COUNT: u64 = 16;
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_SAMPLE_QUORUM_BPS: u64 = 6_667;
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_PROOF_QUORUM_BPS: u64 = 6_667;
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_FINALITY_CONFIRMATIONS: u64 = 20;
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_QUARANTINE_BLOCKS: u64 = 720;
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_LOW_FEE_BUDGET_MICROUNITS: u64 = 80_000;
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_FEE_ASSET_ID: &str = "dxmr";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_MAX_BPS: u64 = 10_000;
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_OPERATOR_ID: &str =
    "da-proof-settlement-operator-devnet";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_WATCHTOWER_ID: &str =
    "da-proof-settlement-watchtower-devnet";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_CERTIFIER_ID: &str =
    "da-proof-settlement-certifier-devnet";
pub const DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_SPONSOR_ID: &str =
    "da-proof-settlement-sponsor-devnet";

pub const CERTIFIER_STATUS_PENDING: &str = "pending";
pub const CERTIFIER_STATUS_ACTIVE: &str = "active";
pub const CERTIFIER_STATUS_VERIFIED: &str = "verified";
pub const CERTIFIER_STATUS_ATTESTED: &str = "attested";
pub const CERTIFIER_STATUS_FINALIZED: &str = "finalized";
pub const CERTIFIER_STATUS_CHALLENGED: &str = "challenged";
pub const CERTIFIER_STATUS_RESOLVED: &str = "resolved";
pub const CERTIFIER_STATUS_EXPIRED: &str = "expired";
pub const CERTIFIER_STATUS_REJECTED: &str = "rejected";
pub const CERTIFIER_STATUS_REVOKED: &str = "revoked";
pub const CERTIFIER_STATUS_QUARANTINED: &str = "quarantined";
pub const CERTIFIER_STATUS_SLASHED: &str = "slashed";
pub const CERTIFIER_STATUS_SPONSORED: &str = "sponsored";
pub const CERTIFIER_STATUS_OBSERVED: &str = "observed";

const VALID_STATE_STATUSES: &[&str] = &[
    CERTIFIER_STATUS_ACTIVE,
    CERTIFIER_STATUS_QUARANTINED,
    CERTIFIER_STATUS_REVOKED,
];
const VALID_CERTIFICATE_STATUSES: &[&str] = &[
    CERTIFIER_STATUS_PENDING,
    CERTIFIER_STATUS_VERIFIED,
    CERTIFIER_STATUS_ATTESTED,
    CERTIFIER_STATUS_FINALIZED,
    CERTIFIER_STATUS_CHALLENGED,
    CERTIFIER_STATUS_REJECTED,
    CERTIFIER_STATUS_REVOKED,
    CERTIFIER_STATUS_QUARANTINED,
    CERTIFIER_STATUS_SPONSORED,
    CERTIFIER_STATUS_OBSERVED,
];
const VALID_WINDOW_STATUSES: &[&str] = &[
    CERTIFIER_STATUS_ACTIVE,
    CERTIFIER_STATUS_CHALLENGED,
    CERTIFIER_STATUS_RESOLVED,
    CERTIFIER_STATUS_EXPIRED,
];
const VALID_REVOCATION_STATUSES: &[&str] = &[
    CERTIFIER_STATUS_PENDING,
    CERTIFIER_STATUS_ACTIVE,
    CERTIFIER_STATUS_REVOKED,
    CERTIFIER_STATUS_QUARANTINED,
    CERTIFIER_STATUS_SLASHED,
    CERTIFIER_STATUS_RESOLVED,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDomain {
    PrivateTransfer,
    MoneroBridge,
    TokenTransfer,
    DefiCall,
    ContractExecution,
    ForcedInclusion,
    Governance,
    Emergency,
}

impl SettlementDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::TokenTransfer => "token_transfer",
            Self::DefiCall => "defi_call",
            Self::ContractExecution => "contract_execution",
            Self::ForcedInclusion => "forced_inclusion",
            Self::Governance => "governance",
            Self::Emergency => "emergency",
        }
    }

    pub fn requires_monero_anchor(&self) -> bool {
        matches!(
            self,
            Self::MoneroBridge | Self::ForcedInclusion | Self::Emergency
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaSampleReceiptKind {
    ErasureShard,
    NamespaceShare,
    DataRootInclusion,
    ProviderCustody,
    RetentionProbe,
}

impl DaSampleReceiptKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ErasureShard => "erasure_shard",
            Self::NamespaceShare => "namespace_share",
            Self::DataRootInclusion => "data_root_inclusion",
            Self::ProviderCustody => "provider_custody",
            Self::RetentionProbe => "retention_probe",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCertificateKind {
    StateTransition,
    MoneroBridge,
    ContractExecution,
    RecursiveAggregate,
    SettlementBatch,
}

impl ProofCertificateKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition",
            Self::MoneroBridge => "monero_bridge",
            Self::ContractExecution => "contract_execution",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::SettlementBatch => "settlement_batch",
        }
    }

    pub fn settlement_domain(&self) -> SettlementDomain {
        match self {
            Self::StateTransition | Self::SettlementBatch | Self::RecursiveAggregate => {
                SettlementDomain::PrivateTransfer
            }
            Self::MoneroBridge => SettlementDomain::MoneroBridge,
            Self::ContractExecution => SettlementDomain::ContractExecution,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveAggregationKind {
    Pairwise,
    Tree,
    StreamingAccumulator,
    SettlementEpoch,
}

impl RecursiveAggregationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pairwise => "pairwise",
            Self::Tree => "tree",
            Self::StreamingAccumulator => "streaming_accumulator",
            Self::SettlementEpoch => "settlement_epoch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroAnchorKind {
    Txid,
    BlockHash,
    OutputCommitment,
    ViewTag,
    KeyImageSet,
    ReserveProof,
}

impl MoneroAnchorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Txid => "txid",
            Self::BlockHash => "block_hash",
            Self::OutputCommitment => "output_commitment",
            Self::ViewTag => "view_tag",
            Self::KeyImageSet => "key_image_set",
            Self::ReserveProof => "reserve_proof",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerObservationKind {
    DaUnavailable,
    ProofMismatch,
    AnchorReorg,
    FinalityDelay,
    LowFeeUnderfunded,
    RevocationSignal,
}

impl WatchtowerObservationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DaUnavailable => "da_unavailable",
            Self::ProofMismatch => "proof_mismatch",
            Self::AnchorReorg => "anchor_reorg",
            Self::FinalityDelay => "finality_delay",
            Self::LowFeeUnderfunded => "low_fee_underfunded",
            Self::RevocationSignal => "revocation_signal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    MissingDaSample,
    InvalidDaReceipt,
    InvalidProof,
    RecursiveAccumulatorMismatch,
    MoneroAnchorMismatch,
    InsufficientFinality,
    CertifierQuorumFailure,
    SponsorFraud,
}

impl ChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingDaSample => "missing_da_sample",
            Self::InvalidDaReceipt => "invalid_da_receipt",
            Self::InvalidProof => "invalid_proof",
            Self::RecursiveAccumulatorMismatch => "recursive_accumulator_mismatch",
            Self::MoneroAnchorMismatch => "monero_anchor_mismatch",
            Self::InsufficientFinality => "insufficient_finality",
            Self::CertifierQuorumFailure => "certifier_quorum_failure",
            Self::SponsorFraud => "sponsor_fraud",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeOutcome {
    Unresolved,
    CertificateAccepted,
    CertificateRejected,
    Reaggregate,
    ExtendWindow,
    SlashCertifier,
    QuarantineAnchor,
}

impl ChallengeOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unresolved => "unresolved",
            Self::CertificateAccepted => "certificate_accepted",
            Self::CertificateRejected => "certificate_rejected",
            Self::Reaggregate => "reaggregate",
            Self::ExtendWindow => "extend_window",
            Self::SlashCertifier => "slash_certifier",
            Self::QuarantineAnchor => "quarantine_anchor",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaProofSettlementCertifierConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub pq_backup_scheme: String,
    pub pq_kem_scheme: String,
    pub da_proof_system: String,
    pub validity_proof_system: String,
    pub recursive_proof_system: String,
    pub monero_anchor_scheme: String,
    pub required_sample_count: u64,
    pub sample_quorum_bps: u64,
    pub proof_quorum_bps: u64,
    pub finality_confirmations: u64,
    pub challenge_window_blocks: u64,
    pub quarantine_blocks: u64,
    pub low_fee_budget_microunits: u64,
    pub fee_asset_id: String,
    pub max_public_record_bytes: u64,
}

impl DaProofSettlementCertifierConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: DA_PROOF_SETTLEMENT_CERTIFIER_PROTOCOL_VERSION.to_string(),
            schema_version: DA_PROOF_SETTLEMENT_CERTIFIER_SCHEMA_VERSION,
            hash_suite: DA_PROOF_SETTLEMENT_CERTIFIER_HASH_SUITE.to_string(),
            pq_signature_scheme: DA_PROOF_SETTLEMENT_CERTIFIER_PQ_SIGNATURE_SCHEME.to_string(),
            pq_backup_scheme: DA_PROOF_SETTLEMENT_CERTIFIER_PQ_BACKUP_SCHEME.to_string(),
            pq_kem_scheme: DA_PROOF_SETTLEMENT_CERTIFIER_PQ_KEM_SCHEME.to_string(),
            da_proof_system: DA_PROOF_SETTLEMENT_CERTIFIER_DA_PROOF_SYSTEM.to_string(),
            validity_proof_system: DA_PROOF_SETTLEMENT_CERTIFIER_VALIDITY_PROOF_SYSTEM.to_string(),
            recursive_proof_system: DA_PROOF_SETTLEMENT_CERTIFIER_RECURSIVE_PROOF_SYSTEM
                .to_string(),
            monero_anchor_scheme: DA_PROOF_SETTLEMENT_CERTIFIER_ANCHOR_SCHEME.to_string(),
            required_sample_count: DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_SAMPLE_COUNT,
            sample_quorum_bps: DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_SAMPLE_QUORUM_BPS,
            proof_quorum_bps: DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_PROOF_QUORUM_BPS,
            finality_confirmations: DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_FINALITY_CONFIRMATIONS,
            challenge_window_blocks: DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            quarantine_blocks: DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_QUARANTINE_BLOCKS,
            low_fee_budget_microunits:
                DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_LOW_FEE_BUDGET_MICROUNITS,
            fee_asset_id: DA_PROOF_SETTLEMENT_CERTIFIER_DEFAULT_FEE_ASSET_ID.to_string(),
            max_public_record_bytes: 32 * 1024,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_backup_scheme": self.pq_backup_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "da_proof_system": self.da_proof_system,
            "validity_proof_system": self.validity_proof_system,
            "recursive_proof_system": self.recursive_proof_system,
            "monero_anchor_scheme": self.monero_anchor_scheme,
            "required_sample_count": self.required_sample_count,
            "sample_quorum_bps": self.sample_quorum_bps,
            "proof_quorum_bps": self.proof_quorum_bps,
            "finality_confirmations": self.finality_confirmations,
            "challenge_window_blocks": self.challenge_window_blocks,
            "quarantine_blocks": self.quarantine_blocks,
            "low_fee_budget_microunits": self.low_fee_budget_microunits,
            "fee_asset_id": self.fee_asset_id,
            "max_public_record_bytes": self.max_public_record_bytes,
        })
    }

    pub fn state_root(&self) -> String {
        da_proof_settlement_certifier_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_signature_scheme", &self.pq_signature_scheme)?;
        require_non_empty("da_proof_system", &self.da_proof_system)?;
        require_non_empty("validity_proof_system", &self.validity_proof_system)?;
        require_non_empty("recursive_proof_system", &self.recursive_proof_system)?;
        require_non_empty("monero_anchor_scheme", &self.monero_anchor_scheme)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        if self.required_sample_count == 0 {
            return Err("required_sample_count must be positive".to_string());
        }
        if self.sample_quorum_bps == 0
            || self.sample_quorum_bps > DA_PROOF_SETTLEMENT_CERTIFIER_MAX_BPS
        {
            return Err("sample_quorum_bps out of range".to_string());
        }
        if self.proof_quorum_bps == 0
            || self.proof_quorum_bps > DA_PROOF_SETTLEMENT_CERTIFIER_MAX_BPS
        {
            return Err("proof_quorum_bps out of range".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("challenge_window_blocks must be positive".to_string());
        }
        if self.finality_confirmations == 0 {
            return Err("finality_confirmations must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSampleReceipt {
    pub receipt_id: String,
    pub settlement_id: String,
    pub kind: DaSampleReceiptKind,
    pub provider_id: String,
    pub blob_root: String,
    pub namespace_id: String,
    pub sample_index: u64,
    pub sample_count: u64,
    pub sample_commitment_root: String,
    pub inclusion_proof_root: String,
    pub custody_signature_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl DaSampleReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "settlement_id": self.settlement_id,
            "kind": self.kind.as_str(),
            "provider_id": self.provider_id,
            "blob_root": self.blob_root,
            "namespace_id": self.namespace_id,
            "sample_index": self.sample_index,
            "sample_count": self.sample_count,
            "sample_commitment_root": self.sample_commitment_root,
            "inclusion_proof_root": self.inclusion_proof_root,
            "custody_signature_root": self.custody_signature_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        da_sample_receipt_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("provider_id", &self.provider_id)?;
        require_non_empty("blob_root", &self.blob_root)?;
        require_non_empty("namespace_id", &self.namespace_id)?;
        require_non_empty("sample_commitment_root", &self.sample_commitment_root)?;
        require_non_empty("inclusion_proof_root", &self.inclusion_proof_root)?;
        require_non_empty("custody_signature_root", &self.custody_signature_root)?;
        require_status(
            "sample_receipt.status",
            &self.status,
            VALID_CERTIFICATE_STATUSES,
        )?;
        if self.sample_count == 0 {
            return Err("sample receipt sample_count must be positive".to_string());
        }
        if self.sample_index >= self.sample_count {
            return Err("sample receipt sample_index must be below sample_count".to_string());
        }
        if self.expires_at_height <= self.observed_at_height {
            return Err("sample receipt expires_at_height must be after observation".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofVerificationCertificate {
    pub certificate_id: String,
    pub settlement_id: String,
    pub kind: ProofCertificateKind,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub proof_commitment_root: String,
    pub public_input_root: String,
    pub private_input_commitment_root: String,
    pub da_receipt_root: String,
    pub verifier_committee_root: String,
    pub verification_transcript_root: String,
    pub verified_at_height: u64,
    pub challenge_expires_at_height: u64,
    pub status: String,
}

impl ProofVerificationCertificate {
    pub fn public_record(&self) -> Value {
        json!({
            "certificate_id": self.certificate_id,
            "settlement_id": self.settlement_id,
            "kind": self.kind.as_str(),
            "proof_system": self.proof_system,
            "verifier_key_root": self.verifier_key_root,
            "proof_commitment_root": self.proof_commitment_root,
            "public_input_root": self.public_input_root,
            "private_input_commitment_root": self.private_input_commitment_root,
            "da_receipt_root": self.da_receipt_root,
            "verifier_committee_root": self.verifier_committee_root,
            "verification_transcript_root": self.verification_transcript_root,
            "verified_at_height": self.verified_at_height,
            "challenge_expires_at_height": self.challenge_expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        proof_verification_certificate_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("certificate_id", &self.certificate_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("proof_system", &self.proof_system)?;
        require_non_empty("verifier_key_root", &self.verifier_key_root)?;
        require_non_empty("proof_commitment_root", &self.proof_commitment_root)?;
        require_non_empty("public_input_root", &self.public_input_root)?;
        require_non_empty(
            "private_input_commitment_root",
            &self.private_input_commitment_root,
        )?;
        require_non_empty("da_receipt_root", &self.da_receipt_root)?;
        require_non_empty("verifier_committee_root", &self.verifier_committee_root)?;
        require_non_empty(
            "verification_transcript_root",
            &self.verification_transcript_root,
        )?;
        require_status(
            "proof_certificate.status",
            &self.status,
            VALID_CERTIFICATE_STATUSES,
        )?;
        if self.challenge_expires_at_height <= self.verified_at_height {
            return Err(
                "proof certificate challenge window must end after verification".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveAggregationAttestation {
    pub attestation_id: String,
    pub settlement_id: String,
    pub aggregation_kind: RecursiveAggregationKind,
    pub aggregator_id: String,
    pub child_certificate_root: String,
    pub child_count: u64,
    pub accumulator_before_root: String,
    pub accumulator_after_root: String,
    pub recursive_proof_root: String,
    pub transcript_root: String,
    pub attested_at_height: u64,
    pub status: String,
}

impl RecursiveAggregationAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "settlement_id": self.settlement_id,
            "aggregation_kind": self.aggregation_kind.as_str(),
            "aggregator_id": self.aggregator_id,
            "child_certificate_root": self.child_certificate_root,
            "child_count": self.child_count,
            "accumulator_before_root": self.accumulator_before_root,
            "accumulator_after_root": self.accumulator_after_root,
            "recursive_proof_root": self.recursive_proof_root,
            "transcript_root": self.transcript_root,
            "attested_at_height": self.attested_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        recursive_aggregation_attestation_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("attestation_id", &self.attestation_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("aggregator_id", &self.aggregator_id)?;
        require_non_empty("child_certificate_root", &self.child_certificate_root)?;
        require_non_empty("accumulator_before_root", &self.accumulator_before_root)?;
        require_non_empty("accumulator_after_root", &self.accumulator_after_root)?;
        require_non_empty("recursive_proof_root", &self.recursive_proof_root)?;
        require_non_empty("transcript_root", &self.transcript_root)?;
        require_status(
            "recursive_attestation.status",
            &self.status,
            VALID_CERTIFICATE_STATUSES,
        )?;
        if self.child_count == 0 {
            return Err("recursive attestation child_count must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAnchorReference {
    pub anchor_id: String,
    pub settlement_id: String,
    pub kind: MoneroAnchorKind,
    pub monero_network: String,
    pub block_height: u64,
    pub block_hash: String,
    pub txid: String,
    pub anchor_payload_root: String,
    pub view_key_commitment_root: String,
    pub output_set_root: String,
    pub key_image_root: String,
    pub confirmations: u64,
    pub observed_at_height: u64,
    pub status: String,
}

impl MoneroAnchorReference {
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "settlement_id": self.settlement_id,
            "kind": self.kind.as_str(),
            "monero_network": self.monero_network,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "txid": self.txid,
            "anchor_payload_root": self.anchor_payload_root,
            "view_key_commitment_root": self.view_key_commitment_root,
            "output_set_root": self.output_set_root,
            "key_image_root": self.key_image_root,
            "confirmations": self.confirmations,
            "observed_at_height": self.observed_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        monero_anchor_reference_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("anchor_id", &self.anchor_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("block_hash", &self.block_hash)?;
        require_non_empty("txid", &self.txid)?;
        require_non_empty("anchor_payload_root", &self.anchor_payload_root)?;
        require_non_empty("view_key_commitment_root", &self.view_key_commitment_root)?;
        require_non_empty("output_set_root", &self.output_set_root)?;
        require_non_empty("key_image_root", &self.key_image_root)?;
        require_status(
            "monero_anchor.status",
            &self.status,
            VALID_CERTIFICATE_STATUSES,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementFinalityCertificate {
    pub finality_id: String,
    pub settlement_id: String,
    pub settlement_domain: SettlementDomain,
    pub batch_root: String,
    pub da_receipt_root: String,
    pub proof_certificate_root: String,
    pub recursive_attestation_root: String,
    pub monero_anchor_root: String,
    pub watchtower_observation_root: String,
    pub pq_signature_root: String,
    pub challenge_window_root: String,
    pub finalized_at_height: u64,
    pub monero_confirmations: u64,
    pub status: String,
}

impl SettlementFinalityCertificate {
    pub fn public_record(&self) -> Value {
        json!({
            "finality_id": self.finality_id,
            "settlement_id": self.settlement_id,
            "settlement_domain": self.settlement_domain.as_str(),
            "batch_root": self.batch_root,
            "da_receipt_root": self.da_receipt_root,
            "proof_certificate_root": self.proof_certificate_root,
            "recursive_attestation_root": self.recursive_attestation_root,
            "monero_anchor_root": self.monero_anchor_root,
            "watchtower_observation_root": self.watchtower_observation_root,
            "pq_signature_root": self.pq_signature_root,
            "challenge_window_root": self.challenge_window_root,
            "finalized_at_height": self.finalized_at_height,
            "monero_confirmations": self.monero_confirmations,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        settlement_finality_certificate_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("finality_id", &self.finality_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("batch_root", &self.batch_root)?;
        require_non_empty("da_receipt_root", &self.da_receipt_root)?;
        require_non_empty("proof_certificate_root", &self.proof_certificate_root)?;
        require_non_empty(
            "recursive_attestation_root",
            &self.recursive_attestation_root,
        )?;
        require_non_empty("monero_anchor_root", &self.monero_anchor_root)?;
        require_non_empty(
            "watchtower_observation_root",
            &self.watchtower_observation_root,
        )?;
        require_non_empty("pq_signature_root", &self.pq_signature_root)?;
        require_non_empty("challenge_window_root", &self.challenge_window_root)?;
        require_status(
            "settlement_finality.status",
            &self.status,
            VALID_CERTIFICATE_STATUSES,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerObservation {
    pub observation_id: String,
    pub settlement_id: String,
    pub watchtower_id: String,
    pub kind: WatchtowerObservationKind,
    pub observed_subject_root: String,
    pub evidence_root: String,
    pub risk_score_bps: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl WatchtowerObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "settlement_id": self.settlement_id,
            "watchtower_id": self.watchtower_id,
            "kind": self.kind.as_str(),
            "observed_subject_root": self.observed_subject_root,
            "evidence_root": self.evidence_root,
            "risk_score_bps": self.risk_score_bps,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        watchtower_observation_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("observation_id", &self.observation_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("watchtower_id", &self.watchtower_id)?;
        require_non_empty("observed_subject_root", &self.observed_subject_root)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        require_status(
            "watchtower_observation.status",
            &self.status,
            VALID_CERTIFICATE_STATUSES,
        )?;
        if self.risk_score_bps > DA_PROOF_SETTLEMENT_CERTIFIER_MAX_BPS {
            return Err("watchtower observation risk_score_bps out of range".to_string());
        }
        if self.expires_at_height <= self.observed_at_height {
            return Err(
                "watchtower observation expires_at_height must be after observation".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofSponsorshipEvidence {
    pub evidence_id: String,
    pub settlement_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_microunits: u64,
    pub paid_fee_microunits: u64,
    pub proof_work_units: u64,
    pub lane_key: String,
    pub invoice_root: String,
    pub payment_receipt_root: String,
    pub opened_at_height: u64,
    pub settled_at_height: u64,
    pub status: String,
}

impl LowFeeProofSponsorshipEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "settlement_id": self.settlement_id,
            "sponsor_id": self.sponsor_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_microunits": self.max_fee_microunits,
            "paid_fee_microunits": self.paid_fee_microunits,
            "proof_work_units": self.proof_work_units,
            "lane_key": self.lane_key,
            "invoice_root": self.invoice_root,
            "payment_receipt_root": self.payment_receipt_root,
            "opened_at_height": self.opened_at_height,
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        low_fee_proof_sponsorship_evidence_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("evidence_id", &self.evidence_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("sponsor_id", &self.sponsor_id)?;
        require_non_empty("beneficiary_commitment", &self.beneficiary_commitment)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("lane_key", &self.lane_key)?;
        require_non_empty("invoice_root", &self.invoice_root)?;
        require_non_empty("payment_receipt_root", &self.payment_receipt_root)?;
        require_status(
            "low_fee_sponsorship.status",
            &self.status,
            VALID_CERTIFICATE_STATUSES,
        )?;
        if self.proof_work_units == 0 {
            return Err("low fee sponsorship proof_work_units must be positive".to_string());
        }
        if self.paid_fee_microunits > self.max_fee_microunits {
            return Err("low fee sponsorship paid fee exceeds maximum".to_string());
        }
        if self.settled_at_height < self.opened_at_height {
            return Err("low fee sponsorship settled before opened".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCertifierSignature {
    pub signature_id: String,
    pub settlement_id: String,
    pub certifier_id: String,
    pub scheme: String,
    pub public_key_root: String,
    pub signed_payload_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub weight_bps: u64,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqCertifierSignature {
    pub fn public_record(&self) -> Value {
        json!({
            "signature_id": self.signature_id,
            "settlement_id": self.settlement_id,
            "certifier_id": self.certifier_id,
            "scheme": self.scheme,
            "public_key_root": self.public_key_root,
            "signed_payload_root": self.signed_payload_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "weight_bps": self.weight_bps,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        pq_certifier_signature_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("signature_id", &self.signature_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("certifier_id", &self.certifier_id)?;
        require_non_empty("scheme", &self.scheme)?;
        require_non_empty("public_key_root", &self.public_key_root)?;
        require_non_empty("signed_payload_root", &self.signed_payload_root)?;
        require_non_empty("transcript_root", &self.transcript_root)?;
        require_non_empty("signature_root", &self.signature_root)?;
        require_status(
            "pq_signature.status",
            &self.status,
            VALID_CERTIFICATE_STATUSES,
        )?;
        if self.weight_bps == 0 || self.weight_bps > DA_PROOF_SETTLEMENT_CERTIFIER_MAX_BPS {
            return Err("pq signature weight_bps out of range".to_string());
        }
        if self.expires_at_height <= self.signed_at_height {
            return Err(
                "pq signature expires_at_height must be after signed_at_height".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeWindow {
    pub window_id: String,
    pub settlement_id: String,
    pub challenge_kind: ChallengeKind,
    pub challenger_commitment: String,
    pub subject_root: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub resolved_at_height: u64,
    pub outcome: ChallengeOutcome,
    pub status: String,
}

impl ChallengeWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "settlement_id": self.settlement_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "subject_root": self.subject_root,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "resolved_at_height": self.resolved_at_height,
            "outcome": self.outcome.as_str(),
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        challenge_window_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("window_id", &self.window_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("challenger_commitment", &self.challenger_commitment)?;
        require_non_empty("subject_root", &self.subject_root)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        require_status(
            "challenge_window.status",
            &self.status,
            VALID_WINDOW_STATUSES,
        )?;
        if self.closes_at_height <= self.opened_at_height {
            return Err(
                "challenge window closes_at_height must be after opened_at_height".to_string(),
            );
        }
        if self.resolved_at_height > 0 && self.resolved_at_height < self.opened_at_height {
            return Err("challenge window resolved before opened".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationQuarantineRecord {
    pub revocation_id: String,
    pub settlement_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub reason_root: String,
    pub quarantine_root: String,
    pub revoked_by: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lifted_at_height: u64,
    pub status: String,
}

impl RevocationQuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "revocation_id": self.revocation_id,
            "settlement_id": self.settlement_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "reason_root": self.reason_root,
            "quarantine_root": self.quarantine_root,
            "revoked_by": self.revoked_by,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "lifted_at_height": self.lifted_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        revocation_quarantine_record_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        require_non_empty("revocation_id", &self.revocation_id)?;
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("subject_root", &self.subject_root)?;
        require_non_empty("reason_root", &self.reason_root)?;
        require_non_empty("quarantine_root", &self.quarantine_root)?;
        require_non_empty("revoked_by", &self.revoked_by)?;
        require_status("revocation.status", &self.status, VALID_REVOCATION_STATUSES)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("revocation expires_at_height must be after opened_at_height".to_string());
        }
        if self.lifted_at_height > 0 && self.lifted_at_height < self.opened_at_height {
            return Err("revocation lifted before opened".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaProofSettlementCertifierRoots {
    pub config_root: String,
    pub da_sample_receipt_root: String,
    pub proof_certificate_root: String,
    pub recursive_attestation_root: String,
    pub monero_anchor_root: String,
    pub settlement_finality_root: String,
    pub watchtower_observation_root: String,
    pub low_fee_sponsorship_root: String,
    pub pq_signature_root: String,
    pub challenge_window_root: String,
    pub revocation_quarantine_root: String,
}

impl DaProofSettlementCertifierRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "da_sample_receipt_root": self.da_sample_receipt_root,
            "proof_certificate_root": self.proof_certificate_root,
            "recursive_attestation_root": self.recursive_attestation_root,
            "monero_anchor_root": self.monero_anchor_root,
            "settlement_finality_root": self.settlement_finality_root,
            "watchtower_observation_root": self.watchtower_observation_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "pq_signature_root": self.pq_signature_root,
            "challenge_window_root": self.challenge_window_root,
            "revocation_quarantine_root": self.revocation_quarantine_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "DA-PROOF-SETTLEMENT-CERTIFIER-ROOTS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(DA_PROOF_SETTLEMENT_CERTIFIER_PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaProofSettlementCertifierCounters {
    pub da_sample_receipts: u64,
    pub proof_certificates: u64,
    pub recursive_attestations: u64,
    pub monero_anchors: u64,
    pub settlement_finality_certificates: u64,
    pub watchtower_observations: u64,
    pub low_fee_sponsorships: u64,
    pub pq_signatures: u64,
    pub challenge_windows: u64,
    pub revocation_quarantines: u64,
}

impl DaProofSettlementCertifierCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "da_sample_receipts": self.da_sample_receipts,
            "proof_certificates": self.proof_certificates,
            "recursive_attestations": self.recursive_attestations,
            "monero_anchors": self.monero_anchors,
            "settlement_finality_certificates": self.settlement_finality_certificates,
            "watchtower_observations": self.watchtower_observations,
            "low_fee_sponsorships": self.low_fee_sponsorships,
            "pq_signatures": self.pq_signatures,
            "challenge_windows": self.challenge_windows,
            "revocation_quarantines": self.revocation_quarantines,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaProofSettlementCertifierState {
    pub config: DaProofSettlementCertifierConfig,
    pub current_height: u64,
    pub status: String,
    pub da_sample_receipts: BTreeMap<String, DaSampleReceipt>,
    pub proof_certificates: BTreeMap<String, ProofVerificationCertificate>,
    pub recursive_attestations: BTreeMap<String, RecursiveAggregationAttestation>,
    pub monero_anchors: BTreeMap<String, MoneroAnchorReference>,
    pub settlement_finality_certificates: BTreeMap<String, SettlementFinalityCertificate>,
    pub watchtower_observations: BTreeMap<String, WatchtowerObservation>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeProofSponsorshipEvidence>,
    pub pq_signatures: BTreeMap<String, PqCertifierSignature>,
    pub challenge_windows: BTreeMap<String, ChallengeWindow>,
    pub revocation_quarantines: BTreeMap<String, RevocationQuarantineRecord>,
}

impl DaProofSettlementCertifierState {
    pub fn devnet() -> DaProofSettlementCertifierResult<Self> {
        let config = DaProofSettlementCertifierConfig::devnet();
        config.validate()?;
        let mut state = Self {
            config,
            current_height: 1,
            status: CERTIFIER_STATUS_ACTIVE.to_string(),
            da_sample_receipts: BTreeMap::new(),
            proof_certificates: BTreeMap::new(),
            recursive_attestations: BTreeMap::new(),
            monero_anchors: BTreeMap::new(),
            settlement_finality_certificates: BTreeMap::new(),
            watchtower_observations: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            pq_signatures: BTreeMap::new(),
            challenge_windows: BTreeMap::new(),
            revocation_quarantines: BTreeMap::new(),
        };

        let settlement_id = settlement_id(
            SettlementDomain::MoneroBridge,
            "devnet-batch-root",
            "devnet-da-root",
            1,
        );
        let sample_commitment_root = commitment_root("devnet-sample", "commitment", 1);
        let receipt = DaSampleReceipt {
            receipt_id: da_sample_receipt_id(
                &settlement_id,
                DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_OPERATOR_ID,
                0,
                &sample_commitment_root,
            ),
            settlement_id: settlement_id.clone(),
            kind: DaSampleReceiptKind::ErasureShard,
            provider_id: DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_OPERATOR_ID.to_string(),
            blob_root: commitment_root("devnet-blob", "private-monero-batch", 1),
            namespace_id: "monero_bridge".to_string(),
            sample_index: 0,
            sample_count: state.config.required_sample_count,
            sample_commitment_root,
            inclusion_proof_root: commitment_root("devnet-inclusion", "receipt", 1),
            custody_signature_root: commitment_root("devnet-custody", "receipt", 1),
            observed_at_height: 1,
            expires_at_height: state.config.challenge_window_blocks + 1,
            status: CERTIFIER_STATUS_VERIFIED.to_string(),
        };
        state.insert_da_sample_receipt(receipt)?;

        let receipt_root = state.da_sample_receipt_root();
        let proof_certificate = ProofVerificationCertificate {
            certificate_id: proof_certificate_id(
                &settlement_id,
                ProofCertificateKind::MoneroBridge,
                "devnet-proof-root",
                &receipt_root,
            ),
            settlement_id: settlement_id.clone(),
            kind: ProofCertificateKind::MoneroBridge,
            proof_system: state.config.validity_proof_system.clone(),
            verifier_key_root: commitment_root("devnet-vk", "monero-bridge", 1),
            proof_commitment_root: commitment_root("devnet-proof", "monero-bridge", 1),
            public_input_root: commitment_root("devnet-public-input", "monero-bridge", 1),
            private_input_commitment_root: commitment_root(
                "devnet-private-input",
                "monero-bridge",
                1,
            ),
            da_receipt_root: receipt_root.clone(),
            verifier_committee_root: commitment_root("devnet-committee", "verifier", 1),
            verification_transcript_root: commitment_root("devnet-transcript", "proof", 1),
            verified_at_height: 1,
            challenge_expires_at_height: state.config.challenge_window_blocks + 1,
            status: CERTIFIER_STATUS_VERIFIED.to_string(),
        };
        state.insert_proof_certificate(proof_certificate)?;

        let proof_root = state.proof_certificate_root();
        let recursive_attestation = RecursiveAggregationAttestation {
            attestation_id: recursive_attestation_id(&settlement_id, &proof_root, 1),
            settlement_id: settlement_id.clone(),
            aggregation_kind: RecursiveAggregationKind::SettlementEpoch,
            aggregator_id: DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_CERTIFIER_ID.to_string(),
            child_certificate_root: proof_root.clone(),
            child_count: 1,
            accumulator_before_root: empty_merkle_root("DA-PROOF-SETTLEMENT-ACCUMULATOR"),
            accumulator_after_root: commitment_root("devnet-accumulator", "after", 1),
            recursive_proof_root: commitment_root("devnet-recursive-proof", "settlement", 1),
            transcript_root: commitment_root("devnet-recursive-transcript", "settlement", 1),
            attested_at_height: 2,
            status: CERTIFIER_STATUS_ATTESTED.to_string(),
        };
        state.insert_recursive_attestation(recursive_attestation)?;

        let monero_anchor = MoneroAnchorReference {
            anchor_id: monero_anchor_id(&settlement_id, "devnet-monero-block", "devnet-monero-tx"),
            settlement_id: settlement_id.clone(),
            kind: MoneroAnchorKind::Txid,
            monero_network: "monero-devnet".to_string(),
            block_height: 10,
            block_hash: "devnet-monero-block".to_string(),
            txid: "devnet-monero-tx".to_string(),
            anchor_payload_root: commitment_root("devnet-anchor-payload", "settlement", 1),
            view_key_commitment_root: commitment_root("devnet-view-key", "anchor", 1),
            output_set_root: commitment_root("devnet-output-set", "anchor", 1),
            key_image_root: commitment_root("devnet-key-image", "anchor", 1),
            confirmations: state.config.finality_confirmations,
            observed_at_height: 2,
            status: CERTIFIER_STATUS_VERIFIED.to_string(),
        };
        state.insert_monero_anchor(monero_anchor)?;

        let observation = WatchtowerObservation {
            observation_id: watchtower_observation_id(
                &settlement_id,
                DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_WATCHTOWER_ID,
                WatchtowerObservationKind::FinalityDelay,
                2,
            ),
            settlement_id: settlement_id.clone(),
            watchtower_id: DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_WATCHTOWER_ID.to_string(),
            kind: WatchtowerObservationKind::FinalityDelay,
            observed_subject_root: state.monero_anchor_root(),
            evidence_root: commitment_root("devnet-watchtower-evidence", "finality", 1),
            risk_score_bps: 0,
            observed_at_height: 2,
            expires_at_height: state.config.challenge_window_blocks + 2,
            status: CERTIFIER_STATUS_OBSERVED.to_string(),
        };
        state.insert_watchtower_observation(observation)?;

        let sponsorship = LowFeeProofSponsorshipEvidence {
            evidence_id: low_fee_sponsorship_id(
                &settlement_id,
                DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_SPONSOR_ID,
                "proofs_settlement_critical",
            ),
            settlement_id: settlement_id.clone(),
            sponsor_id: DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_SPONSOR_ID.to_string(),
            beneficiary_commitment: commitment_root("devnet-beneficiary", "wallet", 1),
            fee_asset_id: state.config.fee_asset_id.clone(),
            max_fee_microunits: state.config.low_fee_budget_microunits,
            paid_fee_microunits: state.config.low_fee_budget_microunits / 2,
            proof_work_units: 1,
            lane_key: "proofs_settlement_critical".to_string(),
            invoice_root: commitment_root("devnet-invoice", "proof", 1),
            payment_receipt_root: commitment_root("devnet-payment", "proof", 1),
            opened_at_height: 1,
            settled_at_height: 2,
            status: CERTIFIER_STATUS_SPONSORED.to_string(),
        };
        state.insert_low_fee_sponsorship(sponsorship)?;

        let signature_payload_root = state.roots().state_root();
        let signature = PqCertifierSignature {
            signature_id: pq_signature_id(
                &settlement_id,
                DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_CERTIFIER_ID,
                &signature_payload_root,
            ),
            settlement_id: settlement_id.clone(),
            certifier_id: DA_PROOF_SETTLEMENT_CERTIFIER_DEVNET_CERTIFIER_ID.to_string(),
            scheme: state.config.pq_signature_scheme.clone(),
            public_key_root: commitment_root("devnet-certifier-pk", "pq", 1),
            signed_payload_root: signature_payload_root,
            transcript_root: commitment_root("devnet-signature-transcript", "pq", 1),
            signature_root: commitment_root("devnet-signature", "pq", 1),
            weight_bps: state.config.proof_quorum_bps,
            signed_at_height: 2,
            expires_at_height: state.config.challenge_window_blocks + 2,
            status: CERTIFIER_STATUS_VERIFIED.to_string(),
        };
        state.insert_pq_signature(signature)?;

        let challenge_window = ChallengeWindow {
            window_id: challenge_window_id(
                &settlement_id,
                ChallengeKind::CertifierQuorumFailure,
                2,
            ),
            settlement_id: settlement_id.clone(),
            challenge_kind: ChallengeKind::CertifierQuorumFailure,
            challenger_commitment: commitment_root("devnet-challenger", "none", 1),
            subject_root: state.pq_signature_root(),
            evidence_root: empty_merkle_root("DA-PROOF-SETTLEMENT-EMPTY-CHALLENGE"),
            opened_at_height: 2,
            closes_at_height: state.config.challenge_window_blocks + 2,
            resolved_at_height: 0,
            outcome: ChallengeOutcome::Unresolved,
            status: CERTIFIER_STATUS_ACTIVE.to_string(),
        };
        state.insert_challenge_window(challenge_window)?;

        let finality = SettlementFinalityCertificate {
            finality_id: finality_certificate_id(&settlement_id, &state.roots().state_root(), 2),
            settlement_id,
            settlement_domain: SettlementDomain::MoneroBridge,
            batch_root: commitment_root("devnet-batch", "settlement", 1),
            da_receipt_root: state.da_sample_receipt_root(),
            proof_certificate_root: state.proof_certificate_root(),
            recursive_attestation_root: state.recursive_attestation_root(),
            monero_anchor_root: state.monero_anchor_root(),
            watchtower_observation_root: state.watchtower_observation_root(),
            pq_signature_root: state.pq_signature_root(),
            challenge_window_root: state.challenge_window_root(),
            finalized_at_height: 3,
            monero_confirmations: state.config.finality_confirmations,
            status: CERTIFIER_STATUS_FINALIZED.to_string(),
        };
        state.insert_settlement_finality_certificate(finality)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> DaProofSettlementCertifierResult<()> {
        if height < self.current_height {
            return Err("height cannot move backwards".to_string());
        }
        self.current_height = height;
        Ok(())
    }

    pub fn insert_da_sample_receipt(
        &mut self,
        receipt: DaSampleReceipt,
    ) -> DaProofSettlementCertifierResult<String> {
        receipt.validate()?;
        let id = receipt.receipt_id.clone();
        self.da_sample_receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn insert_proof_certificate(
        &mut self,
        certificate: ProofVerificationCertificate,
    ) -> DaProofSettlementCertifierResult<String> {
        certificate.validate()?;
        let id = certificate.certificate_id.clone();
        self.proof_certificates.insert(id.clone(), certificate);
        Ok(id)
    }

    pub fn insert_recursive_attestation(
        &mut self,
        attestation: RecursiveAggregationAttestation,
    ) -> DaProofSettlementCertifierResult<String> {
        attestation.validate()?;
        let id = attestation.attestation_id.clone();
        self.recursive_attestations.insert(id.clone(), attestation);
        Ok(id)
    }

    pub fn insert_monero_anchor(
        &mut self,
        anchor: MoneroAnchorReference,
    ) -> DaProofSettlementCertifierResult<String> {
        anchor.validate()?;
        let id = anchor.anchor_id.clone();
        self.monero_anchors.insert(id.clone(), anchor);
        Ok(id)
    }

    pub fn insert_settlement_finality_certificate(
        &mut self,
        certificate: SettlementFinalityCertificate,
    ) -> DaProofSettlementCertifierResult<String> {
        certificate.validate()?;
        let id = certificate.finality_id.clone();
        self.settlement_finality_certificates
            .insert(id.clone(), certificate);
        Ok(id)
    }

    pub fn insert_watchtower_observation(
        &mut self,
        observation: WatchtowerObservation,
    ) -> DaProofSettlementCertifierResult<String> {
        observation.validate()?;
        let id = observation.observation_id.clone();
        self.watchtower_observations.insert(id.clone(), observation);
        Ok(id)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeProofSponsorshipEvidence,
    ) -> DaProofSettlementCertifierResult<String> {
        sponsorship.validate()?;
        let id = sponsorship.evidence_id.clone();
        self.low_fee_sponsorships.insert(id.clone(), sponsorship);
        Ok(id)
    }

    pub fn insert_pq_signature(
        &mut self,
        signature: PqCertifierSignature,
    ) -> DaProofSettlementCertifierResult<String> {
        signature.validate()?;
        let id = signature.signature_id.clone();
        self.pq_signatures.insert(id.clone(), signature);
        Ok(id)
    }

    pub fn insert_challenge_window(
        &mut self,
        window: ChallengeWindow,
    ) -> DaProofSettlementCertifierResult<String> {
        window.validate()?;
        let id = window.window_id.clone();
        self.challenge_windows.insert(id.clone(), window);
        Ok(id)
    }

    pub fn insert_revocation_quarantine(
        &mut self,
        record: RevocationQuarantineRecord,
    ) -> DaProofSettlementCertifierResult<String> {
        record.validate()?;
        let id = record.revocation_id.clone();
        self.revocation_quarantines.insert(id.clone(), record);
        Ok(id)
    }

    pub fn roots(&self) -> DaProofSettlementCertifierRoots {
        DaProofSettlementCertifierRoots {
            config_root: self.config.state_root(),
            da_sample_receipt_root: self.da_sample_receipt_root(),
            proof_certificate_root: self.proof_certificate_root(),
            recursive_attestation_root: self.recursive_attestation_root(),
            monero_anchor_root: self.monero_anchor_root(),
            settlement_finality_root: self.settlement_finality_root(),
            watchtower_observation_root: self.watchtower_observation_root(),
            low_fee_sponsorship_root: self.low_fee_sponsorship_root(),
            pq_signature_root: self.pq_signature_root(),
            challenge_window_root: self.challenge_window_root(),
            revocation_quarantine_root: self.revocation_quarantine_root(),
        }
    }

    pub fn counters(&self) -> DaProofSettlementCertifierCounters {
        DaProofSettlementCertifierCounters {
            da_sample_receipts: self.da_sample_receipts.len() as u64,
            proof_certificates: self.proof_certificates.len() as u64,
            recursive_attestations: self.recursive_attestations.len() as u64,
            monero_anchors: self.monero_anchors.len() as u64,
            settlement_finality_certificates: self.settlement_finality_certificates.len() as u64,
            watchtower_observations: self.watchtower_observations.len() as u64,
            low_fee_sponsorships: self.low_fee_sponsorships.len() as u64,
            pq_signatures: self.pq_signatures.len() as u64,
            challenge_windows: self.challenge_windows.len() as u64,
            revocation_quarantines: self.revocation_quarantines.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_height": self.current_height,
            "status": self.status,
            "roots": roots.public_record(),
            "state_root": roots.state_root(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        da_proof_settlement_certifier_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> DaProofSettlementCertifierResult<()> {
        self.config.validate()?;
        require_status("state.status", &self.status, VALID_STATE_STATUSES)?;
        for receipt in self.da_sample_receipts.values() {
            receipt.validate()?;
        }
        for certificate in self.proof_certificates.values() {
            certificate.validate()?;
        }
        for attestation in self.recursive_attestations.values() {
            attestation.validate()?;
        }
        for anchor in self.monero_anchors.values() {
            anchor.validate()?;
        }
        for finality in self.settlement_finality_certificates.values() {
            finality.validate()?;
        }
        for observation in self.watchtower_observations.values() {
            observation.validate()?;
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
        }
        for signature in self.pq_signatures.values() {
            signature.validate()?;
        }
        for window in self.challenge_windows.values() {
            window.validate()?;
        }
        for revocation in self.revocation_quarantines.values() {
            revocation.validate()?;
        }
        self.validate_referential_integrity()?;
        Ok(())
    }

    pub fn da_sample_receipt_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-SAMPLE-RECEIPT",
            self.da_sample_receipts
                .values()
                .map(DaSampleReceipt::public_record)
                .collect(),
        )
    }

    pub fn proof_certificate_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-PROOF-CERTIFICATE",
            self.proof_certificates
                .values()
                .map(ProofVerificationCertificate::public_record)
                .collect(),
        )
    }

    pub fn recursive_attestation_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-RECURSIVE-ATTESTATION",
            self.recursive_attestations
                .values()
                .map(RecursiveAggregationAttestation::public_record)
                .collect(),
        )
    }

    pub fn monero_anchor_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-MONERO-ANCHOR",
            self.monero_anchors
                .values()
                .map(MoneroAnchorReference::public_record)
                .collect(),
        )
    }

    pub fn settlement_finality_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-FINALITY",
            self.settlement_finality_certificates
                .values()
                .map(SettlementFinalityCertificate::public_record)
                .collect(),
        )
    }

    pub fn watchtower_observation_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-WATCHTOWER-OBSERVATION",
            self.watchtower_observations
                .values()
                .map(WatchtowerObservation::public_record)
                .collect(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-LOW-FEE-SPONSORSHIP",
            self.low_fee_sponsorships
                .values()
                .map(LowFeeProofSponsorshipEvidence::public_record)
                .collect(),
        )
    }

    pub fn pq_signature_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-PQ-SIGNATURE",
            self.pq_signatures
                .values()
                .map(PqCertifierSignature::public_record)
                .collect(),
        )
    }

    pub fn challenge_window_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-CHALLENGE-WINDOW",
            self.challenge_windows
                .values()
                .map(ChallengeWindow::public_record)
                .collect(),
        )
    }

    pub fn revocation_quarantine_root(&self) -> String {
        merkle_record_root(
            "DA-PROOF-SETTLEMENT-REVOCATION-QUARANTINE",
            self.revocation_quarantines
                .values()
                .map(RevocationQuarantineRecord::public_record)
                .collect(),
        )
    }

    fn validate_referential_integrity(&self) -> DaProofSettlementCertifierResult<()> {
        let settlements = self.settlement_ids();
        for certificate in self.proof_certificates.values() {
            if !settlements.contains(&certificate.settlement_id) {
                return Err(format!(
                    "proof certificate references unknown settlement_id {}",
                    certificate.settlement_id
                ));
            }
        }
        for attestation in self.recursive_attestations.values() {
            if !settlements.contains(&attestation.settlement_id) {
                return Err(format!(
                    "recursive attestation references unknown settlement_id {}",
                    attestation.settlement_id
                ));
            }
        }
        for finality in self.settlement_finality_certificates.values() {
            if finality.settlement_domain.requires_monero_anchor()
                && finality.monero_confirmations < self.config.finality_confirmations
            {
                return Err(format!(
                    "finality certificate {} has insufficient Monero confirmations",
                    finality.finality_id
                ));
            }
        }
        Ok(())
    }

    fn settlement_ids(&self) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        for receipt in self.da_sample_receipts.values() {
            ids.insert(receipt.settlement_id.clone());
        }
        for finality in self.settlement_finality_certificates.values() {
            ids.insert(finality.settlement_id.clone());
        }
        ids
    }
}

pub fn settlement_id(
    settlement_domain: SettlementDomain,
    batch_root: &str,
    da_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(DA_PROOF_SETTLEMENT_CERTIFIER_PROTOCOL_VERSION),
            HashPart::Str(settlement_domain.as_str()),
            HashPart::Str(batch_root),
            HashPart::Str(da_root),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn da_sample_receipt_id(
    settlement_id: &str,
    provider_id: &str,
    sample_index: u64,
    sample_commitment_root: &str,
) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-SAMPLE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(provider_id),
            HashPart::Int(sample_index as i128),
            HashPart::Str(sample_commitment_root),
        ],
        32,
    )
}

pub fn proof_certificate_id(
    settlement_id: &str,
    kind: ProofCertificateKind,
    proof_root: &str,
    da_receipt_root: &str,
) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-PROOF-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(proof_root),
            HashPart::Str(da_receipt_root),
        ],
        32,
    )
}

pub fn recursive_attestation_id(
    settlement_id: &str,
    child_certificate_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-RECURSIVE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(child_certificate_root),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn monero_anchor_id(settlement_id: &str, block_hash: &str, txid: &str) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-MONERO-ANCHOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(block_hash),
            HashPart::Str(txid),
        ],
        32,
    )
}

pub fn finality_certificate_id(settlement_id: &str, roots_root: &str, height: u64) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-FINALITY-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(roots_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn watchtower_observation_id(
    settlement_id: &str,
    watchtower_id: &str,
    kind: WatchtowerObservationKind,
    height: u64,
) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-WATCHTOWER-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(watchtower_id),
            HashPart::Str(kind.as_str()),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn low_fee_sponsorship_id(settlement_id: &str, sponsor_id: &str, lane_key: &str) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_key),
        ],
        32,
    )
}

pub fn pq_signature_id(settlement_id: &str, certifier_id: &str, payload_root: &str) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-PQ-SIGNATURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(certifier_id),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn challenge_window_id(
    settlement_id: &str,
    kind: ChallengeKind,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-CHALLENGE-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(kind.as_str()),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn revocation_quarantine_id(
    settlement_id: &str,
    subject_id: &str,
    reason_root: &str,
) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-REVOCATION-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(subject_id),
            HashPart::Str(reason_root),
        ],
        32,
    )
}

pub fn commitment_root(label: &str, value: &str, sequence: u64) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn da_proof_settlement_certifier_root_from_record(record: &Value) -> String {
    domain_hash(
        "DA-PROOF-SETTLEMENT-CERTIFIER-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(DA_PROOF_SETTLEMENT_CERTIFIER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn da_sample_receipt_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-SAMPLE-RECEIPT-ROOT", record)
}

pub fn proof_verification_certificate_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-PROOF-CERTIFICATE-ROOT", record)
}

pub fn recursive_aggregation_attestation_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-RECURSIVE-ATTESTATION-ROOT", record)
}

pub fn monero_anchor_reference_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-MONERO-ANCHOR-ROOT", record)
}

pub fn settlement_finality_certificate_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-FINALITY-CERTIFICATE-ROOT", record)
}

pub fn watchtower_observation_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-WATCHTOWER-OBSERVATION-ROOT", record)
}

pub fn low_fee_proof_sponsorship_evidence_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-LOW-FEE-SPONSORSHIP-ROOT", record)
}

pub fn pq_certifier_signature_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-PQ-SIGNATURE-ROOT", record)
}

pub fn challenge_window_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-CHALLENGE-WINDOW-ROOT", record)
}

pub fn revocation_quarantine_record_root_from_record(record: &Value) -> String {
    typed_record_root("DA-PROOF-SETTLEMENT-REVOCATION-QUARANTINE-ROOT", record)
}

fn typed_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(DA_PROOF_SETTLEMENT_CERTIFIER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn merkle_record_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn empty_merkle_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn require_non_empty(field: &str, value: &str) -> DaProofSettlementCertifierResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn require_status(
    field: &str,
    status: &str,
    allowed: &[&str],
) -> DaProofSettlementCertifierResult<()> {
    if !allowed
        .iter()
        .any(|allowed_status| allowed_status == &status)
    {
        return Err(format!("{field} has invalid status {status}"));
    }
    Ok(())
}

pub fn da_proof_settlement_certifier_state_root(state: &DaProofSettlementCertifierState) -> String {
    state.state_root()
}
