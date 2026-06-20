use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConsensusHardeningResult<T> = Result<T, String>;

pub const CONSENSUS_HARDENING_PROTOCOL_VERSION: &str = "nebula-consensus-hardening-v1";
pub const CONSENSUS_HARDENING_PQ_SIGNATURE_SCHEME: &str = "ml-dsa-87-consensus-threshold-v1";
pub const CONSENSUS_HARDENING_COMMITTEE_HASH_SCHEME: &str = "shake256-committee-root-v1";
pub const CONSENSUS_HARDENING_CERTIFICATE_SCHEME: &str = "nebula-fast-finality-qc-v1";
pub const CONSENSUS_HARDENING_EVIDENCE_SCHEME: &str = "canonical-conflict-evidence-v1";
pub const CONSENSUS_HARDENING_DEVNET_HEIGHT: u64 = 96;
pub const CONSENSUS_HARDENING_MAX_BPS: u64 = 10_000;
pub const CONSENSUS_HARDENING_DEFAULT_SOFT_FINALITY_BPS: u64 = 6_700;
pub const CONSENSUS_HARDENING_DEFAULT_HARD_FINALITY_BPS: u64 = 8_000;
pub const CONSENSUS_HARDENING_DEFAULT_ROTATION_DELAY_BLOCKS: u64 = 32;
pub const CONSENSUS_HARDENING_DEFAULT_CERTIFICATE_TTL_BLOCKS: u64 = 96;
pub const CONSENSUS_HARDENING_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 144;
pub const CONSENSUS_HARDENING_DEFAULT_EVIDENCE_TTL_BLOCKS: u64 = 288;
pub const CONSENSUS_HARDENING_DEFAULT_FINALITY_WINDOW_BLOCKS: u64 = 24;
pub const CONSENSUS_HARDENING_DEFAULT_MAX_FORK_DEPTH: u64 = 4;
pub const CONSENSUS_HARDENING_DEFAULT_MAX_LOW_FEE_PRESSURE_BPS: u64 = 8_500;
pub const CONSENSUS_HARDENING_DEFAULT_MIN_DA_COVERAGE_BPS: u64 = 9_000;
pub const CONSENSUS_HARDENING_DEFAULT_MAX_CLOCK_DRIFT_MS: u64 = 1_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusGuardRail {
    SequencerRotation,
    FastFinality,
    DataAvailability,
    MoneroSettlement,
    PrivateMempool,
    ProverLiveness,
    LowFeeAdmission,
    EmergencyRecovery,
}

impl ConsensusGuardRail {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerRotation => "sequencer_rotation",
            Self::FastFinality => "fast_finality",
            Self::DataAvailability => "data_availability",
            Self::MoneroSettlement => "monero_settlement",
            Self::PrivateMempool => "private_mempool",
            Self::ProverLiveness => "prover_liveness",
            Self::LowFeeAdmission => "low_fee_admission",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorKeyStatus {
    Active,
    Rotating,
    Quarantined,
    Slashed,
    Retired,
}

impl ValidatorKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumCertificateKind {
    Preconfirmation,
    SoftFinality,
    HardFinality,
    DataAvailability,
    SettlementAnchor,
    EmergencyOverride,
}

impl QuorumCertificateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preconfirmation => "preconfirmation",
            Self::SoftFinality => "soft_finality",
            Self::HardFinality => "hard_finality",
            Self::DataAvailability => "data_availability",
            Self::SettlementAnchor => "settlement_anchor",
            Self::EmergencyOverride => "emergency_override",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Pending,
    Verified,
    Superseded,
    Challenged,
    Revoked,
    Expired,
}

impl CertificateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Pending | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkChoiceStatus {
    Candidate,
    Preferred,
    Finalized,
    Rejected,
    RolledBack,
    Expired,
}

impl ForkChoiceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Preferred => "preferred",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::RolledBack => "rolled_back",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Candidate | Self::Preferred | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivocationKind {
    DoubleProposal,
    DoubleVote,
    ConflictingDaVote,
    InvalidPqSignature,
    WithheldData,
    InvalidSettlementAnchor,
    ProverReceiptConflict,
}

impl EquivocationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleProposal => "double_proposal",
            Self::DoubleVote => "double_vote",
            Self::ConflictingDaVote => "conflicting_da_vote",
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::WithheldData => "withheld_data",
            Self::InvalidSettlementAnchor => "invalid_settlement_anchor",
            Self::ProverReceiptConflict => "prover_receipt_conflict",
        }
    }

    pub fn default_slash_bps(self) -> u64 {
        match self {
            Self::DoubleProposal | Self::DoubleVote => 3_000,
            Self::ConflictingDaVote => 2_500,
            Self::InvalidPqSignature => 4_000,
            Self::WithheldData => 1_500,
            Self::InvalidSettlementAnchor => 5_000,
            Self::ProverReceiptConflict => 2_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Open,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Scheduled,
    Active,
    Completed,
    Cancelled,
    Emergency,
    Expired,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Emergency => "emergency",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Scheduled | Self::Active | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityWindowStatus {
    Open,
    Closing,
    Finalized,
    Challenged,
    RolledBack,
    Expired,
}

impl FinalityWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closing => "closing",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::RolledBack => "rolled_back",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Closing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    Fast,
    Normal,
    Degraded,
    Emergency,
}

impl LatencyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Normal => "normal",
            Self::Degraded => "degraded",
            Self::Emergency => "emergency",
        }
    }

    pub fn score_bonus(self) -> u64 {
        match self {
            Self::Fast => 2_000,
            Self::Normal => 1_000,
            Self::Degraded => 250,
            Self::Emergency => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqConsensusAttestationKind {
    ValidatorKey,
    QuorumCertificate,
    ForkChoice,
    Rotation,
    Evidence,
    FinalityWindow,
    LowFeeSafety,
}

impl PqConsensusAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ValidatorKey => "validator_key",
            Self::QuorumCertificate => "quorum_certificate",
            Self::ForkChoice => "fork_choice",
            Self::Rotation => "rotation",
            Self::Evidence => "evidence",
            Self::FinalityWindow => "finality_window",
            Self::LowFeeSafety => "low_fee_safety",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqConsensusAttestationStatus {
    Valid,
    ThresholdValid,
    Revoked,
    Expired,
}

impl PqConsensusAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ThresholdValid => "threshold_valid",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Valid | Self::ThresholdValid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeSafetyMode {
    Open,
    Guarded,
    Constrained,
    Paused,
}

impl LowFeeSafetyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Guarded => "guarded",
            Self::Constrained => "constrained",
            Self::Paused => "paused",
        }
    }

    pub fn from_pressure(pressure_bps: u64, max_pressure_bps: u64) -> Self {
        if pressure_bps >= max_pressure_bps.saturating_add(1_000) {
            Self::Paused
        } else if pressure_bps >= max_pressure_bps {
            Self::Constrained
        } else if pressure_bps >= max_pressure_bps.saturating_mul(8) / 10 {
            Self::Guarded
        } else {
            Self::Open
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusHardeningConfig {
    pub protocol_version: String,
    pub soft_finality_threshold_bps: u64,
    pub hard_finality_threshold_bps: u64,
    pub min_data_availability_coverage_bps: u64,
    pub max_fork_depth: u64,
    pub rotation_delay_blocks: u64,
    pub certificate_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub evidence_ttl_blocks: u64,
    pub finality_window_blocks: u64,
    pub max_low_fee_pressure_bps: u64,
    pub max_clock_drift_ms: u64,
    pub pq_signature_scheme: String,
    pub committee_hash_scheme: String,
    pub enabled_guard_rails: BTreeSet<ConsensusGuardRail>,
}

impl Default for ConsensusHardeningConfig {
    fn default() -> Self {
        Self {
            protocol_version: CONSENSUS_HARDENING_PROTOCOL_VERSION.to_string(),
            soft_finality_threshold_bps: CONSENSUS_HARDENING_DEFAULT_SOFT_FINALITY_BPS,
            hard_finality_threshold_bps: CONSENSUS_HARDENING_DEFAULT_HARD_FINALITY_BPS,
            min_data_availability_coverage_bps: CONSENSUS_HARDENING_DEFAULT_MIN_DA_COVERAGE_BPS,
            max_fork_depth: CONSENSUS_HARDENING_DEFAULT_MAX_FORK_DEPTH,
            rotation_delay_blocks: CONSENSUS_HARDENING_DEFAULT_ROTATION_DELAY_BLOCKS,
            certificate_ttl_blocks: CONSENSUS_HARDENING_DEFAULT_CERTIFICATE_TTL_BLOCKS,
            attestation_ttl_blocks: CONSENSUS_HARDENING_DEFAULT_ATTESTATION_TTL_BLOCKS,
            evidence_ttl_blocks: CONSENSUS_HARDENING_DEFAULT_EVIDENCE_TTL_BLOCKS,
            finality_window_blocks: CONSENSUS_HARDENING_DEFAULT_FINALITY_WINDOW_BLOCKS,
            max_low_fee_pressure_bps: CONSENSUS_HARDENING_DEFAULT_MAX_LOW_FEE_PRESSURE_BPS,
            max_clock_drift_ms: CONSENSUS_HARDENING_DEFAULT_MAX_CLOCK_DRIFT_MS,
            pq_signature_scheme: CONSENSUS_HARDENING_PQ_SIGNATURE_SCHEME.to_string(),
            committee_hash_scheme: CONSENSUS_HARDENING_COMMITTEE_HASH_SCHEME.to_string(),
            enabled_guard_rails: [
                ConsensusGuardRail::SequencerRotation,
                ConsensusGuardRail::FastFinality,
                ConsensusGuardRail::DataAvailability,
                ConsensusGuardRail::MoneroSettlement,
                ConsensusGuardRail::PrivateMempool,
                ConsensusGuardRail::ProverLiveness,
                ConsensusGuardRail::LowFeeAdmission,
                ConsensusGuardRail::EmergencyRecovery,
            ]
            .into_iter()
            .collect(),
        }
    }
}

impl ConsensusHardeningConfig {
    pub fn validate(&self) -> ConsensusHardeningResult<()> {
        ensure_non_empty(
            "consensus hardening protocol version",
            &self.protocol_version,
        )?;
        if self.protocol_version != CONSENSUS_HARDENING_PROTOCOL_VERSION {
            return Err("consensus hardening protocol version mismatch".to_string());
        }
        ensure_bps("soft finality threshold", self.soft_finality_threshold_bps)?;
        ensure_bps("hard finality threshold", self.hard_finality_threshold_bps)?;
        ensure_bps(
            "minimum data availability coverage",
            self.min_data_availability_coverage_bps,
        )?;
        ensure_bps("max low fee pressure", self.max_low_fee_pressure_bps)?;
        if self.soft_finality_threshold_bps > self.hard_finality_threshold_bps {
            return Err("soft finality threshold exceeds hard finality threshold".to_string());
        }
        ensure_positive("max fork depth", self.max_fork_depth)?;
        ensure_positive("rotation delay blocks", self.rotation_delay_blocks)?;
        ensure_positive("certificate ttl blocks", self.certificate_ttl_blocks)?;
        ensure_positive("attestation ttl blocks", self.attestation_ttl_blocks)?;
        ensure_positive("evidence ttl blocks", self.evidence_ttl_blocks)?;
        ensure_positive("finality window blocks", self.finality_window_blocks)?;
        ensure_positive("max clock drift ms", self.max_clock_drift_ms)?;
        ensure_non_empty("pq signature scheme", &self.pq_signature_scheme)?;
        ensure_non_empty("committee hash scheme", &self.committee_hash_scheme)?;
        if self.enabled_guard_rails.is_empty() {
            return Err("at least one consensus guard rail must be enabled".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "consensus_hardening_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "soft_finality_threshold_bps": self.soft_finality_threshold_bps,
            "hard_finality_threshold_bps": self.hard_finality_threshold_bps,
            "min_data_availability_coverage_bps": self.min_data_availability_coverage_bps,
            "max_fork_depth": self.max_fork_depth,
            "rotation_delay_blocks": self.rotation_delay_blocks,
            "certificate_ttl_blocks": self.certificate_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "evidence_ttl_blocks": self.evidence_ttl_blocks,
            "finality_window_blocks": self.finality_window_blocks,
            "max_low_fee_pressure_bps": self.max_low_fee_pressure_bps,
            "max_clock_drift_ms": self.max_clock_drift_ms,
            "pq_signature_scheme": self.pq_signature_scheme,
            "committee_hash_scheme": self.committee_hash_scheme,
            "enabled_guard_rails": self.enabled_guard_rails
                .iter()
                .map(|rail| rail.as_str())
                .collect::<Vec<_>>(),
        })
    }

    pub fn config_root(&self) -> String {
        consensus_hardening_payload_root("CONSENSUS-HARDENING-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorPqIdentity {
    pub validator_id: String,
    pub label: String,
    pub consensus_weight_bps: u64,
    pub pq_public_key_root: String,
    pub network_auth_root: String,
    pub rotation_nonce: u64,
    pub registered_at_height: u64,
    pub rotates_at_height: Option<u64>,
    pub status: ValidatorKeyStatus,
    pub metadata_root: String,
}

impl ValidatorPqIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        consensus_weight_bps: u64,
        pq_key_label: &str,
        network_label: &str,
        rotation_nonce: u64,
        registered_at_height: u64,
        rotates_at_height: Option<u64>,
        metadata: &Value,
    ) -> ConsensusHardeningResult<Self> {
        ensure_non_empty("validator label", label)?;
        ensure_non_empty("validator pq key label", pq_key_label)?;
        ensure_non_empty("validator network label", network_label)?;
        ensure_bps("validator consensus weight", consensus_weight_bps)?;
        if consensus_weight_bps == 0 {
            return Err("validator consensus weight must be positive".to_string());
        }
        if let Some(rotates_at_height) = rotates_at_height {
            ensure_height_window(
                registered_at_height,
                rotates_at_height,
                "validator rotation window",
            )?;
        }
        let pq_public_key_root =
            consensus_hardening_string_root("VALIDATOR-PQ-PUBLIC-KEY", pq_key_label);
        let network_auth_root =
            consensus_hardening_string_root("VALIDATOR-NETWORK-AUTH", network_label);
        let metadata_root = consensus_hardening_payload_root("VALIDATOR-METADATA", metadata);
        let validator_id = consensus_validator_identity_id(
            label,
            consensus_weight_bps,
            &pq_public_key_root,
            rotation_nonce,
        );
        Ok(Self {
            validator_id,
            label: label.to_string(),
            consensus_weight_bps,
            pq_public_key_root,
            network_auth_root,
            rotation_nonce,
            registered_at_height,
            rotates_at_height,
            status: ValidatorKeyStatus::Active,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_pq_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "validator_id": self.validator_id,
            "label": self.label,
            "consensus_weight_bps": self.consensus_weight_bps,
            "pq_public_key_root": self.pq_public_key_root,
            "network_auth_root": self.network_auth_root,
            "rotation_nonce": self.rotation_nonce,
            "registered_at_height": self.registered_at_height,
            "rotates_at_height": self.rotates_at_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn identity_root(&self) -> String {
        consensus_hardening_payload_root("VALIDATOR-PQ-IDENTITY", &self.public_record())
    }

    pub fn validate(&self) -> ConsensusHardeningResult<String> {
        ensure_non_empty("validator id", &self.validator_id)?;
        ensure_non_empty("validator label", &self.label)?;
        ensure_bps("validator consensus weight", self.consensus_weight_bps)?;
        if self.consensus_weight_bps == 0 {
            return Err("validator consensus weight must be positive".to_string());
        }
        ensure_non_empty("validator pq public key root", &self.pq_public_key_root)?;
        ensure_non_empty("validator network auth root", &self.network_auth_root)?;
        ensure_non_empty("validator metadata root", &self.metadata_root)?;
        if let Some(rotates_at_height) = self.rotates_at_height {
            ensure_height_window(
                self.registered_at_height,
                rotates_at_height,
                "validator rotation window",
            )?;
        }
        let expected = consensus_validator_identity_id(
            &self.label,
            self.consensus_weight_bps,
            &self.pq_public_key_root,
            self.rotation_nonce,
        );
        if self.validator_id != expected {
            return Err("validator identity id mismatch".to_string());
        }
        Ok(self.identity_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub certificate_id: String,
    pub certificate_kind: QuorumCertificateKind,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub signer_ids: Vec<String>,
    pub signer_weight_bps: u64,
    pub threshold_bps: u64,
    pub signature_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: CertificateStatus,
}

impl QuorumCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificate_kind: QuorumCertificateKind,
        block_height: u64,
        block_hash: &str,
        state_root: &str,
        signer_ids: Vec<String>,
        signer_weight_bps: u64,
        threshold_bps: u64,
        signature_label: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> ConsensusHardeningResult<Self> {
        ensure_non_empty("quorum certificate block hash", block_hash)?;
        ensure_non_empty("quorum certificate state root", state_root)?;
        ensure_non_empty("quorum certificate signature label", signature_label)?;
        ensure_positive("quorum certificate ttl blocks", ttl_blocks)?;
        ensure_bps("quorum certificate signer weight", signer_weight_bps)?;
        ensure_bps("quorum certificate threshold", threshold_bps)?;
        if signer_ids.is_empty() {
            return Err("quorum certificate has no signers".to_string());
        }
        ensure_unique_strings(&signer_ids, "quorum certificate signer ids")?;
        if signer_weight_bps < threshold_bps {
            return Err("quorum certificate signer weight below threshold".to_string());
        }
        let signature_root = consensus_hardening_payload_root(
            "QUORUM-CERTIFICATE-SIGNATURE",
            &json!({
                "scheme": CONSENSUS_HARDENING_PQ_SIGNATURE_SCHEME,
                "certificate_kind": certificate_kind.as_str(),
                "block_height": block_height,
                "block_hash": block_hash,
                "state_root": state_root,
                "signer_ids": signer_ids,
                "signer_weight_bps": signer_weight_bps,
                "signature_label": signature_label,
            }),
        );
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let certificate_id = quorum_certificate_id(
            certificate_kind,
            block_height,
            block_hash,
            state_root,
            &signature_root,
        );
        Ok(Self {
            certificate_id,
            certificate_kind,
            block_height,
            block_hash: block_hash.to_string(),
            state_root: state_root.to_string(),
            signer_ids,
            signer_weight_bps,
            threshold_bps,
            signature_root,
            created_at_height,
            expires_at_height,
            status: CertificateStatus::Verified,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quorum_certificate",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "certificate_id": self.certificate_id,
            "certificate_kind": self.certificate_kind.as_str(),
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "signer_ids": self.signer_ids,
            "signer_weight_bps": self.signer_weight_bps,
            "threshold_bps": self.threshold_bps,
            "signature_root": self.signature_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn certificate_root(&self) -> String {
        consensus_hardening_payload_root("QUORUM-CERTIFICATE", &self.public_record())
    }

    pub fn validate(&self) -> ConsensusHardeningResult<String> {
        ensure_non_empty("quorum certificate id", &self.certificate_id)?;
        ensure_non_empty("quorum certificate block hash", &self.block_hash)?;
        ensure_non_empty("quorum certificate state root", &self.state_root)?;
        ensure_non_empty("quorum certificate signature root", &self.signature_root)?;
        ensure_bps("quorum certificate signer weight", self.signer_weight_bps)?;
        ensure_bps("quorum certificate threshold", self.threshold_bps)?;
        if self.signer_ids.is_empty() {
            return Err("quorum certificate has no signers".to_string());
        }
        ensure_unique_strings(&self.signer_ids, "quorum certificate signer ids")?;
        if self.signer_weight_bps < self.threshold_bps && self.status.usable() {
            return Err("usable quorum certificate below threshold".to_string());
        }
        ensure_height_window(
            self.created_at_height,
            self.expires_at_height,
            "quorum certificate ttl",
        )?;
        let expected = quorum_certificate_id(
            self.certificate_kind,
            self.block_height,
            &self.block_hash,
            &self.state_root,
            &self.signature_root,
        );
        if self.certificate_id != expected {
            return Err("quorum certificate id mismatch".to_string());
        }
        Ok(self.certificate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkChoiceCandidate {
    pub candidate_id: String,
    pub parent_candidate_id: Option<String>,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub da_root: String,
    pub certificate_id: Option<String>,
    pub signer_weight_bps: u64,
    pub fee_pressure_bps: u64,
    pub latency_class: LatencyClass,
    pub score: u64,
    pub observed_at_height: u64,
    pub status: ForkChoiceStatus,
}

impl ForkChoiceCandidate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_candidate_id: Option<String>,
        block_height: u64,
        block_hash: &str,
        state_root: &str,
        da_root: &str,
        certificate_id: Option<String>,
        signer_weight_bps: u64,
        fee_pressure_bps: u64,
        latency_class: LatencyClass,
        observed_at_height: u64,
        status: ForkChoiceStatus,
    ) -> ConsensusHardeningResult<Self> {
        ensure_non_empty("fork candidate block hash", block_hash)?;
        ensure_non_empty("fork candidate state root", state_root)?;
        ensure_non_empty("fork candidate da root", da_root)?;
        ensure_bps("fork candidate signer weight", signer_weight_bps)?;
        ensure_bps("fork candidate fee pressure", fee_pressure_bps)?;
        let pressure_penalty = fee_pressure_bps / 10;
        let score = signer_weight_bps
            .saturating_add(latency_class.score_bonus())
            .saturating_sub(pressure_penalty);
        let candidate_id = fork_choice_candidate_id(
            block_height,
            block_hash,
            state_root,
            da_root,
            observed_at_height,
        );
        Ok(Self {
            candidate_id,
            parent_candidate_id,
            block_height,
            block_hash: block_hash.to_string(),
            state_root: state_root.to_string(),
            da_root: da_root.to_string(),
            certificate_id,
            signer_weight_bps,
            fee_pressure_bps,
            latency_class,
            score,
            observed_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fork_choice_candidate",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "candidate_id": self.candidate_id,
            "parent_candidate_id": self.parent_candidate_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "da_root": self.da_root,
            "certificate_id": self.certificate_id,
            "signer_weight_bps": self.signer_weight_bps,
            "fee_pressure_bps": self.fee_pressure_bps,
            "latency_class": self.latency_class.as_str(),
            "score": self.score,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn candidate_root(&self) -> String {
        consensus_hardening_payload_root("FORK-CHOICE-CANDIDATE", &self.public_record())
    }

    pub fn validate(&self) -> ConsensusHardeningResult<String> {
        ensure_non_empty("fork candidate id", &self.candidate_id)?;
        ensure_non_empty("fork candidate block hash", &self.block_hash)?;
        ensure_non_empty("fork candidate state root", &self.state_root)?;
        ensure_non_empty("fork candidate da root", &self.da_root)?;
        ensure_bps("fork candidate signer weight", self.signer_weight_bps)?;
        ensure_bps("fork candidate fee pressure", self.fee_pressure_bps)?;
        ensure_positive("fork candidate score", self.score)?;
        let expected = fork_choice_candidate_id(
            self.block_height,
            &self.block_hash,
            &self.state_root,
            &self.da_root,
            self.observed_at_height,
        );
        if self.candidate_id != expected {
            return Err("fork choice candidate id mismatch".to_string());
        }
        Ok(self.candidate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub evidence_id: String,
    pub evidence_kind: EquivocationKind,
    pub offender_id: String,
    pub conflicting_roots: Vec<String>,
    pub witness_root: String,
    pub slashing_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: EvidenceStatus,
}

impl EquivocationEvidence {
    pub fn new(
        evidence_kind: EquivocationKind,
        offender_id: &str,
        conflicting_roots: Vec<String>,
        witness_payload: &Value,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> ConsensusHardeningResult<Self> {
        ensure_non_empty("equivocation offender id", offender_id)?;
        if conflicting_roots.len() < 2 {
            return Err("equivocation evidence needs at least two conflicting roots".to_string());
        }
        ensure_unique_strings(&conflicting_roots, "equivocation conflicting roots")?;
        ensure_positive("equivocation evidence ttl blocks", ttl_blocks)?;
        let witness_root =
            consensus_hardening_payload_root("EQUIVOCATION-WITNESS", witness_payload);
        let slashing_bps = evidence_kind.default_slash_bps();
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let evidence_id = equivocation_evidence_id(
            evidence_kind,
            offender_id,
            &conflicting_roots,
            &witness_root,
            opened_at_height,
        );
        Ok(Self {
            evidence_id,
            evidence_kind,
            offender_id: offender_id.to_string(),
            conflicting_roots,
            witness_root,
            slashing_bps,
            opened_at_height,
            expires_at_height,
            status: EvidenceStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "equivocation_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "offender_id": self.offender_id,
            "conflicting_roots": self.conflicting_roots,
            "witness_root": self.witness_root,
            "slashing_bps": self.slashing_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn evidence_root(&self) -> String {
        consensus_hardening_payload_root("EQUIVOCATION-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> ConsensusHardeningResult<String> {
        ensure_non_empty("equivocation evidence id", &self.evidence_id)?;
        ensure_non_empty("equivocation offender id", &self.offender_id)?;
        if self.conflicting_roots.len() < 2 {
            return Err("equivocation evidence needs at least two conflicting roots".to_string());
        }
        ensure_unique_strings(&self.conflicting_roots, "equivocation conflicting roots")?;
        ensure_non_empty("equivocation witness root", &self.witness_root)?;
        ensure_bps("equivocation slashing bps", self.slashing_bps)?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "equivocation evidence ttl",
        )?;
        let expected = equivocation_evidence_id(
            self.evidence_kind,
            &self.offender_id,
            &self.conflicting_roots,
            &self.witness_root,
            self.opened_at_height,
        );
        if self.evidence_id != expected {
            return Err("equivocation evidence id mismatch".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRotationPlan {
    pub rotation_id: String,
    pub validator_id: String,
    pub old_key_root: String,
    pub new_key_root: String,
    pub scheduled_at_height: u64,
    pub activates_at_height: u64,
    pub completed_at_height: Option<u64>,
    pub guardian_root: String,
    pub status: RotationStatus,
}

impl ValidatorRotationPlan {
    pub fn new(
        validator_id: &str,
        old_key_root: &str,
        new_key_label: &str,
        guardian_labels: Vec<String>,
        scheduled_at_height: u64,
        delay_blocks: u64,
    ) -> ConsensusHardeningResult<Self> {
        ensure_non_empty("rotation validator id", validator_id)?;
        ensure_non_empty("rotation old key root", old_key_root)?;
        ensure_non_empty("rotation new key label", new_key_label)?;
        ensure_positive("rotation delay blocks", delay_blocks)?;
        if guardian_labels.is_empty() {
            return Err("rotation needs at least one guardian label".to_string());
        }
        ensure_unique_strings(&guardian_labels, "rotation guardian labels")?;
        let new_key_root = consensus_hardening_string_root("VALIDATOR-NEW-PQ-KEY", new_key_label);
        if old_key_root == new_key_root {
            return Err("rotation old and new key roots are equal".to_string());
        }
        let guardian_root =
            consensus_hardening_string_set_root("VALIDATOR-ROTATION-GUARDIANS", &guardian_labels);
        let activates_at_height = scheduled_at_height.saturating_add(delay_blocks);
        let rotation_id = validator_rotation_id(
            validator_id,
            old_key_root,
            &new_key_root,
            scheduled_at_height,
        );
        Ok(Self {
            rotation_id,
            validator_id: validator_id.to_string(),
            old_key_root: old_key_root.to_string(),
            new_key_root,
            scheduled_at_height,
            activates_at_height,
            completed_at_height: None,
            guardian_root,
            status: RotationStatus::Scheduled,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "validator_rotation_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "rotation_id": self.rotation_id,
            "validator_id": self.validator_id,
            "old_key_root": self.old_key_root,
            "new_key_root": self.new_key_root,
            "scheduled_at_height": self.scheduled_at_height,
            "activates_at_height": self.activates_at_height,
            "completed_at_height": self.completed_at_height,
            "guardian_root": self.guardian_root,
            "status": self.status.as_str(),
        })
    }

    pub fn rotation_root(&self) -> String {
        consensus_hardening_payload_root("VALIDATOR-ROTATION-PLAN", &self.public_record())
    }

    pub fn validate(&self) -> ConsensusHardeningResult<String> {
        ensure_non_empty("rotation id", &self.rotation_id)?;
        ensure_non_empty("rotation validator id", &self.validator_id)?;
        ensure_non_empty("rotation old key root", &self.old_key_root)?;
        ensure_non_empty("rotation new key root", &self.new_key_root)?;
        ensure_non_empty("rotation guardian root", &self.guardian_root)?;
        if self.old_key_root == self.new_key_root {
            return Err("rotation old and new key roots are equal".to_string());
        }
        ensure_height_window(
            self.scheduled_at_height,
            self.activates_at_height,
            "rotation activation",
        )?;
        if let Some(completed_at_height) = self.completed_at_height {
            ensure_height_window(
                self.scheduled_at_height,
                completed_at_height,
                "rotation completion",
            )?;
        }
        let expected = validator_rotation_id(
            &self.validator_id,
            &self.old_key_root,
            &self.new_key_root,
            self.scheduled_at_height,
        );
        if self.rotation_id != expected {
            return Err("validator rotation id mismatch".to_string());
        }
        Ok(self.rotation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalitySafetyWindow {
    pub window_id: String,
    pub from_height: u64,
    pub to_height: u64,
    pub preferred_candidate_id: String,
    pub finalized_certificate_id: Option<String>,
    pub rollback_bound_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: FinalityWindowStatus,
}

impl FinalitySafetyWindow {
    pub fn new(
        from_height: u64,
        to_height: u64,
        preferred_candidate_id: &str,
        finalized_certificate_id: Option<String>,
        rollback_bound_payload: &Value,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> ConsensusHardeningResult<Self> {
        ensure_height_window(from_height, to_height, "finality safety block span")?;
        ensure_non_empty("preferred candidate id", preferred_candidate_id)?;
        ensure_positive("finality safety ttl blocks", ttl_blocks)?;
        let rollback_bound_root =
            consensus_hardening_payload_root("FINALITY-ROLLBACK-BOUND", rollback_bound_payload);
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let window_id = finality_safety_window_id(
            from_height,
            to_height,
            preferred_candidate_id,
            &rollback_bound_root,
        );
        Ok(Self {
            window_id,
            from_height,
            to_height,
            preferred_candidate_id: preferred_candidate_id.to_string(),
            finalized_certificate_id,
            rollback_bound_root,
            opened_at_height,
            expires_at_height,
            status: FinalityWindowStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "finality_safety_window",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "from_height": self.from_height,
            "to_height": self.to_height,
            "preferred_candidate_id": self.preferred_candidate_id,
            "finalized_certificate_id": self.finalized_certificate_id,
            "rollback_bound_root": self.rollback_bound_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn window_root(&self) -> String {
        consensus_hardening_payload_root("FINALITY-SAFETY-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> ConsensusHardeningResult<String> {
        ensure_non_empty("finality window id", &self.window_id)?;
        ensure_height_window(
            self.from_height,
            self.to_height,
            "finality safety block span",
        )?;
        ensure_non_empty("preferred candidate id", &self.preferred_candidate_id)?;
        ensure_non_empty("rollback bound root", &self.rollback_bound_root)?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "finality safety ttl",
        )?;
        let expected = finality_safety_window_id(
            self.from_height,
            self.to_height,
            &self.preferred_candidate_id,
            &self.rollback_bound_root,
        );
        if self.window_id != expected {
            return Err("finality safety window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSafetyWindow {
    pub window_id: String,
    pub lane_id: String,
    pub pressure_bps: u64,
    pub sponsor_budget_units: u64,
    pub max_admission_bps: u64,
    pub safety_mode: LowFeeSafetyMode,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeSafetyWindow {
    pub fn new(
        lane_id: &str,
        pressure_bps: u64,
        sponsor_budget_units: u64,
        max_pressure_bps: u64,
        observed_at_height: u64,
        ttl_blocks: u64,
    ) -> ConsensusHardeningResult<Self> {
        ensure_non_empty("low fee safety lane id", lane_id)?;
        ensure_bps("low fee pressure", pressure_bps)?;
        ensure_bps("max low fee pressure", max_pressure_bps)?;
        ensure_positive("low fee safety ttl blocks", ttl_blocks)?;
        let safety_mode = LowFeeSafetyMode::from_pressure(pressure_bps, max_pressure_bps);
        let max_admission_bps = match safety_mode {
            LowFeeSafetyMode::Open => CONSENSUS_HARDENING_MAX_BPS,
            LowFeeSafetyMode::Guarded => 7_500,
            LowFeeSafetyMode::Constrained => 3_500,
            LowFeeSafetyMode::Paused => 0,
        };
        let expires_at_height = observed_at_height.saturating_add(ttl_blocks);
        let window_id = low_fee_safety_window_id(lane_id, pressure_bps, observed_at_height);
        Ok(Self {
            window_id,
            lane_id: lane_id.to_string(),
            pressure_bps,
            sponsor_budget_units,
            max_admission_bps,
            safety_mode,
            observed_at_height,
            expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_safety_window",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "pressure_bps": self.pressure_bps,
            "sponsor_budget_units": self.sponsor_budget_units,
            "max_admission_bps": self.max_admission_bps,
            "safety_mode": self.safety_mode.as_str(),
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn window_root(&self) -> String {
        consensus_hardening_payload_root("LOW-FEE-SAFETY-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> ConsensusHardeningResult<String> {
        ensure_non_empty("low fee safety window id", &self.window_id)?;
        ensure_non_empty("low fee safety lane id", &self.lane_id)?;
        ensure_bps("low fee pressure", self.pressure_bps)?;
        ensure_bps("low fee max admission", self.max_admission_bps)?;
        ensure_height_window(
            self.observed_at_height,
            self.expires_at_height,
            "low fee safety ttl",
        )?;
        let expected =
            low_fee_safety_window_id(&self.lane_id, self.pressure_bps, self.observed_at_height);
        if self.window_id != expected {
            return Err("low fee safety window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqConsensusAttestation {
    pub attestation_id: String,
    pub attestation_kind: PqConsensusAttestationKind,
    pub subject_id: String,
    pub subject_root: String,
    pub signer_id: String,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub signer_weight_bps: u64,
    pub status: PqConsensusAttestationStatus,
}

impl PqConsensusAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attestation_kind: PqConsensusAttestationKind,
        subject_id: &str,
        subject_root: &str,
        signer_id: &str,
        signature_label: &str,
        signed_at_height: u64,
        ttl_blocks: u64,
        signer_weight_bps: u64,
        threshold_bps: u64,
    ) -> ConsensusHardeningResult<Self> {
        ensure_non_empty("pq attestation subject id", subject_id)?;
        ensure_non_empty("pq attestation subject root", subject_root)?;
        ensure_non_empty("pq attestation signer id", signer_id)?;
        ensure_non_empty("pq attestation signature label", signature_label)?;
        ensure_positive("pq attestation ttl blocks", ttl_blocks)?;
        ensure_bps("pq attestation signer weight", signer_weight_bps)?;
        ensure_bps("pq attestation threshold", threshold_bps)?;
        let signature_root = consensus_hardening_payload_root(
            "PQ-CONSENSUS-ATTESTATION-SIGNATURE",
            &json!({
                "scheme": CONSENSUS_HARDENING_PQ_SIGNATURE_SCHEME,
                "attestation_kind": attestation_kind.as_str(),
                "subject_id": subject_id,
                "subject_root": subject_root,
                "signer_id": signer_id,
                "signature_label": signature_label,
            }),
        );
        let expires_at_height = signed_at_height.saturating_add(ttl_blocks);
        let status = if signer_weight_bps >= threshold_bps {
            PqConsensusAttestationStatus::ThresholdValid
        } else {
            PqConsensusAttestationStatus::Valid
        };
        let attestation_id = pq_consensus_attestation_id(
            attestation_kind,
            subject_id,
            subject_root,
            signer_id,
            signed_at_height,
        );
        Ok(Self {
            attestation_id,
            attestation_kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            signer_id: signer_id.to_string(),
            signature_root,
            signed_at_height,
            expires_at_height,
            signer_weight_bps,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_consensus_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_id": self.signer_id,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "signer_weight_bps": self.signer_weight_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        consensus_hardening_payload_root("PQ-CONSENSUS-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> ConsensusHardeningResult<String> {
        ensure_non_empty("pq consensus attestation id", &self.attestation_id)?;
        ensure_non_empty("pq consensus subject id", &self.subject_id)?;
        ensure_non_empty("pq consensus subject root", &self.subject_root)?;
        ensure_non_empty("pq consensus signer id", &self.signer_id)?;
        ensure_non_empty("pq consensus signature root", &self.signature_root)?;
        ensure_bps("pq consensus signer weight", self.signer_weight_bps)?;
        ensure_height_window(
            self.signed_at_height,
            self.expires_at_height,
            "pq consensus attestation ttl",
        )?;
        let expected = pq_consensus_attestation_id(
            self.attestation_kind,
            &self.subject_id,
            &self.subject_root,
            &self.signer_id,
            self.signed_at_height,
        );
        if self.attestation_id != expected {
            return Err("pq consensus attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusHardeningRoots {
    pub config_root: String,
    pub validator_root: String,
    pub quorum_certificate_root: String,
    pub fork_choice_candidate_root: String,
    pub equivocation_evidence_root: String,
    pub validator_rotation_root: String,
    pub finality_window_root: String,
    pub low_fee_safety_root: String,
    pub pq_attestation_root: String,
    pub public_record_root: String,
}

impl ConsensusHardeningRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "consensus_hardening_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "validator_root": self.validator_root,
            "quorum_certificate_root": self.quorum_certificate_root,
            "fork_choice_candidate_root": self.fork_choice_candidate_root,
            "equivocation_evidence_root": self.equivocation_evidence_root,
            "validator_rotation_root": self.validator_rotation_root,
            "finality_window_root": self.finality_window_root,
            "low_fee_safety_root": self.low_fee_safety_root,
            "pq_attestation_root": self.pq_attestation_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusHardeningCounters {
    pub height: u64,
    pub epoch: u64,
    pub validator_count: u64,
    pub active_validator_count: u64,
    pub active_weight_bps: u64,
    pub certificate_count: u64,
    pub usable_certificate_count: u64,
    pub preferred_candidate_count: u64,
    pub finalized_candidate_count: u64,
    pub open_evidence_count: u64,
    pub accepted_evidence_count: u64,
    pub active_rotation_count: u64,
    pub open_finality_window_count: u64,
    pub low_fee_window_count: u64,
    pub constrained_low_fee_window_count: u64,
    pub pq_attestation_count: u64,
    pub usable_pq_attestation_count: u64,
    pub quarantined_validator_count: u64,
    pub slashed_validator_count: u64,
}

impl ConsensusHardeningCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "consensus_hardening_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "validator_count": self.validator_count,
            "active_validator_count": self.active_validator_count,
            "active_weight_bps": self.active_weight_bps,
            "certificate_count": self.certificate_count,
            "usable_certificate_count": self.usable_certificate_count,
            "preferred_candidate_count": self.preferred_candidate_count,
            "finalized_candidate_count": self.finalized_candidate_count,
            "open_evidence_count": self.open_evidence_count,
            "accepted_evidence_count": self.accepted_evidence_count,
            "active_rotation_count": self.active_rotation_count,
            "open_finality_window_count": self.open_finality_window_count,
            "low_fee_window_count": self.low_fee_window_count,
            "constrained_low_fee_window_count": self.constrained_low_fee_window_count,
            "pq_attestation_count": self.pq_attestation_count,
            "usable_pq_attestation_count": self.usable_pq_attestation_count,
            "quarantined_validator_count": self.quarantined_validator_count,
            "slashed_validator_count": self.slashed_validator_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusHardeningState {
    pub height: u64,
    pub epoch: u64,
    pub config: ConsensusHardeningConfig,
    pub validators: BTreeMap<String, ValidatorPqIdentity>,
    pub quorum_certificates: BTreeMap<String, QuorumCertificate>,
    pub fork_choice_candidates: BTreeMap<String, ForkChoiceCandidate>,
    pub equivocation_evidence: BTreeMap<String, EquivocationEvidence>,
    pub validator_rotations: BTreeMap<String, ValidatorRotationPlan>,
    pub finality_windows: BTreeMap<String, FinalitySafetyWindow>,
    pub low_fee_windows: BTreeMap<String, LowFeeSafetyWindow>,
    pub pq_attestations: BTreeMap<String, PqConsensusAttestation>,
    pub public_records: BTreeMap<String, Value>,
}

impl ConsensusHardeningState {
    pub fn new(config: ConsensusHardeningConfig) -> ConsensusHardeningResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            epoch: 0,
            config,
            validators: BTreeMap::new(),
            quorum_certificates: BTreeMap::new(),
            fork_choice_candidates: BTreeMap::new(),
            equivocation_evidence: BTreeMap::new(),
            validator_rotations: BTreeMap::new(),
            finality_windows: BTreeMap::new(),
            low_fee_windows: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> ConsensusHardeningResult<Self> {
        let mut state = Self::new(ConsensusHardeningConfig::default())?;
        state.set_height(CONSENSUS_HARDENING_DEVNET_HEIGHT)?;

        let validator_a = ValidatorPqIdentity::new(
            "devnet-validator-a",
            3_400,
            "devnet-validator-a-ml-dsa-key",
            "devnet-validator-a-network-auth",
            1,
            1,
            None,
            &json!({"role": "leader", "region": "local-a", "monero_observer": true}),
        )?;
        let validator_b = ValidatorPqIdentity::new(
            "devnet-validator-b",
            3_300,
            "devnet-validator-b-ml-dsa-key",
            "devnet-validator-b-network-auth",
            1,
            1,
            Some(160),
            &json!({"role": "backup", "region": "local-b", "da_sampler": true}),
        )?;
        let validator_c = ValidatorPqIdentity::new(
            "devnet-validator-c",
            3_300,
            "devnet-validator-c-ml-dsa-key",
            "devnet-validator-c-network-auth",
            1,
            1,
            None,
            &json!({"role": "backup", "region": "local-c", "prover_watch": true}),
        )?;
        let validator_a_id = state.insert_validator(validator_a.clone())?;
        let validator_b_id = state.insert_validator(validator_b.clone())?;
        let validator_c_id = state.insert_validator(validator_c.clone())?;

        let signer_ids = vec![
            validator_a_id.clone(),
            validator_b_id.clone(),
            validator_c_id.clone(),
        ];
        let block_hash = consensus_hardening_string_root("DEVNET-BLOCK-HASH", "devnet-block-96");
        let state_root = consensus_hardening_string_root("DEVNET-STATE-ROOT", "devnet-state-96");
        let da_root = consensus_hardening_string_root("DEVNET-DA-ROOT", "devnet-da-96");
        let qc = QuorumCertificate::new(
            QuorumCertificateKind::SoftFinality,
            96,
            &block_hash,
            &state_root,
            signer_ids.clone(),
            10_000,
            state.config.soft_finality_threshold_bps,
            "devnet-soft-finality-signature-96",
            state.height,
            state.config.certificate_ttl_blocks,
        )?;
        let qc_id = state.insert_quorum_certificate(qc.clone())?;

        let parent_candidate = ForkChoiceCandidate::new(
            None,
            95,
            &consensus_hardening_string_root("DEVNET-BLOCK-HASH", "devnet-block-95"),
            &consensus_hardening_string_root("DEVNET-STATE-ROOT", "devnet-state-95"),
            &consensus_hardening_string_root("DEVNET-DA-ROOT", "devnet-da-95"),
            None,
            10_000,
            1_800,
            LatencyClass::Normal,
            state.height.saturating_sub(1),
            ForkChoiceStatus::Finalized,
        )?;
        let parent_candidate_id = state.insert_fork_choice_candidate(parent_candidate)?;
        let candidate = ForkChoiceCandidate::new(
            Some(parent_candidate_id),
            96,
            &block_hash,
            &state_root,
            &da_root,
            Some(qc_id.clone()),
            10_000,
            2_400,
            LatencyClass::Fast,
            state.height,
            ForkChoiceStatus::Preferred,
        )?;
        let candidate_id = state.insert_fork_choice_candidate(candidate.clone())?;

        let finality_window = FinalitySafetyWindow::new(
            92,
            96,
            &candidate_id,
            Some(qc_id.clone()),
            &json!({
                "max_rollback_depth": state.config.max_fork_depth,
                "monero_anchor_pending": true,
                "da_root": da_root,
            }),
            state.height,
            state.config.finality_window_blocks,
        )?;
        let finality_window_id = state.insert_finality_window(finality_window.clone())?;

        let low_fee_window = LowFeeSafetyWindow::new(
            "devnet-low-fee-private-lane",
            7_200,
            500_000,
            state.config.max_low_fee_pressure_bps,
            state.height,
            state.config.finality_window_blocks,
        )?;
        state.insert_low_fee_window(low_fee_window)?;

        let rotation = ValidatorRotationPlan::new(
            &validator_b_id,
            &validator_b.pq_public_key_root,
            "devnet-validator-b-ml-dsa-key-rotation-2",
            vec![
                validator_a_id.clone(),
                validator_c_id.clone(),
                "devnet-guardian-consensus".to_string(),
            ],
            state.height,
            state.config.rotation_delay_blocks,
        )?;
        let rotation_id = state.insert_validator_rotation(rotation.clone())?;

        let evidence = EquivocationEvidence::new(
            EquivocationKind::ConflictingDaVote,
            &validator_c_id,
            vec![
                consensus_hardening_string_root("DEVNET-CONFLICT", "da-vote-root-a"),
                consensus_hardening_string_root("DEVNET-CONFLICT", "da-vote-root-b"),
            ],
            &json!({
                "watchtower": "devnet-watchtower-a",
                "observed_slots": [94, 95],
                "payload": "conflicting-da-vote-roots",
            }),
            state.height,
            state.config.evidence_ttl_blocks,
        )?;
        let evidence_id = state.insert_equivocation_evidence(evidence.clone())?;

        for (kind, subject_id, subject_root, signer_id, weight) in [
            (
                PqConsensusAttestationKind::QuorumCertificate,
                qc_id.clone(),
                qc.certificate_root(),
                validator_a_id.clone(),
                10_000,
            ),
            (
                PqConsensusAttestationKind::ForkChoice,
                candidate_id.clone(),
                candidate.candidate_root(),
                validator_b_id.clone(),
                6_700,
            ),
            (
                PqConsensusAttestationKind::Rotation,
                rotation_id.clone(),
                rotation.rotation_root(),
                validator_a_id.clone(),
                6_700,
            ),
            (
                PqConsensusAttestationKind::Evidence,
                evidence_id,
                evidence.evidence_root(),
                validator_a_id.clone(),
                6_700,
            ),
            (
                PqConsensusAttestationKind::FinalityWindow,
                finality_window_id,
                finality_window.window_root(),
                validator_c_id.clone(),
                6_700,
            ),
        ] {
            let attestation = PqConsensusAttestation::new(
                kind,
                &subject_id,
                &subject_root,
                &signer_id,
                "devnet-consensus-pq-signature",
                state.height,
                state.config.attestation_ttl_blocks,
                weight,
                state.config.soft_finality_threshold_bps,
            )?;
            state.insert_pq_attestation(attestation)?;
        }

        state.record_public_record(
            "devnet-consensus-operator-note",
            &json!({
                "preferred_candidate_id": candidate_id,
                "soft_finality_certificate_id": qc_id,
                "low_fee_safety": "guarded but open",
            }),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> ConsensusHardeningResult<String> {
        self.height = height;
        self.epoch = height / self.config.finality_window_blocks.max(1);
        for certificate in self.quorum_certificates.values_mut() {
            if self.height > certificate.expires_at_height && certificate.status.usable() {
                certificate.status = CertificateStatus::Expired;
            }
        }
        for evidence in self.equivocation_evidence.values_mut() {
            if self.height > evidence.expires_at_height && evidence.status.live() {
                evidence.status = EvidenceStatus::Expired;
            }
        }
        for rotation in self.validator_rotations.values_mut() {
            if self.height >= rotation.activates_at_height
                && rotation.status == RotationStatus::Scheduled
            {
                rotation.status = RotationStatus::Active;
            }
            if self.height
                > rotation
                    .activates_at_height
                    .saturating_add(self.config.rotation_delay_blocks)
                && rotation.status == RotationStatus::Active
            {
                rotation.status = RotationStatus::Expired;
            }
        }
        for window in self.finality_windows.values_mut() {
            if self.height > window.expires_at_height && window.status.live() {
                window.status = FinalityWindowStatus::Expired;
            } else if self.height >= window.to_height && window.status == FinalityWindowStatus::Open
            {
                window.status = FinalityWindowStatus::Closing;
            }
        }
        for low_fee_window in self.low_fee_windows.values_mut() {
            if self.height > low_fee_window.expires_at_height {
                low_fee_window.safety_mode = LowFeeSafetyMode::Paused;
                low_fee_window.max_admission_bps = 0;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if self.height > attestation.expires_at_height && attestation.status.usable() {
                attestation.status = PqConsensusAttestationStatus::Expired;
            }
        }
        Ok(self.state_root())
    }

    pub fn insert_validator(
        &mut self,
        validator: ValidatorPqIdentity,
    ) -> ConsensusHardeningResult<String> {
        let validator_id = validator.validator_id.clone();
        validator.validate()?;
        if self.validators.contains_key(&validator_id) {
            return Err("validator already exists".to_string());
        }
        self.validators.insert(validator_id.clone(), validator);
        Ok(validator_id)
    }

    pub fn insert_quorum_certificate(
        &mut self,
        certificate: QuorumCertificate,
    ) -> ConsensusHardeningResult<String> {
        let certificate_id = certificate.certificate_id.clone();
        certificate.validate()?;
        for signer_id in &certificate.signer_ids {
            if !self.validators.contains_key(signer_id) {
                return Err(format!("unknown certificate signer {signer_id}"));
            }
        }
        self.quorum_certificates
            .insert(certificate_id.clone(), certificate);
        Ok(certificate_id)
    }

    pub fn insert_fork_choice_candidate(
        &mut self,
        candidate: ForkChoiceCandidate,
    ) -> ConsensusHardeningResult<String> {
        let candidate_id = candidate.candidate_id.clone();
        candidate.validate()?;
        if let Some(parent_id) = &candidate.parent_candidate_id {
            if !self.fork_choice_candidates.contains_key(parent_id) {
                return Err("fork choice candidate parent is unknown".to_string());
            }
        }
        if let Some(certificate_id) = &candidate.certificate_id {
            if !self.quorum_certificates.contains_key(certificate_id) {
                return Err("fork choice candidate certificate is unknown".to_string());
            }
        }
        if candidate.status == ForkChoiceStatus::Preferred {
            for existing in self.fork_choice_candidates.values_mut() {
                if existing.block_height == candidate.block_height
                    && existing.status == ForkChoiceStatus::Preferred
                {
                    existing.status = ForkChoiceStatus::Candidate;
                }
            }
        }
        self.fork_choice_candidates
            .insert(candidate_id.clone(), candidate);
        Ok(candidate_id)
    }

    pub fn insert_equivocation_evidence(
        &mut self,
        evidence: EquivocationEvidence,
    ) -> ConsensusHardeningResult<String> {
        let evidence_id = evidence.evidence_id.clone();
        evidence.validate()?;
        if !self.validators.contains_key(&evidence.offender_id) {
            return Err("equivocation offender is unknown".to_string());
        }
        if let Some(validator) = self.validators.get_mut(&evidence.offender_id) {
            if evidence.status.live() {
                validator.status = ValidatorKeyStatus::Quarantined;
            }
        }
        self.equivocation_evidence
            .insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn insert_validator_rotation(
        &mut self,
        rotation: ValidatorRotationPlan,
    ) -> ConsensusHardeningResult<String> {
        let rotation_id = rotation.rotation_id.clone();
        rotation.validate()?;
        if !self.validators.contains_key(&rotation.validator_id) {
            return Err("rotation validator is unknown".to_string());
        }
        if let Some(validator) = self.validators.get_mut(&rotation.validator_id) {
            validator.rotates_at_height = Some(rotation.activates_at_height);
            validator.status = ValidatorKeyStatus::Rotating;
        }
        self.validator_rotations
            .insert(rotation_id.clone(), rotation);
        Ok(rotation_id)
    }

    pub fn insert_finality_window(
        &mut self,
        window: FinalitySafetyWindow,
    ) -> ConsensusHardeningResult<String> {
        let window_id = window.window_id.clone();
        window.validate()?;
        if !self
            .fork_choice_candidates
            .contains_key(&window.preferred_candidate_id)
        {
            return Err("finality window preferred candidate is unknown".to_string());
        }
        if let Some(certificate_id) = &window.finalized_certificate_id {
            if !self.quorum_certificates.contains_key(certificate_id) {
                return Err("finality window certificate is unknown".to_string());
            }
        }
        self.finality_windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn insert_low_fee_window(
        &mut self,
        window: LowFeeSafetyWindow,
    ) -> ConsensusHardeningResult<String> {
        let window_id = window.window_id.clone();
        window.validate()?;
        self.low_fee_windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqConsensusAttestation,
    ) -> ConsensusHardeningResult<String> {
        let attestation_id = attestation.attestation_id.clone();
        attestation.validate()?;
        if !self.validators.contains_key(&attestation.signer_id) {
            return Err("pq attestation signer is unknown".to_string());
        }
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn record_public_record(
        &mut self,
        label: &str,
        payload: &Value,
    ) -> ConsensusHardeningResult<String> {
        ensure_non_empty("consensus hardening public record label", label)?;
        let record_id = consensus_hardening_public_record_id(label, self.height, payload);
        self.public_records.insert(
            record_id.clone(),
            json!({
                "kind": "consensus_hardening_public_record",
                "chain_id": CHAIN_ID,
                "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
                "record_id": record_id,
                "label": label,
                "height": self.height,
                "payload_root": consensus_hardening_payload_root("CONSENSUS-HARDENING-PUBLIC-PAYLOAD", payload),
            }),
        );
        Ok(record_id)
    }

    pub fn active_validator_ids(&self) -> Vec<String> {
        self.validators
            .values()
            .filter(|validator| validator.status.usable())
            .map(|validator| validator.validator_id.clone())
            .collect()
    }

    pub fn quarantined_validator_ids(&self) -> Vec<String> {
        self.validators
            .values()
            .filter(|validator| validator.status == ValidatorKeyStatus::Quarantined)
            .map(|validator| validator.validator_id.clone())
            .collect()
    }

    pub fn preferred_candidate_ids(&self) -> Vec<String> {
        self.fork_choice_candidates
            .values()
            .filter(|candidate| candidate.status == ForkChoiceStatus::Preferred)
            .map(|candidate| candidate.candidate_id.clone())
            .collect()
    }

    pub fn finalized_candidate_ids(&self) -> Vec<String> {
        self.fork_choice_candidates
            .values()
            .filter(|candidate| candidate.status == ForkChoiceStatus::Finalized)
            .map(|candidate| candidate.candidate_id.clone())
            .collect()
    }

    pub fn active_weight_bps(&self) -> u64 {
        self.validators
            .values()
            .filter(|validator| validator.status.usable())
            .map(|validator| validator.consensus_weight_bps)
            .sum::<u64>()
            .min(CONSENSUS_HARDENING_MAX_BPS)
    }

    pub fn current_low_fee_mode(&self) -> LowFeeSafetyMode {
        if self
            .low_fee_windows
            .values()
            .any(|window| window.safety_mode == LowFeeSafetyMode::Paused)
        {
            LowFeeSafetyMode::Paused
        } else if self
            .low_fee_windows
            .values()
            .any(|window| window.safety_mode == LowFeeSafetyMode::Constrained)
        {
            LowFeeSafetyMode::Constrained
        } else if self
            .low_fee_windows
            .values()
            .any(|window| window.safety_mode == LowFeeSafetyMode::Guarded)
        {
            LowFeeSafetyMode::Guarded
        } else {
            LowFeeSafetyMode::Open
        }
    }

    pub fn validator_root(&self) -> String {
        consensus_validator_collection_root(
            &self
                .validators
                .values()
                .cloned()
                .collect::<Vec<ValidatorPqIdentity>>(),
        )
    }

    pub fn quorum_certificate_root(&self) -> String {
        consensus_quorum_certificate_collection_root(
            &self
                .quorum_certificates
                .values()
                .cloned()
                .collect::<Vec<QuorumCertificate>>(),
        )
    }

    pub fn fork_choice_candidate_root(&self) -> String {
        consensus_fork_choice_collection_root(
            &self
                .fork_choice_candidates
                .values()
                .cloned()
                .collect::<Vec<ForkChoiceCandidate>>(),
        )
    }

    pub fn equivocation_evidence_root(&self) -> String {
        consensus_equivocation_evidence_collection_root(
            &self
                .equivocation_evidence
                .values()
                .cloned()
                .collect::<Vec<EquivocationEvidence>>(),
        )
    }

    pub fn validator_rotation_root(&self) -> String {
        consensus_validator_rotation_collection_root(
            &self
                .validator_rotations
                .values()
                .cloned()
                .collect::<Vec<ValidatorRotationPlan>>(),
        )
    }

    pub fn finality_window_root(&self) -> String {
        consensus_finality_window_collection_root(
            &self
                .finality_windows
                .values()
                .cloned()
                .collect::<Vec<FinalitySafetyWindow>>(),
        )
    }

    pub fn low_fee_safety_root(&self) -> String {
        consensus_low_fee_window_collection_root(
            &self
                .low_fee_windows
                .values()
                .cloned()
                .collect::<Vec<LowFeeSafetyWindow>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        consensus_pq_attestation_collection_root(
            &self
                .pq_attestations
                .values()
                .cloned()
                .collect::<Vec<PqConsensusAttestation>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        consensus_hardening_value_collection_root(
            "CONSENSUS-HARDENING-PUBLIC-RECORDS",
            &self
                .public_records
                .values()
                .cloned()
                .collect::<Vec<Value>>(),
        )
    }

    pub fn roots(&self) -> ConsensusHardeningRoots {
        ConsensusHardeningRoots {
            config_root: self.config.config_root(),
            validator_root: self.validator_root(),
            quorum_certificate_root: self.quorum_certificate_root(),
            fork_choice_candidate_root: self.fork_choice_candidate_root(),
            equivocation_evidence_root: self.equivocation_evidence_root(),
            validator_rotation_root: self.validator_rotation_root(),
            finality_window_root: self.finality_window_root(),
            low_fee_safety_root: self.low_fee_safety_root(),
            pq_attestation_root: self.pq_attestation_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn counters(&self) -> ConsensusHardeningCounters {
        ConsensusHardeningCounters {
            height: self.height,
            epoch: self.epoch,
            validator_count: self.validators.len() as u64,
            active_validator_count: self
                .validators
                .values()
                .filter(|validator| validator.status.usable())
                .count() as u64,
            active_weight_bps: self.active_weight_bps(),
            certificate_count: self.quorum_certificates.len() as u64,
            usable_certificate_count: self
                .quorum_certificates
                .values()
                .filter(|certificate| certificate.status.usable())
                .count() as u64,
            preferred_candidate_count: self.preferred_candidate_ids().len() as u64,
            finalized_candidate_count: self.finalized_candidate_ids().len() as u64,
            open_evidence_count: self
                .equivocation_evidence
                .values()
                .filter(|evidence| evidence.status == EvidenceStatus::Open)
                .count() as u64,
            accepted_evidence_count: self
                .equivocation_evidence
                .values()
                .filter(|evidence| evidence.status == EvidenceStatus::Accepted)
                .count() as u64,
            active_rotation_count: self
                .validator_rotations
                .values()
                .filter(|rotation| rotation.status.live())
                .count() as u64,
            open_finality_window_count: self
                .finality_windows
                .values()
                .filter(|window| window.status.live())
                .count() as u64,
            low_fee_window_count: self.low_fee_windows.len() as u64,
            constrained_low_fee_window_count: self
                .low_fee_windows
                .values()
                .filter(|window| {
                    matches!(
                        window.safety_mode,
                        LowFeeSafetyMode::Constrained | LowFeeSafetyMode::Paused
                    )
                })
                .count() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            usable_pq_attestation_count: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.status.usable())
                .count() as u64,
            quarantined_validator_count: self.quarantined_validator_ids().len() as u64,
            slashed_validator_count: self
                .validators
                .values()
                .filter(|validator| validator.status == ValidatorKeyStatus::Slashed)
                .count() as u64,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "consensus_hardening_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONSENSUS_HARDENING_PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_validator_ids": self.active_validator_ids(),
            "quarantined_validator_ids": self.quarantined_validator_ids(),
            "preferred_candidate_ids": self.preferred_candidate_ids(),
            "finalized_candidate_ids": self.finalized_candidate_ids(),
            "current_low_fee_mode": self.current_low_fee_mode().as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        consensus_hardening_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> ConsensusHardeningResult<String> {
        self.config.validate()?;
        let total_weight = self
            .validators
            .values()
            .map(|validator| validator.consensus_weight_bps)
            .sum::<u64>();
        if total_weight > CONSENSUS_HARDENING_MAX_BPS {
            return Err("validator total weight exceeds 100%".to_string());
        }
        if self.active_weight_bps() < self.config.soft_finality_threshold_bps {
            return Err("active validator weight below soft finality threshold".to_string());
        }
        for validator in self.validators.values() {
            validator.validate()?;
        }
        for certificate in self.quorum_certificates.values() {
            certificate.validate()?;
            for signer_id in &certificate.signer_ids {
                if !self.validators.contains_key(signer_id) {
                    return Err("certificate signer is unknown".to_string());
                }
            }
        }
        for candidate in self.fork_choice_candidates.values() {
            candidate.validate()?;
            if let Some(parent_id) = &candidate.parent_candidate_id {
                if !self.fork_choice_candidates.contains_key(parent_id) {
                    return Err("fork choice candidate parent is unknown".to_string());
                }
            }
            if let Some(certificate_id) = &candidate.certificate_id {
                if !self.quorum_certificates.contains_key(certificate_id) {
                    return Err("fork choice candidate certificate is unknown".to_string());
                }
            }
        }
        let preferred_per_height = self
            .fork_choice_candidates
            .values()
            .filter(|candidate| candidate.status == ForkChoiceStatus::Preferred)
            .fold(BTreeMap::<u64, u64>::new(), |mut counts, candidate| {
                *counts.entry(candidate.block_height).or_default() += 1;
                counts
            });
        if preferred_per_height.values().any(|count| *count > 1) {
            return Err("more than one preferred fork choice candidate at a height".to_string());
        }
        for evidence in self.equivocation_evidence.values() {
            evidence.validate()?;
            if !self.validators.contains_key(&evidence.offender_id) {
                return Err("equivocation offender is unknown".to_string());
            }
        }
        for rotation in self.validator_rotations.values() {
            rotation.validate()?;
            if !self.validators.contains_key(&rotation.validator_id) {
                return Err("rotation validator is unknown".to_string());
            }
        }
        for window in self.finality_windows.values() {
            window.validate()?;
            if !self
                .fork_choice_candidates
                .contains_key(&window.preferred_candidate_id)
            {
                return Err("finality window preferred candidate is unknown".to_string());
            }
        }
        for window in self.low_fee_windows.values() {
            window.validate()?;
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
            if !self.validators.contains_key(&attestation.signer_id) {
                return Err("pq attestation signer is unknown".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn consensus_hardening_state_root_from_record(record: &Value) -> String {
    consensus_hardening_payload_root("CONSENSUS-HARDENING-STATE", record)
}

pub fn consensus_hardening_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn consensus_hardening_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn consensus_hardening_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(consensus_hardening_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn consensus_hardening_value_collection_root(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn consensus_validator_identity_id(
    label: &str,
    consensus_weight_bps: u64,
    pq_public_key_root: &str,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "CONSENSUS-HARDENING-VALIDATOR-ID",
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(consensus_weight_bps as i128),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(rotation_nonce as i128),
        ],
        16,
    )
}

pub fn quorum_certificate_id(
    certificate_kind: QuorumCertificateKind,
    block_height: u64,
    block_hash: &str,
    state_root: &str,
    signature_root: &str,
) -> String {
    domain_hash(
        "CONSENSUS-HARDENING-QUORUM-CERTIFICATE-ID",
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Str(certificate_kind.as_str()),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(state_root),
            HashPart::Str(signature_root),
        ],
        16,
    )
}

pub fn fork_choice_candidate_id(
    block_height: u64,
    block_hash: &str,
    state_root: &str,
    da_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "CONSENSUS-HARDENING-FORK-CHOICE-CANDIDATE-ID",
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(state_root),
            HashPart::Str(da_root),
            HashPart::Int(observed_at_height as i128),
        ],
        16,
    )
}

pub fn equivocation_evidence_id(
    evidence_kind: EquivocationKind,
    offender_id: &str,
    conflicting_roots: &[String],
    witness_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONSENSUS-HARDENING-EQUIVOCATION-EVIDENCE-ID",
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(offender_id),
            HashPart::Str(&consensus_hardening_string_set_root(
                "EQUIVOCATION-CONFLICTING-ROOTS",
                conflicting_roots,
            )),
            HashPart::Str(witness_root),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

pub fn validator_rotation_id(
    validator_id: &str,
    old_key_root: &str,
    new_key_root: &str,
    scheduled_at_height: u64,
) -> String {
    domain_hash(
        "CONSENSUS-HARDENING-VALIDATOR-ROTATION-ID",
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Str(validator_id),
            HashPart::Str(old_key_root),
            HashPart::Str(new_key_root),
            HashPart::Int(scheduled_at_height as i128),
        ],
        16,
    )
}

pub fn finality_safety_window_id(
    from_height: u64,
    to_height: u64,
    preferred_candidate_id: &str,
    rollback_bound_root: &str,
) -> String {
    domain_hash(
        "CONSENSUS-HARDENING-FINALITY-WINDOW-ID",
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Int(from_height as i128),
            HashPart::Int(to_height as i128),
            HashPart::Str(preferred_candidate_id),
            HashPart::Str(rollback_bound_root),
        ],
        16,
    )
}

pub fn low_fee_safety_window_id(
    lane_id: &str,
    pressure_bps: u64,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "CONSENSUS-HARDENING-LOW-FEE-SAFETY-WINDOW-ID",
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Int(pressure_bps as i128),
            HashPart::Int(observed_at_height as i128),
        ],
        16,
    )
}

pub fn pq_consensus_attestation_id(
    attestation_kind: PqConsensusAttestationKind,
    subject_id: &str,
    subject_root: &str,
    signer_id: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "CONSENSUS-HARDENING-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Str(attestation_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signer_id),
            HashPart::Int(signed_at_height as i128),
        ],
        16,
    )
}

pub fn consensus_hardening_public_record_id(label: &str, height: u64, payload: &Value) -> String {
    domain_hash(
        "CONSENSUS-HARDENING-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CONSENSUS_HARDENING_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Json(payload),
        ],
        16,
    )
}

pub fn consensus_validator_collection_root(records: &[ValidatorPqIdentity]) -> String {
    consensus_hardening_value_collection_root(
        "CONSENSUS-HARDENING-VALIDATORS",
        &records
            .iter()
            .map(ValidatorPqIdentity::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn consensus_quorum_certificate_collection_root(records: &[QuorumCertificate]) -> String {
    consensus_hardening_value_collection_root(
        "CONSENSUS-HARDENING-QUORUM-CERTIFICATES",
        &records
            .iter()
            .map(QuorumCertificate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn consensus_fork_choice_collection_root(records: &[ForkChoiceCandidate]) -> String {
    consensus_hardening_value_collection_root(
        "CONSENSUS-HARDENING-FORK-CHOICE-CANDIDATES",
        &records
            .iter()
            .map(ForkChoiceCandidate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn consensus_equivocation_evidence_collection_root(records: &[EquivocationEvidence]) -> String {
    consensus_hardening_value_collection_root(
        "CONSENSUS-HARDENING-EQUIVOCATION-EVIDENCE",
        &records
            .iter()
            .map(EquivocationEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn consensus_validator_rotation_collection_root(records: &[ValidatorRotationPlan]) -> String {
    consensus_hardening_value_collection_root(
        "CONSENSUS-HARDENING-VALIDATOR-ROTATIONS",
        &records
            .iter()
            .map(ValidatorRotationPlan::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn consensus_finality_window_collection_root(records: &[FinalitySafetyWindow]) -> String {
    consensus_hardening_value_collection_root(
        "CONSENSUS-HARDENING-FINALITY-WINDOWS",
        &records
            .iter()
            .map(FinalitySafetyWindow::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn consensus_low_fee_window_collection_root(records: &[LowFeeSafetyWindow]) -> String {
    consensus_hardening_value_collection_root(
        "CONSENSUS-HARDENING-LOW-FEE-WINDOWS",
        &records
            .iter()
            .map(LowFeeSafetyWindow::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn consensus_pq_attestation_collection_root(records: &[PqConsensusAttestation]) -> String {
    consensus_hardening_value_collection_root(
        "CONSENSUS-HARDENING-PQ-ATTESTATIONS",
        &records
            .iter()
            .map(PqConsensusAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

fn ensure_non_empty(label: &str, value: &str) -> ConsensusHardeningResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> ConsensusHardeningResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> ConsensusHardeningResult<()> {
    if value > CONSENSUS_HARDENING_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> ConsensusHardeningResult<()> {
    if end < start {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> ConsensusHardeningResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
