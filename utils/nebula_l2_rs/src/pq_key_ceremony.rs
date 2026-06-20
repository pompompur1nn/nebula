use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqKeyCeremonyResult<T> = Result<T, String>;

pub const PQ_KEY_CEREMONY_PROTOCOL_VERSION: &str = "nebula-pq-key-ceremony-v1";
pub const PQ_KEY_CEREMONY_SECURITY_MODEL: &str = "deterministic-devnet-records-not-real-crypto";
pub const PQ_KEY_CEREMONY_COMMITMENT_SCHEME: &str = "shake256-domain-separated-canonical-json";
pub const PQ_KEY_CEREMONY_DEVNET_HEIGHT: u64 = 264;
pub const PQ_KEY_CEREMONY_DEFAULT_NOTICE_BLOCKS: u64 = 720;
pub const PQ_KEY_CEREMONY_DEFAULT_OVERLAP_BLOCKS: u64 = 144;
pub const PQ_KEY_CEREMONY_DEFAULT_ENROLLMENT_TTL_BLOCKS: u64 = 2_880;
pub const PQ_KEY_CEREMONY_DEFAULT_REVOCATION_TTL_BLOCKS: u64 = 8_640;
pub const PQ_KEY_CEREMONY_DEFAULT_FREEZE_TTL_BLOCKS: u64 = 720;
pub const PQ_KEY_CEREMONY_DEFAULT_LOW_FEE_REKEY_REBATE_BPS: u64 = 9_500;
pub const PQ_KEY_CEREMONY_DEFAULT_MAX_SPONSOR_BUDGET_UNITS: u64 = 500_000;
pub const PQ_KEY_CEREMONY_DEFAULT_MIN_THRESHOLD_WEIGHT_BPS: u64 = 6_700;
pub const PQ_KEY_CEREMONY_DEFAULT_EMERGENCY_QUORUM: u64 = 3;
pub const PQ_KEY_CEREMONY_DEFAULT_RESERVE_SIGNER_QUORUM: u64 = 2;
pub const PQ_KEY_CEREMONY_MAX_BPS: u64 = 10_000;
pub const PQ_KEY_CEREMONY_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_KEY_CEREMONY_DEVNET_RESERVE_ASSET_ID: &str = "xmr-reserve-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqKeyCohortKind {
    Validator,
    Operator,
    Bridge,
    Wallet,
    MoneroReserveSigner,
}

impl PqKeyCohortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::Operator => "operator",
            Self::Bridge => "bridge",
            Self::Wallet => "wallet",
            Self::MoneroReserveSigner => "monero_reserve_signer",
        }
    }

    pub fn requires_threshold(self) -> bool {
        matches!(
            self,
            Self::Validator | Self::Bridge | Self::MoneroReserveSigner
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCeremonyAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    Kyber768,
    Kyber1024,
    HybridMlDsa65Ed25519,
    HybridKyber1024X25519,
    MoneroReserveMultisig,
    ClassicalFallbackEd25519,
}

impl PqCeremonyAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::Kyber768 => "Kyber-768",
            Self::Kyber1024 => "Kyber-1024",
            Self::HybridMlDsa65Ed25519 => "ML-DSA-65+Ed25519",
            Self::HybridKyber1024X25519 => "Kyber-1024+X25519",
            Self::MoneroReserveMultisig => "monero-reserve-multisig",
            Self::ClassicalFallbackEd25519 => "fallback-ed25519",
        }
    }

    pub fn family(self) -> &'static str {
        match self {
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 | Self::HybridMlDsa65Ed25519 => "ml_dsa",
            Self::Kyber768 | Self::Kyber1024 | Self::HybridKyber1024X25519 => "kyber_kem",
            Self::MoneroReserveMultisig => "monero_reserve",
            Self::ClassicalFallbackEd25519 => "classical_fallback",
        }
    }

    pub fn is_post_quantum(self) -> bool {
        !matches!(self, Self::ClassicalFallbackEd25519)
    }

    pub fn is_signature(self) -> bool {
        matches!(
            self,
            Self::MlDsa44
                | Self::MlDsa65
                | Self::MlDsa87
                | Self::HybridMlDsa65Ed25519
                | Self::ClassicalFallbackEd25519
                | Self::MoneroReserveMultisig
        )
    }

    pub fn is_kem(self) -> bool {
        matches!(
            self,
            Self::Kyber768 | Self::Kyber1024 | Self::HybridKyber1024X25519
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAlgorithmReadinessStatus {
    Proposed,
    DevnetReady,
    AuditReady,
    Active,
    Deprecated,
    Revoked,
}

impl PqAlgorithmReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::DevnetReady => "devnet_ready",
            Self::AuditReady => "audit_ready",
            Self::Active => "active",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::DevnetReady | Self::AuditReady | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqKeyCohortStatus {
    Draft,
    Active,
    Rotating,
    Overlap,
    Frozen,
    Retired,
    Revoked,
}

impl PqKeyCohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Overlap => "overlap",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepts_signatures(self) -> bool {
        matches!(self, Self::Active | Self::Rotating | Self::Overlap)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRotationStage {
    Announced,
    EnrollmentOpen,
    ThresholdMet,
    Activating,
    Overlap,
    Complete,
    Cancelled,
    Failed,
}

impl PqRotationStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::EnrollmentOpen => "enrollment_open",
            Self::ThresholdMet => "threshold_met",
            Self::Activating => "activating",
            Self::Overlap => "overlap",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::EnrollmentOpen
                | Self::ThresholdMet
                | Self::Activating
                | Self::Overlap
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqEnrollmentStatus {
    Pending,
    Enrolled,
    Challenged,
    Revoked,
    Expired,
}

impl PqEnrollmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Enrolled => "enrolled",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Enrolled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRevocationEvidenceKind {
    KeyCompromise,
    DoubleSign,
    WeakRandomness,
    ExpiredAttestation,
    MoneroReserveMismatch,
    OperatorExit,
    GovernanceOrder,
}

impl PqRevocationEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyCompromise => "key_compromise",
            Self::DoubleSign => "double_sign",
            Self::WeakRandomness => "weak_randomness",
            Self::ExpiredAttestation => "expired_attestation",
            Self::MoneroReserveMismatch => "monero_reserve_mismatch",
            Self::OperatorExit => "operator_exit",
            Self::GovernanceOrder => "governance_order",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFallbackMode {
    Disabled,
    ObserveOnly,
    HybridRequired,
    ClassicalGrace,
    EmergencyOnly,
}

impl PqFallbackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ObserveOnly => "observe_only",
            Self::HybridRequired => "hybrid_required",
            Self::ClassicalGrace => "classical_grace",
            Self::EmergencyOnly => "emergency_only",
        }
    }

    pub fn allows_classical(self) -> bool {
        matches!(self, Self::ClassicalGrace | Self::EmergencyOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFreezeStatus {
    Proposed,
    Active,
    Resolved,
    Expired,
    Rejected,
}

impl PqFreezeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqLowFeeLaneStatus {
    Open,
    Paused,
    Exhausted,
    Closed,
}

impl PqLowFeeLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_rekeys(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroReserveCeremonyStatus {
    Draft,
    CollectingShares,
    ThresholdMet,
    Published,
    Rotating,
    Retired,
    Revoked,
}

impl MoneroReserveCeremonyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::CollectingShares => "collecting_shares",
            Self::ThresholdMet => "threshold_met",
            Self::Published => "published",
            Self::Rotating => "rotating",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::ThresholdMet | Self::Published | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqPublicRecordKind {
    AlgorithmReadiness,
    Cohort,
    Rotation,
    Enrollment,
    Revocation,
    FallbackPolicy,
    EmergencyFreeze,
    SponsoredRekeyLane,
    MoneroReserveCeremony,
}

impl PqPublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlgorithmReadiness => "algorithm_readiness",
            Self::Cohort => "cohort",
            Self::Rotation => "rotation",
            Self::Enrollment => "enrollment",
            Self::Revocation => "revocation",
            Self::FallbackPolicy => "fallback_policy",
            Self::EmergencyFreeze => "emergency_freeze",
            Self::SponsoredRekeyLane => "sponsored_rekey_lane",
            Self::MoneroReserveCeremony => "monero_reserve_ceremony",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeyCeremonyConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub operator_label: String,
    pub notice_blocks: u64,
    pub overlap_blocks: u64,
    pub enrollment_ttl_blocks: u64,
    pub revocation_ttl_blocks: u64,
    pub freeze_ttl_blocks: u64,
    pub low_fee_rekey_rebate_bps: u64,
    pub max_sponsor_budget_units: u64,
    pub min_threshold_weight_bps: u64,
    pub emergency_quorum: u64,
    pub reserve_signer_quorum: u64,
    pub fee_asset_id: String,
    pub reserve_asset_id: String,
}

impl PqKeyCeremonyConfig {
    pub fn devnet(operator_label: impl Into<String>) -> Self {
        Self {
            protocol_version: PQ_KEY_CEREMONY_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            operator_label: operator_label.into(),
            notice_blocks: PQ_KEY_CEREMONY_DEFAULT_NOTICE_BLOCKS,
            overlap_blocks: PQ_KEY_CEREMONY_DEFAULT_OVERLAP_BLOCKS,
            enrollment_ttl_blocks: PQ_KEY_CEREMONY_DEFAULT_ENROLLMENT_TTL_BLOCKS,
            revocation_ttl_blocks: PQ_KEY_CEREMONY_DEFAULT_REVOCATION_TTL_BLOCKS,
            freeze_ttl_blocks: PQ_KEY_CEREMONY_DEFAULT_FREEZE_TTL_BLOCKS,
            low_fee_rekey_rebate_bps: PQ_KEY_CEREMONY_DEFAULT_LOW_FEE_REKEY_REBATE_BPS,
            max_sponsor_budget_units: PQ_KEY_CEREMONY_DEFAULT_MAX_SPONSOR_BUDGET_UNITS,
            min_threshold_weight_bps: PQ_KEY_CEREMONY_DEFAULT_MIN_THRESHOLD_WEIGHT_BPS,
            emergency_quorum: PQ_KEY_CEREMONY_DEFAULT_EMERGENCY_QUORUM,
            reserve_signer_quorum: PQ_KEY_CEREMONY_DEFAULT_RESERVE_SIGNER_QUORUM,
            fee_asset_id: PQ_KEY_CEREMONY_DEVNET_FEE_ASSET_ID.to_string(),
            reserve_asset_id: PQ_KEY_CEREMONY_DEVNET_RESERVE_ASSET_ID.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_key_ceremony_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "operator_label": self.operator_label,
            "notice_blocks": self.notice_blocks,
            "overlap_blocks": self.overlap_blocks,
            "enrollment_ttl_blocks": self.enrollment_ttl_blocks,
            "revocation_ttl_blocks": self.revocation_ttl_blocks,
            "freeze_ttl_blocks": self.freeze_ttl_blocks,
            "low_fee_rekey_rebate_bps": self.low_fee_rekey_rebate_bps,
            "max_sponsor_budget_units": self.max_sponsor_budget_units,
            "min_threshold_weight_bps": self.min_threshold_weight_bps,
            "emergency_quorum": self.emergency_quorum,
            "reserve_signer_quorum": self.reserve_signer_quorum,
            "fee_asset_id": self.fee_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
        })
    }

    pub fn config_root(&self) -> String {
        pq_key_ceremony_payload_root("PQ-KEY-CEREMONY-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("config protocol version", &self.protocol_version)?;
        require_non_empty("config chain id", &self.chain_id)?;
        require_non_empty("config operator label", &self.operator_label)?;
        require_non_empty("config fee asset id", &self.fee_asset_id)?;
        require_non_empty("config reserve asset id", &self.reserve_asset_id)?;
        require_bps("low fee rekey rebate", self.low_fee_rekey_rebate_bps)?;
        require_bps("minimum threshold weight", self.min_threshold_weight_bps)?;
        if self.notice_blocks == 0 {
            return Err("notice blocks must be non-zero".to_string());
        }
        if self.overlap_blocks == 0 {
            return Err("overlap blocks must be non-zero".to_string());
        }
        if self.enrollment_ttl_blocks <= self.notice_blocks {
            return Err("enrollment ttl must exceed notice blocks".to_string());
        }
        if self.emergency_quorum == 0 {
            return Err("emergency quorum must be non-zero".to_string());
        }
        if self.reserve_signer_quorum == 0 {
            return Err("reserve signer quorum must be non-zero".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAlgorithmReadiness {
    pub algorithm_id: String,
    pub algorithm: PqCeremonyAlgorithm,
    pub status: PqAlgorithmReadinessStatus,
    pub readiness_level: u8,
    pub implementation_root: String,
    pub test_vector_root: String,
    pub audit_root: String,
    pub approved_for: Vec<PqKeyCohortKind>,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl PqAlgorithmReadiness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        algorithm: PqCeremonyAlgorithm,
        status: PqAlgorithmReadinessStatus,
        readiness_level: u8,
        implementation: &Value,
        test_vectors: &Value,
        audits: &Value,
        approved_for: Vec<PqKeyCohortKind>,
        activated_at_height: u64,
        expires_at_height: u64,
    ) -> PqKeyCeremonyResult<Self> {
        if readiness_level > 5 {
            return Err("algorithm readiness level cannot exceed five".to_string());
        }
        if expires_at_height <= activated_at_height {
            return Err("algorithm readiness expiry must follow activation".to_string());
        }
        let implementation_root =
            pq_key_ceremony_payload_root("PQ-ALGORITHM-IMPLEMENTATION", implementation);
        let test_vector_root =
            pq_key_ceremony_payload_root("PQ-ALGORITHM-TEST-VECTORS", test_vectors);
        let audit_root = pq_key_ceremony_payload_root("PQ-ALGORITHM-AUDITS", audits);
        let algorithm_id = pq_algorithm_id(
            algorithm,
            &implementation_root,
            &test_vector_root,
            activated_at_height,
        );
        let record = Self {
            algorithm_id,
            algorithm,
            status,
            readiness_level,
            implementation_root,
            test_vector_root,
            audit_root,
            approved_for,
            activated_at_height,
            expires_at_height,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn usable_at(&self, height: u64) -> bool {
        self.status.usable()
            && self.activated_at_height <= height
            && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_algorithm_readiness",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "algorithm_id": self.algorithm_id,
            "algorithm": self.algorithm.as_str(),
            "family": self.algorithm.family(),
            "status": self.status.as_str(),
            "readiness_level": self.readiness_level,
            "implementation_root": self.implementation_root,
            "test_vector_root": self.test_vector_root,
            "audit_root": self.audit_root,
            "approved_for": self.approved_for.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "post_quantum": self.algorithm.is_post_quantum(),
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("algorithm id", &self.algorithm_id)?;
        require_non_empty("algorithm implementation root", &self.implementation_root)?;
        require_non_empty("algorithm test vector root", &self.test_vector_root)?;
        require_non_empty("algorithm audit root", &self.audit_root)?;
        if self.readiness_level > 5 {
            return Err("algorithm readiness level cannot exceed five".to_string());
        }
        if self.expires_at_height <= self.activated_at_height {
            return Err("algorithm readiness expiry must follow activation".to_string());
        }
        let expected = pq_algorithm_id(
            self.algorithm,
            &self.implementation_root,
            &self.test_vector_root,
            self.activated_at_height,
        );
        if self.algorithm_id != expected {
            return Err("pq algorithm id mismatch".to_string());
        }
        Ok(self.algorithm_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeyCohort {
    pub cohort_id: String,
    pub kind: PqKeyCohortKind,
    pub label: String,
    pub status: PqKeyCohortStatus,
    pub current_key_root: String,
    pub pending_key_root: Option<String>,
    pub algorithm_ids: Vec<String>,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub overlap_ends_at_height: Option<u64>,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl PqKeyCohort {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: PqKeyCohortKind,
        label: &str,
        status: PqKeyCohortStatus,
        current_keys: &Value,
        pending_key_root: Option<String>,
        algorithm_ids: Vec<String>,
        threshold_weight: u64,
        total_weight: u64,
        created_at_height: u64,
    ) -> PqKeyCeremonyResult<Self> {
        require_non_empty("cohort label", label)?;
        if kind.requires_threshold() && threshold_weight == 0 {
            return Err("threshold cohort requires non-zero threshold weight".to_string());
        }
        if threshold_weight > total_weight {
            return Err("cohort threshold cannot exceed total weight".to_string());
        }
        let current_key_root = pq_key_ceremony_payload_root("PQ-COHORT-CURRENT-KEYS", current_keys);
        let cohort_id = pq_cohort_id(kind, label, &current_key_root, created_at_height);
        let cohort = Self {
            cohort_id,
            kind,
            label: label.to_string(),
            status,
            current_key_root,
            pending_key_root,
            algorithm_ids,
            threshold_weight,
            total_weight,
            overlap_ends_at_height: None,
            created_at_height,
            updated_at_height: created_at_height,
        };
        cohort.validate()?;
        Ok(cohort)
    }

    pub fn threshold_bps(&self) -> u64 {
        if self.total_weight == 0 {
            0
        } else {
            self.threshold_weight
                .saturating_mul(PQ_KEY_CEREMONY_MAX_BPS)
                / self.total_weight
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_key_cohort",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "cohort_id": self.cohort_id,
            "cohort_kind": self.kind.as_str(),
            "label": self.label,
            "status": self.status.as_str(),
            "current_key_root": self.current_key_root,
            "pending_key_root": self.pending_key_root,
            "algorithm_ids": self.algorithm_ids,
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "threshold_bps": self.threshold_bps(),
            "overlap_ends_at_height": self.overlap_ends_at_height,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("cohort id", &self.cohort_id)?;
        require_non_empty("cohort label", &self.label)?;
        require_non_empty("cohort current key root", &self.current_key_root)?;
        require_unique_strings("cohort algorithms", &self.algorithm_ids)?;
        if self.kind.requires_threshold() && self.threshold_weight == 0 {
            return Err("threshold cohort requires non-zero threshold weight".to_string());
        }
        if self.threshold_weight > self.total_weight {
            return Err("cohort threshold cannot exceed total weight".to_string());
        }
        if self.updated_at_height < self.created_at_height {
            return Err("cohort update height cannot precede creation".to_string());
        }
        let expected = pq_cohort_id(
            self.kind,
            &self.label,
            &self.current_key_root,
            self.created_at_height,
        );
        if self.cohort_id != expected {
            return Err("pq cohort id mismatch".to_string());
        }
        Ok(self.cohort_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqStagedRotation {
    pub rotation_id: String,
    pub cohort_id: String,
    pub from_key_root: String,
    pub to_key_root: String,
    pub stage: PqRotationStage,
    pub announcement_root: String,
    pub overlap_window_root: String,
    pub threshold_requirement_bps: u64,
    pub announced_at_height: u64,
    pub enrollment_opens_at_height: u64,
    pub activates_at_height: u64,
    pub overlap_ends_at_height: u64,
    pub completed_at_height: Option<u64>,
}

impl PqStagedRotation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cohort_id: &str,
        from_key_root: &str,
        to_keys: &Value,
        announcement: &Value,
        threshold_requirement_bps: u64,
        announced_at_height: u64,
        notice_blocks: u64,
        overlap_blocks: u64,
    ) -> PqKeyCeremonyResult<Self> {
        require_non_empty("rotation cohort id", cohort_id)?;
        require_non_empty("rotation source key root", from_key_root)?;
        require_bps("rotation threshold requirement", threshold_requirement_bps)?;
        if to_keys.is_null() {
            return Err("rotation target keys cannot be null".to_string());
        }
        let to_key_root = pq_key_ceremony_payload_root("PQ-ROTATION-TARGET-KEYS", to_keys);
        if from_key_root == to_key_root {
            return Err("rotation source and target key roots must differ".to_string());
        }
        let announcement_root =
            pq_key_ceremony_payload_root("PQ-ROTATION-ANNOUNCEMENT", announcement);
        let enrollment_opens_at_height = announced_at_height.saturating_add(notice_blocks / 2);
        let activates_at_height = announced_at_height.saturating_add(notice_blocks);
        let overlap_ends_at_height = activates_at_height.saturating_add(overlap_blocks);
        let overlap_window_root =
            pq_overlap_window_root(activates_at_height, overlap_ends_at_height);
        let rotation_id = pq_rotation_id(
            cohort_id,
            from_key_root,
            &to_key_root,
            &announcement_root,
            announced_at_height,
        );
        let rotation = Self {
            rotation_id,
            cohort_id: cohort_id.to_string(),
            from_key_root: from_key_root.to_string(),
            to_key_root,
            stage: PqRotationStage::Announced,
            announcement_root,
            overlap_window_root,
            threshold_requirement_bps,
            announced_at_height,
            enrollment_opens_at_height,
            activates_at_height,
            overlap_ends_at_height,
            completed_at_height: None,
        };
        rotation.validate()?;
        Ok(rotation)
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.stage,
            PqRotationStage::Cancelled | PqRotationStage::Failed | PqRotationStage::Complete
        ) {
            return;
        }
        self.stage = if height >= self.overlap_ends_at_height {
            self.completed_at_height = Some(height);
            PqRotationStage::Complete
        } else if height >= self.activates_at_height {
            PqRotationStage::Overlap
        } else if matches!(self.stage, PqRotationStage::ThresholdMet) {
            PqRotationStage::ThresholdMet
        } else if height >= self.enrollment_opens_at_height {
            PqRotationStage::EnrollmentOpen
        } else {
            PqRotationStage::Announced
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_staged_rotation",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "rotation_id": self.rotation_id,
            "cohort_id": self.cohort_id,
            "from_key_root": self.from_key_root,
            "to_key_root": self.to_key_root,
            "stage": self.stage.as_str(),
            "announcement_root": self.announcement_root,
            "overlap_window_root": self.overlap_window_root,
            "threshold_requirement_bps": self.threshold_requirement_bps,
            "announced_at_height": self.announced_at_height,
            "enrollment_opens_at_height": self.enrollment_opens_at_height,
            "activates_at_height": self.activates_at_height,
            "overlap_ends_at_height": self.overlap_ends_at_height,
            "completed_at_height": self.completed_at_height,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("rotation id", &self.rotation_id)?;
        require_non_empty("rotation cohort id", &self.cohort_id)?;
        require_non_empty("rotation source key root", &self.from_key_root)?;
        require_non_empty("rotation target key root", &self.to_key_root)?;
        require_non_empty("rotation announcement root", &self.announcement_root)?;
        require_non_empty("rotation overlap root", &self.overlap_window_root)?;
        require_bps(
            "rotation threshold requirement",
            self.threshold_requirement_bps,
        )?;
        if self.from_key_root == self.to_key_root {
            return Err("rotation source and target key roots must differ".to_string());
        }
        if self.enrollment_opens_at_height < self.announced_at_height {
            return Err("rotation enrollment cannot precede announcement".to_string());
        }
        if self.activates_at_height <= self.announced_at_height {
            return Err("rotation activation must follow announcement".to_string());
        }
        if self.overlap_ends_at_height <= self.activates_at_height {
            return Err("rotation overlap must outlive activation".to_string());
        }
        if let Some(completed_at_height) = self.completed_at_height {
            if completed_at_height < self.activates_at_height {
                return Err("rotation completion cannot precede activation".to_string());
            }
        }
        let expected = pq_rotation_id(
            &self.cohort_id,
            &self.from_key_root,
            &self.to_key_root,
            &self.announcement_root,
            self.announced_at_height,
        );
        if self.rotation_id != expected {
            return Err("pq rotation id mismatch".to_string());
        }
        Ok(self.rotation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqThresholdSignerEnrollment {
    pub enrollment_id: String,
    pub cohort_id: String,
    pub rotation_id: Option<String>,
    pub signer_label: String,
    pub signer_key_root: String,
    pub algorithm_id: String,
    pub weight: u64,
    pub status: PqEnrollmentStatus,
    pub proof_root: String,
    pub enrolled_at_height: u64,
    pub expires_at_height: u64,
}

impl PqThresholdSignerEnrollment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cohort_id: &str,
        rotation_id: Option<String>,
        signer_label: &str,
        signer_keys: &Value,
        algorithm_id: &str,
        weight: u64,
        proof: &Value,
        enrolled_at_height: u64,
        expires_at_height: u64,
    ) -> PqKeyCeremonyResult<Self> {
        require_non_empty("enrollment cohort id", cohort_id)?;
        require_non_empty("enrollment signer label", signer_label)?;
        require_non_empty("enrollment algorithm id", algorithm_id)?;
        if weight == 0 {
            return Err("enrollment signer weight must be non-zero".to_string());
        }
        if expires_at_height <= enrolled_at_height {
            return Err("enrollment expiry must follow enrollment".to_string());
        }
        let signer_key_root = pq_key_ceremony_payload_root("PQ-SIGNER-KEYS", signer_keys);
        let proof_root = pq_key_ceremony_payload_root("PQ-SIGNER-ENROLLMENT-PROOF", proof);
        let enrollment_id = pq_enrollment_id(
            cohort_id,
            rotation_id.as_deref(),
            signer_label,
            &signer_key_root,
            &proof_root,
            enrolled_at_height,
        );
        let enrollment = Self {
            enrollment_id,
            cohort_id: cohort_id.to_string(),
            rotation_id,
            signer_label: signer_label.to_string(),
            signer_key_root,
            algorithm_id: algorithm_id.to_string(),
            weight,
            status: PqEnrollmentStatus::Enrolled,
            proof_root,
            enrolled_at_height,
            expires_at_height,
        };
        enrollment.validate()?;
        Ok(enrollment)
    }

    pub fn live_at(&self, height: u64) -> bool {
        self.status.usable() && self.enrolled_at_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_threshold_signer_enrollment",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "enrollment_id": self.enrollment_id,
            "cohort_id": self.cohort_id,
            "rotation_id": self.rotation_id,
            "signer_label": self.signer_label,
            "signer_key_root": self.signer_key_root,
            "algorithm_id": self.algorithm_id,
            "weight": self.weight,
            "status": self.status.as_str(),
            "proof_root": self.proof_root,
            "enrolled_at_height": self.enrolled_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("enrollment id", &self.enrollment_id)?;
        require_non_empty("enrollment cohort id", &self.cohort_id)?;
        require_non_empty("enrollment signer label", &self.signer_label)?;
        require_non_empty("enrollment signer key root", &self.signer_key_root)?;
        require_non_empty("enrollment algorithm id", &self.algorithm_id)?;
        require_non_empty("enrollment proof root", &self.proof_root)?;
        if weight_is_zero(self.weight) {
            return Err("enrollment signer weight must be non-zero".to_string());
        }
        if self.expires_at_height <= self.enrolled_at_height {
            return Err("enrollment expiry must follow enrollment".to_string());
        }
        let expected = pq_enrollment_id(
            &self.cohort_id,
            self.rotation_id.as_deref(),
            &self.signer_label,
            &self.signer_key_root,
            &self.proof_root,
            self.enrolled_at_height,
        );
        if self.enrollment_id != expected {
            return Err("pq enrollment id mismatch".to_string());
        }
        Ok(self.enrollment_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRevocationEvidence {
    pub revocation_id: String,
    pub subject_id: String,
    pub cohort_id: String,
    pub evidence_kind: PqRevocationEvidenceKind,
    pub evidence_root: String,
    pub reporter_label: String,
    pub slashing_root: String,
    pub reported_at_height: u64,
    pub expires_at_height: u64,
}

impl PqRevocationEvidence {
    pub fn new(
        subject_id: &str,
        cohort_id: &str,
        evidence_kind: PqRevocationEvidenceKind,
        evidence: &Value,
        reporter_label: &str,
        slashing: &Value,
        reported_at_height: u64,
        expires_at_height: u64,
    ) -> PqKeyCeremonyResult<Self> {
        require_non_empty("revocation subject id", subject_id)?;
        require_non_empty("revocation cohort id", cohort_id)?;
        require_non_empty("revocation reporter label", reporter_label)?;
        if expires_at_height <= reported_at_height {
            return Err("revocation expiry must follow report height".to_string());
        }
        let evidence_root = pq_key_ceremony_payload_root("PQ-REVOCATION-EVIDENCE", evidence);
        let slashing_root = pq_key_ceremony_payload_root("PQ-REVOCATION-SLASHING", slashing);
        let revocation_id = pq_revocation_id(
            subject_id,
            cohort_id,
            evidence_kind,
            &evidence_root,
            reporter_label,
            reported_at_height,
        );
        let revocation = Self {
            revocation_id,
            subject_id: subject_id.to_string(),
            cohort_id: cohort_id.to_string(),
            evidence_kind,
            evidence_root,
            reporter_label: reporter_label.to_string(),
            slashing_root,
            reported_at_height,
            expires_at_height,
        };
        revocation.validate()?;
        Ok(revocation)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.reported_at_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_revocation_evidence",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "revocation_id": self.revocation_id,
            "subject_id": self.subject_id,
            "cohort_id": self.cohort_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "evidence_root": self.evidence_root,
            "reporter_label": self.reporter_label,
            "slashing_root": self.slashing_root,
            "reported_at_height": self.reported_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("revocation id", &self.revocation_id)?;
        require_non_empty("revocation subject id", &self.subject_id)?;
        require_non_empty("revocation cohort id", &self.cohort_id)?;
        require_non_empty("revocation evidence root", &self.evidence_root)?;
        require_non_empty("revocation reporter label", &self.reporter_label)?;
        require_non_empty("revocation slashing root", &self.slashing_root)?;
        if self.expires_at_height <= self.reported_at_height {
            return Err("revocation expiry must follow report height".to_string());
        }
        let expected = pq_revocation_id(
            &self.subject_id,
            &self.cohort_id,
            self.evidence_kind,
            &self.evidence_root,
            &self.reporter_label,
            self.reported_at_height,
        );
        if self.revocation_id != expected {
            return Err("pq revocation id mismatch".to_string());
        }
        Ok(self.revocation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFallbackPolicy {
    pub policy_id: String,
    pub cohort_kind: PqKeyCohortKind,
    pub mode: PqFallbackMode,
    pub primary_algorithm_id: String,
    pub fallback_algorithm_id: String,
    pub guardrail_root: String,
    pub max_fallback_blocks: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl PqFallbackPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cohort_kind: PqKeyCohortKind,
        mode: PqFallbackMode,
        primary_algorithm_id: &str,
        fallback_algorithm_id: &str,
        guardrails: &Value,
        max_fallback_blocks: u64,
        activated_at_height: u64,
        expires_at_height: u64,
    ) -> PqKeyCeremonyResult<Self> {
        require_non_empty("fallback primary algorithm", primary_algorithm_id)?;
        require_non_empty("fallback algorithm", fallback_algorithm_id)?;
        if primary_algorithm_id == fallback_algorithm_id {
            return Err("fallback primary and fallback algorithms must differ".to_string());
        }
        if max_fallback_blocks == 0 {
            return Err("fallback max blocks must be non-zero".to_string());
        }
        if expires_at_height <= activated_at_height {
            return Err("fallback policy expiry must follow activation".to_string());
        }
        let guardrail_root = pq_key_ceremony_payload_root("PQ-FALLBACK-GUARDRAILS", guardrails);
        let policy_id = pq_fallback_policy_id(
            cohort_kind,
            mode,
            primary_algorithm_id,
            fallback_algorithm_id,
            &guardrail_root,
            activated_at_height,
        );
        let policy = Self {
            policy_id,
            cohort_kind,
            mode,
            primary_algorithm_id: primary_algorithm_id.to_string(),
            fallback_algorithm_id: fallback_algorithm_id.to_string(),
            guardrail_root,
            max_fallback_blocks,
            activated_at_height,
            expires_at_height,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.activated_at_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fallback_policy",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "policy_id": self.policy_id,
            "cohort_kind": self.cohort_kind.as_str(),
            "mode": self.mode.as_str(),
            "primary_algorithm_id": self.primary_algorithm_id,
            "fallback_algorithm_id": self.fallback_algorithm_id,
            "guardrail_root": self.guardrail_root,
            "allows_classical": self.mode.allows_classical(),
            "max_fallback_blocks": self.max_fallback_blocks,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("fallback policy id", &self.policy_id)?;
        require_non_empty("fallback primary algorithm", &self.primary_algorithm_id)?;
        require_non_empty("fallback algorithm", &self.fallback_algorithm_id)?;
        require_non_empty("fallback guardrail root", &self.guardrail_root)?;
        if self.primary_algorithm_id == self.fallback_algorithm_id {
            return Err("fallback primary and fallback algorithms must differ".to_string());
        }
        if self.max_fallback_blocks == 0 {
            return Err("fallback max blocks must be non-zero".to_string());
        }
        if self.expires_at_height <= self.activated_at_height {
            return Err("fallback policy expiry must follow activation".to_string());
        }
        let expected = pq_fallback_policy_id(
            self.cohort_kind,
            self.mode,
            &self.primary_algorithm_id,
            &self.fallback_algorithm_id,
            &self.guardrail_root,
            self.activated_at_height,
        );
        if self.policy_id != expected {
            return Err("pq fallback policy id mismatch".to_string());
        }
        Ok(self.policy_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqQuantumEmergencyFreeze {
    pub freeze_id: String,
    pub affected_cohort_ids: Vec<String>,
    pub status: PqFreezeStatus,
    pub reason_root: String,
    pub guardian_quorum: u64,
    pub attestation_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl PqQuantumEmergencyFreeze {
    pub fn new(
        affected_cohort_ids: Vec<String>,
        reason: &Value,
        guardian_quorum: u64,
        attestations: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> PqKeyCeremonyResult<Self> {
        if affected_cohort_ids.is_empty() {
            return Err("emergency freeze requires at least one affected cohort".to_string());
        }
        require_unique_strings("freeze affected cohorts", &affected_cohort_ids)?;
        if guardian_quorum == 0 {
            return Err("emergency freeze guardian quorum must be non-zero".to_string());
        }
        if expires_at_height <= opened_at_height {
            return Err("emergency freeze expiry must follow open height".to_string());
        }
        let reason_root = pq_key_ceremony_payload_root("PQ-EMERGENCY-FREEZE-REASON", reason);
        let attestation_root =
            pq_key_ceremony_payload_root("PQ-EMERGENCY-FREEZE-ATTESTATIONS", attestations);
        let freeze_id = pq_freeze_id(
            &affected_cohort_ids,
            &reason_root,
            &attestation_root,
            opened_at_height,
        );
        let freeze = Self {
            freeze_id,
            affected_cohort_ids,
            status: PqFreezeStatus::Active,
            reason_root,
            guardian_quorum,
            attestation_root,
            opened_at_height,
            expires_at_height,
            resolved_at_height: None,
        };
        freeze.validate()?;
        Ok(freeze)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == PqFreezeStatus::Active && height >= self.expires_at_height {
            self.status = PqFreezeStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_quantum_emergency_freeze",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "freeze_id": self.freeze_id,
            "affected_cohort_ids": self.affected_cohort_ids,
            "status": self.status.as_str(),
            "reason_root": self.reason_root,
            "guardian_quorum": self.guardian_quorum,
            "attestation_root": self.attestation_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("emergency freeze id", &self.freeze_id)?;
        if self.affected_cohort_ids.is_empty() {
            return Err("emergency freeze requires at least one affected cohort".to_string());
        }
        require_unique_strings("freeze affected cohorts", &self.affected_cohort_ids)?;
        require_non_empty("emergency freeze reason root", &self.reason_root)?;
        require_non_empty("emergency freeze attestation root", &self.attestation_root)?;
        if self.guardian_quorum == 0 {
            return Err("emergency freeze guardian quorum must be non-zero".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("emergency freeze expiry must follow open height".to_string());
        }
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err("emergency freeze resolution cannot precede open height".to_string());
            }
        }
        let expected = pq_freeze_id(
            &self.affected_cohort_ids,
            &self.reason_root,
            &self.attestation_root,
            self.opened_at_height,
        );
        if self.freeze_id != expected {
            return Err("pq emergency freeze id mismatch".to_string());
        }
        Ok(self.freeze_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLowFeeSponsoredRekeyLane {
    pub lane_id: String,
    pub sponsor_label: String,
    pub cohort_kind: PqKeyCohortKind,
    pub fee_asset_id: String,
    pub rebate_bps: u64,
    pub budget_units: u64,
    pub spent_units: u64,
    pub status: PqLowFeeLaneStatus,
    pub policy_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl PqLowFeeSponsoredRekeyLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        cohort_kind: PqKeyCohortKind,
        fee_asset_id: &str,
        rebate_bps: u64,
        budget_units: u64,
        policy: &Value,
        opened_at_height: u64,
        closes_at_height: u64,
    ) -> PqKeyCeremonyResult<Self> {
        require_non_empty("sponsor label", sponsor_label)?;
        require_non_empty("rekey lane fee asset id", fee_asset_id)?;
        require_bps("rekey lane rebate", rebate_bps)?;
        if budget_units == 0 {
            return Err("rekey lane budget must be non-zero".to_string());
        }
        if closes_at_height <= opened_at_height {
            return Err("rekey lane close height must follow open height".to_string());
        }
        let policy_root = pq_key_ceremony_payload_root("PQ-LOW-FEE-REKEY-LANE-POLICY", policy);
        let lane_id = pq_low_fee_lane_id(
            sponsor_label,
            cohort_kind,
            fee_asset_id,
            &policy_root,
            opened_at_height,
        );
        let lane = Self {
            lane_id,
            sponsor_label: sponsor_label.to_string(),
            cohort_kind,
            fee_asset_id: fee_asset_id.to_string(),
            rebate_bps,
            budget_units,
            spent_units: 0,
            status: PqLowFeeLaneStatus::Open,
            policy_root,
            opened_at_height,
            closes_at_height,
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn remaining_budget_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == PqLowFeeLaneStatus::Open && height >= self.closes_at_height {
            self.status = PqLowFeeLaneStatus::Closed;
        }
        if self.status == PqLowFeeLaneStatus::Open && self.spent_units >= self.budget_units {
            self.status = PqLowFeeLaneStatus::Exhausted;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_low_fee_sponsored_rekey_lane",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "sponsor_label": self.sponsor_label,
            "cohort_kind": self.cohort_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "rebate_bps": self.rebate_bps,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "remaining_budget_units": self.remaining_budget_units(),
            "status": self.status.as_str(),
            "policy_root": self.policy_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("rekey lane id", &self.lane_id)?;
        require_non_empty("sponsor label", &self.sponsor_label)?;
        require_non_empty("rekey lane fee asset id", &self.fee_asset_id)?;
        require_non_empty("rekey lane policy root", &self.policy_root)?;
        require_bps("rekey lane rebate", self.rebate_bps)?;
        if self.budget_units == 0 {
            return Err("rekey lane budget must be non-zero".to_string());
        }
        if self.spent_units > self.budget_units {
            return Err("rekey lane spent units cannot exceed budget".to_string());
        }
        if self.closes_at_height <= self.opened_at_height {
            return Err("rekey lane close height must follow open height".to_string());
        }
        let expected = pq_low_fee_lane_id(
            &self.sponsor_label,
            self.cohort_kind,
            &self.fee_asset_id,
            &self.policy_root,
            self.opened_at_height,
        );
        if self.lane_id != expected {
            return Err("pq low fee lane id mismatch".to_string());
        }
        Ok(self.lane_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReserveSignerCeremony {
    pub ceremony_id: String,
    pub reserve_asset_id: String,
    pub reserve_address_root: String,
    pub view_key_root: String,
    pub spend_key_share_root: String,
    pub signer_set_root: String,
    pub status: MoneroReserveCeremonyStatus,
    pub threshold: u64,
    pub signer_count: u64,
    pub opened_at_height: u64,
    pub published_at_height: Option<u64>,
}

impl MoneroReserveSignerCeremony {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reserve_asset_id: &str,
        reserve_addresses: &Value,
        view_keys: &Value,
        spend_key_shares: &Value,
        signer_set: &Value,
        threshold: u64,
        signer_count: u64,
        opened_at_height: u64,
    ) -> PqKeyCeremonyResult<Self> {
        require_non_empty("reserve asset id", reserve_asset_id)?;
        if threshold == 0 {
            return Err("reserve ceremony threshold must be non-zero".to_string());
        }
        if threshold > signer_count {
            return Err("reserve ceremony threshold cannot exceed signer count".to_string());
        }
        let reserve_address_root =
            pq_key_ceremony_payload_root("MONERO-RESERVE-ADDRESSES", reserve_addresses);
        let view_key_root = pq_key_ceremony_payload_root("MONERO-RESERVE-VIEW-KEYS", view_keys);
        let spend_key_share_root =
            pq_key_ceremony_payload_root("MONERO-RESERVE-SPEND-SHARES", spend_key_shares);
        let signer_set_root = pq_key_ceremony_payload_root("MONERO-RESERVE-SIGNER-SET", signer_set);
        let ceremony_id = pq_reserve_ceremony_id(
            reserve_asset_id,
            &reserve_address_root,
            &view_key_root,
            &signer_set_root,
            opened_at_height,
        );
        let ceremony = Self {
            ceremony_id,
            reserve_asset_id: reserve_asset_id.to_string(),
            reserve_address_root,
            view_key_root,
            spend_key_share_root,
            signer_set_root,
            status: MoneroReserveCeremonyStatus::CollectingShares,
            threshold,
            signer_count,
            opened_at_height,
            published_at_height: None,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_reserve_signer_ceremony",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "ceremony_id": self.ceremony_id,
            "reserve_asset_id": self.reserve_asset_id,
            "reserve_address_root": self.reserve_address_root,
            "view_key_root": self.view_key_root,
            "spend_key_share_root": self.spend_key_share_root,
            "signer_set_root": self.signer_set_root,
            "status": self.status.as_str(),
            "threshold": self.threshold,
            "signer_count": self.signer_count,
            "opened_at_height": self.opened_at_height,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("reserve ceremony id", &self.ceremony_id)?;
        require_non_empty("reserve asset id", &self.reserve_asset_id)?;
        require_non_empty("reserve address root", &self.reserve_address_root)?;
        require_non_empty("reserve view key root", &self.view_key_root)?;
        require_non_empty("reserve spend share root", &self.spend_key_share_root)?;
        require_non_empty("reserve signer set root", &self.signer_set_root)?;
        if self.threshold == 0 {
            return Err("reserve ceremony threshold must be non-zero".to_string());
        }
        if self.threshold > self.signer_count {
            return Err("reserve ceremony threshold cannot exceed signer count".to_string());
        }
        if let Some(published_at_height) = self.published_at_height {
            if published_at_height < self.opened_at_height {
                return Err("reserve ceremony publish cannot precede open height".to_string());
            }
        }
        let expected = pq_reserve_ceremony_id(
            &self.reserve_asset_id,
            &self.reserve_address_root,
            &self.view_key_root,
            &self.signer_set_root,
            self.opened_at_height,
        );
        if self.ceremony_id != expected {
            return Err("monero reserve ceremony id mismatch".to_string());
        }
        Ok(self.ceremony_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeyCeremonyPublicRecord {
    pub record_id: String,
    pub record_kind: PqPublicRecordKind,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl PqKeyCeremonyPublicRecord {
    pub fn new(
        record_kind: PqPublicRecordKind,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PqKeyCeremonyResult<Self> {
        require_non_empty("public record subject id", subject_id)?;
        let payload_root = pq_key_ceremony_payload_root("PQ-PUBLIC-RECORD-PAYLOAD", payload);
        let record_id = pq_public_record_id(
            record_kind,
            subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            record_kind,
            subject_id: subject_id.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_key_ceremony_public_record",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        require_non_empty("public record id", &self.record_id)?;
        require_non_empty("public record subject id", &self.subject_id)?;
        require_non_empty("public record payload root", &self.payload_root)?;
        let expected = pq_public_record_id(
            self.record_kind,
            &self.subject_id,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected {
            return Err("pq public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeyCeremonyRoots {
    pub config_root: String,
    pub algorithm_root: String,
    pub cohort_root: String,
    pub rotation_root: String,
    pub enrollment_root: String,
    pub revocation_root: String,
    pub fallback_policy_root: String,
    pub emergency_freeze_root: String,
    pub sponsored_rekey_lane_root: String,
    pub reserve_ceremony_root: String,
    pub public_record_root: String,
}

impl PqKeyCeremonyRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_key_ceremony_roots",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "algorithm_root": self.algorithm_root,
            "cohort_root": self.cohort_root,
            "rotation_root": self.rotation_root,
            "enrollment_root": self.enrollment_root,
            "revocation_root": self.revocation_root,
            "fallback_policy_root": self.fallback_policy_root,
            "emergency_freeze_root": self.emergency_freeze_root,
            "sponsored_rekey_lane_root": self.sponsored_rekey_lane_root,
            "reserve_ceremony_root": self.reserve_ceremony_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        pq_key_ceremony_payload_root("PQ-KEY-CEREMONY-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeyCeremonyCounters {
    pub algorithm_count: u64,
    pub usable_algorithm_count: u64,
    pub post_quantum_algorithm_count: u64,
    pub cohort_count: u64,
    pub active_cohort_count: u64,
    pub active_rotation_count: u64,
    pub threshold_met_rotation_count: u64,
    pub live_enrollment_count: u64,
    pub live_enrollment_weight: u64,
    pub revocation_count: u64,
    pub active_freeze_count: u64,
    pub fallback_policy_count: u64,
    pub sponsored_rekey_lane_count: u64,
    pub sponsored_rekey_remaining_budget_units: u64,
    pub reserve_ceremony_count: u64,
    pub public_record_count: u64,
}

impl PqKeyCeremonyCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_key_ceremony_counters",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "algorithm_count": self.algorithm_count,
            "usable_algorithm_count": self.usable_algorithm_count,
            "post_quantum_algorithm_count": self.post_quantum_algorithm_count,
            "cohort_count": self.cohort_count,
            "active_cohort_count": self.active_cohort_count,
            "active_rotation_count": self.active_rotation_count,
            "threshold_met_rotation_count": self.threshold_met_rotation_count,
            "live_enrollment_count": self.live_enrollment_count,
            "live_enrollment_weight": self.live_enrollment_weight,
            "revocation_count": self.revocation_count,
            "active_freeze_count": self.active_freeze_count,
            "fallback_policy_count": self.fallback_policy_count,
            "sponsored_rekey_lane_count": self.sponsored_rekey_lane_count,
            "sponsored_rekey_remaining_budget_units": self.sponsored_rekey_remaining_budget_units,
            "reserve_ceremony_count": self.reserve_ceremony_count,
            "public_record_count": self.public_record_count,
        })
    }

    pub fn counters_root(&self) -> String {
        pq_key_ceremony_payload_root("PQ-KEY-CEREMONY-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeyCeremonyState {
    pub config: PqKeyCeremonyConfig,
    pub height: u64,
    pub algorithms: BTreeMap<String, PqAlgorithmReadiness>,
    pub cohorts: BTreeMap<String, PqKeyCohort>,
    pub rotations: BTreeMap<String, PqStagedRotation>,
    pub enrollments: BTreeMap<String, PqThresholdSignerEnrollment>,
    pub revocations: BTreeMap<String, PqRevocationEvidence>,
    pub fallback_policies: BTreeMap<String, PqFallbackPolicy>,
    pub emergency_freezes: BTreeMap<String, PqQuantumEmergencyFreeze>,
    pub sponsored_rekey_lanes: BTreeMap<String, PqLowFeeSponsoredRekeyLane>,
    pub reserve_ceremonies: BTreeMap<String, MoneroReserveSignerCeremony>,
    pub public_records: BTreeMap<String, PqKeyCeremonyPublicRecord>,
}

impl PqKeyCeremonyState {
    pub fn devnet(operator_label: &str) -> PqKeyCeremonyResult<Self> {
        let config = PqKeyCeremonyConfig::devnet(operator_label);
        let height = PQ_KEY_CEREMONY_DEVNET_HEIGHT;
        let mut state = Self {
            config,
            height,
            algorithms: BTreeMap::new(),
            cohorts: BTreeMap::new(),
            rotations: BTreeMap::new(),
            enrollments: BTreeMap::new(),
            revocations: BTreeMap::new(),
            fallback_policies: BTreeMap::new(),
            emergency_freezes: BTreeMap::new(),
            sponsored_rekey_lanes: BTreeMap::new(),
            reserve_ceremonies: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };

        let ml_dsa = PqAlgorithmReadiness::new(
            PqCeremonyAlgorithm::MlDsa65,
            PqAlgorithmReadinessStatus::Active,
            4,
            &json!({"standard": "FIPS-204", "profile": "validator-operator-devnet"}),
            &json!({"vectors": "deterministic-devnet", "encoding": "canonical-json"}),
            &json!({"audit": "internal-devnet-readiness", "score_bps": 9200}),
            vec![
                PqKeyCohortKind::Validator,
                PqKeyCohortKind::Operator,
                PqKeyCohortKind::Wallet,
            ],
            height.saturating_sub(200),
            height.saturating_add(40_320),
        )?;
        let kyber = PqAlgorithmReadiness::new(
            PqCeremonyAlgorithm::Kyber1024,
            PqAlgorithmReadinessStatus::AuditReady,
            3,
            &json!({"standard": "ML-KEM-devnet-label", "profile": "bridge-envelopes"}),
            &json!({"vectors": "kyber-placeholder-devnet"}),
            &json!({"audit": "hybrid-kem-review", "score_bps": 8900}),
            vec![PqKeyCohortKind::Bridge, PqKeyCohortKind::Wallet],
            height.saturating_sub(144),
            height.saturating_add(20_160),
        )?;
        let reserve_algo = PqAlgorithmReadiness::new(
            PqCeremonyAlgorithm::MoneroReserveMultisig,
            PqAlgorithmReadinessStatus::DevnetReady,
            3,
            &json!({"scheme": "monero-multisig-reserve", "profile": "view-spend-share-rooted"}),
            &json!({"vectors": "reserve-share-root-devnet"}),
            &json!({"audit": "reserve-signer-dry-run", "score_bps": 8700}),
            vec![PqKeyCohortKind::MoneroReserveSigner],
            height.saturating_sub(72),
            height.saturating_add(20_160),
        )?;
        let fallback_algo = PqAlgorithmReadiness::new(
            PqCeremonyAlgorithm::ClassicalFallbackEd25519,
            PqAlgorithmReadinessStatus::Deprecated,
            1,
            &json!({"scheme": "ed25519", "purpose": "bounded-emergency-grace"}),
            &json!({"vectors": "legacy-devnet"}),
            &json!({"finding": "classical-only-not-quantum-safe"}),
            vec![PqKeyCohortKind::Operator],
            height.saturating_sub(10_080),
            height.saturating_add(1_440),
        )?;
        let ml_dsa_id = ml_dsa.algorithm_id.clone();
        let kyber_id = kyber.algorithm_id.clone();
        let reserve_algo_id = reserve_algo.algorithm_id.clone();
        let fallback_algo_id = fallback_algo.algorithm_id.clone();
        state.insert_algorithm(ml_dsa)?;
        state.insert_algorithm(kyber)?;
        state.insert_algorithm(reserve_algo)?;
        state.insert_algorithm(fallback_algo)?;

        let validator_cohort = PqKeyCohort::new(
            PqKeyCohortKind::Validator,
            "devnet-validator-pq-cohort",
            PqKeyCohortStatus::Rotating,
            &json!({"validators": ["validator-a", "validator-b", "validator-c"], "scheme": "ML-DSA-65"}),
            None,
            vec![ml_dsa_id.clone()],
            67,
            100,
            height.saturating_sub(100),
        )?;
        let bridge_cohort = PqKeyCohort::new(
            PqKeyCohortKind::Bridge,
            "devnet-bridge-pq-cohort",
            PqKeyCohortStatus::Active,
            &json!({"bridge_signers": ["bridge-a", "bridge-b", "bridge-c"], "sig": "ML-DSA-65", "kem": "Kyber-1024"}),
            None,
            vec![ml_dsa_id.clone(), kyber_id.clone()],
            67,
            100,
            height.saturating_sub(88),
        )?;
        let wallet_cohort = PqKeyCohort::new(
            PqKeyCohortKind::Wallet,
            "devnet-wallet-rekey-cohort",
            PqKeyCohortStatus::Active,
            &json!({"wallet_batch": "low-fee-rekey-alpha", "scheme": "ML-DSA-65+Kyber-1024"}),
            None,
            vec![ml_dsa_id.clone(), kyber_id.clone()],
            1,
            1,
            height.saturating_sub(32),
        )?;
        let reserve_cohort = PqKeyCohort::new(
            PqKeyCohortKind::MoneroReserveSigner,
            "devnet-monero-reserve-signers",
            PqKeyCohortStatus::Active,
            &json!({"reserve_signers": ["reserve-a", "reserve-b", "reserve-c"], "network": "monero-devnet"}),
            None,
            vec![reserve_algo_id.clone()],
            67,
            100,
            height.saturating_sub(72),
        )?;
        let validator_cohort_id = validator_cohort.cohort_id.clone();
        let validator_key_root = validator_cohort.current_key_root.clone();
        let bridge_cohort_id = bridge_cohort.cohort_id.clone();
        let wallet_cohort_id = wallet_cohort.cohort_id.clone();
        let reserve_cohort_id = reserve_cohort.cohort_id.clone();
        state.insert_cohort(validator_cohort)?;
        state.insert_cohort(bridge_cohort)?;
        state.insert_cohort(wallet_cohort)?;
        state.insert_cohort(reserve_cohort)?;

        let mut rotation = PqStagedRotation::new(
            &validator_cohort_id,
            &validator_key_root,
            &json!({"validators": ["validator-a2", "validator-b2", "validator-c2"], "scheme": "ML-DSA-65", "kyber_aux": true}),
            &json!({"notice": "validator-pq-key-rotation", "operator": operator_label}),
            state.config.min_threshold_weight_bps,
            height.saturating_sub(state.config.notice_blocks),
            state.config.notice_blocks,
            state.config.overlap_blocks,
        )?;
        rotation.stage = PqRotationStage::ThresholdMet;
        let rotation_id = rotation.rotation_id.clone();
        state.insert_rotation(rotation)?;

        for (idx, signer) in ["validator-a", "validator-b", "validator-c"]
            .iter()
            .enumerate()
        {
            let enrollment = PqThresholdSignerEnrollment::new(
                &validator_cohort_id,
                Some(rotation_id.clone()),
                signer,
                &json!({"signer": signer, "ml_dsa": format!("{signer}-mldsa65"), "kyber_aux": format!("{signer}-kyber1024")}),
                &ml_dsa_id,
                1,
                &json!({"proof": "devnet-possession", "index": idx}),
                height.saturating_sub(40).saturating_add(idx as u64),
                height.saturating_add(state.config.enrollment_ttl_blocks),
            )?;
            state.insert_enrollment(enrollment)?;
        }

        let revocation = PqRevocationEvidence::new(
            "operator-legacy-key",
            &bridge_cohort_id,
            PqRevocationEvidenceKind::ExpiredAttestation,
            &json!({"legacy_key": "operator-ed25519-2024", "reason": "post-quantum-cutover"}),
            operator_label,
            &json!({"slash": false, "action": "deprecate"}),
            height.saturating_sub(12),
            height.saturating_add(state.config.revocation_ttl_blocks),
        )?;
        state.insert_revocation(revocation)?;

        let fallback = PqFallbackPolicy::new(
            PqKeyCohortKind::Operator,
            PqFallbackMode::EmergencyOnly,
            &ml_dsa_id,
            &fallback_algo_id,
            &json!({"max_uses": 1, "requires_freeze": true, "post_facto_public_record": true}),
            state.config.overlap_blocks,
            height.saturating_sub(6),
            height.saturating_add(state.config.freeze_ttl_blocks),
        )?;
        state.insert_fallback_policy(fallback)?;

        let freeze = PqQuantumEmergencyFreeze::new(
            vec![bridge_cohort_id.clone()],
            &json!({"signal": "quantum-emergency-drill", "scope": "bridge-withdrawals"}),
            state.config.emergency_quorum,
            &json!({"guardians": ["guardian-a", "guardian-b", "guardian-c"], "threshold": 3}),
            height.saturating_sub(2),
            height.saturating_add(state.config.freeze_ttl_blocks),
        )?;
        state.insert_emergency_freeze(freeze)?;

        let lane = PqLowFeeSponsoredRekeyLane::new(
            operator_label,
            PqKeyCohortKind::Wallet,
            &state.config.fee_asset_id,
            state.config.low_fee_rekey_rebate_bps,
            state.config.max_sponsor_budget_units,
            &json!({"lane": "wallet-pq-rekeys", "eligibility": "kyber+mldsa-migration"}),
            height.saturating_sub(8),
            height.saturating_add(7_200),
        )?;
        state.insert_sponsored_rekey_lane(lane)?;

        let reserve = MoneroReserveSignerCeremony::new(
            &state.config.reserve_asset_id,
            &json!({"network": "monero-devnet", "address_commitments": ["reserve-address-a", "reserve-address-b"]}),
            &json!({"view_key_commitments": ["view-a", "view-b", "view-c"]}),
            &json!({"spend_share_commitments": ["share-a", "share-b", "share-c"]}),
            &json!({"cohort_id": reserve_cohort_id, "signers": ["reserve-a", "reserve-b", "reserve-c"]}),
            state.config.reserve_signer_quorum,
            3,
            height.saturating_sub(60),
        )?;
        state.insert_reserve_ceremony(reserve)?;

        let wallet_record = PqKeyCeremonyPublicRecord::new(
            PqPublicRecordKind::Cohort,
            &wallet_cohort_id,
            &json!({"cohort_id": wallet_cohort_id, "purpose": "sponsored-wallet-rekey-lane"}),
            height,
            0,
        )?;
        state.insert_public_record(wallet_record)?;

        state.set_height(height);
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for rotation in self.rotations.values_mut() {
            rotation.set_height(height);
        }
        for freeze in self.emergency_freezes.values_mut() {
            freeze.set_height(height);
        }
        for lane in self.sponsored_rekey_lanes.values_mut() {
            lane.set_height(height);
        }
        for enrollment in self.enrollments.values_mut() {
            if enrollment.status == PqEnrollmentStatus::Enrolled
                && height >= enrollment.expires_at_height
            {
                enrollment.status = PqEnrollmentStatus::Expired;
            }
        }
    }

    pub fn insert_algorithm(
        &mut self,
        algorithm: PqAlgorithmReadiness,
    ) -> PqKeyCeremonyResult<String> {
        let id = algorithm.validate()?;
        self.algorithms.insert(id.clone(), algorithm);
        Ok(id)
    }

    pub fn insert_cohort(&mut self, cohort: PqKeyCohort) -> PqKeyCeremonyResult<String> {
        let id = cohort.validate()?;
        self.cohorts.insert(id.clone(), cohort);
        Ok(id)
    }

    pub fn insert_rotation(&mut self, rotation: PqStagedRotation) -> PqKeyCeremonyResult<String> {
        let id = rotation.validate()?;
        if !self.cohorts.contains_key(&rotation.cohort_id) {
            return Err("rotation references unknown cohort".to_string());
        }
        self.rotations.insert(id.clone(), rotation);
        Ok(id)
    }

    pub fn insert_enrollment(
        &mut self,
        enrollment: PqThresholdSignerEnrollment,
    ) -> PqKeyCeremonyResult<String> {
        let id = enrollment.validate()?;
        if !self.cohorts.contains_key(&enrollment.cohort_id) {
            return Err("enrollment references unknown cohort".to_string());
        }
        if let Some(rotation_id) = &enrollment.rotation_id {
            if !self.rotations.contains_key(rotation_id) {
                return Err("enrollment references unknown rotation".to_string());
            }
        }
        if !self.algorithms.contains_key(&enrollment.algorithm_id) {
            return Err("enrollment references unknown algorithm".to_string());
        }
        self.enrollments.insert(id.clone(), enrollment);
        Ok(id)
    }

    pub fn insert_revocation(
        &mut self,
        revocation: PqRevocationEvidence,
    ) -> PqKeyCeremonyResult<String> {
        let id = revocation.validate()?;
        if !self.cohorts.contains_key(&revocation.cohort_id) {
            return Err("revocation references unknown cohort".to_string());
        }
        self.revocations.insert(id.clone(), revocation);
        Ok(id)
    }

    pub fn insert_fallback_policy(
        &mut self,
        policy: PqFallbackPolicy,
    ) -> PqKeyCeremonyResult<String> {
        let id = policy.validate()?;
        if !self.algorithms.contains_key(&policy.primary_algorithm_id) {
            return Err("fallback policy references unknown primary algorithm".to_string());
        }
        if !self.algorithms.contains_key(&policy.fallback_algorithm_id) {
            return Err("fallback policy references unknown fallback algorithm".to_string());
        }
        self.fallback_policies.insert(id.clone(), policy);
        Ok(id)
    }

    pub fn insert_emergency_freeze(
        &mut self,
        freeze: PqQuantumEmergencyFreeze,
    ) -> PqKeyCeremonyResult<String> {
        let id = freeze.validate()?;
        for cohort_id in &freeze.affected_cohort_ids {
            if !self.cohorts.contains_key(cohort_id) {
                return Err("emergency freeze references unknown cohort".to_string());
            }
        }
        self.emergency_freezes.insert(id.clone(), freeze);
        Ok(id)
    }

    pub fn insert_sponsored_rekey_lane(
        &mut self,
        lane: PqLowFeeSponsoredRekeyLane,
    ) -> PqKeyCeremonyResult<String> {
        let id = lane.validate()?;
        self.sponsored_rekey_lanes.insert(id.clone(), lane);
        Ok(id)
    }

    pub fn insert_reserve_ceremony(
        &mut self,
        ceremony: MoneroReserveSignerCeremony,
    ) -> PqKeyCeremonyResult<String> {
        let id = ceremony.validate()?;
        self.reserve_ceremonies.insert(id.clone(), ceremony);
        Ok(id)
    }

    pub fn insert_public_record(
        &mut self,
        record: PqKeyCeremonyPublicRecord,
    ) -> PqKeyCeremonyResult<String> {
        let id = record.validate()?;
        self.public_records.insert(id.clone(), record);
        Ok(id)
    }

    pub fn roots(&self) -> PqKeyCeremonyRoots {
        PqKeyCeremonyRoots {
            config_root: self.config.config_root(),
            algorithm_root: pq_algorithm_root(&self.algorithms),
            cohort_root: pq_cohort_root(&self.cohorts),
            rotation_root: pq_rotation_root(&self.rotations),
            enrollment_root: pq_enrollment_root(&self.enrollments),
            revocation_root: pq_revocation_root(&self.revocations),
            fallback_policy_root: pq_fallback_policy_root(&self.fallback_policies),
            emergency_freeze_root: pq_emergency_freeze_root(&self.emergency_freezes),
            sponsored_rekey_lane_root: pq_sponsored_rekey_lane_root(&self.sponsored_rekey_lanes),
            reserve_ceremony_root: pq_reserve_ceremony_root(&self.reserve_ceremonies),
            public_record_root: pq_key_public_record_root(&self.public_records),
        }
    }

    pub fn counters(&self) -> PqKeyCeremonyCounters {
        let usable_algorithm_count = self
            .algorithms
            .values()
            .filter(|algorithm| algorithm.usable_at(self.height))
            .count() as u64;
        let post_quantum_algorithm_count = self
            .algorithms
            .values()
            .filter(|algorithm| algorithm.algorithm.is_post_quantum())
            .count() as u64;
        let active_cohort_count = self
            .cohorts
            .values()
            .filter(|cohort| cohort.status.accepts_signatures())
            .count() as u64;
        let active_rotation_count = self
            .rotations
            .values()
            .filter(|rotation| rotation.stage.active())
            .count() as u64;
        let threshold_met_rotation_count = self
            .rotations
            .values()
            .filter(|rotation| {
                matches!(
                    rotation.stage,
                    PqRotationStage::ThresholdMet
                        | PqRotationStage::Activating
                        | PqRotationStage::Overlap
                        | PqRotationStage::Complete
                )
            })
            .count() as u64;
        let live_enrollments = self
            .enrollments
            .values()
            .filter(|enrollment| enrollment.live_at(self.height))
            .collect::<Vec<_>>();
        let active_freeze_count = self
            .emergency_freezes
            .values()
            .filter(|freeze| freeze.status.active())
            .count() as u64;
        let sponsored_rekey_remaining_budget_units = self
            .sponsored_rekey_lanes
            .values()
            .map(PqLowFeeSponsoredRekeyLane::remaining_budget_units)
            .sum();
        PqKeyCeremonyCounters {
            algorithm_count: self.algorithms.len() as u64,
            usable_algorithm_count,
            post_quantum_algorithm_count,
            cohort_count: self.cohorts.len() as u64,
            active_cohort_count,
            active_rotation_count,
            threshold_met_rotation_count,
            live_enrollment_count: live_enrollments.len() as u64,
            live_enrollment_weight: live_enrollments
                .iter()
                .map(|enrollment| enrollment.weight)
                .sum(),
            revocation_count: self.revocations.len() as u64,
            active_freeze_count,
            fallback_policy_count: self.fallback_policies.len() as u64,
            sponsored_rekey_lane_count: self.sponsored_rekey_lanes.len() as u64,
            sponsored_rekey_remaining_budget_units,
            reserve_ceremony_count: self.reserve_ceremonies.len() as u64,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_key_ceremony_state",
            "protocol_version": PQ_KEY_CEREMONY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "security_model": PQ_KEY_CEREMONY_SECURITY_MODEL,
            "commitment_scheme": PQ_KEY_CEREMONY_COMMITMENT_SCHEME,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "state_root",
            self.state_root(),
        )
    }

    pub fn state_root(&self) -> String {
        pq_key_ceremony_state_root_from_record(&self.public_record_without_root())
    }

    pub fn validate(&self) -> PqKeyCeremonyResult<String> {
        self.config.validate()?;
        if self.config.chain_id != CHAIN_ID {
            return Err("pq key ceremony config chain id mismatch".to_string());
        }
        for (id, algorithm) in &self.algorithms {
            let validated = algorithm.validate()?;
            if id != &validated {
                return Err("algorithm map key mismatch".to_string());
            }
        }
        for (id, cohort) in &self.cohorts {
            let validated = cohort.validate()?;
            if id != &validated {
                return Err("cohort map key mismatch".to_string());
            }
            for algorithm_id in &cohort.algorithm_ids {
                if !self.algorithms.contains_key(algorithm_id) {
                    return Err("cohort references unknown algorithm".to_string());
                }
            }
            if cohort.threshold_bps() < self.config.min_threshold_weight_bps
                && cohort.kind.requires_threshold()
            {
                return Err("cohort threshold below configured minimum".to_string());
            }
        }
        for (id, rotation) in &self.rotations {
            let validated = rotation.validate()?;
            if id != &validated {
                return Err("rotation map key mismatch".to_string());
            }
            if !self.cohorts.contains_key(&rotation.cohort_id) {
                return Err("rotation references unknown cohort".to_string());
            }
        }
        for (id, enrollment) in &self.enrollments {
            let validated = enrollment.validate()?;
            if id != &validated {
                return Err("enrollment map key mismatch".to_string());
            }
            if !self.cohorts.contains_key(&enrollment.cohort_id) {
                return Err("enrollment references unknown cohort".to_string());
            }
            if !self.algorithms.contains_key(&enrollment.algorithm_id) {
                return Err("enrollment references unknown algorithm".to_string());
            }
            if let Some(rotation_id) = &enrollment.rotation_id {
                if !self.rotations.contains_key(rotation_id) {
                    return Err("enrollment references unknown rotation".to_string());
                }
            }
        }
        for (id, revocation) in &self.revocations {
            let validated = revocation.validate()?;
            if id != &validated {
                return Err("revocation map key mismatch".to_string());
            }
            if !self.cohorts.contains_key(&revocation.cohort_id) {
                return Err("revocation references unknown cohort".to_string());
            }
        }
        for (id, policy) in &self.fallback_policies {
            let validated = policy.validate()?;
            if id != &validated {
                return Err("fallback policy map key mismatch".to_string());
            }
            if !self.algorithms.contains_key(&policy.primary_algorithm_id) {
                return Err("fallback policy references unknown primary algorithm".to_string());
            }
            if !self.algorithms.contains_key(&policy.fallback_algorithm_id) {
                return Err("fallback policy references unknown fallback algorithm".to_string());
            }
        }
        for (id, freeze) in &self.emergency_freezes {
            let validated = freeze.validate()?;
            if id != &validated {
                return Err("emergency freeze map key mismatch".to_string());
            }
            for cohort_id in &freeze.affected_cohort_ids {
                if !self.cohorts.contains_key(cohort_id) {
                    return Err("emergency freeze references unknown cohort".to_string());
                }
            }
        }
        for (id, lane) in &self.sponsored_rekey_lanes {
            let validated = lane.validate()?;
            if id != &validated {
                return Err("sponsored rekey lane map key mismatch".to_string());
            }
            if lane.rebate_bps > self.config.low_fee_rekey_rebate_bps {
                return Err("sponsored rekey lane rebate exceeds configured cap".to_string());
            }
            if lane.budget_units > self.config.max_sponsor_budget_units {
                return Err("sponsored rekey lane budget exceeds configured cap".to_string());
            }
        }
        for (id, ceremony) in &self.reserve_ceremonies {
            let validated = ceremony.validate()?;
            if id != &validated {
                return Err("reserve ceremony map key mismatch".to_string());
            }
            if ceremony.threshold < self.config.reserve_signer_quorum {
                return Err("reserve ceremony threshold below configured quorum".to_string());
            }
        }
        for (id, record) in &self.public_records {
            let validated = record.validate()?;
            if id != &validated {
                return Err("public record map key mismatch".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn pq_key_ceremony_state_root_from_record(record: &Value) -> String {
    pq_key_ceremony_payload_root("PQ-KEY-CEREMONY-STATE", record)
}

pub fn pq_key_ceremony_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn pq_key_ceremony_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn pq_algorithm_id(
    algorithm: PqCeremonyAlgorithm,
    implementation_root: &str,
    test_vector_root: &str,
    activated_at_height: u64,
) -> String {
    domain_hash(
        "PQ-ALGORITHM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(algorithm.as_str()),
            HashPart::Str(algorithm.family()),
            HashPart::Str(implementation_root),
            HashPart::Str(test_vector_root),
            HashPart::Int(activated_at_height as i128),
        ],
        32,
    )
}

pub fn pq_cohort_id(
    kind: PqKeyCohortKind,
    label: &str,
    current_key_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PQ-KEY-COHORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(current_key_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn pq_rotation_id(
    cohort_id: &str,
    from_key_root: &str,
    to_key_root: &str,
    announcement_root: &str,
    announced_at_height: u64,
) -> String {
    domain_hash(
        "PQ-STAGED-ROTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(cohort_id),
            HashPart::Str(from_key_root),
            HashPart::Str(to_key_root),
            HashPart::Str(announcement_root),
            HashPart::Int(announced_at_height as i128),
        ],
        32,
    )
}

pub fn pq_overlap_window_root(activates_at_height: u64, overlap_ends_at_height: u64) -> String {
    domain_hash(
        "PQ-OVERLAP-WINDOW",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(activates_at_height as i128),
            HashPart::Int(overlap_ends_at_height as i128),
        ],
        32,
    )
}

pub fn pq_enrollment_id(
    cohort_id: &str,
    rotation_id: Option<&str>,
    signer_label: &str,
    signer_key_root: &str,
    proof_root: &str,
    enrolled_at_height: u64,
) -> String {
    let rotation_component = match rotation_id {
        Some(value) => value,
        None => "",
    };
    domain_hash(
        "PQ-THRESHOLD-SIGNER-ENROLLMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(cohort_id),
            HashPart::Str(rotation_component),
            HashPart::Str(signer_label),
            HashPart::Str(signer_key_root),
            HashPart::Str(proof_root),
            HashPart::Int(enrolled_at_height as i128),
        ],
        32,
    )
}

pub fn pq_revocation_id(
    subject_id: &str,
    cohort_id: &str,
    evidence_kind: PqRevocationEvidenceKind,
    evidence_root: &str,
    reporter_label: &str,
    reported_at_height: u64,
) -> String {
    domain_hash(
        "PQ-REVOCATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(cohort_id),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(reporter_label),
            HashPart::Int(reported_at_height as i128),
        ],
        32,
    )
}

pub fn pq_fallback_policy_id(
    cohort_kind: PqKeyCohortKind,
    mode: PqFallbackMode,
    primary_algorithm_id: &str,
    fallback_algorithm_id: &str,
    guardrail_root: &str,
    activated_at_height: u64,
) -> String {
    domain_hash(
        "PQ-FALLBACK-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(cohort_kind.as_str()),
            HashPart::Str(mode.as_str()),
            HashPart::Str(primary_algorithm_id),
            HashPart::Str(fallback_algorithm_id),
            HashPart::Str(guardrail_root),
            HashPart::Int(activated_at_height as i128),
        ],
        32,
    )
}

pub fn pq_freeze_id(
    affected_cohort_ids: &[String],
    reason_root: &str,
    attestation_root: &str,
    opened_at_height: u64,
) -> String {
    let cohorts = affected_cohort_ids.join(",");
    domain_hash(
        "PQ-QUANTUM-EMERGENCY-FREEZE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&cohorts),
            HashPart::Str(reason_root),
            HashPart::Str(attestation_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn pq_low_fee_lane_id(
    sponsor_label: &str,
    cohort_kind: PqKeyCohortKind,
    fee_asset_id: &str,
    policy_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PQ-LOW-FEE-REKEY-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::Str(cohort_kind.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Str(policy_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn pq_reserve_ceremony_id(
    reserve_asset_id: &str,
    reserve_address_root: &str,
    view_key_root: &str,
    signer_set_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-SIGNER-CEREMONY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reserve_asset_id),
            HashPart::Str(reserve_address_root),
            HashPart::Str(view_key_root),
            HashPart::Str(signer_set_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn pq_public_record_id(
    record_kind: PqPublicRecordKind,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-KEY-CEREMONY-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn pq_algorithm_root(records: &BTreeMap<String, PqAlgorithmReadiness>) -> String {
    keyed_value_root(
        "PQ-ALGORITHM-READINESS-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_cohort_root(records: &BTreeMap<String, PqKeyCohort>) -> String {
    keyed_value_root(
        "PQ-KEY-COHORT-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_rotation_root(records: &BTreeMap<String, PqStagedRotation>) -> String {
    keyed_value_root(
        "PQ-STAGED-ROTATION-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_enrollment_root(records: &BTreeMap<String, PqThresholdSignerEnrollment>) -> String {
    keyed_value_root(
        "PQ-THRESHOLD-SIGNER-ENROLLMENT-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_revocation_root(records: &BTreeMap<String, PqRevocationEvidence>) -> String {
    keyed_value_root(
        "PQ-REVOCATION-EVIDENCE-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_fallback_policy_root(records: &BTreeMap<String, PqFallbackPolicy>) -> String {
    keyed_value_root(
        "PQ-FALLBACK-POLICY-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_emergency_freeze_root(records: &BTreeMap<String, PqQuantumEmergencyFreeze>) -> String {
    keyed_value_root(
        "PQ-QUANTUM-EMERGENCY-FREEZE-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_sponsored_rekey_lane_root(
    records: &BTreeMap<String, PqLowFeeSponsoredRekeyLane>,
) -> String {
    keyed_value_root(
        "PQ-LOW-FEE-SPONSORED-REKEY-LANE-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_reserve_ceremony_root(records: &BTreeMap<String, MoneroReserveSignerCeremony>) -> String {
    keyed_value_root(
        "MONERO-RESERVE-SIGNER-CEREMONY-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_key_public_record_root(records: &BTreeMap<String, PqKeyCeremonyPublicRecord>) -> String {
    keyed_value_root(
        "PQ-KEY-CEREMONY-PUBLIC-RECORD-ROOT",
        records
            .iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(id, value)| json!({"id": id, "record": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(root));
    }
    record
}

fn require_non_empty(label: &str, value: &str) -> PqKeyCeremonyResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> PqKeyCeremonyResult<()> {
    if value > PQ_KEY_CEREMONY_MAX_BPS {
        Err(format!(
            "{label} cannot exceed {PQ_KEY_CEREMONY_MAX_BPS} bps"
        ))
    } else {
        Ok(())
    }
}

fn require_unique_strings(label: &str, values: &[String]) -> PqKeyCeremonyResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}

fn weight_is_zero(value: u64) -> bool {
    value == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_roots_are_stable() -> PqKeyCeremonyResult<()> {
        let state = PqKeyCeremonyState::devnet("operator-devnet")?;
        let root = state.state_root();
        assert_eq!(state.validate()?, root);
        assert_eq!(state.public_record()["state_root"], root);
        Ok(())
    }
}
