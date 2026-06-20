use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash_hex, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqAggregateFinalityResult<T> = Result<T, String>;

pub const PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION: &str = "nebula-pq-aggregate-finality-v1";
pub const PQ_AGGREGATE_FINALITY_SCHEMA_VERSION: u64 = 1;
pub const PQ_AGGREGATE_FINALITY_SECURITY_MODEL: &str =
    "deterministic-devnet-records-not-real-crypto";
pub const PQ_AGGREGATE_FINALITY_HASH_SUITE: &str = "SHAKE256";
pub const PQ_AGGREGATE_FINALITY_PRIMARY_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PQ_AGGREGATE_FINALITY_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_AGGREGATE_FINALITY_LATTICE_COMMITMENT_SCHEME: &str =
    "module-lattice-commitment-root-v1";
pub const PQ_AGGREGATE_FINALITY_HASH_COMMITMENT_SCHEME: &str = "hash-tree-commitment-root-v1";
pub const PQ_AGGREGATE_FINALITY_DEVNET_HEIGHT: u64 = 512;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 720;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_ROTATION_NOTICE_BLOCKS: u64 = 288;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_ROTATION_OVERLAP_BLOCKS: u64 = 144;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_FINALITY_DEPTH_BLOCKS: u64 = 12;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_LOW_FEE_MICROUNITS: u64 = 25_000;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_AGGREGATE_QUORUM_BPS: u64 = 6_700;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_FAST_QUORUM_BPS: u64 = 8_000;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_FALLBACK_QUORUM_BPS: u64 = 7_500;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_WATCHTOWER_QUORUM: u64 = 2;
pub const PQ_AGGREGATE_FINALITY_DEFAULT_MAX_BUNDLE_SIGNERS: u64 = 256;
pub const PQ_AGGREGATE_FINALITY_MAX_BPS: u64 = 10_000;
pub const PQ_AGGREGATE_FINALITY_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PQ_AGGREGATE_FINALITY_DEVNET_COMMITTEE_ID: &str = "pq-finality-devnet-committee";
pub const PQ_AGGREGATE_FINALITY_DEVNET_OPERATOR_ID: &str = "pq-finality-devnet-operator";
pub const PQ_AGGREGATE_FINALITY_DEVNET_WATCHTOWER_ID: &str = "pq-finality-devnet-watchtower";

const STATE_STATUS_ACTIVE: &str = "active";
const STATE_STATUS_ROTATING: &str = "rotating";
const STATE_STATUS_EMERGENCY: &str = "emergency";
const STATE_STATUS_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFinalityDomain {
    PrivateTransfer,
    MoneroBridge,
    TokenTransfer,
    DefiCall,
    ContractExecution,
    Governance,
    ForcedInclusion,
    Emergency,
}

impl PqFinalityDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridge => "monero_bridge",
            Self::TokenTransfer => "token_transfer",
            Self::DefiCall => "defi_call",
            Self::ContractExecution => "contract_execution",
            Self::Governance => "governance",
            Self::ForcedInclusion => "forced_inclusion",
            Self::Emergency => "emergency",
        }
    }

    pub fn privacy_critical(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer
                | Self::MoneroBridge
                | Self::DefiCall
                | Self::ForcedInclusion
                | Self::Emergency
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignerRole {
    Validator,
    Sequencer,
    Bridge,
    Watchtower,
    GovernanceGuardian,
    EmergencyFallback,
}

impl PqSignerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::Sequencer => "sequencer",
            Self::Bridge => "bridge",
            Self::Watchtower => "watchtower",
            Self::GovernanceGuardian => "governance_guardian",
            Self::EmergencyFallback => "emergency_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCommitmentFamily {
    Lattice,
    HashBased,
    Hybrid,
    ViewOnlyFallback,
}

impl PqCommitmentFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lattice => "lattice",
            Self::HashBased => "hash_based",
            Self::Hybrid => "hybrid",
            Self::ViewOnlyFallback => "view_only_fallback",
        }
    }

    pub fn quantum_resistant(self) -> bool {
        !matches!(self, Self::ViewOnlyFallback)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCheckpointStatus {
    Proposed,
    Aggregating,
    QuorumReached,
    ChallengeOpen,
    Finalized,
    Disputed,
    Rejected,
    FallbackFinalized,
}

impl PqCheckpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Aggregating => "aggregating",
            Self::QuorumReached => "quorum_reached",
            Self::ChallengeOpen => "challenge_open",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
            Self::FallbackFinalized => "fallback_finalized",
        }
    }

    pub fn final_status(self) -> bool {
        matches!(self, Self::Finalized | Self::FallbackFinalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqBundleStatus {
    Draft,
    Collected,
    Verified,
    ChallengeOpen,
    Accepted,
    Rejected,
    Slashed,
    Superseded,
}

impl PqBundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Collected => "collected",
            Self::Verified => "verified",
            Self::ChallengeOpen => "challenge_open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Superseded => "superseded",
        }
    }

    pub fn usable_for_finality(self) -> bool {
        matches!(self, Self::Verified | Self::ChallengeOpen | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqChallengeKind {
    InvalidSignature,
    Equivocation,
    WrongCheckpointRoot,
    InsufficientWeight,
    ExpiredCommittee,
    DaUnavailable,
    PrivacyLeak,
    RotationFraud,
    FallbackMisuse,
}

impl PqChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::Equivocation => "equivocation",
            Self::WrongCheckpointRoot => "wrong_checkpoint_root",
            Self::InsufficientWeight => "insufficient_weight",
            Self::ExpiredCommittee => "expired_committee",
            Self::DaUnavailable => "da_unavailable",
            Self::PrivacyLeak => "privacy_leak",
            Self::RotationFraud => "rotation_fraud",
            Self::FallbackMisuse => "fallback_misuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqChallengeOutcome {
    Unresolved,
    Dismissed,
    Sustained,
    BundleRejected,
    SlashQueued,
    FallbackActivated,
}

impl PqChallengeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unresolved => "unresolved",
            Self::Dismissed => "dismissed",
            Self::Sustained => "sustained",
            Self::BundleRejected => "bundle_rejected",
            Self::SlashQueued => "slash_queued",
            Self::FallbackActivated => "fallback_activated",
        }
    }

    pub fn resolved(self) -> bool {
        !matches!(self, Self::Unresolved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRotationStage {
    Announced,
    EnrollmentOpen,
    Warmup,
    Overlap,
    Active,
    Complete,
    Cancelled,
    Failed,
}

impl PqRotationStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::EnrollmentOpen => "enrollment_open",
            Self::Warmup => "warmup",
            Self::Overlap => "overlap",
            Self::Active => "active",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Announced | Self::EnrollmentOpen | Self::Warmup | Self::Overlap | Self::Active
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSlashKind {
    DoubleSign,
    InvalidAggregate,
    WithheldFallbackShare,
    RevealedPrivatePayload,
    InvalidRotationTicket,
    ChallengeNonResponse,
}

impl PqSlashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleSign => "double_sign",
            Self::InvalidAggregate => "invalid_aggregate",
            Self::WithheldFallbackShare => "withheld_fallback_share",
            Self::RevealedPrivatePayload => "revealed_private_payload",
            Self::InvalidRotationTicket => "invalid_rotation_ticket",
            Self::ChallengeNonResponse => "challenge_non_response",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqFallbackReason {
    QuantumEmergency,
    CommitteeUnavailable,
    ChallengeSustained,
    MoneroBridgeSafety,
    GovernanceHalt,
    RecoveryDrill,
}

impl PqFallbackReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuantumEmergency => "quantum_emergency",
            Self::CommitteeUnavailable => "committee_unavailable",
            Self::ChallengeSustained => "challenge_sustained",
            Self::MoneroBridgeSafety => "monero_bridge_safety",
            Self::GovernanceHalt => "governance_halt",
            Self::RecoveryDrill => "recovery_drill",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAggregateFinalityConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub primary_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub lattice_commitment_scheme: String,
    pub hash_commitment_scheme: String,
    pub hash_suite: String,
    pub epoch_length_blocks: u64,
    pub challenge_window_blocks: u64,
    pub rotation_notice_blocks: u64,
    pub rotation_overlap_blocks: u64,
    pub finality_depth_blocks: u64,
    pub aggregate_quorum_bps: u64,
    pub fast_quorum_bps: u64,
    pub fallback_quorum_bps: u64,
    pub watchtower_quorum: u64,
    pub max_bundle_signers: u64,
    pub low_fee_micro_units: u64,
    pub fee_asset_id: String,
    pub private_domains: BTreeSet<PqFinalityDomain>,
    pub defi_domains: BTreeSet<PqFinalityDomain>,
}

impl PqAggregateFinalityConfig {
    pub fn devnet() -> Self {
        let private_domains = [
            PqFinalityDomain::PrivateTransfer,
            PqFinalityDomain::MoneroBridge,
            PqFinalityDomain::DefiCall,
            PqFinalityDomain::ForcedInclusion,
        ]
        .into_iter()
        .collect();
        let defi_domains = [
            PqFinalityDomain::TokenTransfer,
            PqFinalityDomain::DefiCall,
            PqFinalityDomain::ContractExecution,
        ]
        .into_iter()
        .collect();
        Self {
            protocol_version: PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_AGGREGATE_FINALITY_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            primary_signature_scheme: PQ_AGGREGATE_FINALITY_PRIMARY_SIGNATURE_SCHEME.to_string(),
            backup_signature_scheme: PQ_AGGREGATE_FINALITY_BACKUP_SIGNATURE_SCHEME.to_string(),
            lattice_commitment_scheme: PQ_AGGREGATE_FINALITY_LATTICE_COMMITMENT_SCHEME.to_string(),
            hash_commitment_scheme: PQ_AGGREGATE_FINALITY_HASH_COMMITMENT_SCHEME.to_string(),
            hash_suite: PQ_AGGREGATE_FINALITY_HASH_SUITE.to_string(),
            epoch_length_blocks: PQ_AGGREGATE_FINALITY_DEFAULT_EPOCH_LENGTH_BLOCKS,
            challenge_window_blocks: PQ_AGGREGATE_FINALITY_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            rotation_notice_blocks: PQ_AGGREGATE_FINALITY_DEFAULT_ROTATION_NOTICE_BLOCKS,
            rotation_overlap_blocks: PQ_AGGREGATE_FINALITY_DEFAULT_ROTATION_OVERLAP_BLOCKS,
            finality_depth_blocks: PQ_AGGREGATE_FINALITY_DEFAULT_FINALITY_DEPTH_BLOCKS,
            aggregate_quorum_bps: PQ_AGGREGATE_FINALITY_DEFAULT_AGGREGATE_QUORUM_BPS,
            fast_quorum_bps: PQ_AGGREGATE_FINALITY_DEFAULT_FAST_QUORUM_BPS,
            fallback_quorum_bps: PQ_AGGREGATE_FINALITY_DEFAULT_FALLBACK_QUORUM_BPS,
            watchtower_quorum: PQ_AGGREGATE_FINALITY_DEFAULT_WATCHTOWER_QUORUM,
            max_bundle_signers: PQ_AGGREGATE_FINALITY_DEFAULT_MAX_BUNDLE_SIGNERS,
            low_fee_micro_units: PQ_AGGREGATE_FINALITY_DEFAULT_LOW_FEE_MICROUNITS,
            fee_asset_id: PQ_AGGREGATE_FINALITY_DEVNET_FEE_ASSET_ID.to_string(),
            private_domains,
            defi_domains,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_aggregate_finality_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "security_model": PQ_AGGREGATE_FINALITY_SECURITY_MODEL,
            "primary_signature_scheme": self.primary_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "lattice_commitment_scheme": self.lattice_commitment_scheme,
            "hash_commitment_scheme": self.hash_commitment_scheme,
            "hash_suite": self.hash_suite,
            "epoch_length_blocks": self.epoch_length_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "rotation_notice_blocks": self.rotation_notice_blocks,
            "rotation_overlap_blocks": self.rotation_overlap_blocks,
            "finality_depth_blocks": self.finality_depth_blocks,
            "aggregate_quorum_bps": self.aggregate_quorum_bps,
            "fast_quorum_bps": self.fast_quorum_bps,
            "fallback_quorum_bps": self.fallback_quorum_bps,
            "watchtower_quorum": self.watchtower_quorum,
            "max_bundle_signers": self.max_bundle_signers,
            "low_fee_micro_units": self.low_fee_micro_units,
            "fee_asset_id": self.fee_asset_id,
            "private_domains": self.private_domains.iter().map(|domain| domain.as_str()).collect::<Vec<_>>(),
            "defi_domains": self.defi_domains.iter().map(|domain| domain.as_str()).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_payload_root("PQ-AGGREGATE-FINALITY-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<()> {
        require_nonempty("config.protocol_version", &self.protocol_version)?;
        require_nonempty("config.chain_id", &self.chain_id)?;
        require_nonempty(
            "config.primary_signature_scheme",
            &self.primary_signature_scheme,
        )?;
        require_nonempty(
            "config.backup_signature_scheme",
            &self.backup_signature_scheme,
        )?;
        require_nonempty(
            "config.lattice_commitment_scheme",
            &self.lattice_commitment_scheme,
        )?;
        require_nonempty(
            "config.hash_commitment_scheme",
            &self.hash_commitment_scheme,
        )?;
        require_nonempty("config.hash_suite", &self.hash_suite)?;
        require_nonempty("config.fee_asset_id", &self.fee_asset_id)?;
        if self.protocol_version != PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION {
            return Err("pq aggregate finality protocol version mismatch".to_string());
        }
        if self.schema_version != PQ_AGGREGATE_FINALITY_SCHEMA_VERSION {
            return Err("pq aggregate finality schema version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("pq aggregate finality chain id mismatch".to_string());
        }
        if self.epoch_length_blocks == 0 {
            return Err("epoch length must be positive".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("challenge window must be positive".to_string());
        }
        if self.rotation_notice_blocks == 0 {
            return Err("rotation notice must be positive".to_string());
        }
        if self.rotation_overlap_blocks == 0 {
            return Err("rotation overlap must be positive".to_string());
        }
        if self.finality_depth_blocks == 0 {
            return Err("finality depth must be positive".to_string());
        }
        require_bps("config.aggregate_quorum_bps", self.aggregate_quorum_bps)?;
        require_bps("config.fast_quorum_bps", self.fast_quorum_bps)?;
        require_bps("config.fallback_quorum_bps", self.fallback_quorum_bps)?;
        if self.fast_quorum_bps < self.aggregate_quorum_bps {
            return Err("fast quorum cannot be below aggregate quorum".to_string());
        }
        if self.watchtower_quorum == 0 {
            return Err("watchtower quorum must be positive".to_string());
        }
        if self.max_bundle_signers == 0 {
            return Err("max bundle signers must be positive".to_string());
        }
        if self.private_domains.is_empty() {
            return Err("private domain set cannot be empty".to_string());
        }
        if self.defi_domains.is_empty() {
            return Err("defi domain set cannot be empty".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignerCommitment {
    pub signer_id: String,
    pub operator_id: String,
    pub role: PqSignerRole,
    pub family: PqCommitmentFamily,
    pub lattice_public_key_root: String,
    pub hash_public_key_root: String,
    pub vrf_public_key_root: String,
    pub encrypted_share_root: String,
    pub privacy_budget_root: String,
    pub weight_bps: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub slashed: bool,
}

impl PqSignerCommitment {
    pub fn new(
        operator_id: &str,
        role: PqSignerRole,
        family: PqCommitmentFamily,
        key_label: &str,
        weight_bps: u64,
        activated_at_height: u64,
        expires_at_height: u64,
    ) -> PqAggregateFinalityResult<Self> {
        require_nonempty("operator_id", operator_id)?;
        require_nonempty("key_label", key_label)?;
        require_bps("signer.weight_bps", weight_bps)?;
        if activated_at_height >= expires_at_height {
            return Err("signer commitment expires before activation".to_string());
        }
        let lattice_public_key_root = commitment_root("signer-lattice-pk", key_label, 0);
        let hash_public_key_root = commitment_root("signer-hash-pk", key_label, 0);
        let signer_id = signer_commitment_id(
            operator_id,
            role,
            family,
            &lattice_public_key_root,
            &hash_public_key_root,
        );
        Ok(Self {
            signer_id,
            operator_id: operator_id.to_string(),
            role,
            family,
            lattice_public_key_root,
            hash_public_key_root,
            vrf_public_key_root: commitment_root("signer-vrf-pk", key_label, 0),
            encrypted_share_root: commitment_root("signer-share", key_label, 0),
            privacy_budget_root: commitment_root("signer-privacy-budget", key_label, 0),
            weight_bps,
            activated_at_height,
            expires_at_height,
            slashed: false,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        !self.slashed && height >= self.activated_at_height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_signer_commitment",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "signer_id": self.signer_id,
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "family": self.family.as_str(),
            "quantum_resistant": self.family.quantum_resistant(),
            "lattice_public_key_root": self.lattice_public_key_root,
            "hash_public_key_root": self.hash_public_key_root,
            "vrf_public_key_root": self.vrf_public_key_root,
            "encrypted_share_root": self.encrypted_share_root,
            "privacy_budget_root": self.privacy_budget_root,
            "weight_bps": self.weight_bps,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "slashed": self.slashed,
        })
    }

    pub fn commitment_root(&self) -> String {
        pq_payload_root("PQ-FINALITY-SIGNER-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        require_nonempty("signer.signer_id", &self.signer_id)?;
        require_nonempty("signer.operator_id", &self.operator_id)?;
        require_nonempty(
            "signer.lattice_public_key_root",
            &self.lattice_public_key_root,
        )?;
        require_nonempty("signer.hash_public_key_root", &self.hash_public_key_root)?;
        require_nonempty("signer.vrf_public_key_root", &self.vrf_public_key_root)?;
        require_nonempty("signer.encrypted_share_root", &self.encrypted_share_root)?;
        require_nonempty("signer.privacy_budget_root", &self.privacy_budget_root)?;
        require_bps("signer.weight_bps", self.weight_bps)?;
        if self.activated_at_height >= self.expires_at_height {
            return Err("signer commitment expires before activation".to_string());
        }
        if self.signer_id
            != signer_commitment_id(
                &self.operator_id,
                self.role,
                self.family,
                &self.lattice_public_key_root,
                &self.hash_public_key_root,
            )
        {
            return Err("signer commitment id mismatch".to_string());
        }
        Ok(self.signer_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeEpoch {
    pub epoch_id: String,
    pub committee_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub activation_root: String,
    pub signer_ids: Vec<String>,
    pub signer_commitment_root: String,
    pub threshold_bps: u64,
    pub fast_threshold_bps: u64,
    pub fallback_threshold_bps: u64,
    pub private_domain_root: String,
    pub fee_policy_root: String,
    pub status: String,
}

impl PqCommitteeEpoch {
    pub fn new(
        committee_id: &str,
        epoch: u64,
        start_height: u64,
        end_height: u64,
        signer_ids: Vec<String>,
        signer_commitment_root: &str,
        config: &PqAggregateFinalityConfig,
    ) -> PqAggregateFinalityResult<Self> {
        require_nonempty("committee_id", committee_id)?;
        require_nonempty("signer_commitment_root", signer_commitment_root)?;
        if start_height >= end_height {
            return Err("committee epoch end must be greater than start".to_string());
        }
        if signer_ids.is_empty() {
            return Err("committee epoch signer set cannot be empty".to_string());
        }
        let epoch_id =
            committee_epoch_id(committee_id, epoch, start_height, signer_commitment_root);
        Ok(Self {
            epoch_id,
            committee_id: committee_id.to_string(),
            epoch,
            start_height,
            end_height,
            activation_root: commitment_root("committee-activation", committee_id, epoch),
            signer_ids,
            signer_commitment_root: signer_commitment_root.to_string(),
            threshold_bps: config.aggregate_quorum_bps,
            fast_threshold_bps: config.fast_quorum_bps,
            fallback_threshold_bps: config.fallback_quorum_bps,
            private_domain_root: pq_payload_root(
                "PQ-FINALITY-PRIVATE-DOMAINS",
                &json!({
                    "committee_id": committee_id,
                    "epoch": epoch,
                    "domains": config.private_domains.iter().map(|domain| domain.as_str()).collect::<Vec<_>>(),
                }),
            ),
            fee_policy_root: pq_payload_root(
                "PQ-FINALITY-FEE-POLICY",
                &json!({
                    "fee_asset_id": config.fee_asset_id,
                    "low_fee_micro_units": config.low_fee_micro_units,
                }),
            ),
            status: STATE_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn live_at(&self, height: u64) -> bool {
        self.status == STATE_STATUS_ACTIVE
            && height >= self.start_height
            && height < self.end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_committee_epoch",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "epoch_id": self.epoch_id,
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "activation_root": self.activation_root,
            "signer_ids": self.signer_ids,
            "signer_commitment_root": self.signer_commitment_root,
            "threshold_bps": self.threshold_bps,
            "fast_threshold_bps": self.fast_threshold_bps,
            "fallback_threshold_bps": self.fallback_threshold_bps,
            "private_domain_root": self.private_domain_root,
            "fee_policy_root": self.fee_policy_root,
            "status": self.status,
        })
    }

    pub fn epoch_root(&self) -> String {
        pq_payload_root("PQ-FINALITY-COMMITTEE-EPOCH", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        require_nonempty("committee.epoch_id", &self.epoch_id)?;
        require_nonempty("committee.committee_id", &self.committee_id)?;
        require_nonempty("committee.activation_root", &self.activation_root)?;
        require_nonempty(
            "committee.signer_commitment_root",
            &self.signer_commitment_root,
        )?;
        require_nonempty("committee.private_domain_root", &self.private_domain_root)?;
        require_nonempty("committee.fee_policy_root", &self.fee_policy_root)?;
        require_state_status("committee.status", &self.status)?;
        require_bps("committee.threshold_bps", self.threshold_bps)?;
        require_bps("committee.fast_threshold_bps", self.fast_threshold_bps)?;
        require_bps(
            "committee.fallback_threshold_bps",
            self.fallback_threshold_bps,
        )?;
        if self.start_height >= self.end_height {
            return Err("committee epoch end must be greater than start".to_string());
        }
        if self.signer_ids.is_empty() {
            return Err("committee signer set cannot be empty".to_string());
        }
        if self.fast_threshold_bps < self.threshold_bps {
            return Err("committee fast threshold below aggregate threshold".to_string());
        }
        if self.epoch_id
            != committee_epoch_id(
                &self.committee_id,
                self.epoch,
                self.start_height,
                &self.signer_commitment_root,
            )
        {
            return Err("committee epoch id mismatch".to_string());
        }
        Ok(self.epoch_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCheckpointClaim {
    pub checkpoint_id: String,
    pub domain: PqFinalityDomain,
    pub l2_height: u64,
    pub l2_block_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub transaction_root: String,
    pub private_note_root: String,
    pub nullifier_root: String,
    pub contract_root: String,
    pub token_root: String,
    pub defi_state_root: String,
    pub monero_anchor_root: String,
    pub data_availability_root: String,
    pub validity_proof_root: String,
    pub fee_receipt_root: String,
    pub proposed_at_height: u64,
    pub challenge_expires_at_height: u64,
    pub status: PqCheckpointStatus,
}

impl PqCheckpointClaim {
    pub fn new(
        domain: PqFinalityDomain,
        l2_height: u64,
        label: &str,
        proposed_at_height: u64,
        challenge_window_blocks: u64,
    ) -> PqAggregateFinalityResult<Self> {
        require_nonempty("checkpoint.label", label)?;
        if challenge_window_blocks == 0 {
            return Err("checkpoint challenge window must be positive".to_string());
        }
        let l2_block_root = commitment_root("checkpoint-l2-block", label, l2_height);
        let post_state_root = commitment_root("checkpoint-post-state", label, l2_height);
        let checkpoint_id =
            checkpoint_claim_id(domain, l2_height, &l2_block_root, &post_state_root);
        Ok(Self {
            checkpoint_id,
            domain,
            l2_height,
            l2_block_root,
            pre_state_root: commitment_root("checkpoint-pre-state", label, l2_height),
            post_state_root,
            transaction_root: commitment_root("checkpoint-transactions", label, l2_height),
            private_note_root: commitment_root("checkpoint-notes", label, l2_height),
            nullifier_root: commitment_root("checkpoint-nullifiers", label, l2_height),
            contract_root: commitment_root("checkpoint-contracts", label, l2_height),
            token_root: commitment_root("checkpoint-tokens", label, l2_height),
            defi_state_root: commitment_root("checkpoint-defi", label, l2_height),
            monero_anchor_root: commitment_root("checkpoint-monero-anchor", label, l2_height),
            data_availability_root: commitment_root("checkpoint-da", label, l2_height),
            validity_proof_root: commitment_root("checkpoint-validity", label, l2_height),
            fee_receipt_root: commitment_root("checkpoint-fee", label, l2_height),
            proposed_at_height,
            challenge_expires_at_height: proposed_at_height.saturating_add(challenge_window_blocks),
            status: PqCheckpointStatus::ChallengeOpen,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_checkpoint_claim",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "checkpoint_id": self.checkpoint_id,
            "domain": self.domain.as_str(),
            "privacy_critical": self.domain.privacy_critical(),
            "l2_height": self.l2_height,
            "l2_block_root": self.l2_block_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "transaction_root": self.transaction_root,
            "private_note_root": self.private_note_root,
            "nullifier_root": self.nullifier_root,
            "contract_root": self.contract_root,
            "token_root": self.token_root,
            "defi_state_root": self.defi_state_root,
            "monero_anchor_root": self.monero_anchor_root,
            "data_availability_root": self.data_availability_root,
            "validity_proof_root": self.validity_proof_root,
            "fee_receipt_root": self.fee_receipt_root,
            "proposed_at_height": self.proposed_at_height,
            "challenge_expires_at_height": self.challenge_expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn checkpoint_root(&self) -> String {
        pq_payload_root("PQ-FINALITY-CHECKPOINT-CLAIM", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        require_nonempty("checkpoint.checkpoint_id", &self.checkpoint_id)?;
        require_nonempty("checkpoint.l2_block_root", &self.l2_block_root)?;
        require_nonempty("checkpoint.pre_state_root", &self.pre_state_root)?;
        require_nonempty("checkpoint.post_state_root", &self.post_state_root)?;
        require_nonempty("checkpoint.transaction_root", &self.transaction_root)?;
        require_nonempty("checkpoint.private_note_root", &self.private_note_root)?;
        require_nonempty("checkpoint.nullifier_root", &self.nullifier_root)?;
        require_nonempty("checkpoint.contract_root", &self.contract_root)?;
        require_nonempty("checkpoint.token_root", &self.token_root)?;
        require_nonempty("checkpoint.defi_state_root", &self.defi_state_root)?;
        require_nonempty("checkpoint.monero_anchor_root", &self.monero_anchor_root)?;
        require_nonempty(
            "checkpoint.data_availability_root",
            &self.data_availability_root,
        )?;
        require_nonempty("checkpoint.validity_proof_root", &self.validity_proof_root)?;
        require_nonempty("checkpoint.fee_receipt_root", &self.fee_receipt_root)?;
        if self.proposed_at_height >= self.challenge_expires_at_height {
            return Err("checkpoint challenge expires before proposal".to_string());
        }
        if self.checkpoint_id
            != checkpoint_claim_id(
                self.domain,
                self.l2_height,
                &self.l2_block_root,
                &self.post_state_root,
            )
        {
            return Err("checkpoint id mismatch".to_string());
        }
        Ok(self.checkpoint_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAggregateSignatureBundle {
    pub bundle_id: String,
    pub checkpoint_id: String,
    pub committee_epoch_id: String,
    pub aggregator_id: String,
    pub signature_scheme: String,
    pub signer_ids: Vec<String>,
    pub signer_bitmap_root: String,
    pub signer_commitment_root: String,
    pub aggregate_signature_root: String,
    pub aggregate_public_key_root: String,
    pub transcript_root: String,
    pub challenge_seed_root: String,
    pub signed_payload_root: String,
    pub total_weight_bps: u64,
    pub fast_path: bool,
    pub collected_at_height: u64,
    pub challenge_expires_at_height: u64,
    pub status: PqBundleStatus,
}

impl PqAggregateSignatureBundle {
    pub fn new(
        checkpoint_id: &str,
        committee_epoch_id: &str,
        aggregator_id: &str,
        signature_scheme: &str,
        signer_ids: Vec<String>,
        total_weight_bps: u64,
        collected_at_height: u64,
        challenge_window_blocks: u64,
    ) -> PqAggregateFinalityResult<Self> {
        require_nonempty("bundle.checkpoint_id", checkpoint_id)?;
        require_nonempty("bundle.committee_epoch_id", committee_epoch_id)?;
        require_nonempty("bundle.aggregator_id", aggregator_id)?;
        require_nonempty("bundle.signature_scheme", signature_scheme)?;
        require_bps("bundle.total_weight_bps", total_weight_bps)?;
        if signer_ids.is_empty() {
            return Err("aggregate bundle signer set cannot be empty".to_string());
        }
        if challenge_window_blocks == 0 {
            return Err("bundle challenge window must be positive".to_string());
        }
        let signer_bitmap_root = signer_set_root("PQ-FINALITY-BUNDLE-SIGNER-BITMAP", &signer_ids);
        let signed_payload_root = aggregate_signed_payload_root(checkpoint_id, committee_epoch_id);
        let bundle_id = aggregate_bundle_id(
            checkpoint_id,
            committee_epoch_id,
            aggregator_id,
            &signer_bitmap_root,
            &signed_payload_root,
        );
        Ok(Self {
            bundle_id,
            checkpoint_id: checkpoint_id.to_string(),
            committee_epoch_id: committee_epoch_id.to_string(),
            aggregator_id: aggregator_id.to_string(),
            signature_scheme: signature_scheme.to_string(),
            signer_ids,
            signer_bitmap_root,
            signer_commitment_root: commitment_root(
                "bundle-signer-commitments",
                aggregator_id,
                collected_at_height,
            ),
            aggregate_signature_root: commitment_root(
                "bundle-aggregate-signature",
                aggregator_id,
                collected_at_height,
            ),
            aggregate_public_key_root: commitment_root(
                "bundle-aggregate-public-key",
                aggregator_id,
                collected_at_height,
            ),
            transcript_root: commitment_root(
                "bundle-transcript",
                aggregator_id,
                collected_at_height,
            ),
            challenge_seed_root: commitment_root(
                "bundle-challenge-seed",
                aggregator_id,
                collected_at_height,
            ),
            signed_payload_root,
            total_weight_bps,
            fast_path: total_weight_bps >= PQ_AGGREGATE_FINALITY_DEFAULT_FAST_QUORUM_BPS,
            collected_at_height,
            challenge_expires_at_height: collected_at_height
                .saturating_add(challenge_window_blocks),
            status: PqBundleStatus::Verified,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_aggregate_signature_bundle",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "bundle_id": self.bundle_id,
            "checkpoint_id": self.checkpoint_id,
            "committee_epoch_id": self.committee_epoch_id,
            "aggregator_id": self.aggregator_id,
            "signature_scheme": self.signature_scheme,
            "signer_ids": self.signer_ids,
            "signer_bitmap_root": self.signer_bitmap_root,
            "signer_commitment_root": self.signer_commitment_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "aggregate_public_key_root": self.aggregate_public_key_root,
            "transcript_root": self.transcript_root,
            "challenge_seed_root": self.challenge_seed_root,
            "signed_payload_root": self.signed_payload_root,
            "total_weight_bps": self.total_weight_bps,
            "fast_path": self.fast_path,
            "collected_at_height": self.collected_at_height,
            "challenge_expires_at_height": self.challenge_expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn bundle_root(&self) -> String {
        pq_payload_root("PQ-FINALITY-AGGREGATE-BUNDLE", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        require_nonempty("bundle.bundle_id", &self.bundle_id)?;
        require_nonempty("bundle.checkpoint_id", &self.checkpoint_id)?;
        require_nonempty("bundle.committee_epoch_id", &self.committee_epoch_id)?;
        require_nonempty("bundle.aggregator_id", &self.aggregator_id)?;
        require_nonempty("bundle.signature_scheme", &self.signature_scheme)?;
        require_nonempty("bundle.signer_bitmap_root", &self.signer_bitmap_root)?;
        require_nonempty(
            "bundle.signer_commitment_root",
            &self.signer_commitment_root,
        )?;
        require_nonempty(
            "bundle.aggregate_signature_root",
            &self.aggregate_signature_root,
        )?;
        require_nonempty(
            "bundle.aggregate_public_key_root",
            &self.aggregate_public_key_root,
        )?;
        require_nonempty("bundle.transcript_root", &self.transcript_root)?;
        require_nonempty("bundle.challenge_seed_root", &self.challenge_seed_root)?;
        require_nonempty("bundle.signed_payload_root", &self.signed_payload_root)?;
        require_bps("bundle.total_weight_bps", self.total_weight_bps)?;
        if self.signer_ids.is_empty() {
            return Err("aggregate bundle signer set cannot be empty".to_string());
        }
        if self.collected_at_height >= self.challenge_expires_at_height {
            return Err("bundle challenge expires before collection".to_string());
        }
        if self.signer_bitmap_root
            != signer_set_root("PQ-FINALITY-BUNDLE-SIGNER-BITMAP", &self.signer_ids)
        {
            return Err("bundle signer bitmap root mismatch".to_string());
        }
        if self.signed_payload_root
            != aggregate_signed_payload_root(&self.checkpoint_id, &self.committee_epoch_id)
        {
            return Err("bundle signed payload root mismatch".to_string());
        }
        if self.bundle_id
            != aggregate_bundle_id(
                &self.checkpoint_id,
                &self.committee_epoch_id,
                &self.aggregator_id,
                &self.signer_bitmap_root,
                &self.signed_payload_root,
            )
        {
            return Err("bundle id mismatch".to_string());
        }
        Ok(self.bundle_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqChallengeWindow {
    pub challenge_id: String,
    pub bundle_id: String,
    pub checkpoint_id: String,
    pub challenger_commitment: String,
    pub kind: PqChallengeKind,
    pub subject_root: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub resolved_at_height: u64,
    pub outcome: PqChallengeOutcome,
}

impl PqChallengeWindow {
    pub fn new(
        bundle_id: &str,
        checkpoint_id: &str,
        challenger_commitment: &str,
        kind: PqChallengeKind,
        subject_root: &str,
        evidence_root: &str,
        opened_at_height: u64,
        window_blocks: u64,
    ) -> PqAggregateFinalityResult<Self> {
        require_nonempty("challenge.bundle_id", bundle_id)?;
        require_nonempty("challenge.checkpoint_id", checkpoint_id)?;
        require_nonempty("challenge.challenger_commitment", challenger_commitment)?;
        require_nonempty("challenge.subject_root", subject_root)?;
        require_nonempty("challenge.evidence_root", evidence_root)?;
        if window_blocks == 0 {
            return Err("challenge window blocks must be positive".to_string());
        }
        let challenge_id = challenge_window_id(bundle_id, checkpoint_id, kind, opened_at_height);
        Ok(Self {
            challenge_id,
            bundle_id: bundle_id.to_string(),
            checkpoint_id: checkpoint_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            kind,
            subject_root: subject_root.to_string(),
            evidence_root: evidence_root.to_string(),
            opened_at_height,
            closes_at_height: opened_at_height.saturating_add(window_blocks),
            resolved_at_height: 0,
            outcome: PqChallengeOutcome::Unresolved,
        })
    }

    pub fn open_at(&self, height: u64) -> bool {
        !self.outcome.resolved()
            && height >= self.opened_at_height
            && height < self.closes_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_finality_challenge_window",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "bundle_id": self.bundle_id,
            "checkpoint_id": self.checkpoint_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.kind.as_str(),
            "subject_root": self.subject_root,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "resolved_at_height": self.resolved_at_height,
            "outcome": self.outcome.as_str(),
        })
    }

    pub fn challenge_root(&self) -> String {
        pq_payload_root("PQ-FINALITY-CHALLENGE-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        require_nonempty("challenge.challenge_id", &self.challenge_id)?;
        require_nonempty("challenge.bundle_id", &self.bundle_id)?;
        require_nonempty("challenge.checkpoint_id", &self.checkpoint_id)?;
        require_nonempty(
            "challenge.challenger_commitment",
            &self.challenger_commitment,
        )?;
        require_nonempty("challenge.subject_root", &self.subject_root)?;
        require_nonempty("challenge.evidence_root", &self.evidence_root)?;
        if self.opened_at_height >= self.closes_at_height {
            return Err("challenge closes before opening".to_string());
        }
        if self.outcome.resolved() && self.resolved_at_height < self.opened_at_height {
            return Err("challenge resolved before opening".to_string());
        }
        if !self.outcome.resolved() && self.resolved_at_height != 0 {
            return Err("unresolved challenge cannot have resolved height".to_string());
        }
        if self.challenge_id
            != challenge_window_id(
                &self.bundle_id,
                &self.checkpoint_id,
                self.kind,
                self.opened_at_height,
            )
        {
            return Err("challenge id mismatch".to_string());
        }
        Ok(self.challenge_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRotationTicket {
    pub ticket_id: String,
    pub old_committee_epoch_id: String,
    pub new_committee_epoch_id: String,
    pub rotation_stage: PqRotationStage,
    pub notice_root: String,
    pub old_signer_root: String,
    pub new_signer_root: String,
    pub overlap_start_height: u64,
    pub overlap_end_height: u64,
    pub activation_height: u64,
    pub aggregate_authorization_root: String,
    pub watchtower_ack_root: String,
    pub created_at_height: u64,
}

impl PqRotationTicket {
    pub fn new(
        old_committee_epoch_id: &str,
        new_committee_epoch_id: &str,
        label: &str,
        created_at_height: u64,
        notice_blocks: u64,
        overlap_blocks: u64,
    ) -> PqAggregateFinalityResult<Self> {
        require_nonempty("rotation.old_committee_epoch_id", old_committee_epoch_id)?;
        require_nonempty("rotation.new_committee_epoch_id", new_committee_epoch_id)?;
        require_nonempty("rotation.label", label)?;
        if notice_blocks == 0 || overlap_blocks == 0 {
            return Err("rotation notice and overlap must be positive".to_string());
        }
        let activation_height = created_at_height.saturating_add(notice_blocks);
        let overlap_end_height = activation_height.saturating_add(overlap_blocks);
        let notice_root = commitment_root("rotation-notice", label, created_at_height);
        let ticket_id = rotation_ticket_id(
            old_committee_epoch_id,
            new_committee_epoch_id,
            &notice_root,
            created_at_height,
        );
        Ok(Self {
            ticket_id,
            old_committee_epoch_id: old_committee_epoch_id.to_string(),
            new_committee_epoch_id: new_committee_epoch_id.to_string(),
            rotation_stage: PqRotationStage::Overlap,
            notice_root,
            old_signer_root: commitment_root("rotation-old-signers", label, created_at_height),
            new_signer_root: commitment_root("rotation-new-signers", label, created_at_height),
            overlap_start_height: activation_height,
            overlap_end_height,
            activation_height,
            aggregate_authorization_root: commitment_root(
                "rotation-aggregate-authorization",
                label,
                created_at_height,
            ),
            watchtower_ack_root: commitment_root(
                "rotation-watchtower-ack",
                label,
                created_at_height,
            ),
            created_at_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.rotation_stage.live()
            && height >= self.created_at_height
            && height < self.overlap_end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_finality_rotation_ticket",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "ticket_id": self.ticket_id,
            "old_committee_epoch_id": self.old_committee_epoch_id,
            "new_committee_epoch_id": self.new_committee_epoch_id,
            "rotation_stage": self.rotation_stage.as_str(),
            "notice_root": self.notice_root,
            "old_signer_root": self.old_signer_root,
            "new_signer_root": self.new_signer_root,
            "overlap_start_height": self.overlap_start_height,
            "overlap_end_height": self.overlap_end_height,
            "activation_height": self.activation_height,
            "aggregate_authorization_root": self.aggregate_authorization_root,
            "watchtower_ack_root": self.watchtower_ack_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn ticket_root(&self) -> String {
        pq_payload_root("PQ-FINALITY-ROTATION-TICKET", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        require_nonempty("rotation.ticket_id", &self.ticket_id)?;
        require_nonempty(
            "rotation.old_committee_epoch_id",
            &self.old_committee_epoch_id,
        )?;
        require_nonempty(
            "rotation.new_committee_epoch_id",
            &self.new_committee_epoch_id,
        )?;
        require_nonempty("rotation.notice_root", &self.notice_root)?;
        require_nonempty("rotation.old_signer_root", &self.old_signer_root)?;
        require_nonempty("rotation.new_signer_root", &self.new_signer_root)?;
        require_nonempty(
            "rotation.aggregate_authorization_root",
            &self.aggregate_authorization_root,
        )?;
        require_nonempty("rotation.watchtower_ack_root", &self.watchtower_ack_root)?;
        if self.old_committee_epoch_id == self.new_committee_epoch_id {
            return Err("rotation old and new committee cannot match".to_string());
        }
        if self.created_at_height > self.activation_height {
            return Err("rotation activation before creation".to_string());
        }
        if self.overlap_start_height > self.overlap_end_height {
            return Err("rotation overlap ends before start".to_string());
        }
        if self.ticket_id
            != rotation_ticket_id(
                &self.old_committee_epoch_id,
                &self.new_committee_epoch_id,
                &self.notice_root,
                self.created_at_height,
            )
        {
            return Err("rotation ticket id mismatch".to_string());
        }
        Ok(self.ticket_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSlashingEvidence {
    pub evidence_id: String,
    pub offender_signer_id: String,
    pub committee_epoch_id: String,
    pub bundle_id: String,
    pub kind: PqSlashKind,
    pub evidence_root: String,
    pub witness_root: String,
    pub slash_amount_bps: u64,
    pub opened_at_height: u64,
    pub resolved_at_height: u64,
    pub applied: bool,
}

impl PqSlashingEvidence {
    pub fn new(
        offender_signer_id: &str,
        committee_epoch_id: &str,
        bundle_id: &str,
        kind: PqSlashKind,
        label: &str,
        slash_amount_bps: u64,
        opened_at_height: u64,
    ) -> PqAggregateFinalityResult<Self> {
        require_nonempty("slash.offender_signer_id", offender_signer_id)?;
        require_nonempty("slash.committee_epoch_id", committee_epoch_id)?;
        require_nonempty("slash.bundle_id", bundle_id)?;
        require_nonempty("slash.label", label)?;
        require_bps("slash.slash_amount_bps", slash_amount_bps)?;
        let evidence_root = commitment_root("slash-evidence", label, opened_at_height);
        let evidence_id = slashing_evidence_id(
            offender_signer_id,
            committee_epoch_id,
            bundle_id,
            kind,
            &evidence_root,
        );
        Ok(Self {
            evidence_id,
            offender_signer_id: offender_signer_id.to_string(),
            committee_epoch_id: committee_epoch_id.to_string(),
            bundle_id: bundle_id.to_string(),
            kind,
            evidence_root,
            witness_root: commitment_root("slash-witness", label, opened_at_height),
            slash_amount_bps,
            opened_at_height,
            resolved_at_height: 0,
            applied: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_finality_slashing_evidence",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "offender_signer_id": self.offender_signer_id,
            "committee_epoch_id": self.committee_epoch_id,
            "bundle_id": self.bundle_id,
            "slash_kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "witness_root": self.witness_root,
            "slash_amount_bps": self.slash_amount_bps,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "applied": self.applied,
        })
    }

    pub fn slash_root(&self) -> String {
        pq_payload_root("PQ-FINALITY-SLASHING-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        require_nonempty("slash.evidence_id", &self.evidence_id)?;
        require_nonempty("slash.offender_signer_id", &self.offender_signer_id)?;
        require_nonempty("slash.committee_epoch_id", &self.committee_epoch_id)?;
        require_nonempty("slash.bundle_id", &self.bundle_id)?;
        require_nonempty("slash.evidence_root", &self.evidence_root)?;
        require_nonempty("slash.witness_root", &self.witness_root)?;
        require_bps("slash.slash_amount_bps", self.slash_amount_bps)?;
        if self.applied && self.resolved_at_height < self.opened_at_height {
            return Err("slash applied before evidence opened".to_string());
        }
        if !self.applied && self.resolved_at_height != 0 {
            return Err("unapplied slash cannot have resolved height".to_string());
        }
        if self.evidence_id
            != slashing_evidence_id(
                &self.offender_signer_id,
                &self.committee_epoch_id,
                &self.bundle_id,
                self.kind,
                &self.evidence_root,
            )
        {
            return Err("slashing evidence id mismatch".to_string());
        }
        Ok(self.evidence_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFallbackFinalityAttestation {
    pub attestation_id: String,
    pub checkpoint_id: String,
    pub committee_epoch_id: String,
    pub reason: PqFallbackReason,
    pub guardian_set_root: String,
    pub fallback_signature_root: String,
    pub monero_safety_root: String,
    pub halted_domain_root: String,
    pub recovery_plan_root: String,
    pub total_weight_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl PqFallbackFinalityAttestation {
    pub fn new(
        checkpoint_id: &str,
        committee_epoch_id: &str,
        reason: PqFallbackReason,
        label: &str,
        total_weight_bps: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> PqAggregateFinalityResult<Self> {
        require_nonempty("fallback.checkpoint_id", checkpoint_id)?;
        require_nonempty("fallback.committee_epoch_id", committee_epoch_id)?;
        require_nonempty("fallback.label", label)?;
        require_bps("fallback.total_weight_bps", total_weight_bps)?;
        if ttl_blocks == 0 {
            return Err("fallback ttl must be positive".to_string());
        }
        let fallback_signature_root =
            commitment_root("fallback-signature", label, opened_at_height);
        let attestation_id = fallback_attestation_id(
            checkpoint_id,
            committee_epoch_id,
            reason,
            &fallback_signature_root,
        );
        Ok(Self {
            attestation_id,
            checkpoint_id: checkpoint_id.to_string(),
            committee_epoch_id: committee_epoch_id.to_string(),
            reason,
            guardian_set_root: commitment_root("fallback-guardian-set", label, opened_at_height),
            fallback_signature_root,
            monero_safety_root: commitment_root("fallback-monero-safety", label, opened_at_height),
            halted_domain_root: commitment_root("fallback-halted-domains", label, opened_at_height),
            recovery_plan_root: commitment_root("fallback-recovery-plan", label, opened_at_height),
            total_weight_bps,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            consumed: false,
        })
    }

    pub fn live_at(&self, height: u64) -> bool {
        !self.consumed && height >= self.opened_at_height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_fallback_finality_attestation",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "checkpoint_id": self.checkpoint_id,
            "committee_epoch_id": self.committee_epoch_id,
            "reason": self.reason.as_str(),
            "guardian_set_root": self.guardian_set_root,
            "fallback_signature_root": self.fallback_signature_root,
            "monero_safety_root": self.monero_safety_root,
            "halted_domain_root": self.halted_domain_root,
            "recovery_plan_root": self.recovery_plan_root,
            "total_weight_bps": self.total_weight_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "consumed": self.consumed,
        })
    }

    pub fn attestation_root(&self) -> String {
        pq_payload_root("PQ-FINALITY-FALLBACK-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        require_nonempty("fallback.attestation_id", &self.attestation_id)?;
        require_nonempty("fallback.checkpoint_id", &self.checkpoint_id)?;
        require_nonempty("fallback.committee_epoch_id", &self.committee_epoch_id)?;
        require_nonempty("fallback.guardian_set_root", &self.guardian_set_root)?;
        require_nonempty(
            "fallback.fallback_signature_root",
            &self.fallback_signature_root,
        )?;
        require_nonempty("fallback.monero_safety_root", &self.monero_safety_root)?;
        require_nonempty("fallback.halted_domain_root", &self.halted_domain_root)?;
        require_nonempty("fallback.recovery_plan_root", &self.recovery_plan_root)?;
        require_bps("fallback.total_weight_bps", self.total_weight_bps)?;
        if self.opened_at_height >= self.expires_at_height {
            return Err("fallback attestation expires before opening".to_string());
        }
        if self.attestation_id
            != fallback_attestation_id(
                &self.checkpoint_id,
                &self.committee_epoch_id,
                self.reason,
                &self.fallback_signature_root,
            )
        {
            return Err("fallback attestation id mismatch".to_string());
        }
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqFinalityPublicRecord {
    pub record_id: String,
    pub checkpoint_id: String,
    pub bundle_id: Option<String>,
    pub fallback_attestation_id: Option<String>,
    pub finality_root: String,
    pub public_counter_root: String,
    pub finalized_at_height: u64,
    pub finality_depth_blocks: u64,
    pub fee_asset_id: String,
    pub fee_micro_units: u64,
    pub privacy_statement_root: String,
    pub status: PqCheckpointStatus,
}

impl PqFinalityPublicRecord {
    pub fn new(
        checkpoint_id: &str,
        bundle_id: Option<String>,
        fallback_attestation_id: Option<String>,
        finality_root: &str,
        counters: &PqAggregateFinalityCounters,
        finalized_at_height: u64,
        config: &PqAggregateFinalityConfig,
        status: PqCheckpointStatus,
    ) -> PqAggregateFinalityResult<Self> {
        require_nonempty("public_record.checkpoint_id", checkpoint_id)?;
        require_nonempty("public_record.finality_root", finality_root)?;
        if !status.final_status() {
            return Err("public record status must be final".to_string());
        }
        let public_counter_root = counters.counters_root();
        let record_id = public_finality_record_id(
            checkpoint_id,
            optional_id_value(&bundle_id),
            optional_id_value(&fallback_attestation_id),
            finality_root,
        );
        Ok(Self {
            record_id,
            checkpoint_id: checkpoint_id.to_string(),
            bundle_id,
            fallback_attestation_id,
            finality_root: finality_root.to_string(),
            public_counter_root,
            finalized_at_height,
            finality_depth_blocks: config.finality_depth_blocks,
            fee_asset_id: config.fee_asset_id.clone(),
            fee_micro_units: config.low_fee_micro_units,
            privacy_statement_root: pq_payload_root(
                "PQ-FINALITY-PRIVACY-STATEMENT",
                &json!({
                    "checkpoint_id": checkpoint_id,
                    "statement": "no private memo, address, note, or contract witness data in public record",
                }),
            ),
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_finality_public_record",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "record_id": self.record_id,
            "checkpoint_id": self.checkpoint_id,
            "bundle_id": self.bundle_id,
            "fallback_attestation_id": self.fallback_attestation_id,
            "finality_root": self.finality_root,
            "public_counter_root": self.public_counter_root,
            "finalized_at_height": self.finalized_at_height,
            "finality_depth_blocks": self.finality_depth_blocks,
            "fee_asset_id": self.fee_asset_id,
            "fee_micro_units": self.fee_micro_units,
            "privacy_statement_root": self.privacy_statement_root,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        pq_payload_root("PQ-FINALITY-PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        require_nonempty("public_record.record_id", &self.record_id)?;
        require_nonempty("public_record.checkpoint_id", &self.checkpoint_id)?;
        require_nonempty("public_record.finality_root", &self.finality_root)?;
        require_nonempty(
            "public_record.public_counter_root",
            &self.public_counter_root,
        )?;
        require_nonempty("public_record.fee_asset_id", &self.fee_asset_id)?;
        require_nonempty(
            "public_record.privacy_statement_root",
            &self.privacy_statement_root,
        )?;
        if !self.status.final_status() {
            return Err("public record status must be final".to_string());
        }
        if self.bundle_id.is_none() && self.fallback_attestation_id.is_none() {
            return Err("public record needs aggregate bundle or fallback attestation".to_string());
        }
        if self.record_id
            != public_finality_record_id(
                &self.checkpoint_id,
                optional_id_value(&self.bundle_id),
                optional_id_value(&self.fallback_attestation_id),
                &self.finality_root,
            )
        {
            return Err("public finality record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAggregateFinalityRoots {
    pub config_root: String,
    pub signer_commitment_root: String,
    pub committee_epoch_root: String,
    pub checkpoint_root: String,
    pub aggregate_bundle_root: String,
    pub challenge_window_root: String,
    pub rotation_ticket_root: String,
    pub slashing_evidence_root: String,
    pub fallback_attestation_root: String,
    pub public_record_root: String,
}

impl PqAggregateFinalityRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_aggregate_finality_roots",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "signer_commitment_root": self.signer_commitment_root,
            "committee_epoch_root": self.committee_epoch_root,
            "checkpoint_root": self.checkpoint_root,
            "aggregate_bundle_root": self.aggregate_bundle_root,
            "challenge_window_root": self.challenge_window_root,
            "rotation_ticket_root": self.rotation_ticket_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "fallback_attestation_root": self.fallback_attestation_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        pq_payload_root("PQ-AGGREGATE-FINALITY-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAggregateFinalityCounters {
    pub signer_commitment_count: u64,
    pub active_signer_count: u64,
    pub quantum_resistant_signer_count: u64,
    pub committee_epoch_count: u64,
    pub live_committee_epoch_count: u64,
    pub checkpoint_count: u64,
    pub finalized_checkpoint_count: u64,
    pub aggregate_bundle_count: u64,
    pub fast_bundle_count: u64,
    pub open_challenge_count: u64,
    pub rotation_ticket_count: u64,
    pub live_rotation_ticket_count: u64,
    pub slashing_evidence_count: u64,
    pub applied_slashing_count: u64,
    pub fallback_attestation_count: u64,
    pub live_fallback_attestation_count: u64,
    pub public_record_count: u64,
}

impl PqAggregateFinalityCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_aggregate_finality_counters",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "signer_commitment_count": self.signer_commitment_count,
            "active_signer_count": self.active_signer_count,
            "quantum_resistant_signer_count": self.quantum_resistant_signer_count,
            "committee_epoch_count": self.committee_epoch_count,
            "live_committee_epoch_count": self.live_committee_epoch_count,
            "checkpoint_count": self.checkpoint_count,
            "finalized_checkpoint_count": self.finalized_checkpoint_count,
            "aggregate_bundle_count": self.aggregate_bundle_count,
            "fast_bundle_count": self.fast_bundle_count,
            "open_challenge_count": self.open_challenge_count,
            "rotation_ticket_count": self.rotation_ticket_count,
            "live_rotation_ticket_count": self.live_rotation_ticket_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "applied_slashing_count": self.applied_slashing_count,
            "fallback_attestation_count": self.fallback_attestation_count,
            "live_fallback_attestation_count": self.live_fallback_attestation_count,
            "public_record_count": self.public_record_count,
        })
    }

    pub fn counters_root(&self) -> String {
        pq_payload_root("PQ-AGGREGATE-FINALITY-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAggregateFinalityState {
    pub config: PqAggregateFinalityConfig,
    pub height: u64,
    pub status: String,
    pub signer_commitments: BTreeMap<String, PqSignerCommitment>,
    pub committee_epochs: BTreeMap<String, PqCommitteeEpoch>,
    pub checkpoints: BTreeMap<String, PqCheckpointClaim>,
    pub aggregate_bundles: BTreeMap<String, PqAggregateSignatureBundle>,
    pub challenge_windows: BTreeMap<String, PqChallengeWindow>,
    pub rotation_tickets: BTreeMap<String, PqRotationTicket>,
    pub slashing_evidence: BTreeMap<String, PqSlashingEvidence>,
    pub fallback_attestations: BTreeMap<String, PqFallbackFinalityAttestation>,
    pub public_records: BTreeMap<String, PqFinalityPublicRecord>,
}

impl PqAggregateFinalityState {
    pub fn devnet() -> PqAggregateFinalityResult<Self> {
        let config = PqAggregateFinalityConfig::devnet();
        config.validate()?;
        let height = PQ_AGGREGATE_FINALITY_DEVNET_HEIGHT;
        let mut state = Self {
            config,
            height,
            status: STATE_STATUS_ACTIVE.to_string(),
            signer_commitments: BTreeMap::new(),
            committee_epochs: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            aggregate_bundles: BTreeMap::new(),
            challenge_windows: BTreeMap::new(),
            rotation_tickets: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            fallback_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };

        for (index, (operator_id, role, family, weight)) in [
            (
                "validator-a",
                PqSignerRole::Validator,
                PqCommitmentFamily::Hybrid,
                2_500,
            ),
            (
                "validator-b",
                PqSignerRole::Validator,
                PqCommitmentFamily::Hybrid,
                2_500,
            ),
            (
                "validator-c",
                PqSignerRole::Validator,
                PqCommitmentFamily::Lattice,
                2_000,
            ),
            (
                "bridge-a",
                PqSignerRole::Bridge,
                PqCommitmentFamily::Hybrid,
                1_500,
            ),
            (
                "watchtower-a",
                PqSignerRole::Watchtower,
                PqCommitmentFamily::HashBased,
                1_000,
            ),
            (
                "guardian-a",
                PqSignerRole::GovernanceGuardian,
                PqCommitmentFamily::HashBased,
                500,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let signer = PqSignerCommitment::new(
                operator_id,
                role,
                family,
                &format!("devnet-{operator_id}-pq-key-{index}"),
                weight,
                height.saturating_sub(300),
                height.saturating_add(10_080),
            )?;
            state.insert_signer_commitment(signer)?;
        }

        let signer_ids = state.signer_commitments.keys().cloned().collect::<Vec<_>>();
        let signer_commitment_root = state.signer_commitment_root();
        let committee = PqCommitteeEpoch::new(
            PQ_AGGREGATE_FINALITY_DEVNET_COMMITTEE_ID,
            1,
            height.saturating_sub(300),
            height.saturating_add(state.config.epoch_length_blocks),
            signer_ids.clone(),
            &signer_commitment_root,
            &state.config,
        )?;
        let committee_epoch_id = committee.epoch_id.clone();
        state.insert_committee_epoch(committee)?;

        let checkpoint = PqCheckpointClaim::new(
            PqFinalityDomain::MoneroBridge,
            42,
            "devnet-monero-bridge-fast-defi-checkpoint",
            height.saturating_sub(4),
            state.config.challenge_window_blocks,
        )?;
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        state.insert_checkpoint(checkpoint)?;

        let bundle_signers = signer_ids.iter().take(4).cloned().collect::<Vec<_>>();
        let bundle = PqAggregateSignatureBundle::new(
            &checkpoint_id,
            &committee_epoch_id,
            PQ_AGGREGATE_FINALITY_DEVNET_OPERATOR_ID,
            &state.config.primary_signature_scheme,
            bundle_signers,
            state.config.fast_quorum_bps,
            height.saturating_sub(3),
            state.config.challenge_window_blocks,
        )?;
        let bundle_id = bundle.bundle_id.clone();
        let bundle_root = bundle.bundle_root();
        state.insert_aggregate_bundle(bundle)?;

        let challenge = PqChallengeWindow::new(
            &bundle_id,
            &checkpoint_id,
            &commitment_root(
                "challenge-challenger",
                PQ_AGGREGATE_FINALITY_DEVNET_WATCHTOWER_ID,
                height,
            ),
            PqChallengeKind::DaUnavailable,
            &bundle_root,
            &empty_record_root("PQ-FINALITY-EMPTY-CHALLENGE"),
            height.saturating_sub(2),
            state.config.challenge_window_blocks,
        )?;
        state.insert_challenge_window(challenge)?;

        let next_committee = PqCommitteeEpoch::new(
            "pq-finality-devnet-committee-next",
            2,
            height.saturating_add(state.config.rotation_notice_blocks),
            height
                .saturating_add(state.config.rotation_notice_blocks)
                .saturating_add(state.config.epoch_length_blocks),
            signer_ids,
            &signer_commitment_root,
            &state.config,
        )?;
        let next_committee_epoch_id = next_committee.epoch_id.clone();
        state.insert_committee_epoch(next_committee)?;

        let rotation = PqRotationTicket::new(
            &committee_epoch_id,
            &next_committee_epoch_id,
            "devnet-pq-finality-committee-rotation",
            height.saturating_sub(1),
            state.config.rotation_notice_blocks,
            state.config.rotation_overlap_blocks,
        )?;
        state.insert_rotation_ticket(rotation)?;

        if let Some(offender_id) = state.signer_commitments.keys().next().cloned() {
            let slash = PqSlashingEvidence::new(
                &offender_id,
                &committee_epoch_id,
                &bundle_id,
                PqSlashKind::ChallengeNonResponse,
                "devnet-watchtower-drill",
                50,
                height,
            )?;
            state.insert_slashing_evidence(slash)?;
        }

        let fallback = PqFallbackFinalityAttestation::new(
            &checkpoint_id,
            &committee_epoch_id,
            PqFallbackReason::RecoveryDrill,
            "devnet-fallback-drill",
            state.config.fallback_quorum_bps,
            height,
            state.config.challenge_window_blocks,
        )?;
        state.insert_fallback_attestation(fallback)?;

        let finality_root = state.roots().state_root();
        let public_record = PqFinalityPublicRecord::new(
            &checkpoint_id,
            Some(bundle_id),
            None,
            &finality_root,
            &state.counters(),
            height.saturating_add(state.config.finality_depth_blocks),
            &state.config,
            PqCheckpointStatus::Finalized,
        )?;
        state.insert_public_record(public_record)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqAggregateFinalityResult<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn insert_signer_commitment(
        &mut self,
        signer: PqSignerCommitment,
    ) -> PqAggregateFinalityResult<String> {
        let id = signer.validate()?;
        self.signer_commitments.insert(id.clone(), signer);
        Ok(id)
    }

    pub fn insert_committee_epoch(
        &mut self,
        epoch: PqCommitteeEpoch,
    ) -> PqAggregateFinalityResult<String> {
        let id = epoch.validate()?;
        for signer_id in &epoch.signer_ids {
            if !self.signer_commitments.contains_key(signer_id) {
                return Err("committee epoch references unknown signer".to_string());
            }
        }
        self.committee_epochs.insert(id.clone(), epoch);
        Ok(id)
    }

    pub fn insert_checkpoint(
        &mut self,
        checkpoint: PqCheckpointClaim,
    ) -> PqAggregateFinalityResult<String> {
        let id = checkpoint.validate()?;
        self.checkpoints.insert(id.clone(), checkpoint);
        Ok(id)
    }

    pub fn insert_aggregate_bundle(
        &mut self,
        bundle: PqAggregateSignatureBundle,
    ) -> PqAggregateFinalityResult<String> {
        let id = bundle.validate()?;
        if !self.checkpoints.contains_key(&bundle.checkpoint_id) {
            return Err("aggregate bundle references unknown checkpoint".to_string());
        }
        if !self
            .committee_epochs
            .contains_key(&bundle.committee_epoch_id)
        {
            return Err("aggregate bundle references unknown committee epoch".to_string());
        }
        if bundle.signer_ids.len() as u64 > self.config.max_bundle_signers {
            return Err("aggregate bundle exceeds configured signer limit".to_string());
        }
        for signer_id in &bundle.signer_ids {
            if !self.signer_commitments.contains_key(signer_id) {
                return Err("aggregate bundle references unknown signer".to_string());
            }
        }
        self.aggregate_bundles.insert(id.clone(), bundle);
        Ok(id)
    }

    pub fn insert_challenge_window(
        &mut self,
        window: PqChallengeWindow,
    ) -> PqAggregateFinalityResult<String> {
        let id = window.validate()?;
        if !self.checkpoints.contains_key(&window.checkpoint_id) {
            return Err("challenge references unknown checkpoint".to_string());
        }
        if !self.aggregate_bundles.contains_key(&window.bundle_id) {
            return Err("challenge references unknown aggregate bundle".to_string());
        }
        self.challenge_windows.insert(id.clone(), window);
        Ok(id)
    }

    pub fn insert_rotation_ticket(
        &mut self,
        ticket: PqRotationTicket,
    ) -> PqAggregateFinalityResult<String> {
        let id = ticket.validate()?;
        if !self
            .committee_epochs
            .contains_key(&ticket.old_committee_epoch_id)
        {
            return Err("rotation references unknown old committee epoch".to_string());
        }
        if !self
            .committee_epochs
            .contains_key(&ticket.new_committee_epoch_id)
        {
            return Err("rotation references unknown new committee epoch".to_string());
        }
        self.rotation_tickets.insert(id.clone(), ticket);
        Ok(id)
    }

    pub fn insert_slashing_evidence(
        &mut self,
        evidence: PqSlashingEvidence,
    ) -> PqAggregateFinalityResult<String> {
        let id = evidence.validate()?;
        if !self
            .signer_commitments
            .contains_key(&evidence.offender_signer_id)
        {
            return Err("slashing evidence references unknown signer".to_string());
        }
        if !self
            .committee_epochs
            .contains_key(&evidence.committee_epoch_id)
        {
            return Err("slashing evidence references unknown committee epoch".to_string());
        }
        if !self.aggregate_bundles.contains_key(&evidence.bundle_id) {
            return Err("slashing evidence references unknown aggregate bundle".to_string());
        }
        self.slashing_evidence.insert(id.clone(), evidence);
        Ok(id)
    }

    pub fn insert_fallback_attestation(
        &mut self,
        attestation: PqFallbackFinalityAttestation,
    ) -> PqAggregateFinalityResult<String> {
        let id = attestation.validate()?;
        if !self.checkpoints.contains_key(&attestation.checkpoint_id) {
            return Err("fallback attestation references unknown checkpoint".to_string());
        }
        if !self
            .committee_epochs
            .contains_key(&attestation.committee_epoch_id)
        {
            return Err("fallback attestation references unknown committee epoch".to_string());
        }
        self.fallback_attestations.insert(id.clone(), attestation);
        Ok(id)
    }

    pub fn insert_public_record(
        &mut self,
        record: PqFinalityPublicRecord,
    ) -> PqAggregateFinalityResult<String> {
        let id = record.validate()?;
        if !self.checkpoints.contains_key(&record.checkpoint_id) {
            return Err("public record references unknown checkpoint".to_string());
        }
        if let Some(bundle_id) = &record.bundle_id {
            if !self.aggregate_bundles.contains_key(bundle_id) {
                return Err("public record references unknown aggregate bundle".to_string());
            }
        }
        if let Some(attestation_id) = &record.fallback_attestation_id {
            if !self.fallback_attestations.contains_key(attestation_id) {
                return Err("public record references unknown fallback attestation".to_string());
            }
        }
        self.public_records.insert(id.clone(), record);
        Ok(id)
    }

    pub fn roots(&self) -> PqAggregateFinalityRoots {
        PqAggregateFinalityRoots {
            config_root: self.config.state_root(),
            signer_commitment_root: self.signer_commitment_root(),
            committee_epoch_root: self.committee_epoch_root(),
            checkpoint_root: self.checkpoint_root(),
            aggregate_bundle_root: self.aggregate_bundle_root(),
            challenge_window_root: self.challenge_window_root(),
            rotation_ticket_root: self.rotation_ticket_root(),
            slashing_evidence_root: self.slashing_evidence_root(),
            fallback_attestation_root: self.fallback_attestation_root(),
            public_record_root: self.finality_public_record_root(),
        }
    }

    pub fn counters(&self) -> PqAggregateFinalityCounters {
        PqAggregateFinalityCounters {
            signer_commitment_count: self.signer_commitments.len() as u64,
            active_signer_count: self
                .signer_commitments
                .values()
                .filter(|signer| signer.active_at(self.height))
                .count() as u64,
            quantum_resistant_signer_count: self
                .signer_commitments
                .values()
                .filter(|signer| signer.family.quantum_resistant())
                .count() as u64,
            committee_epoch_count: self.committee_epochs.len() as u64,
            live_committee_epoch_count: self
                .committee_epochs
                .values()
                .filter(|epoch| epoch.live_at(self.height))
                .count() as u64,
            checkpoint_count: self.checkpoints.len() as u64,
            finalized_checkpoint_count: self
                .checkpoints
                .values()
                .filter(|checkpoint| checkpoint.status.final_status())
                .count() as u64,
            aggregate_bundle_count: self.aggregate_bundles.len() as u64,
            fast_bundle_count: self
                .aggregate_bundles
                .values()
                .filter(|bundle| bundle.fast_path && bundle.status.usable_for_finality())
                .count() as u64,
            open_challenge_count: self
                .challenge_windows
                .values()
                .filter(|window| window.open_at(self.height))
                .count() as u64,
            rotation_ticket_count: self.rotation_tickets.len() as u64,
            live_rotation_ticket_count: self
                .rotation_tickets
                .values()
                .filter(|ticket| ticket.active_at(self.height))
                .count() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            applied_slashing_count: self
                .slashing_evidence
                .values()
                .filter(|evidence| evidence.applied)
                .count() as u64,
            fallback_attestation_count: self.fallback_attestations.len() as u64,
            live_fallback_attestation_count: self
                .fallback_attestations
                .values()
                .filter(|attestation| attestation.live_at(self.height))
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_aggregate_finality_state",
            "protocol_version": PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION,
            "schema_version": PQ_AGGREGATE_FINALITY_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "status": self.status,
            "security_model": PQ_AGGREGATE_FINALITY_SECURITY_MODEL,
            "hash_suite": PQ_AGGREGATE_FINALITY_HASH_SUITE,
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_root();
        json!({
            "kind": "pq_aggregate_finality_state_record",
            "record": record,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_payload_root(
            "PQ-AGGREGATE-FINALITY-STATE",
            &self.public_record_without_root(),
        )
    }

    pub fn validate(&self) -> PqAggregateFinalityResult<String> {
        self.config.validate()?;
        require_state_status("state.status", &self.status)?;
        for (id, signer) in &self.signer_commitments {
            let validated = signer.validate()?;
            if id != &validated {
                return Err("signer commitment map key mismatch".to_string());
            }
        }
        for (id, epoch) in &self.committee_epochs {
            let validated = epoch.validate()?;
            if id != &validated {
                return Err("committee epoch map key mismatch".to_string());
            }
            for signer_id in &epoch.signer_ids {
                if !self.signer_commitments.contains_key(signer_id) {
                    return Err("committee epoch references unknown signer".to_string());
                }
            }
        }
        for (id, checkpoint) in &self.checkpoints {
            let validated = checkpoint.validate()?;
            if id != &validated {
                return Err("checkpoint map key mismatch".to_string());
            }
        }
        for (id, bundle) in &self.aggregate_bundles {
            let validated = bundle.validate()?;
            if id != &validated {
                return Err("aggregate bundle map key mismatch".to_string());
            }
            self.validate_bundle_references(bundle)?;
        }
        for (id, window) in &self.challenge_windows {
            let validated = window.validate()?;
            if id != &validated {
                return Err("challenge window map key mismatch".to_string());
            }
            if !self.checkpoints.contains_key(&window.checkpoint_id) {
                return Err("challenge references unknown checkpoint".to_string());
            }
            if !self.aggregate_bundles.contains_key(&window.bundle_id) {
                return Err("challenge references unknown aggregate bundle".to_string());
            }
        }
        for (id, ticket) in &self.rotation_tickets {
            let validated = ticket.validate()?;
            if id != &validated {
                return Err("rotation ticket map key mismatch".to_string());
            }
            if !self
                .committee_epochs
                .contains_key(&ticket.old_committee_epoch_id)
                || !self
                    .committee_epochs
                    .contains_key(&ticket.new_committee_epoch_id)
            {
                return Err("rotation ticket references unknown committee epoch".to_string());
            }
        }
        for (id, evidence) in &self.slashing_evidence {
            let validated = evidence.validate()?;
            if id != &validated {
                return Err("slashing evidence map key mismatch".to_string());
            }
            if !self
                .signer_commitments
                .contains_key(&evidence.offender_signer_id)
            {
                return Err("slashing evidence references unknown signer".to_string());
            }
            if !self
                .committee_epochs
                .contains_key(&evidence.committee_epoch_id)
            {
                return Err("slashing evidence references unknown committee epoch".to_string());
            }
            if !self.aggregate_bundles.contains_key(&evidence.bundle_id) {
                return Err("slashing evidence references unknown aggregate bundle".to_string());
            }
        }
        for (id, attestation) in &self.fallback_attestations {
            let validated = attestation.validate()?;
            if id != &validated {
                return Err("fallback attestation map key mismatch".to_string());
            }
            if !self.checkpoints.contains_key(&attestation.checkpoint_id) {
                return Err("fallback attestation references unknown checkpoint".to_string());
            }
            if !self
                .committee_epochs
                .contains_key(&attestation.committee_epoch_id)
            {
                return Err("fallback attestation references unknown committee epoch".to_string());
            }
        }
        for (id, record) in &self.public_records {
            let validated = record.validate()?;
            if id != &validated {
                return Err("public finality record map key mismatch".to_string());
            }
        }
        Ok(self.state_root())
    }

    pub fn signer_commitment_root(&self) -> String {
        map_root(
            "PQ-FINALITY-SIGNER-COMMITMENTS",
            self.signer_commitments
                .values()
                .map(PqSignerCommitment::public_record)
                .collect(),
        )
    }

    pub fn committee_epoch_root(&self) -> String {
        map_root(
            "PQ-FINALITY-COMMITTEE-EPOCHS",
            self.committee_epochs
                .values()
                .map(PqCommitteeEpoch::public_record)
                .collect(),
        )
    }

    pub fn checkpoint_root(&self) -> String {
        map_root(
            "PQ-FINALITY-CHECKPOINTS",
            self.checkpoints
                .values()
                .map(PqCheckpointClaim::public_record)
                .collect(),
        )
    }

    pub fn aggregate_bundle_root(&self) -> String {
        map_root(
            "PQ-FINALITY-AGGREGATE-BUNDLES",
            self.aggregate_bundles
                .values()
                .map(PqAggregateSignatureBundle::public_record)
                .collect(),
        )
    }

    pub fn challenge_window_root(&self) -> String {
        map_root(
            "PQ-FINALITY-CHALLENGE-WINDOWS",
            self.challenge_windows
                .values()
                .map(PqChallengeWindow::public_record)
                .collect(),
        )
    }

    pub fn rotation_ticket_root(&self) -> String {
        map_root(
            "PQ-FINALITY-ROTATION-TICKETS",
            self.rotation_tickets
                .values()
                .map(PqRotationTicket::public_record)
                .collect(),
        )
    }

    pub fn slashing_evidence_root(&self) -> String {
        map_root(
            "PQ-FINALITY-SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(PqSlashingEvidence::public_record)
                .collect(),
        )
    }

    pub fn fallback_attestation_root(&self) -> String {
        map_root(
            "PQ-FINALITY-FALLBACK-ATTESTATIONS",
            self.fallback_attestations
                .values()
                .map(PqFallbackFinalityAttestation::public_record)
                .collect(),
        )
    }

    pub fn finality_public_record_root(&self) -> String {
        map_root(
            "PQ-FINALITY-PUBLIC-RECORDS",
            self.public_records
                .values()
                .map(PqFinalityPublicRecord::public_record)
                .collect(),
        )
    }

    fn validate_bundle_references(
        &self,
        bundle: &PqAggregateSignatureBundle,
    ) -> PqAggregateFinalityResult<()> {
        if !self.checkpoints.contains_key(&bundle.checkpoint_id) {
            return Err("aggregate bundle references unknown checkpoint".to_string());
        }
        let epoch = match self.committee_epochs.get(&bundle.committee_epoch_id) {
            Some(epoch) => epoch,
            None => return Err("aggregate bundle references unknown committee epoch".to_string()),
        };
        let mut seen = BTreeSet::new();
        let mut total_weight = 0_u64;
        for signer_id in &bundle.signer_ids {
            if !seen.insert(signer_id.clone()) {
                return Err("aggregate bundle contains duplicate signer".to_string());
            }
            if !epoch.signer_ids.contains(signer_id) {
                return Err("aggregate bundle signer not in committee epoch".to_string());
            }
            let signer = match self.signer_commitments.get(signer_id) {
                Some(signer) => signer,
                None => return Err("aggregate bundle references unknown signer".to_string()),
            };
            total_weight = total_weight.saturating_add(signer.weight_bps);
        }
        if total_weight < bundle.total_weight_bps {
            return Err("aggregate bundle claims more weight than signer set".to_string());
        }
        if bundle.total_weight_bps < epoch.threshold_bps {
            return Err("aggregate bundle below committee threshold".to_string());
        }
        Ok(())
    }
}

fn require_nonempty(field: &str, value: &str) -> PqAggregateFinalityResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> PqAggregateFinalityResult<()> {
    if value > PQ_AGGREGATE_FINALITY_MAX_BPS {
        return Err(format!("{field} exceeds max bps"));
    }
    Ok(())
}

fn require_state_status(field: &str, value: &str) -> PqAggregateFinalityResult<()> {
    if matches!(
        value,
        STATE_STATUS_ACTIVE | STATE_STATUS_ROTATING | STATE_STATUS_EMERGENCY | STATE_STATUS_HALTED
    ) {
        return Ok(());
    }
    Err(format!("{field} has invalid status"))
}

fn optional_id_value(value: &Option<String>) -> &str {
    match value {
        Some(value) => value.as_str(),
        None => "",
    }
}

fn pq_payload_root(domain: &str, payload: &Value) -> String {
    stable_hash_hex(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn empty_record_root(domain: &str) -> String {
    stable_hash_hex(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION),
            HashPart::Str("empty"),
        ],
        32,
    )
}

fn commitment_root(scope: &str, label: &str, nonce: u64) -> String {
    stable_hash_hex(
        "PQ-FINALITY-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_AGGREGATE_FINALITY_PROTOCOL_VERSION),
            HashPart::Str(scope),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn signer_set_root(domain: &str, signer_ids: &[String]) -> String {
    let leaves = signer_ids
        .iter()
        .map(|signer_id| json!({"signer_id": signer_id}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn signer_commitment_id(
    operator_id: &str,
    role: PqSignerRole,
    family: PqCommitmentFamily,
    lattice_public_key_root: &str,
    hash_public_key_root: &str,
) -> String {
    stable_hash_hex(
        "PQ-FINALITY-SIGNER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(family.as_str()),
            HashPart::Str(lattice_public_key_root),
            HashPart::Str(hash_public_key_root),
        ],
        32,
    )
}

fn committee_epoch_id(
    committee_id: &str,
    epoch: u64,
    start_height: u64,
    signer_commitment_root: &str,
) -> String {
    stable_hash_hex(
        "PQ-FINALITY-COMMITTEE-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(committee_id),
            HashPart::Int(epoch as i128),
            HashPart::Int(start_height as i128),
            HashPart::Str(signer_commitment_root),
        ],
        32,
    )
}

fn checkpoint_claim_id(
    domain: PqFinalityDomain,
    l2_height: u64,
    l2_block_root: &str,
    post_state_root: &str,
) -> String {
    stable_hash_hex(
        "PQ-FINALITY-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain.as_str()),
            HashPart::Int(l2_height as i128),
            HashPart::Str(l2_block_root),
            HashPart::Str(post_state_root),
        ],
        32,
    )
}

fn aggregate_signed_payload_root(checkpoint_id: &str, committee_epoch_id: &str) -> String {
    stable_hash_hex(
        "PQ-FINALITY-SIGNED-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(committee_epoch_id),
        ],
        32,
    )
}

fn aggregate_bundle_id(
    checkpoint_id: &str,
    committee_epoch_id: &str,
    aggregator_id: &str,
    signer_bitmap_root: &str,
    signed_payload_root: &str,
) -> String {
    stable_hash_hex(
        "PQ-FINALITY-AGGREGATE-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(committee_epoch_id),
            HashPart::Str(aggregator_id),
            HashPart::Str(signer_bitmap_root),
            HashPart::Str(signed_payload_root),
        ],
        32,
    )
}

fn challenge_window_id(
    bundle_id: &str,
    checkpoint_id: &str,
    kind: PqChallengeKind,
    opened_at_height: u64,
) -> String {
    stable_hash_hex(
        "PQ-FINALITY-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(checkpoint_id),
            HashPart::Str(kind.as_str()),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

fn rotation_ticket_id(
    old_committee_epoch_id: &str,
    new_committee_epoch_id: &str,
    notice_root: &str,
    created_at_height: u64,
) -> String {
    stable_hash_hex(
        "PQ-FINALITY-ROTATION-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(old_committee_epoch_id),
            HashPart::Str(new_committee_epoch_id),
            HashPart::Str(notice_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

fn slashing_evidence_id(
    offender_signer_id: &str,
    committee_epoch_id: &str,
    bundle_id: &str,
    kind: PqSlashKind,
    evidence_root: &str,
) -> String {
    stable_hash_hex(
        "PQ-FINALITY-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(offender_signer_id),
            HashPart::Str(committee_epoch_id),
            HashPart::Str(bundle_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn fallback_attestation_id(
    checkpoint_id: &str,
    committee_epoch_id: &str,
    reason: PqFallbackReason,
    fallback_signature_root: &str,
) -> String {
    stable_hash_hex(
        "PQ-FINALITY-FALLBACK-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(committee_epoch_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(fallback_signature_root),
        ],
        32,
    )
}

fn public_finality_record_id(
    checkpoint_id: &str,
    bundle_id: &str,
    fallback_attestation_id: &str,
    finality_root: &str,
) -> String {
    stable_hash_hex(
        "PQ-FINALITY-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(checkpoint_id),
            HashPart::Str(bundle_id),
            HashPart::Str(fallback_attestation_id),
            HashPart::Str(finality_root),
        ],
        32,
    )
}
