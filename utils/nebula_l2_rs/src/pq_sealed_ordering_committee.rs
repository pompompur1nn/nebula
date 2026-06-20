use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqSealedOrderingCommitteeResult<T> = Result<T, String>;

pub const PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_VERSION: u32 = 1;
pub const PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL: &str =
    "nebula-pq-sealed-ordering-committee-v1";
pub const PQ_SEALED_ORDERING_COMMITTEE_SCHEMA_VERSION: u64 = 1;
pub const PQ_SEALED_ORDERING_COMMITTEE_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PQ_SEALED_ORDERING_COMMITTEE_SECURITY_MODEL: &str =
    "production-shaped-devnet-records-not-real-cryptography";
pub const PQ_SEALED_ORDERING_COMMITTEE_ML_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PQ_SEALED_ORDERING_COMMITTEE_PRIMARY_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PQ_SEALED_ORDERING_COMMITTEE_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_SEALED_ORDERING_COMMITTEE_THRESHOLD_REVEAL_SCHEME: &str =
    "ml-kem-threshold-batch-reveal-devnet-v1";
pub const PQ_SEALED_ORDERING_COMMITTEE_FAIR_WINDOW_POLICY: &str =
    "encrypted-arrival-window-anti-mev-tiebreak-v1";
pub const PQ_SEALED_ORDERING_COMMITTEE_ANTI_MEV_POLICY: &str =
    "commitment-first-privacy-budget-neutral-tiebreak-v1";
pub const PQ_SEALED_ORDERING_COMMITTEE_DEVNET_HEIGHT: u64 = 1_280;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PQ_SEALED_ORDERING_COMMITTEE_DEVNET_BRIDGE_ASSET_ID: &str = "xmr";
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_COMMITTEE_SIZE: u64 = 5;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_THRESHOLD: u64 = 4;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_WINDOW_BLOCKS: u64 = 3;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 1;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 4;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_FAST_LANE_DEADLINE_MS: u64 = 750;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_FAST_LANE_QUORUM_BPS: u64 = 6_700;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_PRIVATE_POLICY_TTL_BLOCKS: u64 = 720;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_MONERO_PRIORITY_BPS: u64 = 2_500;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_MAX_CAPSULE_BYTES: u64 = 256 * 1024;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_MAX_BATCH_BYTES: u64 = 4 * 1024 * 1024;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_MAX_CAPSULES_PER_WINDOW: u64 = 1_024;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_SLASH_BPS: u64 = 2_000;
pub const PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_PRIVACY_BUDGET_BPS: u64 = 5_000;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_BPS: u64 = 10_000;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_MEMBERS: usize = 128;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_WINDOWS: usize = 512;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_CAPSULES: usize = 8_192;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_REVEALS: usize = 1_024;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_ATTESTATIONS: usize = 8_192;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_FAST_LANES: usize = 64;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_POLICIES: usize = 1_024;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_MONERO_LANES: usize = 64;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_SLASHING_EVIDENCE: usize = 1_024;
pub const PQ_SEALED_ORDERING_COMMITTEE_MAX_PUBLIC_EVENTS: usize = 4_096;

const STATE_STATUS_BOOTSTRAPPING: &str = "bootstrapping";
const STATE_STATUS_ACTIVE: &str = "active";
const STATE_STATUS_REVEALING: &str = "revealing";
const STATE_STATUS_CHALLENGE_MODE: &str = "challenge_mode";
const STATE_STATUS_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqOrderingSignatureScheme {
    MlDsa65,
    MlDsa87,
    SlhDsaShake128s,
    HybridMlDsaSlhDsa,
}

impl PqOrderingSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => PQ_SEALED_ORDERING_COMMITTEE_PRIMARY_SIGNATURE_SCHEME,
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaShake128s => PQ_SEALED_ORDERING_COMMITTEE_BACKUP_SIGNATURE_SCHEME,
            Self::HybridMlDsaSlhDsa => "ML-DSA-65+SLH-DSA-SHAKE-128s",
        }
    }

    pub fn fallback_ready(self) -> bool {
        matches!(self, Self::SlhDsaShake128s | Self::HybridMlDsaSlhDsa)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedOrderingLaneKind {
    Standard,
    PrivateTransfer,
    PrivateContract,
    DefiSettlement,
    LowLatencyFastLane,
    MoneroBridgeDeposit,
    MoneroBridgeExit,
    ForcedInclusion,
    GovernanceEmergency,
}

impl SealedOrderingLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateContract => "private_contract",
            Self::DefiSettlement => "defi_settlement",
            Self::LowLatencyFastLane => "low_latency_fast_lane",
            Self::MoneroBridgeDeposit => "monero_bridge_deposit",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::ForcedInclusion => "forced_inclusion",
            Self::GovernanceEmergency => "governance_emergency",
        }
    }

    pub fn ordering_priority(self) -> u64 {
        match self {
            Self::GovernanceEmergency => 0,
            Self::ForcedInclusion => 1,
            Self::MoneroBridgeExit => 2,
            Self::MoneroBridgeDeposit => 3,
            Self::LowLatencyFastLane => 4,
            Self::PrivateContract => 5,
            Self::DefiSettlement => 6,
            Self::PrivateTransfer => 7,
            Self::Standard => 8,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer
                | Self::PrivateContract
                | Self::DefiSettlement
                | Self::LowLatencyFastLane
                | Self::MoneroBridgeDeposit
                | Self::MoneroBridgeExit
                | Self::ForcedInclusion
        )
    }

    pub fn monero_bridge(self) -> bool {
        matches!(self, Self::MoneroBridgeDeposit | Self::MoneroBridgeExit)
    }

    pub fn fast_lane(self) -> bool {
        matches!(self, Self::LowLatencyFastLane | Self::GovernanceEmergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeMemberStatus {
    Active,
    Standby,
    Muted,
    Retiring,
    Retired,
    Slashed,
}

impl CommitteeMemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Muted => "muted",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::Muted)
    }

    pub fn can_reveal(self) -> bool {
        matches!(self, Self::Active | Self::Muted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderCapsuleStatus {
    Submitted,
    FastLaneReserved,
    WindowLocked,
    RevealPending,
    Revealed,
    Ordered,
    Included,
    Rejected,
    Expired,
}

impl OrderCapsuleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::FastLaneReserved => "fast_lane_reserved",
            Self::WindowLocked => "window_locked",
            Self::RevealPending => "reveal_pending",
            Self::Revealed => "revealed",
            Self::Ordered => "ordered",
            Self::Included => "included",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::FastLaneReserved | Self::WindowLocked | Self::RevealPending
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FairOrderingWindowStatus {
    Collecting,
    Locked,
    Revealing,
    Ordering,
    Sealed,
    Challenged,
    Finalized,
}

impl FairOrderingWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Locked => "locked",
            Self::Revealing => "revealing",
            Self::Ordering => "ordering",
            Self::Sealed => "sealed",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
        }
    }

    pub fn accepts_capsules(self) -> bool {
        matches!(self, Self::Collecting)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchRevealStatus {
    Draft,
    ThresholdCommitted,
    SharesCollected,
    PlaintextRootPublished,
    Attested,
    Challenged,
    Finalized,
}

impl BatchRevealStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::ThresholdCommitted => "threshold_committed",
            Self::SharesCollected => "shares_collected",
            Self::PlaintextRootPublished => "plaintext_root_published",
            Self::Attested => "attested",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeAttestationKind {
    WindowLocked,
    BatchReveal,
    FairOrder,
    FastLanePreconfirmation,
    PrivatePolicyAdmission,
    MoneroPriorityAdmission,
    SlashingEvidence,
}

impl CommitteeAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowLocked => "window_locked",
            Self::BatchReveal => "batch_reveal",
            Self::FairOrder => "fair_order",
            Self::FastLanePreconfirmation => "fast_lane_preconfirmation",
            Self::PrivatePolicyAdmission => "private_policy_admission",
            Self::MoneroPriorityAdmission => "monero_priority_admission",
            Self::SlashingEvidence => "slashing_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TieBreakerKind {
    ArrivalCommitment,
    SealedEntropy,
    PrivateNullifier,
    MoneroAnchorAge,
    FastLaneDeadline,
    ForcedInclusionAge,
}

impl TieBreakerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArrivalCommitment => "arrival_commitment",
            Self::SealedEntropy => "sealed_entropy",
            Self::PrivateNullifier => "private_nullifier",
            Self::MoneroAnchorAge => "monero_anchor_age",
            Self::FastLaneDeadline => "fast_lane_deadline",
            Self::ForcedInclusionAge => "forced_inclusion_age",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateContractPolicyMode {
    StrictCallerPrivacy,
    EncryptedIntentOnly,
    AllowedSolverSet,
    MoneroBridgeOnly,
    EmergencyBypass,
}

impl PrivateContractPolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StrictCallerPrivacy => "strict_caller_privacy",
            Self::EncryptedIntentOnly => "encrypted_intent_only",
            Self::AllowedSolverSet => "allowed_solver_set",
            Self::MoneroBridgeOnly => "monero_bridge_only",
            Self::EmergencyBypass => "emergency_bypass",
        }
    }

    pub fn requires_capsule(self) -> bool {
        !matches!(self, Self::EmergencyBypass)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    EquivocatedOrder,
    PrematureReveal,
    InvalidShare,
    MissingReveal,
    FastLaneFavoritism,
    PolicyBypass,
    MoneroPriorityAbuse,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EquivocatedOrder => "equivocated_order",
            Self::PrematureReveal => "premature_reveal",
            Self::InvalidShare => "invalid_share",
            Self::MissingReveal => "missing_reveal",
            Self::FastLaneFavoritism => "fast_lane_favoritism",
            Self::PolicyBypass => "policy_bypass",
            Self::MoneroPriorityAbuse => "monero_priority_abuse",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSealedOrderingCommitteeConfig {
    pub config_id: String,
    pub chain_id: String,
    pub protocol_version: u32,
    pub schema_version: u64,
    pub hash_suite: String,
    pub security_model: String,
    pub ml_kem_scheme: String,
    pub primary_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub threshold_reveal_scheme: String,
    pub fair_window_policy: String,
    pub anti_mev_policy: String,
    pub committee_size: u64,
    pub threshold: u64,
    pub window_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub reveal_window_blocks: u64,
    pub fast_lane_deadline_ms: u64,
    pub fast_lane_quorum_bps: u64,
    pub private_policy_ttl_blocks: u64,
    pub monero_priority_bps: u64,
    pub max_capsule_bytes: u64,
    pub max_batch_bytes: u64,
    pub max_capsules_per_window: u64,
    pub default_slash_bps: u64,
    pub privacy_budget_bps: u64,
    pub fee_asset_id: String,
    pub bridge_asset_id: String,
}

impl PqSealedOrderingCommitteeConfig {
    pub fn devnet() -> Self {
        let config_id =
            pq_soc_config_id(CHAIN_ID, PQ_SEALED_ORDERING_COMMITTEE_DEVNET_FEE_ASSET_ID);
        Self {
            config_id,
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_VERSION,
            schema_version: PQ_SEALED_ORDERING_COMMITTEE_SCHEMA_VERSION,
            hash_suite: PQ_SEALED_ORDERING_COMMITTEE_HASH_SUITE.to_string(),
            security_model: PQ_SEALED_ORDERING_COMMITTEE_SECURITY_MODEL.to_string(),
            ml_kem_scheme: PQ_SEALED_ORDERING_COMMITTEE_ML_KEM_SCHEME.to_string(),
            primary_signature_scheme: PQ_SEALED_ORDERING_COMMITTEE_PRIMARY_SIGNATURE_SCHEME
                .to_string(),
            backup_signature_scheme: PQ_SEALED_ORDERING_COMMITTEE_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            threshold_reveal_scheme: PQ_SEALED_ORDERING_COMMITTEE_THRESHOLD_REVEAL_SCHEME
                .to_string(),
            fair_window_policy: PQ_SEALED_ORDERING_COMMITTEE_FAIR_WINDOW_POLICY.to_string(),
            anti_mev_policy: PQ_SEALED_ORDERING_COMMITTEE_ANTI_MEV_POLICY.to_string(),
            committee_size: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_COMMITTEE_SIZE,
            threshold: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_THRESHOLD,
            window_blocks: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_WINDOW_BLOCKS,
            reveal_delay_blocks: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_REVEAL_DELAY_BLOCKS,
            reveal_window_blocks: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_REVEAL_WINDOW_BLOCKS,
            fast_lane_deadline_ms: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_FAST_LANE_DEADLINE_MS,
            fast_lane_quorum_bps: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_FAST_LANE_QUORUM_BPS,
            private_policy_ttl_blocks:
                PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_PRIVATE_POLICY_TTL_BLOCKS,
            monero_priority_bps: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_MONERO_PRIORITY_BPS,
            max_capsule_bytes: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_MAX_CAPSULE_BYTES,
            max_batch_bytes: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_MAX_BATCH_BYTES,
            max_capsules_per_window: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_MAX_CAPSULES_PER_WINDOW,
            default_slash_bps: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_SLASH_BPS,
            privacy_budget_bps: PQ_SEALED_ORDERING_COMMITTEE_DEFAULT_PRIVACY_BUDGET_BPS,
            fee_asset_id: PQ_SEALED_ORDERING_COMMITTEE_DEVNET_FEE_ASSET_ID.to_string(),
            bridge_asset_id: PQ_SEALED_ORDERING_COMMITTEE_DEVNET_BRIDGE_ASSET_ID.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sealed_ordering_committee_config",
            "config_id": self.config_id,
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "security_model": self.security_model,
            "ml_kem_scheme": self.ml_kem_scheme,
            "primary_signature_scheme": self.primary_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "threshold_reveal_scheme": self.threshold_reveal_scheme,
            "fair_window_policy": self.fair_window_policy,
            "anti_mev_policy": self.anti_mev_policy,
            "committee_size": self.committee_size,
            "threshold": self.threshold,
            "window_blocks": self.window_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "reveal_window_blocks": self.reveal_window_blocks,
            "fast_lane_deadline_ms": self.fast_lane_deadline_ms,
            "fast_lane_quorum_bps": self.fast_lane_quorum_bps,
            "private_policy_ttl_blocks": self.private_policy_ttl_blocks,
            "monero_priority_bps": self.monero_priority_bps,
            "max_capsule_bytes": self.max_capsule_bytes,
            "max_batch_bytes": self.max_batch_bytes,
            "max_capsules_per_window": self.max_capsules_per_window,
            "default_slash_bps": self.default_slash_bps,
            "privacy_budget_bps": self.privacy_budget_bps,
            "fee_asset_id": self.fee_asset_id,
            "bridge_asset_id": self.bridge_asset_id,
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-SEALED-ORDERING-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("config.config_id", &self.config_id)?;
        ensure_non_empty("config.chain_id", &self.chain_id)?;
        ensure_non_empty("config.hash_suite", &self.hash_suite)?;
        ensure_non_empty("config.ml_kem_scheme", &self.ml_kem_scheme)?;
        ensure_non_empty(
            "config.primary_signature_scheme",
            &self.primary_signature_scheme,
        )?;
        ensure_non_empty(
            "config.backup_signature_scheme",
            &self.backup_signature_scheme,
        )?;
        ensure_non_empty(
            "config.threshold_reveal_scheme",
            &self.threshold_reveal_scheme,
        )?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("config.bridge_asset_id", &self.bridge_asset_id)?;
        ensure_positive("config.committee_size", self.committee_size)?;
        ensure_positive("config.threshold", self.threshold)?;
        if self.threshold > self.committee_size {
            return Err("config threshold cannot exceed committee size".to_string());
        }
        ensure_positive("config.window_blocks", self.window_blocks)?;
        ensure_positive("config.reveal_window_blocks", self.reveal_window_blocks)?;
        ensure_positive("config.max_capsule_bytes", self.max_capsule_bytes)?;
        ensure_positive("config.max_batch_bytes", self.max_batch_bytes)?;
        ensure_positive(
            "config.max_capsules_per_window",
            self.max_capsules_per_window,
        )?;
        ensure_bps("config.fast_lane_quorum_bps", self.fast_lane_quorum_bps)?;
        ensure_bps("config.monero_priority_bps", self.monero_priority_bps)?;
        ensure_bps("config.default_slash_bps", self.default_slash_bps)?;
        ensure_bps("config.privacy_budget_bps", self.privacy_budget_bps)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingCommitteeMember {
    pub member_id: String,
    pub operator_label: String,
    pub validator_key_commitment: String,
    pub ml_kem_ordering_key_root: String,
    pub ml_dsa_attestation_key_root: String,
    pub slh_dsa_backup_key_root: String,
    pub supported_signature_schemes: BTreeSet<PqOrderingSignatureScheme>,
    pub stake_weight: u64,
    pub reveal_weight: u64,
    pub latency_score_bps: u64,
    pub privacy_score_bps: u64,
    pub status: CommitteeMemberStatus,
    pub joined_height: u64,
    pub last_attested_height: u64,
}

impl OrderingCommitteeMember {
    pub fn devnet(index: u64, height: u64) -> PqSealedOrderingCommitteeResult<Self> {
        let operator_label = format!("devnet-pq-ordering-member-{index}");
        let member_id = pq_soc_member_id(&operator_label, index);
        let validator_key_commitment =
            pq_soc_string_commitment("PQ-SEALED-ORDERING-VALIDATOR-KEY", &operator_label);
        let ml_kem_ordering_key_root = pq_soc_string_commitment(
            "PQ-SEALED-ORDERING-ML-KEM-KEY",
            &format!("{operator_label}:ml-kem"),
        );
        let ml_dsa_attestation_key_root = pq_soc_string_commitment(
            "PQ-SEALED-ORDERING-ML-DSA-KEY",
            &format!("{operator_label}:ml-dsa"),
        );
        let slh_dsa_backup_key_root = pq_soc_string_commitment(
            "PQ-SEALED-ORDERING-SLH-DSA-KEY",
            &format!("{operator_label}:slh-dsa"),
        );
        let mut supported_signature_schemes = BTreeSet::new();
        supported_signature_schemes.insert(PqOrderingSignatureScheme::MlDsa65);
        supported_signature_schemes.insert(PqOrderingSignatureScheme::SlhDsaShake128s);
        let member = Self {
            member_id,
            operator_label,
            validator_key_commitment,
            ml_kem_ordering_key_root,
            ml_dsa_attestation_key_root,
            slh_dsa_backup_key_root,
            supported_signature_schemes,
            stake_weight: 1_000 + index * 125,
            reveal_weight: 1_000,
            latency_score_bps: 9_200_u64.saturating_sub(index * 150),
            privacy_score_bps: 9_600_u64.saturating_sub(index * 75),
            status: CommitteeMemberStatus::Active,
            joined_height: height.saturating_sub(240),
            last_attested_height: height,
        };
        member.validate()?;
        Ok(member)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_ordering_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "member_id": self.member_id,
            "operator_label": self.operator_label,
            "validator_key_commitment": self.validator_key_commitment,
            "ml_kem_ordering_key_root": self.ml_kem_ordering_key_root,
            "ml_dsa_attestation_key_root": self.ml_dsa_attestation_key_root,
            "slh_dsa_backup_key_root": self.slh_dsa_backup_key_root,
            "supported_signature_schemes": self.supported_signature_schemes.iter().map(|scheme| scheme.as_str()).collect::<Vec<_>>(),
            "stake_weight": self.stake_weight,
            "reveal_weight": self.reveal_weight,
            "latency_score_bps": self.latency_score_bps,
            "privacy_score_bps": self.privacy_score_bps,
            "status": self.status.as_str(),
            "joined_height": self.joined_height,
            "last_attested_height": self.last_attested_height,
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-SEALED-ORDERING-MEMBER", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("member.member_id", &self.member_id)?;
        ensure_non_empty("member.operator_label", &self.operator_label)?;
        ensure_non_empty(
            "member.validator_key_commitment",
            &self.validator_key_commitment,
        )?;
        ensure_non_empty(
            "member.ml_kem_ordering_key_root",
            &self.ml_kem_ordering_key_root,
        )?;
        ensure_non_empty(
            "member.ml_dsa_attestation_key_root",
            &self.ml_dsa_attestation_key_root,
        )?;
        ensure_non_empty(
            "member.slh_dsa_backup_key_root",
            &self.slh_dsa_backup_key_root,
        )?;
        ensure_positive("member.stake_weight", self.stake_weight)?;
        ensure_positive("member.reveal_weight", self.reveal_weight)?;
        ensure_bps("member.latency_score_bps", self.latency_score_bps)?;
        ensure_bps("member.privacy_score_bps", self.privacy_score_bps)?;
        if self.supported_signature_schemes.is_empty() {
            return Err("member supported signature schemes cannot be empty".to_string());
        }
        if !self
            .supported_signature_schemes
            .iter()
            .any(|scheme| scheme.fallback_ready())
        {
            return Err("member must advertise a backup pq signature scheme".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOrderCapsule {
    pub capsule_id: String,
    pub lane: SealedOrderingLaneKind,
    pub window_id: String,
    pub submitter_commitment: String,
    pub private_policy_id: Option<String>,
    pub monero_lane_id: Option<String>,
    pub payload_ciphertext_root: String,
    pub ml_kem_ciphertext_root: String,
    pub replay_nullifier: String,
    pub arrival_commitment: String,
    pub encrypted_tip_commitment: String,
    pub declared_payload_bytes: u64,
    pub max_fee_micro_units: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub fast_lane_requested: bool,
    pub status: OrderCapsuleStatus,
}

impl SealedOrderCapsule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: SealedOrderingLaneKind,
        window_id: &str,
        submitter_label: &str,
        private_policy_id: Option<String>,
        monero_lane_id: Option<String>,
        payload_bytes: u64,
        max_fee_micro_units: u64,
        submitted_height: u64,
        expires_height: u64,
    ) -> PqSealedOrderingCommitteeResult<Self> {
        ensure_non_empty("capsule.window_id", window_id)?;
        ensure_non_empty("capsule.submitter_label", submitter_label)?;
        let submitter_commitment =
            pq_soc_string_commitment("PQ-SEALED-ORDERING-SUBMITTER", submitter_label);
        let payload_ciphertext_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-PAYLOAD-CIPHERTEXT",
            &json!({
                "submitter": submitter_commitment,
                "lane": lane.as_str(),
                "payload_bytes": payload_bytes,
                "submitted_height": submitted_height,
            }),
        );
        let ml_kem_ciphertext_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-ML-KEM-CIPHERTEXT",
            &json!({
                "payload_ciphertext_root": payload_ciphertext_root,
                "window_id": window_id,
                "lane": lane.as_str(),
            }),
        );
        let replay_nullifier = pq_soc_string_commitment(
            "PQ-SEALED-ORDERING-REPLAY-NULLIFIER",
            &format!("{submitter_label}:{window_id}:{}", lane.as_str()),
        );
        let arrival_commitment = pq_soc_arrival_commitment(
            window_id,
            &submitter_commitment,
            submitted_height,
            lane.ordering_priority(),
        );
        let encrypted_tip_commitment = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-ENCRYPTED-TIP",
            &json!({
                "arrival_commitment": arrival_commitment,
                "fee": max_fee_micro_units,
            }),
        );
        let capsule_id = pq_soc_capsule_id(
            window_id,
            lane,
            &submitter_commitment,
            &payload_ciphertext_root,
        );
        let capsule = Self {
            capsule_id,
            lane,
            window_id: window_id.to_string(),
            submitter_commitment,
            private_policy_id,
            monero_lane_id,
            payload_ciphertext_root,
            ml_kem_ciphertext_root,
            replay_nullifier,
            arrival_commitment,
            encrypted_tip_commitment,
            declared_payload_bytes: payload_bytes,
            max_fee_micro_units,
            submitted_height,
            expires_height,
            fast_lane_requested: lane.fast_lane(),
            status: if lane.fast_lane() {
                OrderCapsuleStatus::FastLaneReserved
            } else {
                OrderCapsuleStatus::Submitted
            },
        };
        capsule.validate()?;
        Ok(capsule)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sealed_order_capsule",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "capsule_id": self.capsule_id,
            "lane": self.lane.as_str(),
            "window_id": self.window_id,
            "submitter_commitment": self.submitter_commitment,
            "private_policy_id": self.private_policy_id,
            "monero_lane_id": self.monero_lane_id,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "ml_kem_ciphertext_root": self.ml_kem_ciphertext_root,
            "replay_nullifier": self.replay_nullifier,
            "arrival_commitment": self.arrival_commitment,
            "encrypted_tip_commitment": self.encrypted_tip_commitment,
            "declared_payload_bytes": self.declared_payload_bytes,
            "max_fee_micro_units": self.max_fee_micro_units,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "fast_lane_requested": self.fast_lane_requested,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-SEALED-ORDER-CAPSULE", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("capsule.capsule_id", &self.capsule_id)?;
        ensure_non_empty("capsule.window_id", &self.window_id)?;
        ensure_non_empty("capsule.submitter_commitment", &self.submitter_commitment)?;
        ensure_non_empty(
            "capsule.payload_ciphertext_root",
            &self.payload_ciphertext_root,
        )?;
        ensure_non_empty(
            "capsule.ml_kem_ciphertext_root",
            &self.ml_kem_ciphertext_root,
        )?;
        ensure_non_empty("capsule.replay_nullifier", &self.replay_nullifier)?;
        ensure_non_empty("capsule.arrival_commitment", &self.arrival_commitment)?;
        ensure_positive(
            "capsule.declared_payload_bytes",
            self.declared_payload_bytes,
        )?;
        if self.expires_height <= self.submitted_height {
            return Err("capsule expires height must be after submitted height".to_string());
        }
        if self.lane.privacy_sensitive() && self.ml_kem_ciphertext_root.is_empty() {
            return Err("privacy sensitive capsule requires ML-KEM ciphertext root".to_string());
        }
        if self.lane.monero_bridge() && self.monero_lane_id.is_none() {
            return Err("monero bridge capsule requires monero lane id".to_string());
        }
        if matches!(self.lane, SealedOrderingLaneKind::PrivateContract)
            && self.private_policy_id.is_none()
        {
            return Err("private contract capsule requires private policy id".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingWindow {
    pub window_id: String,
    pub epoch: u64,
    pub committee_id: String,
    pub start_height: u64,
    pub lock_height: u64,
    pub reveal_start_height: u64,
    pub reveal_deadline_height: u64,
    pub ordering_seed: String,
    pub capsule_ids: Vec<String>,
    pub ordered_capsule_ids: Vec<String>,
    pub tie_breakers: BTreeMap<String, TieBreakerKind>,
    pub anti_mev_entropy_root: String,
    pub status: FairOrderingWindowStatus,
}

impl FairOrderingWindow {
    pub fn new(
        epoch: u64,
        committee_id: &str,
        start_height: u64,
        config: &PqSealedOrderingCommitteeConfig,
    ) -> PqSealedOrderingCommitteeResult<Self> {
        ensure_non_empty("window.committee_id", committee_id)?;
        let lock_height = start_height.saturating_add(config.window_blocks);
        let reveal_start_height = lock_height.saturating_add(config.reveal_delay_blocks);
        let reveal_deadline_height =
            reveal_start_height.saturating_add(config.reveal_window_blocks);
        let window_id = pq_soc_window_id(epoch, committee_id, start_height);
        let ordering_seed = pq_soc_ordering_seed(&window_id, committee_id, epoch);
        let anti_mev_entropy_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-ANTI-MEV-ENTROPY",
            &json!({
                "window_id": window_id,
                "ordering_seed": ordering_seed,
                "policy": PQ_SEALED_ORDERING_COMMITTEE_ANTI_MEV_POLICY,
            }),
        );
        let window = Self {
            window_id,
            epoch,
            committee_id: committee_id.to_string(),
            start_height,
            lock_height,
            reveal_start_height,
            reveal_deadline_height,
            ordering_seed,
            capsule_ids: Vec::new(),
            ordered_capsule_ids: Vec::new(),
            tie_breakers: BTreeMap::new(),
            anti_mev_entropy_root,
            status: FairOrderingWindowStatus::Collecting,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn attach_capsule(
        &mut self,
        capsule_id: &str,
        tie_breaker: TieBreakerKind,
    ) -> PqSealedOrderingCommitteeResult<()> {
        ensure_non_empty("window.attach_capsule.capsule_id", capsule_id)?;
        if !self.capsule_ids.iter().any(|value| value == capsule_id) {
            self.capsule_ids.push(capsule_id.to_string());
        }
        self.tie_breakers
            .insert(capsule_id.to_string(), tie_breaker);
        self.validate()?;
        Ok(())
    }

    pub fn seal_order(
        &mut self,
        ordered_capsule_ids: Vec<String>,
    ) -> PqSealedOrderingCommitteeResult<()> {
        if ordered_capsule_ids.is_empty() {
            return Err("window ordered capsule ids cannot be empty".to_string());
        }
        for capsule_id in &ordered_capsule_ids {
            if !self.capsule_ids.iter().any(|known| known == capsule_id) {
                return Err("window ordered capsule missing from capsule set".to_string());
            }
        }
        self.ordered_capsule_ids = ordered_capsule_ids;
        self.status = FairOrderingWindowStatus::Sealed;
        self.validate()?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sealed_ordering_window",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "window_id": self.window_id,
            "epoch": self.epoch,
            "committee_id": self.committee_id,
            "start_height": self.start_height,
            "lock_height": self.lock_height,
            "reveal_start_height": self.reveal_start_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "ordering_seed": self.ordering_seed,
            "capsule_ids": self.capsule_ids,
            "ordered_capsule_ids": self.ordered_capsule_ids,
            "tie_breakers": self.tie_breakers.iter().map(|(id, kind)| json!({"capsule_id": id, "tie_breaker": kind.as_str()})).collect::<Vec<_>>(),
            "anti_mev_entropy_root": self.anti_mev_entropy_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-SEALED-ORDERING-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("window.window_id", &self.window_id)?;
        ensure_non_empty("window.committee_id", &self.committee_id)?;
        ensure_non_empty("window.ordering_seed", &self.ordering_seed)?;
        ensure_non_empty("window.anti_mev_entropy_root", &self.anti_mev_entropy_root)?;
        if self.lock_height <= self.start_height {
            return Err("window lock height must be after start height".to_string());
        }
        if self.reveal_start_height < self.lock_height {
            return Err("window reveal start cannot precede lock height".to_string());
        }
        if self.reveal_deadline_height <= self.reveal_start_height {
            return Err("window reveal deadline must be after reveal start".to_string());
        }
        for ordered_id in &self.ordered_capsule_ids {
            if !self
                .capsule_ids
                .iter()
                .any(|capsule_id| capsule_id == ordered_id)
            {
                return Err("window ordered capsule not present in capsule set".to_string());
            }
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdBatchReveal {
    pub reveal_id: String,
    pub window_id: String,
    pub committee_id: String,
    pub capsule_ids: Vec<String>,
    pub share_commitment_root: String,
    pub reveal_share_root: String,
    pub plaintext_batch_root: String,
    pub batch_transcript_root: String,
    pub collected_share_count: u64,
    pub required_share_count: u64,
    pub revealed_at_height: u64,
    pub status: BatchRevealStatus,
}

impl ThresholdBatchReveal {
    pub fn new(
        window: &FairOrderingWindow,
        required_share_count: u64,
        collected_share_count: u64,
        revealed_at_height: u64,
    ) -> PqSealedOrderingCommitteeResult<Self> {
        ensure_positive("reveal.required_share_count", required_share_count)?;
        ensure_positive("reveal.collected_share_count", collected_share_count)?;
        let share_commitment_root = pq_soc_string_set_root(
            "PQ-SEALED-ORDERING-REVEAL-SHARE-COMMITMENTS",
            &window.capsule_ids,
        );
        let reveal_share_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-REVEAL-SHARES",
            &json!({
                "window_id": window.window_id,
                "collected_share_count": collected_share_count,
                "required_share_count": required_share_count,
            }),
        );
        let plaintext_batch_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-PLAINTEXT-BATCH",
            &json!({
                "window_id": window.window_id,
                "ordered_capsule_ids": window.ordered_capsule_ids,
            }),
        );
        let batch_transcript_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-BATCH-TRANSCRIPT",
            &json!({
                "share_commitment_root": share_commitment_root,
                "reveal_share_root": reveal_share_root,
                "plaintext_batch_root": plaintext_batch_root,
            }),
        );
        let reveal_id = pq_soc_reveal_id(&window.window_id, &batch_transcript_root);
        let reveal = Self {
            reveal_id,
            window_id: window.window_id.clone(),
            committee_id: window.committee_id.clone(),
            capsule_ids: window.capsule_ids.clone(),
            share_commitment_root,
            reveal_share_root,
            plaintext_batch_root,
            batch_transcript_root,
            collected_share_count,
            required_share_count,
            revealed_at_height,
            status: if collected_share_count >= required_share_count {
                BatchRevealStatus::PlaintextRootPublished
            } else {
                BatchRevealStatus::SharesCollected
            },
        };
        reveal.validate()?;
        Ok(reveal)
    }

    pub fn threshold_met(&self) -> bool {
        self.collected_share_count >= self.required_share_count
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_threshold_batch_reveal",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "reveal_id": self.reveal_id,
            "window_id": self.window_id,
            "committee_id": self.committee_id,
            "capsule_ids": self.capsule_ids,
            "share_commitment_root": self.share_commitment_root,
            "reveal_share_root": self.reveal_share_root,
            "plaintext_batch_root": self.plaintext_batch_root,
            "batch_transcript_root": self.batch_transcript_root,
            "collected_share_count": self.collected_share_count,
            "required_share_count": self.required_share_count,
            "revealed_at_height": self.revealed_at_height,
            "threshold_met": self.threshold_met(),
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-THRESHOLD-BATCH-REVEAL", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("reveal.reveal_id", &self.reveal_id)?;
        ensure_non_empty("reveal.window_id", &self.window_id)?;
        ensure_non_empty("reveal.committee_id", &self.committee_id)?;
        ensure_non_empty("reveal.share_commitment_root", &self.share_commitment_root)?;
        ensure_non_empty("reveal.reveal_share_root", &self.reveal_share_root)?;
        ensure_non_empty("reveal.plaintext_batch_root", &self.plaintext_batch_root)?;
        ensure_non_empty("reveal.batch_transcript_root", &self.batch_transcript_root)?;
        ensure_positive("reveal.required_share_count", self.required_share_count)?;
        if self.collected_share_count < self.required_share_count
            && matches!(
                self.status,
                BatchRevealStatus::PlaintextRootPublished
                    | BatchRevealStatus::Attested
                    | BatchRevealStatus::Finalized
            )
        {
            return Err("reveal cannot publish plaintext before threshold is met".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeAttestation {
    pub attestation_id: String,
    pub kind: CommitteeAttestationKind,
    pub subject_id: String,
    pub committee_id: String,
    pub signer_member_ids: Vec<String>,
    pub signature_scheme: PqOrderingSignatureScheme,
    pub signature_root: String,
    pub transcript_root: String,
    pub attested_height: u64,
    pub quorum_bps: u64,
}

impl CommitteeAttestation {
    pub fn new(
        kind: CommitteeAttestationKind,
        subject_id: &str,
        committee_id: &str,
        signer_member_ids: Vec<String>,
        signature_scheme: PqOrderingSignatureScheme,
        attested_height: u64,
        quorum_bps: u64,
    ) -> PqSealedOrderingCommitteeResult<Self> {
        ensure_non_empty("attestation.subject_id", subject_id)?;
        ensure_non_empty("attestation.committee_id", committee_id)?;
        if signer_member_ids.is_empty() {
            return Err("attestation signer member ids cannot be empty".to_string());
        }
        ensure_bps("attestation.quorum_bps", quorum_bps)?;
        let transcript_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-ATTESTATION-TRANSCRIPT",
            &json!({
                "kind": kind.as_str(),
                "subject_id": subject_id,
                "committee_id": committee_id,
                "signer_member_ids": signer_member_ids,
                "attested_height": attested_height,
            }),
        );
        let signature_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-COMMITTEE-SIGNATURE",
            &json!({
                "signature_scheme": signature_scheme.as_str(),
                "transcript_root": transcript_root,
            }),
        );
        let attestation_id = pq_soc_attestation_id(kind, subject_id, committee_id, &signature_root);
        let attestation = Self {
            attestation_id,
            kind,
            subject_id: subject_id.to_string(),
            committee_id: committee_id.to_string(),
            signer_member_ids,
            signature_scheme,
            signature_root,
            transcript_root,
            attested_height,
            quorum_bps,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_ordering_committee_attestation",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "attestation_id": self.attestation_id,
            "attestation_kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "committee_id": self.committee_id,
            "signer_member_ids": self.signer_member_ids,
            "signature_scheme": self.signature_scheme.as_str(),
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "attested_height": self.attested_height,
            "quorum_bps": self.quorum_bps,
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-ORDERING-COMMITTEE-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("attestation.attestation_id", &self.attestation_id)?;
        ensure_non_empty("attestation.subject_id", &self.subject_id)?;
        ensure_non_empty("attestation.committee_id", &self.committee_id)?;
        ensure_non_empty("attestation.signature_root", &self.signature_root)?;
        ensure_non_empty("attestation.transcript_root", &self.transcript_root)?;
        ensure_bps("attestation.quorum_bps", self.quorum_bps)?;
        if self.signer_member_ids.is_empty() {
            return Err("attestation signer set cannot be empty".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLaneReservation {
    pub lane_id: String,
    pub lane: SealedOrderingLaneKind,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub reserved_capacity_bytes: u64,
    pub max_latency_ms: u64,
    pub quorum_bps: u64,
    pub active_from_height: u64,
    pub active_until_height: u64,
    pub admitted_capsule_ids: Vec<String>,
}

impl FastLaneReservation {
    pub fn new(
        label: &str,
        lane: SealedOrderingLaneKind,
        fee_asset_id: &str,
        height: u64,
        max_latency_ms: u64,
        quorum_bps: u64,
    ) -> PqSealedOrderingCommitteeResult<Self> {
        ensure_non_empty("fast_lane.label", label)?;
        ensure_non_empty("fast_lane.fee_asset_id", fee_asset_id)?;
        if !lane.fast_lane() {
            return Err("fast lane reservation requires fast lane kind".to_string());
        }
        ensure_positive("fast_lane.max_latency_ms", max_latency_ms)?;
        ensure_bps("fast_lane.quorum_bps", quorum_bps)?;
        let sponsor_commitment =
            pq_soc_string_commitment("PQ-SEALED-ORDERING-FAST-LANE-SPONSOR", label);
        let lane_id = pq_soc_fast_lane_id(label, lane, height);
        let reservation = Self {
            lane_id,
            lane,
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            reserved_capacity_bytes: 512 * 1024,
            max_latency_ms,
            quorum_bps,
            active_from_height: height,
            active_until_height: height.saturating_add(480),
            admitted_capsule_ids: Vec::new(),
        };
        reservation.validate()?;
        Ok(reservation)
    }

    pub fn admit_capsule(&mut self, capsule_id: &str) -> PqSealedOrderingCommitteeResult<()> {
        ensure_non_empty("fast_lane.admit_capsule.capsule_id", capsule_id)?;
        if !self
            .admitted_capsule_ids
            .iter()
            .any(|known| known == capsule_id)
        {
            self.admitted_capsule_ids.push(capsule_id.to_string());
        }
        self.validate()?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sealed_ordering_fast_lane_reservation",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "reserved_capacity_bytes": self.reserved_capacity_bytes,
            "max_latency_ms": self.max_latency_ms,
            "quorum_bps": self.quorum_bps,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "admitted_capsule_ids": self.admitted_capsule_ids,
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-SEALED-ORDERING-FAST-LANE", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("fast_lane.lane_id", &self.lane_id)?;
        ensure_non_empty("fast_lane.sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("fast_lane.fee_asset_id", &self.fee_asset_id)?;
        ensure_positive(
            "fast_lane.reserved_capacity_bytes",
            self.reserved_capacity_bytes,
        )?;
        ensure_positive("fast_lane.max_latency_ms", self.max_latency_ms)?;
        ensure_bps("fast_lane.quorum_bps", self.quorum_bps)?;
        if self.active_until_height <= self.active_from_height {
            return Err("fast lane active until must be after active from".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractOrderingPolicy {
    pub policy_id: String,
    pub contract_commitment: String,
    pub mode: PrivateContractPolicyMode,
    pub allowed_lane: SealedOrderingLaneKind,
    pub allowed_solver_root: String,
    pub privacy_budget_bps: u64,
    pub max_reorder_distance: u64,
    pub active_from_height: u64,
    pub expires_height: u64,
    pub requires_threshold_reveal: bool,
}

impl PrivateContractOrderingPolicy {
    pub fn new(
        contract_label: &str,
        mode: PrivateContractPolicyMode,
        allowed_lane: SealedOrderingLaneKind,
        height: u64,
        ttl_blocks: u64,
        privacy_budget_bps: u64,
    ) -> PqSealedOrderingCommitteeResult<Self> {
        ensure_non_empty("private_policy.contract_label", contract_label)?;
        ensure_bps("private_policy.privacy_budget_bps", privacy_budget_bps)?;
        let contract_commitment =
            pq_soc_string_commitment("PQ-SEALED-ORDERING-PRIVATE-CONTRACT", contract_label);
        let allowed_solver_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-ALLOWED-SOLVERS",
            &json!({
                "contract_commitment": contract_commitment,
                "mode": mode.as_str(),
            }),
        );
        let policy_id = pq_soc_private_policy_id(&contract_commitment, mode, height);
        let policy = Self {
            policy_id,
            contract_commitment,
            mode,
            allowed_lane,
            allowed_solver_root,
            privacy_budget_bps,
            max_reorder_distance: 2,
            active_from_height: height,
            expires_height: height.saturating_add(ttl_blocks),
            requires_threshold_reveal: mode.requires_capsule(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_contract_ordering_policy",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "policy_id": self.policy_id,
            "contract_commitment": self.contract_commitment,
            "mode": self.mode.as_str(),
            "allowed_lane": self.allowed_lane.as_str(),
            "allowed_solver_root": self.allowed_solver_root,
            "privacy_budget_bps": self.privacy_budget_bps,
            "max_reorder_distance": self.max_reorder_distance,
            "active_from_height": self.active_from_height,
            "expires_height": self.expires_height,
            "requires_threshold_reveal": self.requires_threshold_reveal,
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-PRIVATE-CONTRACT-ORDERING-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("private_policy.policy_id", &self.policy_id)?;
        ensure_non_empty(
            "private_policy.contract_commitment",
            &self.contract_commitment,
        )?;
        ensure_non_empty(
            "private_policy.allowed_solver_root",
            &self.allowed_solver_root,
        )?;
        ensure_bps("private_policy.privacy_budget_bps", self.privacy_budget_bps)?;
        if self.expires_height <= self.active_from_height {
            return Err("private policy expires height must be after active height".to_string());
        }
        if self.mode.requires_capsule() && !self.requires_threshold_reveal {
            return Err("private policy mode requires threshold reveal".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgePriorityLane {
    pub lane_id: String,
    pub lane: SealedOrderingLaneKind,
    pub bridge_account_commitment: String,
    pub monero_anchor_root: String,
    pub view_tag_batch_root: String,
    pub priority_bps: u64,
    pub min_confirmations: u64,
    pub max_delay_blocks: u64,
    pub reserved_capsule_ids: Vec<String>,
    pub active: bool,
}

impl MoneroBridgePriorityLane {
    pub fn new(
        bridge_label: &str,
        lane: SealedOrderingLaneKind,
        priority_bps: u64,
    ) -> PqSealedOrderingCommitteeResult<Self> {
        ensure_non_empty("monero_lane.bridge_label", bridge_label)?;
        if !lane.monero_bridge() {
            return Err("monero priority lane requires monero bridge lane kind".to_string());
        }
        ensure_bps("monero_lane.priority_bps", priority_bps)?;
        let bridge_account_commitment =
            pq_soc_string_commitment("PQ-SEALED-ORDERING-MONERO-BRIDGE-ACCOUNT", bridge_label);
        let monero_anchor_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-MONERO-ANCHOR",
            &json!({
                "bridge_account_commitment": bridge_account_commitment,
                "lane": lane.as_str(),
            }),
        );
        let view_tag_batch_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-MONERO-VIEW-TAGS",
            &json!({
                "bridge_account_commitment": bridge_account_commitment,
                "policy": "priority-without-address-disclosure",
            }),
        );
        let lane_id = pq_soc_monero_lane_id(&bridge_account_commitment, lane);
        let lane = Self {
            lane_id,
            lane,
            bridge_account_commitment,
            monero_anchor_root,
            view_tag_batch_root,
            priority_bps,
            min_confirmations: 10,
            max_delay_blocks: 8,
            reserved_capsule_ids: Vec::new(),
            active: true,
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn reserve_capsule(&mut self, capsule_id: &str) -> PqSealedOrderingCommitteeResult<()> {
        ensure_non_empty("monero_lane.reserve_capsule.capsule_id", capsule_id)?;
        if !self
            .reserved_capsule_ids
            .iter()
            .any(|known| known == capsule_id)
        {
            self.reserved_capsule_ids.push(capsule_id.to_string());
        }
        self.validate()?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_monero_bridge_priority_lane",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "bridge_account_commitment": self.bridge_account_commitment,
            "monero_anchor_root": self.monero_anchor_root,
            "view_tag_batch_root": self.view_tag_batch_root,
            "priority_bps": self.priority_bps,
            "min_confirmations": self.min_confirmations,
            "max_delay_blocks": self.max_delay_blocks,
            "reserved_capsule_ids": self.reserved_capsule_ids,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-MONERO-BRIDGE-PRIORITY-LANE", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("monero_lane.lane_id", &self.lane_id)?;
        ensure_non_empty(
            "monero_lane.bridge_account_commitment",
            &self.bridge_account_commitment,
        )?;
        ensure_non_empty("monero_lane.monero_anchor_root", &self.monero_anchor_root)?;
        ensure_non_empty("monero_lane.view_tag_batch_root", &self.view_tag_batch_root)?;
        ensure_bps("monero_lane.priority_bps", self.priority_bps)?;
        ensure_positive("monero_lane.min_confirmations", self.min_confirmations)?;
        ensure_positive("monero_lane.max_delay_blocks", self.max_delay_blocks)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingSlashingEvidence {
    pub evidence_id: String,
    pub kind: SlashingEvidenceKind,
    pub accused_member_id: String,
    pub window_id: String,
    pub capsule_id: Option<String>,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slash_bps: u64,
    pub submitted_height: u64,
    pub resolved: bool,
}

impl OrderingSlashingEvidence {
    pub fn new(
        kind: SlashingEvidenceKind,
        accused_member_id: &str,
        window_id: &str,
        capsule_id: Option<String>,
        challenger_label: &str,
        slash_bps: u64,
        submitted_height: u64,
    ) -> PqSealedOrderingCommitteeResult<Self> {
        ensure_non_empty("slashing.accused_member_id", accused_member_id)?;
        ensure_non_empty("slashing.window_id", window_id)?;
        ensure_non_empty("slashing.challenger_label", challenger_label)?;
        ensure_bps("slashing.slash_bps", slash_bps)?;
        let challenger_commitment =
            pq_soc_string_commitment("PQ-SEALED-ORDERING-SLASH-CHALLENGER", challenger_label);
        let evidence_root = pq_soc_payload_root(
            "PQ-SEALED-ORDERING-SLASHING-EVIDENCE",
            &json!({
                "kind": kind.as_str(),
                "accused_member_id": accused_member_id,
                "window_id": window_id,
                "capsule_id": capsule_id,
                "submitted_height": submitted_height,
            }),
        );
        let evidence_id = pq_soc_slashing_evidence_id(kind, accused_member_id, &evidence_root);
        let evidence = Self {
            evidence_id,
            kind,
            accused_member_id: accused_member_id.to_string(),
            window_id: window_id.to_string(),
            capsule_id,
            evidence_root,
            challenger_commitment,
            slash_bps,
            submitted_height,
            resolved: false,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_ordering_slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.kind.as_str(),
            "accused_member_id": self.accused_member_id,
            "window_id": self.window_id,
            "capsule_id": self.capsule_id,
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "slash_bps": self.slash_bps,
            "submitted_height": self.submitted_height,
            "resolved": self.resolved,
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-ORDERING-SLASHING-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("slashing.evidence_id", &self.evidence_id)?;
        ensure_non_empty("slashing.accused_member_id", &self.accused_member_id)?;
        ensure_non_empty("slashing.window_id", &self.window_id)?;
        ensure_non_empty("slashing.evidence_root", &self.evidence_root)?;
        ensure_non_empty(
            "slashing.challenger_commitment",
            &self.challenger_commitment,
        )?;
        ensure_bps("slashing.slash_bps", self.slash_bps)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingPublicEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}

impl OrderingPublicEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
        height: u64,
    ) -> PqSealedOrderingCommitteeResult<Self> {
        ensure_non_empty("event.event_kind", event_kind)?;
        ensure_non_empty("event.subject_id", subject_id)?;
        let payload_root = pq_soc_payload_root("PQ-SEALED-ORDERING-EVENT-PAYLOAD", payload);
        let event_id = pq_soc_event_id(event_kind, subject_id, &payload_root, height);
        let event = Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            height,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sealed_ordering_public_event",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
        })
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        ensure_non_empty("event.event_id", &self.event_id)?;
        ensure_non_empty("event.event_kind", &self.event_kind)?;
        ensure_non_empty("event.subject_id", &self.subject_id)?;
        ensure_non_empty("event.payload_root", &self.payload_root)?;
        Ok(pq_soc_payload_root(
            "PQ-SEALED-ORDERING-PUBLIC-EVENT",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSealedOrderingCommitteeRoots {
    pub config_root: String,
    pub member_root: String,
    pub window_root: String,
    pub capsule_root: String,
    pub reveal_root: String,
    pub attestation_root: String,
    pub fast_lane_root: String,
    pub private_policy_root: String,
    pub monero_lane_root: String,
    pub slashing_evidence_root: String,
    pub public_event_root: String,
}

impl PqSealedOrderingCommitteeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "member_root": self.member_root,
            "window_root": self.window_root,
            "capsule_root": self.capsule_root,
            "reveal_root": self.reveal_root,
            "attestation_root": self.attestation_root,
            "fast_lane_root": self.fast_lane_root,
            "private_policy_root": self.private_policy_root,
            "monero_lane_root": self.monero_lane_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "public_event_root": self.public_event_root,
        })
    }

    pub fn state_root(&self) -> String {
        pq_soc_payload_root("PQ-SEALED-ORDERING-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSealedOrderingCommitteeCounters {
    pub member_count: u64,
    pub active_member_count: u64,
    pub window_count: u64,
    pub collecting_window_count: u64,
    pub capsule_count: u64,
    pub open_capsule_count: u64,
    pub fast_lane_capsule_count: u64,
    pub monero_capsule_count: u64,
    pub reveal_count: u64,
    pub threshold_reveal_count: u64,
    pub attestation_count: u64,
    pub fast_lane_count: u64,
    pub private_policy_count: u64,
    pub monero_lane_count: u64,
    pub slashing_evidence_count: u64,
    pub unresolved_slashing_evidence_count: u64,
    pub public_event_count: u64,
}

impl PqSealedOrderingCommitteeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "member_count": self.member_count,
            "active_member_count": self.active_member_count,
            "window_count": self.window_count,
            "collecting_window_count": self.collecting_window_count,
            "capsule_count": self.capsule_count,
            "open_capsule_count": self.open_capsule_count,
            "fast_lane_capsule_count": self.fast_lane_capsule_count,
            "monero_capsule_count": self.monero_capsule_count,
            "reveal_count": self.reveal_count,
            "threshold_reveal_count": self.threshold_reveal_count,
            "attestation_count": self.attestation_count,
            "fast_lane_count": self.fast_lane_count,
            "private_policy_count": self.private_policy_count,
            "monero_lane_count": self.monero_lane_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "unresolved_slashing_evidence_count": self.unresolved_slashing_evidence_count,
            "public_event_count": self.public_event_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSealedOrderingCommitteeState {
    pub config: PqSealedOrderingCommitteeConfig,
    pub height: u64,
    pub epoch: u64,
    pub committee_id: String,
    pub status: String,
    pub members: BTreeMap<String, OrderingCommitteeMember>,
    pub windows: BTreeMap<String, FairOrderingWindow>,
    pub capsules: BTreeMap<String, SealedOrderCapsule>,
    pub batch_reveals: BTreeMap<String, ThresholdBatchReveal>,
    pub attestations: BTreeMap<String, CommitteeAttestation>,
    pub fast_lanes: BTreeMap<String, FastLaneReservation>,
    pub private_policies: BTreeMap<String, PrivateContractOrderingPolicy>,
    pub monero_lanes: BTreeMap<String, MoneroBridgePriorityLane>,
    pub slashing_evidence: BTreeMap<String, OrderingSlashingEvidence>,
    pub public_events: BTreeMap<String, OrderingPublicEvent>,
}

impl PqSealedOrderingCommitteeState {
    pub fn devnet() -> PqSealedOrderingCommitteeResult<Self> {
        let config = PqSealedOrderingCommitteeConfig::devnet();
        let height = PQ_SEALED_ORDERING_COMMITTEE_DEVNET_HEIGHT;
        let epoch = height / 120;
        let mut members = BTreeMap::new();
        for index in 0..config.committee_size {
            let member = OrderingCommitteeMember::devnet(index, height)?;
            members.insert(member.member_id.clone(), member);
        }
        let member_ids = members.keys().cloned().collect::<Vec<_>>();
        let committee_id = pq_soc_committee_id(epoch, &member_ids);

        let mut state = Self {
            config: config.clone(),
            height,
            epoch,
            committee_id: committee_id.clone(),
            status: STATE_STATUS_ACTIVE.to_string(),
            members,
            windows: BTreeMap::new(),
            capsules: BTreeMap::new(),
            batch_reveals: BTreeMap::new(),
            attestations: BTreeMap::new(),
            fast_lanes: BTreeMap::new(),
            private_policies: BTreeMap::new(),
            monero_lanes: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            public_events: BTreeMap::new(),
        };

        let private_policy = PrivateContractOrderingPolicy::new(
            "devnet-private-amm-router",
            PrivateContractPolicyMode::AllowedSolverSet,
            SealedOrderingLaneKind::PrivateContract,
            height.saturating_sub(16),
            config.private_policy_ttl_blocks,
            config.privacy_budget_bps,
        )?;
        let private_policy_id = private_policy.policy_id.clone();
        state.insert_private_policy(private_policy)?;

        let mut monero_exit_lane = MoneroBridgePriorityLane::new(
            "devnet-monero-exit-vault",
            SealedOrderingLaneKind::MoneroBridgeExit,
            config.monero_priority_bps,
        )?;
        let monero_exit_lane_id = monero_exit_lane.lane_id.clone();

        let monero_deposit_lane = MoneroBridgePriorityLane::new(
            "devnet-monero-deposit-vault",
            SealedOrderingLaneKind::MoneroBridgeDeposit,
            config.monero_priority_bps.saturating_sub(500),
        )?;
        state.insert_monero_lane(monero_deposit_lane)?;

        let mut fast_lane = FastLaneReservation::new(
            "devnet-low-latency-auction",
            SealedOrderingLaneKind::LowLatencyFastLane,
            &config.fee_asset_id,
            height.saturating_sub(4),
            config.fast_lane_deadline_ms,
            config.fast_lane_quorum_bps,
        )?;
        let fast_lane_id = fast_lane.lane_id.clone();

        let mut window = FairOrderingWindow::new(
            epoch,
            &committee_id,
            height.saturating_sub(config.window_blocks),
            &config,
        )?;

        let standard_capsule = SealedOrderCapsule::new(
            SealedOrderingLaneKind::Standard,
            &window.window_id,
            "devnet-wallet-standard-transfer",
            None,
            None,
            1_024,
            2_000,
            height.saturating_sub(2),
            height.saturating_add(12),
        )?;
        let private_capsule = SealedOrderCapsule::new(
            SealedOrderingLaneKind::PrivateContract,
            &window.window_id,
            "devnet-private-contract-call",
            Some(private_policy_id.clone()),
            None,
            8_192,
            4_500,
            height.saturating_sub(2),
            height.saturating_add(12),
        )?;
        let fast_capsule = SealedOrderCapsule::new(
            SealedOrderingLaneKind::LowLatencyFastLane,
            &window.window_id,
            "devnet-fast-lane-swap",
            None,
            None,
            4_096,
            7_500,
            height.saturating_sub(1),
            height.saturating_add(8),
        )?;
        let monero_capsule = SealedOrderCapsule::new(
            SealedOrderingLaneKind::MoneroBridgeExit,
            &window.window_id,
            "devnet-monero-exit-intent",
            None,
            Some(monero_exit_lane_id.clone()),
            2_048,
            3_000,
            height.saturating_sub(1),
            height.saturating_add(18),
        )?;

        window.attach_capsule(
            &standard_capsule.capsule_id,
            TieBreakerKind::ArrivalCommitment,
        )?;
        window.attach_capsule(
            &private_capsule.capsule_id,
            TieBreakerKind::PrivateNullifier,
        )?;
        window.attach_capsule(&fast_capsule.capsule_id, TieBreakerKind::FastLaneDeadline)?;
        window.attach_capsule(&monero_capsule.capsule_id, TieBreakerKind::MoneroAnchorAge)?;
        let ordered_ids = vec![
            monero_capsule.capsule_id.clone(),
            fast_capsule.capsule_id.clone(),
            private_capsule.capsule_id.clone(),
            standard_capsule.capsule_id.clone(),
        ];
        window.seal_order(ordered_ids)?;

        fast_lane.admit_capsule(&fast_capsule.capsule_id)?;
        monero_exit_lane.reserve_capsule(&monero_capsule.capsule_id)?;
        state.insert_fast_lane(fast_lane)?;
        state.insert_monero_lane(monero_exit_lane)?;

        state.insert_capsule(standard_capsule)?;
        state.insert_capsule(private_capsule)?;
        state.insert_capsule(fast_capsule)?;
        state.insert_capsule(monero_capsule)?;

        let reveal = ThresholdBatchReveal::new(
            &window,
            config.threshold,
            config.threshold,
            window.reveal_start_height,
        )?;
        let reveal_id = reveal.reveal_id.clone();
        state.insert_window(window)?;
        state.insert_batch_reveal(reveal)?;

        let signer_ids = state
            .members
            .values()
            .filter(|member| member.status.can_attest())
            .take(config.threshold as usize)
            .map(|member| member.member_id.clone())
            .collect::<Vec<_>>();
        state.insert_attestation(CommitteeAttestation::new(
            CommitteeAttestationKind::BatchReveal,
            &reveal_id,
            &committee_id,
            signer_ids.clone(),
            PqOrderingSignatureScheme::HybridMlDsaSlhDsa,
            height,
            config.fast_lane_quorum_bps,
        )?)?;
        state.insert_attestation(CommitteeAttestation::new(
            CommitteeAttestationKind::FastLanePreconfirmation,
            &fast_lane_id,
            &committee_id,
            signer_ids.clone(),
            PqOrderingSignatureScheme::MlDsa65,
            height,
            config.fast_lane_quorum_bps,
        )?)?;
        state.insert_attestation(CommitteeAttestation::new(
            CommitteeAttestationKind::MoneroPriorityAdmission,
            &monero_exit_lane_id,
            &committee_id,
            signer_ids,
            PqOrderingSignatureScheme::MlDsa65,
            height,
            7_000,
        )?)?;

        let accused_member_id = state
            .members
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet state requires at least one member".to_string())?;
        let window_id = state
            .windows
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet state requires at least one window".to_string())?;
        let slash = OrderingSlashingEvidence::new(
            SlashingEvidenceKind::PrematureReveal,
            &accused_member_id,
            &window_id,
            None,
            "devnet-watchtower-sealed-ordering",
            config.default_slash_bps,
            height,
        )?;
        state.insert_slashing_evidence(slash)?;
        let initialized_subject_id = state.committee_id.clone();
        let initialized_payload = state.roots().public_record();
        state.record_event(
            "devnet_state_initialized",
            &initialized_subject_id,
            &initialized_payload,
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqSealedOrderingCommitteeResult<()> {
        if height < self.height {
            return Err("sealed ordering committee height cannot decrease".to_string());
        }
        self.height = height;
        self.epoch = height / 120;
        self.refresh_status();
        self.validate()?;
        Ok(())
    }

    pub fn roots(&self) -> PqSealedOrderingCommitteeRoots {
        PqSealedOrderingCommitteeRoots {
            config_root: self.config.state_root(),
            member_root: map_root(
                "PQ-SEALED-ORDERING-MEMBERS",
                self.members
                    .values()
                    .map(OrderingCommitteeMember::public_record)
                    .collect(),
            ),
            window_root: map_root(
                "PQ-SEALED-ORDERING-WINDOWS",
                self.windows
                    .values()
                    .map(FairOrderingWindow::public_record)
                    .collect(),
            ),
            capsule_root: map_root(
                "PQ-SEALED-ORDERING-CAPSULES",
                self.capsules
                    .values()
                    .map(SealedOrderCapsule::public_record)
                    .collect(),
            ),
            reveal_root: map_root(
                "PQ-SEALED-ORDERING-BATCH-REVEALS",
                self.batch_reveals
                    .values()
                    .map(ThresholdBatchReveal::public_record)
                    .collect(),
            ),
            attestation_root: map_root(
                "PQ-SEALED-ORDERING-ATTESTATIONS",
                self.attestations
                    .values()
                    .map(CommitteeAttestation::public_record)
                    .collect(),
            ),
            fast_lane_root: map_root(
                "PQ-SEALED-ORDERING-FAST-LANES",
                self.fast_lanes
                    .values()
                    .map(FastLaneReservation::public_record)
                    .collect(),
            ),
            private_policy_root: map_root(
                "PQ-SEALED-ORDERING-PRIVATE-POLICIES",
                self.private_policies
                    .values()
                    .map(PrivateContractOrderingPolicy::public_record)
                    .collect(),
            ),
            monero_lane_root: map_root(
                "PQ-SEALED-ORDERING-MONERO-LANES",
                self.monero_lanes
                    .values()
                    .map(MoneroBridgePriorityLane::public_record)
                    .collect(),
            ),
            slashing_evidence_root: map_root(
                "PQ-SEALED-ORDERING-SLASHING-EVIDENCE",
                self.slashing_evidence
                    .values()
                    .map(OrderingSlashingEvidence::public_record)
                    .collect(),
            ),
            public_event_root: map_root(
                "PQ-SEALED-ORDERING-PUBLIC-EVENTS",
                self.public_events
                    .values()
                    .map(OrderingPublicEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> PqSealedOrderingCommitteeCounters {
        PqSealedOrderingCommitteeCounters {
            member_count: self.members.len() as u64,
            active_member_count: self
                .members
                .values()
                .filter(|member| member.status.can_attest())
                .count() as u64,
            window_count: self.windows.len() as u64,
            collecting_window_count: self
                .windows
                .values()
                .filter(|window| window.status.accepts_capsules())
                .count() as u64,
            capsule_count: self.capsules.len() as u64,
            open_capsule_count: self
                .capsules
                .values()
                .filter(|capsule| capsule.status.open())
                .count() as u64,
            fast_lane_capsule_count: self
                .capsules
                .values()
                .filter(|capsule| capsule.fast_lane_requested)
                .count() as u64,
            monero_capsule_count: self
                .capsules
                .values()
                .filter(|capsule| capsule.lane.monero_bridge())
                .count() as u64,
            reveal_count: self.batch_reveals.len() as u64,
            threshold_reveal_count: self
                .batch_reveals
                .values()
                .filter(|reveal| reveal.threshold_met())
                .count() as u64,
            attestation_count: self.attestations.len() as u64,
            fast_lane_count: self.fast_lanes.len() as u64,
            private_policy_count: self.private_policies.len() as u64,
            monero_lane_count: self.monero_lanes.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            unresolved_slashing_evidence_count: self
                .slashing_evidence
                .values()
                .filter(|evidence| !evidence.resolved)
                .count() as u64,
            public_event_count: self.public_events.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let record_without_root = json!({
            "kind": "pq_sealed_ordering_committee_state",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "protocol_version": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_VERSION,
            "schema_version": PQ_SEALED_ORDERING_COMMITTEE_SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "committee_id": self.committee_id,
            "status": self.status,
            "config": self.config.public_record(),
            "members": self.members.values().map(OrderingCommitteeMember::public_record).collect::<Vec<_>>(),
            "windows": self.windows.values().map(FairOrderingWindow::public_record).collect::<Vec<_>>(),
            "capsules": self.capsules.values().map(SealedOrderCapsule::public_record).collect::<Vec<_>>(),
            "batch_reveals": self.batch_reveals.values().map(ThresholdBatchReveal::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(CommitteeAttestation::public_record).collect::<Vec<_>>(),
            "fast_lanes": self.fast_lanes.values().map(FastLaneReservation::public_record).collect::<Vec<_>>(),
            "private_policies": self.private_policies.values().map(PrivateContractOrderingPolicy::public_record).collect::<Vec<_>>(),
            "monero_lanes": self.monero_lanes.values().map(MoneroBridgePriorityLane::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(OrderingSlashingEvidence::public_record).collect::<Vec<_>>(),
            "public_events": self.public_events.values().map(OrderingPublicEvent::public_record).collect::<Vec<_>>(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters().public_record(),
        });
        let state_root = pq_sealed_ordering_committee_state_root_from_record(&record_without_root);
        let mut record = record_without_root;
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let record = json!({
            "kind": "pq_sealed_ordering_committee_state",
            "chain_id": CHAIN_ID,
            "protocol_label": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL,
            "protocol_version": PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_VERSION,
            "schema_version": PQ_SEALED_ORDERING_COMMITTEE_SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "committee_id": self.committee_id,
            "status": self.status,
            "config": self.config.public_record(),
            "members": self.members.values().map(OrderingCommitteeMember::public_record).collect::<Vec<_>>(),
            "windows": self.windows.values().map(FairOrderingWindow::public_record).collect::<Vec<_>>(),
            "capsules": self.capsules.values().map(SealedOrderCapsule::public_record).collect::<Vec<_>>(),
            "batch_reveals": self.batch_reveals.values().map(ThresholdBatchReveal::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(CommitteeAttestation::public_record).collect::<Vec<_>>(),
            "fast_lanes": self.fast_lanes.values().map(FastLaneReservation::public_record).collect::<Vec<_>>(),
            "private_policies": self.private_policies.values().map(PrivateContractOrderingPolicy::public_record).collect::<Vec<_>>(),
            "monero_lanes": self.monero_lanes.values().map(MoneroBridgePriorityLane::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(OrderingSlashingEvidence::public_record).collect::<Vec<_>>(),
            "public_events": self.public_events.values().map(OrderingPublicEvent::public_record).collect::<Vec<_>>(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters().public_record(),
        });
        pq_sealed_ordering_committee_state_root_from_record(&record)
    }

    pub fn validate(&self) -> PqSealedOrderingCommitteeResult<String> {
        self.config.validate()?;
        require_state_status("state.status", &self.status)?;
        ensure_non_empty("state.committee_id", &self.committee_id)?;
        if self.members.is_empty() {
            return Err("state members cannot be empty".to_string());
        }
        if self.members.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_MEMBERS {
            return Err("state has too many committee members".to_string());
        }
        if self.windows.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_WINDOWS {
            return Err("state has too many fair ordering windows".to_string());
        }
        if self.capsules.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_CAPSULES {
            return Err("state has too many order capsules".to_string());
        }
        if self.batch_reveals.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_REVEALS {
            return Err("state has too many batch reveals".to_string());
        }
        if self.attestations.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_ATTESTATIONS {
            return Err("state has too many attestations".to_string());
        }
        if self.fast_lanes.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_FAST_LANES {
            return Err("state has too many fast lanes".to_string());
        }
        if self.private_policies.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_POLICIES {
            return Err("state has too many private policies".to_string());
        }
        if self.monero_lanes.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_MONERO_LANES {
            return Err("state has too many monero lanes".to_string());
        }
        if self.slashing_evidence.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_SLASHING_EVIDENCE {
            return Err("state has too much slashing evidence".to_string());
        }
        if self.public_events.len() > PQ_SEALED_ORDERING_COMMITTEE_MAX_PUBLIC_EVENTS {
            return Err("state has too many public events".to_string());
        }

        for (member_id, member) in &self.members {
            if member_id != &member.member_id {
                return Err("member map key does not match member id".to_string());
            }
            member.validate()?;
        }
        for (window_id, window) in &self.windows {
            if window_id != &window.window_id {
                return Err("window map key does not match window id".to_string());
            }
            window.validate()?;
            if window.committee_id != self.committee_id {
                return Err("window committee id does not match active committee".to_string());
            }
            if window.capsule_ids.len() as u64 > self.config.max_capsules_per_window {
                return Err("window exceeds max capsules per window".to_string());
            }
            for capsule_id in &window.capsule_ids {
                if !self.capsules.contains_key(capsule_id) {
                    return Err("window references missing capsule".to_string());
                }
            }
        }
        for (capsule_id, capsule) in &self.capsules {
            if capsule_id != &capsule.capsule_id {
                return Err("capsule map key does not match capsule id".to_string());
            }
            capsule.validate()?;
            if capsule.declared_payload_bytes > self.config.max_capsule_bytes {
                return Err("capsule exceeds configured max bytes".to_string());
            }
            if !self.windows.contains_key(&capsule.window_id) {
                return Err("capsule references missing window".to_string());
            }
            if let Some(policy_id) = &capsule.private_policy_id {
                if !self.private_policies.contains_key(policy_id) {
                    return Err("capsule references missing private policy".to_string());
                }
            }
            if let Some(lane_id) = &capsule.monero_lane_id {
                if !self.monero_lanes.contains_key(lane_id) {
                    return Err("capsule references missing monero lane".to_string());
                }
            }
        }
        for (reveal_id, reveal) in &self.batch_reveals {
            if reveal_id != &reveal.reveal_id {
                return Err("reveal map key does not match reveal id".to_string());
            }
            reveal.validate()?;
            if !self.windows.contains_key(&reveal.window_id) {
                return Err("reveal references missing window".to_string());
            }
            if reveal.required_share_count != self.config.threshold {
                return Err(
                    "reveal required share count does not match config threshold".to_string(),
                );
            }
        }
        for (attestation_id, attestation) in &self.attestations {
            if attestation_id != &attestation.attestation_id {
                return Err("attestation map key does not match attestation id".to_string());
            }
            attestation.validate()?;
            if attestation.committee_id != self.committee_id {
                return Err("attestation committee id does not match active committee".to_string());
            }
            for member_id in &attestation.signer_member_ids {
                if !self.members.contains_key(member_id) {
                    return Err("attestation references missing signer".to_string());
                }
            }
        }
        for (lane_id, lane) in &self.fast_lanes {
            if lane_id != &lane.lane_id {
                return Err("fast lane map key does not match lane id".to_string());
            }
            lane.validate()?;
            for capsule_id in &lane.admitted_capsule_ids {
                if !self.capsules.contains_key(capsule_id) {
                    return Err("fast lane references missing capsule".to_string());
                }
            }
        }
        for (policy_id, policy) in &self.private_policies {
            if policy_id != &policy.policy_id {
                return Err("private policy map key does not match policy id".to_string());
            }
            policy.validate()?;
        }
        for (lane_id, lane) in &self.monero_lanes {
            if lane_id != &lane.lane_id {
                return Err("monero lane map key does not match lane id".to_string());
            }
            lane.validate()?;
            for capsule_id in &lane.reserved_capsule_ids {
                if !self.capsules.contains_key(capsule_id) {
                    return Err("monero lane references missing capsule".to_string());
                }
            }
        }
        for (evidence_id, evidence) in &self.slashing_evidence {
            if evidence_id != &evidence.evidence_id {
                return Err("slashing evidence map key does not match evidence id".to_string());
            }
            evidence.validate()?;
            if !self.members.contains_key(&evidence.accused_member_id) {
                return Err("slashing evidence references missing member".to_string());
            }
            if !self.windows.contains_key(&evidence.window_id) {
                return Err("slashing evidence references missing window".to_string());
            }
            if let Some(capsule_id) = &evidence.capsule_id {
                if !self.capsules.contains_key(capsule_id) {
                    return Err("slashing evidence references missing capsule".to_string());
                }
            }
        }
        for (event_id, event) in &self.public_events {
            if event_id != &event.event_id {
                return Err("public event map key does not match event id".to_string());
            }
            event.validate()?;
        }
        Ok(self.state_root())
    }

    fn insert_window(&mut self, window: FairOrderingWindow) -> PqSealedOrderingCommitteeResult<()> {
        window.validate()?;
        self.windows.insert(window.window_id.clone(), window);
        Ok(())
    }

    fn insert_capsule(
        &mut self,
        capsule: SealedOrderCapsule,
    ) -> PqSealedOrderingCommitteeResult<()> {
        capsule.validate()?;
        self.capsules.insert(capsule.capsule_id.clone(), capsule);
        Ok(())
    }

    fn insert_batch_reveal(
        &mut self,
        reveal: ThresholdBatchReveal,
    ) -> PqSealedOrderingCommitteeResult<()> {
        reveal.validate()?;
        self.batch_reveals.insert(reveal.reveal_id.clone(), reveal);
        Ok(())
    }

    fn insert_attestation(
        &mut self,
        attestation: CommitteeAttestation,
    ) -> PqSealedOrderingCommitteeResult<()> {
        attestation.validate()?;
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    fn insert_fast_lane(
        &mut self,
        lane: FastLaneReservation,
    ) -> PqSealedOrderingCommitteeResult<()> {
        lane.validate()?;
        self.fast_lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    fn insert_private_policy(
        &mut self,
        policy: PrivateContractOrderingPolicy,
    ) -> PqSealedOrderingCommitteeResult<()> {
        policy.validate()?;
        self.private_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    fn insert_monero_lane(
        &mut self,
        lane: MoneroBridgePriorityLane,
    ) -> PqSealedOrderingCommitteeResult<()> {
        lane.validate()?;
        self.monero_lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    fn insert_slashing_evidence(
        &mut self,
        evidence: OrderingSlashingEvidence,
    ) -> PqSealedOrderingCommitteeResult<()> {
        evidence.validate()?;
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    fn record_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        payload: &Value,
    ) -> PqSealedOrderingCommitteeResult<()> {
        let event = OrderingPublicEvent::new(event_kind, subject_id, payload, self.height)?;
        self.public_events.insert(event.event_id.clone(), event);
        Ok(())
    }

    fn refresh_status(&mut self) {
        if self
            .windows
            .values()
            .any(|window| matches!(window.status, FairOrderingWindowStatus::Challenged))
        {
            self.status = STATE_STATUS_CHALLENGE_MODE.to_string();
        } else if self
            .batch_reveals
            .values()
            .any(|reveal| matches!(reveal.status, BatchRevealStatus::SharesCollected))
        {
            self.status = STATE_STATUS_REVEALING.to_string();
        } else {
            self.status = STATE_STATUS_ACTIVE.to_string();
        }
    }
}

pub fn pq_sealed_ordering_committee_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-COMMITTEE-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL),
            HashPart::Int(PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_VERSION as i128),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn pq_soc_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn pq_soc_string_commitment(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn pq_soc_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!(pq_soc_string_commitment(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn pq_soc_config_id(chain_id: &str, fee_asset_id: &str) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-CONFIG-ID",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(PQ_SEALED_ORDERING_COMMITTEE_PROTOCOL_LABEL),
            HashPart::Str(fee_asset_id),
        ],
        32,
    )
}

fn pq_soc_member_id(operator_label: &str, index: u64) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Int(index as i128),
        ],
        32,
    )
}

fn pq_soc_committee_id(epoch: u64, member_ids: &[String]) -> String {
    let member_root = pq_soc_string_set_root("PQ-SEALED-ORDERING-COMMITTEE-MEMBER-IDS", member_ids);
    domain_hash(
        "PQ-SEALED-ORDERING-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(&member_root),
        ],
        32,
    )
}

fn pq_soc_window_id(epoch: u64, committee_id: &str, start_height: u64) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(committee_id),
            HashPart::Int(start_height as i128),
        ],
        32,
    )
}

fn pq_soc_ordering_seed(window_id: &str, committee_id: &str, epoch: u64) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(committee_id),
            HashPart::Int(epoch as i128),
        ],
        32,
    )
}

fn pq_soc_arrival_commitment(
    window_id: &str,
    submitter_commitment: &str,
    submitted_height: u64,
    priority: u64,
) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-ARRIVAL-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(submitter_commitment),
            HashPart::Int(submitted_height as i128),
            HashPart::Int(priority as i128),
        ],
        32,
    )
}

fn pq_soc_capsule_id(
    window_id: &str,
    lane: SealedOrderingLaneKind,
    submitter_commitment: &str,
    payload_ciphertext_root: &str,
) -> String {
    domain_hash(
        "PQ-SEALED-ORDER-CAPSULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(submitter_commitment),
            HashPart::Str(payload_ciphertext_root),
        ],
        32,
    )
}

fn pq_soc_reveal_id(window_id: &str, batch_transcript_root: &str) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-REVEAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(window_id),
            HashPart::Str(batch_transcript_root),
        ],
        32,
    )
}

fn pq_soc_attestation_id(
    kind: CommitteeAttestationKind,
    subject_id: &str,
    committee_id: &str,
    signature_root: &str,
) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(committee_id),
            HashPart::Str(signature_root),
        ],
        32,
    )
}

fn pq_soc_fast_lane_id(label: &str, lane: SealedOrderingLaneKind, height: u64) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-FAST-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(lane.as_str()),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn pq_soc_private_policy_id(
    contract_commitment: &str,
    mode: PrivateContractPolicyMode,
    height: u64,
) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-PRIVATE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_commitment),
            HashPart::Str(mode.as_str()),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn pq_soc_monero_lane_id(bridge_account_commitment: &str, lane: SealedOrderingLaneKind) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-MONERO-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bridge_account_commitment),
            HashPart::Str(lane.as_str()),
        ],
        32,
    )
}

fn pq_soc_slashing_evidence_id(
    kind: SlashingEvidenceKind,
    accused_member_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(accused_member_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn pq_soc_event_id(event_kind: &str, subject_id: &str, payload_root: &str, height: u64) -> String {
    domain_hash(
        "PQ-SEALED-ORDERING-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn ensure_non_empty(label: &str, value: &str) -> PqSealedOrderingCommitteeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> PqSealedOrderingCommitteeResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> PqSealedOrderingCommitteeResult<()> {
    if value > PQ_SEALED_ORDERING_COMMITTEE_MAX_BPS {
        return Err(format!("{label} exceeds max basis points"));
    }
    Ok(())
}

fn require_state_status(label: &str, value: &str) -> PqSealedOrderingCommitteeResult<()> {
    ensure_non_empty(label, value)?;
    if matches!(
        value,
        STATE_STATUS_BOOTSTRAPPING
            | STATE_STATUS_ACTIVE
            | STATE_STATUS_REVEALING
            | STATE_STATUS_CHALLENGE_MODE
            | STATE_STATUS_HALTED
    ) {
        Ok(())
    } else {
        Err(format!(
            "{label} is not a recognized sealed ordering status"
        ))
    }
}
