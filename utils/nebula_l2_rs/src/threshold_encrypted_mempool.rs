use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ThresholdEncryptedMempoolResult<T> = Result<T, String>;

pub const THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION: &str =
    "nebula-threshold-encrypted-mempool-v1";
pub const THRESHOLD_ENCRYPTED_MEMPOOL_PQ_KEM_SCHEME: &str = "ML-KEM-1024+devnet-threshold";
pub const THRESHOLD_ENCRYPTED_MEMPOOL_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const THRESHOLD_ENCRYPTED_MEMPOOL_COMMITMENT_SCHEME: &str = "SHAKE256-domain-v1";
pub const THRESHOLD_ENCRYPTED_MEMPOOL_FAIR_ORDERING_POLICY: &str =
    "encrypted-commit-reveal-fair-window-v1";
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_COMMITTEE_SIZE: u64 = 4;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_THRESHOLD: u64 = 3;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_WINDOW_BLOCKS: u64 = 4;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_DECRYPT_DELAY_BLOCKS: u64 = 1;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 3;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 12;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_ENVELOPE_TTL_BLOCKS: u64 = 24;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_FORCED_INCLUSION_GRACE_BLOCKS: u64 = 8;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_LOW_FEE_LANE_TTL_BLOCKS: u64 = 96;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_DISCLOSURE_DELAY_BLOCKS: u64 = 720;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_MAX_ENVELOPES_PER_WINDOW: u64 = 512;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_MAX_PAYLOAD_BYTES: u64 = 128 * 1024;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_LOW_FEE_MAX_FEE_MICRO_UNITS: u64 = 2_500;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_MIN_FEE_MICRO_UNITS: u64 = 100;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_SLASH_BPS: u64 = 1_500;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_MAX_BPS: u64 = 10_000;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_MAX_COMMITTEE_MEMBERS: usize = 128;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_MAX_COMMITTEES: usize = 64;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_MAX_ENVELOPES: usize = 4_096;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_MAX_WINDOWS: usize = 512;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_MAX_LOW_FEE_LANES: usize = 32;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_MAX_FORCED_HOOKS: usize = 1_024;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_MAX_DISCLOSURE_RECEIPTS: usize = 2_048;
pub const THRESHOLD_ENCRYPTED_MEMPOOL_MAX_SLASHING_EVIDENCE: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdMempoolLaneKind {
    Standard,
    PrivateTransfer,
    BridgeExit,
    ContractCall,
    LowFeePrivacy,
    LowFeeBridge,
    ForcedInclusion,
    Maintenance,
}

impl ThresholdMempoolLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::PrivateTransfer => "private_transfer",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::LowFeePrivacy => "low_fee_privacy",
            Self::LowFeeBridge => "low_fee_bridge",
            Self::ForcedInclusion => "forced_inclusion",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn fairness_priority(self) -> u64 {
        match self {
            Self::ForcedInclusion => 0,
            Self::BridgeExit => 1,
            Self::LowFeeBridge => 2,
            Self::LowFeePrivacy => 3,
            Self::PrivateTransfer => 4,
            Self::ContractCall => 5,
            Self::Standard => 6,
            Self::Maintenance => 7,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer
                | Self::BridgeExit
                | Self::ContractCall
                | Self::LowFeePrivacy
                | Self::LowFeeBridge
                | Self::ForcedInclusion
        )
    }

    pub fn low_fee(self) -> bool {
        matches!(self, Self::LowFeePrivacy | Self::LowFeeBridge)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedEnvelopeStatus {
    Submitted,
    Queued,
    Committed,
    Decrypting,
    Decrypted,
    Ordered,
    Included,
    Expired,
    Rejected,
}

impl EncryptedEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Queued => "queued",
            Self::Committed => "committed",
            Self::Decrypting => "decrypting",
            Self::Decrypted => "decrypted",
            Self::Ordered => "ordered",
            Self::Included => "included",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Queued | Self::Committed | Self::Decrypting | Self::Decrypted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdCommitteeStatus {
    Active,
    Rotating,
    Retired,
    Slashed,
}

impl ThresholdCommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_envelopes(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdCommitteeMemberStatus {
    Active,
    Muted,
    Retired,
    Slashed,
}

impl ThresholdCommitteeMemberStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Muted => "muted",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_decrypt(self) -> bool {
        matches!(self, Self::Active | Self::Muted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecryptionShareStatus {
    Committed,
    Revealed,
    Accepted,
    Challenged,
    Slashed,
    Expired,
}

impl DecryptionShareStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FairOrderingWindowStatus {
    Collecting,
    CommitLocked,
    Decrypting,
    Ordered,
    Sealed,
    Challenged,
    Finalized,
    Expired,
}

impl FairOrderingWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::CommitLocked => "commit_locked",
            Self::Decrypting => "decrypting",
            Self::Ordered => "ordered",
            Self::Sealed => "sealed",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Collecting | Self::CommitLocked | Self::Decrypting | Self::Ordered
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeLaneStatus {
    Active,
    Paused,
    Exhausted,
    Expired,
}

impl LowFeeLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForcedInclusionHookStatus {
    Pending,
    Committed,
    Included,
    RescueEligible,
    Rescued,
    Challenged,
    Expired,
}

impl ForcedInclusionHookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Committed => "committed",
            Self::Included => "included",
            Self::RescueEligible => "rescue_eligible",
            Self::Rescued => "rescued",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn is_pending(self) -> bool {
        matches!(self, Self::Pending | Self::Committed | Self::RescueEligible)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyDisclosureScope {
    UserOnly,
    Auditor,
    Watchtower,
    CourtOrder,
    Public,
}

impl PrivacyDisclosureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserOnly => "user_only",
            Self::Auditor => "auditor",
            Self::Watchtower => "watchtower",
            Self::CourtOrder => "court_order",
            Self::Public => "public",
        }
    }

    pub fn requires_redaction(self) -> bool {
        !matches!(self, Self::Public)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyDisclosureStatus {
    PendingDelay,
    Disclosed,
    Revoked,
    Expired,
}

impl PrivacyDisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingDelay => "pending_delay",
            Self::Disclosed => "disclosed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    CiphertextEquivocation,
    ShareEquivocation,
    OrderingEquivocation,
    EarlyReveal,
    ShareWithholding,
    ForcedInclusionCensorship,
    LowFeeLaneTheft,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CiphertextEquivocation => "ciphertext_equivocation",
            Self::ShareEquivocation => "share_equivocation",
            Self::OrderingEquivocation => "ordering_equivocation",
            Self::EarlyReveal => "early_reveal",
            Self::ShareWithholding => "share_withholding",
            Self::ForcedInclusionCensorship => "forced_inclusion_censorship",
            Self::LowFeeLaneTheft => "low_fee_lane_theft",
        }
    }

    pub fn default_slash_multiplier_bps(self) -> u64 {
        match self {
            Self::CiphertextEquivocation | Self::OrderingEquivocation => 10_000,
            Self::ShareEquivocation => 7_500,
            Self::EarlyReveal => 5_000,
            Self::ShareWithholding => 2_500,
            Self::ForcedInclusionCensorship => 6_000,
            Self::LowFeeLaneTheft => 4_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceStatus {
    Observed,
    Submitted,
    Accepted,
    Rejected,
    Executed,
}

impl SlashingEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Executed => "executed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdEncryptedMempoolConfig {
    pub config_id: String,
    pub committee_size: u64,
    pub threshold: u64,
    pub fair_ordering_window_blocks: u64,
    pub decrypt_delay_blocks: u64,
    pub reveal_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub envelope_ttl_blocks: u64,
    pub forced_inclusion_grace_blocks: u64,
    pub low_fee_lane_ttl_blocks: u64,
    pub privacy_disclosure_delay_blocks: u64,
    pub max_envelopes_per_window: u64,
    pub max_payload_bytes: u64,
    pub low_fee_max_fee_micro_units: u64,
    pub min_fee_micro_units: u64,
    pub slashing_fraction_bps: u64,
    pub require_pq_threshold_encryption: bool,
    pub enable_anti_mev_commitments: bool,
    pub enable_low_fee_lanes: bool,
    pub enable_forced_inclusion_hooks: bool,
    pub enable_privacy_receipts: bool,
}

impl Default for ThresholdEncryptedMempoolConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            committee_size: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_COMMITTEE_SIZE,
            threshold: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_THRESHOLD,
            fair_ordering_window_blocks: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_WINDOW_BLOCKS,
            decrypt_delay_blocks: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_DECRYPT_DELAY_BLOCKS,
            reveal_window_blocks: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_REVEAL_WINDOW_BLOCKS,
            challenge_window_blocks: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            envelope_ttl_blocks: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_ENVELOPE_TTL_BLOCKS,
            forced_inclusion_grace_blocks:
                THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_FORCED_INCLUSION_GRACE_BLOCKS,
            low_fee_lane_ttl_blocks: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_LOW_FEE_LANE_TTL_BLOCKS,
            privacy_disclosure_delay_blocks:
                THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_DISCLOSURE_DELAY_BLOCKS,
            max_envelopes_per_window: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_MAX_ENVELOPES_PER_WINDOW,
            max_payload_bytes: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_MAX_PAYLOAD_BYTES,
            low_fee_max_fee_micro_units:
                THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_LOW_FEE_MAX_FEE_MICRO_UNITS,
            min_fee_micro_units: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_MIN_FEE_MICRO_UNITS,
            slashing_fraction_bps: THRESHOLD_ENCRYPTED_MEMPOOL_DEFAULT_SLASH_BPS,
            require_pq_threshold_encryption: true,
            enable_anti_mev_commitments: true,
            enable_low_fee_lanes: true,
            enable_forced_inclusion_hooks: true,
            enable_privacy_receipts: true,
        };
        config.config_id = threshold_encrypted_mempool_config_id(&config.identity_record());
        config
    }
}

impl ThresholdEncryptedMempoolConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_config",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "committee_size": self.committee_size,
            "threshold": self.threshold,
            "fair_ordering_window_blocks": self.fair_ordering_window_blocks,
            "decrypt_delay_blocks": self.decrypt_delay_blocks,
            "reveal_window_blocks": self.reveal_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "envelope_ttl_blocks": self.envelope_ttl_blocks,
            "forced_inclusion_grace_blocks": self.forced_inclusion_grace_blocks,
            "low_fee_lane_ttl_blocks": self.low_fee_lane_ttl_blocks,
            "privacy_disclosure_delay_blocks": self.privacy_disclosure_delay_blocks,
            "max_envelopes_per_window": self.max_envelopes_per_window,
            "max_payload_bytes": self.max_payload_bytes,
            "low_fee_max_fee_micro_units": self.low_fee_max_fee_micro_units,
            "min_fee_micro_units": self.min_fee_micro_units,
            "slashing_fraction_bps": self.slashing_fraction_bps,
            "require_pq_threshold_encryption": self.require_pq_threshold_encryption,
            "enable_anti_mev_commitments": self.enable_anti_mev_commitments,
            "enable_low_fee_lanes": self.enable_low_fee_lanes,
            "enable_forced_inclusion_hooks": self.enable_forced_inclusion_hooks,
            "enable_privacy_receipts": self.enable_privacy_receipts,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("threshold encrypted mempool config object");
        object.insert(
            "config_id".to_string(),
            Value::String(self.config_id.clone()),
        );
        object.insert("config_root".to_string(), Value::String(self.config_root()));
        record
    }

    pub fn config_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-CONFIG",
            &self.identity_record(),
        )
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.config_id, "threshold encrypted mempool config id")?;
        if self.committee_size == 0 {
            return Err("threshold encrypted mempool committee size cannot be zero".to_string());
        }
        if self.threshold == 0 || self.threshold > self.committee_size {
            return Err(
                "threshold encrypted mempool threshold must fit committee size".to_string(),
            );
        }
        if self.fair_ordering_window_blocks == 0 {
            return Err("threshold encrypted mempool ordering window cannot be zero".to_string());
        }
        if self.reveal_window_blocks == 0 {
            return Err("threshold encrypted mempool reveal window cannot be zero".to_string());
        }
        if self.envelope_ttl_blocks <= self.fair_ordering_window_blocks {
            return Err(
                "threshold encrypted mempool envelope ttl must cover an ordering window"
                    .to_string(),
            );
        }
        if self.max_envelopes_per_window == 0 {
            return Err(
                "threshold encrypted mempool max envelopes per window cannot be zero".to_string(),
            );
        }
        if self.max_payload_bytes == 0 {
            return Err("threshold encrypted mempool max payload bytes cannot be zero".to_string());
        }
        if self.low_fee_max_fee_micro_units < self.min_fee_micro_units {
            return Err("threshold encrypted mempool low fee cap below min fee".to_string());
        }
        ensure_bps(
            self.slashing_fraction_bps,
            "threshold encrypted mempool slashing fraction",
        )?;
        let expected = threshold_encrypted_mempool_config_id(&self.identity_record());
        if self.config_id != expected {
            return Err("threshold encrypted mempool config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqThresholdCommitteeMember {
    pub member_id: String,
    pub operator_id: String,
    pub validator_label: String,
    pub pq_kem_public_key_root: String,
    pub pq_signature_public_key_root: String,
    pub share_commitment_root: String,
    pub stake_units: u64,
    pub weight: u64,
    pub activation_height: u64,
    pub deactivation_height: Option<u64>,
    pub status: ThresholdCommitteeMemberStatus,
}

impl PqThresholdCommitteeMember {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: impl Into<String>,
        validator_label: impl Into<String>,
        pq_kem_public_key: &str,
        pq_signature_public_key: &str,
        share_commitment: &str,
        stake_units: u64,
        weight: u64,
        activation_height: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        let operator_id = operator_id.into();
        let validator_label = validator_label.into();
        ensure_non_empty(&operator_id, "threshold committee operator id")?;
        ensure_non_empty(&validator_label, "threshold committee validator label")?;
        ensure_non_empty(pq_kem_public_key, "threshold committee kem public key")?;
        ensure_non_empty(
            pq_signature_public_key,
            "threshold committee signature public key",
        )?;
        ensure_non_empty(share_commitment, "threshold committee share commitment")?;
        if stake_units == 0 || weight == 0 {
            return Err("threshold committee member stake and weight must be positive".to_string());
        }
        let pq_kem_public_key_root = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-MEMBER-KEM-KEY",
            pq_kem_public_key,
        );
        let pq_signature_public_key_root = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-MEMBER-SIGNATURE-KEY",
            pq_signature_public_key,
        );
        let share_commitment_root = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-MEMBER-SHARE",
            share_commitment,
        );
        let member_id = threshold_encrypted_mempool_committee_member_id(
            &operator_id,
            &validator_label,
            &pq_kem_public_key_root,
            &share_commitment_root,
            activation_height,
        );
        let member = Self {
            member_id,
            operator_id,
            validator_label,
            pq_kem_public_key_root,
            pq_signature_public_key_root,
            share_commitment_root,
            stake_units,
            weight,
            activation_height,
            deactivation_height: None,
            status: ThresholdCommitteeMemberStatus::Active,
        };
        member.validate()?;
        Ok(member)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "operator_id": self.operator_id,
            "validator_label": self.validator_label,
            "pq_kem_scheme": THRESHOLD_ENCRYPTED_MEMPOOL_PQ_KEM_SCHEME,
            "pq_signature_scheme": THRESHOLD_ENCRYPTED_MEMPOOL_PQ_SIGNATURE_SCHEME,
            "pq_kem_public_key_root": self.pq_kem_public_key_root,
            "pq_signature_public_key_root": self.pq_signature_public_key_root,
            "share_commitment_root": self.share_commitment_root,
            "stake_units": self.stake_units,
            "weight": self.weight,
            "activation_height": self.activation_height,
            "deactivation_height": self.deactivation_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("threshold committee member record object");
        object.insert(
            "member_id".to_string(),
            Value::String(self.member_id.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert("member_root".to_string(), Value::String(self.member_root()));
        record
    }

    pub fn member_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-COMMITTEE-MEMBER",
            &self.identity_record(),
        )
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.can_decrypt()
            && self.activation_height <= height
            && self
                .deactivation_height
                .map(|deactivation| height < deactivation)
                .unwrap_or(true)
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.member_id, "threshold committee member id")?;
        ensure_non_empty(&self.operator_id, "threshold committee operator id")?;
        ensure_non_empty(&self.validator_label, "threshold committee validator label")?;
        ensure_non_empty(
            &self.pq_kem_public_key_root,
            "threshold committee kem public key root",
        )?;
        ensure_non_empty(
            &self.pq_signature_public_key_root,
            "threshold committee signature public key root",
        )?;
        ensure_non_empty(
            &self.share_commitment_root,
            "threshold committee share commitment root",
        )?;
        if self.stake_units == 0 || self.weight == 0 {
            return Err("threshold committee member stake and weight must be positive".to_string());
        }
        if let Some(deactivation_height) = self.deactivation_height {
            if deactivation_height <= self.activation_height {
                return Err(
                    "threshold committee member deactivation must follow activation".to_string(),
                );
            }
        }
        let expected = threshold_encrypted_mempool_committee_member_id(
            &self.operator_id,
            &self.validator_label,
            &self.pq_kem_public_key_root,
            &self.share_commitment_root,
            self.activation_height,
        );
        if self.member_id != expected {
            return Err("threshold committee member id mismatch".to_string());
        }
        Ok(self.member_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqThresholdEncryptionCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub threshold: u64,
    pub member_ids: Vec<String>,
    pub member_root: String,
    pub aggregate_pq_public_key_root: String,
    pub transcript_root: String,
    pub activation_height: u64,
    pub retirement_height: Option<u64>,
    pub created_at_height: u64,
    pub status: ThresholdCommitteeStatus,
}

impl PqThresholdEncryptionCommittee {
    pub fn new(
        epoch: u64,
        threshold: u64,
        members: &[PqThresholdCommitteeMember],
        aggregate_pq_public_key: &str,
        transcript: &Value,
        activation_height: u64,
        created_at_height: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        if members.is_empty() {
            return Err("threshold committee requires members".to_string());
        }
        if threshold == 0 || threshold as usize > members.len() {
            return Err("threshold committee threshold must fit members".to_string());
        }
        ensure_non_empty(
            aggregate_pq_public_key,
            "threshold committee aggregate public key",
        )?;
        let member_ids = members
            .iter()
            .map(|member| member.member_id.clone())
            .collect::<Vec<_>>();
        let member_leaves = members
            .iter()
            .map(PqThresholdCommitteeMember::public_record)
            .collect::<Vec<_>>();
        let member_root = merkle_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-COMMITTEE-MEMBERS",
            &member_leaves,
        );
        let aggregate_pq_public_key_root = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-COMMITTEE-AGGREGATE-KEY",
            aggregate_pq_public_key,
        );
        let transcript_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-COMMITTEE-TRANSCRIPT",
            transcript,
        );
        let committee_id = threshold_encrypted_mempool_committee_id(
            epoch,
            threshold,
            &member_root,
            &aggregate_pq_public_key_root,
            activation_height,
        );
        let committee = Self {
            committee_id,
            epoch,
            threshold,
            member_ids,
            member_root,
            aggregate_pq_public_key_root,
            transcript_root,
            activation_height,
            retirement_height: None,
            created_at_height,
            status: ThresholdCommitteeStatus::Active,
        };
        committee.validate()?;
        Ok(committee)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_committee",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "epoch": self.epoch,
            "threshold": self.threshold,
            "member_ids": self.member_ids,
            "member_root": self.member_root,
            "aggregate_pq_public_key_root": self.aggregate_pq_public_key_root,
            "transcript_root": self.transcript_root,
            "activation_height": self.activation_height,
            "retirement_height": self.retirement_height,
            "created_at_height": self.created_at_height,
            "threshold_scheme": THRESHOLD_ENCRYPTED_MEMPOOL_PQ_KEM_SCHEME,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("threshold committee public record object");
        object.insert(
            "committee_id".to_string(),
            Value::String(self.committee_id.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert(
            "committee_root".to_string(),
            Value::String(self.committee_root()),
        );
        record
    }

    pub fn committee_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-COMMITTEE",
            &self.identity_record(),
        )
    }

    pub fn accepts_at(&self, height: u64) -> bool {
        self.status.accepts_envelopes()
            && self.activation_height <= height
            && self
                .retirement_height
                .map(|retirement| height < retirement)
                .unwrap_or(true)
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.committee_id, "threshold committee id")?;
        if self.member_ids.is_empty() {
            return Err("threshold committee member ids cannot be empty".to_string());
        }
        if self.threshold == 0 || self.threshold as usize > self.member_ids.len() {
            return Err("threshold committee threshold must fit members".to_string());
        }
        ensure_non_empty(&self.member_root, "threshold committee member root")?;
        ensure_non_empty(
            &self.aggregate_pq_public_key_root,
            "threshold committee aggregate public key root",
        )?;
        ensure_non_empty(&self.transcript_root, "threshold committee transcript root")?;
        if let Some(retirement_height) = self.retirement_height {
            if retirement_height <= self.activation_height {
                return Err("threshold committee retirement must follow activation".to_string());
            }
        }
        ensure_unique_strings(&self.member_ids, "threshold committee member ids")?;
        let expected = threshold_encrypted_mempool_committee_id(
            self.epoch,
            self.threshold,
            &self.member_root,
            &self.aggregate_pq_public_key_root,
            self.activation_height,
        );
        if self.committee_id != expected {
            return Err("threshold committee id mismatch".to_string());
        }
        Ok(self.committee_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedTransactionEnvelope {
    pub envelope_id: String,
    pub lane_kind: ThresholdMempoolLaneKind,
    pub lane_key: String,
    pub submitter_commitment: String,
    pub tx_kind_commitment: String,
    pub payload_ciphertext_root: String,
    pub payload_size_bytes: u64,
    pub pq_ciphertext_root: String,
    pub committee_id: String,
    pub encrypted_fee_commitment: String,
    pub fee_micro_units: u64,
    pub low_fee_credit_root: Option<String>,
    pub anti_mev_commitment_id: Option<String>,
    pub forced_inclusion_ticket_id: Option<String>,
    pub replay_nullifier: String,
    pub nonce: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: EncryptedEnvelopeStatus,
}

impl EncryptedTransactionEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_kind: ThresholdMempoolLaneKind,
        submitter_label: &str,
        tx_kind: &str,
        encrypted_payload: &Value,
        payload_size_bytes: u64,
        committee_id: impl Into<String>,
        fee_micro_units: u64,
        low_fee_credit: Option<&str>,
        anti_mev_commitment_id: Option<String>,
        forced_inclusion_ticket_id: Option<String>,
        nonce: u64,
        submitted_at_height: u64,
        ttl_blocks: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        ensure_non_empty(submitter_label, "encrypted envelope submitter")?;
        ensure_non_empty(tx_kind, "encrypted envelope transaction kind")?;
        let committee_id = committee_id.into();
        ensure_non_empty(&committee_id, "encrypted envelope committee id")?;
        if payload_size_bytes == 0 {
            return Err("encrypted envelope payload size must be positive".to_string());
        }
        if ttl_blocks == 0 {
            return Err("encrypted envelope ttl cannot be zero".to_string());
        }
        let lane_key = threshold_encrypted_mempool_lane_key(lane_kind, tx_kind);
        let submitter_commitment = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-SUBMITTER",
            submitter_label,
        );
        let tx_kind_commitment =
            threshold_encrypted_mempool_string_root("THRESHOLD-ENCRYPTED-MEMPOOL-TX-KIND", tx_kind);
        let payload_ciphertext_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-CIPHERTEXT-PAYLOAD",
            encrypted_payload,
        );
        let pq_ciphertext_root = threshold_encrypted_mempool_pq_ciphertext_root(
            &committee_id,
            &payload_ciphertext_root,
            nonce,
        );
        let fee_blinding = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-FEE-BLINDING",
            &format!("{submitter_label}:{tx_kind}:{nonce}"),
        );
        let encrypted_fee_commitment =
            threshold_encrypted_mempool_amount_commitment(fee_micro_units, &fee_blinding);
        let low_fee_credit_root = low_fee_credit.map(|credit| {
            threshold_encrypted_mempool_string_root(
                "THRESHOLD-ENCRYPTED-MEMPOOL-LOW-FEE-CREDIT",
                credit,
            )
        });
        let replay_nullifier = threshold_encrypted_mempool_replay_nullifier(
            &submitter_commitment,
            &payload_ciphertext_root,
            nonce,
        );
        let expires_at_height = submitted_at_height
            .checked_add(ttl_blocks)
            .ok_or_else(|| "encrypted envelope expiry height overflow".to_string())?;
        let envelope_id = threshold_encrypted_mempool_envelope_id(
            lane_kind,
            &submitter_commitment,
            &tx_kind_commitment,
            &payload_ciphertext_root,
            &pq_ciphertext_root,
            &committee_id,
            nonce,
        );
        let envelope = Self {
            envelope_id,
            lane_kind,
            lane_key,
            submitter_commitment,
            tx_kind_commitment,
            payload_ciphertext_root,
            payload_size_bytes,
            pq_ciphertext_root,
            committee_id,
            encrypted_fee_commitment,
            fee_micro_units,
            low_fee_credit_root,
            anti_mev_commitment_id,
            forced_inclusion_ticket_id,
            replay_nullifier,
            nonce,
            submitted_at_height,
            expires_at_height,
            status: EncryptedEnvelopeStatus::Submitted,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "lane_kind": self.lane_kind.as_str(),
            "lane_key": self.lane_key,
            "submitter_commitment": self.submitter_commitment,
            "tx_kind_commitment": self.tx_kind_commitment,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "payload_size_bytes": self.payload_size_bytes,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "pq_kem_scheme": THRESHOLD_ENCRYPTED_MEMPOOL_PQ_KEM_SCHEME,
            "committee_id": self.committee_id,
            "encrypted_fee_commitment": self.encrypted_fee_commitment,
            "fee_micro_units": self.fee_micro_units,
            "low_fee_credit_root": self.low_fee_credit_root,
            "anti_mev_commitment_id": self.anti_mev_commitment_id,
            "forced_inclusion_ticket_id": self.forced_inclusion_ticket_id,
            "replay_nullifier": self.replay_nullifier,
            "nonce": self.nonce,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("encrypted envelope public record object");
        object.insert(
            "envelope_id".to_string(),
            Value::String(self.envelope_id.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert(
            "envelope_root".to_string(),
            Value::String(self.envelope_root()),
        );
        record
    }

    pub fn envelope_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-ENVELOPE",
            &self.identity_record(),
        )
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn ordering_key(&self, ordering_seed: &str) -> String {
        threshold_encrypted_mempool_ordering_key(
            ordering_seed,
            &self.envelope_id,
            self.submitted_at_height,
            self.lane_kind,
        )
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.envelope_id, "encrypted envelope id")?;
        ensure_non_empty(&self.lane_key, "encrypted envelope lane key")?;
        ensure_non_empty(
            &self.submitter_commitment,
            "encrypted envelope submitter commitment",
        )?;
        ensure_non_empty(
            &self.tx_kind_commitment,
            "encrypted envelope transaction kind commitment",
        )?;
        ensure_non_empty(
            &self.payload_ciphertext_root,
            "encrypted envelope payload ciphertext root",
        )?;
        ensure_non_empty(
            &self.pq_ciphertext_root,
            "encrypted envelope pq ciphertext root",
        )?;
        ensure_non_empty(&self.committee_id, "encrypted envelope committee id")?;
        ensure_non_empty(
            &self.encrypted_fee_commitment,
            "encrypted envelope fee commitment",
        )?;
        ensure_non_empty(
            &self.replay_nullifier,
            "encrypted envelope replay nullifier",
        )?;
        if self.payload_size_bytes == 0 {
            return Err("encrypted envelope payload size must be positive".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("encrypted envelope expiry must follow submission".to_string());
        }
        if self.lane_kind.low_fee() && self.low_fee_credit_root.is_none() {
            return Err("low fee encrypted envelope requires a low fee credit root".to_string());
        }
        if self.lane_kind == ThresholdMempoolLaneKind::ForcedInclusion
            && self.forced_inclusion_ticket_id.is_none()
        {
            return Err(
                "forced inclusion encrypted envelope requires forced inclusion ticket id"
                    .to_string(),
            );
        }
        let expected = threshold_encrypted_mempool_envelope_id(
            self.lane_kind,
            &self.submitter_commitment,
            &self.tx_kind_commitment,
            &self.payload_ciphertext_root,
            &self.pq_ciphertext_root,
            &self.committee_id,
            self.nonce,
        );
        if self.envelope_id != expected {
            return Err("encrypted envelope id mismatch".to_string());
        }
        let expected_nullifier = threshold_encrypted_mempool_replay_nullifier(
            &self.submitter_commitment,
            &self.payload_ciphertext_root,
            self.nonce,
        );
        if self.replay_nullifier != expected_nullifier {
            return Err("encrypted envelope replay nullifier mismatch".to_string());
        }
        Ok(self.envelope_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiMevCommitment {
    pub commitment_id: String,
    pub envelope_id: String,
    pub searcher_commitment: String,
    pub bundle_commitment_root: String,
    pub sealed_bid_root: String,
    pub salt_commitment_root: String,
    pub mev_budget_micro_units: u64,
    pub commit_height: u64,
    pub reveal_deadline_height: u64,
    pub revealed_bid_root: Option<String>,
    pub status: DecryptionShareStatus,
}

impl AntiMevCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        envelope_id: impl Into<String>,
        searcher_label: &str,
        bundle_payload: &Value,
        sealed_bid: &Value,
        salt: &str,
        mev_budget_micro_units: u64,
        commit_height: u64,
        reveal_deadline_height: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        let envelope_id = envelope_id.into();
        ensure_non_empty(&envelope_id, "anti mev envelope id")?;
        ensure_non_empty(searcher_label, "anti mev searcher label")?;
        ensure_non_empty(salt, "anti mev salt")?;
        if reveal_deadline_height <= commit_height {
            return Err("anti mev reveal deadline must follow commit height".to_string());
        }
        let searcher_commitment = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-ANTI-MEV-SEARCHER",
            searcher_label,
        );
        let bundle_commitment_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-ANTI-MEV-BUNDLE",
            bundle_payload,
        );
        let sealed_bid_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-ANTI-MEV-SEALED-BID",
            sealed_bid,
        );
        let salt_commitment_root = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-ANTI-MEV-SALT",
            salt,
        );
        let commitment_id = threshold_encrypted_mempool_anti_mev_commitment_id(
            &envelope_id,
            &searcher_commitment,
            &bundle_commitment_root,
            &sealed_bid_root,
            commit_height,
        );
        let commitment = Self {
            commitment_id,
            envelope_id,
            searcher_commitment,
            bundle_commitment_root,
            sealed_bid_root,
            salt_commitment_root,
            mev_budget_micro_units,
            commit_height,
            reveal_deadline_height,
            revealed_bid_root: None,
            status: DecryptionShareStatus::Committed,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn reveal_bid(&mut self, revealed_bid: &Value) -> ThresholdEncryptedMempoolResult<()> {
        self.revealed_bid_root = Some(threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-ANTI-MEV-REVEAL",
            revealed_bid,
        ));
        self.status = DecryptionShareStatus::Revealed;
        self.validate()?;
        Ok(())
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_anti_mev_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "searcher_commitment": self.searcher_commitment,
            "bundle_commitment_root": self.bundle_commitment_root,
            "sealed_bid_root": self.sealed_bid_root,
            "salt_commitment_root": self.salt_commitment_root,
            "mev_budget_micro_units": self.mev_budget_micro_units,
            "commit_height": self.commit_height,
            "reveal_deadline_height": self.reveal_deadline_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("anti mev commitment public record object");
        object.insert(
            "commitment_id".to_string(),
            Value::String(self.commitment_id.clone()),
        );
        object.insert(
            "revealed_bid_root".to_string(),
            self.revealed_bid_root
                .as_ref()
                .map(|root| Value::String(root.clone()))
                .unwrap_or(Value::Null),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert(
            "commitment_root".to_string(),
            Value::String(self.commitment_root()),
        );
        record
    }

    pub fn commitment_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-ANTI-MEV-COMMITMENT",
            &self.identity_record(),
        )
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.commitment_id, "anti mev commitment id")?;
        ensure_non_empty(&self.envelope_id, "anti mev envelope id")?;
        ensure_non_empty(&self.searcher_commitment, "anti mev searcher commitment")?;
        ensure_non_empty(
            &self.bundle_commitment_root,
            "anti mev bundle commitment root",
        )?;
        ensure_non_empty(&self.sealed_bid_root, "anti mev sealed bid root")?;
        ensure_non_empty(&self.salt_commitment_root, "anti mev salt commitment root")?;
        if self.reveal_deadline_height <= self.commit_height {
            return Err("anti mev reveal deadline must follow commit height".to_string());
        }
        if matches!(
            self.status,
            DecryptionShareStatus::Accepted | DecryptionShareStatus::Slashed
        ) && self.revealed_bid_root.is_none()
        {
            return Err("anti mev accepted or slashed status requires revealed bid".to_string());
        }
        let expected = threshold_encrypted_mempool_anti_mev_commitment_id(
            &self.envelope_id,
            &self.searcher_commitment,
            &self.bundle_commitment_root,
            &self.sealed_bid_root,
            self.commit_height,
        );
        if self.commitment_id != expected {
            return Err("anti mev commitment id mismatch".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionShareCommitment {
    pub commitment_id: String,
    pub window_id: String,
    pub envelope_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub share_index: u64,
    pub encrypted_share_root: String,
    pub share_commitment_root: String,
    pub commit_height: u64,
    pub reveal_deadline_height: u64,
    pub status: DecryptionShareStatus,
}

impl DecryptionShareCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: impl Into<String>,
        envelope_id: impl Into<String>,
        committee_id: impl Into<String>,
        member_id: impl Into<String>,
        share_index: u64,
        encrypted_share_payload: &Value,
        share_commitment: &str,
        commit_height: u64,
        reveal_deadline_height: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        let window_id = window_id.into();
        let envelope_id = envelope_id.into();
        let committee_id = committee_id.into();
        let member_id = member_id.into();
        ensure_non_empty(&window_id, "decryption share window id")?;
        ensure_non_empty(&envelope_id, "decryption share envelope id")?;
        ensure_non_empty(&committee_id, "decryption share committee id")?;
        ensure_non_empty(&member_id, "decryption share member id")?;
        ensure_non_empty(share_commitment, "decryption share commitment")?;
        if reveal_deadline_height <= commit_height {
            return Err("decryption share reveal deadline must follow commit height".to_string());
        }
        let encrypted_share_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-ENCRYPTED-SHARE",
            encrypted_share_payload,
        );
        let share_commitment_root = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-SHARE-COMMITMENT",
            share_commitment,
        );
        let commitment_id = threshold_encrypted_mempool_decryption_commitment_id(
            &window_id,
            &envelope_id,
            &committee_id,
            &member_id,
            share_index,
            &share_commitment_root,
        );
        let commitment = Self {
            commitment_id,
            window_id,
            envelope_id,
            committee_id,
            member_id,
            share_index,
            encrypted_share_root,
            share_commitment_root,
            commit_height,
            reveal_deadline_height,
            status: DecryptionShareStatus::Committed,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_decryption_share_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "envelope_id": self.envelope_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "share_index": self.share_index,
            "encrypted_share_root": self.encrypted_share_root,
            "share_commitment_root": self.share_commitment_root,
            "commit_height": self.commit_height,
            "reveal_deadline_height": self.reveal_deadline_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("decryption share commitment record object");
        object.insert(
            "commitment_id".to_string(),
            Value::String(self.commitment_id.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert(
            "commitment_root".to_string(),
            Value::String(self.commitment_root()),
        );
        record
    }

    pub fn commitment_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-DECRYPTION-SHARE-COMMITMENT",
            &self.identity_record(),
        )
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.commitment_id, "decryption share commitment id")?;
        ensure_non_empty(&self.window_id, "decryption share window id")?;
        ensure_non_empty(&self.envelope_id, "decryption share envelope id")?;
        ensure_non_empty(&self.committee_id, "decryption share committee id")?;
        ensure_non_empty(&self.member_id, "decryption share member id")?;
        ensure_non_empty(
            &self.encrypted_share_root,
            "decryption share encrypted share root",
        )?;
        ensure_non_empty(
            &self.share_commitment_root,
            "decryption share commitment root",
        )?;
        if self.reveal_deadline_height <= self.commit_height {
            return Err("decryption share reveal deadline must follow commit height".to_string());
        }
        let expected = threshold_encrypted_mempool_decryption_commitment_id(
            &self.window_id,
            &self.envelope_id,
            &self.committee_id,
            &self.member_id,
            self.share_index,
            &self.share_commitment_root,
        );
        if self.commitment_id != expected {
            return Err("decryption share commitment id mismatch".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionShareReveal {
    pub reveal_id: String,
    pub commitment_id: String,
    pub window_id: String,
    pub envelope_id: String,
    pub committee_id: String,
    pub member_id: String,
    pub share_index: u64,
    pub decrypted_share_root: String,
    pub proof_root: String,
    pub revealed_at_height: u64,
    pub accepted: bool,
    pub status: DecryptionShareStatus,
}

impl DecryptionShareReveal {
    pub fn new(
        commitment: &DecryptionShareCommitment,
        decrypted_share: &str,
        proof: &Value,
        revealed_at_height: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        ensure_non_empty(decrypted_share, "decryption share reveal decrypted share")?;
        if revealed_at_height > commitment.reveal_deadline_height {
            return Err("decryption share reveal is after deadline".to_string());
        }
        let decrypted_share_root = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-DECRYPTED-SHARE",
            decrypted_share,
        );
        let proof_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-DECRYPTION-PROOF",
            proof,
        );
        let reveal_id = threshold_encrypted_mempool_decryption_reveal_id(
            &commitment.commitment_id,
            &commitment.envelope_id,
            &commitment.member_id,
            &decrypted_share_root,
            revealed_at_height,
        );
        let reveal = Self {
            reveal_id,
            commitment_id: commitment.commitment_id.clone(),
            window_id: commitment.window_id.clone(),
            envelope_id: commitment.envelope_id.clone(),
            committee_id: commitment.committee_id.clone(),
            member_id: commitment.member_id.clone(),
            share_index: commitment.share_index,
            decrypted_share_root,
            proof_root,
            revealed_at_height,
            accepted: true,
            status: DecryptionShareStatus::Accepted,
        };
        reveal.validate()?;
        Ok(reveal)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_decryption_share_reveal",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "window_id": self.window_id,
            "envelope_id": self.envelope_id,
            "committee_id": self.committee_id,
            "member_id": self.member_id,
            "share_index": self.share_index,
            "decrypted_share_root": self.decrypted_share_root,
            "proof_root": self.proof_root,
            "revealed_at_height": self.revealed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("decryption share reveal record object");
        object.insert(
            "reveal_id".to_string(),
            Value::String(self.reveal_id.clone()),
        );
        object.insert("accepted".to_string(), Value::Bool(self.accepted));
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert("reveal_root".to_string(), Value::String(self.reveal_root()));
        record
    }

    pub fn reveal_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-DECRYPTION-SHARE-REVEAL",
            &self.identity_record(),
        )
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.reveal_id, "decryption share reveal id")?;
        ensure_non_empty(&self.commitment_id, "decryption share reveal commitment id")?;
        ensure_non_empty(&self.window_id, "decryption share reveal window id")?;
        ensure_non_empty(&self.envelope_id, "decryption share reveal envelope id")?;
        ensure_non_empty(&self.committee_id, "decryption share reveal committee id")?;
        ensure_non_empty(&self.member_id, "decryption share reveal member id")?;
        ensure_non_empty(
            &self.decrypted_share_root,
            "decryption share reveal decrypted share root",
        )?;
        ensure_non_empty(&self.proof_root, "decryption share reveal proof root")?;
        if self.accepted && self.status != DecryptionShareStatus::Accepted {
            return Err("accepted decryption share reveal must have accepted status".to_string());
        }
        let expected = threshold_encrypted_mempool_decryption_reveal_id(
            &self.commitment_id,
            &self.envelope_id,
            &self.member_id,
            &self.decrypted_share_root,
            self.revealed_at_height,
        );
        if self.reveal_id != expected {
            return Err("decryption share reveal id mismatch".to_string());
        }
        Ok(self.reveal_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingWindow {
    pub window_id: String,
    pub sequence: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub commit_deadline_height: u64,
    pub reveal_start_height: u64,
    pub reveal_end_height: u64,
    pub challenge_deadline_height: u64,
    pub ordering_seed: String,
    pub envelope_ids: Vec<String>,
    pub low_fee_lane_keys: Vec<String>,
    pub forced_inclusion_ticket_ids: Vec<String>,
    pub anti_mev_commitment_root: String,
    pub decryption_share_commitment_root: String,
    pub decryption_share_reveal_root: String,
    pub ordered_envelope_ids: Vec<String>,
    pub order_root: String,
    pub status: FairOrderingWindowStatus,
}

impl FairOrderingWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        start_height: u64,
        end_height: u64,
        decrypt_delay_blocks: u64,
        reveal_window_blocks: u64,
        challenge_window_blocks: u64,
        envelope_ids: Vec<String>,
        low_fee_lane_keys: Vec<String>,
        forced_inclusion_ticket_ids: Vec<String>,
        anti_mev_commitment_root: impl Into<String>,
        decryption_share_commitment_root: impl Into<String>,
        decryption_share_reveal_root: impl Into<String>,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        if end_height <= start_height {
            return Err("fair ordering window end must follow start".to_string());
        }
        if envelope_ids.is_empty() {
            return Err("fair ordering window requires at least one envelope".to_string());
        }
        ensure_unique_strings(&envelope_ids, "fair ordering window envelope ids")?;
        let commit_deadline_height = end_height;
        let reveal_start_height = commit_deadline_height
            .checked_add(decrypt_delay_blocks)
            .ok_or_else(|| "fair ordering window reveal start overflow".to_string())?;
        let reveal_end_height = reveal_start_height
            .checked_add(reveal_window_blocks)
            .ok_or_else(|| "fair ordering window reveal end overflow".to_string())?;
        let challenge_deadline_height = reveal_end_height
            .checked_add(challenge_window_blocks)
            .ok_or_else(|| "fair ordering window challenge deadline overflow".to_string())?;
        let anti_mev_commitment_root = anti_mev_commitment_root.into();
        let decryption_share_commitment_root = decryption_share_commitment_root.into();
        let decryption_share_reveal_root = decryption_share_reveal_root.into();
        ensure_non_empty(
            &anti_mev_commitment_root,
            "fair ordering window anti mev root",
        )?;
        ensure_non_empty(
            &decryption_share_commitment_root,
            "fair ordering window decryption commitment root",
        )?;
        ensure_non_empty(
            &decryption_share_reveal_root,
            "fair ordering window decryption reveal root",
        )?;
        let ordering_seed = threshold_encrypted_mempool_ordering_seed(
            sequence,
            start_height,
            end_height,
            &anti_mev_commitment_root,
            &decryption_share_commitment_root,
        );
        let order_root = threshold_encrypted_mempool_string_set_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-EMPTY-ORDER",
            &[],
        );
        let window_id = threshold_encrypted_mempool_fair_ordering_window_id(
            sequence,
            start_height,
            end_height,
            &ordering_seed,
            &threshold_encrypted_mempool_string_set_root(
                "THRESHOLD-ENCRYPTED-MEMPOOL-WINDOW-ENVELOPES",
                &envelope_ids,
            ),
        );
        let window = Self {
            window_id,
            sequence,
            start_height,
            end_height,
            commit_deadline_height,
            reveal_start_height,
            reveal_end_height,
            challenge_deadline_height,
            ordering_seed,
            envelope_ids,
            low_fee_lane_keys,
            forced_inclusion_ticket_ids,
            anti_mev_commitment_root,
            decryption_share_commitment_root,
            decryption_share_reveal_root,
            ordered_envelope_ids: Vec::new(),
            order_root,
            status: FairOrderingWindowStatus::Collecting,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn seal_with_order(
        &mut self,
        ordered_envelope_ids: Vec<String>,
    ) -> ThresholdEncryptedMempoolResult<()> {
        if ordered_envelope_ids.is_empty() {
            return Err("fair ordering window order cannot be empty".to_string());
        }
        ensure_unique_strings(
            &ordered_envelope_ids,
            "fair ordering window ordered envelope ids",
        )?;
        let expected = self.envelope_ids.iter().cloned().collect::<BTreeSet<_>>();
        let observed = ordered_envelope_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if expected != observed {
            return Err(
                "fair ordering window order must contain exactly window envelopes".to_string(),
            );
        }
        self.ordered_envelope_ids = ordered_envelope_ids;
        self.order_root = threshold_encrypted_mempool_string_set_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-ORDERED-ENVELOPES",
            &self.ordered_envelope_ids,
        );
        self.status = FairOrderingWindowStatus::Sealed;
        self.validate()?;
        Ok(())
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_fair_ordering_window",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "ordering_policy": THRESHOLD_ENCRYPTED_MEMPOOL_FAIR_ORDERING_POLICY,
            "sequence": self.sequence,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "commit_deadline_height": self.commit_deadline_height,
            "reveal_start_height": self.reveal_start_height,
            "reveal_end_height": self.reveal_end_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "ordering_seed": self.ordering_seed,
            "envelope_root": threshold_encrypted_mempool_string_set_root(
                "THRESHOLD-ENCRYPTED-MEMPOOL-WINDOW-ENVELOPES",
                &self.envelope_ids
            ),
            "low_fee_lane_root": threshold_encrypted_mempool_string_set_root(
                "THRESHOLD-ENCRYPTED-MEMPOOL-WINDOW-LOW-FEE-LANES",
                &self.low_fee_lane_keys
            ),
            "forced_inclusion_ticket_root": threshold_encrypted_mempool_string_set_root(
                "THRESHOLD-ENCRYPTED-MEMPOOL-WINDOW-FORCED-TICKETS",
                &self.forced_inclusion_ticket_ids
            ),
            "anti_mev_commitment_root": self.anti_mev_commitment_root,
            "decryption_share_commitment_root": self.decryption_share_commitment_root,
            "decryption_share_reveal_root": self.decryption_share_reveal_root,
            "order_root": self.order_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("fair ordering window public record object");
        object.insert(
            "window_id".to_string(),
            Value::String(self.window_id.clone()),
        );
        object.insert("envelope_ids".to_string(), json!(self.envelope_ids));
        object.insert(
            "ordered_envelope_ids".to_string(),
            json!(self.ordered_envelope_ids),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert("window_root".to_string(), Value::String(self.window_root()));
        record
    }

    pub fn window_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-FAIR-ORDERING-WINDOW",
            &self.identity_record(),
        )
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.is_open()
            && self.start_height <= height
            && height <= self.challenge_deadline_height
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.window_id, "fair ordering window id")?;
        ensure_non_empty(&self.ordering_seed, "fair ordering window seed")?;
        ensure_non_empty(
            &self.anti_mev_commitment_root,
            "fair ordering window anti mev root",
        )?;
        ensure_non_empty(
            &self.decryption_share_commitment_root,
            "fair ordering window decryption commitment root",
        )?;
        ensure_non_empty(
            &self.decryption_share_reveal_root,
            "fair ordering window decryption reveal root",
        )?;
        if self.end_height <= self.start_height {
            return Err("fair ordering window end must follow start".to_string());
        }
        if self.commit_deadline_height != self.end_height {
            return Err("fair ordering window commit deadline must equal end height".to_string());
        }
        if self.reveal_start_height < self.commit_deadline_height {
            return Err("fair ordering window reveal start before commit deadline".to_string());
        }
        if self.reveal_end_height <= self.reveal_start_height {
            return Err("fair ordering window reveal end must follow reveal start".to_string());
        }
        if self.challenge_deadline_height < self.reveal_end_height {
            return Err("fair ordering window challenge deadline before reveal end".to_string());
        }
        if self.envelope_ids.is_empty() {
            return Err("fair ordering window requires envelopes".to_string());
        }
        ensure_unique_strings(&self.envelope_ids, "fair ordering window envelope ids")?;
        ensure_unique_strings(
            &self.ordered_envelope_ids,
            "fair ordering window ordered envelope ids",
        )?;
        if !self.ordered_envelope_ids.is_empty() {
            let expected = self.envelope_ids.iter().cloned().collect::<BTreeSet<_>>();
            let observed = self
                .ordered_envelope_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if expected != observed {
                return Err("fair ordering window ordered ids must match envelope ids".to_string());
            }
        }
        let envelope_root = threshold_encrypted_mempool_string_set_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-WINDOW-ENVELOPES",
            &self.envelope_ids,
        );
        let expected = threshold_encrypted_mempool_fair_ordering_window_id(
            self.sequence,
            self.start_height,
            self.end_height,
            &self.ordering_seed,
            &envelope_root,
        );
        if self.window_id != expected {
            return Err("fair ordering window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeQueueLane {
    pub lane_id: String,
    pub lane_key: String,
    pub lane_kind: ThresholdMempoolLaneKind,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub subsidy_budget_units: u64,
    pub reserved_subsidy_units: u64,
    pub eligible_envelope_ids: Vec<String>,
    pub pending_nullifier_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: LowFeeLaneStatus,
}

impl LowFeeQueueLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_key: impl Into<String>,
        lane_kind: ThresholdMempoolLaneKind,
        fee_asset_id: impl Into<String>,
        max_fee_micro_units: u64,
        subsidy_budget_units: u64,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        let lane_key = lane_key.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&lane_key, "low fee lane key")?;
        ensure_non_empty(&fee_asset_id, "low fee lane fee asset")?;
        if !lane_kind.low_fee() {
            return Err("low fee queue lane must use a low fee lane kind".to_string());
        }
        if max_fee_micro_units == 0 {
            return Err("low fee lane max fee cannot be zero".to_string());
        }
        if subsidy_budget_units == 0 {
            return Err("low fee lane subsidy budget cannot be zero".to_string());
        }
        if ttl_blocks == 0 {
            return Err("low fee lane ttl cannot be zero".to_string());
        }
        let expires_at_height = created_at_height
            .checked_add(ttl_blocks)
            .ok_or_else(|| "low fee lane expiry overflow".to_string())?;
        let pending_nullifier_root = threshold_encrypted_mempool_string_set_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-LOW-FEE-PENDING-NULLIFIERS",
            &[],
        );
        let lane_id = threshold_encrypted_mempool_low_fee_lane_id(
            &lane_key,
            lane_kind,
            &fee_asset_id,
            max_fee_micro_units,
            created_at_height,
        );
        let lane = Self {
            lane_id,
            lane_key,
            lane_kind,
            fee_asset_id,
            max_fee_micro_units,
            subsidy_budget_units,
            reserved_subsidy_units: 0,
            eligible_envelope_ids: Vec::new(),
            pending_nullifier_root,
            created_at_height,
            expires_at_height,
            status: LowFeeLaneStatus::Active,
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn reserve_envelope(
        &mut self,
        envelope: &EncryptedTransactionEnvelope,
        subsidy_units: u64,
    ) -> ThresholdEncryptedMempoolResult<()> {
        if envelope.fee_micro_units > self.max_fee_micro_units {
            return Err("low fee lane envelope fee exceeds lane cap".to_string());
        }
        if !envelope.lane_kind.low_fee() {
            return Err("low fee lane envelope must be low fee".to_string());
        }
        if self.eligible_envelope_ids.contains(&envelope.envelope_id) {
            return Ok(());
        }
        let next_reserved = self
            .reserved_subsidy_units
            .checked_add(subsidy_units)
            .ok_or_else(|| "low fee lane reserved subsidy overflow".to_string())?;
        if next_reserved > self.subsidy_budget_units {
            return Err("low fee lane subsidy budget exhausted".to_string());
        }
        self.reserved_subsidy_units = next_reserved;
        self.eligible_envelope_ids
            .push(envelope.envelope_id.clone());
        self.pending_nullifier_root = threshold_encrypted_mempool_string_set_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-LOW-FEE-PENDING-NULLIFIERS",
            &self.eligible_envelope_ids,
        );
        if self.reserved_subsidy_units == self.subsidy_budget_units {
            self.status = LowFeeLaneStatus::Exhausted;
        }
        self.validate()?;
        Ok(())
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_low_fee_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "lane_key": self.lane_key,
            "lane_kind": self.lane_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "subsidy_budget_units": self.subsidy_budget_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("low fee lane public record object");
        object.insert("lane_id".to_string(), Value::String(self.lane_id.clone()));
        object.insert(
            "reserved_subsidy_units".to_string(),
            json!(self.reserved_subsidy_units),
        );
        object.insert(
            "eligible_envelope_ids".to_string(),
            json!(self.eligible_envelope_ids),
        );
        object.insert(
            "pending_nullifier_root".to_string(),
            Value::String(self.pending_nullifier_root.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert("lane_root".to_string(), Value::String(self.lane_root()));
        record
    }

    pub fn lane_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-LOW-FEE-LANE",
            &self.identity_record(),
        )
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == LowFeeLaneStatus::Active
            && self.created_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.lane_id, "low fee lane id")?;
        ensure_non_empty(&self.lane_key, "low fee lane key")?;
        ensure_non_empty(&self.fee_asset_id, "low fee lane fee asset")?;
        ensure_non_empty(
            &self.pending_nullifier_root,
            "low fee lane pending nullifier root",
        )?;
        if !self.lane_kind.low_fee() {
            return Err("low fee lane kind must be low fee".to_string());
        }
        if self.max_fee_micro_units == 0 || self.subsidy_budget_units == 0 {
            return Err("low fee lane fee cap and subsidy budget must be positive".to_string());
        }
        if self.reserved_subsidy_units > self.subsidy_budget_units {
            return Err("low fee lane reserved subsidy exceeds budget".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("low fee lane expiry must follow creation".to_string());
        }
        ensure_unique_strings(
            &self.eligible_envelope_ids,
            "low fee lane eligible envelope ids",
        )?;
        let expected = threshold_encrypted_mempool_low_fee_lane_id(
            &self.lane_key,
            self.lane_kind,
            &self.fee_asset_id,
            self.max_fee_micro_units,
            self.created_at_height,
        );
        if self.lane_id != expected {
            return Err("low fee lane id mismatch".to_string());
        }
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedInclusionHook {
    pub hook_id: String,
    pub ticket_id: String,
    pub envelope_id: String,
    pub requester_commitment: String,
    pub l1_anchor_root: String,
    pub escape_payload_root: String,
    pub requested_at_height: u64,
    pub soft_deadline_height: u64,
    pub hard_deadline_height: u64,
    pub rescue_deadline_height: u64,
    pub bond_units: u64,
    pub priority_score: u64,
    pub status: ForcedInclusionHookStatus,
}

impl ForcedInclusionHook {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket_id: impl Into<String>,
        envelope_id: impl Into<String>,
        requester_label: &str,
        l1_anchor: &Value,
        escape_payload: &Value,
        requested_at_height: u64,
        grace_blocks: u64,
        hard_delay_blocks: u64,
        rescue_delay_blocks: u64,
        bond_units: u64,
        priority_score: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        let ticket_id = ticket_id.into();
        let envelope_id = envelope_id.into();
        ensure_non_empty(&ticket_id, "forced inclusion ticket id")?;
        ensure_non_empty(&envelope_id, "forced inclusion envelope id")?;
        ensure_non_empty(requester_label, "forced inclusion requester")?;
        if grace_blocks == 0 || hard_delay_blocks < grace_blocks {
            return Err("forced inclusion deadlines are inconsistent".to_string());
        }
        if rescue_delay_blocks < hard_delay_blocks {
            return Err("forced inclusion rescue delay must be at least hard delay".to_string());
        }
        if bond_units == 0 {
            return Err("forced inclusion bond must be positive".to_string());
        }
        let requester_commitment = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-FORCED-REQUESTER",
            requester_label,
        );
        let l1_anchor_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-FORCED-L1-ANCHOR",
            l1_anchor,
        );
        let escape_payload_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-FORCED-ESCAPE-PAYLOAD",
            escape_payload,
        );
        let soft_deadline_height = requested_at_height
            .checked_add(grace_blocks)
            .ok_or_else(|| "forced inclusion soft deadline overflow".to_string())?;
        let hard_deadline_height = requested_at_height
            .checked_add(hard_delay_blocks)
            .ok_or_else(|| "forced inclusion hard deadline overflow".to_string())?;
        let rescue_deadline_height = requested_at_height
            .checked_add(rescue_delay_blocks)
            .ok_or_else(|| "forced inclusion rescue deadline overflow".to_string())?;
        let hook_id = threshold_encrypted_mempool_forced_inclusion_hook_id(
            &ticket_id,
            &envelope_id,
            &requester_commitment,
            &l1_anchor_root,
            requested_at_height,
        );
        let hook = Self {
            hook_id,
            ticket_id,
            envelope_id,
            requester_commitment,
            l1_anchor_root,
            escape_payload_root,
            requested_at_height,
            soft_deadline_height,
            hard_deadline_height,
            rescue_deadline_height,
            bond_units,
            priority_score,
            status: ForcedInclusionHookStatus::Pending,
        };
        hook.validate()?;
        Ok(hook)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_forced_inclusion_hook",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "envelope_id": self.envelope_id,
            "requester_commitment": self.requester_commitment,
            "l1_anchor_root": self.l1_anchor_root,
            "escape_payload_root": self.escape_payload_root,
            "requested_at_height": self.requested_at_height,
            "soft_deadline_height": self.soft_deadline_height,
            "hard_deadline_height": self.hard_deadline_height,
            "rescue_deadline_height": self.rescue_deadline_height,
            "bond_units": self.bond_units,
            "priority_score": self.priority_score,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("forced inclusion hook public record object");
        object.insert("hook_id".to_string(), Value::String(self.hook_id.clone()));
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert("hook_root".to_string(), Value::String(self.hook_root()));
        record
    }

    pub fn hook_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-FORCED-INCLUSION-HOOK",
            &self.identity_record(),
        )
    }

    pub fn rescue_eligible_at(&self, height: u64) -> bool {
        self.status.is_pending() && height >= self.hard_deadline_height
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.hook_id, "forced inclusion hook id")?;
        ensure_non_empty(&self.ticket_id, "forced inclusion ticket id")?;
        ensure_non_empty(&self.envelope_id, "forced inclusion envelope id")?;
        ensure_non_empty(
            &self.requester_commitment,
            "forced inclusion requester commitment",
        )?;
        ensure_non_empty(&self.l1_anchor_root, "forced inclusion l1 anchor root")?;
        ensure_non_empty(
            &self.escape_payload_root,
            "forced inclusion escape payload root",
        )?;
        if self.soft_deadline_height <= self.requested_at_height {
            return Err("forced inclusion soft deadline must follow request".to_string());
        }
        if self.hard_deadline_height < self.soft_deadline_height {
            return Err("forced inclusion hard deadline before soft deadline".to_string());
        }
        if self.rescue_deadline_height < self.hard_deadline_height {
            return Err("forced inclusion rescue deadline before hard deadline".to_string());
        }
        if self.bond_units == 0 {
            return Err("forced inclusion bond must be positive".to_string());
        }
        let expected = threshold_encrypted_mempool_forced_inclusion_hook_id(
            &self.ticket_id,
            &self.envelope_id,
            &self.requester_commitment,
            &self.l1_anchor_root,
            self.requested_at_height,
        );
        if self.hook_id != expected {
            return Err("forced inclusion hook id mismatch".to_string());
        }
        Ok(self.hook_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyDisclosureReceipt {
    pub receipt_id: String,
    pub envelope_id: String,
    pub committee_id: String,
    pub scope: PrivacyDisclosureScope,
    pub viewer_commitment: String,
    pub disclosed_record_root: String,
    pub justification_root: String,
    pub auditor_signature_root: String,
    pub redaction_root: String,
    pub disclosed_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivacyDisclosureStatus,
}

impl PrivacyDisclosureReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        envelope_id: impl Into<String>,
        committee_id: impl Into<String>,
        scope: PrivacyDisclosureScope,
        viewer_label: &str,
        disclosed_record: &Value,
        justification: &Value,
        auditor_signature: &str,
        redaction_policy: &Value,
        disclosed_at_height: u64,
        ttl_blocks: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        let envelope_id = envelope_id.into();
        let committee_id = committee_id.into();
        ensure_non_empty(&envelope_id, "privacy disclosure envelope id")?;
        ensure_non_empty(&committee_id, "privacy disclosure committee id")?;
        ensure_non_empty(viewer_label, "privacy disclosure viewer")?;
        ensure_non_empty(auditor_signature, "privacy disclosure auditor signature")?;
        if ttl_blocks == 0 {
            return Err("privacy disclosure ttl cannot be zero".to_string());
        }
        let viewer_commitment = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-DISCLOSURE-VIEWER",
            viewer_label,
        );
        let disclosed_record_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-DISCLOSURE-RECORD",
            disclosed_record,
        );
        let justification_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-DISCLOSURE-JUSTIFICATION",
            justification,
        );
        let auditor_signature_root = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-DISCLOSURE-AUDITOR-SIGNATURE",
            auditor_signature,
        );
        let redaction_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-DISCLOSURE-REDACTION",
            redaction_policy,
        );
        let expires_at_height = disclosed_at_height
            .checked_add(ttl_blocks)
            .ok_or_else(|| "privacy disclosure expiry overflow".to_string())?;
        let receipt_id = threshold_encrypted_mempool_privacy_disclosure_receipt_id(
            &envelope_id,
            &committee_id,
            scope,
            &viewer_commitment,
            &disclosed_record_root,
            disclosed_at_height,
        );
        let receipt = Self {
            receipt_id,
            envelope_id,
            committee_id,
            scope,
            viewer_commitment,
            disclosed_record_root,
            justification_root,
            auditor_signature_root,
            redaction_root,
            disclosed_at_height,
            expires_at_height,
            status: PrivacyDisclosureStatus::Disclosed,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_privacy_disclosure_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "committee_id": self.committee_id,
            "scope": self.scope.as_str(),
            "viewer_commitment": self.viewer_commitment,
            "disclosed_record_root": self.disclosed_record_root,
            "justification_root": self.justification_root,
            "auditor_signature_root": self.auditor_signature_root,
            "redaction_root": self.redaction_root,
            "disclosed_at_height": self.disclosed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("privacy disclosure receipt public record object");
        object.insert(
            "receipt_id".to_string(),
            Value::String(self.receipt_id.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert(
            "receipt_root".to_string(),
            Value::String(self.receipt_root()),
        );
        record
    }

    pub fn receipt_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-PRIVACY-DISCLOSURE-RECEIPT",
            &self.identity_record(),
        )
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.receipt_id, "privacy disclosure receipt id")?;
        ensure_non_empty(&self.envelope_id, "privacy disclosure envelope id")?;
        ensure_non_empty(&self.committee_id, "privacy disclosure committee id")?;
        ensure_non_empty(
            &self.viewer_commitment,
            "privacy disclosure viewer commitment",
        )?;
        ensure_non_empty(
            &self.disclosed_record_root,
            "privacy disclosure record root",
        )?;
        ensure_non_empty(
            &self.justification_root,
            "privacy disclosure justification root",
        )?;
        ensure_non_empty(
            &self.auditor_signature_root,
            "privacy disclosure auditor signature root",
        )?;
        ensure_non_empty(&self.redaction_root, "privacy disclosure redaction root")?;
        if self.expires_at_height <= self.disclosed_at_height {
            return Err("privacy disclosure expiry must follow disclosure".to_string());
        }
        let expected = threshold_encrypted_mempool_privacy_disclosure_receipt_id(
            &self.envelope_id,
            &self.committee_id,
            self.scope,
            &self.viewer_commitment,
            &self.disclosed_record_root,
            self.disclosed_at_height,
        );
        if self.receipt_id != expected {
            return Err("privacy disclosure receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationSlashingEvidence {
    pub evidence_id: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub accused_member_id: String,
    pub related_committee_id: String,
    pub window_id: Option<String>,
    pub envelope_id: Option<String>,
    pub first_record_root: String,
    pub second_record_root: String,
    pub conflict_root: String,
    pub reporter_commitment: String,
    pub slash_amount_units: u64,
    pub discovered_at_height: u64,
    pub submit_deadline_height: u64,
    pub status: SlashingEvidenceStatus,
}

impl EquivocationSlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: SlashingEvidenceKind,
        accused_member_id: impl Into<String>,
        related_committee_id: impl Into<String>,
        window_id: Option<String>,
        envelope_id: Option<String>,
        first_record: &Value,
        second_record: &Value,
        reporter_label: &str,
        slash_amount_units: u64,
        discovered_at_height: u64,
        submit_deadline_height: u64,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        let accused_member_id = accused_member_id.into();
        let related_committee_id = related_committee_id.into();
        ensure_non_empty(&accused_member_id, "slashing evidence accused member")?;
        ensure_non_empty(&related_committee_id, "slashing evidence committee")?;
        ensure_non_empty(reporter_label, "slashing evidence reporter")?;
        if slash_amount_units == 0 {
            return Err("slashing evidence slash amount must be positive".to_string());
        }
        if submit_deadline_height <= discovered_at_height {
            return Err("slashing evidence submit deadline must follow discovery".to_string());
        }
        let first_record_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-SLASH-FIRST-RECORD",
            first_record,
        );
        let second_record_root = threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-SLASH-SECOND-RECORD",
            second_record,
        );
        if first_record_root == second_record_root {
            return Err("slashing evidence records must conflict".to_string());
        }
        let conflict_root = threshold_encrypted_mempool_conflict_root(
            evidence_kind,
            &first_record_root,
            &second_record_root,
        );
        let reporter_commitment = threshold_encrypted_mempool_string_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-SLASH-REPORTER",
            reporter_label,
        );
        let evidence_id = threshold_encrypted_mempool_slashing_evidence_id(
            evidence_kind,
            &accused_member_id,
            &related_committee_id,
            window_id.as_deref(),
            envelope_id.as_deref(),
            &conflict_root,
            discovered_at_height,
        );
        let evidence = Self {
            evidence_id,
            evidence_kind,
            accused_member_id,
            related_committee_id,
            window_id,
            envelope_id,
            first_record_root,
            second_record_root,
            conflict_root,
            reporter_commitment,
            slash_amount_units,
            discovered_at_height,
            submit_deadline_height,
            status: SlashingEvidenceStatus::Observed,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_equivocation_slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "evidence_kind": self.evidence_kind.as_str(),
            "accused_member_id": self.accused_member_id,
            "related_committee_id": self.related_committee_id,
            "window_id": self.window_id,
            "envelope_id": self.envelope_id,
            "first_record_root": self.first_record_root,
            "second_record_root": self.second_record_root,
            "conflict_root": self.conflict_root,
            "reporter_commitment": self.reporter_commitment,
            "slash_amount_units": self.slash_amount_units,
            "discovered_at_height": self.discovered_at_height,
            "submit_deadline_height": self.submit_deadline_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("slashing evidence public record object");
        object.insert(
            "evidence_id".to_string(),
            Value::String(self.evidence_id.clone()),
        );
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert(
            "evidence_root".to_string(),
            Value::String(self.evidence_root()),
        );
        record
    }

    pub fn evidence_root(&self) -> String {
        threshold_encrypted_mempool_payload_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-SLASHING-EVIDENCE",
            &self.identity_record(),
        )
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(&self.evidence_id, "slashing evidence id")?;
        ensure_non_empty(
            &self.accused_member_id,
            "slashing evidence accused member id",
        )?;
        ensure_non_empty(
            &self.related_committee_id,
            "slashing evidence related committee id",
        )?;
        ensure_non_empty(&self.first_record_root, "slashing evidence first record")?;
        ensure_non_empty(&self.second_record_root, "slashing evidence second record")?;
        ensure_non_empty(&self.conflict_root, "slashing evidence conflict root")?;
        ensure_non_empty(
            &self.reporter_commitment,
            "slashing evidence reporter commitment",
        )?;
        if self.first_record_root == self.second_record_root {
            return Err("slashing evidence records must conflict".to_string());
        }
        if self.slash_amount_units == 0 {
            return Err("slashing evidence slash amount must be positive".to_string());
        }
        if self.submit_deadline_height <= self.discovered_at_height {
            return Err("slashing evidence submit deadline must follow discovery".to_string());
        }
        let expected_conflict = threshold_encrypted_mempool_conflict_root(
            self.evidence_kind,
            &self.first_record_root,
            &self.second_record_root,
        );
        if self.conflict_root != expected_conflict {
            return Err("slashing evidence conflict root mismatch".to_string());
        }
        let expected = threshold_encrypted_mempool_slashing_evidence_id(
            self.evidence_kind,
            &self.accused_member_id,
            &self.related_committee_id,
            self.window_id.as_deref(),
            self.envelope_id.as_deref(),
            &self.conflict_root,
            self.discovered_at_height,
        );
        if self.evidence_id != expected {
            return Err("slashing evidence id mismatch".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdEncryptedMempoolRoots {
    pub config_root: String,
    pub committee_member_root: String,
    pub committee_root: String,
    pub envelope_root: String,
    pub anti_mev_commitment_root: String,
    pub decryption_commitment_root: String,
    pub decryption_reveal_root: String,
    pub fair_ordering_window_root: String,
    pub low_fee_lane_root: String,
    pub forced_inclusion_hook_root: String,
    pub privacy_disclosure_receipt_root: String,
    pub slashing_evidence_root: String,
    pub replay_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl ThresholdEncryptedMempoolRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "committee_member_root": self.committee_member_root,
            "committee_root": self.committee_root,
            "envelope_root": self.envelope_root,
            "anti_mev_commitment_root": self.anti_mev_commitment_root,
            "decryption_commitment_root": self.decryption_commitment_root,
            "decryption_reveal_root": self.decryption_reveal_root,
            "fair_ordering_window_root": self.fair_ordering_window_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "forced_inclusion_hook_root": self.forced_inclusion_hook_root,
            "privacy_disclosure_receipt_root": self.privacy_disclosure_receipt_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record
            .as_object_mut()
            .expect("threshold encrypted mempool roots object")
            .insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdEncryptedMempoolCounters {
    pub height: u64,
    pub committee_member_count: u64,
    pub active_member_count: u64,
    pub committee_count: u64,
    pub active_committee_count: u64,
    pub envelope_count: u64,
    pub submitted_envelope_count: u64,
    pub queued_envelope_count: u64,
    pub decrypting_envelope_count: u64,
    pub decrypted_envelope_count: u64,
    pub ordered_envelope_count: u64,
    pub included_envelope_count: u64,
    pub expired_envelope_count: u64,
    pub fair_window_count: u64,
    pub active_fair_window_count: u64,
    pub anti_mev_commitment_count: u64,
    pub decryption_commitment_count: u64,
    pub decryption_reveal_count: u64,
    pub accepted_decryption_reveal_count: u64,
    pub low_fee_lane_count: u64,
    pub active_low_fee_lane_count: u64,
    pub forced_inclusion_hook_count: u64,
    pub pending_forced_inclusion_hook_count: u64,
    pub privacy_disclosure_receipt_count: u64,
    pub slashing_evidence_count: u64,
    pub accepted_slashing_evidence_count: u64,
    pub replay_nullifier_count: u64,
    pub total_payload_bytes: u64,
    pub total_fee_micro_units: u64,
    pub low_fee_reserved_subsidy_units: u64,
}

impl ThresholdEncryptedMempoolCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "threshold_encrypted_mempool_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "height": self.height,
            "committee_member_count": self.committee_member_count,
            "active_member_count": self.active_member_count,
            "committee_count": self.committee_count,
            "active_committee_count": self.active_committee_count,
            "envelope_count": self.envelope_count,
            "submitted_envelope_count": self.submitted_envelope_count,
            "queued_envelope_count": self.queued_envelope_count,
            "decrypting_envelope_count": self.decrypting_envelope_count,
            "decrypted_envelope_count": self.decrypted_envelope_count,
            "ordered_envelope_count": self.ordered_envelope_count,
            "included_envelope_count": self.included_envelope_count,
            "expired_envelope_count": self.expired_envelope_count,
            "fair_window_count": self.fair_window_count,
            "active_fair_window_count": self.active_fair_window_count,
            "anti_mev_commitment_count": self.anti_mev_commitment_count,
            "decryption_commitment_count": self.decryption_commitment_count,
            "decryption_reveal_count": self.decryption_reveal_count,
            "accepted_decryption_reveal_count": self.accepted_decryption_reveal_count,
            "low_fee_lane_count": self.low_fee_lane_count,
            "active_low_fee_lane_count": self.active_low_fee_lane_count,
            "forced_inclusion_hook_count": self.forced_inclusion_hook_count,
            "pending_forced_inclusion_hook_count": self.pending_forced_inclusion_hook_count,
            "privacy_disclosure_receipt_count": self.privacy_disclosure_receipt_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "accepted_slashing_evidence_count": self.accepted_slashing_evidence_count,
            "replay_nullifier_count": self.replay_nullifier_count,
            "total_payload_bytes": self.total_payload_bytes,
            "total_fee_micro_units": self.total_fee_micro_units,
            "low_fee_reserved_subsidy_units": self.low_fee_reserved_subsidy_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdEncryptedMempoolState {
    pub height: u64,
    pub operator_label: String,
    pub next_window_sequence: u64,
    pub config: ThresholdEncryptedMempoolConfig,
    pub committee_members: BTreeMap<String, PqThresholdCommitteeMember>,
    pub committees: BTreeMap<String, PqThresholdEncryptionCommittee>,
    pub envelopes: BTreeMap<String, EncryptedTransactionEnvelope>,
    pub anti_mev_commitments: BTreeMap<String, AntiMevCommitment>,
    pub decryption_commitments: BTreeMap<String, DecryptionShareCommitment>,
    pub decryption_reveals: BTreeMap<String, DecryptionShareReveal>,
    pub fair_ordering_windows: BTreeMap<String, FairOrderingWindow>,
    pub low_fee_lanes: BTreeMap<String, LowFeeQueueLane>,
    pub forced_inclusion_hooks: BTreeMap<String, ForcedInclusionHook>,
    pub privacy_disclosure_receipts: BTreeMap<String, PrivacyDisclosureReceipt>,
    pub slashing_evidence: BTreeMap<String, EquivocationSlashingEvidence>,
    pub consumed_replay_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for ThresholdEncryptedMempoolState {
    fn default() -> Self {
        Self::new(
            "threshold-encrypted-mempool",
            ThresholdEncryptedMempoolConfig::default(),
        )
        .expect("default threshold encrypted mempool state")
    }
}

impl ThresholdEncryptedMempoolState {
    pub fn new(
        operator_label: impl Into<String>,
        config: ThresholdEncryptedMempoolConfig,
    ) -> ThresholdEncryptedMempoolResult<Self> {
        config.validate()?;
        let operator_label = operator_label.into();
        ensure_non_empty(
            &operator_label,
            "threshold encrypted mempool operator label",
        )?;
        Ok(Self {
            height: 0,
            operator_label,
            next_window_sequence: 0,
            config,
            committee_members: BTreeMap::new(),
            committees: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            anti_mev_commitments: BTreeMap::new(),
            decryption_commitments: BTreeMap::new(),
            decryption_reveals: BTreeMap::new(),
            fair_ordering_windows: BTreeMap::new(),
            low_fee_lanes: BTreeMap::new(),
            forced_inclusion_hooks: BTreeMap::new(),
            privacy_disclosure_receipts: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            consumed_replay_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> ThresholdEncryptedMempoolResult<Self> {
        let mut state = Self::new(
            "devnet-threshold-encrypted-mempool",
            ThresholdEncryptedMempoolConfig::default(),
        )?;
        state.set_height(16);

        let mut members = Vec::new();
        for (index, label) in [
            "devnet-threshold-a",
            "devnet-threshold-b",
            "devnet-threshold-c",
            "devnet-threshold-d",
        ]
        .iter()
        .enumerate()
        {
            let member = PqThresholdCommitteeMember::new(
                format!("operator-{label}"),
                *label,
                &format!("devnet-{label}-ml-kem-public-key"),
                &format!("devnet-{label}-ml-dsa-public-key"),
                &format!("devnet-{label}-encrypted-share-commitment"),
                1_000_000 + (index as u64 * 50_000),
                1,
                1,
            )?;
            state.insert_committee_member(member.clone())?;
            members.push(member);
        }

        let committee = PqThresholdEncryptionCommittee::new(
            0,
            state.config.threshold,
            &members,
            "devnet-threshold-aggregate-pq-public-key",
            &json!({
                "ceremony": "devnet-threshold-encrypted-mempool",
                "participants": members.iter().map(|member| member.member_id.clone()).collect::<Vec<_>>(),
                "view_key_policy": "delayed-disclosure-receipts",
            }),
            1,
            1,
        )?;
        let committee_id = committee.committee_id.clone();
        state.insert_committee(committee)?;

        let low_fee_privacy_lane = LowFeeQueueLane::new(
            "devnet-low-fee-privacy",
            ThresholdMempoolLaneKind::LowFeePrivacy,
            "wxmr-devnet",
            state.config.low_fee_max_fee_micro_units,
            500_000,
            state.height,
            state.config.low_fee_lane_ttl_blocks,
        )?;
        let low_fee_bridge_lane = LowFeeQueueLane::new(
            "devnet-low-fee-bridge",
            ThresholdMempoolLaneKind::LowFeeBridge,
            "wxmr-devnet",
            state.config.low_fee_max_fee_micro_units,
            750_000,
            state.height,
            state.config.low_fee_lane_ttl_blocks,
        )?;
        let low_fee_privacy_lane_id = state.insert_low_fee_lane(low_fee_privacy_lane)?;
        let low_fee_bridge_lane_id = state.insert_low_fee_lane(low_fee_bridge_lane)?;

        let standard_envelope = EncryptedTransactionEnvelope::new(
            ThresholdMempoolLaneKind::PrivateTransfer,
            "devnet-alice",
            "private_transfer",
            &json!({
                "note_commitment": "alice-note-001",
                "recipient_view_tag": "encrypted-recipient-tag",
                "amount_bucket": "bucket-42",
            }),
            2_048,
            committee_id.clone(),
            9_500,
            None,
            None,
            None,
            1,
            state.height,
            state.config.envelope_ttl_blocks,
        )?;
        let low_fee_envelope = EncryptedTransactionEnvelope::new(
            ThresholdMempoolLaneKind::LowFeePrivacy,
            "devnet-bob",
            "low_fee_private_transfer",
            &json!({
                "note_commitment": "bob-note-001",
                "recipient_view_tag": "encrypted-low-fee-recipient",
                "amount_bucket": "bucket-7",
            }),
            1_536,
            committee_id.clone(),
            1_700,
            Some("devnet-low-fee-credit-bob-001"),
            None,
            None,
            2,
            state.height,
            state.config.envelope_ttl_blocks,
        )?;
        let bridge_envelope = EncryptedTransactionEnvelope::new(
            ThresholdMempoolLaneKind::LowFeeBridge,
            "devnet-carol",
            "monero_bridge_exit",
            &json!({
                "exit_commitment": "carol-bridge-exit-001",
                "recipient_address_hash": "encrypted-monero-destination",
                "fee_bucket": "low",
            }),
            2_304,
            committee_id.clone(),
            2_200,
            Some("devnet-low-fee-credit-carol-bridge-001"),
            None,
            None,
            3,
            state.height,
            state.config.envelope_ttl_blocks,
        )?;
        let forced_ticket_id = "devnet-forced-ticket-001".to_string();
        let forced_envelope = EncryptedTransactionEnvelope::new(
            ThresholdMempoolLaneKind::ForcedInclusion,
            "devnet-dave",
            "forced_private_exit",
            &json!({
                "escape_commitment": "dave-forced-exit-001",
                "l1_anchor_hint": "monero-devnet-anchor-42",
                "watchtower": "devnet-watchtower-a",
            }),
            2_816,
            committee_id.clone(),
            12_000,
            None,
            None,
            Some(forced_ticket_id.clone()),
            4,
            state.height,
            state.config.envelope_ttl_blocks,
        )?;

        let standard_id = state.submit_envelope(standard_envelope)?;
        let low_fee_id = state.submit_envelope(low_fee_envelope)?;
        let bridge_id = state.submit_envelope(bridge_envelope)?;
        let forced_id = state.submit_envelope(forced_envelope)?;

        let anti_mev = AntiMevCommitment::new(
            &standard_id,
            "devnet-searcher-protector",
            &json!({
                "bundle": "protect-private-transfer",
                "do_not_backrun": true,
            }),
            &json!({
                "max_bid_micro_units": 5_000,
                "sealed": true,
            }),
            "devnet-anti-mev-salt-001",
            5_000,
            state.height,
            state.height + 3,
        )?;
        let anti_mev_id = anti_mev.commitment_id.clone();
        state.insert_anti_mev_commitment(anti_mev)?;
        if let Some(envelope) = state.envelopes.get_mut(&standard_id) {
            envelope.anti_mev_commitment_id = Some(anti_mev_id);
        }

        state.reserve_low_fee_envelope(&low_fee_privacy_lane_id, &low_fee_id, 1_250)?;
        state.reserve_low_fee_envelope(&low_fee_bridge_lane_id, &bridge_id, 1_500)?;

        let forced_hook = ForcedInclusionHook::new(
            &forced_ticket_id,
            &forced_id,
            "devnet-dave",
            &json!({
                "source": "monero-devnet",
                "anchor_height": 42,
                "anchor_hash": "devnet-monero-anchor-42",
            }),
            &json!({
                "escape": "private_exit",
                "payload_root": state.envelopes[&forced_id].payload_ciphertext_root,
            }),
            state.height,
            state.config.forced_inclusion_grace_blocks,
            state.config.forced_inclusion_grace_blocks * 2,
            state.config.forced_inclusion_grace_blocks * 3,
            4,
            1_000_000,
        )?;
        state.insert_forced_inclusion_hook(forced_hook)?;

        let window = state.open_fair_ordering_window(vec![
            standard_id.clone(),
            low_fee_id.clone(),
            bridge_id.clone(),
            forced_id.clone(),
        ])?;
        let window_id = window.window_id.clone();

        for envelope_id in [&standard_id, &low_fee_id, &bridge_id, &forced_id] {
            for (share_index, member) in members.iter().enumerate() {
                let commitment = DecryptionShareCommitment::new(
                    &window_id,
                    envelope_id,
                    &committee_id,
                    &member.member_id,
                    share_index as u64,
                    &json!({
                        "encrypted_share": format!("{envelope_id}:{}", member.validator_label),
                        "committee": committee_id,
                    }),
                    &format!("share-commitment:{envelope_id}:{}", member.member_id),
                    state.height + 1,
                    state.height + 4,
                )?;
                let commitment_id = state.insert_decryption_commitment(commitment.clone())?;
                if share_index < state.config.threshold as usize {
                    let reveal = DecryptionShareReveal::new(
                        &commitment,
                        &format!("decrypted-share:{envelope_id}:{}", member.member_id),
                        &json!({
                            "proof": "devnet-share-proof",
                            "share_index": share_index,
                        }),
                        state.height + 2,
                    )?;
                    state.reveal_decryption_share(reveal)?;
                    let stored = state
                        .decryption_commitments
                        .get_mut(&commitment_id)
                        .expect("devnet commitment exists");
                    stored.status = DecryptionShareStatus::Accepted;
                }
            }
        }

        state.seal_ordering_window(&window_id)?;

        let receipt = PrivacyDisclosureReceipt::new(
            &standard_id,
            &committee_id,
            PrivacyDisclosureScope::Auditor,
            "devnet-auditor",
            &json!({
                "envelope_id": standard_id,
                "fields": ["lane_kind", "fee_micro_units", "payload_ciphertext_root"],
            }),
            &json!({
                "reason": "devnet audit fixture",
                "delayed_disclosure": true,
            }),
            "devnet-auditor-ml-dsa-signature",
            &json!({
                "redact_payload": true,
                "retain_roots": true,
            }),
            state.height + state.config.privacy_disclosure_delay_blocks,
            144,
        )?;
        state.insert_privacy_disclosure_receipt(receipt)?;

        let first_share = state
            .decryption_commitments
            .values()
            .next()
            .map(DecryptionShareCommitment::public_record)
            .ok_or_else(|| "devnet requires decryption commitment".to_string())?;
        let second_share = json!({
            "same_member": true,
            "conflicting_share_root": "devnet-conflicting-share",
            "window_id": window_id,
        });
        let slash = EquivocationSlashingEvidence::new(
            SlashingEvidenceKind::ShareEquivocation,
            members[0].member_id.clone(),
            committee_id.clone(),
            Some(window_id.clone()),
            Some(forced_id.clone()),
            &first_share,
            &second_share,
            "devnet-watchtower-a",
            members[0].stake_units
                * SlashingEvidenceKind::ShareEquivocation.default_slash_multiplier_bps()
                / THRESHOLD_ENCRYPTED_MEMPOOL_MAX_BPS,
            state.height + 3,
            state.height + state.config.challenge_window_blocks,
        )?;
        state.insert_slashing_evidence(slash)?;

        for object_id in [
            standard_id.as_str(),
            low_fee_id.as_str(),
            bridge_id.as_str(),
            forced_id.as_str(),
            window_id.as_str(),
        ] {
            let record = state
                .envelopes
                .get(object_id)
                .map(EncryptedTransactionEnvelope::public_record)
                .or_else(|| {
                    state
                        .fair_ordering_windows
                        .get(object_id)
                        .map(FairOrderingWindow::public_record)
                })
                .ok_or_else(|| "devnet public record source missing".to_string())?;
            state.publish_public_record(object_id, &record)?;
        }

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.expire_records();
    }

    pub fn insert_committee_member(
        &mut self,
        member: PqThresholdCommitteeMember,
    ) -> ThresholdEncryptedMempoolResult<String> {
        member.validate()?;
        let member_id = member.member_id.clone();
        self.committee_members.insert(member_id.clone(), member);
        Ok(member_id)
    }

    pub fn insert_committee(
        &mut self,
        committee: PqThresholdEncryptionCommittee,
    ) -> ThresholdEncryptedMempoolResult<String> {
        committee.validate()?;
        for member_id in &committee.member_ids {
            if !self.committee_members.contains_key(member_id) {
                return Err("threshold committee references unknown member".to_string());
            }
        }
        let committee_id = committee.committee_id.clone();
        self.committees.insert(committee_id.clone(), committee);
        Ok(committee_id)
    }

    pub fn active_committee(&self) -> Option<&PqThresholdEncryptionCommittee> {
        self.committees
            .values()
            .filter(|committee| committee.accepts_at(self.height))
            .max_by_key(|committee| (committee.epoch, committee.activation_height))
    }

    pub fn submit_envelope(
        &mut self,
        mut envelope: EncryptedTransactionEnvelope,
    ) -> ThresholdEncryptedMempoolResult<String> {
        envelope.validate()?;
        if envelope.payload_size_bytes > self.config.max_payload_bytes {
            return Err("encrypted envelope payload exceeds config max".to_string());
        }
        if envelope.fee_micro_units < self.config.min_fee_micro_units {
            return Err("encrypted envelope fee below minimum".to_string());
        }
        if envelope.lane_kind.low_fee()
            && (!self.config.enable_low_fee_lanes
                || envelope.fee_micro_units > self.config.low_fee_max_fee_micro_units)
        {
            return Err("encrypted envelope low fee lane disabled or fee too high".to_string());
        }
        if envelope.lane_kind == ThresholdMempoolLaneKind::ForcedInclusion
            && !self.config.enable_forced_inclusion_hooks
        {
            return Err("forced inclusion envelopes are disabled".to_string());
        }
        let committee = self
            .committees
            .get(&envelope.committee_id)
            .ok_or_else(|| "encrypted envelope references unknown committee".to_string())?;
        if !committee.accepts_at(self.height) {
            return Err("encrypted envelope committee is not active".to_string());
        }
        if self
            .consumed_replay_nullifiers
            .contains(&envelope.replay_nullifier)
        {
            return Err("encrypted envelope replay nullifier already consumed".to_string());
        }
        if envelope.is_expired(self.height) {
            envelope.status = EncryptedEnvelopeStatus::Expired;
        } else {
            envelope.status = EncryptedEnvelopeStatus::Queued;
        }
        let envelope_id = envelope.envelope_id.clone();
        self.consumed_replay_nullifiers
            .insert(envelope.replay_nullifier.clone());
        self.envelopes.insert(envelope_id.clone(), envelope);
        Ok(envelope_id)
    }

    pub fn insert_anti_mev_commitment(
        &mut self,
        commitment: AntiMevCommitment,
    ) -> ThresholdEncryptedMempoolResult<String> {
        commitment.validate()?;
        if !self.config.enable_anti_mev_commitments {
            return Err("anti mev commitments are disabled".to_string());
        }
        if !self.envelopes.contains_key(&commitment.envelope_id) {
            return Err("anti mev commitment references unknown envelope".to_string());
        }
        let commitment_id = commitment.commitment_id.clone();
        self.anti_mev_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn insert_decryption_commitment(
        &mut self,
        commitment: DecryptionShareCommitment,
    ) -> ThresholdEncryptedMempoolResult<String> {
        commitment.validate()?;
        if !self.envelopes.contains_key(&commitment.envelope_id) {
            return Err("decryption commitment references unknown envelope".to_string());
        }
        let committee = self
            .committees
            .get(&commitment.committee_id)
            .ok_or_else(|| "decryption commitment references unknown committee".to_string())?;
        if !committee.member_ids.contains(&commitment.member_id) {
            return Err("decryption commitment member not in committee".to_string());
        }
        let member = self
            .committee_members
            .get(&commitment.member_id)
            .ok_or_else(|| "decryption commitment references unknown member".to_string())?;
        if !member.active_at(self.height) {
            return Err("decryption commitment member is not active".to_string());
        }
        if !self
            .fair_ordering_windows
            .contains_key(&commitment.window_id)
        {
            return Err("decryption commitment references unknown ordering window".to_string());
        }
        let commitment_id = commitment.commitment_id.clone();
        self.decryption_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn reveal_decryption_share(
        &mut self,
        reveal: DecryptionShareReveal,
    ) -> ThresholdEncryptedMempoolResult<String> {
        reveal.validate()?;
        let commitment = self
            .decryption_commitments
            .get_mut(&reveal.commitment_id)
            .ok_or_else(|| "decryption reveal references unknown commitment".to_string())?;
        if commitment.window_id != reveal.window_id
            || commitment.envelope_id != reveal.envelope_id
            || commitment.member_id != reveal.member_id
            || commitment.share_index != reveal.share_index
        {
            return Err("decryption reveal does not match commitment".to_string());
        }
        commitment.status = DecryptionShareStatus::Accepted;
        let reveal_id = reveal.reveal_id.clone();
        self.decryption_reveals.insert(reveal_id.clone(), reveal);
        self.update_envelope_decryption_statuses();
        Ok(reveal_id)
    }

    pub fn open_fair_ordering_window(
        &mut self,
        envelope_ids: Vec<String>,
    ) -> ThresholdEncryptedMempoolResult<FairOrderingWindow> {
        if envelope_ids.is_empty() {
            return Err("cannot open fair ordering window without envelopes".to_string());
        }
        if envelope_ids.len() as u64 > self.config.max_envelopes_per_window {
            return Err("fair ordering window exceeds max envelopes".to_string());
        }
        for envelope_id in &envelope_ids {
            let envelope = self
                .envelopes
                .get(envelope_id)
                .ok_or_else(|| "fair ordering window references unknown envelope".to_string())?;
            if !envelope.status.is_open() {
                return Err("fair ordering window references closed envelope".to_string());
            }
        }
        let sequence = self.next_window_sequence;
        self.next_window_sequence = self
            .next_window_sequence
            .checked_add(1)
            .ok_or_else(|| "fair ordering window sequence overflow".to_string())?;
        let start_height = self.height;
        let end_height = start_height
            .checked_add(self.config.fair_ordering_window_blocks)
            .ok_or_else(|| "fair ordering window end overflow".to_string())?;
        let low_fee_lane_keys = self
            .low_fee_lanes
            .values()
            .filter(|lane| lane.active_at(self.height))
            .map(|lane| lane.lane_key.clone())
            .collect::<Vec<_>>();
        let forced_inclusion_ticket_ids = envelope_ids
            .iter()
            .filter_map(|envelope_id| {
                self.envelopes
                    .get(envelope_id)
                    .and_then(|envelope| envelope.forced_inclusion_ticket_id.clone())
            })
            .collect::<Vec<_>>();
        let window = FairOrderingWindow::new(
            sequence,
            start_height,
            end_height,
            self.config.decrypt_delay_blocks,
            self.config.reveal_window_blocks,
            self.config.challenge_window_blocks,
            envelope_ids.clone(),
            low_fee_lane_keys,
            forced_inclusion_ticket_ids,
            self.anti_mev_commitment_root(),
            self.decryption_commitment_root(),
            self.decryption_reveal_root(),
        )?;
        for envelope_id in &envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EncryptedEnvelopeStatus::Committed;
            }
        }
        let window_id = window.window_id.clone();
        self.fair_ordering_windows.insert(window_id, window.clone());
        Ok(window)
    }

    pub fn seal_ordering_window(
        &mut self,
        window_id: &str,
    ) -> ThresholdEncryptedMempoolResult<Vec<String>> {
        let window = self
            .fair_ordering_windows
            .get(window_id)
            .ok_or_else(|| "unknown fair ordering window".to_string())?
            .clone();
        let mut envelopes = window
            .envelope_ids
            .iter()
            .map(|envelope_id| {
                self.envelopes
                    .get(envelope_id)
                    .cloned()
                    .ok_or_else(|| "fair ordering window envelope missing".to_string())
            })
            .collect::<ThresholdEncryptedMempoolResult<Vec<_>>>()?;
        envelopes.sort_by(|left, right| {
            left.lane_kind
                .fairness_priority()
                .cmp(&right.lane_kind.fairness_priority())
                .then_with(|| left.submitted_at_height.cmp(&right.submitted_at_height))
                .then_with(|| {
                    left.ordering_key(&window.ordering_seed)
                        .cmp(&right.ordering_key(&window.ordering_seed))
                })
                .then_with(|| left.envelope_id.cmp(&right.envelope_id))
        });
        let ordered = envelopes
            .iter()
            .map(|envelope| envelope.envelope_id.clone())
            .collect::<Vec<_>>();
        let decryption_share_commitment_root = self.decryption_commitment_root();
        let decryption_share_reveal_root = self.decryption_reveal_root();
        let anti_mev_commitment_root = self.anti_mev_commitment_root();
        let stored_window = self
            .fair_ordering_windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown fair ordering window".to_string())?;
        stored_window.decryption_share_commitment_root = decryption_share_commitment_root;
        stored_window.decryption_share_reveal_root = decryption_share_reveal_root;
        stored_window.anti_mev_commitment_root = anti_mev_commitment_root;
        stored_window.seal_with_order(ordered.clone())?;
        for envelope_id in &ordered {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EncryptedEnvelopeStatus::Ordered;
            }
        }
        Ok(ordered)
    }

    pub fn insert_low_fee_lane(
        &mut self,
        lane: LowFeeQueueLane,
    ) -> ThresholdEncryptedMempoolResult<String> {
        lane.validate()?;
        if !self.config.enable_low_fee_lanes {
            return Err("low fee lanes are disabled".to_string());
        }
        let lane_id = lane.lane_id.clone();
        self.low_fee_lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn reserve_low_fee_envelope(
        &mut self,
        lane_id: &str,
        envelope_id: &str,
        subsidy_units: u64,
    ) -> ThresholdEncryptedMempoolResult<()> {
        let envelope = self
            .envelopes
            .get(envelope_id)
            .cloned()
            .ok_or_else(|| "low fee reservation references unknown envelope".to_string())?;
        let lane = self
            .low_fee_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "unknown low fee lane".to_string())?;
        lane.reserve_envelope(&envelope, subsidy_units)
    }

    pub fn insert_forced_inclusion_hook(
        &mut self,
        hook: ForcedInclusionHook,
    ) -> ThresholdEncryptedMempoolResult<String> {
        hook.validate()?;
        if !self.config.enable_forced_inclusion_hooks {
            return Err("forced inclusion hooks are disabled".to_string());
        }
        if !self.envelopes.contains_key(&hook.envelope_id) {
            return Err("forced inclusion hook references unknown envelope".to_string());
        }
        let hook_id = hook.hook_id.clone();
        self.forced_inclusion_hooks.insert(hook_id.clone(), hook);
        Ok(hook_id)
    }

    pub fn insert_privacy_disclosure_receipt(
        &mut self,
        receipt: PrivacyDisclosureReceipt,
    ) -> ThresholdEncryptedMempoolResult<String> {
        receipt.validate()?;
        if !self.config.enable_privacy_receipts {
            return Err("privacy disclosure receipts are disabled".to_string());
        }
        if !self.envelopes.contains_key(&receipt.envelope_id) {
            return Err("privacy disclosure receipt references unknown envelope".to_string());
        }
        if !self.committees.contains_key(&receipt.committee_id) {
            return Err("privacy disclosure receipt references unknown committee".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.privacy_disclosure_receipts
            .insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn insert_slashing_evidence(
        &mut self,
        evidence: EquivocationSlashingEvidence,
    ) -> ThresholdEncryptedMempoolResult<String> {
        evidence.validate()?;
        if !self
            .committee_members
            .contains_key(&evidence.accused_member_id)
        {
            return Err("slashing evidence references unknown member".to_string());
        }
        if !self.committees.contains_key(&evidence.related_committee_id) {
            return Err("slashing evidence references unknown committee".to_string());
        }
        if let Some(window_id) = &evidence.window_id {
            if !self.fair_ordering_windows.contains_key(window_id) {
                return Err("slashing evidence references unknown window".to_string());
            }
        }
        if let Some(envelope_id) = &evidence.envelope_id {
            if !self.envelopes.contains_key(envelope_id) {
                return Err("slashing evidence references unknown envelope".to_string());
            }
        }
        let evidence_id = evidence.evidence_id.clone();
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn publish_public_record(
        &mut self,
        object_id: &str,
        record: &Value,
    ) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(
            object_id,
            "threshold encrypted mempool public record object id",
        )?;
        let record_id = threshold_encrypted_mempool_public_record_id(object_id, record);
        self.public_records
            .insert(record_id.clone(), record.clone());
        Ok(record_id)
    }

    pub fn roots(&self) -> ThresholdEncryptedMempoolRoots {
        let config_root = self.config.config_root();
        let committee_member_root =
            threshold_encrypted_mempool_committee_member_set_root(&self.committee_members);
        let committee_root = threshold_encrypted_mempool_committee_set_root(&self.committees);
        let envelope_root = self.envelope_root();
        let anti_mev_commitment_root = self.anti_mev_commitment_root();
        let decryption_commitment_root = self.decryption_commitment_root();
        let decryption_reveal_root = self.decryption_reveal_root();
        let fair_ordering_window_root =
            threshold_encrypted_mempool_fair_ordering_window_set_root(&self.fair_ordering_windows);
        let low_fee_lane_root =
            threshold_encrypted_mempool_low_fee_lane_set_root(&self.low_fee_lanes);
        let forced_inclusion_hook_root = threshold_encrypted_mempool_forced_inclusion_hook_set_root(
            &self.forced_inclusion_hooks,
        );
        let privacy_disclosure_receipt_root =
            threshold_encrypted_mempool_privacy_disclosure_receipt_set_root(
                &self.privacy_disclosure_receipts,
            );
        let slashing_evidence_root =
            threshold_encrypted_mempool_slashing_evidence_set_root(&self.slashing_evidence);
        let replay_nullifier_root = threshold_encrypted_mempool_string_set_root(
            "THRESHOLD-ENCRYPTED-MEMPOOL-REPLAY-NULLIFIERS",
            &self
                .consumed_replay_nullifiers
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        );
        let public_record_root =
            threshold_encrypted_mempool_public_record_set_root(&self.public_records);
        let state_record = json!({
            "kind": "threshold_encrypted_mempool_state_root_record",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "height": self.height,
            "operator_label_root": threshold_encrypted_mempool_string_root(
                "THRESHOLD-ENCRYPTED-MEMPOOL-OPERATOR-LABEL",
                &self.operator_label,
            ),
            "next_window_sequence": self.next_window_sequence,
            "config_root": config_root,
            "committee_member_root": committee_member_root,
            "committee_root": committee_root,
            "envelope_root": envelope_root,
            "anti_mev_commitment_root": anti_mev_commitment_root,
            "decryption_commitment_root": decryption_commitment_root,
            "decryption_reveal_root": decryption_reveal_root,
            "fair_ordering_window_root": fair_ordering_window_root,
            "low_fee_lane_root": low_fee_lane_root,
            "forced_inclusion_hook_root": forced_inclusion_hook_root,
            "privacy_disclosure_receipt_root": privacy_disclosure_receipt_root,
            "slashing_evidence_root": slashing_evidence_root,
            "replay_nullifier_root": replay_nullifier_root,
            "public_record_root": public_record_root,
            "counters": self.counters().public_record(),
        });
        let state_root = threshold_encrypted_mempool_state_root_from_record(&state_record);
        ThresholdEncryptedMempoolRoots {
            config_root,
            committee_member_root,
            committee_root,
            envelope_root,
            anti_mev_commitment_root,
            decryption_commitment_root,
            decryption_reveal_root,
            fair_ordering_window_root,
            low_fee_lane_root,
            forced_inclusion_hook_root,
            privacy_disclosure_receipt_root,
            slashing_evidence_root,
            replay_nullifier_root,
            public_record_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn counters(&self) -> ThresholdEncryptedMempoolCounters {
        let mut counters = ThresholdEncryptedMempoolCounters {
            height: self.height,
            committee_member_count: self.committee_members.len() as u64,
            committee_count: self.committees.len() as u64,
            envelope_count: self.envelopes.len() as u64,
            fair_window_count: self.fair_ordering_windows.len() as u64,
            anti_mev_commitment_count: self.anti_mev_commitments.len() as u64,
            decryption_commitment_count: self.decryption_commitments.len() as u64,
            decryption_reveal_count: self.decryption_reveals.len() as u64,
            low_fee_lane_count: self.low_fee_lanes.len() as u64,
            forced_inclusion_hook_count: self.forced_inclusion_hooks.len() as u64,
            privacy_disclosure_receipt_count: self.privacy_disclosure_receipts.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            replay_nullifier_count: self.consumed_replay_nullifiers.len() as u64,
            ..ThresholdEncryptedMempoolCounters::default()
        };
        for member in self.committee_members.values() {
            if member.active_at(self.height) {
                counters.active_member_count += 1;
            }
        }
        for committee in self.committees.values() {
            if committee.accepts_at(self.height) {
                counters.active_committee_count += 1;
            }
        }
        for envelope in self.envelopes.values() {
            match envelope.status {
                EncryptedEnvelopeStatus::Submitted => counters.submitted_envelope_count += 1,
                EncryptedEnvelopeStatus::Queued | EncryptedEnvelopeStatus::Committed => {
                    counters.queued_envelope_count += 1
                }
                EncryptedEnvelopeStatus::Decrypting => counters.decrypting_envelope_count += 1,
                EncryptedEnvelopeStatus::Decrypted => counters.decrypted_envelope_count += 1,
                EncryptedEnvelopeStatus::Ordered => counters.ordered_envelope_count += 1,
                EncryptedEnvelopeStatus::Included => counters.included_envelope_count += 1,
                EncryptedEnvelopeStatus::Expired => counters.expired_envelope_count += 1,
                EncryptedEnvelopeStatus::Rejected => {}
            }
            counters.total_payload_bytes = counters
                .total_payload_bytes
                .saturating_add(envelope.payload_size_bytes);
            counters.total_fee_micro_units = counters
                .total_fee_micro_units
                .saturating_add(envelope.fee_micro_units);
        }
        for reveal in self.decryption_reveals.values() {
            if reveal.accepted {
                counters.accepted_decryption_reveal_count += 1;
            }
        }
        for window in self.fair_ordering_windows.values() {
            if window.active_at(self.height) {
                counters.active_fair_window_count += 1;
            }
        }
        for lane in self.low_fee_lanes.values() {
            if lane.active_at(self.height) {
                counters.active_low_fee_lane_count += 1;
            }
            counters.low_fee_reserved_subsidy_units = counters
                .low_fee_reserved_subsidy_units
                .saturating_add(lane.reserved_subsidy_units);
        }
        for hook in self.forced_inclusion_hooks.values() {
            if hook.status.is_pending() {
                counters.pending_forced_inclusion_hook_count += 1;
            }
        }
        for evidence in self.slashing_evidence.values() {
            if evidence.status == SlashingEvidenceStatus::Accepted
                || evidence.status == SlashingEvidenceStatus::Executed
            {
                counters.accepted_slashing_evidence_count += 1;
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "threshold_encrypted_mempool_state",
            "chain_id": CHAIN_ID,
            "protocol_version": THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION,
            "height": self.height,
            "operator_label": self.operator_label,
            "next_window_sequence": self.next_window_sequence,
            "config": self.config.public_record(),
            "committee_members": self.committee_members.values().map(PqThresholdCommitteeMember::public_record).collect::<Vec<_>>(),
            "committees": self.committees.values().map(PqThresholdEncryptionCommittee::public_record).collect::<Vec<_>>(),
            "envelopes": self.envelopes.values().map(EncryptedTransactionEnvelope::public_record).collect::<Vec<_>>(),
            "anti_mev_commitments": self.anti_mev_commitments.values().map(AntiMevCommitment::public_record).collect::<Vec<_>>(),
            "decryption_commitments": self.decryption_commitments.values().map(DecryptionShareCommitment::public_record).collect::<Vec<_>>(),
            "decryption_reveals": self.decryption_reveals.values().map(DecryptionShareReveal::public_record).collect::<Vec<_>>(),
            "fair_ordering_windows": self.fair_ordering_windows.values().map(FairOrderingWindow::public_record).collect::<Vec<_>>(),
            "low_fee_lanes": self.low_fee_lanes.values().map(LowFeeQueueLane::public_record).collect::<Vec<_>>(),
            "forced_inclusion_hooks": self.forced_inclusion_hooks.values().map(ForcedInclusionHook::public_record).collect::<Vec<_>>(),
            "privacy_disclosure_receipts": self.privacy_disclosure_receipts.values().map(PrivacyDisclosureReceipt::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(EquivocationSlashingEvidence::public_record).collect::<Vec<_>>(),
            "consumed_replay_nullifiers": self.consumed_replay_nullifiers.iter().cloned().collect::<Vec<_>>(),
            "public_record_count": self.public_records.len(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> ThresholdEncryptedMempoolResult<String> {
        ensure_non_empty(
            &self.operator_label,
            "threshold encrypted mempool operator label",
        )?;
        self.config.validate()?;
        if self.committee_members.len() > THRESHOLD_ENCRYPTED_MEMPOOL_MAX_COMMITTEE_MEMBERS {
            return Err("threshold encrypted mempool has too many committee members".to_string());
        }
        if self.committees.len() > THRESHOLD_ENCRYPTED_MEMPOOL_MAX_COMMITTEES {
            return Err("threshold encrypted mempool has too many committees".to_string());
        }
        if self.envelopes.len() > THRESHOLD_ENCRYPTED_MEMPOOL_MAX_ENVELOPES {
            return Err("threshold encrypted mempool has too many envelopes".to_string());
        }
        if self.fair_ordering_windows.len() > THRESHOLD_ENCRYPTED_MEMPOOL_MAX_WINDOWS {
            return Err(
                "threshold encrypted mempool has too many fair ordering windows".to_string(),
            );
        }
        if self.low_fee_lanes.len() > THRESHOLD_ENCRYPTED_MEMPOOL_MAX_LOW_FEE_LANES {
            return Err("threshold encrypted mempool has too many low fee lanes".to_string());
        }
        if self.forced_inclusion_hooks.len() > THRESHOLD_ENCRYPTED_MEMPOOL_MAX_FORCED_HOOKS {
            return Err(
                "threshold encrypted mempool has too many forced inclusion hooks".to_string(),
            );
        }
        if self.privacy_disclosure_receipts.len()
            > THRESHOLD_ENCRYPTED_MEMPOOL_MAX_DISCLOSURE_RECEIPTS
        {
            return Err(
                "threshold encrypted mempool has too many privacy disclosure receipts".to_string(),
            );
        }
        if self.slashing_evidence.len() > THRESHOLD_ENCRYPTED_MEMPOOL_MAX_SLASHING_EVIDENCE {
            return Err("threshold encrypted mempool has too much slashing evidence".to_string());
        }
        for member in self.committee_members.values() {
            member.validate()?;
        }
        for committee in self.committees.values() {
            committee.validate()?;
            for member_id in &committee.member_ids {
                if !self.committee_members.contains_key(member_id) {
                    return Err("threshold committee references missing member".to_string());
                }
            }
        }
        let mut nullifiers = BTreeSet::new();
        for envelope in self.envelopes.values() {
            envelope.validate()?;
            if !self.committees.contains_key(&envelope.committee_id) {
                return Err("encrypted envelope references missing committee".to_string());
            }
            nullifiers.insert(envelope.replay_nullifier.clone());
            if let Some(commitment_id) = &envelope.anti_mev_commitment_id {
                if !self.anti_mev_commitments.contains_key(commitment_id) {
                    return Err(
                        "encrypted envelope references missing anti mev commitment".to_string()
                    );
                }
            }
            if let Some(ticket_id) = &envelope.forced_inclusion_ticket_id {
                let found = self.forced_inclusion_hooks.values().any(|hook| {
                    &hook.ticket_id == ticket_id && hook.envelope_id == envelope.envelope_id
                });
                if !found && envelope.lane_kind == ThresholdMempoolLaneKind::ForcedInclusion {
                    return Err(
                        "forced inclusion envelope missing forced inclusion hook".to_string()
                    );
                }
            }
        }
        if !nullifiers.is_subset(&self.consumed_replay_nullifiers) {
            return Err(
                "threshold mempool replay nullifier index missing envelope nullifier".to_string(),
            );
        }
        for commitment in self.anti_mev_commitments.values() {
            commitment.validate()?;
            if !self.envelopes.contains_key(&commitment.envelope_id) {
                return Err("anti mev commitment references missing envelope".to_string());
            }
        }
        for commitment in self.decryption_commitments.values() {
            commitment.validate()?;
            if !self.envelopes.contains_key(&commitment.envelope_id) {
                return Err("decryption commitment references missing envelope".to_string());
            }
            if !self.committees.contains_key(&commitment.committee_id) {
                return Err("decryption commitment references missing committee".to_string());
            }
            if !self.committee_members.contains_key(&commitment.member_id) {
                return Err("decryption commitment references missing member".to_string());
            }
            if !self
                .fair_ordering_windows
                .contains_key(&commitment.window_id)
            {
                return Err("decryption commitment references missing window".to_string());
            }
        }
        for reveal in self.decryption_reveals.values() {
            reveal.validate()?;
            if !self
                .decryption_commitments
                .contains_key(&reveal.commitment_id)
            {
                return Err("decryption reveal references missing commitment".to_string());
            }
        }
        for window in self.fair_ordering_windows.values() {
            window.validate()?;
            for envelope_id in &window.envelope_ids {
                if !self.envelopes.contains_key(envelope_id) {
                    return Err("fair ordering window references missing envelope".to_string());
                }
            }
        }
        for lane in self.low_fee_lanes.values() {
            lane.validate()?;
            for envelope_id in &lane.eligible_envelope_ids {
                if !self.envelopes.contains_key(envelope_id) {
                    return Err("low fee lane references missing envelope".to_string());
                }
            }
        }
        for hook in self.forced_inclusion_hooks.values() {
            hook.validate()?;
            if !self.envelopes.contains_key(&hook.envelope_id) {
                return Err("forced inclusion hook references missing envelope".to_string());
            }
        }
        for receipt in self.privacy_disclosure_receipts.values() {
            receipt.validate()?;
            if !self.envelopes.contains_key(&receipt.envelope_id) {
                return Err("privacy disclosure receipt references missing envelope".to_string());
            }
            if !self.committees.contains_key(&receipt.committee_id) {
                return Err("privacy disclosure receipt references missing committee".to_string());
            }
        }
        for evidence in self.slashing_evidence.values() {
            evidence.validate()?;
        }
        Ok(self.state_root())
    }

    fn expire_records(&mut self) {
        for envelope in self.envelopes.values_mut() {
            if envelope.status.is_open() && envelope.is_expired(self.height) {
                envelope.status = EncryptedEnvelopeStatus::Expired;
            }
        }
        for lane in self.low_fee_lanes.values_mut() {
            if lane.status == LowFeeLaneStatus::Active && self.height >= lane.expires_at_height {
                lane.status = LowFeeLaneStatus::Expired;
            }
        }
        for hook in self.forced_inclusion_hooks.values_mut() {
            if hook.status.is_pending() && self.height >= hook.rescue_deadline_height {
                hook.status = ForcedInclusionHookStatus::Expired;
            } else if hook.rescue_eligible_at(self.height) {
                hook.status = ForcedInclusionHookStatus::RescueEligible;
            }
        }
        for receipt in self.privacy_disclosure_receipts.values_mut() {
            if matches!(
                receipt.status,
                PrivacyDisclosureStatus::PendingDelay | PrivacyDisclosureStatus::Disclosed
            ) && self.height >= receipt.expires_at_height
            {
                receipt.status = PrivacyDisclosureStatus::Expired;
            }
        }
        for window in self.fair_ordering_windows.values_mut() {
            if window.status.is_open() && self.height > window.challenge_deadline_height {
                window.status = FairOrderingWindowStatus::Expired;
            }
        }
    }

    fn update_envelope_decryption_statuses(&mut self) {
        let mut accepted_by_envelope = BTreeMap::<String, BTreeSet<String>>::new();
        for reveal in self.decryption_reveals.values() {
            if reveal.accepted {
                accepted_by_envelope
                    .entry(reveal.envelope_id.clone())
                    .or_default()
                    .insert(reveal.member_id.clone());
            }
        }
        for (envelope_id, member_ids) in accepted_by_envelope {
            if let Some(envelope) = self.envelopes.get_mut(&envelope_id) {
                if let Some(committee) = self.committees.get(&envelope.committee_id) {
                    if member_ids.len() as u64 >= committee.threshold
                        && envelope.status != EncryptedEnvelopeStatus::Ordered
                        && envelope.status != EncryptedEnvelopeStatus::Included
                    {
                        envelope.status = EncryptedEnvelopeStatus::Decrypted;
                    } else if !matches!(
                        envelope.status,
                        EncryptedEnvelopeStatus::Ordered | EncryptedEnvelopeStatus::Included
                    ) {
                        envelope.status = EncryptedEnvelopeStatus::Decrypting;
                    }
                }
            }
        }
    }

    fn envelope_root(&self) -> String {
        threshold_encrypted_mempool_envelope_set_root(&self.envelopes)
    }

    fn anti_mev_commitment_root(&self) -> String {
        threshold_encrypted_mempool_anti_mev_commitment_set_root(&self.anti_mev_commitments)
    }

    fn decryption_commitment_root(&self) -> String {
        threshold_encrypted_mempool_decryption_commitment_set_root(&self.decryption_commitments)
    }

    fn decryption_reveal_root(&self) -> String {
        threshold_encrypted_mempool_decryption_reveal_set_root(&self.decryption_reveals)
    }
}

pub fn threshold_encrypted_mempool_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(threshold_encrypted_mempool_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn threshold_encrypted_mempool_config_id(record: &Value) -> String {
    threshold_encrypted_mempool_payload_root("THRESHOLD-ENCRYPTED-MEMPOOL-CONFIG-ID", record)
}

pub fn threshold_encrypted_mempool_lane_key(
    lane_kind: ThresholdMempoolLaneKind,
    tx_kind: &str,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-LANE-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(tx_kind),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_amount_commitment(amount: u64, blinding: &str) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Int(amount as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_pq_ciphertext_root(
    committee_id: &str,
    payload_ciphertext_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-PQ-CIPHERTEXT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(committee_id),
            HashPart::Str(payload_ciphertext_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_replay_nullifier(
    submitter_commitment: &str,
    payload_ciphertext_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-REPLAY-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(submitter_commitment),
            HashPart::Str(payload_ciphertext_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_committee_member_id(
    operator_id: &str,
    validator_label: &str,
    pq_kem_public_key_root: &str,
    share_commitment_root: &str,
    activation_height: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-COMMITTEE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(validator_label),
            HashPart::Str(pq_kem_public_key_root),
            HashPart::Str(share_commitment_root),
            HashPart::Int(activation_height as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_committee_id(
    epoch: u64,
    threshold: u64,
    member_root: &str,
    aggregate_pq_public_key_root: &str,
    activation_height: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Int(epoch as i128),
            HashPart::Int(threshold as i128),
            HashPart::Str(member_root),
            HashPart::Str(aggregate_pq_public_key_root),
            HashPart::Int(activation_height as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_envelope_id(
    lane_kind: ThresholdMempoolLaneKind,
    submitter_commitment: &str,
    tx_kind_commitment: &str,
    payload_ciphertext_root: &str,
    pq_ciphertext_root: &str,
    committee_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(submitter_commitment),
            HashPart::Str(tx_kind_commitment),
            HashPart::Str(payload_ciphertext_root),
            HashPart::Str(pq_ciphertext_root),
            HashPart::Str(committee_id),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_anti_mev_commitment_id(
    envelope_id: &str,
    searcher_commitment: &str,
    bundle_commitment_root: &str,
    sealed_bid_root: &str,
    commit_height: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-ANTI-MEV-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(envelope_id),
            HashPart::Str(searcher_commitment),
            HashPart::Str(bundle_commitment_root),
            HashPart::Str(sealed_bid_root),
            HashPart::Int(commit_height as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_decryption_commitment_id(
    window_id: &str,
    envelope_id: &str,
    committee_id: &str,
    member_id: &str,
    share_index: u64,
    share_commitment_root: &str,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-DECRYPTION-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(envelope_id),
            HashPart::Str(committee_id),
            HashPart::Str(member_id),
            HashPart::Int(share_index as i128),
            HashPart::Str(share_commitment_root),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_decryption_reveal_id(
    commitment_id: &str,
    envelope_id: &str,
    member_id: &str,
    decrypted_share_root: &str,
    revealed_at_height: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-DECRYPTION-REVEAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(commitment_id),
            HashPart::Str(envelope_id),
            HashPart::Str(member_id),
            HashPart::Str(decrypted_share_root),
            HashPart::Int(revealed_at_height as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_ordering_seed(
    sequence: u64,
    start_height: u64,
    end_height: u64,
    anti_mev_commitment_root: &str,
    decryption_share_commitment_root: &str,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-ORDERING-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(anti_mev_commitment_root),
            HashPart::Str(decryption_share_commitment_root),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_ordering_key(
    ordering_seed: &str,
    envelope_id: &str,
    submitted_at_height: u64,
    lane_kind: ThresholdMempoolLaneKind,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-ORDERING-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(ordering_seed),
            HashPart::Str(envelope_id),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Str(lane_kind.as_str()),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_fair_ordering_window_id(
    sequence: u64,
    start_height: u64,
    end_height: u64,
    ordering_seed: &str,
    envelope_root: &str,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-FAIR-ORDERING-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(ordering_seed),
            HashPart::Str(envelope_root),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_low_fee_lane_id(
    lane_key: &str,
    lane_kind: ThresholdMempoolLaneKind,
    fee_asset_id: &str,
    max_fee_micro_units: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-LOW-FEE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(lane_key),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Int(max_fee_micro_units as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_forced_inclusion_hook_id(
    ticket_id: &str,
    envelope_id: &str,
    requester_commitment: &str,
    l1_anchor_root: &str,
    requested_at_height: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-FORCED-INCLUSION-HOOK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(ticket_id),
            HashPart::Str(envelope_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(l1_anchor_root),
            HashPart::Int(requested_at_height as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_privacy_disclosure_receipt_id(
    envelope_id: &str,
    committee_id: &str,
    scope: PrivacyDisclosureScope,
    viewer_commitment: &str,
    disclosed_record_root: &str,
    disclosed_at_height: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-PRIVACY-DISCLOSURE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(envelope_id),
            HashPart::Str(committee_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(viewer_commitment),
            HashPart::Str(disclosed_record_root),
            HashPart::Int(disclosed_at_height as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_conflict_root(
    evidence_kind: SlashingEvidenceKind,
    first_record_root: &str,
    second_record_root: &str,
) -> String {
    let mut roots = [
        first_record_root.to_string(),
        second_record_root.to_string(),
    ];
    roots.sort();
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-CONFLICT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(&roots[0]),
            HashPart::Str(&roots[1]),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_slashing_evidence_id(
    evidence_kind: SlashingEvidenceKind,
    accused_member_id: &str,
    related_committee_id: &str,
    window_id: Option<&str>,
    envelope_id: Option<&str>,
    conflict_root: &str,
    discovered_at_height: u64,
) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(accused_member_id),
            HashPart::Str(related_committee_id),
            HashPart::Str(window_id.unwrap_or("")),
            HashPart::Str(envelope_id.unwrap_or("")),
            HashPart::Str(conflict_root),
            HashPart::Int(discovered_at_height as i128),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_public_record_id(object_id: &str, record: &Value) -> String {
    domain_hash(
        "THRESHOLD-ENCRYPTED-MEMPOOL-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(THRESHOLD_ENCRYPTED_MEMPOOL_PROTOCOL_VERSION),
            HashPart::Str(object_id),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn threshold_encrypted_mempool_committee_member_set_root(
    members: &BTreeMap<String, PqThresholdCommitteeMember>,
) -> String {
    let leaves = members
        .values()
        .map(PqThresholdCommitteeMember::public_record)
        .collect::<Vec<_>>();
    merkle_root("THRESHOLD-ENCRYPTED-MEMPOOL-COMMITTEE-MEMBER-SET", &leaves)
}

pub fn threshold_encrypted_mempool_committee_set_root(
    committees: &BTreeMap<String, PqThresholdEncryptionCommittee>,
) -> String {
    let leaves = committees
        .values()
        .map(PqThresholdEncryptionCommittee::public_record)
        .collect::<Vec<_>>();
    merkle_root("THRESHOLD-ENCRYPTED-MEMPOOL-COMMITTEE-SET", &leaves)
}

pub fn threshold_encrypted_mempool_envelope_set_root(
    envelopes: &BTreeMap<String, EncryptedTransactionEnvelope>,
) -> String {
    let leaves = envelopes
        .values()
        .map(EncryptedTransactionEnvelope::public_record)
        .collect::<Vec<_>>();
    merkle_root("THRESHOLD-ENCRYPTED-MEMPOOL-ENVELOPE-SET", &leaves)
}

pub fn threshold_encrypted_mempool_anti_mev_commitment_set_root(
    commitments: &BTreeMap<String, AntiMevCommitment>,
) -> String {
    let leaves = commitments
        .values()
        .map(AntiMevCommitment::public_record)
        .collect::<Vec<_>>();
    merkle_root("THRESHOLD-ENCRYPTED-MEMPOOL-ANTI-MEV-SET", &leaves)
}

pub fn threshold_encrypted_mempool_decryption_commitment_set_root(
    commitments: &BTreeMap<String, DecryptionShareCommitment>,
) -> String {
    let leaves = commitments
        .values()
        .map(DecryptionShareCommitment::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "THRESHOLD-ENCRYPTED-MEMPOOL-DECRYPTION-COMMITMENT-SET",
        &leaves,
    )
}

pub fn threshold_encrypted_mempool_decryption_reveal_set_root(
    reveals: &BTreeMap<String, DecryptionShareReveal>,
) -> String {
    let leaves = reveals
        .values()
        .map(DecryptionShareReveal::public_record)
        .collect::<Vec<_>>();
    merkle_root("THRESHOLD-ENCRYPTED-MEMPOOL-DECRYPTION-REVEAL-SET", &leaves)
}

pub fn threshold_encrypted_mempool_fair_ordering_window_set_root(
    windows: &BTreeMap<String, FairOrderingWindow>,
) -> String {
    let leaves = windows
        .values()
        .map(FairOrderingWindow::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "THRESHOLD-ENCRYPTED-MEMPOOL-FAIR-ORDERING-WINDOW-SET",
        &leaves,
    )
}

pub fn threshold_encrypted_mempool_low_fee_lane_set_root(
    lanes: &BTreeMap<String, LowFeeQueueLane>,
) -> String {
    let leaves = lanes
        .values()
        .map(LowFeeQueueLane::public_record)
        .collect::<Vec<_>>();
    merkle_root("THRESHOLD-ENCRYPTED-MEMPOOL-LOW-FEE-LANE-SET", &leaves)
}

pub fn threshold_encrypted_mempool_forced_inclusion_hook_set_root(
    hooks: &BTreeMap<String, ForcedInclusionHook>,
) -> String {
    let leaves = hooks
        .values()
        .map(ForcedInclusionHook::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "THRESHOLD-ENCRYPTED-MEMPOOL-FORCED-INCLUSION-HOOK-SET",
        &leaves,
    )
}

pub fn threshold_encrypted_mempool_privacy_disclosure_receipt_set_root(
    receipts: &BTreeMap<String, PrivacyDisclosureReceipt>,
) -> String {
    let leaves = receipts
        .values()
        .map(PrivacyDisclosureReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "THRESHOLD-ENCRYPTED-MEMPOOL-PRIVACY-DISCLOSURE-RECEIPT-SET",
        &leaves,
    )
}

pub fn threshold_encrypted_mempool_slashing_evidence_set_root(
    evidence: &BTreeMap<String, EquivocationSlashingEvidence>,
) -> String {
    let leaves = evidence
        .values()
        .map(EquivocationSlashingEvidence::public_record)
        .collect::<Vec<_>>();
    merkle_root("THRESHOLD-ENCRYPTED-MEMPOOL-SLASHING-EVIDENCE-SET", &leaves)
}

pub fn threshold_encrypted_mempool_public_record_set_root(
    records: &BTreeMap<String, Value>,
) -> String {
    let leaves = records
        .iter()
        .map(|(record_id, record)| {
            json!({
                "record_id": record_id,
                "record_root": threshold_encrypted_mempool_payload_root(
                    "THRESHOLD-ENCRYPTED-MEMPOOL-PUBLIC-RECORD",
                    record,
                ),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("THRESHOLD-ENCRYPTED-MEMPOOL-PUBLIC-RECORD-SET", &leaves)
}

fn ensure_non_empty(value: &str, label: &str) -> ThresholdEncryptedMempoolResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> ThresholdEncryptedMempoolResult<()> {
    if value > THRESHOLD_ENCRYPTED_MEMPOOL_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> ThresholdEncryptedMempoolResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value {value}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_roots_are_stable() {
        let state = ThresholdEncryptedMempoolState::devnet().expect("devnet state");
        let root = state.validate().expect("valid devnet state");
        assert_eq!(root, state.state_root());
        assert!(state.counters().envelope_count >= 4);
        assert!(state.counters().accepted_decryption_reveal_count >= state.config.threshold);
    }

    #[test]
    fn envelope_ids_are_deterministic() {
        let committee_id = threshold_encrypted_mempool_string_root("TEST-COMMITTEE", "committee");
        let left = EncryptedTransactionEnvelope::new(
            ThresholdMempoolLaneKind::PrivateTransfer,
            "alice",
            "private_transfer",
            &json!({"ciphertext": "a"}),
            128,
            committee_id.clone(),
            1_000,
            None,
            None,
            None,
            7,
            10,
            20,
        )
        .expect("left envelope");
        let right = EncryptedTransactionEnvelope::new(
            ThresholdMempoolLaneKind::PrivateTransfer,
            "alice",
            "private_transfer",
            &json!({"ciphertext": "a"}),
            128,
            committee_id,
            1_000,
            None,
            None,
            None,
            7,
            10,
            20,
        )
        .expect("right envelope");
        assert_eq!(left.envelope_id, right.envelope_id);
        assert_eq!(left.public_record(), right.public_record());
    }
}
