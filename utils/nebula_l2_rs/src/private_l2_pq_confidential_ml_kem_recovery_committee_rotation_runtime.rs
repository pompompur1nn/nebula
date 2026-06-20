use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlKemRecoveryCommitteeRotationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_RECOVERY_COMMITTEE_ROTATION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-ml-kem-recovery-committee-rotation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_RECOVERY_COMMITTEE_ROTATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ML_KEM_SUITE: &str = "ML-KEM-1024+HKDF-SHA3-512-recovery-envelope-v1";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-quorum-attestation-v1";
pub const SHARD_COMMITMENT_SUITE: &str = "monero-private-l2-recovery-shard-commitment-v1";
pub const SPONSOR_BOND_SUITE: &str = "low-fee-rotation-sponsor-bond-v1";
pub const PRIVACY_BUDGET_SUITE: &str = "operator-safe-committee-rotation-redaction-budget-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "redacted-ml-kem-recovery-operator-summary-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 4_683_240;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_451_120;
pub const DEVNET_EPOCH: u64 = 21_024;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 720;
pub const DEFAULT_GRACE_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ENVELOPE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8;
pub const DEFAULT_REFUND_CAP_BPS: u64 = 2_500;
pub const DEFAULT_SPONSOR_BOND_MICRO_UNITS: u64 = 150_000_000;
pub const DEFAULT_OPERATOR_BOND_MICRO_UNITS: u64 = 250_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MAX_REDACTIONS_PER_EPOCH: u64 = 64;
pub const DEFAULT_MAX_COMMITTEE_MEMBERS: usize = 512;
pub const DEFAULT_MAX_SHARDS: usize = 4_096;
pub const DEFAULT_MAX_ENVELOPES: usize = 8_388_608;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 16_777_216;
pub const DEFAULT_MAX_BONDS: usize = 1_048_576;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 2_097_152;
pub const DEFAULT_MAX_REFUNDS: usize = 16_777_216;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    Scheduled,
    MembershipDrift,
    KeyExpiry,
    PrivacySetRefresh,
    OperatorExit,
    EmergencyCompromise,
    SlashRecovery,
    FeeSponsorRefresh,
    Custom,
}

impl RotationReason {
    pub fn urgency_weight(self) -> u64 {
        match self {
            Self::EmergencyCompromise => 10_000,
            Self::SlashRecovery => 9_600,
            Self::KeyExpiry => 8_900,
            Self::MembershipDrift => 8_400,
            Self::PrivacySetRefresh => 8_000,
            Self::OperatorExit => 7_600,
            Self::FeeSponsorRefresh => 7_100,
            Self::Scheduled => 6_400,
            Self::Custom => 5_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Draft,
    Open,
    CommitPhase,
    Attesting,
    GracePeriod,
    Activated,
    Paused,
    Failed,
    Slashed,
    Superseded,
}

impl RotationStatus {
    pub fn accepts_envelopes(self) -> bool {
        matches!(self, Self::Open | Self::CommitPhase | Self::Attesting)
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(self, Self::Attesting | Self::GracePeriod)
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::CommitPhase | Self::Attesting | Self::GracePeriod | Self::Activated
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    RecoveryCustodian,
    ShardAssembler,
    PrivacyAuditor,
    FeeSponsor,
    Watchtower,
    EmergencyVeto,
    Observer,
}

impl CommitteeRole {
    pub fn voting_weight(self) -> u64 {
        match self {
            Self::RecoveryCustodian => 10_000,
            Self::ShardAssembler => 8_800,
            Self::PrivacyAuditor => 8_200,
            Self::Watchtower => 7_600,
            Self::EmergencyVeto => 7_200,
            Self::FeeSponsor => 6_800,
            Self::Observer => 2_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Candidate,
    Active,
    Standby,
    RotatingOut,
    Quarantined,
    Slashed,
    Exited,
}

impl MemberStatus {
    pub fn can_vote(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::RotatingOut)
    }

    pub fn slashable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Standby | Self::RotatingOut | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardClass {
    SpendRecovery,
    ViewRecovery,
    SessionRecovery,
    BridgeExitRecovery,
    ContractAdminRecovery,
    EmergencyBreakGlass,
    DecoyOnly,
}

impl ShardClass {
    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::DecoyOnly => 10_000,
            Self::SpendRecovery => 9_700,
            Self::ViewRecovery => 9_100,
            Self::SessionRecovery => 8_800,
            Self::BridgeExitRecovery => 8_500,
            Self::ContractAdminRecovery => 8_100,
            Self::EmergencyBreakGlass => 7_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Pending,
    Opened,
    QuorumBound,
    Refunded,
    Expired,
    Redacted,
    Disputed,
}

impl EnvelopeStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Pending | Self::Opened | Self::QuorumBound)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    KeyPossession,
    ShardAvailability,
    RecoveryReadiness,
    PrivacyBudgetCompliance,
    FeeCapCompliance,
    EmergencyVetoRelease,
    RotationActivation,
}

impl AttestationKind {
    pub fn security_weight(self) -> u64 {
        match self {
            Self::RotationActivation => 10_000,
            Self::EmergencyVetoRelease => 9_600,
            Self::RecoveryReadiness => 9_300,
            Self::ShardAvailability => 8_900,
            Self::KeyPossession => 8_500,
            Self::PrivacyBudgetCompliance => 8_100,
            Self::FeeCapCompliance => 7_600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Locked,
    PartiallyReleased,
    Released,
    Slashed,
    Refunding,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidMlKemCiphertext,
    MissingShard,
    EquivocatedAttestation,
    PrivacyBudgetExceeded,
    FeeOvercharge,
    LateActivation,
    OperatorCensorship,
    EmergencyKeyLeak,
}

impl SlashingReason {
    pub fn default_penalty_bps(self) -> u64 {
        match self {
            Self::EmergencyKeyLeak => 8_500,
            Self::EquivocatedAttestation => 6_000,
            Self::InvalidMlKemCiphertext => 5_500,
            Self::MissingShard => 4_500,
            Self::OperatorCensorship => 3_500,
            Self::PrivacyBudgetExceeded => 3_000,
            Self::FeeOvercharge => 2_500,
            Self::LateActivation => 1_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundStatus {
    Accruing,
    Claimable,
    Claimed,
    Expired,
    Donated,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub epoch_length_blocks: u64,
    pub grace_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub envelope_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub refund_cap_bps: u64,
    pub sponsor_bond_micro_units: u64,
    pub operator_bond_micro_units: u64,
    pub default_slash_bps: u64,
    pub max_redactions_per_epoch: u64,
    pub max_committee_members: usize,
    pub max_shards: usize,
    pub max_envelopes: usize,
    pub max_attestations: usize,
    pub max_bonds: usize,
    pub max_slashing_evidence: usize,
    pub max_refunds: usize,
    pub require_dual_pq_attestation: bool,
    pub enable_low_fee_refunds: bool,
    pub expose_operator_summaries: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            epoch_length_blocks: DEFAULT_EPOCH_LENGTH_BLOCKS,
            grace_blocks: DEFAULT_GRACE_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            envelope_ttl_blocks: DEFAULT_ENVELOPE_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            refund_cap_bps: DEFAULT_REFUND_CAP_BPS,
            sponsor_bond_micro_units: DEFAULT_SPONSOR_BOND_MICRO_UNITS,
            operator_bond_micro_units: DEFAULT_OPERATOR_BOND_MICRO_UNITS,
            default_slash_bps: DEFAULT_SLASH_BPS,
            max_redactions_per_epoch: DEFAULT_MAX_REDACTIONS_PER_EPOCH,
            max_committee_members: DEFAULT_MAX_COMMITTEE_MEMBERS,
            max_shards: DEFAULT_MAX_SHARDS,
            max_envelopes: DEFAULT_MAX_ENVELOPES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_bonds: DEFAULT_MAX_BONDS,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            max_refunds: DEFAULT_MAX_REFUNDS,
            require_dual_pq_attestation: true,
            enable_low_fee_refunds: true,
            expose_operator_summaries: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.min_pq_security_bits >= 192,
            "minimum pq security bits too low: {}",
            self.min_pq_security_bits
        );
        ensure!(
            self.min_privacy_set_size > 0
                && self.target_privacy_set_size >= self.min_privacy_set_size,
            "invalid privacy set bounds"
        );
        ensure!(
            self.epoch_length_blocks > 0,
            "epoch length must be non-zero"
        );
        ensure!(
            self.attestation_ttl_blocks > 0,
            "attestation ttl must be non-zero"
        );
        ensure!(
            self.envelope_ttl_blocks > 0,
            "envelope ttl must be non-zero"
        );
        ensure!(
            self.max_user_fee_bps <= MAX_BPS
                && self.low_fee_target_bps <= self.max_user_fee_bps
                && self.refund_cap_bps <= MAX_BPS,
            "invalid fee basis point policy"
        );
        ensure!(
            self.default_slash_bps <= MAX_BPS,
            "invalid default slash bps {}",
            self.default_slash_bps
        );
        ensure!(
            self.max_committee_members > 0 && self.max_shards > 0,
            "committee and shard limits must be non-zero"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "epoch_length_blocks": self.epoch_length_blocks,
            "grace_blocks": self.grace_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "envelope_ttl_blocks": self.envelope_ttl_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "refund_cap_bps": self.refund_cap_bps,
            "sponsor_bond_micro_units": self.sponsor_bond_micro_units,
            "operator_bond_micro_units": self.operator_bond_micro_units,
            "default_slash_bps": self.default_slash_bps,
            "max_redactions_per_epoch": self.max_redactions_per_epoch,
            "require_dual_pq_attestation": self.require_dual_pq_attestation,
            "enable_low_fee_refunds": self.enable_low_fee_refunds,
            "expose_operator_summaries": self.expose_operator_summaries,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub rotations_opened: u64,
    pub rotations_activated: u64,
    pub rotations_slashed: u64,
    pub members_registered: u64,
    pub shards_committed: u64,
    pub envelopes_committed: u64,
    pub attestations_accepted: u64,
    pub sponsor_bonds_locked: u64,
    pub slashing_evidence_accepted: u64,
    pub refunds_credited: u64,
    pub privacy_redactions_spent: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "rotations_opened": self.rotations_opened,
            "rotations_activated": self.rotations_activated,
            "rotations_slashed": self.rotations_slashed,
            "members_registered": self.members_registered,
            "shards_committed": self.shards_committed,
            "envelopes_committed": self.envelopes_committed,
            "attestations_accepted": self.attestations_accepted,
            "sponsor_bonds_locked": self.sponsor_bonds_locked,
            "slashing_evidence_accepted": self.slashing_evidence_accepted,
            "refunds_credited": self.refunds_credited,
            "privacy_redactions_spent": self.privacy_redactions_spent,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub rotation_root: String,
    pub member_root: String,
    pub shard_root: String,
    pub envelope_root: String,
    pub attestation_root: String,
    pub bond_root: String,
    pub slashing_root: String,
    pub refund_root: String,
    pub privacy_budget_root: String,
    pub operator_summary_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "rotation_root": self.rotation_root,
            "member_root": self.member_root,
            "shard_root": self.shard_root,
            "envelope_root": self.envelope_root,
            "attestation_root": self.attestation_root,
            "bond_root": self.bond_root,
            "slashing_root": self.slashing_root,
            "refund_root": self.refund_root,
            "privacy_budget_root": self.privacy_budget_root,
            "operator_summary_root": self.operator_summary_root,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RotationEpoch {
    pub rotation_id: String,
    pub prior_rotation_id: Option<String>,
    pub epoch: u64,
    pub l2_start_height: u64,
    pub monero_anchor_height: u64,
    pub activate_after_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub reason: RotationReason,
    pub status: RotationStatus,
    pub target_member_count: u16,
    pub recovery_threshold: u16,
    pub veto_threshold: u16,
    pub min_privacy_set_size: u64,
    pub outbound_committee_root: String,
    pub inbound_committee_root: String,
    pub shard_manifest_root: String,
    pub attestation_root: String,
    pub sponsor_bond_root: String,
    pub fee_floor_bps: u64,
    pub operator_note_commitment: String,
}

impl RotationEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rotation_id: impl Into<String>,
        prior_rotation_id: Option<String>,
        epoch: u64,
        l2_start_height: u64,
        monero_anchor_height: u64,
        reason: RotationReason,
        target_member_count: u16,
        recovery_threshold: u16,
        veto_threshold: u16,
        config: &Config,
    ) -> Result<Self> {
        ensure!(
            target_member_count > 0,
            "target member count must be non-zero"
        );
        ensure!(
            recovery_threshold > 0 && recovery_threshold <= target_member_count,
            "invalid recovery threshold"
        );
        ensure!(
            veto_threshold <= target_member_count,
            "invalid veto threshold {}",
            veto_threshold
        );
        let rotation_id = rotation_id.into();
        ensure!(!rotation_id.is_empty(), "rotation id must not be empty");
        Ok(Self {
            rotation_id,
            prior_rotation_id,
            epoch,
            l2_start_height,
            monero_anchor_height,
            activate_after_l2_height: l2_start_height + config.epoch_length_blocks,
            expires_at_l2_height: l2_start_height
                + config.epoch_length_blocks
                + config.grace_blocks,
            reason,
            status: RotationStatus::Open,
            target_member_count,
            recovery_threshold,
            veto_threshold,
            min_privacy_set_size: config.min_privacy_set_size,
            outbound_committee_root: empty_root("OUTBOUND-COMMITTEE"),
            inbound_committee_root: empty_root("INBOUND-COMMITTEE"),
            shard_manifest_root: empty_root("SHARD-MANIFEST"),
            attestation_root: empty_root("ATTESTATIONS"),
            sponsor_bond_root: empty_root("SPONSOR-BONDS"),
            fee_floor_bps: config.low_fee_target_bps,
            operator_note_commitment: deterministic_commitment("rotation-note", epoch, 32),
        })
    }

    pub fn is_expired(&self, l2_height: u64) -> bool {
        l2_height > self.expires_at_l2_height
    }

    pub fn ready_for_activation(&self, l2_height: u64, quorum_weight_bps: u64) -> bool {
        self.status.accepts_attestations()
            && l2_height >= self.activate_after_l2_height
            && quorum_weight_bps >= MAX_BPS
    }

    pub fn transition(&mut self, next: RotationStatus) -> Result<()> {
        ensure!(
            matches!(
                (self.status, next),
                (RotationStatus::Open, RotationStatus::CommitPhase)
                    | (RotationStatus::CommitPhase, RotationStatus::Attesting)
                    | (RotationStatus::Attesting, RotationStatus::GracePeriod)
                    | (RotationStatus::Attesting, RotationStatus::Activated)
                    | (RotationStatus::GracePeriod, RotationStatus::Activated)
                    | (_, RotationStatus::Paused)
                    | (_, RotationStatus::Failed)
                    | (_, RotationStatus::Slashed)
                    | (_, RotationStatus::Superseded)
            ),
            "invalid rotation transition {:?} -> {:?}",
            self.status,
            next
        );
        self.status = next;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "rotation_id": self.rotation_id,
            "prior_rotation_id": self.prior_rotation_id,
            "epoch": self.epoch,
            "l2_start_height": self.l2_start_height,
            "monero_anchor_height": self.monero_anchor_height,
            "activate_after_l2_height": self.activate_after_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "reason": self.reason,
            "status": self.status,
            "target_member_count": self.target_member_count,
            "recovery_threshold": self.recovery_threshold,
            "veto_threshold": self.veto_threshold,
            "min_privacy_set_size": self.min_privacy_set_size,
            "outbound_committee_root": self.outbound_committee_root,
            "inbound_committee_root": self.inbound_committee_root,
            "shard_manifest_root": self.shard_manifest_root,
            "attestation_root": self.attestation_root,
            "sponsor_bond_root": self.sponsor_bond_root,
            "fee_floor_bps": self.fee_floor_bps,
            "operator_note_commitment": self.operator_note_commitment,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-ROTATION-EPOCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_id: String,
    pub role: CommitteeRole,
    pub status: MemberStatus,
    pub weight_bps: u64,
    pub ml_kem_public_key_commitment: String,
    pub ml_dsa_public_key_commitment: String,
    pub slh_dsa_public_key_commitment: String,
    pub bond_id: String,
    pub registered_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub jurisdiction_tag_commitment: String,
    pub service_endpoint_commitment: String,
    pub visibility_tags: BTreeSet<String>,
}

impl CommitteeMember {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        member_id: impl Into<String>,
        operator_id: impl Into<String>,
        role: CommitteeRole,
        weight_bps: u64,
        bond_id: impl Into<String>,
        l2_height: u64,
        config: &Config,
    ) -> Result<Self> {
        let member_id = member_id.into();
        let operator_id = operator_id.into();
        ensure!(!member_id.is_empty(), "member id must not be empty");
        ensure!(!operator_id.is_empty(), "operator id must not be empty");
        ensure!(weight_bps <= MAX_BPS, "member weight exceeds MAX_BPS");
        Ok(Self {
            ml_kem_public_key_commitment: deterministic_commitment(&member_id, 1, 48),
            ml_dsa_public_key_commitment: deterministic_commitment(&member_id, 2, 48),
            slh_dsa_public_key_commitment: deterministic_commitment(&member_id, 3, 48),
            jurisdiction_tag_commitment: deterministic_commitment(&operator_id, 4, 24),
            service_endpoint_commitment: deterministic_commitment(&operator_id, 5, 24),
            member_id,
            operator_id,
            role,
            status: MemberStatus::Candidate,
            weight_bps,
            bond_id: bond_id.into(),
            registered_at_l2_height: l2_height,
            expires_at_l2_height: l2_height + config.envelope_ttl_blocks * 4,
            visibility_tags: BTreeSet::new(),
        })
    }

    pub fn activate(&mut self) {
        self.status = MemberStatus::Active;
    }

    pub fn effective_weight_bps(&self) -> u64 {
        if self.status.can_vote() {
            self.weight_bps.saturating_mul(self.role.voting_weight()) / MAX_BPS
        } else {
            0
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_id": self.operator_id,
            "role": self.role,
            "status": self.status,
            "weight_bps": self.weight_bps,
            "effective_weight_bps": self.effective_weight_bps(),
            "ml_kem_public_key_commitment": self.ml_kem_public_key_commitment,
            "ml_dsa_public_key_commitment": self.ml_dsa_public_key_commitment,
            "slh_dsa_public_key_commitment": self.slh_dsa_public_key_commitment,
            "bond_id": self.bond_id,
            "registered_at_l2_height": self.registered_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "jurisdiction_tag_commitment": self.jurisdiction_tag_commitment,
            "service_endpoint_commitment": self.service_endpoint_commitment,
            "visibility_tags": self.visibility_tags,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-COMMITTEE-MEMBER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CommitteeShard {
    pub shard_id: String,
    pub rotation_id: String,
    pub holder_member_id: String,
    pub shard_class: ShardClass,
    pub index: u16,
    pub threshold: u16,
    pub total_shards: u16,
    pub account_cohort_commitment: String,
    pub shard_ciphertext_commitment: String,
    pub shard_opening_commitment: String,
    pub decoy_set_root: String,
    pub nullifier_set_root: String,
    pub privacy_set_size: u64,
    pub committed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub redacted: bool,
}

impl CommitteeShard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_id: impl Into<String>,
        rotation_id: impl Into<String>,
        holder_member_id: impl Into<String>,
        shard_class: ShardClass,
        index: u16,
        threshold: u16,
        total_shards: u16,
        privacy_set_size: u64,
        l2_height: u64,
        config: &Config,
    ) -> Result<Self> {
        let shard_id = shard_id.into();
        ensure!(!shard_id.is_empty(), "shard id must not be empty");
        ensure!(index < total_shards, "shard index must be less than total");
        ensure!(
            threshold > 0 && threshold <= total_shards,
            "invalid shard threshold"
        );
        ensure!(
            privacy_set_size >= config.min_privacy_set_size,
            "privacy set below configured minimum"
        );
        Ok(Self {
            account_cohort_commitment: deterministic_commitment(&shard_id, 11, 32),
            shard_ciphertext_commitment: deterministic_commitment(&shard_id, 12, 48),
            shard_opening_commitment: deterministic_commitment(&shard_id, 13, 32),
            decoy_set_root: deterministic_commitment(&shard_id, 14, 32),
            nullifier_set_root: deterministic_commitment(&shard_id, 15, 32),
            shard_id,
            rotation_id: rotation_id.into(),
            holder_member_id: holder_member_id.into(),
            shard_class,
            index,
            threshold,
            total_shards,
            privacy_set_size,
            committed_at_l2_height: l2_height,
            expires_at_l2_height: l2_height + config.envelope_ttl_blocks,
            redacted: false,
        })
    }

    pub fn fee_discount_bps(&self, config: &Config) -> u64 {
        let privacy_bonus = self.privacy_set_size.saturating_mul(config.refund_cap_bps)
            / config.target_privacy_set_size.max(1);
        privacy_bonus.min(config.refund_cap_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "rotation_id": self.rotation_id,
            "holder_member_id": self.holder_member_id,
            "shard_class": self.shard_class,
            "index": self.index,
            "threshold": self.threshold,
            "total_shards": self.total_shards,
            "account_cohort_commitment": self.account_cohort_commitment,
            "shard_ciphertext_commitment": self.shard_ciphertext_commitment,
            "shard_opening_commitment": self.shard_opening_commitment,
            "decoy_set_root": self.decoy_set_root,
            "nullifier_set_root": self.nullifier_set_root,
            "privacy_set_size": self.privacy_set_size,
            "committed_at_l2_height": self.committed_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "redacted": self.redacted,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-COMMITTEE-SHARD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct MlKemEnvelopeCommitment {
    pub envelope_id: String,
    pub rotation_id: String,
    pub shard_id: String,
    pub recipient_member_id: String,
    pub status: EnvelopeStatus,
    pub suite: String,
    pub kem_ciphertext_commitment: String,
    pub encapsulated_key_commitment: String,
    pub associated_data_root: String,
    pub fee_commitment: String,
    pub refund_address_commitment: String,
    pub created_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub user_fee_bps: u64,
    pub sponsor_id: Option<String>,
    pub redaction_budget_id: Option<String>,
}

impl MlKemEnvelopeCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        envelope_id: impl Into<String>,
        rotation_id: impl Into<String>,
        shard_id: impl Into<String>,
        recipient_member_id: impl Into<String>,
        user_fee_bps: u64,
        sponsor_id: Option<String>,
        l2_height: u64,
        config: &Config,
    ) -> Result<Self> {
        let envelope_id = envelope_id.into();
        ensure!(!envelope_id.is_empty(), "envelope id must not be empty");
        ensure!(
            user_fee_bps <= config.max_user_fee_bps,
            "user fee {} bps exceeds cap {}",
            user_fee_bps,
            config.max_user_fee_bps
        );
        Ok(Self {
            kem_ciphertext_commitment: deterministic_commitment(&envelope_id, 21, 64),
            encapsulated_key_commitment: deterministic_commitment(&envelope_id, 22, 48),
            associated_data_root: deterministic_commitment(&envelope_id, 23, 32),
            fee_commitment: deterministic_commitment(&envelope_id, 24, 24),
            refund_address_commitment: deterministic_commitment(&envelope_id, 25, 24),
            envelope_id,
            rotation_id: rotation_id.into(),
            shard_id: shard_id.into(),
            recipient_member_id: recipient_member_id.into(),
            status: EnvelopeStatus::Pending,
            suite: ML_KEM_SUITE.to_string(),
            created_at_l2_height: l2_height,
            expires_at_l2_height: l2_height + config.envelope_ttl_blocks,
            user_fee_bps,
            sponsor_id,
            redaction_budget_id: None,
        })
    }

    pub fn expected_refund_bps(&self, config: &Config) -> u64 {
        if !config.enable_low_fee_refunds || self.user_fee_bps <= config.low_fee_target_bps {
            0
        } else {
            self.user_fee_bps
                .saturating_sub(config.low_fee_target_bps)
                .min(config.refund_cap_bps)
        }
    }

    pub fn bind_quorum(&mut self) {
        self.status = EnvelopeStatus::QuorumBound;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "rotation_id": self.rotation_id,
            "shard_id": self.shard_id,
            "recipient_member_id": self.recipient_member_id,
            "status": self.status,
            "suite": self.suite,
            "kem_ciphertext_commitment": self.kem_ciphertext_commitment,
            "encapsulated_key_commitment": self.encapsulated_key_commitment,
            "associated_data_root": self.associated_data_root,
            "fee_commitment": self.fee_commitment,
            "refund_address_commitment": self.refund_address_commitment,
            "created_at_l2_height": self.created_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "user_fee_bps": self.user_fee_bps,
            "expected_refund_bps": self.expected_refund_bps(&Config::default()),
            "sponsor_id": self.sponsor_id,
            "redaction_budget_id": self.redaction_budget_id,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-ENVELOPE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RecoveryQuorumAttestation {
    pub attestation_id: String,
    pub rotation_id: String,
    pub envelope_id: Option<String>,
    pub kind: AttestationKind,
    pub signer_member_id: String,
    pub signer_weight_bps: u64,
    pub statement_root: String,
    pub ml_dsa_signature_commitment: String,
    pub slh_dsa_signature_commitment: String,
    pub transcript_root: String,
    pub observed_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub accepted: bool,
}

impl RecoveryQuorumAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attestation_id: impl Into<String>,
        rotation_id: impl Into<String>,
        envelope_id: Option<String>,
        kind: AttestationKind,
        signer: &CommitteeMember,
        observed_l2_height: u64,
        config: &Config,
    ) -> Result<Self> {
        let attestation_id = attestation_id.into();
        ensure!(
            !attestation_id.is_empty(),
            "attestation id must not be empty"
        );
        ensure!(signer.status.can_vote(), "signer is not eligible to attest");
        let signer_weight_bps = signer.effective_weight_bps();
        ensure!(signer_weight_bps > 0, "signer weight is zero");
        Ok(Self {
            statement_root: deterministic_commitment(&attestation_id, 31, 32),
            ml_dsa_signature_commitment: deterministic_commitment(&attestation_id, 32, 48),
            slh_dsa_signature_commitment: deterministic_commitment(&attestation_id, 33, 48),
            transcript_root: deterministic_commitment(&attestation_id, 34, 32),
            attestation_id,
            rotation_id: rotation_id.into(),
            envelope_id,
            kind,
            signer_member_id: signer.member_id.clone(),
            signer_weight_bps,
            observed_l2_height,
            expires_at_l2_height: observed_l2_height + config.attestation_ttl_blocks,
            accepted: true,
        })
    }

    pub fn weighted_security_score(&self) -> u64 {
        self.signer_weight_bps
            .saturating_mul(self.kind.security_weight())
            / MAX_BPS
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "rotation_id": self.rotation_id,
            "envelope_id": self.envelope_id,
            "kind": self.kind,
            "signer_member_id": self.signer_member_id,
            "signer_weight_bps": self.signer_weight_bps,
            "weighted_security_score": self.weighted_security_score(),
            "statement_root": self.statement_root,
            "ml_dsa_signature_commitment": self.ml_dsa_signature_commitment,
            "slh_dsa_signature_commitment": self.slh_dsa_signature_commitment,
            "transcript_root": self.transcript_root,
            "observed_l2_height": self.observed_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-QUORUM-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SponsorBond {
    pub bond_id: String,
    pub sponsor_id: String,
    pub operator_id: String,
    pub rotation_id: Option<String>,
    pub asset_id: String,
    pub locked_micro_units: u64,
    pub remaining_micro_units: u64,
    pub max_sponsored_fee_bps: u64,
    pub status: BondStatus,
    pub locked_at_l2_height: u64,
    pub release_after_l2_height: u64,
    pub commitment: String,
}

impl SponsorBond {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bond_id: impl Into<String>,
        sponsor_id: impl Into<String>,
        operator_id: impl Into<String>,
        rotation_id: Option<String>,
        locked_micro_units: u64,
        max_sponsored_fee_bps: u64,
        l2_height: u64,
        config: &Config,
    ) -> Result<Self> {
        let bond_id = bond_id.into();
        ensure!(!bond_id.is_empty(), "bond id must not be empty");
        ensure!(
            locked_micro_units >= config.sponsor_bond_micro_units,
            "sponsor bond below minimum"
        );
        ensure!(
            max_sponsored_fee_bps <= config.max_user_fee_bps,
            "sponsored fee exceeds user cap"
        );
        Ok(Self {
            commitment: deterministic_commitment(&bond_id, 41, 32),
            bond_id,
            sponsor_id: sponsor_id.into(),
            operator_id: operator_id.into(),
            rotation_id,
            asset_id: config.fee_asset_id.clone(),
            locked_micro_units,
            remaining_micro_units: locked_micro_units,
            max_sponsored_fee_bps,
            status: BondStatus::Locked,
            locked_at_l2_height: l2_height,
            release_after_l2_height: l2_height + config.envelope_ttl_blocks,
        })
    }

    pub fn slash(&mut self, amount_micro_units: u64) -> u64 {
        let amount = amount_micro_units.min(self.remaining_micro_units);
        self.remaining_micro_units -= amount;
        if self.remaining_micro_units == 0 {
            self.status = BondStatus::Slashed;
        } else {
            self.status = BondStatus::PartiallyReleased;
        }
        amount
    }

    pub fn releaseable(&self, l2_height: u64) -> bool {
        self.status == BondStatus::Locked && l2_height >= self.release_after_l2_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bond_id": self.bond_id,
            "sponsor_id": self.sponsor_id,
            "operator_id": self.operator_id,
            "rotation_id": self.rotation_id,
            "asset_id": self.asset_id,
            "locked_micro_units": self.locked_micro_units,
            "remaining_micro_units": self.remaining_micro_units,
            "max_sponsored_fee_bps": self.max_sponsored_fee_bps,
            "status": self.status,
            "locked_at_l2_height": self.locked_at_l2_height,
            "release_after_l2_height": self.release_after_l2_height,
            "commitment": self.commitment,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-SPONSOR-BOND", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub rotation_id: String,
    pub accused_member_id: String,
    pub reporter_id: String,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub offending_transcript_root: String,
    pub slash_bps: u64,
    pub accepted_at_l2_height: u64,
    pub applied_bond_id: Option<String>,
    pub reporter_reward_micro_units: u64,
    pub operator_visible: bool,
}

impl SlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_id: impl Into<String>,
        rotation_id: impl Into<String>,
        accused_member_id: impl Into<String>,
        reporter_id: impl Into<String>,
        reason: SlashingReason,
        accepted_at_l2_height: u64,
        config: &Config,
    ) -> Result<Self> {
        let evidence_id = evidence_id.into();
        ensure!(!evidence_id.is_empty(), "evidence id must not be empty");
        let slash_bps = reason.default_penalty_bps().max(config.default_slash_bps);
        Ok(Self {
            evidence_root: deterministic_commitment(&evidence_id, 51, 32),
            offending_transcript_root: deterministic_commitment(&evidence_id, 52, 32),
            evidence_id,
            rotation_id: rotation_id.into(),
            accused_member_id: accused_member_id.into(),
            reporter_id: reporter_id.into(),
            reason,
            slash_bps,
            accepted_at_l2_height,
            applied_bond_id: None,
            reporter_reward_micro_units: 0,
            operator_visible: true,
        })
    }

    pub fn reward_from_slash(&mut self, slashed_micro_units: u64) {
        self.reporter_reward_micro_units = slashed_micro_units / 5;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "rotation_id": self.rotation_id,
            "accused_member_id": self.accused_member_id,
            "reporter_id": self.reporter_id,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "offending_transcript_root": self.offending_transcript_root,
            "slash_bps": self.slash_bps,
            "accepted_at_l2_height": self.accepted_at_l2_height,
            "applied_bond_id": self.applied_bond_id,
            "reporter_reward_micro_units": self.reporter_reward_micro_units,
            "operator_visible": self.operator_visible,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeCreditRefund {
    pub refund_id: String,
    pub envelope_id: String,
    pub rotation_id: String,
    pub sponsor_id: Option<String>,
    pub recipient_commitment: String,
    pub asset_id: String,
    pub credit_micro_units: u64,
    pub refund_bps: u64,
    pub status: RefundStatus,
    pub created_at_l2_height: u64,
    pub claim_after_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl FeeCreditRefund {
    pub fn for_envelope(
        refund_id: impl Into<String>,
        envelope: &MlKemEnvelopeCommitment,
        charged_micro_units: u64,
        l2_height: u64,
        config: &Config,
    ) -> Result<Self> {
        let refund_id = refund_id.into();
        ensure!(!refund_id.is_empty(), "refund id must not be empty");
        let refund_bps = envelope.expected_refund_bps(config);
        let credit_micro_units = charged_micro_units.saturating_mul(refund_bps) / MAX_BPS;
        Ok(Self {
            recipient_commitment: envelope.refund_address_commitment.clone(),
            refund_id,
            envelope_id: envelope.envelope_id.clone(),
            rotation_id: envelope.rotation_id.clone(),
            sponsor_id: envelope.sponsor_id.clone(),
            asset_id: config.fee_asset_id.clone(),
            credit_micro_units,
            refund_bps,
            status: if credit_micro_units > 0 {
                RefundStatus::Claimable
            } else {
                RefundStatus::Donated
            },
            created_at_l2_height: l2_height,
            claim_after_l2_height: l2_height,
            expires_at_l2_height: l2_height + config.envelope_ttl_blocks,
        })
    }

    pub fn claim(&mut self) -> Result<u64> {
        ensure!(
            self.status == RefundStatus::Claimable,
            "refund not claimable"
        );
        self.status = RefundStatus::Claimed;
        Ok(self.credit_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "refund_id": self.refund_id,
            "envelope_id": self.envelope_id,
            "rotation_id": self.rotation_id,
            "sponsor_id": self.sponsor_id,
            "recipient_commitment": self.recipient_commitment,
            "asset_id": self.asset_id,
            "credit_micro_units": self.credit_micro_units,
            "refund_bps": self.refund_bps,
            "status": self.status,
            "created_at_l2_height": self.created_at_l2_height,
            "claim_after_l2_height": self.claim_after_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-FEE-CREDIT-REFUND", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub rotation_id: String,
    pub epoch: u64,
    pub allowed_redactions: u64,
    pub spent_redactions: u64,
    pub salt_commitment: String,
    pub redacted_fields: BTreeSet<String>,
    pub expires_at_l2_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        operator_id: impl Into<String>,
        rotation_id: impl Into<String>,
        epoch: u64,
        l2_height: u64,
        config: &Config,
    ) -> Result<Self> {
        let budget_id = budget_id.into();
        ensure!(!budget_id.is_empty(), "budget id must not be empty");
        Ok(Self {
            salt_commitment: deterministic_commitment(&budget_id, 61, 32),
            budget_id,
            operator_id: operator_id.into(),
            rotation_id: rotation_id.into(),
            epoch,
            allowed_redactions: config.max_redactions_per_epoch,
            spent_redactions: 0,
            redacted_fields: BTreeSet::new(),
            expires_at_l2_height: l2_height + config.epoch_length_blocks,
        })
    }

    pub fn spend(&mut self, field: impl Into<String>) -> Result<()> {
        ensure!(
            self.spent_redactions < self.allowed_redactions,
            "redaction budget exhausted"
        );
        self.spent_redactions += 1;
        self.redacted_fields.insert(field.into());
        Ok(())
    }

    pub fn remaining(&self) -> u64 {
        self.allowed_redactions
            .saturating_sub(self.spent_redactions)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "operator_id": self.operator_id,
            "rotation_id": self.rotation_id,
            "epoch": self.epoch,
            "allowed_redactions": self.allowed_redactions,
            "spent_redactions": self.spent_redactions,
            "remaining_redactions": self.remaining(),
            "salt_commitment": self.salt_commitment,
            "redacted_fields": self.redacted_fields,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root(
            "ML-KEM-RECOVERY-PRIVACY-REDACTION-BUDGET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub active_members: u64,
    pub active_weight_bps: u64,
    pub envelopes_served: u64,
    pub attestations_signed: u64,
    pub refunds_sponsored_micro_units: u64,
    pub bonds_locked_micro_units: u64,
    pub slash_count: u64,
    pub redactions_remaining: u64,
    pub latest_rotation_id: Option<String>,
    pub visibility_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "suite": OPERATOR_SUMMARY_SUITE,
            "operator_id": self.operator_id,
            "active_members": self.active_members,
            "active_weight_bps": self.active_weight_bps,
            "envelopes_served": self.envelopes_served,
            "attestations_signed": self.attestations_signed,
            "refunds_sponsored_micro_units": self.refunds_sponsored_micro_units,
            "bonds_locked_micro_units": self.bonds_locked_micro_units,
            "slash_count": self.slash_count,
            "redactions_remaining": self.redactions_remaining,
            "latest_rotation_id": self.latest_rotation_id,
            "visibility_root": self.visibility_root,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-RECOVERY-OPERATOR-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub rotations: BTreeMap<String, RotationEpoch>,
    pub members: BTreeMap<String, CommitteeMember>,
    pub shards: BTreeMap<String, CommitteeShard>,
    pub envelopes: BTreeMap<String, MlKemEnvelopeCommitment>,
    pub attestations: BTreeMap<String, RecoveryQuorumAttestation>,
    pub sponsor_bonds: BTreeMap<String, SponsorBond>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub fee_credit_refunds: BTreeMap<String, FeeCreditRefund>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub active_rotation_id: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            rotations: BTreeMap::new(),
            members: BTreeMap::new(),
            shards: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsor_bonds: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            fee_credit_refunds: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            active_rotation_id: None,
        }
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            rotation_root: map_root(
                "ML-KEM-RECOVERY-ROTATIONS",
                self.rotations
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            member_root: map_root(
                "ML-KEM-RECOVERY-MEMBERS",
                self.members
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            shard_root: map_root(
                "ML-KEM-RECOVERY-SHARDS",
                self.shards
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            envelope_root: map_root(
                "ML-KEM-RECOVERY-ENVELOPES",
                self.envelopes
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            attestation_root: map_root(
                "ML-KEM-RECOVERY-ATTESTATIONS",
                self.attestations
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            bond_root: map_root(
                "ML-KEM-RECOVERY-BONDS",
                self.sponsor_bonds
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            slashing_root: map_root(
                "ML-KEM-RECOVERY-SLASHING",
                self.slashing_evidence
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            refund_root: map_root(
                "ML-KEM-RECOVERY-REFUNDS",
                self.fee_credit_refunds
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            privacy_budget_root: map_root(
                "ML-KEM-RECOVERY-PRIVACY-BUDGETS",
                self.redaction_budgets
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            operator_summary_root: map_root(
                "ML-KEM-RECOVERY-OPERATOR-SUMMARIES",
                self.operator_summaries
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
        }
    }

    pub fn open_rotation(&mut self, rotation: RotationEpoch) -> Result<()> {
        ensure!(
            self.rotations.len() < usize::MAX,
            "rotation table capacity exhausted"
        );
        ensure!(
            !self.rotations.contains_key(&rotation.rotation_id),
            "rotation already exists: {}",
            rotation.rotation_id
        );
        self.active_rotation_id = Some(rotation.rotation_id.clone());
        self.counters.rotations_opened += 1;
        self.rotations
            .insert(rotation.rotation_id.clone(), rotation);
        Ok(())
    }

    pub fn register_member(&mut self, mut member: CommitteeMember) -> Result<()> {
        ensure!(
            self.members.len() < self.config.max_committee_members,
            "committee member capacity exhausted"
        );
        ensure!(
            !self.members.contains_key(&member.member_id),
            "member already exists: {}",
            member.member_id
        );
        member.activate();
        self.counters.members_registered += 1;
        self.upsert_operator_summary_for_member(&member);
        self.members.insert(member.member_id.clone(), member);
        Ok(())
    }

    pub fn commit_shard(&mut self, shard: CommitteeShard) -> Result<()> {
        ensure!(
            self.shards.len() < self.config.max_shards,
            "shard capacity exhausted"
        );
        ensure!(
            self.rotations.contains_key(&shard.rotation_id),
            "unknown rotation for shard {}",
            shard.rotation_id
        );
        ensure!(
            self.members.contains_key(&shard.holder_member_id),
            "unknown shard holder {}",
            shard.holder_member_id
        );
        ensure!(
            !self.shards.contains_key(&shard.shard_id),
            "shard already exists: {}",
            shard.shard_id
        );
        self.counters.shards_committed += 1;
        self.shards.insert(shard.shard_id.clone(), shard);
        self.refresh_rotation_roots();
        Ok(())
    }

    pub fn commit_envelope(&mut self, envelope: MlKemEnvelopeCommitment) -> Result<()> {
        ensure!(
            self.envelopes.len() < self.config.max_envelopes,
            "envelope capacity exhausted"
        );
        ensure!(
            !self.envelopes.contains_key(&envelope.envelope_id),
            "envelope already exists: {}",
            envelope.envelope_id
        );
        let rotation = self
            .rotations
            .get(&envelope.rotation_id)
            .ok_or_else(|| format!("unknown rotation {}", envelope.rotation_id))?;
        ensure!(
            rotation.status.accepts_envelopes(),
            "rotation does not accept envelopes"
        );
        ensure!(
            self.shards.contains_key(&envelope.shard_id),
            "unknown shard {}",
            envelope.shard_id
        );
        ensure!(
            self.members.contains_key(&envelope.recipient_member_id),
            "unknown recipient member {}",
            envelope.recipient_member_id
        );
        if let Some(sponsor_id) = &envelope.sponsor_id {
            ensure!(
                self.sponsor_bonds
                    .values()
                    .any(|bond| &bond.sponsor_id == sponsor_id && bond.status == BondStatus::Locked),
                "sponsor has no locked bond: {}",
                sponsor_id
            );
        }
        self.counters.envelopes_committed += 1;
        self.bump_operator_envelope(&envelope.recipient_member_id);
        self.envelopes
            .insert(envelope.envelope_id.clone(), envelope);
        self.refresh_rotation_roots();
        Ok(())
    }

    pub fn accept_attestation(&mut self, attestation: RecoveryQuorumAttestation) -> Result<()> {
        ensure!(
            self.attestations.len() < self.config.max_attestations,
            "attestation capacity exhausted"
        );
        ensure!(
            !self.attestations.contains_key(&attestation.attestation_id),
            "attestation already exists: {}",
            attestation.attestation_id
        );
        ensure!(
            self.rotations.contains_key(&attestation.rotation_id),
            "unknown rotation {}",
            attestation.rotation_id
        );
        ensure!(
            self.members.contains_key(&attestation.signer_member_id),
            "unknown signer {}",
            attestation.signer_member_id
        );
        if let Some(envelope_id) = &attestation.envelope_id {
            ensure!(
                self.envelopes.contains_key(envelope_id),
                "unknown attested envelope {}",
                envelope_id
            );
        }
        self.counters.attestations_accepted += 1;
        self.bump_operator_attestation(&attestation.signer_member_id);
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_rotation_roots();
        Ok(())
    }

    pub fn lock_sponsor_bond(&mut self, bond: SponsorBond) -> Result<()> {
        ensure!(
            self.sponsor_bonds.len() < self.config.max_bonds,
            "sponsor bond capacity exhausted"
        );
        ensure!(
            !self.sponsor_bonds.contains_key(&bond.bond_id),
            "bond already exists: {}",
            bond.bond_id
        );
        self.counters.sponsor_bonds_locked += 1;
        self.upsert_operator_summary_for_bond(&bond);
        self.sponsor_bonds.insert(bond.bond_id.clone(), bond);
        self.refresh_rotation_roots();
        Ok(())
    }

    pub fn accept_slashing_evidence(&mut self, mut evidence: SlashingEvidence) -> Result<()> {
        ensure!(
            self.slashing_evidence.len() < self.config.max_slashing_evidence,
            "slashing evidence capacity exhausted"
        );
        ensure!(
            !self.slashing_evidence.contains_key(&evidence.evidence_id),
            "evidence already exists: {}",
            evidence.evidence_id
        );
        let accused = self
            .members
            .get_mut(&evidence.accused_member_id)
            .ok_or_else(|| format!("unknown accused member {}", evidence.accused_member_id))?;
        ensure!(
            accused.status.slashable(),
            "accused member is not slashable"
        );
        accused.status = MemberStatus::Slashed;
        let bond_id = accused.bond_id.clone();
        let slashed = if let Some(bond) = self.sponsor_bonds.get_mut(&bond_id) {
            let amount = bond.locked_micro_units.saturating_mul(evidence.slash_bps) / MAX_BPS;
            evidence.applied_bond_id = Some(bond.bond_id.clone());
            bond.slash(amount)
        } else {
            0
        };
        evidence.reward_from_slash(slashed);
        self.counters.slashing_evidence_accepted += 1;
        self.counters.rotations_slashed += 1;
        self.bump_operator_slash(&accused.operator_id);
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        self.refresh_operator_summaries();
        self.refresh_rotation_roots();
        Ok(())
    }

    pub fn credit_refund(&mut self, refund: FeeCreditRefund) -> Result<()> {
        ensure!(
            self.fee_credit_refunds.len() < self.config.max_refunds,
            "refund capacity exhausted"
        );
        ensure!(
            !self.fee_credit_refunds.contains_key(&refund.refund_id),
            "refund already exists: {}",
            refund.refund_id
        );
        self.counters.refunds_credited += 1;
        if let Some(sponsor_id) = &refund.sponsor_id {
            self.bump_sponsor_refund(sponsor_id, refund.credit_micro_units);
        }
        self.fee_credit_refunds
            .insert(refund.refund_id.clone(), refund);
        Ok(())
    }

    pub fn open_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<()> {
        ensure!(
            !self.redaction_budgets.contains_key(&budget.budget_id),
            "redaction budget already exists: {}",
            budget.budget_id
        );
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_operator_summaries();
        Ok(())
    }

    pub fn spend_redaction(&mut self, budget_id: &str, field: impl Into<String>) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("unknown redaction budget {}", budget_id))?;
        budget.spend(field)?;
        self.counters.privacy_redactions_spent += 1;
        self.refresh_operator_summaries();
        Ok(())
    }

    pub fn activate_rotation(&mut self, rotation_id: &str, l2_height: u64) -> Result<()> {
        let quorum_weight = self.rotation_quorum_weight_bps(rotation_id);
        let rotation = self
            .rotations
            .get_mut(rotation_id)
            .ok_or_else(|| format!("unknown rotation {}", rotation_id))?;
        ensure!(
            rotation.ready_for_activation(l2_height, quorum_weight),
            "rotation not ready for activation"
        );
        rotation.status = RotationStatus::Activated;
        self.active_rotation_id = Some(rotation_id.to_string());
        self.counters.rotations_activated += 1;
        self.refresh_rotation_roots();
        Ok(())
    }

    pub fn rotation_quorum_weight_bps(&self, rotation_id: &str) -> u64 {
        let signers: BTreeSet<&str> = self
            .attestations
            .values()
            .filter(|attestation| {
                attestation.rotation_id == rotation_id
                    && attestation.kind == AttestationKind::RotationActivation
                    && attestation.accepted
            })
            .map(|attestation| attestation.signer_member_id.as_str())
            .collect();
        signers
            .into_iter()
            .filter_map(|member_id| self.members.get(member_id))
            .map(CommitteeMember::effective_weight_bps)
            .sum::<u64>()
            .min(MAX_BPS)
    }

    fn refresh_rotation_roots(&mut self) {
        let shard_root = map_root(
            "ML-KEM-RECOVERY-SHARDS",
            self.shards
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        let attestation_root = map_root(
            "ML-KEM-RECOVERY-ATTESTATIONS",
            self.attestations
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        let bond_root = map_root(
            "ML-KEM-RECOVERY-BONDS",
            self.sponsor_bonds
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        let member_root = map_root(
            "ML-KEM-RECOVERY-MEMBERS",
            self.members
                .iter()
                .map(|(id, item)| (id.as_str(), item.state_root())),
        );
        for rotation in self.rotations.values_mut() {
            rotation.shard_manifest_root = shard_root.clone();
            rotation.attestation_root = attestation_root.clone();
            rotation.sponsor_bond_root = bond_root.clone();
            rotation.inbound_committee_root = member_root.clone();
        }
    }

    fn upsert_operator_summary_for_member(&mut self, member: &CommitteeMember) {
        let summary = self
            .operator_summaries
            .entry(member.operator_id.clone())
            .or_insert_with(|| OperatorSummary {
                operator_id: member.operator_id.clone(),
                visibility_root: deterministic_commitment(&member.operator_id, 71, 32),
                ..OperatorSummary::default()
            });
        if member.status.can_vote() {
            summary.active_members += 1;
            summary.active_weight_bps = summary
                .active_weight_bps
                .saturating_add(member.effective_weight_bps());
        }
        summary.latest_rotation_id = self.active_rotation_id.clone();
    }

    fn upsert_operator_summary_for_bond(&mut self, bond: &SponsorBond) {
        let summary = self
            .operator_summaries
            .entry(bond.operator_id.clone())
            .or_insert_with(|| OperatorSummary {
                operator_id: bond.operator_id.clone(),
                visibility_root: deterministic_commitment(&bond.operator_id, 72, 32),
                ..OperatorSummary::default()
            });
        summary.bonds_locked_micro_units = summary
            .bonds_locked_micro_units
            .saturating_add(bond.locked_micro_units);
        summary.latest_rotation_id = bond.rotation_id.clone().or(self.active_rotation_id.clone());
    }

    fn bump_operator_envelope(&mut self, member_id: &str) {
        if let Some(member) = self.members.get(member_id) {
            if let Some(summary) = self.operator_summaries.get_mut(&member.operator_id) {
                summary.envelopes_served += 1;
            }
        }
    }

    fn bump_operator_attestation(&mut self, member_id: &str) {
        if let Some(member) = self.members.get(member_id) {
            if let Some(summary) = self.operator_summaries.get_mut(&member.operator_id) {
                summary.attestations_signed += 1;
            }
        }
    }

    fn bump_operator_slash(&mut self, operator_id: &str) {
        if let Some(summary) = self.operator_summaries.get_mut(operator_id) {
            summary.slash_count += 1;
        }
    }

    fn bump_sponsor_refund(&mut self, sponsor_id: &str, amount: u64) {
        let operator_id = self
            .sponsor_bonds
            .values()
            .find(|bond| bond.sponsor_id == sponsor_id)
            .map(|bond| bond.operator_id.clone());
        if let Some(operator_id) = operator_id {
            if let Some(summary) = self.operator_summaries.get_mut(&operator_id) {
                summary.refunds_sponsored_micro_units =
                    summary.refunds_sponsored_micro_units.saturating_add(amount);
            }
        }
    }

    fn refresh_operator_summaries(&mut self) {
        let mut summaries = BTreeMap::<String, OperatorSummary>::new();
        for member in self.members.values() {
            let summary = summaries
                .entry(member.operator_id.clone())
                .or_insert_with(|| OperatorSummary {
                    operator_id: member.operator_id.clone(),
                    visibility_root: deterministic_commitment(&member.operator_id, 73, 32),
                    ..OperatorSummary::default()
                });
            if member.status.can_vote() {
                summary.active_members += 1;
                summary.active_weight_bps = summary
                    .active_weight_bps
                    .saturating_add(member.effective_weight_bps());
            }
            if member.status == MemberStatus::Slashed {
                summary.slash_count += 1;
            }
        }
        for envelope in self.envelopes.values() {
            if let Some(member) = self.members.get(&envelope.recipient_member_id) {
                if let Some(summary) = summaries.get_mut(&member.operator_id) {
                    summary.envelopes_served += 1;
                }
            }
        }
        for attestation in self.attestations.values() {
            if let Some(member) = self.members.get(&attestation.signer_member_id) {
                if let Some(summary) = summaries.get_mut(&member.operator_id) {
                    summary.attestations_signed += 1;
                }
            }
        }
        for bond in self.sponsor_bonds.values() {
            let summary = summaries
                .entry(bond.operator_id.clone())
                .or_insert_with(|| OperatorSummary {
                    operator_id: bond.operator_id.clone(),
                    visibility_root: deterministic_commitment(&bond.operator_id, 74, 32),
                    ..OperatorSummary::default()
                });
            summary.bonds_locked_micro_units = summary
                .bonds_locked_micro_units
                .saturating_add(bond.remaining_micro_units);
        }
        for refund in self.fee_credit_refunds.values() {
            if let Some(sponsor_id) = &refund.sponsor_id {
                if let Some(bond) = self
                    .sponsor_bonds
                    .values()
                    .find(|bond| &bond.sponsor_id == sponsor_id)
                {
                    if let Some(summary) = summaries.get_mut(&bond.operator_id) {
                        summary.refunds_sponsored_micro_units = summary
                            .refunds_sponsored_micro_units
                            .saturating_add(refund.credit_micro_units);
                    }
                }
            }
        }
        for budget in self.redaction_budgets.values() {
            let summary = summaries
                .entry(budget.operator_id.clone())
                .or_insert_with(|| OperatorSummary {
                    operator_id: budget.operator_id.clone(),
                    visibility_root: deterministic_commitment(&budget.operator_id, 75, 32),
                    ..OperatorSummary::default()
                });
            summary.redactions_remaining = summary
                .redactions_remaining
                .saturating_add(budget.remaining());
        }
        for summary in summaries.values_mut() {
            summary.latest_rotation_id = self.active_rotation_id.clone();
        }
        self.operator_summaries = summaries;
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let mut state = State::new(config.clone()).expect("valid devnet config");
    let rotation = RotationEpoch::new(
        "rot-devnet-mlkem-0001",
        None,
        DEVNET_EPOCH,
        DEVNET_L2_HEIGHT,
        DEVNET_MONERO_HEIGHT,
        RotationReason::PrivacySetRefresh,
        6,
        4,
        2,
        &config,
    )
    .expect("valid devnet rotation");
    state.open_rotation(rotation).expect("open devnet rotation");

    for index in 0..6 {
        let role = match index {
            0 | 1 | 2 => CommitteeRole::RecoveryCustodian,
            3 => CommitteeRole::ShardAssembler,
            4 => CommitteeRole::PrivacyAuditor,
            _ => CommitteeRole::Watchtower,
        };
        let bond = SponsorBond::new(
            format!("bond-devnet-{:02}", index),
            format!("sponsor-devnet-{:02}", index),
            format!("operator-devnet-{:02}", index / 2),
            Some("rot-devnet-mlkem-0001".to_string()),
            config.operator_bond_micro_units,
            config.low_fee_target_bps,
            DEVNET_L2_HEIGHT,
            &config,
        )
        .expect("valid devnet bond");
        state.lock_sponsor_bond(bond).expect("lock devnet bond");
        let member = CommitteeMember::new(
            format!("member-devnet-{:02}", index),
            format!("operator-devnet-{:02}", index / 2),
            role,
            if index < 4 { 2_000 } else { 1_000 },
            format!("bond-devnet-{:02}", index),
            DEVNET_L2_HEIGHT,
            &config,
        )
        .expect("valid devnet member");
        state
            .register_member(member)
            .expect("register devnet member");
    }

    for index in 0..12 {
        let holder = format!("member-devnet-{:02}", index % 6);
        let shard = CommitteeShard::new(
            format!("shard-devnet-{:02}", index),
            "rot-devnet-mlkem-0001",
            holder.clone(),
            if index % 5 == 0 {
                ShardClass::DecoyOnly
            } else {
                ShardClass::SpendRecovery
            },
            index,
            4,
            12,
            config.target_privacy_set_size + (index as u64 * 4096),
            DEVNET_L2_HEIGHT + 2,
            &config,
        )
        .expect("valid devnet shard");
        state.commit_shard(shard).expect("commit devnet shard");
        let envelope = MlKemEnvelopeCommitment::new(
            format!("env-devnet-{:02}", index),
            "rot-devnet-mlkem-0001",
            format!("shard-devnet-{:02}", index),
            holder,
            config.low_fee_target_bps + (index as u64 % 3),
            Some(format!("sponsor-devnet-{:02}", index % 6)),
            DEVNET_L2_HEIGHT + 3,
            &config,
        )
        .expect("valid devnet envelope");
        let refund = FeeCreditRefund::for_envelope(
            format!("refund-devnet-{:02}", index),
            &envelope,
            10_000 + index as u64 * 100,
            DEVNET_L2_HEIGHT + 4,
            &config,
        )
        .expect("valid devnet refund");
        state
            .commit_envelope(envelope)
            .expect("commit devnet envelope");
        state.credit_refund(refund).expect("credit devnet refund");
    }

    for index in 0..6 {
        let member = state
            .members
            .get(&format!("member-devnet-{:02}", index))
            .cloned()
            .expect("member exists");
        let attestation = RecoveryQuorumAttestation::new(
            format!("att-devnet-activation-{:02}", index),
            "rot-devnet-mlkem-0001",
            None,
            AttestationKind::RotationActivation,
            &member,
            DEVNET_L2_HEIGHT + config.epoch_length_blocks,
            &config,
        )
        .expect("valid devnet attestation");
        state
            .accept_attestation(attestation)
            .expect("accept devnet attestation");
    }

    for operator_index in 0..3 {
        let budget = PrivacyRedactionBudget::new(
            format!("budget-devnet-{:02}", operator_index),
            format!("operator-devnet-{:02}", operator_index),
            "rot-devnet-mlkem-0001",
            DEVNET_EPOCH,
            DEVNET_L2_HEIGHT,
            &config,
        )
        .expect("valid devnet privacy budget");
        state
            .open_redaction_budget(budget)
            .expect("open devnet budget");
    }

    let evidence = SlashingEvidence::new(
        "evidence-devnet-late-shard-00",
        "rot-devnet-mlkem-0001",
        "member-devnet-05",
        "watchtower-devnet-00",
        SlashingReason::LateActivation,
        DEVNET_L2_HEIGHT + 18,
        &config,
    )
    .expect("valid devnet evidence");
    state
        .accept_slashing_evidence(evidence)
        .expect("accept devnet evidence");
    state.refresh_operator_summaries();
    state.refresh_rotation_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.spend_redaction("budget-devnet-00", "service_endpoint_commitment");
    let _ = state.spend_redaction("budget-devnet-01", "jurisdiction_tag_commitment");
    state
}

pub fn public_record(state: &State) -> Value {
    let roots = state.roots();
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "ml_kem_suite": ML_KEM_SUITE,
        "pq_signature_suite": PQ_SIGNATURE_SUITE,
        "shard_commitment_suite": SHARD_COMMITMENT_SUITE,
        "sponsor_bond_suite": SPONSOR_BOND_SUITE,
        "privacy_budget_suite": PRIVACY_BUDGET_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": roots.public_record(),
        "state_root": roots.state_root(),
        "active_rotation_id": state.active_rotation_id,
        "rotations": state
            .rotations
            .iter()
            .map(|(id, rotation)| (id, rotation.public_record()))
            .collect::<BTreeMap<_, _>>(),
        "members": state
            .members
            .iter()
            .map(|(id, member)| (id, member.public_record()))
            .collect::<BTreeMap<_, _>>(),
        "shards": state
            .shards
            .iter()
            .map(|(id, shard)| (id, shard.public_record()))
            .collect::<BTreeMap<_, _>>(),
        "envelopes": state
            .envelopes
            .iter()
            .map(|(id, envelope)| (id, envelope.public_record()))
            .collect::<BTreeMap<_, _>>(),
        "attestations": state
            .attestations
            .iter()
            .map(|(id, attestation)| (id, attestation.public_record()))
            .collect::<BTreeMap<_, _>>(),
        "sponsor_bonds": state
            .sponsor_bonds
            .iter()
            .map(|(id, bond)| (id, bond.public_record()))
            .collect::<BTreeMap<_, _>>(),
        "slashing_evidence": state
            .slashing_evidence
            .iter()
            .map(|(id, evidence)| (id, evidence.public_record()))
            .collect::<BTreeMap<_, _>>(),
        "fee_credit_refunds": state
            .fee_credit_refunds
            .iter()
            .map(|(id, refund)| (id, refund.public_record()))
            .collect::<BTreeMap<_, _>>(),
        "redaction_budgets": state
            .redaction_budgets
            .iter()
            .map(|(id, budget)| (id, budget.public_record()))
            .collect::<BTreeMap<_, _>>(),
        "operator_summaries": state
            .operator_summaries
            .iter()
            .map(|(id, summary)| (id, summary.public_record()))
            .collect::<BTreeMap<_, _>>(),
    })
}

pub fn state_root(state: &State) -> String {
    runtime_root("ML-KEM-RECOVERY-RUNTIME-STATE", &public_record(state))
}

fn runtime_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Json(value),
        ],
        32,
    )
}

fn map_root<'a>(domain: &str, items: impl Iterator<Item = (&'a str, String)>) -> String {
    let leaves = items
        .map(|(id, root)| {
            Value::String(domain_hash(
                domain,
                &[HashPart::Str(id), HashPart::Str(root.as_str())],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, leaves.as_slice())
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn deterministic_commitment(label: &str, nonce: u64, bytes: usize) -> String {
    domain_hash(
        "ML-KEM-RECOVERY-DETERMINISTIC-COMMITMENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        bytes,
    )
}
