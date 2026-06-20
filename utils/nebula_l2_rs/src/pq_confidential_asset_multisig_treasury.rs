use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqConfidentialAssetMultisigTreasuryResult<T> = Result<T, String>;

pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_PROTOCOL_VERSION: &str =
    "nebula-pq-confidential-asset-multisig-treasury-v1";
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_SCHEMA_VERSION: u64 = 1;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_PQ_SIGNATURE_SUITE: &str =
    "ml-dsa-87-slh-dsa-shake-256f-hybrid-treasury-v1";
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_COMMITMENT_SUITE: &str =
    "confidential-asset-pedersen-compatible-devnet-v1";
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_AUDIT_DISCLOSURE_SUITE: &str =
    "selective-disclosure-viewkey-audit-v1";
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEVNET_HEIGHT: u64 = 6_144;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_TIMELOCK_BLOCKS: u64 = 144;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_ROTATION_NOTICE_BLOCKS: u64 = 1_440;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_SPONSOR_RESERVE_UNITS: u128 =
    50_000_000_000;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_MAX_FEE_BPS: u64 = 75;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_THRESHOLD_BPS: u64 = 6_700;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_BPS: u64 = 10_000;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_VAULTS: usize = 16_384;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_COMMITTEES: usize = 1_024;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_GUARDIANS: usize = 16_384;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_COMMITMENTS: usize = 1_048_576;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_PROPOSALS: usize = 524_288;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_AUTHORIZATIONS: usize = 2_097_152;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_TIMELOCKS: usize = 524_288;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_SPONSOR_RESERVES: usize = 262_144;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_ROTATIONS: usize = 262_144;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_DISCLOSURES: usize = 524_288;
pub const PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_EVENTS: usize = 1_048_576;

pub type VaultId = String;
pub type CommitteeId = String;
pub type GuardianId = String;
pub type CommitmentId = String;
pub type ProposalId = String;
pub type AuthorizationId = String;
pub type TimelockId = String;
pub type SponsorReserveId = String;
pub type RotationId = String;
pub type DisclosureId = String;
pub type EventId = String;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Active,
    Frozen,
    RotationPending,
    EmergencyOnly,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::RotationPending => "rotation_pending",
            Self::EmergencyOnly => "emergency_only",
            Self::Retired => "retired",
        }
    }

    pub fn allows_spend(self) -> bool {
        matches!(self, Self::Active | Self::RotationPending)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Active,
    Rotating,
    Paused,
    Emergency,
    Retired,
    Slashed,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Emergency => "emergency",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn counts_for_threshold(self) -> bool {
        matches!(self, Self::Active | Self::Rotating | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardianStatus {
    Active,
    Standby,
    Suspect,
    RotatingOut,
    Retired,
    Slashed,
}

impl GuardianStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Suspect => "suspect",
            Self::RotatingOut => "rotating_out",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_authorize(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::RotatingOut)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Unspent,
    Reserved,
    Spent,
    Frozen,
    Disclosed,
    Burned,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspent => "unspent",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Frozen => "frozen",
            Self::Disclosed => "disclosed",
            Self::Burned => "burned",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    TreasurySpend,
    SponsorFeeTopUp,
    AuditDisclosure,
    VaultRebalance,
    EmergencyFreeze,
    GuardianRotation,
    PolicyUpdate,
}

impl ProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TreasurySpend => "treasury_spend",
            Self::SponsorFeeTopUp => "sponsor_fee_top_up",
            Self::AuditDisclosure => "audit_disclosure",
            Self::VaultRebalance => "vault_rebalance",
            Self::EmergencyFreeze => "emergency_freeze",
            Self::GuardianRotation => "guardian_rotation",
            Self::PolicyUpdate => "policy_update",
        }
    }

    pub fn emergency(self) -> bool {
        matches!(self, Self::EmergencyFreeze | Self::GuardianRotation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Draft,
    Open,
    ThresholdMet,
    Timelocked,
    Executable,
    Executed,
    Cancelled,
    Expired,
    Challenged,
    Rejected,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::ThresholdMet => "threshold_met",
            Self::Timelocked => "timelocked",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::ThresholdMet | Self::Timelocked | Self::Executable
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Pending,
    Counted,
    Superseded,
    Revoked,
    Expired,
    Slashed,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Counted => "counted",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn counts(self) -> bool {
        matches!(self, Self::Pending | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelockStatus {
    Pending,
    ChallengeOpen,
    Matured,
    Released,
    Cancelled,
    Expired,
}

impl TimelockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ChallengeOpen => "challenge_open",
            Self::Matured => "matured",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReserveStatus {
    Active,
    Reserved,
    Depleted,
    Frozen,
    Retired,
}

impl SponsorReserveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Depleted => "depleted",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Announced,
    CollectingApprovals,
    Timelocked,
    Executed,
    Cancelled,
    EmergencyExecuted,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::CollectingApprovals => "collecting_approvals",
            Self::Timelocked => "timelocked",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::EmergencyExecuted => "emergency_executed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Requested,
    Granted,
    Viewed,
    Revoked,
    Expired,
}

impl DisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Granted => "granted",
            Self::Viewed => "viewed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub commitment_suite: String,
    pub audit_disclosure_suite: String,
    pub default_epoch_blocks: u64,
    pub default_timelock_blocks: u64,
    pub default_challenge_window_blocks: u64,
    pub default_rotation_notice_blocks: u64,
    pub default_min_privacy_set_size: u64,
    pub default_sponsor_reserve_units: u128,
    pub default_max_fee_bps: u64,
    pub default_threshold_bps: u64,
    pub emergency_pause_enabled: bool,
    pub private_amounts_required: bool,
    pub audit_disclosures_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_SCHEMA_VERSION,
            hash_suite: PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_HASH_SUITE.to_string(),
            pq_signature_suite: PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_PQ_SIGNATURE_SUITE
                .to_string(),
            commitment_suite: PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_COMMITMENT_SUITE.to_string(),
            audit_disclosure_suite: PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_AUDIT_DISCLOSURE_SUITE
                .to_string(),
            default_epoch_blocks: PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_EPOCH_BLOCKS,
            default_timelock_blocks:
                PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_TIMELOCK_BLOCKS,
            default_challenge_window_blocks:
                PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            default_rotation_notice_blocks:
                PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_ROTATION_NOTICE_BLOCKS,
            default_min_privacy_set_size:
                PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_MIN_PRIVACY_SET_SIZE,
            default_sponsor_reserve_units:
                PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_SPONSOR_RESERVE_UNITS,
            default_max_fee_bps: PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_MAX_FEE_BPS,
            default_threshold_bps: PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_THRESHOLD_BPS,
            emergency_pause_enabled: true,
            private_amounts_required: true,
            audit_disclosures_enabled: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> PqConfidentialAssetMultisigTreasuryResult<()> {
        if self.protocol_version != PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.schema_version != PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_SCHEMA_VERSION {
            return Err("schema version mismatch".to_string());
        }
        if self.default_epoch_blocks == 0 {
            return Err("default epoch blocks must be non-zero".to_string());
        }
        if self.default_timelock_blocks == 0 {
            return Err("default timelock blocks must be non-zero".to_string());
        }
        if self.default_challenge_window_blocks == 0 {
            return Err("default challenge window blocks must be non-zero".to_string());
        }
        if self.default_rotation_notice_blocks < self.default_timelock_blocks {
            return Err("rotation notice must cover the default timelock".to_string());
        }
        if self.default_threshold_bps == 0
            || self.default_threshold_bps > PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_BPS
        {
            return Err("default threshold bps out of range".to_string());
        }
        if self.default_max_fee_bps > PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_BPS {
            return Err("default max fee bps out of range".to_string());
        }
        if self.default_min_privacy_set_size == 0 {
            return Err("default minimum privacy set size must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_signature_suite": self.pq_signature_suite,
            "commitment_suite": self.commitment_suite,
            "audit_disclosure_suite": self.audit_disclosure_suite,
            "default_epoch_blocks": self.default_epoch_blocks,
            "default_timelock_blocks": self.default_timelock_blocks,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "default_rotation_notice_blocks": self.default_rotation_notice_blocks,
            "default_min_privacy_set_size": self.default_min_privacy_set_size,
            "default_sponsor_reserve_units": self.default_sponsor_reserve_units.to_string(),
            "default_max_fee_bps": self.default_max_fee_bps,
            "default_threshold_bps": self.default_threshold_bps,
            "emergency_pause_enabled": self.emergency_pause_enabled,
            "private_amounts_required": self.private_amounts_required,
            "audit_disclosures_enabled": self.audit_disclosures_enabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTreasuryVault {
    pub vault_id: VaultId,
    pub label_commitment: String,
    pub asset_id: String,
    pub committee_id: CommitteeId,
    pub status: VaultStatus,
    pub asset_commitment_root: String,
    pub nullifier_root: String,
    pub policy_root: String,
    pub sponsor_reserve_id: SponsorReserveId,
    pub min_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub last_activity_height: u64,
}

impl ShieldedTreasuryVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "label_commitment": self.label_commitment,
            "asset_id": self.asset_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "asset_commitment_root": self.asset_commitment_root,
            "nullifier_root": self.nullifier_root,
            "policy_root": self.policy_root,
            "sponsor_reserve_id": self.sponsor_reserve_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "last_activity_height": self.last_activity_height,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-VAULT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGuardianCommittee {
    pub committee_id: CommitteeId,
    pub epoch: u64,
    pub status: CommitteeStatus,
    pub guardian_ids: BTreeSet<GuardianId>,
    pub threshold_bps: u64,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub pq_key_root: String,
    pub emergency_key_root: String,
    pub rotation_nonce: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl PqGuardianCommittee {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "guardian_ids": self.guardian_ids.iter().cloned().collect::<Vec<_>>(),
            "threshold_bps": self.threshold_bps,
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "pq_key_root": self.pq_key_root,
            "emergency_key_root": self.emergency_key_root,
            "rotation_nonce": self.rotation_nonce,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-COMMITTEE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGuardian {
    pub guardian_id: GuardianId,
    pub operator_commitment: String,
    pub committee_id: CommitteeId,
    pub status: GuardianStatus,
    pub signing_weight: u64,
    pub ml_dsa_public_key_commitment: String,
    pub slh_dsa_public_key_commitment: String,
    pub attestation_root: String,
    pub recovery_share_commitment: String,
    pub joined_at_height: u64,
    pub last_heartbeat_height: u64,
}

impl PqGuardian {
    pub fn public_record(&self) -> Value {
        json!({
            "guardian_id": self.guardian_id,
            "operator_commitment": self.operator_commitment,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "signing_weight": self.signing_weight,
            "ml_dsa_public_key_commitment": self.ml_dsa_public_key_commitment,
            "slh_dsa_public_key_commitment": self.slh_dsa_public_key_commitment,
            "attestation_root": self.attestation_root,
            "recovery_share_commitment": self.recovery_share_commitment,
            "joined_at_height": self.joined_at_height,
            "last_heartbeat_height": self.last_heartbeat_height,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-GUARDIAN", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAssetCommitment {
    pub commitment_id: CommitmentId,
    pub vault_id: VaultId,
    pub asset_id: String,
    pub amount_commitment: String,
    pub blinding_commitment: String,
    pub owner_commitment: String,
    pub note_ciphertext_hash: String,
    pub nullifier_hash: String,
    pub status: CommitmentStatus,
    pub created_at_height: u64,
    pub reserved_by_proposal_id: Option<ProposalId>,
}

impl PrivateAssetCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "vault_id": self.vault_id,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "blinding_commitment": self.blinding_commitment,
            "owner_commitment": self.owner_commitment,
            "note_ciphertext_hash": self.note_ciphertext_hash,
            "nullifier_hash": self.nullifier_hash,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "reserved_by_proposal_id": self.reserved_by_proposal_id,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-ASSET-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSpendProposal {
    pub proposal_id: ProposalId,
    pub vault_id: VaultId,
    pub committee_id: CommitteeId,
    pub kind: ProposalKind,
    pub status: ProposalStatus,
    pub input_commitment_ids: BTreeSet<CommitmentId>,
    pub output_commitment_root: String,
    pub recipient_commitment_root: String,
    pub amount_bucket: u64,
    pub fee_budget_units: u128,
    pub sponsor_reserve_id: SponsorReserveId,
    pub threshold_weight_collected: u64,
    pub threshold_weight_required: u64,
    pub authorization_root: String,
    pub timelock_id: Option<TimelockId>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ThresholdSpendProposal {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "vault_id": self.vault_id,
            "committee_id": self.committee_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "input_commitment_ids": self.input_commitment_ids.iter().cloned().collect::<Vec<_>>(),
            "output_commitment_root": self.output_commitment_root,
            "recipient_commitment_root": self.recipient_commitment_root,
            "amount_bucket": self.amount_bucket,
            "fee_budget_units": self.fee_budget_units.to_string(),
            "sponsor_reserve_id": self.sponsor_reserve_id,
            "threshold_weight_collected": self.threshold_weight_collected,
            "threshold_weight_required": self.threshold_weight_required,
            "authorization_root": self.authorization_root,
            "timelock_id": self.timelock_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-SPEND-PROPOSAL", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardianAuthorization {
    pub authorization_id: AuthorizationId,
    pub proposal_id: ProposalId,
    pub guardian_id: GuardianId,
    pub committee_id: CommitteeId,
    pub status: AuthorizationStatus,
    pub signing_weight: u64,
    pub pq_signature_commitment: String,
    pub signed_payload_root: String,
    pub nullifier_hash: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl GuardianAuthorization {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "proposal_id": self.proposal_id,
            "guardian_id": self.guardian_id,
            "committee_id": self.committee_id,
            "status": self.status.as_str(),
            "signing_weight": self.signing_weight,
            "pq_signature_commitment": self.pq_signature_commitment,
            "signed_payload_root": self.signed_payload_root,
            "nullifier_hash": self.nullifier_hash,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-AUTHORIZATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendTimelock {
    pub timelock_id: TimelockId,
    pub proposal_id: ProposalId,
    pub vault_id: VaultId,
    pub status: TimelockStatus,
    pub opened_at_height: u64,
    pub earliest_execution_height: u64,
    pub challenge_deadline_height: u64,
    pub challenge_root: String,
    pub release_receipt_root: String,
}

impl SpendTimelock {
    pub fn public_record(&self) -> Value {
        json!({
            "timelock_id": self.timelock_id,
            "proposal_id": self.proposal_id,
            "vault_id": self.vault_id,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "earliest_execution_height": self.earliest_execution_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "challenge_root": self.challenge_root,
            "release_receipt_root": self.release_receipt_root,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-TIMELOCK", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorReserve {
    pub sponsor_reserve_id: SponsorReserveId,
    pub vault_id: VaultId,
    pub asset_id: String,
    pub status: SponsorReserveStatus,
    pub reserve_commitment: String,
    pub available_units: u128,
    pub reserved_units: u128,
    pub spent_units: u128,
    pub max_fee_bps: u64,
    pub low_fee_floor_units: u64,
    pub last_replenished_height: u64,
}

impl FeeSponsorReserve {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_reserve_id": self.sponsor_reserve_id,
            "vault_id": self.vault_id,
            "asset_id": self.asset_id,
            "status": self.status.as_str(),
            "reserve_commitment": self.reserve_commitment,
            "available_units": self.available_units.to_string(),
            "reserved_units": self.reserved_units.to_string(),
            "spent_units": self.spent_units.to_string(),
            "max_fee_bps": self.max_fee_bps,
            "low_fee_floor_units": self.low_fee_floor_units,
            "last_replenished_height": self.last_replenished_height,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-SPONSOR-RESERVE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyRotation {
    pub rotation_id: RotationId,
    pub vault_id: VaultId,
    pub old_committee_id: CommitteeId,
    pub new_committee_id: CommitteeId,
    pub status: RotationStatus,
    pub reason_root: String,
    pub outgoing_guardian_root: String,
    pub incoming_guardian_root: String,
    pub approval_root: String,
    pub announced_at_height: u64,
    pub executable_at_height: u64,
    pub executed_at_height: Option<u64>,
}

impl EmergencyRotation {
    pub fn public_record(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "vault_id": self.vault_id,
            "old_committee_id": self.old_committee_id,
            "new_committee_id": self.new_committee_id,
            "status": self.status.as_str(),
            "reason_root": self.reason_root,
            "outgoing_guardian_root": self.outgoing_guardian_root,
            "incoming_guardian_root": self.incoming_guardian_root,
            "approval_root": self.approval_root,
            "announced_at_height": self.announced_at_height,
            "executable_at_height": self.executable_at_height,
            "executed_at_height": self.executed_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-EMERGENCY-ROTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditDisclosure {
    pub disclosure_id: DisclosureId,
    pub vault_id: VaultId,
    pub auditor_commitment: String,
    pub status: DisclosureStatus,
    pub scope_root: String,
    pub view_key_commitment: String,
    pub redaction_policy_root: String,
    pub revealed_commitment_root: String,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
}

impl AuditDisclosure {
    pub fn public_record(&self) -> Value {
        json!({
            "disclosure_id": self.disclosure_id,
            "vault_id": self.vault_id,
            "auditor_commitment": self.auditor_commitment,
            "status": self.status.as_str(),
            "scope_root": self.scope_root,
            "view_key_commitment": self.view_key_commitment,
            "redaction_policy_root": self.redaction_policy_root,
            "revealed_commitment_root": self.revealed_commitment_root,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-AUDIT-DISCLOSURE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryEvent {
    pub event_id: EventId,
    pub kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl TreasuryEvent {
    pub fn new(kind: &str, subject_id: &str, subject: &Value, height: u64, sequence: u64) -> Self {
        let subject_root = treasury_payload_root("PQ-CAMT-EVENT-SUBJECT", subject);
        let event_id = treasury_id(
            "PQ-CAMT-EVENT-ID",
            &[
                kind,
                subject_id,
                &subject_root,
                &height.to_string(),
                &sequence.to_string(),
            ],
        );
        Self {
            event_id,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            emitted_at_height: height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub committee_root: String,
    pub guardian_root: String,
    pub asset_commitment_root: String,
    pub proposal_root: String,
    pub authorization_root: String,
    pub timelock_root: String,
    pub sponsor_reserve_root: String,
    pub emergency_rotation_root: String,
    pub audit_disclosure_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "vault_root": self.vault_root,
            "committee_root": self.committee_root,
            "guardian_root": self.guardian_root,
            "asset_commitment_root": self.asset_commitment_root,
            "proposal_root": self.proposal_root,
            "authorization_root": self.authorization_root,
            "timelock_root": self.timelock_root,
            "sponsor_reserve_root": self.sponsor_reserve_root,
            "emergency_rotation_root": self.emergency_rotation_root,
            "audit_disclosure_root": self.audit_disclosure_root,
            "event_root": self.event_root,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub vaults: u64,
    pub active_vaults: u64,
    pub committees: u64,
    pub active_committees: u64,
    pub guardians: u64,
    pub active_guardians: u64,
    pub asset_commitments: u64,
    pub unspent_commitments: u64,
    pub proposals: u64,
    pub active_proposals: u64,
    pub authorizations: u64,
    pub counted_authorizations: u64,
    pub timelocks: u64,
    pub matured_timelocks: u64,
    pub sponsor_reserves: u64,
    pub rotations: u64,
    pub audit_disclosures: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "vaults": self.vaults,
            "active_vaults": self.active_vaults,
            "committees": self.committees,
            "active_committees": self.active_committees,
            "guardians": self.guardians,
            "active_guardians": self.active_guardians,
            "asset_commitments": self.asset_commitments,
            "unspent_commitments": self.unspent_commitments,
            "proposals": self.proposals,
            "active_proposals": self.active_proposals,
            "authorizations": self.authorizations,
            "counted_authorizations": self.counted_authorizations,
            "timelocks": self.timelocks,
            "matured_timelocks": self.matured_timelocks,
            "sponsor_reserves": self.sponsor_reserves,
            "rotations": self.rotations,
            "audit_disclosures": self.audit_disclosures,
            "events": self.events,
        })
    }

    pub fn record_root(&self) -> String {
        treasury_payload_root("PQ-CAMT-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub vaults: BTreeMap<VaultId, ShieldedTreasuryVault>,
    pub committees: BTreeMap<CommitteeId, PqGuardianCommittee>,
    pub guardians: BTreeMap<GuardianId, PqGuardian>,
    pub asset_commitments: BTreeMap<CommitmentId, PrivateAssetCommitment>,
    pub proposals: BTreeMap<ProposalId, ThresholdSpendProposal>,
    pub authorizations: BTreeMap<AuthorizationId, GuardianAuthorization>,
    pub timelocks: BTreeMap<TimelockId, SpendTimelock>,
    pub sponsor_reserves: BTreeMap<SponsorReserveId, FeeSponsorReserve>,
    pub emergency_rotations: BTreeMap<RotationId, EmergencyRotation>,
    pub audit_disclosures: BTreeMap<DisclosureId, AuditDisclosure>,
    pub events: BTreeMap<EventId, TreasuryEvent>,
}

impl State {
    pub fn devnet() -> PqConfidentialAssetMultisigTreasuryResult<Self> {
        let config = Config::default();
        config.validate()?;
        let height = PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEVNET_HEIGHT;

        let primary_committee_id = treasury_id("PQ-CAMT-COMMITTEE-ID", &["primary", "0"]);
        let emergency_committee_id = treasury_id("PQ-CAMT-COMMITTEE-ID", &["emergency", "0"]);
        let primary_vault_id = treasury_id("PQ-CAMT-VAULT-ID", &["operations", "asset:wxmr"]);
        let grants_vault_id = treasury_id("PQ-CAMT-VAULT-ID", &["grants", "asset:nebula"]);
        let primary_sponsor_id = treasury_id("PQ-CAMT-SPONSOR-ID", &[&primary_vault_id]);
        let grants_sponsor_id = treasury_id("PQ-CAMT-SPONSOR-ID", &[&grants_vault_id]);

        let mut guardians = BTreeMap::new();
        let mut primary_guardian_ids = BTreeSet::new();
        let mut emergency_guardian_ids = BTreeSet::new();
        for index in 0..7_u64 {
            let guardian_id = treasury_id(
                "PQ-CAMT-GUARDIAN-ID",
                &["primary", &index.to_string(), &primary_committee_id],
            );
            primary_guardian_ids.insert(guardian_id.clone());
            guardians.insert(
                guardian_id.clone(),
                devnet_guardian(&guardian_id, &primary_committee_id, index, height),
            );
        }
        for index in 0..5_u64 {
            let guardian_id = treasury_id(
                "PQ-CAMT-GUARDIAN-ID",
                &["emergency", &index.to_string(), &emergency_committee_id],
            );
            emergency_guardian_ids.insert(guardian_id.clone());
            let mut guardian =
                devnet_guardian(&guardian_id, &emergency_committee_id, index, height);
            guardian.signing_weight = 2;
            guardians.insert(guardian_id, guardian);
        }

        let primary_weight = guardian_weight(&guardians, &primary_guardian_ids);
        let emergency_weight = guardian_weight(&guardians, &emergency_guardian_ids);
        let mut committees = BTreeMap::new();
        committees.insert(
            primary_committee_id.clone(),
            PqGuardianCommittee {
                committee_id: primary_committee_id.clone(),
                epoch: height / config.default_epoch_blocks,
                status: CommitteeStatus::Active,
                guardian_ids: primary_guardian_ids,
                threshold_bps: config.default_threshold_bps,
                threshold_weight: threshold_weight(primary_weight, config.default_threshold_bps),
                total_weight: primary_weight,
                pq_key_root: devnet_root("primary-committee-pq-key-root"),
                emergency_key_root: devnet_root("primary-committee-emergency-key-root"),
                rotation_nonce: 0,
                activated_at_height: height - config.default_epoch_blocks,
                expires_at_height: height + config.default_epoch_blocks,
            },
        );
        committees.insert(
            emergency_committee_id.clone(),
            PqGuardianCommittee {
                committee_id: emergency_committee_id.clone(),
                epoch: height / config.default_epoch_blocks,
                status: CommitteeStatus::Emergency,
                guardian_ids: emergency_guardian_ids,
                threshold_bps: 8_000,
                threshold_weight: threshold_weight(emergency_weight, 8_000),
                total_weight: emergency_weight,
                pq_key_root: devnet_root("emergency-committee-pq-key-root"),
                emergency_key_root: devnet_root("emergency-committee-break-glass-key-root"),
                rotation_nonce: 0,
                activated_at_height: height - 2 * config.default_epoch_blocks,
                expires_at_height: height + 4 * config.default_epoch_blocks,
            },
        );

        let mut sponsor_reserves = BTreeMap::new();
        sponsor_reserves.insert(
            primary_sponsor_id.clone(),
            devnet_sponsor_reserve(
                &primary_sponsor_id,
                &primary_vault_id,
                "asset:wxmr",
                config.default_sponsor_reserve_units,
                config.default_max_fee_bps,
                height,
            ),
        );
        sponsor_reserves.insert(
            grants_sponsor_id.clone(),
            devnet_sponsor_reserve(
                &grants_sponsor_id,
                &grants_vault_id,
                "asset:nebula",
                config.default_sponsor_reserve_units / 2,
                config.default_max_fee_bps,
                height,
            ),
        );

        let mut vaults = BTreeMap::new();
        vaults.insert(
            primary_vault_id.clone(),
            ShieldedTreasuryVault {
                vault_id: primary_vault_id.clone(),
                label_commitment: treasury_id("PQ-CAMT-LABEL", &["operations"]),
                asset_id: "asset:wxmr".to_string(),
                committee_id: primary_committee_id.clone(),
                status: VaultStatus::Active,
                asset_commitment_root: devnet_root("operations-asset-commitments"),
                nullifier_root: devnet_root("operations-nullifiers"),
                policy_root: devnet_root("operations-policy"),
                sponsor_reserve_id: primary_sponsor_id.clone(),
                min_privacy_set_size: config.default_min_privacy_set_size,
                max_fee_bps: config.default_max_fee_bps,
                opened_at_height: height - 2_048,
                last_activity_height: height - 4,
            },
        );
        vaults.insert(
            grants_vault_id.clone(),
            ShieldedTreasuryVault {
                vault_id: grants_vault_id.clone(),
                label_commitment: treasury_id("PQ-CAMT-LABEL", &["grants"]),
                asset_id: "asset:nebula".to_string(),
                committee_id: primary_committee_id.clone(),
                status: VaultStatus::RotationPending,
                asset_commitment_root: devnet_root("grants-asset-commitments"),
                nullifier_root: devnet_root("grants-nullifiers"),
                policy_root: devnet_root("grants-policy"),
                sponsor_reserve_id: grants_sponsor_id.clone(),
                min_privacy_set_size: config.default_min_privacy_set_size,
                max_fee_bps: config.default_max_fee_bps,
                opened_at_height: height - 1_200,
                last_activity_height: height - 12,
            },
        );

        let mut asset_commitments = BTreeMap::new();
        for index in 0..4_u64 {
            let commitment = devnet_asset_commitment(
                &primary_vault_id,
                "asset:wxmr",
                index,
                CommitmentStatus::Unspent,
                height,
                None,
            );
            asset_commitments.insert(commitment.commitment_id.clone(), commitment);
        }

        let proposal_id = treasury_id("PQ-CAMT-PROPOSAL-ID", &[&primary_vault_id, "ops-spend-0"]);
        let timelock_id = treasury_id("PQ-CAMT-TIMELOCK-ID", &[&proposal_id]);
        let input_commitment_ids = asset_commitments
            .keys()
            .take(2)
            .cloned()
            .collect::<BTreeSet<_>>();
        let proposal = ThresholdSpendProposal {
            proposal_id: proposal_id.clone(),
            vault_id: primary_vault_id.clone(),
            committee_id: primary_committee_id.clone(),
            kind: ProposalKind::TreasurySpend,
            status: ProposalStatus::Timelocked,
            input_commitment_ids,
            output_commitment_root: devnet_root("ops-spend-output-commitments"),
            recipient_commitment_root: devnet_root("ops-spend-recipients"),
            amount_bucket: 10_000,
            fee_budget_units: 250_000,
            sponsor_reserve_id: primary_sponsor_id.clone(),
            threshold_weight_collected: 5,
            threshold_weight_required: 5,
            authorization_root: devnet_root("ops-spend-authorizations"),
            timelock_id: Some(timelock_id.clone()),
            opened_at_height: height - 32,
            expires_at_height: height + config.default_epoch_blocks,
        };
        let mut proposals = BTreeMap::new();
        proposals.insert(proposal_id.clone(), proposal.clone());

        let mut authorizations = BTreeMap::new();
        let authorization_guardians = if let Some(committee) = committees.get(&primary_committee_id)
        {
            committee
                .guardian_ids
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for (index, guardian_id) in authorization_guardians.into_iter().enumerate() {
            let authorization = devnet_authorization(
                &proposal_id,
                &primary_committee_id,
                &guardian_id,
                index as u64,
                height,
            );
            authorizations.insert(authorization.authorization_id.clone(), authorization);
        }

        let mut timelocks = BTreeMap::new();
        timelocks.insert(
            timelock_id.clone(),
            SpendTimelock {
                timelock_id: timelock_id.clone(),
                proposal_id: proposal_id.clone(),
                vault_id: primary_vault_id.clone(),
                status: TimelockStatus::ChallengeOpen,
                opened_at_height: height - 8,
                earliest_execution_height: height + config.default_timelock_blocks,
                challenge_deadline_height: height + config.default_challenge_window_blocks,
                challenge_root: devnet_root("ops-spend-challenge-empty"),
                release_receipt_root: devnet_root("ops-spend-release-pending"),
            },
        );

        let rotation_id = treasury_id("PQ-CAMT-ROTATION-ID", &[&grants_vault_id, "planned"]);
        let mut emergency_rotations = BTreeMap::new();
        emergency_rotations.insert(
            rotation_id.clone(),
            EmergencyRotation {
                rotation_id,
                vault_id: grants_vault_id.clone(),
                old_committee_id: primary_committee_id.clone(),
                new_committee_id: emergency_committee_id.clone(),
                status: RotationStatus::CollectingApprovals,
                reason_root: devnet_root("grants-rotation-reason"),
                outgoing_guardian_root: devnet_root("grants-rotation-outgoing"),
                incoming_guardian_root: devnet_root("grants-rotation-incoming"),
                approval_root: devnet_root("grants-rotation-approvals"),
                announced_at_height: height - 16,
                executable_at_height: height + config.default_rotation_notice_blocks,
                executed_at_height: None,
            },
        );

        let disclosure_id = treasury_id("PQ-CAMT-DISCLOSURE-ID", &[&primary_vault_id, "audit-0"]);
        let mut audit_disclosures = BTreeMap::new();
        audit_disclosures.insert(
            disclosure_id.clone(),
            AuditDisclosure {
                disclosure_id,
                vault_id: primary_vault_id.clone(),
                auditor_commitment: treasury_id("PQ-CAMT-AUDITOR", &["devnet-auditor"]),
                status: DisclosureStatus::Granted,
                scope_root: devnet_root("audit-scope-ops-quarterly"),
                view_key_commitment: devnet_root("audit-view-key-commitment"),
                redaction_policy_root: devnet_root("audit-redaction-policy"),
                revealed_commitment_root: devnet_root("audit-revealed-commitments"),
                requested_at_height: height - 64,
                expires_at_height: height + 2 * config.default_epoch_blocks,
            },
        );

        let mut state = Self {
            height,
            config,
            vaults,
            committees,
            guardians,
            asset_commitments,
            proposals,
            authorizations,
            timelocks,
            sponsor_reserves,
            emergency_rotations,
            audit_disclosures,
            events: BTreeMap::new(),
        };
        state.rebuild_events();
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PqConfidentialAssetMultisigTreasuryResult<()> {
        self.config.validate()?;
        enforce_len(
            "vaults",
            self.vaults.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_VAULTS,
        )?;
        enforce_len(
            "committees",
            self.committees.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_COMMITTEES,
        )?;
        enforce_len(
            "guardians",
            self.guardians.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_GUARDIANS,
        )?;
        enforce_len(
            "asset commitments",
            self.asset_commitments.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_COMMITMENTS,
        )?;
        enforce_len(
            "proposals",
            self.proposals.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_PROPOSALS,
        )?;
        enforce_len(
            "authorizations",
            self.authorizations.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_AUTHORIZATIONS,
        )?;
        enforce_len(
            "timelocks",
            self.timelocks.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_TIMELOCKS,
        )?;
        enforce_len(
            "sponsor reserves",
            self.sponsor_reserves.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_SPONSOR_RESERVES,
        )?;
        enforce_len(
            "emergency rotations",
            self.emergency_rotations.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_ROTATIONS,
        )?;
        enforce_len(
            "audit disclosures",
            self.audit_disclosures.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_DISCLOSURES,
        )?;
        enforce_len(
            "events",
            self.events.len(),
            PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_EVENTS,
        )?;

        for (vault_id, vault) in &self.vaults {
            if vault_id != &vault.vault_id {
                return Err(format!("vault key mismatch for {vault_id}"));
            }
            if !self.committees.contains_key(&vault.committee_id) {
                return Err(format!("vault {vault_id} references missing committee"));
            }
            if !self
                .sponsor_reserves
                .contains_key(&vault.sponsor_reserve_id)
            {
                return Err(format!(
                    "vault {vault_id} references missing sponsor reserve"
                ));
            }
            if vault.max_fee_bps > PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_BPS {
                return Err(format!("vault {vault_id} fee bps out of range"));
            }
            if vault.min_privacy_set_size == 0 {
                return Err(format!("vault {vault_id} privacy set is empty"));
            }
        }

        for (committee_id, committee) in &self.committees {
            if committee_id != &committee.committee_id {
                return Err(format!("committee key mismatch for {committee_id}"));
            }
            if committee.threshold_bps == 0
                || committee.threshold_bps > PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_BPS
            {
                return Err(format!(
                    "committee {committee_id} threshold bps out of range"
                ));
            }
            let observed_weight = guardian_weight(&self.guardians, &committee.guardian_ids);
            if observed_weight != committee.total_weight {
                return Err(format!("committee {committee_id} total weight mismatch"));
            }
            if committee.threshold_weight == 0
                || committee.threshold_weight > committee.total_weight
            {
                return Err(format!(
                    "committee {committee_id} threshold weight out of range"
                ));
            }
            for guardian_id in &committee.guardian_ids {
                let guardian = self.guardians.get(guardian_id).ok_or_else(|| {
                    format!("committee {committee_id} references missing guardian")
                })?;
                if guardian.committee_id != *committee_id {
                    return Err(format!("guardian {guardian_id} committee mismatch"));
                }
            }
        }

        for (guardian_id, guardian) in &self.guardians {
            if guardian_id != &guardian.guardian_id {
                return Err(format!("guardian key mismatch for {guardian_id}"));
            }
            if guardian.signing_weight == 0 {
                return Err(format!("guardian {guardian_id} has zero signing weight"));
            }
            if !self.committees.contains_key(&guardian.committee_id) {
                return Err(format!(
                    "guardian {guardian_id} references missing committee"
                ));
            }
        }

        for (commitment_id, commitment) in &self.asset_commitments {
            if commitment_id != &commitment.commitment_id {
                return Err(format!("asset commitment key mismatch for {commitment_id}"));
            }
            if !self.vaults.contains_key(&commitment.vault_id) {
                return Err(format!(
                    "asset commitment {commitment_id} references missing vault"
                ));
            }
            if let Some(proposal_id) = &commitment.reserved_by_proposal_id {
                if !self.proposals.contains_key(proposal_id) {
                    return Err(format!(
                        "asset commitment {commitment_id} references missing proposal"
                    ));
                }
            }
        }

        for (proposal_id, proposal) in &self.proposals {
            if proposal_id != &proposal.proposal_id {
                return Err(format!("proposal key mismatch for {proposal_id}"));
            }
            let vault = self
                .vaults
                .get(&proposal.vault_id)
                .ok_or_else(|| format!("proposal {proposal_id} references missing vault"))?;
            if !vault.status.allows_spend() && !proposal.kind.emergency() {
                return Err(format!(
                    "proposal {proposal_id} cannot spend from vault state"
                ));
            }
            let committee = self
                .committees
                .get(&proposal.committee_id)
                .ok_or_else(|| format!("proposal {proposal_id} references missing committee"))?;
            if !committee.status.counts_for_threshold() {
                return Err(format!(
                    "proposal {proposal_id} references inactive committee"
                ));
            }
            if proposal.threshold_weight_required == 0
                || proposal.threshold_weight_required > committee.total_weight
            {
                return Err(format!(
                    "proposal {proposal_id} threshold requirement out of range"
                ));
            }
            if proposal.threshold_weight_collected > committee.total_weight {
                return Err(format!(
                    "proposal {proposal_id} collected too much threshold weight"
                ));
            }
            if !self
                .sponsor_reserves
                .contains_key(&proposal.sponsor_reserve_id)
            {
                return Err(format!(
                    "proposal {proposal_id} references missing sponsor reserve"
                ));
            }
            for commitment_id in &proposal.input_commitment_ids {
                if !self.asset_commitments.contains_key(commitment_id) {
                    return Err(format!(
                        "proposal {proposal_id} references missing input commitment"
                    ));
                }
            }
            if let Some(timelock_id) = &proposal.timelock_id {
                if !self.timelocks.contains_key(timelock_id) {
                    return Err(format!(
                        "proposal {proposal_id} references missing timelock"
                    ));
                }
            }
        }

        for (authorization_id, authorization) in &self.authorizations {
            if authorization_id != &authorization.authorization_id {
                return Err(format!("authorization key mismatch for {authorization_id}"));
            }
            if !self.proposals.contains_key(&authorization.proposal_id) {
                return Err(format!(
                    "authorization {authorization_id} references missing proposal"
                ));
            }
            let guardian = self
                .guardians
                .get(&authorization.guardian_id)
                .ok_or_else(|| {
                    format!("authorization {authorization_id} references missing guardian")
                })?;
            if !guardian.status.can_authorize() {
                return Err(format!(
                    "authorization {authorization_id} signer cannot authorize"
                ));
            }
            if authorization.committee_id != guardian.committee_id {
                return Err(format!(
                    "authorization {authorization_id} committee mismatch"
                ));
            }
            if authorization.signing_weight != guardian.signing_weight {
                return Err(format!("authorization {authorization_id} weight mismatch"));
            }
        }

        for (timelock_id, timelock) in &self.timelocks {
            if timelock_id != &timelock.timelock_id {
                return Err(format!("timelock key mismatch for {timelock_id}"));
            }
            if !self.proposals.contains_key(&timelock.proposal_id) {
                return Err(format!(
                    "timelock {timelock_id} references missing proposal"
                ));
            }
            if !self.vaults.contains_key(&timelock.vault_id) {
                return Err(format!("timelock {timelock_id} references missing vault"));
            }
            if timelock.earliest_execution_height < timelock.opened_at_height {
                return Err(format!("timelock {timelock_id} execution precedes opening"));
            }
            if timelock.challenge_deadline_height < timelock.earliest_execution_height {
                return Err(format!(
                    "timelock {timelock_id} challenge precedes execution"
                ));
            }
        }

        for (reserve_id, reserve) in &self.sponsor_reserves {
            if reserve_id != &reserve.sponsor_reserve_id {
                return Err(format!("sponsor reserve key mismatch for {reserve_id}"));
            }
            if reserve.max_fee_bps > PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_BPS {
                return Err(format!("sponsor reserve {reserve_id} fee bps out of range"));
            }
            if reserve.available_units + reserve.reserved_units < reserve.spent_units {
                return Err(format!("sponsor reserve {reserve_id} accounting underflow"));
            }
        }

        for (rotation_id, rotation) in &self.emergency_rotations {
            if rotation_id != &rotation.rotation_id {
                return Err(format!("rotation key mismatch for {rotation_id}"));
            }
            if !self.vaults.contains_key(&rotation.vault_id) {
                return Err(format!("rotation {rotation_id} references missing vault"));
            }
            if !self.committees.contains_key(&rotation.old_committee_id)
                || !self.committees.contains_key(&rotation.new_committee_id)
            {
                return Err(format!(
                    "rotation {rotation_id} references missing committee"
                ));
            }
            if rotation.executable_at_height < rotation.announced_at_height {
                return Err(format!(
                    "rotation {rotation_id} executable height precedes announcement"
                ));
            }
        }

        for (disclosure_id, disclosure) in &self.audit_disclosures {
            if disclosure_id != &disclosure.disclosure_id {
                return Err(format!("audit disclosure key mismatch for {disclosure_id}"));
            }
            if !self.vaults.contains_key(&disclosure.vault_id) {
                return Err(format!(
                    "audit disclosure {disclosure_id} references missing vault"
                ));
            }
            if disclosure.expires_at_height <= disclosure.requested_at_height {
                return Err(format!(
                    "audit disclosure {disclosure_id} expiry is invalid"
                ));
            }
        }

        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PqConfidentialAssetMultisigTreasuryResult<()> {
        if height < self.height {
            return Err("height cannot decrease".to_string());
        }
        self.height = height;
        self.refresh_height_sensitive_statuses();
        self.validate()
    }

    pub fn update_height(&mut self, delta: u64) -> PqConfidentialAssetMultisigTreasuryResult<()> {
        let next = self
            .height
            .checked_add(delta)
            .ok_or_else(|| "height update overflow".to_string())?;
        self.set_height(next)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: treasury_payload_root("PQ-CAMT-CONFIG", &self.config.public_record()),
            vault_root: map_root("PQ-CAMT-VAULT-ROOT", &self.vaults, |vault| {
                vault.public_record()
            }),
            committee_root: map_root("PQ-CAMT-COMMITTEE-ROOT", &self.committees, |committee| {
                committee.public_record()
            }),
            guardian_root: map_root("PQ-CAMT-GUARDIAN-ROOT", &self.guardians, |guardian| {
                guardian.public_record()
            }),
            asset_commitment_root: map_root(
                "PQ-CAMT-ASSET-COMMITMENT-ROOT",
                &self.asset_commitments,
                |commitment| commitment.public_record(),
            ),
            proposal_root: map_root("PQ-CAMT-PROPOSAL-ROOT", &self.proposals, |proposal| {
                proposal.public_record()
            }),
            authorization_root: map_root(
                "PQ-CAMT-AUTHORIZATION-ROOT",
                &self.authorizations,
                |authorization| authorization.public_record(),
            ),
            timelock_root: map_root("PQ-CAMT-TIMELOCK-ROOT", &self.timelocks, |timelock| {
                timelock.public_record()
            }),
            sponsor_reserve_root: map_root(
                "PQ-CAMT-SPONSOR-RESERVE-ROOT",
                &self.sponsor_reserves,
                |reserve| reserve.public_record(),
            ),
            emergency_rotation_root: map_root(
                "PQ-CAMT-EMERGENCY-ROTATION-ROOT",
                &self.emergency_rotations,
                |rotation| rotation.public_record(),
            ),
            audit_disclosure_root: map_root(
                "PQ-CAMT-AUDIT-DISCLOSURE-ROOT",
                &self.audit_disclosures,
                |disclosure| disclosure.public_record(),
            ),
            event_root: map_root("PQ-CAMT-EVENT-ROOT", &self.events, |event| {
                event.public_record()
            }),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            vaults: self.vaults.len() as u64,
            active_vaults: self
                .vaults
                .values()
                .filter(|vault| vault.status.allows_spend())
                .count() as u64,
            committees: self.committees.len() as u64,
            active_committees: self
                .committees
                .values()
                .filter(|committee| committee.status.counts_for_threshold())
                .count() as u64,
            guardians: self.guardians.len() as u64,
            active_guardians: self
                .guardians
                .values()
                .filter(|guardian| guardian.status.can_authorize())
                .count() as u64,
            asset_commitments: self.asset_commitments.len() as u64,
            unspent_commitments: self
                .asset_commitments
                .values()
                .filter(|commitment| commitment.status == CommitmentStatus::Unspent)
                .count() as u64,
            proposals: self.proposals.len() as u64,
            active_proposals: self
                .proposals
                .values()
                .filter(|proposal| proposal.status.active())
                .count() as u64,
            authorizations: self.authorizations.len() as u64,
            counted_authorizations: self
                .authorizations
                .values()
                .filter(|authorization| authorization.status.counts())
                .count() as u64,
            timelocks: self.timelocks.len() as u64,
            matured_timelocks: self
                .timelocks
                .values()
                .filter(|timelock| timelock.status == TimelockStatus::Matured)
                .count() as u64,
            sponsor_reserves: self.sponsor_reserves.len() as u64,
            rotations: self.emergency_rotations.len() as u64,
            audit_disclosures: self.audit_disclosures.len() as u64,
            events: self.events.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "height": self.height,
            "protocol_version": PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root_schema": "pq_confidential_asset_multisig_treasury_state_v1",
        })
    }

    pub fn insert_vault(
        &mut self,
        vault: ShieldedTreasuryVault,
    ) -> PqConfidentialAssetMultisigTreasuryResult<()> {
        if self.vaults.contains_key(&vault.vault_id) {
            return Err(format!("vault {} already exists", vault.vault_id));
        }
        let event = TreasuryEvent::new(
            "vault_inserted",
            &vault.vault_id,
            &vault.public_record(),
            self.height,
            self.events.len() as u64,
        );
        self.vaults.insert(vault.vault_id.clone(), vault);
        self.events.insert(event.event_id.clone(), event);
        self.validate()
    }

    pub fn insert_asset_commitment(
        &mut self,
        commitment: PrivateAssetCommitment,
    ) -> PqConfidentialAssetMultisigTreasuryResult<()> {
        if self
            .asset_commitments
            .contains_key(&commitment.commitment_id)
        {
            return Err(format!(
                "asset commitment {} already exists",
                commitment.commitment_id
            ));
        }
        let event = TreasuryEvent::new(
            "asset_commitment_inserted",
            &commitment.commitment_id,
            &commitment.public_record(),
            self.height,
            self.events.len() as u64,
        );
        self.asset_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        self.events.insert(event.event_id.clone(), event);
        self.validate()
    }

    pub fn insert_proposal(
        &mut self,
        proposal: ThresholdSpendProposal,
    ) -> PqConfidentialAssetMultisigTreasuryResult<()> {
        if self.proposals.contains_key(&proposal.proposal_id) {
            return Err(format!("proposal {} already exists", proposal.proposal_id));
        }
        let event = TreasuryEvent::new(
            "proposal_inserted",
            &proposal.proposal_id,
            &proposal.public_record(),
            self.height,
            self.events.len() as u64,
        );
        self.proposals
            .insert(proposal.proposal_id.clone(), proposal);
        self.events.insert(event.event_id.clone(), event);
        self.validate()
    }

    fn refresh_height_sensitive_statuses(&mut self) {
        for proposal in self.proposals.values_mut() {
            if proposal.status.active() && self.height > proposal.expires_at_height {
                proposal.status = ProposalStatus::Expired;
            }
        }
        for timelock in self.timelocks.values_mut() {
            if timelock.status == TimelockStatus::ChallengeOpen
                && self.height >= timelock.earliest_execution_height
            {
                timelock.status = TimelockStatus::Matured;
            }
            if matches!(
                timelock.status,
                TimelockStatus::Pending | TimelockStatus::ChallengeOpen
            ) && self.height > timelock.challenge_deadline_height
            {
                timelock.status = TimelockStatus::Expired;
            }
        }
        for disclosure in self.audit_disclosures.values_mut() {
            if matches!(
                disclosure.status,
                DisclosureStatus::Requested | DisclosureStatus::Granted
            ) && self.height > disclosure.expires_at_height
            {
                disclosure.status = DisclosureStatus::Expired;
            }
        }
    }

    fn rebuild_events(&mut self) {
        self.events.clear();
        let mut sequence = 0_u64;
        for vault in self.vaults.values() {
            let event = TreasuryEvent::new(
                "devnet_vault",
                &vault.vault_id,
                &vault.public_record(),
                self.height,
                sequence,
            );
            self.events.insert(event.event_id.clone(), event);
            sequence += 1;
        }
        for committee in self.committees.values() {
            let event = TreasuryEvent::new(
                "devnet_committee",
                &committee.committee_id,
                &committee.public_record(),
                self.height,
                sequence,
            );
            self.events.insert(event.event_id.clone(), event);
            sequence += 1;
        }
        for proposal in self.proposals.values() {
            let event = TreasuryEvent::new(
                "devnet_proposal",
                &proposal.proposal_id,
                &proposal.public_record(),
                self.height,
                sequence,
            );
            self.events.insert(event.event_id.clone(), event);
            sequence += 1;
        }
        for disclosure in self.audit_disclosures.values() {
            let event = TreasuryEvent::new(
                "devnet_audit_disclosure",
                &disclosure.disclosure_id,
                &disclosure.public_record(),
                self.height,
                sequence,
            );
            self.events.insert(event.event_id.clone(), event);
            sequence += 1;
        }
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-CAMT-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> PqConfidentialAssetMultisigTreasuryResult<State> {
    State::devnet()
}

fn devnet_guardian(guardian_id: &str, committee_id: &str, index: u64, height: u64) -> PqGuardian {
    PqGuardian {
        guardian_id: guardian_id.to_string(),
        operator_commitment: treasury_id("PQ-CAMT-OPERATOR", &[committee_id, &index.to_string()]),
        committee_id: committee_id.to_string(),
        status: GuardianStatus::Active,
        signing_weight: 1,
        ml_dsa_public_key_commitment: treasury_id(
            "PQ-CAMT-ML-DSA-PK",
            &[guardian_id, &index.to_string()],
        ),
        slh_dsa_public_key_commitment: treasury_id(
            "PQ-CAMT-SLH-DSA-PK",
            &[guardian_id, &index.to_string()],
        ),
        attestation_root: devnet_root(&format!("guardian-attestation-{index}")),
        recovery_share_commitment: treasury_id("PQ-CAMT-RECOVERY-SHARE", &[guardian_id]),
        joined_at_height: height.saturating_sub(2_000 + index),
        last_heartbeat_height: height.saturating_sub(index),
    }
}

fn devnet_sponsor_reserve(
    sponsor_reserve_id: &str,
    vault_id: &str,
    asset_id: &str,
    units: u128,
    max_fee_bps: u64,
    height: u64,
) -> FeeSponsorReserve {
    FeeSponsorReserve {
        sponsor_reserve_id: sponsor_reserve_id.to_string(),
        vault_id: vault_id.to_string(),
        asset_id: asset_id.to_string(),
        status: SponsorReserveStatus::Active,
        reserve_commitment: treasury_id(
            "PQ-CAMT-SPONSOR-RESERVE-COMMITMENT",
            &[sponsor_reserve_id, vault_id, asset_id],
        ),
        available_units: units,
        reserved_units: units / 10,
        spent_units: units / 100,
        max_fee_bps,
        low_fee_floor_units: 2,
        last_replenished_height: height.saturating_sub(320),
    }
}

fn devnet_asset_commitment(
    vault_id: &str,
    asset_id: &str,
    index: u64,
    status: CommitmentStatus,
    height: u64,
    reserved_by_proposal_id: Option<ProposalId>,
) -> PrivateAssetCommitment {
    let commitment_id = treasury_id(
        "PQ-CAMT-ASSET-COMMITMENT-ID",
        &[vault_id, asset_id, &index.to_string()],
    );
    PrivateAssetCommitment {
        commitment_id: commitment_id.clone(),
        vault_id: vault_id.to_string(),
        asset_id: asset_id.to_string(),
        amount_commitment: treasury_id("PQ-CAMT-AMOUNT-COMMITMENT", &[&commitment_id]),
        blinding_commitment: treasury_id("PQ-CAMT-BLINDING-COMMITMENT", &[&commitment_id]),
        owner_commitment: treasury_id("PQ-CAMT-OWNER-COMMITMENT", &[&commitment_id]),
        note_ciphertext_hash: treasury_id("PQ-CAMT-NOTE-CIPHERTEXT", &[&commitment_id]),
        nullifier_hash: treasury_id("PQ-CAMT-NULLIFIER", &[&commitment_id]),
        status,
        created_at_height: height.saturating_sub(256 + index),
        reserved_by_proposal_id,
    }
}

fn devnet_authorization(
    proposal_id: &str,
    committee_id: &str,
    guardian_id: &str,
    index: u64,
    height: u64,
) -> GuardianAuthorization {
    let authorization_id = treasury_id(
        "PQ-CAMT-AUTHORIZATION-ID",
        &[proposal_id, guardian_id, &index.to_string()],
    );
    GuardianAuthorization {
        authorization_id: authorization_id.clone(),
        proposal_id: proposal_id.to_string(),
        guardian_id: guardian_id.to_string(),
        committee_id: committee_id.to_string(),
        status: AuthorizationStatus::Counted,
        signing_weight: 1,
        pq_signature_commitment: treasury_id("PQ-CAMT-PQ-SIGNATURE", &[&authorization_id]),
        signed_payload_root: treasury_id("PQ-CAMT-SIGNED-PAYLOAD", &[proposal_id]),
        nullifier_hash: treasury_id("PQ-CAMT-AUTH-NULLIFIER", &[&authorization_id]),
        observed_at_height: height.saturating_sub(24 + index),
        expires_at_height: height + PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_DEFAULT_EPOCH_BLOCKS,
    }
}

fn threshold_weight(total_weight: u64, threshold_bps: u64) -> u64 {
    let numerator = total_weight.saturating_mul(threshold_bps);
    let rounded = numerator.saturating_add(PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_BPS - 1)
        / PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_MAX_BPS;
    rounded.max(1)
}

fn guardian_weight(
    guardians: &BTreeMap<GuardianId, PqGuardian>,
    ids: &BTreeSet<GuardianId>,
) -> u64 {
    ids.iter()
        .filter_map(|guardian_id| guardians.get(guardian_id))
        .map(|guardian| guardian.signing_weight)
        .sum()
}

fn treasury_id(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

fn treasury_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn devnet_root(label: &str) -> String {
    domain_hash(
        "PQ-CAMT-DEVNET-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CONFIDENTIAL_ASSET_MULTISIG_TREASURY_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, mut public_record: F) -> String
where
    F: FnMut(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(id, value)| {
            json!({
                "id": id,
                "record": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn enforce_len(
    name: &str,
    observed: usize,
    max: usize,
) -> PqConfidentialAssetMultisigTreasuryResult<()> {
    if observed > max {
        return Err(format!("{name} exceeds maximum records"));
    }
    Ok(())
}
