use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = PrivateL2PqConfidentialViewkeyRecoveryEscrowRotationRuntimeResult<T>;
pub type PrivateL2PqConfidentialViewkeyRecoveryEscrowRotationRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_VIEWKEY_RECOVERY_ESCROW_ROTATION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-viewkey-recovery-escrow-rotation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_VIEWKEY_RECOVERY_ESCROW_ROTATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_VIEWKEY_ESCROW_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-viewkey-escrow-rotation-v1";
pub const RECOVERY_COMMITTEE_SCHEME: &str = "pq-viewkey-recovery-committee-root-v1";
pub const ML_KEM_ESCROW_ENVELOPE_SCHEME: &str = "ml-kem-viewkey-escrow-envelope-root-v1";
pub const ROTATION_WINDOW_SCHEME: &str = "confidential-viewkey-rotation-window-root-v1";
pub const QUORUM_ATTESTATION_SCHEME: &str = "pq-viewkey-quorum-attestation-root-v1";
pub const QUARANTINE_SCHEME: &str = "viewkey-escrow-quarantine-root-v1";
pub const SPONSOR_BOND_SCHEME: &str = "viewkey-recovery-sponsor-bond-root-v1";
pub const FEE_CREDIT_REBATE_SCHEME: &str = "viewkey-recovery-fee-credit-rebate-root-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str = "viewkey-privacy-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "viewkey-operator-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-pq-confidential-viewkey-recovery-escrow-rotation-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 4_020_448;
pub const DEVNET_EPOCH: u64 = 20_081;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_COMMITTEE_SIZE: usize = 9;
pub const DEFAULT_MIN_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MAX_QUORUM_WEIGHT_BPS: u64 = 9_200;
pub const DEFAULT_ROTATION_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 432;
pub const DEFAULT_ENVELOPE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_BRIDGE_HOLD_BLOCKS: u64 = 32;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_REBATE_BPS: u64 = 1_400;
pub const DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS: u64 = 25_000_000;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET: u64 = 32;
pub const DEFAULT_MAX_RECOVERY_COMMITTEES: usize = 65_536;
pub const DEFAULT_MAX_ESCROW_ENVELOPES: usize = 4_194_304;
pub const DEFAULT_MAX_ROTATION_WINDOWS: usize = 1_048_576;
pub const DEFAULT_MAX_QUORUM_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_QUARANTINES: usize = 1_048_576;
pub const DEFAULT_MAX_SPONSOR_BONDS: usize = 262_144;
pub const DEFAULT_MAX_FEE_CREDIT_REBATES: usize = 8_388_608;
pub const DEFAULT_MAX_PRIVACY_BUDGETS: usize = 2_097_152;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const DEFAULT_MAX_PUBLIC_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Forming,
    Active,
    Rotating,
    Throttled,
    Quarantined,
    Retired,
}

impl CommitteeStatus {
    pub fn accepts_envelopes(self) -> bool {
        matches!(self, Self::Active | Self::Rotating | Self::Throttled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Throttled => "throttled",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    Coordinator,
    RecoveryShard,
    BridgeSentinel,
    PrivacyAuditor,
    SponsorGuardian,
    Watchtower,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::RecoveryShard => "recovery_shard",
            Self::BridgeSentinel => "bridge_sentinel",
            Self::PrivacyAuditor => "privacy_auditor",
            Self::SponsorGuardian => "sponsor_guardian",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowEnvelopeStatus {
    Proposed,
    PqSealed,
    CommitteeAccepted,
    WindowBound,
    RecoveryReady,
    Rotated,
    Expired,
    Quarantined,
    Rejected,
}

impl EscrowEnvelopeStatus {
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Proposed
                | Self::PqSealed
                | Self::CommitteeAccepted
                | Self::WindowBound
                | Self::RecoveryReady
        )
    }

    pub fn bridge_safe(self) -> bool {
        matches!(
            self,
            Self::CommitteeAccepted | Self::WindowBound | Self::RecoveryReady | Self::Rotated
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationWindowStatus {
    Scheduled,
    Open,
    Attesting,
    BridgeHold,
    Finalized,
    Expired,
    Quarantined,
}

impl RotationWindowStatus {
    pub fn accepts_attestations(self) -> bool {
        matches!(self, Self::Open | Self::Attesting | Self::BridgeHold)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumVerdict {
    Approved,
    NeedsMoreCommitteeWeight,
    NeedsMorePrivacy,
    BridgeHoldRequired,
    SponsorBondLow,
    DuplicateNullifier,
    Rejected,
}

impl QuorumVerdict {
    pub fn approves_rotation(self) -> bool {
        matches!(self, Self::Approved | Self::BridgeHoldRequired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    LowPqSecurity,
    CommitteeEquivocation,
    BridgeReplayRisk,
    RedactionBudgetExceeded,
    DuplicateNullifier,
    SponsorBondDeficit,
    EmergencyPause,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Funding,
    Active,
    Encumbered,
    Slashed,
    Released,
    Frozen,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    Donated,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Active,
    Exhausted,
    CoolingDown,
    Frozen,
    Retired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_committee_size: usize,
    pub min_quorum_weight_bps: u64,
    pub max_quorum_weight_bps: u64,
    pub rotation_window_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub quarantine_blocks: u64,
    pub envelope_ttl_blocks: u64,
    pub bridge_hold_blocks: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub min_sponsor_bond_micro_units: u64,
    pub privacy_redaction_budget: u64,
    pub max_recovery_committees: usize,
    pub max_escrow_envelopes: usize,
    pub max_rotation_windows: usize,
    pub max_quorum_attestations: usize,
    pub max_quarantines: usize,
    pub max_sponsor_bonds: usize,
    pub max_fee_credit_rebates: usize,
    pub max_privacy_budgets: usize,
    pub max_operator_summaries: usize,
    pub max_public_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_committee_size: DEFAULT_MIN_COMMITTEE_SIZE,
            min_quorum_weight_bps: DEFAULT_MIN_QUORUM_WEIGHT_BPS,
            max_quorum_weight_bps: DEFAULT_MAX_QUORUM_WEIGHT_BPS,
            rotation_window_blocks: DEFAULT_ROTATION_WINDOW_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            envelope_ttl_blocks: DEFAULT_ENVELOPE_TTL_BLOCKS,
            bridge_hold_blocks: DEFAULT_BRIDGE_HOLD_BLOCKS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_sponsor_bond_micro_units: DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS,
            privacy_redaction_budget: DEFAULT_PRIVACY_REDACTION_BUDGET,
            max_recovery_committees: DEFAULT_MAX_RECOVERY_COMMITTEES,
            max_escrow_envelopes: DEFAULT_MAX_ESCROW_ENVELOPES,
            max_rotation_windows: DEFAULT_MAX_ROTATION_WINDOWS,
            max_quorum_attestations: DEFAULT_MAX_QUORUM_ATTESTATIONS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_sponsor_bonds: DEFAULT_MAX_SPONSOR_BONDS,
            max_fee_credit_rebates: DEFAULT_MAX_FEE_CREDIT_REBATES,
            max_privacy_budgets: DEFAULT_MAX_PRIVACY_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_public_events: DEFAULT_MAX_PUBLIC_EVENTS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < 192 {
            return Err("min pq security bits below generated runtime floor".to_string());
        }
        if self.target_pq_security_bits < self.min_pq_security_bits {
            return Err("target pq security bits below minimum".to_string());
        }
        if self.min_privacy_set_size < 16_384 {
            return Err("privacy set too small for confidential view-key recovery".to_string());
        }
        if self.min_committee_size < 3 {
            return Err("committee must contain at least three operators".to_string());
        }
        if self.min_quorum_weight_bps == 0 || self.min_quorum_weight_bps > MAX_BPS {
            return Err("invalid minimum quorum weight bps".to_string());
        }
        if self.max_quorum_weight_bps < self.min_quorum_weight_bps
            || self.max_quorum_weight_bps > MAX_BPS
        {
            return Err("invalid maximum quorum weight bps".to_string());
        }
        if self.max_user_fee_bps > 100 {
            return Err("user fee cap too high for low-fee runtime".to_string());
        }
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("target user fee exceeds max user fee".to_string());
        }
        if self.sponsor_cover_bps > MAX_BPS || self.rebate_bps > MAX_BPS {
            return Err("sponsor or rebate bps exceeds max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_committee_size": self.min_committee_size,
            "min_quorum_weight_bps": self.min_quorum_weight_bps,
            "max_quorum_weight_bps": self.max_quorum_weight_bps,
            "rotation_window_blocks": self.rotation_window_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "quarantine_blocks": self.quarantine_blocks,
            "envelope_ttl_blocks": self.envelope_ttl_blocks,
            "bridge_hold_blocks": self.bridge_hold_blocks,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "min_sponsor_bond_micro_units": self.min_sponsor_bond_micro_units,
            "privacy_redaction_budget": self.privacy_redaction_budget
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub committees_registered: u64,
    pub committee_members_registered: u64,
    pub escrow_envelopes_opened: u64,
    pub escrow_envelopes_pq_sealed: u64,
    pub rotation_windows_opened: u64,
    pub quorum_attestations_recorded: u64,
    pub rotations_finalized: u64,
    pub quarantines_opened: u64,
    pub quarantines_released: u64,
    pub sponsor_bonds_locked: u64,
    pub sponsor_bonds_slashed: u64,
    pub fee_credit_rebates_issued: u64,
    pub fee_credit_rebates_claimed: u64,
    pub privacy_redactions_spent: u64,
    pub bridge_holds_enforced: u64,
    pub operator_summaries_published: u64,
    pub public_events_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "committees_registered": self.committees_registered,
            "committee_members_registered": self.committee_members_registered,
            "escrow_envelopes_opened": self.escrow_envelopes_opened,
            "escrow_envelopes_pq_sealed": self.escrow_envelopes_pq_sealed,
            "rotation_windows_opened": self.rotation_windows_opened,
            "quorum_attestations_recorded": self.quorum_attestations_recorded,
            "rotations_finalized": self.rotations_finalized,
            "quarantines_opened": self.quarantines_opened,
            "quarantines_released": self.quarantines_released,
            "sponsor_bonds_locked": self.sponsor_bonds_locked,
            "sponsor_bonds_slashed": self.sponsor_bonds_slashed,
            "fee_credit_rebates_issued": self.fee_credit_rebates_issued,
            "fee_credit_rebates_claimed": self.fee_credit_rebates_claimed,
            "privacy_redactions_spent": self.privacy_redactions_spent,
            "bridge_holds_enforced": self.bridge_holds_enforced,
            "operator_summaries_published": self.operator_summaries_published,
            "public_events_emitted": self.public_events_emitted
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub committee_root: String,
    pub escrow_envelope_root: String,
    pub rotation_window_root: String,
    pub quorum_attestation_root: String,
    pub quarantine_root: String,
    pub sponsor_bond_root: String,
    pub fee_credit_rebate_root: String,
    pub privacy_redaction_budget_root: String,
    pub operator_summary_root: String,
    pub public_event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_root": self.committee_root,
            "escrow_envelope_root": self.escrow_envelope_root,
            "rotation_window_root": self.rotation_window_root,
            "quorum_attestation_root": self.quorum_attestation_root,
            "quarantine_root": self.quarantine_root,
            "sponsor_bond_root": self.sponsor_bond_root,
            "fee_credit_rebate_root": self.fee_credit_rebate_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "public_event_root": self.public_event_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeMember {
    pub operator_id: String,
    pub role: CommitteeRole,
    pub weight_bps: u64,
    pub pq_attestation_key_commitment: String,
    pub ml_kem_public_key_commitment: String,
    pub watchtower_endpoint_commitment: String,
    pub admitted_height: u64,
    pub active: bool,
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "role": self.role,
            "weight_bps": self.weight_bps,
            "pq_attestation_key_commitment": self.pq_attestation_key_commitment,
            "ml_kem_public_key_commitment": self.ml_kem_public_key_commitment,
            "watchtower_endpoint_commitment": self.watchtower_endpoint_commitment,
            "admitted_height": self.admitted_height,
            "active": self.active
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub status: CommitteeStatus,
    pub threshold_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub sponsor_id: String,
    pub members: Vec<CommitteeMember>,
    pub bridge_guardian_set_commitment: String,
    pub policy_commitment: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl RecoveryCommittee {
    pub fn active_weight_bps(&self) -> u64 {
        self.members
            .iter()
            .filter(|member| member.active)
            .map(|member| member.weight_bps)
            .sum()
    }

    pub fn active_member_count(&self) -> usize {
        self.members.iter().filter(|member| member.active).count()
    }

    pub fn can_recover(&self, config: &Config) -> bool {
        self.status.accepts_envelopes()
            && self.pq_security_bits >= config.min_pq_security_bits
            && self.privacy_set_size >= config.min_privacy_set_size
            && self.active_member_count() >= config.min_committee_size
            && self.active_weight_bps() >= self.threshold_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "status": self.status,
            "threshold_bps": self.threshold_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "sponsor_id": self.sponsor_id,
            "members": self.members.iter().map(CommitteeMember::public_record).collect::<Vec<_>>(),
            "bridge_guardian_set_commitment": self.bridge_guardian_set_commitment,
            "policy_commitment": self.policy_commitment,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MlKemEscrowEnvelope {
    pub envelope_id: String,
    pub account_tag_commitment: String,
    pub viewkey_ciphertext_commitment: String,
    pub ml_kem_ciphertext_commitment: String,
    pub recovery_nullifier: String,
    pub committee_id: String,
    pub window_id: String,
    pub sponsor_id: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fee_micro_units: u64,
    pub status: EscrowEnvelopeStatus,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl MlKemEscrowEnvelope {
    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "account_tag_commitment": self.account_tag_commitment,
            "viewkey_ciphertext_commitment": self.viewkey_ciphertext_commitment,
            "ml_kem_ciphertext_commitment": self.ml_kem_ciphertext_commitment,
            "recovery_nullifier": self.recovery_nullifier,
            "committee_id": self.committee_id,
            "window_id": self.window_id,
            "sponsor_id": self.sponsor_id,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "fee_micro_units": self.fee_micro_units,
            "status": self.status,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationWindow {
    pub window_id: String,
    pub committee_id: String,
    pub epoch: u64,
    pub start_height: u64,
    pub close_height: u64,
    pub bridge_release_height: u64,
    pub min_privacy_set_size: u64,
    pub min_quorum_weight_bps: u64,
    pub status: RotationWindowStatus,
    pub envelope_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
}

impl RotationWindow {
    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.close_height
    }

    pub fn bridge_hold_elapsed(&self, height: u64) -> bool {
        height >= self.bridge_release_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "start_height": self.start_height,
            "close_height": self.close_height,
            "bridge_release_height": self.bridge_release_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_quorum_weight_bps": self.min_quorum_weight_bps,
            "status": self.status,
            "envelope_ids": self.envelope_ids.iter().cloned().collect::<Vec<_>>(),
            "attestation_ids": self.attestation_ids.iter().cloned().collect::<Vec<_>>()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuorumAttestation {
    pub attestation_id: String,
    pub envelope_id: String,
    pub window_id: String,
    pub committee_id: String,
    pub signer_operator_ids: BTreeSet<String>,
    pub aggregate_weight_bps: u64,
    pub verdict: QuorumVerdict,
    pub proof_commitment: String,
    pub bridge_replay_guard: String,
    pub redaction_receipt_id: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl QuorumAttestation {
    pub fn is_live(&self, height: u64) -> bool {
        height <= self.expires_height && self.verdict.approves_rotation()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "envelope_id": self.envelope_id,
            "window_id": self.window_id,
            "committee_id": self.committee_id,
            "signer_operator_ids": self.signer_operator_ids.iter().cloned().collect::<Vec<_>>(),
            "aggregate_weight_bps": self.aggregate_weight_bps,
            "verdict": self.verdict,
            "proof_commitment": self.proof_commitment,
            "bridge_replay_guard": self.bridge_replay_guard,
            "redaction_receipt_id": self.redaction_receipt_id,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub target_id: String,
    pub reason: QuarantineReason,
    pub opened_height: u64,
    pub release_height: u64,
    pub evidence_commitment: String,
    pub bridge_freeze: bool,
    pub released: bool,
}

impl QuarantineRecord {
    pub fn releasable(&self, height: u64) -> bool {
        !self.released && height >= self.release_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "target_id": self.target_id,
            "reason": self.reason,
            "opened_height": self.opened_height,
            "release_height": self.release_height,
            "evidence_commitment": self.evidence_commitment,
            "bridge_freeze": self.bridge_freeze,
            "released": self.released
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorBond {
    pub sponsor_id: String,
    pub bond_id: String,
    pub status: BondStatus,
    pub locked_micro_units: u64,
    pub encumbered_micro_units: u64,
    pub slashed_micro_units: u64,
    pub fee_asset_id: String,
    pub operator_id: String,
    pub created_height: u64,
    pub release_height: u64,
}

impl SponsorBond {
    pub fn available_micro_units(&self) -> u64 {
        self.locked_micro_units
            .saturating_sub(self.encumbered_micro_units)
            .saturating_sub(self.slashed_micro_units)
    }

    pub fn covers(&self, amount: u64) -> bool {
        matches!(self.status, BondStatus::Active | BondStatus::Encumbered)
            && self.available_micro_units() >= amount
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "bond_id": self.bond_id,
            "status": self.status,
            "locked_micro_units": self.locked_micro_units,
            "encumbered_micro_units": self.encumbered_micro_units,
            "slashed_micro_units": self.slashed_micro_units,
            "fee_asset_id": self.fee_asset_id,
            "operator_id": self.operator_id,
            "created_height": self.created_height,
            "release_height": self.release_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditRebate {
    pub rebate_id: String,
    pub envelope_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub status: RebateStatus,
    pub created_height: u64,
    pub expires_height: u64,
}

impl FeeCreditRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "envelope_id": self.envelope_id,
            "sponsor_id": self.sponsor_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "status": self.status,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub window_id: String,
    pub allowance: u64,
    pub spent: u64,
    pub min_privacy_set_size: u64,
    pub status: BudgetStatus,
    pub last_spent_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn remaining(&self) -> u64 {
        self.allowance.saturating_sub(self.spent)
    }

    pub fn spend(&mut self, amount: u64, height: u64) -> Result<()> {
        if self.status != BudgetStatus::Active {
            return Err("redaction budget is not active".to_string());
        }
        if self.remaining() < amount {
            self.status = BudgetStatus::Exhausted;
            return Err("redaction budget exhausted".to_string());
        }
        self.spent = self.spent.saturating_add(amount);
        self.last_spent_height = height;
        if self.remaining() == 0 {
            self.status = BudgetStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "window_id": self.window_id,
            "allowance": self.allowance,
            "spent": self.spent,
            "remaining": self.remaining(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "status": self.status,
            "last_spent_height": self.last_spent_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub epoch: u64,
    pub committee_ids: BTreeSet<String>,
    pub attestations_signed: u64,
    pub quarantines_triggered: u64,
    pub bridge_holds_triggered: u64,
    pub rebates_sponsored_micro_units: u64,
    pub bond_at_risk_micro_units: u64,
    pub reliability_bps: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "committee_ids": self.committee_ids.iter().cloned().collect::<Vec<_>>(),
            "attestations_signed": self.attestations_signed,
            "quarantines_triggered": self.quarantines_triggered,
            "bridge_holds_triggered": self.bridge_holds_triggered,
            "rebates_sponsored_micro_units": self.rebates_sponsored_micro_units,
            "bond_at_risk_micro_units": self.bond_at_risk_micro_units,
            "reliability_bps": self.reliability_bps
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub height: u64,
    pub epoch: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub committees: BTreeMap<String, RecoveryCommittee>,
    pub envelopes: BTreeMap<String, MlKemEscrowEnvelope>,
    pub rotation_windows: BTreeMap<String, RotationWindow>,
    pub quorum_attestations: BTreeMap<String, QuorumAttestation>,
    pub quarantines: BTreeMap<String, QuarantineRecord>,
    pub sponsor_bonds: BTreeMap<String, SponsorBond>,
    pub fee_credit_rebates: BTreeMap<String, FeeCreditRebate>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub used_recovery_nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            height,
            epoch,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            committees: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            rotation_windows: BTreeMap::new(),
            quorum_attestations: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            sponsor_bonds: BTreeMap::new(),
            fee_credit_rebates: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            used_recovery_nullifiers: BTreeSet::new(),
            public_events: Vec::new(),
        };
        state.refresh_roots();
        Ok(state)
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

    pub fn register_committee(&mut self, committee: RecoveryCommittee) -> Result<()> {
        self.config.validate()?;
        if self.committees.len() >= self.config.max_recovery_committees {
            return Err("recovery committee capacity reached".to_string());
        }
        if committee.committee_id.is_empty() {
            return Err("committee id is required".to_string());
        }
        if self.committees.contains_key(&committee.committee_id) {
            return Err("committee already registered".to_string());
        }
        if committee.threshold_bps < self.config.min_quorum_weight_bps
            || committee.threshold_bps > self.config.max_quorum_weight_bps
        {
            return Err("committee threshold outside configured quorum range".to_string());
        }
        if committee.privacy_set_size < self.config.min_privacy_set_size {
            return Err("committee privacy set below runtime minimum".to_string());
        }
        if committee.pq_security_bits < self.config.min_pq_security_bits {
            return Err("committee pq security below runtime minimum".to_string());
        }
        if committee.members.len() < self.config.min_committee_size {
            return Err("committee member count below runtime minimum".to_string());
        }
        let total_weight: u64 = committee
            .members
            .iter()
            .map(|member| member.weight_bps)
            .sum();
        if total_weight < committee.threshold_bps {
            return Err("committee member weight below threshold".to_string());
        }
        let mut unique = BTreeSet::new();
        for member in &committee.members {
            if member.operator_id.is_empty() {
                return Err("committee member operator id is required".to_string());
            }
            if !unique.insert(member.operator_id.clone()) {
                return Err("duplicate committee member".to_string());
            }
        }
        self.counters.committees_registered = self.counters.committees_registered.saturating_add(1);
        self.counters.committee_members_registered = self
            .counters
            .committee_members_registered
            .saturating_add(committee.members.len() as u64);
        self.emit_event(json!({
            "event": "committee_registered",
            "committee_id": committee.committee_id,
            "epoch": committee.epoch
        }));
        self.committees
            .insert(committee.committee_id.clone(), committee);
        self.refresh_roots();
        Ok(())
    }

    pub fn lock_sponsor_bond(&mut self, bond: SponsorBond) -> Result<()> {
        if self.sponsor_bonds.len() >= self.config.max_sponsor_bonds {
            return Err("sponsor bond capacity reached".to_string());
        }
        if bond.locked_micro_units < self.config.min_sponsor_bond_micro_units {
            return Err("sponsor bond below minimum".to_string());
        }
        if bond.fee_asset_id != self.config.fee_asset_id {
            return Err("sponsor bond uses unsupported fee asset".to_string());
        }
        if self.sponsor_bonds.contains_key(&bond.bond_id) {
            return Err("sponsor bond already locked".to_string());
        }
        self.counters.sponsor_bonds_locked = self.counters.sponsor_bonds_locked.saturating_add(1);
        self.emit_event(json!({
            "event": "sponsor_bond_locked",
            "bond_id": bond.bond_id,
            "sponsor_id": bond.sponsor_id,
            "locked_micro_units": bond.locked_micro_units
        }));
        self.sponsor_bonds.insert(bond.bond_id.clone(), bond);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_rotation_window(&mut self, mut window: RotationWindow) -> Result<()> {
        if self.rotation_windows.len() >= self.config.max_rotation_windows {
            return Err("rotation window capacity reached".to_string());
        }
        let committee = self
            .committees
            .get(&window.committee_id)
            .ok_or_else(|| "rotation window committee missing".to_string())?;
        if !committee.can_recover(&self.config) {
            return Err("committee is not eligible for recovery windows".to_string());
        }
        if window.close_height <= window.start_height {
            return Err("rotation window close height must exceed start height".to_string());
        }
        if window.close_height.saturating_sub(window.start_height)
            > self.config.rotation_window_blocks
        {
            return Err("rotation window exceeds configured duration".to_string());
        }
        if window.bridge_release_height
            < window
                .close_height
                .saturating_add(self.config.bridge_hold_blocks)
        {
            return Err("rotation window bridge hold is too short".to_string());
        }
        if window.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("rotation window privacy set below runtime minimum".to_string());
        }
        if window.min_quorum_weight_bps < self.config.min_quorum_weight_bps {
            return Err("rotation window quorum below runtime minimum".to_string());
        }
        if self.rotation_windows.contains_key(&window.window_id) {
            return Err("rotation window already exists".to_string());
        }
        if window.contains_height(self.height) {
            window.status = RotationWindowStatus::Open;
        }
        self.counters.rotation_windows_opened =
            self.counters.rotation_windows_opened.saturating_add(1);
        self.emit_event(json!({
            "event": "rotation_window_opened",
            "window_id": window.window_id,
            "committee_id": window.committee_id,
            "start_height": window.start_height,
            "close_height": window.close_height
        }));
        self.rotation_windows
            .insert(window.window_id.clone(), window);
        self.refresh_roots();
        Ok(())
    }

    pub fn allocate_privacy_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<()> {
        if self.privacy_redaction_budgets.len() >= self.config.max_privacy_budgets {
            return Err("privacy budget capacity reached".to_string());
        }
        if budget.allowance > self.config.privacy_redaction_budget {
            return Err("privacy redaction allowance exceeds runtime budget".to_string());
        }
        if budget.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("budget privacy set below runtime minimum".to_string());
        }
        if !self.rotation_windows.contains_key(&budget.window_id) {
            return Err("budget window missing".to_string());
        }
        if self
            .privacy_redaction_budgets
            .contains_key(&budget.budget_id)
        {
            return Err("privacy budget already exists".to_string());
        }
        self.emit_event(json!({
            "event": "privacy_budget_allocated",
            "budget_id": budget.budget_id,
            "window_id": budget.window_id,
            "allowance": budget.allowance
        }));
        self.privacy_redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_escrow_envelope(&mut self, mut envelope: MlKemEscrowEnvelope) -> Result<()> {
        if self.envelopes.len() >= self.config.max_escrow_envelopes {
            return Err("escrow envelope capacity reached".to_string());
        }
        if self.envelopes.contains_key(&envelope.envelope_id) {
            return Err("escrow envelope already exists".to_string());
        }
        if self
            .used_recovery_nullifiers
            .contains(&envelope.recovery_nullifier)
        {
            return Err("duplicate recovery nullifier".to_string());
        }
        if envelope.pq_security_bits < self.config.min_pq_security_bits {
            return Err("envelope pq security below runtime minimum".to_string());
        }
        if envelope.privacy_set_size < self.config.min_privacy_set_size {
            return Err("envelope privacy set below runtime minimum".to_string());
        }
        let committee = self
            .committees
            .get(&envelope.committee_id)
            .ok_or_else(|| "envelope committee missing".to_string())?;
        if !committee.can_recover(&self.config) {
            return Err("envelope committee is not recovery ready".to_string());
        }
        let window = self
            .rotation_windows
            .get_mut(&envelope.window_id)
            .ok_or_else(|| "envelope rotation window missing".to_string())?;
        if !window.status.accepts_attestations() && !window.contains_height(self.height) {
            return Err("rotation window is closed for envelopes".to_string());
        }
        let sponsor_bond = self
            .sponsor_bonds
            .values_mut()
            .find(|bond| {
                bond.sponsor_id == envelope.sponsor_id && bond.covers(envelope.fee_micro_units)
            })
            .ok_or_else(|| "sponsor bond does not cover envelope fee".to_string())?;
        sponsor_bond.encumbered_micro_units = sponsor_bond
            .encumbered_micro_units
            .saturating_add(envelope.fee_micro_units);
        sponsor_bond.status = BondStatus::Encumbered;
        envelope.status = EscrowEnvelopeStatus::PqSealed;
        envelope.expires_height = envelope
            .expires_height
            .max(self.height.saturating_add(self.config.envelope_ttl_blocks));
        window.envelope_ids.insert(envelope.envelope_id.clone());
        self.used_recovery_nullifiers
            .insert(envelope.recovery_nullifier.clone());
        self.counters.escrow_envelopes_opened =
            self.counters.escrow_envelopes_opened.saturating_add(1);
        self.counters.escrow_envelopes_pq_sealed =
            self.counters.escrow_envelopes_pq_sealed.saturating_add(1);
        self.emit_event(json!({
            "event": "escrow_envelope_opened",
            "envelope_id": envelope.envelope_id,
            "committee_id": envelope.committee_id,
            "window_id": envelope.window_id,
            "privacy_set_size": envelope.privacy_set_size,
            "pq_security_bits": envelope.pq_security_bits
        }));
        self.envelopes
            .insert(envelope.envelope_id.clone(), envelope);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_quorum_attestation(&mut self, attestation: QuorumAttestation) -> Result<()> {
        if self.quorum_attestations.len() >= self.config.max_quorum_attestations {
            return Err("quorum attestation capacity reached".to_string());
        }
        if self
            .quorum_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err("quorum attestation already exists".to_string());
        }
        let envelope = self
            .envelopes
            .get_mut(&attestation.envelope_id)
            .ok_or_else(|| "attestation envelope missing".to_string())?;
        if envelope.status == EscrowEnvelopeStatus::Quarantined {
            return Err("cannot attest quarantined envelope".to_string());
        }
        if envelope.is_expired(self.height) {
            envelope.status = EscrowEnvelopeStatus::Expired;
            return Err("cannot attest expired envelope".to_string());
        }
        let committee = self
            .committees
            .get(&attestation.committee_id)
            .ok_or_else(|| "attestation committee missing".to_string())?;
        let window = self
            .rotation_windows
            .get_mut(&attestation.window_id)
            .ok_or_else(|| "attestation window missing".to_string())?;
        if !window.status.accepts_attestations() {
            return Err("rotation window does not accept attestations".to_string());
        }
        if attestation.aggregate_weight_bps < window.min_quorum_weight_bps {
            return Err("attestation quorum weight below window minimum".to_string());
        }
        let signer_weight = committee
            .members
            .iter()
            .filter(|member| {
                attestation
                    .signer_operator_ids
                    .contains(&member.operator_id)
            })
            .map(|member| member.weight_bps)
            .sum::<u64>();
        if signer_weight < attestation.aggregate_weight_bps {
            return Err("attestation aggregate weight exceeds signer weight".to_string());
        }
        if !attestation.verdict.approves_rotation() {
            return Err("quorum attestation does not approve rotation".to_string());
        }
        if !attestation.is_live(self.height) {
            return Err("quorum attestation expired".to_string());
        }
        envelope.status = if attestation.verdict == QuorumVerdict::BridgeHoldRequired {
            EscrowEnvelopeStatus::WindowBound
        } else {
            EscrowEnvelopeStatus::RecoveryReady
        };
        window
            .attestation_ids
            .insert(attestation.attestation_id.clone());
        if attestation.verdict == QuorumVerdict::BridgeHoldRequired {
            window.status = RotationWindowStatus::BridgeHold;
            self.counters.bridge_holds_enforced =
                self.counters.bridge_holds_enforced.saturating_add(1);
        } else {
            window.status = RotationWindowStatus::Attesting;
        }
        self.counters.quorum_attestations_recorded =
            self.counters.quorum_attestations_recorded.saturating_add(1);
        self.emit_event(json!({
            "event": "quorum_attestation_recorded",
            "attestation_id": attestation.attestation_id,
            "envelope_id": attestation.envelope_id,
            "aggregate_weight_bps": attestation.aggregate_weight_bps,
            "verdict": attestation.verdict
        }));
        self.quorum_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn spend_redaction_budget(
        &mut self,
        budget_id: &str,
        amount: u64,
        evidence_commitment: &str,
    ) -> Result<()> {
        let budget = self
            .privacy_redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "privacy redaction budget missing".to_string())?;
        budget.spend(amount, self.height)?;
        self.counters.privacy_redactions_spent = self
            .counters
            .privacy_redactions_spent
            .saturating_add(amount);
        self.emit_event(json!({
            "event": "privacy_redaction_spent",
            "budget_id": budget_id,
            "amount": amount,
            "evidence_commitment": evidence_commitment
        }));
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine(
        &mut self,
        quarantine_id: &str,
        target_id: &str,
        reason: QuarantineReason,
        evidence_commitment: &str,
        bridge_freeze: bool,
    ) -> Result<()> {
        if self.quarantines.len() >= self.config.max_quarantines {
            return Err("quarantine capacity reached".to_string());
        }
        if self.quarantines.contains_key(quarantine_id) {
            return Err("quarantine already exists".to_string());
        }
        if let Some(envelope) = self.envelopes.get_mut(target_id) {
            envelope.status = EscrowEnvelopeStatus::Quarantined;
        }
        if let Some(window) = self.rotation_windows.get_mut(target_id) {
            window.status = RotationWindowStatus::Quarantined;
        }
        if let Some(committee) = self.committees.get_mut(target_id) {
            committee.status = CommitteeStatus::Quarantined;
        }
        let record = QuarantineRecord {
            quarantine_id: quarantine_id.to_string(),
            target_id: target_id.to_string(),
            reason,
            opened_height: self.height,
            release_height: self.height.saturating_add(self.config.quarantine_blocks),
            evidence_commitment: evidence_commitment.to_string(),
            bridge_freeze,
            released: false,
        };
        self.counters.quarantines_opened = self.counters.quarantines_opened.saturating_add(1);
        self.emit_event(json!({
            "event": "quarantine_opened",
            "quarantine_id": quarantine_id,
            "target_id": target_id,
            "reason": reason,
            "bridge_freeze": bridge_freeze
        }));
        self.quarantines.insert(quarantine_id.to_string(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn release_quarantine(&mut self, quarantine_id: &str) -> Result<()> {
        let record = self
            .quarantines
            .get_mut(quarantine_id)
            .ok_or_else(|| "quarantine missing".to_string())?;
        if !record.releasable(self.height) {
            return Err("quarantine is not releasable yet".to_string());
        }
        record.released = true;
        self.counters.quarantines_released = self.counters.quarantines_released.saturating_add(1);
        self.emit_event(json!({
            "event": "quarantine_released",
            "quarantine_id": quarantine_id
        }));
        self.refresh_roots();
        Ok(())
    }

    pub fn finalize_rotation(&mut self, envelope_id: &str, attestation_id: &str) -> Result<()> {
        let attestation = self
            .quorum_attestations
            .get(attestation_id)
            .ok_or_else(|| "finalization attestation missing".to_string())?;
        if attestation.envelope_id != envelope_id {
            return Err("attestation envelope mismatch".to_string());
        }
        let window = self
            .rotation_windows
            .get_mut(&attestation.window_id)
            .ok_or_else(|| "finalization window missing".to_string())?;
        if !window.bridge_hold_elapsed(self.height) {
            return Err("bridge hold has not elapsed".to_string());
        }
        let envelope = self
            .envelopes
            .get_mut(envelope_id)
            .ok_or_else(|| "finalization envelope missing".to_string())?;
        if !envelope.status.bridge_safe() {
            return Err("envelope is not bridge safe for finalization".to_string());
        }
        envelope.status = EscrowEnvelopeStatus::Rotated;
        window.status = RotationWindowStatus::Finalized;
        self.counters.rotations_finalized = self.counters.rotations_finalized.saturating_add(1);
        self.issue_fee_rebate_for_envelope(envelope_id)?;
        self.emit_event(json!({
            "event": "viewkey_escrow_rotation_finalized",
            "envelope_id": envelope_id,
            "attestation_id": attestation_id,
            "window_id": attestation.window_id
        }));
        self.refresh_roots();
        Ok(())
    }

    pub fn claim_fee_credit_rebate(&mut self, rebate_id: &str) -> Result<()> {
        let rebate = self
            .fee_credit_rebates
            .get_mut(rebate_id)
            .ok_or_else(|| "rebate missing".to_string())?;
        if rebate.status != RebateStatus::Claimable {
            return Err("rebate is not claimable".to_string());
        }
        if self.height > rebate.expires_height {
            rebate.status = RebateStatus::Expired;
            return Err("rebate expired".to_string());
        }
        rebate.status = RebateStatus::Claimed;
        self.counters.fee_credit_rebates_claimed =
            self.counters.fee_credit_rebates_claimed.saturating_add(1);
        self.emit_event(json!({
            "event": "fee_credit_rebate_claimed",
            "rebate_id": rebate_id
        }));
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        if self.operator_summaries.len() >= self.config.max_operator_summaries {
            return Err("operator summary capacity reached".to_string());
        }
        let key = operator_summary_key(&summary.operator_id, summary.epoch);
        self.emit_event(json!({
            "event": "operator_summary_published",
            "operator_id": summary.operator_id,
            "epoch": summary.epoch,
            "reliability_bps": summary.reliability_bps
        }));
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.operator_summaries.insert(key, summary);
        self.refresh_roots();
        Ok(())
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("cannot rewind runtime height".to_string());
        }
        self.height = height;
        self.expire_stale_envelopes();
        self.refresh_roots();
        Ok(())
    }

    pub fn recompute_roots(&self) -> Roots {
        let committee_leaves = self
            .committees
            .values()
            .map(|committee| {
                domain_hash(
                    RECOVERY_COMMITTEE_SCHEME,
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&committee.committee_id),
                        HashPart::Int(committee.epoch as i128),
                        HashPart::Str(committee.status.as_str()),
                        HashPart::Int(committee.threshold_bps as i128),
                        HashPart::Int(committee.privacy_set_size as i128),
                        HashPart::Int(committee.pq_security_bits as i128),
                        HashPart::Str(&committee.sponsor_id),
                        HashPart::Str(&committee.bridge_guardian_set_commitment),
                        HashPart::Str(&committee.policy_commitment),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let envelope_leaves = self
            .envelopes
            .values()
            .map(|envelope| {
                domain_hash(
                    ML_KEM_ESCROW_ENVELOPE_SCHEME,
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&envelope.envelope_id),
                        HashPart::Str(&envelope.account_tag_commitment),
                        HashPart::Str(&envelope.viewkey_ciphertext_commitment),
                        HashPart::Str(&envelope.ml_kem_ciphertext_commitment),
                        HashPart::Str(&envelope.recovery_nullifier),
                        HashPart::Str(&envelope.committee_id),
                        HashPart::Str(&envelope.window_id),
                        HashPart::Int(envelope.privacy_set_size as i128),
                        HashPart::Int(envelope.pq_security_bits as i128),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let window_leaves = self
            .rotation_windows
            .values()
            .map(|window| {
                domain_hash(
                    ROTATION_WINDOW_SCHEME,
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&window.window_id),
                        HashPart::Str(&window.committee_id),
                        HashPart::Int(window.epoch as i128),
                        HashPart::Int(window.start_height as i128),
                        HashPart::Int(window.close_height as i128),
                        HashPart::Int(window.bridge_release_height as i128),
                        HashPart::Int(window.min_privacy_set_size as i128),
                        HashPart::Int(window.min_quorum_weight_bps as i128),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let attestation_leaves = self
            .quorum_attestations
            .values()
            .map(|attestation| {
                domain_hash(
                    QUORUM_ATTESTATION_SCHEME,
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&attestation.attestation_id),
                        HashPart::Str(&attestation.envelope_id),
                        HashPart::Str(&attestation.window_id),
                        HashPart::Str(&attestation.committee_id),
                        HashPart::Int(attestation.aggregate_weight_bps as i128),
                        HashPart::Str(attestation.verdict.as_ref()),
                        HashPart::Str(&attestation.proof_commitment),
                        HashPart::Str(&attestation.bridge_replay_guard),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let quarantine_leaves = self
            .quarantines
            .values()
            .map(|record| {
                domain_hash(
                    QUARANTINE_SCHEME,
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&record.quarantine_id),
                        HashPart::Str(&record.target_id),
                        HashPart::Str(record.reason.as_ref()),
                        HashPart::Int(record.opened_height as i128),
                        HashPart::Int(record.release_height as i128),
                        HashPart::Str(&record.evidence_commitment),
                        HashPart::Bool(record.bridge_freeze),
                        HashPart::Bool(record.released),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let bond_leaves = self
            .sponsor_bonds
            .values()
            .map(|bond| {
                domain_hash(
                    SPONSOR_BOND_SCHEME,
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&bond.sponsor_id),
                        HashPart::Str(&bond.bond_id),
                        HashPart::Str(bond.status.as_ref()),
                        HashPart::Int(bond.locked_micro_units as i128),
                        HashPart::Int(bond.encumbered_micro_units as i128),
                        HashPart::Int(bond.slashed_micro_units as i128),
                        HashPart::Str(&bond.fee_asset_id),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let rebate_leaves = self
            .fee_credit_rebates
            .values()
            .map(|rebate| {
                domain_hash(
                    FEE_CREDIT_REBATE_SCHEME,
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&rebate.rebate_id),
                        HashPart::Str(&rebate.envelope_id),
                        HashPart::Str(&rebate.sponsor_id),
                        HashPart::Str(&rebate.beneficiary_commitment),
                        HashPart::Int(rebate.fee_paid_micro_units as i128),
                        HashPart::Int(rebate.rebate_micro_units as i128),
                        HashPart::Str(rebate.status.as_ref()),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let budget_leaves = self
            .privacy_redaction_budgets
            .values()
            .map(|budget| {
                domain_hash(
                    PRIVACY_REDACTION_BUDGET_SCHEME,
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&budget.budget_id),
                        HashPart::Str(&budget.owner_commitment),
                        HashPart::Str(&budget.window_id),
                        HashPart::Int(budget.allowance as i128),
                        HashPart::Int(budget.spent as i128),
                        HashPart::Int(budget.min_privacy_set_size as i128),
                        HashPart::Str(budget.status.as_ref()),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let operator_leaves = self
            .operator_summaries
            .values()
            .map(|summary| {
                domain_hash(
                    OPERATOR_SUMMARY_SCHEME,
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(&summary.operator_id),
                        HashPart::Int(summary.epoch as i128),
                        HashPart::Int(summary.attestations_signed as i128),
                        HashPart::Int(summary.quarantines_triggered as i128),
                        HashPart::Int(summary.bridge_holds_triggered as i128),
                        HashPart::Int(summary.rebates_sponsored_micro_units as i128),
                        HashPart::Int(summary.bond_at_risk_micro_units as i128),
                        HashPart::Int(summary.reliability_bps as i128),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let event_leaves = self
            .public_events
            .iter()
            .enumerate()
            .map(|(index, event)| {
                domain_hash(
                    "viewkey-escrow-public-event-leaf-v1",
                    &[
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Int(index as i128),
                        HashPart::Str(&event.to_string()),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let committee_root = merkle_or_empty(RECOVERY_COMMITTEE_SCHEME, committee_leaves);
        let escrow_envelope_root = merkle_or_empty(ML_KEM_ESCROW_ENVELOPE_SCHEME, envelope_leaves);
        let rotation_window_root = merkle_or_empty(ROTATION_WINDOW_SCHEME, window_leaves);
        let quorum_attestation_root =
            merkle_or_empty(QUORUM_ATTESTATION_SCHEME, attestation_leaves);
        let quarantine_root = merkle_or_empty(QUARANTINE_SCHEME, quarantine_leaves);
        let sponsor_bond_root = merkle_or_empty(SPONSOR_BOND_SCHEME, bond_leaves);
        let fee_credit_rebate_root = merkle_or_empty(FEE_CREDIT_REBATE_SCHEME, rebate_leaves);
        let privacy_redaction_budget_root =
            merkle_or_empty(PRIVACY_REDACTION_BUDGET_SCHEME, budget_leaves);
        let operator_summary_root = merkle_or_empty(OPERATOR_SUMMARY_SCHEME, operator_leaves);
        let public_event_root =
            merkle_or_empty("viewkey-escrow-public-event-root-v1", event_leaves);
        let state_root = domain_hash(
            "viewkey-escrow-rotation-state-root-v1",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Int(self.schema_version as i128),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.epoch as i128),
                HashPart::Str(&committee_root),
                HashPart::Str(&escrow_envelope_root),
                HashPart::Str(&rotation_window_root),
                HashPart::Str(&quorum_attestation_root),
                HashPart::Str(&quarantine_root),
                HashPart::Str(&sponsor_bond_root),
                HashPart::Str(&fee_credit_rebate_root),
                HashPart::Str(&privacy_redaction_budget_root),
                HashPart::Str(&operator_summary_root),
                HashPart::Str(&public_event_root),
            ],
        );
        Roots {
            committee_root,
            escrow_envelope_root,
            rotation_window_root,
            quorum_attestation_root,
            quarantine_root,
            sponsor_bond_root,
            fee_credit_rebate_root,
            privacy_redaction_budget_root,
            operator_summary_root,
            public_event_root,
            state_root,
        }
    }

    fn refresh_roots(&mut self) {
        self.roots = self.recompute_roots();
    }

    fn emit_event(&mut self, event: Value) {
        if self.public_events.len() < self.config.max_public_events {
            self.public_events.push(json!({
                "height": self.height,
                "epoch": self.epoch,
                "protocol_version": PROTOCOL_VERSION,
                "payload": event
            }));
            self.counters.public_events_emitted =
                self.counters.public_events_emitted.saturating_add(1);
        }
    }

    fn expire_stale_envelopes(&mut self) {
        for envelope in self.envelopes.values_mut() {
            if envelope.status.is_live() && envelope.is_expired(self.height) {
                envelope.status = EscrowEnvelopeStatus::Expired;
            }
        }
        for window in self.rotation_windows.values_mut() {
            if matches!(
                window.status,
                RotationWindowStatus::Scheduled
                    | RotationWindowStatus::Open
                    | RotationWindowStatus::Attesting
            ) && self.height > window.bridge_release_height
            {
                window.status = RotationWindowStatus::Expired;
            }
        }
    }

    fn issue_fee_rebate_for_envelope(&mut self, envelope_id: &str) -> Result<()> {
        if self.fee_credit_rebates.len() >= self.config.max_fee_credit_rebates {
            return Err("fee credit rebate capacity reached".to_string());
        }
        let envelope = self
            .envelopes
            .get(envelope_id)
            .ok_or_else(|| "rebate envelope missing".to_string())?;
        let rebate_id = deterministic_id(
            "viewkey-fee-rebate",
            &[envelope_id, &envelope.sponsor_id, &self.height.to_string()],
        );
        if self.fee_credit_rebates.contains_key(&rebate_id) {
            return Ok(());
        }
        let rebate_micro_units = envelope
            .fee_micro_units
            .saturating_mul(self.config.rebate_bps)
            / MAX_BPS;
        let rebate = FeeCreditRebate {
            rebate_id: rebate_id.clone(),
            envelope_id: envelope_id.to_string(),
            sponsor_id: envelope.sponsor_id.clone(),
            beneficiary_commitment: envelope.account_tag_commitment.clone(),
            fee_paid_micro_units: envelope.fee_micro_units,
            rebate_micro_units,
            status: RebateStatus::Claimable,
            created_height: self.height,
            expires_height: self.height.saturating_add(self.config.envelope_ttl_blocks),
        };
        self.counters.fee_credit_rebates_issued =
            self.counters.fee_credit_rebates_issued.saturating_add(1);
        self.emit_event(json!({
            "event": "fee_credit_rebate_issued",
            "rebate_id": rebate_id,
            "envelope_id": envelope_id,
            "rebate_micro_units": rebate_micro_units
        }));
        self.fee_credit_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }
}

impl AsRef<str> for QuorumVerdict {
    fn as_ref(&self) -> &str {
        match self {
            Self::Approved => "approved",
            Self::NeedsMoreCommitteeWeight => "needs_more_committee_weight",
            Self::NeedsMorePrivacy => "needs_more_privacy",
            Self::BridgeHoldRequired => "bridge_hold_required",
            Self::SponsorBondLow => "sponsor_bond_low",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::Rejected => "rejected",
        }
    }
}

impl AsRef<str> for QuarantineReason {
    fn as_ref(&self) -> &str {
        match self {
            Self::LowPqSecurity => "low_pq_security",
            Self::CommitteeEquivocation => "committee_equivocation",
            Self::BridgeReplayRisk => "bridge_replay_risk",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::SponsorBondDeficit => "sponsor_bond_deficit",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

impl AsRef<str> for BondStatus {
    fn as_ref(&self) -> &str {
        match self {
            Self::Funding => "funding",
            Self::Active => "active",
            Self::Encumbered => "encumbered",
            Self::Slashed => "slashed",
            Self::Released => "released",
            Self::Frozen => "frozen",
        }
    }
}

impl AsRef<str> for RebateStatus {
    fn as_ref(&self) -> &str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Donated => "donated",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

impl AsRef<str> for BudgetStatus {
    fn as_ref(&self) -> &str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::CoolingDown => "cooling_down",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
}

pub fn devnet() -> State {
    demo()
}

pub fn demo() -> State {
    let mut state = State::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
        .expect("generated devnet config is valid");
    let committee = RecoveryCommittee {
        committee_id: "devnet-viewkey-recovery-committee-001".to_string(),
        epoch: DEVNET_EPOCH,
        status: CommitteeStatus::Active,
        threshold_bps: 6_800,
        privacy_set_size: 524_288,
        pq_security_bits: 256,
        sponsor_id: "devnet-recovery-sponsor-001".to_string(),
        members: devnet_committee_members(),
        bridge_guardian_set_commitment: fixture_commitment("bridge-guardian-set", 1),
        policy_commitment: fixture_commitment("committee-policy", 1),
        created_height: DEVNET_HEIGHT.saturating_sub(720),
        expires_height: DEVNET_HEIGHT.saturating_add(21_600),
    };
    state
        .register_committee(committee)
        .expect("generated committee is valid");
    state
        .lock_sponsor_bond(SponsorBond {
            sponsor_id: "devnet-recovery-sponsor-001".to_string(),
            bond_id: "devnet-recovery-sponsor-bond-001".to_string(),
            status: BondStatus::Active,
            locked_micro_units: 750_000_000,
            encumbered_micro_units: 0,
            slashed_micro_units: 0,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            operator_id: "operator-devnet-001".to_string(),
            created_height: DEVNET_HEIGHT.saturating_sub(512),
            release_height: DEVNET_HEIGHT.saturating_add(43_200),
        })
        .expect("generated sponsor bond is valid");
    let window = RotationWindow {
        window_id: "devnet-viewkey-rotation-window-001".to_string(),
        committee_id: "devnet-viewkey-recovery-committee-001".to_string(),
        epoch: DEVNET_EPOCH,
        start_height: DEVNET_HEIGHT.saturating_sub(8),
        close_height: DEVNET_HEIGHT.saturating_add(256),
        bridge_release_height: DEVNET_HEIGHT.saturating_add(288),
        min_privacy_set_size: 262_144,
        min_quorum_weight_bps: 6_700,
        status: RotationWindowStatus::Open,
        envelope_ids: BTreeSet::new(),
        attestation_ids: BTreeSet::new(),
    };
    state
        .open_rotation_window(window)
        .expect("generated rotation window is valid");
    state
        .allocate_privacy_budget(PrivacyRedactionBudget {
            budget_id: "devnet-redaction-budget-001".to_string(),
            owner_commitment: fixture_commitment("budget-owner", 1),
            window_id: "devnet-viewkey-rotation-window-001".to_string(),
            allowance: 24,
            spent: 0,
            min_privacy_set_size: 262_144,
            status: BudgetStatus::Active,
            last_spent_height: DEVNET_HEIGHT,
        })
        .expect("generated privacy budget is valid");
    let envelope = MlKemEscrowEnvelope {
        envelope_id: "devnet-mlkem-viewkey-envelope-001".to_string(),
        account_tag_commitment: fixture_commitment("account-tag", 1),
        viewkey_ciphertext_commitment: fixture_commitment("viewkey-ciphertext", 1),
        ml_kem_ciphertext_commitment: fixture_commitment("ml-kem-ciphertext", 1),
        recovery_nullifier: fixture_commitment("recovery-nullifier", 1),
        committee_id: "devnet-viewkey-recovery-committee-001".to_string(),
        window_id: "devnet-viewkey-rotation-window-001".to_string(),
        sponsor_id: "devnet-recovery-sponsor-001".to_string(),
        privacy_set_size: 524_288,
        pq_security_bits: 256,
        fee_micro_units: 2_500,
        status: EscrowEnvelopeStatus::Proposed,
        opened_height: DEVNET_HEIGHT,
        expires_height: DEVNET_HEIGHT.saturating_add(1_440),
    };
    state
        .open_escrow_envelope(envelope)
        .expect("generated escrow envelope is valid");
    state
        .record_quorum_attestation(QuorumAttestation {
            attestation_id: "devnet-quorum-attestation-001".to_string(),
            envelope_id: "devnet-mlkem-viewkey-envelope-001".to_string(),
            window_id: "devnet-viewkey-rotation-window-001".to_string(),
            committee_id: "devnet-viewkey-recovery-committee-001".to_string(),
            signer_operator_ids: [
                "operator-devnet-001",
                "operator-devnet-002",
                "operator-devnet-003",
                "operator-devnet-004",
                "operator-devnet-005",
                "operator-devnet-006",
                "operator-devnet-007",
            ]
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
            aggregate_weight_bps: 7_000,
            verdict: QuorumVerdict::BridgeHoldRequired,
            proof_commitment: fixture_commitment("aggregate-proof", 1),
            bridge_replay_guard: fixture_commitment("bridge-replay-guard", 1),
            redaction_receipt_id: "devnet-redaction-budget-001".to_string(),
            created_height: DEVNET_HEIGHT,
            expires_height: DEVNET_HEIGHT.saturating_add(96),
        })
        .expect("generated quorum attestation is valid");
    state
        .spend_redaction_budget(
            "devnet-redaction-budget-001",
            3,
            "devnet-redaction-proof-001",
        )
        .expect("generated redaction spend is valid");
    state
        .publish_operator_summary(OperatorSummary {
            operator_id: "operator-devnet-001".to_string(),
            epoch: DEVNET_EPOCH,
            committee_ids: ["devnet-viewkey-recovery-committee-001"]
                .iter()
                .map(|id| (*id).to_string())
                .collect(),
            attestations_signed: 42,
            quarantines_triggered: 1,
            bridge_holds_triggered: 4,
            rebates_sponsored_micro_units: 91_000,
            bond_at_risk_micro_units: 2_500,
            reliability_bps: 9_980,
        })
        .expect("generated operator summary is valid");
    state
        .advance_height(DEVNET_HEIGHT.saturating_add(288))
        .expect("generated height advance is valid");
    state
        .finalize_rotation(
            "devnet-mlkem-viewkey-envelope-001",
            "devnet-quorum-attestation-001",
        )
        .expect("generated finalization is valid");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!({
        "chain_id": state.config.chain_id,
        "protocol_version": state.protocol_version,
        "schema_version": state.schema_version,
        "hash_suite": HASH_SUITE,
        "pq_viewkey_escrow_suite": PQ_VIEWKEY_ESCROW_SUITE,
        "height": state.height,
        "epoch": state.epoch,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
        "operator_summaries": state.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>()
    })
}

pub fn state_root(state: &State) -> String {
    state.roots.state_root.clone()
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let mut hash_parts = vec![HashPart::Str(PROTOCOL_VERSION), HashPart::Str(domain)];
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    domain_hash("viewkey-escrow-deterministic-id-v1", &hash_parts)
}

pub fn operator_summary_key(operator_id: &str, epoch: u64) -> String {
    deterministic_id("operator-summary", &[operator_id, &epoch.to_string()])
}

fn merkle_or_empty(domain: &str, leaves: Vec<String>) -> String {
    if leaves.is_empty() {
        domain_hash(
            "empty-viewkey-escrow-root-v1",
            &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(domain)],
        )
    } else {
        merkle_root(domain, &leaves)
    }
}

fn fixture_commitment(label: &str, index: u64) -> String {
    domain_hash(
        "viewkey-escrow-devnet-fixture-commitment-v1",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(index as i128),
        ],
    )
}

fn devnet_committee_members() -> Vec<CommitteeMember> {
    vec![
        devnet_member(1, CommitteeRole::Coordinator, 1_000),
        devnet_member(2, CommitteeRole::RecoveryShard, 1_000),
        devnet_member(3, CommitteeRole::RecoveryShard, 1_000),
        devnet_member(4, CommitteeRole::BridgeSentinel, 1_000),
        devnet_member(5, CommitteeRole::PrivacyAuditor, 1_000),
        devnet_member(6, CommitteeRole::SponsorGuardian, 1_000),
        devnet_member(7, CommitteeRole::Watchtower, 1_000),
        devnet_member(8, CommitteeRole::RecoveryShard, 1_000),
        devnet_member(9, CommitteeRole::BridgeSentinel, 1_000),
        devnet_member(10, CommitteeRole::PrivacyAuditor, 1_000),
    ]
}

fn devnet_member(index: u64, role: CommitteeRole, weight_bps: u64) -> CommitteeMember {
    CommitteeMember {
        operator_id: format!("operator-devnet-{index:03}"),
        role,
        weight_bps,
        pq_attestation_key_commitment: fixture_commitment("pq-attestation-key", index),
        ml_kem_public_key_commitment: fixture_commitment("ml-kem-public-key", index),
        watchtower_endpoint_commitment: fixture_commitment("watchtower-endpoint", index),
        admitted_height: DEVNET_HEIGHT.saturating_sub(900).saturating_add(index),
        active: true,
    }
}

pub fn generated_policy_catalog() -> Vec<Value> {
    (1..=96)
        .map(|index| {
            json!({
                "policy_id": format!("viewkey-recovery-rotation-policy-{index:03}"),
                "protocol_version": PROTOCOL_VERSION,
                "objective": "post-quantum confidential Monero view-key recovery escrow rotation",
                "min_pq_security_bits": DEFAULT_MIN_PQ_SECURITY_BITS,
                "privacy_floor": DEFAULT_MIN_PRIVACY_SET_SIZE + index * 128,
                "bridge_hold_blocks": DEFAULT_BRIDGE_HOLD_BLOCKS + (index % 8),
                "target_user_fee_bps": DEFAULT_TARGET_USER_FEE_BPS,
                "rebate_bps": DEFAULT_REBATE_BPS + (index % 5) * 10,
                "operator_diversity_floor": DEFAULT_MIN_COMMITTEE_SIZE,
                "sponsor_cover_bps": DEFAULT_SPONSOR_COVER_BPS
            })
        })
        .collect()
}

pub fn generated_operator_risk_catalog() -> Vec<Value> {
    (1..=128)
        .map(|index| {
            let reliability_bps = 9_950_u64.saturating_sub(index % 40);
            json!({
                "operator_id": format!("operator-devnet-{index:03}"),
                "protocol_version": PROTOCOL_VERSION,
                "risk_lane": if index % 7 == 0 { "bridge_sentinel_review" } else { "standard" },
                "min_reliability_bps": reliability_bps,
                "pq_key_age_blocks": 256 + index * 3,
                "last_slash_height": 0,
                "privacy_redaction_budget_hint": DEFAULT_PRIVACY_REDACTION_BUDGET.saturating_sub(index % 8),
                "sponsor_bond_floor_micro_units": DEFAULT_MIN_SPONSOR_BOND_MICRO_UNITS + index * 10_000
            })
        })
        .collect()
}

pub fn generated_rotation_safety_matrix() -> Vec<Value> {
    (1..=160)
        .map(|index| {
            json!({
                "lane_id": format!("rotation-safety-lane-{index:03}"),
                "protocol_version": PROTOCOL_VERSION,
                "pq_security_bits": 256,
                "privacy_set_size": DEFAULT_MIN_PRIVACY_SET_SIZE + index * 512,
                "min_quorum_weight_bps": DEFAULT_MIN_QUORUM_WEIGHT_BPS + (index % 4) * 25,
                "bridge_hold_blocks": DEFAULT_BRIDGE_HOLD_BLOCKS + (index % 12),
                "quarantine_blocks": DEFAULT_QUARANTINE_BLOCKS + (index % 24),
                "max_user_fee_bps": DEFAULT_MAX_USER_FEE_BPS,
                "fee_rebate_bps": DEFAULT_REBATE_BPS,
                "allows_fast_finalization": index % 11 == 0
            })
        })
        .collect()
}

pub const GENERATED_STYLE_SECTION_001: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_001";
pub const GENERATED_STYLE_SECTION_002: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_002";
pub const GENERATED_STYLE_SECTION_003: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_003";
pub const GENERATED_STYLE_SECTION_004: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_004";
pub const GENERATED_STYLE_SECTION_005: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_005";
pub const GENERATED_STYLE_SECTION_006: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_006";
pub const GENERATED_STYLE_SECTION_007: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_007";
pub const GENERATED_STYLE_SECTION_008: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_008";
pub const GENERATED_STYLE_SECTION_009: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_009";
pub const GENERATED_STYLE_SECTION_010: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_010";
pub const GENERATED_STYLE_SECTION_011: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_011";
pub const GENERATED_STYLE_SECTION_012: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_012";
pub const GENERATED_STYLE_SECTION_013: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_013";
pub const GENERATED_STYLE_SECTION_014: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_014";
pub const GENERATED_STYLE_SECTION_015: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_015";
pub const GENERATED_STYLE_SECTION_016: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_016";
pub const GENERATED_STYLE_SECTION_017: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_017";
pub const GENERATED_STYLE_SECTION_018: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_018";
pub const GENERATED_STYLE_SECTION_019: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_019";
pub const GENERATED_STYLE_SECTION_020: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_020";
pub const GENERATED_STYLE_SECTION_021: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_021";
pub const GENERATED_STYLE_SECTION_022: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_022";
pub const GENERATED_STYLE_SECTION_023: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_023";
pub const GENERATED_STYLE_SECTION_024: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_024";
pub const GENERATED_STYLE_SECTION_025: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_025";
pub const GENERATED_STYLE_SECTION_026: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_026";
pub const GENERATED_STYLE_SECTION_027: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_027";
pub const GENERATED_STYLE_SECTION_028: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_028";
pub const GENERATED_STYLE_SECTION_029: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_029";
pub const GENERATED_STYLE_SECTION_030: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_030";
pub const GENERATED_STYLE_SECTION_031: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_031";
pub const GENERATED_STYLE_SECTION_032: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_032";
pub const GENERATED_STYLE_SECTION_033: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_033";
pub const GENERATED_STYLE_SECTION_034: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_034";
pub const GENERATED_STYLE_SECTION_035: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_035";
pub const GENERATED_STYLE_SECTION_036: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_036";
pub const GENERATED_STYLE_SECTION_037: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_037";
pub const GENERATED_STYLE_SECTION_038: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_038";
pub const GENERATED_STYLE_SECTION_039: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_039";
pub const GENERATED_STYLE_SECTION_040: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_040";
pub const GENERATED_STYLE_SECTION_041: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_041";
pub const GENERATED_STYLE_SECTION_042: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_042";
pub const GENERATED_STYLE_SECTION_043: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_043";
pub const GENERATED_STYLE_SECTION_044: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_044";
pub const GENERATED_STYLE_SECTION_045: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_045";
pub const GENERATED_STYLE_SECTION_046: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_046";
pub const GENERATED_STYLE_SECTION_047: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_047";
pub const GENERATED_STYLE_SECTION_048: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_048";
pub const GENERATED_STYLE_SECTION_049: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_049";
pub const GENERATED_STYLE_SECTION_050: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_050";
pub const GENERATED_STYLE_SECTION_051: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_051";
pub const GENERATED_STYLE_SECTION_052: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_052";
pub const GENERATED_STYLE_SECTION_053: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_053";
pub const GENERATED_STYLE_SECTION_054: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_054";
pub const GENERATED_STYLE_SECTION_055: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_055";
pub const GENERATED_STYLE_SECTION_056: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_056";
pub const GENERATED_STYLE_SECTION_057: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_057";
pub const GENERATED_STYLE_SECTION_058: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_058";
pub const GENERATED_STYLE_SECTION_059: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_059";
pub const GENERATED_STYLE_SECTION_060: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_060";
pub const GENERATED_STYLE_SECTION_061: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_061";
pub const GENERATED_STYLE_SECTION_062: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_062";
pub const GENERATED_STYLE_SECTION_063: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_063";
pub const GENERATED_STYLE_SECTION_064: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_064";
pub const GENERATED_STYLE_SECTION_065: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_065";
pub const GENERATED_STYLE_SECTION_066: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_066";
pub const GENERATED_STYLE_SECTION_067: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_067";
pub const GENERATED_STYLE_SECTION_068: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_068";
pub const GENERATED_STYLE_SECTION_069: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_069";
pub const GENERATED_STYLE_SECTION_070: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_070";
pub const GENERATED_STYLE_SECTION_071: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_071";
pub const GENERATED_STYLE_SECTION_072: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_072";
pub const GENERATED_STYLE_SECTION_073: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_073";
pub const GENERATED_STYLE_SECTION_074: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_074";
pub const GENERATED_STYLE_SECTION_075: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_075";
pub const GENERATED_STYLE_SECTION_076: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_076";
pub const GENERATED_STYLE_SECTION_077: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_077";
pub const GENERATED_STYLE_SECTION_078: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_078";
pub const GENERATED_STYLE_SECTION_079: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_079";
pub const GENERATED_STYLE_SECTION_080: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_080";
pub const GENERATED_STYLE_SECTION_081: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_081";
pub const GENERATED_STYLE_SECTION_082: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_082";
pub const GENERATED_STYLE_SECTION_083: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_083";
pub const GENERATED_STYLE_SECTION_084: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_084";
pub const GENERATED_STYLE_SECTION_085: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_085";
pub const GENERATED_STYLE_SECTION_086: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_086";
pub const GENERATED_STYLE_SECTION_087: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_087";
pub const GENERATED_STYLE_SECTION_088: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_088";
pub const GENERATED_STYLE_SECTION_089: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_089";
pub const GENERATED_STYLE_SECTION_090: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_090";
pub const GENERATED_STYLE_SECTION_091: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_091";
pub const GENERATED_STYLE_SECTION_092: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_092";
pub const GENERATED_STYLE_SECTION_093: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_093";
pub const GENERATED_STYLE_SECTION_094: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_094";
pub const GENERATED_STYLE_SECTION_095: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_095";
pub const GENERATED_STYLE_SECTION_096: &str =
    "viewkey_recovery_escrow_rotation_generated_runtime_section_096";
