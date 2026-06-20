use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type BridgeRecoveryResult<T> = Result<T, String>;

pub const BRIDGE_RECOVERY_PROTOCOL_VERSION: &str = "nebula-bridge-recovery-v1";
pub const BRIDGE_RECOVERY_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const BRIDGE_RECOVERY_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const BRIDGE_RECOVERY_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const BRIDGE_RECOVERY_DEFAULT_FINALITY_DEPTH: u64 = 10;
pub const BRIDGE_RECOVERY_DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 96;
pub const BRIDGE_RECOVERY_DEFAULT_STUCK_EXIT_GRACE_BLOCKS: u64 = 18;
pub const BRIDGE_RECOVERY_DEFAULT_STUCK_EXIT_RETRY_BLOCKS: u64 = 6;
pub const BRIDGE_RECOVERY_DEFAULT_RECOVERY_TICKET_TTL_BLOCKS: u64 = 144;
pub const BRIDGE_RECOVERY_DEFAULT_CLAIM_TTL_BLOCKS: u64 = 96;
pub const BRIDGE_RECOVERY_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 72;
pub const BRIDGE_RECOVERY_DEFAULT_DEFICIT_ESCALATION_BLOCKS: u64 = 24;
pub const BRIDGE_RECOVERY_DEFAULT_SIGNER_REPLACEMENT_GRACE_BLOCKS: u64 = 48;
pub const BRIDGE_RECOVERY_DEFAULT_PQ_ACTIVATION_BLOCKS: u64 = 4;
pub const BRIDGE_RECOVERY_DEFAULT_DELAYED_DRAIN_BATCH_LIMIT: u64 = 64;
pub const BRIDGE_RECOVERY_DEFAULT_MAX_OPEN_TICKETS: u64 = 512;
pub const BRIDGE_RECOVERY_DEFAULT_MAX_ACTIVE_QUARANTINES: u64 = 128;
pub const BRIDGE_RECOVERY_DEFAULT_WATCHTOWER_QUORUM: u64 = 2;
pub const BRIDGE_RECOVERY_DEFAULT_GUARDIAN_QUORUM: u64 = 2;
pub const BRIDGE_RECOVERY_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const BRIDGE_RECOVERY_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_500;
pub const BRIDGE_RECOVERY_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoverySeverity {
    Info,
    Watch,
    Degraded,
    Critical,
    Emergency,
}

impl RecoverySeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Degraded => "degraded",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }

    pub fn requires_guardian_quorum(self) -> bool {
        matches!(self, Self::Critical | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPriority {
    Low,
    Normal,
    High,
    Emergency,
}

impl RecoveryPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryActionKind {
    ReorgQuarantine,
    StuckExitRecovery,
    ReserveDeficitRemediation,
    SignerReplacement,
    PqEmergencyRotation,
    DelayedReleaseDrain,
    UserClaimProof,
    LowFeeSponsorship,
    AuditTrail,
    SlashingEvidence,
}

impl RecoveryActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReorgQuarantine => "reorg_quarantine",
            Self::StuckExitRecovery => "stuck_exit_recovery",
            Self::ReserveDeficitRemediation => "reserve_deficit_remediation",
            Self::SignerReplacement => "signer_replacement",
            Self::PqEmergencyRotation => "pq_emergency_rotation",
            Self::DelayedReleaseDrain => "delayed_release_drain",
            Self::UserClaimProof => "user_claim_proof",
            Self::LowFeeSponsorship => "low_fee_sponsorship",
            Self::AuditTrail => "audit_trail",
            Self::SlashingEvidence => "slashing_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessAttestationStatus {
    Fresh,
    Superseded,
    Expired,
    Revoked,
}

impl WitnessAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgQuarantineStatus {
    Observed,
    Quarantined,
    ProvedBenign,
    Released,
    Slashed,
    Expired,
}

impl ReorgQuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Quarantined => "quarantined",
            Self::ProvedBenign => "proved_benign",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Observed | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StuckExitStatus {
    Detected,
    Sponsored,
    Rebroadcast,
    Requeued,
    Claimed,
    Cancelled,
    Expired,
}

impl StuckExitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Sponsored => "sponsored",
            Self::Rebroadcast => "rebroadcast",
            Self::Requeued => "requeued",
            Self::Claimed => "claimed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Detected | Self::Sponsored | Self::Rebroadcast | Self::Requeued
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveDeficitStatus {
    Detected,
    Remediating,
    Backfilled,
    Insured,
    GovernanceEscalated,
    Resolved,
    Disputed,
}

impl ReserveDeficitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Remediating => "remediating",
            Self::Backfilled => "backfilled",
            Self::Insured => "insured",
            Self::GovernanceEscalated => "governance_escalated",
            Self::Resolved => "resolved",
            Self::Disputed => "disputed",
        }
    }

    pub fn is_unresolved(self) -> bool {
        matches!(
            self,
            Self::Detected | Self::Remediating | Self::GovernanceEscalated | Self::Disputed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerReplacementStatus {
    Proposed,
    Grace,
    Active,
    Retired,
    Revoked,
    Slashed,
    Expired,
}

impl SignerReplacementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Grace => "grace",
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_signatures(self) -> bool {
        matches!(self, Self::Grace | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRotationStatus {
    Prepared,
    Scheduled,
    Active,
    Cooldown,
    Completed,
    EmergencyCancelled,
}

impl PqRotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::Cooldown => "cooldown",
            Self::Completed => "completed",
            Self::EmergencyCancelled => "emergency_cancelled",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Scheduled | Self::Active | Self::Cooldown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainStatus {
    Scheduled,
    Draining,
    Paused,
    Completed,
    Cancelled,
    Expired,
}

impl DrainStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Scheduled | Self::Draining | Self::Paused)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryTicketStatus {
    Open,
    Assigned,
    Executing,
    AwaitingClaim,
    Resolved,
    Cancelled,
    Expired,
}

impl RecoveryTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Assigned => "assigned",
            Self::Executing => "executing",
            Self::AwaitingClaim => "awaiting_claim",
            Self::Resolved => "resolved",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Assigned | Self::Executing | Self::AwaitingClaim
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimProofStatus {
    Submitted,
    Accepted,
    Challenged,
    Paid,
    Rejected,
    Expired,
}

impl ClaimProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn blocks_replay(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted | Self::Paid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Reimbursed,
    Cancelled,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reimbursed => "reimbursed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    Observation,
    Decision,
    StateTransition,
    Governance,
    ExternalProof,
    Settlement,
    Alert,
}

impl AuditEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Decision => "decision",
            Self::StateTransition => "state_transition",
            Self::Governance => "governance",
            Self::ExternalProof => "external_proof",
            Self::Settlement => "settlement",
            Self::Alert => "alert",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceStatus {
    Collected,
    Submitted,
    Slashable,
    Executed,
    Rejected,
    Expired,
}

impl SlashingEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collected => "collected",
            Self::Submitted => "submitted",
            Self::Slashable => "slashable",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn slashable(self) -> bool {
        matches!(self, Self::Submitted | Self::Slashable)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRecoveryConfig {
    pub config_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub finality_depth: u64,
    pub quarantine_ttl_blocks: u64,
    pub stuck_exit_grace_blocks: u64,
    pub stuck_exit_retry_blocks: u64,
    pub recovery_ticket_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub deficit_escalation_blocks: u64,
    pub signer_replacement_grace_blocks: u64,
    pub pq_emergency_activation_blocks: u64,
    pub delayed_drain_batch_limit: u64,
    pub max_open_recovery_tickets: u64,
    pub max_active_quarantines: u64,
    pub min_watchtower_quorum: u64,
    pub min_guardian_quorum: u64,
    pub min_reserve_coverage_bps: u64,
    pub low_fee_sponsor_rebate_bps: u64,
    pub require_pq_rotation_for_emergency: bool,
    pub status: String,
}

impl Default for BridgeRecoveryConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            monero_network: BRIDGE_RECOVERY_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: BRIDGE_RECOVERY_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: BRIDGE_RECOVERY_DEVNET_FEE_ASSET_ID.to_string(),
            finality_depth: BRIDGE_RECOVERY_DEFAULT_FINALITY_DEPTH,
            quarantine_ttl_blocks: BRIDGE_RECOVERY_DEFAULT_QUARANTINE_TTL_BLOCKS,
            stuck_exit_grace_blocks: BRIDGE_RECOVERY_DEFAULT_STUCK_EXIT_GRACE_BLOCKS,
            stuck_exit_retry_blocks: BRIDGE_RECOVERY_DEFAULT_STUCK_EXIT_RETRY_BLOCKS,
            recovery_ticket_ttl_blocks: BRIDGE_RECOVERY_DEFAULT_RECOVERY_TICKET_TTL_BLOCKS,
            claim_ttl_blocks: BRIDGE_RECOVERY_DEFAULT_CLAIM_TTL_BLOCKS,
            sponsorship_ttl_blocks: BRIDGE_RECOVERY_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            deficit_escalation_blocks: BRIDGE_RECOVERY_DEFAULT_DEFICIT_ESCALATION_BLOCKS,
            signer_replacement_grace_blocks:
                BRIDGE_RECOVERY_DEFAULT_SIGNER_REPLACEMENT_GRACE_BLOCKS,
            pq_emergency_activation_blocks: BRIDGE_RECOVERY_DEFAULT_PQ_ACTIVATION_BLOCKS,
            delayed_drain_batch_limit: BRIDGE_RECOVERY_DEFAULT_DELAYED_DRAIN_BATCH_LIMIT,
            max_open_recovery_tickets: BRIDGE_RECOVERY_DEFAULT_MAX_OPEN_TICKETS,
            max_active_quarantines: BRIDGE_RECOVERY_DEFAULT_MAX_ACTIVE_QUARANTINES,
            min_watchtower_quorum: BRIDGE_RECOVERY_DEFAULT_WATCHTOWER_QUORUM,
            min_guardian_quorum: BRIDGE_RECOVERY_DEFAULT_GUARDIAN_QUORUM,
            min_reserve_coverage_bps: BRIDGE_RECOVERY_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            low_fee_sponsor_rebate_bps: BRIDGE_RECOVERY_DEFAULT_LOW_FEE_REBATE_BPS,
            require_pq_rotation_for_emergency: true,
            status: "active".to_string(),
        };
        config.config_id = bridge_recovery_config_id(&config.identity_record());
        config
    }
}

impl BridgeRecoveryConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_config_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "finality_depth": self.finality_depth,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "stuck_exit_grace_blocks": self.stuck_exit_grace_blocks,
            "stuck_exit_retry_blocks": self.stuck_exit_retry_blocks,
            "recovery_ticket_ttl_blocks": self.recovery_ticket_ttl_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "deficit_escalation_blocks": self.deficit_escalation_blocks,
            "signer_replacement_grace_blocks": self.signer_replacement_grace_blocks,
            "pq_emergency_activation_blocks": self.pq_emergency_activation_blocks,
            "delayed_drain_batch_limit": self.delayed_drain_batch_limit,
            "max_open_recovery_tickets": self.max_open_recovery_tickets,
            "max_active_quarantines": self.max_active_quarantines,
            "min_watchtower_quorum": self.min_watchtower_quorum,
            "min_guardian_quorum": self.min_guardian_quorum,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "low_fee_sponsor_rebate_bps": self.low_fee_sponsor_rebate_bps,
            "require_pq_rotation_for_emergency": self.require_pq_rotation_for_emergency,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("bridge recovery config identity record object");
        object.insert(
            "kind".to_string(),
            Value::String("bridge_recovery_config".to_string()),
        );
        object.insert(
            "config_id".to_string(),
            Value::String(self.config_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert("config_root".to_string(), Value::String(self.config_root()));
        record
    }

    pub fn config_root(&self) -> String {
        bridge_recovery_payload_root("BRIDGE-RECOVERY-CONFIG", &self.identity_record())
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.config_id, "bridge recovery config id")?;
        ensure_non_empty(&self.monero_network, "bridge recovery monero network")?;
        ensure_non_empty(&self.asset_id, "bridge recovery asset id")?;
        ensure_non_empty(&self.fee_asset_id, "bridge recovery fee asset id")?;
        ensure_positive(self.finality_depth, "bridge recovery finality depth")?;
        ensure_positive(self.quarantine_ttl_blocks, "bridge recovery quarantine ttl")?;
        ensure_positive(
            self.stuck_exit_grace_blocks,
            "bridge recovery stuck exit grace",
        )?;
        ensure_positive(
            self.stuck_exit_retry_blocks,
            "bridge recovery stuck exit retry",
        )?;
        ensure_positive(
            self.recovery_ticket_ttl_blocks,
            "bridge recovery ticket ttl",
        )?;
        ensure_positive(self.claim_ttl_blocks, "bridge recovery claim ttl")?;
        ensure_positive(
            self.sponsorship_ttl_blocks,
            "bridge recovery sponsorship ttl",
        )?;
        ensure_positive(
            self.deficit_escalation_blocks,
            "bridge recovery deficit escalation",
        )?;
        ensure_positive(
            self.signer_replacement_grace_blocks,
            "bridge recovery signer grace",
        )?;
        ensure_positive(
            self.pq_emergency_activation_blocks,
            "bridge recovery pq activation",
        )?;
        ensure_positive(
            self.delayed_drain_batch_limit,
            "bridge recovery delayed drain batch limit",
        )?;
        ensure_positive(
            self.max_open_recovery_tickets,
            "bridge recovery max open tickets",
        )?;
        ensure_positive(
            self.max_active_quarantines,
            "bridge recovery max active quarantines",
        )?;
        ensure_positive(
            self.min_watchtower_quorum,
            "bridge recovery watchtower quorum",
        )?;
        ensure_positive(self.min_guardian_quorum, "bridge recovery guardian quorum")?;
        ensure_bps(
            self.min_reserve_coverage_bps,
            "bridge recovery reserve coverage bps",
        )?;
        ensure_bps(
            self.low_fee_sponsor_rebate_bps,
            "bridge recovery low fee rebate bps",
        )?;
        let expected = bridge_recovery_config_id(&self.identity_record());
        if self.config_id != expected {
            return Err("bridge recovery config id does not match identity".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryWitnessAttestation {
    pub attestation_id: String,
    pub witness_label: String,
    pub witness_public_key_root: String,
    pub witness_role: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub observed_height: u64,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub signature_root: String,
    pub status: WitnessAttestationStatus,
}

impl RecoveryWitnessAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        witness_label: impl Into<String>,
        witness_public_key_root: impl Into<String>,
        witness_role: impl Into<String>,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        observed_height: u64,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> BridgeRecoveryResult<Self> {
        let witness_label = witness_label.into();
        let witness_public_key_root = witness_public_key_root.into();
        let witness_role = witness_role.into();
        let subject_kind = subject_kind.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let signature_root = bridge_recovery_signature_root(
            "BRIDGE-RECOVERY-WITNESS-SIGNATURE",
            &witness_label,
            &subject_root,
            signed_at_height,
        );
        let mut attestation = Self {
            attestation_id: String::new(),
            witness_label,
            witness_public_key_root,
            witness_role,
            subject_kind,
            subject_id,
            subject_root,
            observed_height,
            signed_at_height,
            expires_at_height,
            signature_root,
            status: WitnessAttestationStatus::Fresh,
        };
        attestation.attestation_id =
            bridge_recovery_witness_attestation_id(&attestation.identity_record());
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_witness_attestation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "witness_label": self.witness_label,
            "witness_role": self.witness_role,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "observed_height": self.observed_height,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_witness_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "witness_label": self.witness_label,
            "witness_public_key_root": self.witness_public_key_root,
            "witness_role": self.witness_role,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "observed_height": self.observed_height,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-WITNESS-ATTESTATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "attestation_root",
            self.attestation_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == WitnessAttestationStatus::Fresh && height > self.expires_at_height {
            self.status = WitnessAttestationStatus::Expired;
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.attestation_id, "bridge recovery attestation id")?;
        ensure_non_empty(&self.witness_label, "bridge recovery witness label")?;
        ensure_non_empty(
            &self.witness_public_key_root,
            "bridge recovery witness key root",
        )?;
        ensure_non_empty(&self.witness_role, "bridge recovery witness role")?;
        ensure_non_empty(
            &self.subject_kind,
            "bridge recovery attestation subject kind",
        )?;
        ensure_non_empty(&self.subject_id, "bridge recovery attestation subject id")?;
        ensure_non_empty(
            &self.subject_root,
            "bridge recovery attestation subject root",
        )?;
        ensure_non_empty(
            &self.signature_root,
            "bridge recovery attestation signature",
        )?;
        if self.expires_at_height <= self.signed_at_height {
            return Err("bridge recovery attestation expiry must follow signature".to_string());
        }
        if self.observed_height > self.signed_at_height {
            return Err("bridge recovery attestation observed after signed height".to_string());
        }
        let expected = bridge_recovery_witness_attestation_id(&self.identity_record());
        if self.attestation_id != expected {
            return Err("bridge recovery attestation id does not match identity".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgQuarantine {
    pub quarantine_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub trigger_txid_hash: String,
    pub old_block_height: u64,
    pub old_block_hash: String,
    pub new_block_height: u64,
    pub new_block_hash: String,
    pub affected_output_root: String,
    pub affected_withdrawal_ids: Vec<String>,
    pub amount_units: u64,
    pub detected_at_height: u64,
    pub quarantine_until_height: u64,
    pub witness_attestation_ids: Vec<String>,
    pub evidence_root: String,
    pub release_authority_root: String,
    pub status: ReorgQuarantineStatus,
    pub severity: RecoverySeverity,
}

impl ReorgQuarantine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        monero_network: impl Into<String>,
        asset_id: impl Into<String>,
        trigger_txid_hash: impl Into<String>,
        old_block_height: u64,
        old_block_hash: impl Into<String>,
        new_block_height: u64,
        new_block_hash: impl Into<String>,
        affected_output_root: impl Into<String>,
        affected_withdrawal_ids: Vec<String>,
        amount_units: u64,
        detected_at_height: u64,
        quarantine_until_height: u64,
        witness_attestation_ids: Vec<String>,
        evidence_root: impl Into<String>,
        release_authority_root: impl Into<String>,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let mut quarantine = Self {
            quarantine_id: String::new(),
            monero_network: monero_network.into(),
            asset_id: asset_id.into(),
            trigger_txid_hash: trigger_txid_hash.into(),
            old_block_height,
            old_block_hash: old_block_hash.into(),
            new_block_height,
            new_block_hash: new_block_hash.into(),
            affected_output_root: affected_output_root.into(),
            affected_withdrawal_ids: ordered_strings(&affected_withdrawal_ids),
            amount_units,
            detected_at_height,
            quarantine_until_height,
            witness_attestation_ids: ordered_strings(&witness_attestation_ids),
            evidence_root: evidence_root.into(),
            release_authority_root: release_authority_root.into(),
            status: ReorgQuarantineStatus::Quarantined,
            severity,
        };
        quarantine.quarantine_id =
            bridge_recovery_reorg_quarantine_id(&quarantine.identity_record());
        quarantine.validate()?;
        Ok(quarantine)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_reorg_quarantine_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "trigger_txid_hash": self.trigger_txid_hash,
            "old_block_height": self.old_block_height,
            "old_block_hash": self.old_block_hash,
            "new_block_height": self.new_block_height,
            "new_block_hash": self.new_block_hash,
            "affected_output_root": self.affected_output_root,
            "detected_at_height": self.detected_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_reorg_quarantine",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "quarantine_id": self.quarantine_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "trigger_txid_hash": self.trigger_txid_hash,
            "old_block_height": self.old_block_height,
            "old_block_hash": self.old_block_hash,
            "new_block_height": self.new_block_height,
            "new_block_hash": self.new_block_hash,
            "affected_output_root": self.affected_output_root,
            "affected_withdrawal_ids": self.affected_withdrawal_ids,
            "amount_units": self.amount_units,
            "detected_at_height": self.detected_at_height,
            "quarantine_until_height": self.quarantine_until_height,
            "witness_attestation_ids": self.witness_attestation_ids,
            "evidence_root": self.evidence_root,
            "release_authority_root": self.release_authority_root,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
        })
    }

    pub fn quarantine_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-REORG-QUARANTINE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "quarantine_root",
            self.quarantine_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_active() && height > self.quarantine_until_height {
            self.status = ReorgQuarantineStatus::Expired;
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.quarantine_id, "bridge recovery quarantine id")?;
        ensure_non_empty(&self.monero_network, "bridge recovery quarantine network")?;
        ensure_non_empty(&self.asset_id, "bridge recovery quarantine asset")?;
        ensure_non_empty(&self.trigger_txid_hash, "bridge recovery quarantine txid")?;
        ensure_non_empty(&self.old_block_hash, "bridge recovery old block hash")?;
        ensure_non_empty(&self.new_block_hash, "bridge recovery new block hash")?;
        ensure_non_empty(
            &self.affected_output_root,
            "bridge recovery affected output root",
        )?;
        ensure_non_empty(
            &self.evidence_root,
            "bridge recovery quarantine evidence root",
        )?;
        ensure_non_empty(
            &self.release_authority_root,
            "bridge recovery release authority root",
        )?;
        if self.old_block_height == self.new_block_height
            && self.old_block_hash == self.new_block_hash
        {
            return Err("bridge recovery quarantine must describe a competing block".to_string());
        }
        if self.quarantine_until_height <= self.detected_at_height {
            return Err("bridge recovery quarantine expiry must follow detection".to_string());
        }
        ensure_unique_strings(
            &self.affected_withdrawal_ids,
            "bridge recovery affected withdrawal ids",
        )?;
        ensure_unique_strings(
            &self.witness_attestation_ids,
            "bridge recovery quarantine witness ids",
        )?;
        let expected = bridge_recovery_reorg_quarantine_id(&self.identity_record());
        if self.quarantine_id != expected {
            return Err("bridge recovery quarantine id does not match identity".to_string());
        }
        Ok(self.quarantine_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StuckExitRecovery {
    pub recovery_id: String,
    pub withdrawal_id: String,
    pub exit_id: String,
    pub account_commitment: String,
    pub recipient_address_hash: String,
    pub asset_id: String,
    pub amount_units: u64,
    pub original_fee_units: u64,
    pub sponsor_fee_units: u64,
    pub detected_at_height: u64,
    pub last_broadcast_height: u64,
    pub retry_count: u64,
    pub next_retry_height: u64,
    pub expires_at_height: u64,
    pub quarantine_id: Option<String>,
    pub sponsorship_id: Option<String>,
    pub recovery_ticket_id: Option<String>,
    pub replacement_tx_root: String,
    pub status: StuckExitStatus,
    pub severity: RecoverySeverity,
}

impl StuckExitRecovery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: impl Into<String>,
        exit_id: impl Into<String>,
        account_commitment: impl Into<String>,
        recipient_address_hash: impl Into<String>,
        asset_id: impl Into<String>,
        amount_units: u64,
        original_fee_units: u64,
        detected_at_height: u64,
        retry_after_blocks: u64,
        expires_at_height: u64,
        quarantine_id: Option<String>,
        sponsorship_id: Option<String>,
        recovery_ticket_id: Option<String>,
        replacement_tx_root: impl Into<String>,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let mut recovery = Self {
            recovery_id: String::new(),
            withdrawal_id: withdrawal_id.into(),
            exit_id: exit_id.into(),
            account_commitment: account_commitment.into(),
            recipient_address_hash: recipient_address_hash.into(),
            asset_id: asset_id.into(),
            amount_units,
            original_fee_units,
            sponsor_fee_units: 0,
            detected_at_height,
            last_broadcast_height: detected_at_height,
            retry_count: 0,
            next_retry_height: detected_at_height.saturating_add(retry_after_blocks),
            expires_at_height,
            quarantine_id,
            sponsorship_id,
            recovery_ticket_id,
            replacement_tx_root: replacement_tx_root.into(),
            status: StuckExitStatus::Detected,
            severity,
        };
        recovery.recovery_id = bridge_recovery_stuck_exit_id(&recovery.identity_record());
        recovery.validate()?;
        Ok(recovery)
    }

    pub fn with_sponsor_fee(mut self, sponsor_fee_units: u64) -> BridgeRecoveryResult<Self> {
        self.sponsor_fee_units = sponsor_fee_units;
        if sponsor_fee_units > 0 && self.status == StuckExitStatus::Detected {
            self.status = StuckExitStatus::Sponsored;
        }
        self.validate()?;
        Ok(self)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_stuck_exit_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "exit_id": self.exit_id,
            "account_commitment": self.account_commitment,
            "recipient_address_hash": self.recipient_address_hash,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "detected_at_height": self.detected_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_stuck_exit",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "recovery_id": self.recovery_id,
            "withdrawal_id": self.withdrawal_id,
            "exit_id": self.exit_id,
            "account_commitment": self.account_commitment,
            "recipient_address_hash": self.recipient_address_hash,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "original_fee_units": self.original_fee_units,
            "sponsor_fee_units": self.sponsor_fee_units,
            "detected_at_height": self.detected_at_height,
            "last_broadcast_height": self.last_broadcast_height,
            "retry_count": self.retry_count,
            "next_retry_height": self.next_retry_height,
            "expires_at_height": self.expires_at_height,
            "quarantine_id": self.quarantine_id,
            "sponsorship_id": self.sponsorship_id,
            "recovery_ticket_id": self.recovery_ticket_id,
            "replacement_tx_root": self.replacement_tx_root,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
        })
    }

    pub fn recovery_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-STUCK-EXIT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "recovery_root",
            self.recovery_root(),
        )
    }

    pub fn set_height(&mut self, height: u64, retry_after_blocks: u64) {
        if self.status.is_open() && height > self.expires_at_height {
            self.status = StuckExitStatus::Expired;
            return;
        }
        if self.status.is_open() && height >= self.next_retry_height {
            self.status = StuckExitStatus::Requeued;
            self.retry_count = self.retry_count.saturating_add(1);
            self.last_broadcast_height = height;
            self.next_retry_height = height.saturating_add(retry_after_blocks);
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.recovery_id, "bridge recovery stuck exit id")?;
        ensure_non_empty(&self.withdrawal_id, "bridge recovery withdrawal id")?;
        ensure_non_empty(&self.exit_id, "bridge recovery exit id")?;
        ensure_non_empty(
            &self.account_commitment,
            "bridge recovery account commitment",
        )?;
        ensure_non_empty(
            &self.recipient_address_hash,
            "bridge recovery recipient address hash",
        )?;
        ensure_non_empty(&self.asset_id, "bridge recovery stuck exit asset")?;
        ensure_positive(self.amount_units, "bridge recovery stuck exit amount")?;
        ensure_non_empty(
            &self.replacement_tx_root,
            "bridge recovery replacement tx root",
        )?;
        if self.expires_at_height <= self.detected_at_height {
            return Err("bridge recovery stuck exit expiry must follow detection".to_string());
        }
        if self.last_broadcast_height < self.detected_at_height {
            return Err("bridge recovery stuck exit broadcast before detection".to_string());
        }
        let expected = bridge_recovery_stuck_exit_id(&self.identity_record());
        if self.recovery_id != expected {
            return Err("bridge recovery stuck exit id does not match identity".to_string());
        }
        Ok(self.recovery_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveDeficitRemediation {
    pub remediation_id: String,
    pub asset_id: String,
    pub monero_network: String,
    pub checkpoint_id: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub observed_reserve_units: u64,
    pub required_liability_units: u64,
    pub deficit_units: u64,
    pub insurance_available_units: u64,
    pub backfill_commitment_root: String,
    pub opened_height: u64,
    pub escalation_height: u64,
    pub resolved_height: Option<u64>,
    pub witness_attestation_ids: Vec<String>,
    pub status: ReserveDeficitStatus,
    pub severity: RecoverySeverity,
}

impl ReserveDeficitRemediation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        asset_id: impl Into<String>,
        monero_network: impl Into<String>,
        checkpoint_id: impl Into<String>,
        reserve_root: impl Into<String>,
        liability_root: impl Into<String>,
        observed_reserve_units: u64,
        required_liability_units: u64,
        insurance_available_units: u64,
        backfill_commitment_root: impl Into<String>,
        opened_height: u64,
        escalation_height: u64,
        witness_attestation_ids: Vec<String>,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let deficit_units = required_liability_units.saturating_sub(observed_reserve_units);
        let mut remediation = Self {
            remediation_id: String::new(),
            asset_id: asset_id.into(),
            monero_network: monero_network.into(),
            checkpoint_id: checkpoint_id.into(),
            reserve_root: reserve_root.into(),
            liability_root: liability_root.into(),
            observed_reserve_units,
            required_liability_units,
            deficit_units,
            insurance_available_units,
            backfill_commitment_root: backfill_commitment_root.into(),
            opened_height,
            escalation_height,
            resolved_height: None,
            witness_attestation_ids: ordered_strings(&witness_attestation_ids),
            status: if deficit_units == 0 {
                ReserveDeficitStatus::Resolved
            } else {
                ReserveDeficitStatus::Detected
            },
            severity,
        };
        remediation.remediation_id =
            bridge_recovery_reserve_deficit_id(&remediation.identity_record());
        remediation.validate()?;
        Ok(remediation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_reserve_deficit_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "asset_id": self.asset_id,
            "monero_network": self.monero_network,
            "checkpoint_id": self.checkpoint_id,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "observed_reserve_units": self.observed_reserve_units,
            "required_liability_units": self.required_liability_units,
            "opened_height": self.opened_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_reserve_deficit",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "remediation_id": self.remediation_id,
            "asset_id": self.asset_id,
            "monero_network": self.monero_network,
            "checkpoint_id": self.checkpoint_id,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "observed_reserve_units": self.observed_reserve_units,
            "required_liability_units": self.required_liability_units,
            "deficit_units": self.deficit_units,
            "insurance_available_units": self.insurance_available_units,
            "backfill_commitment_root": self.backfill_commitment_root,
            "opened_height": self.opened_height,
            "escalation_height": self.escalation_height,
            "resolved_height": self.resolved_height,
            "witness_attestation_ids": self.witness_attestation_ids,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
        })
    }

    pub fn remediation_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-RESERVE-DEFICIT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "remediation_root",
            self.remediation_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == ReserveDeficitStatus::Detected && height >= self.escalation_height {
            self.status = ReserveDeficitStatus::GovernanceEscalated;
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.remediation_id, "bridge recovery reserve deficit id")?;
        ensure_non_empty(&self.asset_id, "bridge recovery reserve deficit asset")?;
        ensure_non_empty(&self.monero_network, "bridge recovery reserve network")?;
        ensure_non_empty(&self.checkpoint_id, "bridge recovery reserve checkpoint")?;
        ensure_non_empty(&self.reserve_root, "bridge recovery reserve root")?;
        ensure_non_empty(&self.liability_root, "bridge recovery liability root")?;
        ensure_non_empty(
            &self.backfill_commitment_root,
            "bridge recovery backfill root",
        )?;
        if self.deficit_units
            != self
                .required_liability_units
                .saturating_sub(self.observed_reserve_units)
        {
            return Err("bridge recovery reserve deficit units mismatch".to_string());
        }
        if self.escalation_height <= self.opened_height && self.deficit_units > 0 {
            return Err("bridge recovery deficit escalation must follow opening".to_string());
        }
        if let Some(resolved_height) = self.resolved_height {
            if resolved_height < self.opened_height {
                return Err("bridge recovery deficit resolved before opening".to_string());
            }
        }
        ensure_unique_strings(
            &self.witness_attestation_ids,
            "bridge recovery reserve witness ids",
        )?;
        let expected = bridge_recovery_reserve_deficit_id(&self.identity_record());
        if self.remediation_id != expected {
            return Err("bridge recovery reserve deficit id does not match identity".to_string());
        }
        Ok(self.remediation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerReplacement {
    pub replacement_id: String,
    pub old_signer_id: String,
    pub new_signer_id: String,
    pub signer_set_id: String,
    pub old_signer_key_root: String,
    pub new_signer_key_root: String,
    pub reason: String,
    pub evidence_root: String,
    pub proposed_at_height: u64,
    pub activate_at_height: u64,
    pub grace_until_height: u64,
    pub retired_at_height: Option<u64>,
    pub guardian_attestation_ids: Vec<String>,
    pub status: SignerReplacementStatus,
    pub severity: RecoverySeverity,
}

impl SignerReplacement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        old_signer_id: impl Into<String>,
        new_signer_id: impl Into<String>,
        signer_set_id: impl Into<String>,
        old_signer_key_root: impl Into<String>,
        new_signer_key_root: impl Into<String>,
        reason: impl Into<String>,
        evidence_root: impl Into<String>,
        proposed_at_height: u64,
        activate_at_height: u64,
        grace_until_height: u64,
        guardian_attestation_ids: Vec<String>,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let mut replacement = Self {
            replacement_id: String::new(),
            old_signer_id: old_signer_id.into(),
            new_signer_id: new_signer_id.into(),
            signer_set_id: signer_set_id.into(),
            old_signer_key_root: old_signer_key_root.into(),
            new_signer_key_root: new_signer_key_root.into(),
            reason: reason.into(),
            evidence_root: evidence_root.into(),
            proposed_at_height,
            activate_at_height,
            grace_until_height,
            retired_at_height: None,
            guardian_attestation_ids: ordered_strings(&guardian_attestation_ids),
            status: SignerReplacementStatus::Proposed,
            severity,
        };
        replacement.replacement_id =
            bridge_recovery_signer_replacement_id(&replacement.identity_record());
        replacement.validate()?;
        Ok(replacement)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_signer_replacement_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "old_signer_id": self.old_signer_id,
            "new_signer_id": self.new_signer_id,
            "signer_set_id": self.signer_set_id,
            "old_signer_key_root": self.old_signer_key_root,
            "new_signer_key_root": self.new_signer_key_root,
            "proposed_at_height": self.proposed_at_height,
            "activate_at_height": self.activate_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_signer_replacement",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "replacement_id": self.replacement_id,
            "old_signer_id": self.old_signer_id,
            "new_signer_id": self.new_signer_id,
            "signer_set_id": self.signer_set_id,
            "old_signer_key_root": self.old_signer_key_root,
            "new_signer_key_root": self.new_signer_key_root,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "proposed_at_height": self.proposed_at_height,
            "activate_at_height": self.activate_at_height,
            "grace_until_height": self.grace_until_height,
            "retired_at_height": self.retired_at_height,
            "guardian_attestation_ids": self.guardian_attestation_ids,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
        })
    }

    pub fn replacement_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-SIGNER-REPLACEMENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "replacement_root",
            self.replacement_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == SignerReplacementStatus::Proposed && height >= self.activate_at_height {
            self.status = SignerReplacementStatus::Active;
        }
        if self.status == SignerReplacementStatus::Active && height > self.grace_until_height {
            self.status = SignerReplacementStatus::Retired;
            self.retired_at_height.get_or_insert(height);
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(
            &self.replacement_id,
            "bridge recovery signer replacement id",
        )?;
        ensure_non_empty(&self.old_signer_id, "bridge recovery old signer id")?;
        ensure_non_empty(&self.new_signer_id, "bridge recovery new signer id")?;
        ensure_non_empty(&self.signer_set_id, "bridge recovery signer set id")?;
        ensure_non_empty(&self.old_signer_key_root, "bridge recovery old signer key")?;
        ensure_non_empty(&self.new_signer_key_root, "bridge recovery new signer key")?;
        ensure_non_empty(&self.reason, "bridge recovery signer replacement reason")?;
        ensure_non_empty(&self.evidence_root, "bridge recovery signer evidence")?;
        if self.old_signer_id == self.new_signer_id {
            return Err("bridge recovery signer replacement must change signer".to_string());
        }
        if self.activate_at_height < self.proposed_at_height {
            return Err("bridge recovery signer activation before proposal".to_string());
        }
        if self.grace_until_height <= self.activate_at_height {
            return Err("bridge recovery signer grace must follow activation".to_string());
        }
        ensure_unique_strings(
            &self.guardian_attestation_ids,
            "bridge recovery signer guardian ids",
        )?;
        let expected = bridge_recovery_signer_replacement_id(&self.identity_record());
        if self.replacement_id != expected {
            return Err(
                "bridge recovery signer replacement id does not match identity".to_string(),
            );
        }
        Ok(self.replacement_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqEmergencyRotation {
    pub rotation_id: String,
    pub rotation_label: String,
    pub previous_committee_root: String,
    pub next_committee_root: String,
    pub kyber_epoch_root: String,
    pub falcon_epoch_root: String,
    pub dilithium_epoch_root: String,
    pub hybrid_transcript_root: String,
    pub signer_replacement_id: Option<String>,
    pub emergency: bool,
    pub scheduled_at_height: u64,
    pub activate_at_height: u64,
    pub cooldown_until_height: u64,
    pub guardian_attestation_ids: Vec<String>,
    pub status: PqRotationStatus,
    pub severity: RecoverySeverity,
}

impl PqEmergencyRotation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rotation_label: impl Into<String>,
        previous_committee_root: impl Into<String>,
        next_committee_root: impl Into<String>,
        kyber_epoch_root: impl Into<String>,
        falcon_epoch_root: impl Into<String>,
        dilithium_epoch_root: impl Into<String>,
        hybrid_transcript_root: impl Into<String>,
        signer_replacement_id: Option<String>,
        emergency: bool,
        scheduled_at_height: u64,
        activate_at_height: u64,
        cooldown_until_height: u64,
        guardian_attestation_ids: Vec<String>,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let mut rotation = Self {
            rotation_id: String::new(),
            rotation_label: rotation_label.into(),
            previous_committee_root: previous_committee_root.into(),
            next_committee_root: next_committee_root.into(),
            kyber_epoch_root: kyber_epoch_root.into(),
            falcon_epoch_root: falcon_epoch_root.into(),
            dilithium_epoch_root: dilithium_epoch_root.into(),
            hybrid_transcript_root: hybrid_transcript_root.into(),
            signer_replacement_id,
            emergency,
            scheduled_at_height,
            activate_at_height,
            cooldown_until_height,
            guardian_attestation_ids: ordered_strings(&guardian_attestation_ids),
            status: PqRotationStatus::Scheduled,
            severity,
        };
        rotation.rotation_id = bridge_recovery_pq_rotation_id(&rotation.identity_record());
        rotation.validate()?;
        Ok(rotation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_pq_rotation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "rotation_label": self.rotation_label,
            "previous_committee_root": self.previous_committee_root,
            "next_committee_root": self.next_committee_root,
            "hybrid_transcript_root": self.hybrid_transcript_root,
            "emergency": self.emergency,
            "scheduled_at_height": self.scheduled_at_height,
            "activate_at_height": self.activate_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_pq_emergency_rotation",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "rotation_id": self.rotation_id,
            "rotation_label": self.rotation_label,
            "previous_committee_root": self.previous_committee_root,
            "next_committee_root": self.next_committee_root,
            "kyber_epoch_root": self.kyber_epoch_root,
            "falcon_epoch_root": self.falcon_epoch_root,
            "dilithium_epoch_root": self.dilithium_epoch_root,
            "hybrid_transcript_root": self.hybrid_transcript_root,
            "signer_replacement_id": self.signer_replacement_id,
            "emergency": self.emergency,
            "scheduled_at_height": self.scheduled_at_height,
            "activate_at_height": self.activate_at_height,
            "cooldown_until_height": self.cooldown_until_height,
            "guardian_attestation_ids": self.guardian_attestation_ids,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
        })
    }

    pub fn rotation_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-PQ-EMERGENCY-ROTATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "rotation_root",
            self.rotation_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == PqRotationStatus::Scheduled && height >= self.activate_at_height {
            self.status = PqRotationStatus::Active;
        }
        if self.status == PqRotationStatus::Active && height > self.cooldown_until_height {
            self.status = PqRotationStatus::Completed;
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.rotation_id, "bridge recovery pq rotation id")?;
        ensure_non_empty(&self.rotation_label, "bridge recovery pq rotation label")?;
        ensure_non_empty(
            &self.previous_committee_root,
            "bridge recovery previous committee root",
        )?;
        ensure_non_empty(
            &self.next_committee_root,
            "bridge recovery next committee root",
        )?;
        ensure_non_empty(&self.kyber_epoch_root, "bridge recovery kyber root")?;
        ensure_non_empty(&self.falcon_epoch_root, "bridge recovery falcon root")?;
        ensure_non_empty(&self.dilithium_epoch_root, "bridge recovery dilithium root")?;
        ensure_non_empty(
            &self.hybrid_transcript_root,
            "bridge recovery hybrid transcript root",
        )?;
        if self.previous_committee_root == self.next_committee_root {
            return Err("bridge recovery pq rotation must change committee root".to_string());
        }
        if self.activate_at_height < self.scheduled_at_height {
            return Err("bridge recovery pq activation before schedule".to_string());
        }
        if self.cooldown_until_height <= self.activate_at_height {
            return Err("bridge recovery pq cooldown must follow activation".to_string());
        }
        ensure_unique_strings(
            &self.guardian_attestation_ids,
            "bridge recovery pq guardian ids",
        )?;
        let expected = bridge_recovery_pq_rotation_id(&self.identity_record());
        if self.rotation_id != expected {
            return Err("bridge recovery pq rotation id does not match identity".to_string());
        }
        Ok(self.rotation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedReleaseDrain {
    pub drain_id: String,
    pub lane_id: String,
    pub asset_id: String,
    pub queue_root: String,
    pub queue_item_ids: Vec<String>,
    pub stuck_exit_ids: Vec<String>,
    pub recovery_ticket_ids: Vec<String>,
    pub total_amount_units: u64,
    pub sponsor_fee_units: u64,
    pub scheduled_at_height: u64,
    pub start_height: u64,
    pub deadline_height: u64,
    pub completed_height: Option<u64>,
    pub operator_commitment: String,
    pub status: DrainStatus,
    pub severity: RecoverySeverity,
}

impl DelayedReleaseDrain {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: impl Into<String>,
        asset_id: impl Into<String>,
        queue_root: impl Into<String>,
        queue_item_ids: Vec<String>,
        stuck_exit_ids: Vec<String>,
        recovery_ticket_ids: Vec<String>,
        total_amount_units: u64,
        sponsor_fee_units: u64,
        scheduled_at_height: u64,
        start_height: u64,
        deadline_height: u64,
        operator_commitment: impl Into<String>,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let mut drain = Self {
            drain_id: String::new(),
            lane_id: lane_id.into(),
            asset_id: asset_id.into(),
            queue_root: queue_root.into(),
            queue_item_ids: ordered_strings(&queue_item_ids),
            stuck_exit_ids: ordered_strings(&stuck_exit_ids),
            recovery_ticket_ids: ordered_strings(&recovery_ticket_ids),
            total_amount_units,
            sponsor_fee_units,
            scheduled_at_height,
            start_height,
            deadline_height,
            completed_height: None,
            operator_commitment: operator_commitment.into(),
            status: DrainStatus::Scheduled,
            severity,
        };
        drain.drain_id = bridge_recovery_delayed_drain_id(&drain.identity_record());
        drain.validate()?;
        Ok(drain)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_delayed_drain_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "queue_root": self.queue_root,
            "queue_item_ids": self.queue_item_ids,
            "stuck_exit_ids": self.stuck_exit_ids,
            "scheduled_at_height": self.scheduled_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_delayed_release_drain",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "drain_id": self.drain_id,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "queue_root": self.queue_root,
            "queue_item_ids": self.queue_item_ids,
            "stuck_exit_ids": self.stuck_exit_ids,
            "recovery_ticket_ids": self.recovery_ticket_ids,
            "total_amount_units": self.total_amount_units,
            "sponsor_fee_units": self.sponsor_fee_units,
            "scheduled_at_height": self.scheduled_at_height,
            "start_height": self.start_height,
            "deadline_height": self.deadline_height,
            "completed_height": self.completed_height,
            "operator_commitment": self.operator_commitment,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
        })
    }

    pub fn drain_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-DELAYED-RELEASE-DRAIN",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "drain_root",
            self.drain_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == DrainStatus::Scheduled && height >= self.start_height {
            self.status = DrainStatus::Draining;
        }
        if self.status.is_open() && height > self.deadline_height {
            self.status = DrainStatus::Expired;
        }
    }

    pub fn mark_completed(&mut self, height: u64) -> BridgeRecoveryResult<String> {
        if height < self.start_height {
            return Err("bridge recovery drain cannot complete before start".to_string());
        }
        self.status = DrainStatus::Completed;
        self.completed_height = Some(height);
        self.validate()
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.drain_id, "bridge recovery drain id")?;
        ensure_non_empty(&self.lane_id, "bridge recovery drain lane")?;
        ensure_non_empty(&self.asset_id, "bridge recovery drain asset")?;
        ensure_non_empty(&self.queue_root, "bridge recovery drain queue root")?;
        ensure_non_empty(&self.operator_commitment, "bridge recovery drain operator")?;
        ensure_positive(self.total_amount_units, "bridge recovery drain amount")?;
        if self.queue_item_ids.is_empty() && self.stuck_exit_ids.is_empty() {
            return Err("bridge recovery drain must include queue or stuck exits".to_string());
        }
        if self.start_height < self.scheduled_at_height {
            return Err("bridge recovery drain start before schedule".to_string());
        }
        if self.deadline_height <= self.start_height {
            return Err("bridge recovery drain deadline must follow start".to_string());
        }
        ensure_unique_strings(&self.queue_item_ids, "bridge recovery drain queue ids")?;
        ensure_unique_strings(&self.stuck_exit_ids, "bridge recovery drain stuck exit ids")?;
        ensure_unique_strings(
            &self.recovery_ticket_ids,
            "bridge recovery drain ticket ids",
        )?;
        if let Some(completed_height) = self.completed_height {
            if completed_height < self.start_height {
                return Err("bridge recovery drain completed before start".to_string());
            }
        }
        let expected = bridge_recovery_delayed_drain_id(&self.identity_record());
        if self.drain_id != expected {
            return Err("bridge recovery drain id does not match identity".to_string());
        }
        Ok(self.drain_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryTicket {
    pub ticket_id: String,
    pub requester_commitment: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub requested_action: RecoveryActionKind,
    pub priority: RecoveryPriority,
    pub opened_at_height: u64,
    pub assigned_operator: Option<String>,
    pub assigned_at_height: Option<u64>,
    pub expires_at_height: u64,
    pub resolution_root: Option<String>,
    pub status: RecoveryTicketStatus,
    pub severity: RecoverySeverity,
    pub notes_root: String,
}

impl RecoveryTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requester_commitment: impl Into<String>,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        requested_action: RecoveryActionKind,
        priority: RecoveryPriority,
        opened_at_height: u64,
        expires_at_height: u64,
        severity: RecoverySeverity,
        notes_root: impl Into<String>,
    ) -> BridgeRecoveryResult<Self> {
        let mut ticket = Self {
            ticket_id: String::new(),
            requester_commitment: requester_commitment.into(),
            subject_kind: subject_kind.into(),
            subject_id: subject_id.into(),
            subject_root: subject_root.into(),
            requested_action,
            priority,
            opened_at_height,
            assigned_operator: None,
            assigned_at_height: None,
            expires_at_height,
            resolution_root: None,
            status: RecoveryTicketStatus::Open,
            severity,
            notes_root: notes_root.into(),
        };
        ticket.ticket_id = bridge_recovery_ticket_id(&ticket.identity_record());
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn assign(
        &mut self,
        operator_commitment: impl Into<String>,
        assigned_at_height: u64,
    ) -> BridgeRecoveryResult<String> {
        if assigned_at_height < self.opened_at_height {
            return Err("bridge recovery ticket assignment before opening".to_string());
        }
        self.assigned_operator = Some(operator_commitment.into());
        self.assigned_at_height = Some(assigned_at_height);
        self.status = RecoveryTicketStatus::Assigned;
        self.validate()
    }

    pub fn resolve(
        &mut self,
        resolution_root: impl Into<String>,
        resolved_at_height: u64,
    ) -> BridgeRecoveryResult<String> {
        if resolved_at_height < self.opened_at_height {
            return Err("bridge recovery ticket resolved before opening".to_string());
        }
        self.resolution_root = Some(resolution_root.into());
        self.status = RecoveryTicketStatus::Resolved;
        self.validate()
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_ticket_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "requester_commitment": self.requester_commitment,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "requested_action": self.requested_action.as_str(),
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "requester_commitment": self.requester_commitment,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "requested_action": self.requested_action.as_str(),
            "priority": self.priority.as_str(),
            "opened_at_height": self.opened_at_height,
            "assigned_operator": self.assigned_operator,
            "assigned_at_height": self.assigned_at_height,
            "expires_at_height": self.expires_at_height,
            "resolution_root": self.resolution_root,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "notes_root": self.notes_root,
        })
    }

    pub fn ticket_root(&self) -> String {
        bridge_recovery_payload_root("BRIDGE-RECOVERY-TICKET", &self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "ticket_root",
            self.ticket_root(),
        )
    }

    pub fn subject_key(&self) -> String {
        format!("{}:{}", self.subject_kind, self.subject_id)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_open() && height > self.expires_at_height {
            self.status = RecoveryTicketStatus::Expired;
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.ticket_id, "bridge recovery ticket id")?;
        ensure_non_empty(
            &self.requester_commitment,
            "bridge recovery ticket requester",
        )?;
        ensure_non_empty(&self.subject_kind, "bridge recovery ticket subject kind")?;
        ensure_non_empty(&self.subject_id, "bridge recovery ticket subject id")?;
        ensure_non_empty(&self.subject_root, "bridge recovery ticket subject root")?;
        ensure_non_empty(&self.notes_root, "bridge recovery ticket notes root")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("bridge recovery ticket expiry must follow opening".to_string());
        }
        if let Some(assigned_at_height) = self.assigned_at_height {
            if assigned_at_height < self.opened_at_height {
                return Err("bridge recovery ticket assigned before opening".to_string());
            }
        }
        if matches!(self.status, RecoveryTicketStatus::Resolved)
            && self.resolution_root.as_deref().unwrap_or("").is_empty()
        {
            return Err("bridge recovery resolved ticket requires resolution root".to_string());
        }
        let expected = bridge_recovery_ticket_id(&self.identity_record());
        if self.ticket_id != expected {
            return Err("bridge recovery ticket id does not match identity".to_string());
        }
        Ok(self.ticket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserClaimProof {
    pub claim_id: String,
    pub ticket_id: Option<String>,
    pub withdrawal_id: String,
    pub exit_id: String,
    pub account_commitment: String,
    pub claim_nullifier: String,
    pub key_image_root: String,
    pub claim_amount_units: u64,
    pub fee_units: u64,
    pub proof_system: String,
    pub proof_root: String,
    pub recipient_commitment: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub accepted_at_height: Option<u64>,
    pub paid_at_height: Option<u64>,
    pub status: ClaimProofStatus,
    pub severity: RecoverySeverity,
}

impl UserClaimProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket_id: Option<String>,
        withdrawal_id: impl Into<String>,
        exit_id: impl Into<String>,
        account_commitment: impl Into<String>,
        claim_nullifier: impl Into<String>,
        key_image_root: impl Into<String>,
        claim_amount_units: u64,
        fee_units: u64,
        proof_system: impl Into<String>,
        proof_root: impl Into<String>,
        recipient_commitment: impl Into<String>,
        submitted_at_height: u64,
        expires_at_height: u64,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let mut claim = Self {
            claim_id: String::new(),
            ticket_id,
            withdrawal_id: withdrawal_id.into(),
            exit_id: exit_id.into(),
            account_commitment: account_commitment.into(),
            claim_nullifier: claim_nullifier.into(),
            key_image_root: key_image_root.into(),
            claim_amount_units,
            fee_units,
            proof_system: proof_system.into(),
            proof_root: proof_root.into(),
            recipient_commitment: recipient_commitment.into(),
            submitted_at_height,
            expires_at_height,
            accepted_at_height: None,
            paid_at_height: None,
            status: ClaimProofStatus::Submitted,
            severity,
        };
        claim.claim_id = bridge_recovery_user_claim_id(&claim.identity_record());
        claim.validate()?;
        Ok(claim)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_user_claim_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "exit_id": self.exit_id,
            "account_commitment": self.account_commitment,
            "claim_nullifier": self.claim_nullifier,
            "key_image_root": self.key_image_root,
            "claim_amount_units": self.claim_amount_units,
            "proof_root": self.proof_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_user_claim_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "ticket_id": self.ticket_id,
            "withdrawal_id": self.withdrawal_id,
            "exit_id": self.exit_id,
            "account_commitment": self.account_commitment,
            "claim_nullifier": self.claim_nullifier,
            "key_image_root": self.key_image_root,
            "claim_amount_units": self.claim_amount_units,
            "fee_units": self.fee_units,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "recipient_commitment": self.recipient_commitment,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "accepted_at_height": self.accepted_at_height,
            "paid_at_height": self.paid_at_height,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
        })
    }

    pub fn claim_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-USER-CLAIM-PROOF",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "claim_root",
            self.claim_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.status,
            ClaimProofStatus::Submitted | ClaimProofStatus::Challenged
        ) && height > self.expires_at_height
        {
            self.status = ClaimProofStatus::Expired;
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.claim_id, "bridge recovery claim id")?;
        ensure_non_empty(&self.withdrawal_id, "bridge recovery claim withdrawal")?;
        ensure_non_empty(&self.exit_id, "bridge recovery claim exit")?;
        ensure_non_empty(&self.account_commitment, "bridge recovery claim account")?;
        ensure_non_empty(&self.claim_nullifier, "bridge recovery claim nullifier")?;
        ensure_non_empty(&self.key_image_root, "bridge recovery claim key image root")?;
        ensure_positive(self.claim_amount_units, "bridge recovery claim amount")?;
        ensure_non_empty(&self.proof_system, "bridge recovery claim proof system")?;
        ensure_non_empty(&self.proof_root, "bridge recovery claim proof root")?;
        ensure_non_empty(
            &self.recipient_commitment,
            "bridge recovery claim recipient commitment",
        )?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("bridge recovery claim expiry must follow submission".to_string());
        }
        if let Some(accepted_at_height) = self.accepted_at_height {
            if accepted_at_height < self.submitted_at_height {
                return Err("bridge recovery claim accepted before submission".to_string());
            }
        }
        if let Some(paid_at_height) = self.paid_at_height {
            if paid_at_height < self.submitted_at_height {
                return Err("bridge recovery claim paid before submission".to_string());
            }
        }
        let expected = bridge_recovery_user_claim_id(&self.identity_record());
        if self.claim_id != expected {
            return Err("bridge recovery claim id does not match identity".to_string());
        }
        Ok(self.claim_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRecoverySponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub ticket_id: Option<String>,
    pub withdrawal_id: Option<String>,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub applied_units: u64,
    pub rebate_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub reimbursement_root: Option<String>,
    pub status: SponsorshipStatus,
    pub severity: RecoverySeverity,
}

impl LowFeeRecoverySponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        ticket_id: Option<String>,
        withdrawal_id: Option<String>,
        fee_asset_id: impl Into<String>,
        budget_units: u64,
        reserved_units: u64,
        rebate_bps: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let mut sponsorship = Self {
            sponsorship_id: String::new(),
            sponsor_commitment: sponsor_commitment.into(),
            ticket_id,
            withdrawal_id,
            fee_asset_id: fee_asset_id.into(),
            budget_units,
            reserved_units,
            applied_units: 0,
            rebate_bps,
            opened_at_height,
            expires_at_height,
            reimbursement_root: None,
            status: if reserved_units > 0 {
                SponsorshipStatus::Reserved
            } else {
                SponsorshipStatus::Offered
            },
            severity,
        };
        sponsorship.sponsorship_id =
            bridge_recovery_low_fee_sponsorship_id(&sponsorship.identity_record());
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn apply_units(&mut self, units: u64) -> BridgeRecoveryResult<String> {
        let next = self.applied_units.saturating_add(units);
        if next > self.reserved_units {
            return Err("bridge recovery sponsorship applied units exceed reserve".to_string());
        }
        self.applied_units = next;
        self.status = SponsorshipStatus::Applied;
        self.validate()
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_low_fee_sponsorship_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "sponsor_commitment": self.sponsor_commitment,
            "ticket_id": self.ticket_id,
            "withdrawal_id": self.withdrawal_id,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "rebate_bps": self.rebate_bps,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_low_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "ticket_id": self.ticket_id,
            "withdrawal_id": self.withdrawal_id,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "applied_units": self.applied_units,
            "rebate_bps": self.rebate_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "reimbursement_root": self.reimbursement_root,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-LOW-FEE-SPONSORSHIP",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "sponsorship_root",
            self.sponsorship_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.expires_at_height {
            self.status = SponsorshipStatus::Expired;
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.sponsorship_id, "bridge recovery sponsorship id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "bridge recovery sponsor commitment",
        )?;
        ensure_non_empty(&self.fee_asset_id, "bridge recovery sponsorship fee asset")?;
        ensure_positive(self.budget_units, "bridge recovery sponsorship budget")?;
        ensure_bps(self.rebate_bps, "bridge recovery sponsorship rebate bps")?;
        if self.reserved_units > self.budget_units {
            return Err("bridge recovery sponsorship reserved exceeds budget".to_string());
        }
        if self.applied_units > self.reserved_units {
            return Err("bridge recovery sponsorship applied exceeds reserved".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("bridge recovery sponsorship expiry must follow opening".to_string());
        }
        let expected = bridge_recovery_low_fee_sponsorship_id(&self.identity_record());
        if self.sponsorship_id != expected {
            return Err("bridge recovery sponsorship id does not match identity".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryAuditTrail {
    pub audit_id: String,
    pub event_kind: AuditEventKind,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub actor_commitment: String,
    pub previous_state_root: String,
    pub next_state_root: String,
    pub payload_root: String,
    pub event_height: u64,
    pub log_index: u64,
    pub witness_attestation_ids: Vec<String>,
    pub severity: RecoverySeverity,
}

impl RecoveryAuditTrail {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_kind: AuditEventKind,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        actor_commitment: impl Into<String>,
        previous_state_root: impl Into<String>,
        next_state_root: impl Into<String>,
        payload_root: impl Into<String>,
        event_height: u64,
        log_index: u64,
        witness_attestation_ids: Vec<String>,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let mut audit = Self {
            audit_id: String::new(),
            event_kind,
            subject_kind: subject_kind.into(),
            subject_id: subject_id.into(),
            subject_root: subject_root.into(),
            actor_commitment: actor_commitment.into(),
            previous_state_root: previous_state_root.into(),
            next_state_root: next_state_root.into(),
            payload_root: payload_root.into(),
            event_height,
            log_index,
            witness_attestation_ids: ordered_strings(&witness_attestation_ids),
            severity,
        };
        audit.audit_id = bridge_recovery_audit_id(&audit.identity_record());
        audit.validate()?;
        Ok(audit)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_audit_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "event_kind": self.event_kind.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "event_height": self.event_height,
            "log_index": self.log_index,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_audit_trail",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "audit_id": self.audit_id,
            "event_kind": self.event_kind.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "actor_commitment": self.actor_commitment,
            "previous_state_root": self.previous_state_root,
            "next_state_root": self.next_state_root,
            "payload_root": self.payload_root,
            "event_height": self.event_height,
            "log_index": self.log_index,
            "witness_attestation_ids": self.witness_attestation_ids,
            "severity": self.severity.as_str(),
        })
    }

    pub fn audit_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-AUDIT-TRAIL",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "audit_root",
            self.audit_root(),
        )
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.audit_id, "bridge recovery audit id")?;
        ensure_non_empty(&self.subject_kind, "bridge recovery audit subject kind")?;
        ensure_non_empty(&self.subject_id, "bridge recovery audit subject id")?;
        ensure_non_empty(&self.subject_root, "bridge recovery audit subject root")?;
        ensure_non_empty(&self.actor_commitment, "bridge recovery audit actor")?;
        ensure_non_empty(
            &self.previous_state_root,
            "bridge recovery audit previous state",
        )?;
        ensure_non_empty(&self.next_state_root, "bridge recovery audit next state")?;
        ensure_non_empty(&self.payload_root, "bridge recovery audit payload root")?;
        ensure_unique_strings(
            &self.witness_attestation_ids,
            "bridge recovery audit witness ids",
        )?;
        let expected = bridge_recovery_audit_id(&self.identity_record());
        if self.audit_id != expected {
            return Err("bridge recovery audit id does not match identity".to_string());
        }
        Ok(self.audit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySlashingEvidence {
    pub evidence_id: String,
    pub offender_signer_id: String,
    pub offender_role: String,
    pub offense_kind: String,
    pub first_subject_root: String,
    pub conflicting_subject_root: String,
    pub attestation_root: String,
    pub slash_amount_units: u64,
    pub discovered_at_height: u64,
    pub submit_deadline_height: u64,
    pub executed_at_height: Option<u64>,
    pub recovery_ticket_id: Option<String>,
    pub status: SlashingEvidenceStatus,
    pub severity: RecoverySeverity,
}

impl RecoverySlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offender_signer_id: impl Into<String>,
        offender_role: impl Into<String>,
        offense_kind: impl Into<String>,
        first_subject_root: impl Into<String>,
        conflicting_subject_root: impl Into<String>,
        attestation_root: impl Into<String>,
        slash_amount_units: u64,
        discovered_at_height: u64,
        submit_deadline_height: u64,
        recovery_ticket_id: Option<String>,
        severity: RecoverySeverity,
    ) -> BridgeRecoveryResult<Self> {
        let mut evidence = Self {
            evidence_id: String::new(),
            offender_signer_id: offender_signer_id.into(),
            offender_role: offender_role.into(),
            offense_kind: offense_kind.into(),
            first_subject_root: first_subject_root.into(),
            conflicting_subject_root: conflicting_subject_root.into(),
            attestation_root: attestation_root.into(),
            slash_amount_units,
            discovered_at_height,
            submit_deadline_height,
            executed_at_height: None,
            recovery_ticket_id,
            status: SlashingEvidenceStatus::Collected,
            severity,
        };
        evidence.evidence_id = bridge_recovery_slashing_evidence_id(&evidence.identity_record());
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_slashing_evidence_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "offender_signer_id": self.offender_signer_id,
            "offender_role": self.offender_role,
            "offense_kind": self.offense_kind,
            "first_subject_root": self.first_subject_root,
            "conflicting_subject_root": self.conflicting_subject_root,
            "attestation_root": self.attestation_root,
            "discovered_at_height": self.discovered_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "offender_signer_id": self.offender_signer_id,
            "offender_role": self.offender_role,
            "offense_kind": self.offense_kind,
            "first_subject_root": self.first_subject_root,
            "conflicting_subject_root": self.conflicting_subject_root,
            "attestation_root": self.attestation_root,
            "slash_amount_units": self.slash_amount_units,
            "discovered_at_height": self.discovered_at_height,
            "submit_deadline_height": self.submit_deadline_height,
            "executed_at_height": self.executed_at_height,
            "recovery_ticket_id": self.recovery_ticket_id,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
        })
    }

    pub fn evidence_root(&self) -> String {
        bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-SLASHING-EVIDENCE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "evidence_root",
            self.evidence_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == SlashingEvidenceStatus::Collected && height > self.submit_deadline_height
        {
            self.status = SlashingEvidenceStatus::Expired;
        }
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        ensure_non_empty(&self.evidence_id, "bridge recovery slashing evidence id")?;
        ensure_non_empty(
            &self.offender_signer_id,
            "bridge recovery slashing offender",
        )?;
        ensure_non_empty(
            &self.offender_role,
            "bridge recovery slashing offender role",
        )?;
        ensure_non_empty(&self.offense_kind, "bridge recovery slashing offense kind")?;
        ensure_non_empty(
            &self.first_subject_root,
            "bridge recovery slashing first subject",
        )?;
        ensure_non_empty(
            &self.conflicting_subject_root,
            "bridge recovery slashing conflicting subject",
        )?;
        ensure_non_empty(
            &self.attestation_root,
            "bridge recovery slashing attestation root",
        )?;
        if self.first_subject_root == self.conflicting_subject_root {
            return Err("bridge recovery slashing evidence needs conflicting roots".to_string());
        }
        if self.submit_deadline_height <= self.discovered_at_height {
            return Err("bridge recovery slashing deadline must follow discovery".to_string());
        }
        if let Some(executed_at_height) = self.executed_at_height {
            if executed_at_height < self.discovered_at_height {
                return Err("bridge recovery slashing executed before discovery".to_string());
            }
        }
        let expected = bridge_recovery_slashing_evidence_id(&self.identity_record());
        if self.evidence_id != expected {
            return Err("bridge recovery slashing evidence id does not match identity".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRecoveryRoots {
    pub config_root: String,
    pub witness_attestation_root: String,
    pub reorg_quarantine_root: String,
    pub stuck_exit_recovery_root: String,
    pub reserve_deficit_root: String,
    pub signer_replacement_root: String,
    pub pq_rotation_root: String,
    pub delayed_drain_root: String,
    pub recovery_ticket_root: String,
    pub user_claim_proof_root: String,
    pub sponsorship_root: String,
    pub audit_trail_root: String,
    pub slashing_evidence_root: String,
    pub quarantined_subject_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl BridgeRecoveryRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "bridge_recovery_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "witness_attestation_root": self.witness_attestation_root,
            "reorg_quarantine_root": self.reorg_quarantine_root,
            "stuck_exit_recovery_root": self.stuck_exit_recovery_root,
            "reserve_deficit_root": self.reserve_deficit_root,
            "signer_replacement_root": self.signer_replacement_root,
            "pq_rotation_root": self.pq_rotation_root,
            "delayed_drain_root": self.delayed_drain_root,
            "recovery_ticket_root": self.recovery_ticket_root,
            "user_claim_proof_root": self.user_claim_proof_root,
            "sponsorship_root": self.sponsorship_root,
            "audit_trail_root": self.audit_trail_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "quarantined_subject_root": self.quarantined_subject_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record
            .as_object_mut()
            .expect("bridge recovery roots record object")
            .insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        record
    }

    pub fn roots_root(&self) -> String {
        bridge_recovery_payload_root("BRIDGE-RECOVERY-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRecoveryCounters {
    pub height: u64,
    pub emergency_paused: bool,
    pub witness_attestation_count: u64,
    pub fresh_witness_attestation_count: u64,
    pub reorg_quarantine_count: u64,
    pub active_quarantine_count: u64,
    pub stuck_exit_recovery_count: u64,
    pub open_stuck_exit_count: u64,
    pub reserve_deficit_count: u64,
    pub unresolved_deficit_count: u64,
    pub signer_replacement_count: u64,
    pub active_signer_replacement_count: u64,
    pub pq_rotation_count: u64,
    pub active_pq_rotation_count: u64,
    pub delayed_drain_count: u64,
    pub open_delayed_drain_count: u64,
    pub recovery_ticket_count: u64,
    pub open_recovery_ticket_count: u64,
    pub user_claim_proof_count: u64,
    pub replay_blocking_claim_count: u64,
    pub sponsorship_count: u64,
    pub active_sponsorship_count: u64,
    pub audit_trail_count: u64,
    pub slashing_evidence_count: u64,
    pub slashable_evidence_count: u64,
    pub total_quarantined_units: u64,
    pub total_stuck_exit_units: u64,
    pub total_deficit_units: u64,
    pub total_sponsor_budget_units: u64,
    pub total_sponsor_applied_units: u64,
    pub total_drain_units: u64,
    pub total_claim_units: u64,
    pub total_slashable_units: u64,
    pub reserve_coverage_bps: u64,
}

impl BridgeRecoveryCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_recovery_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "height": self.height,
            "emergency_paused": self.emergency_paused,
            "witness_attestation_count": self.witness_attestation_count,
            "fresh_witness_attestation_count": self.fresh_witness_attestation_count,
            "reorg_quarantine_count": self.reorg_quarantine_count,
            "active_quarantine_count": self.active_quarantine_count,
            "stuck_exit_recovery_count": self.stuck_exit_recovery_count,
            "open_stuck_exit_count": self.open_stuck_exit_count,
            "reserve_deficit_count": self.reserve_deficit_count,
            "unresolved_deficit_count": self.unresolved_deficit_count,
            "signer_replacement_count": self.signer_replacement_count,
            "active_signer_replacement_count": self.active_signer_replacement_count,
            "pq_rotation_count": self.pq_rotation_count,
            "active_pq_rotation_count": self.active_pq_rotation_count,
            "delayed_drain_count": self.delayed_drain_count,
            "open_delayed_drain_count": self.open_delayed_drain_count,
            "recovery_ticket_count": self.recovery_ticket_count,
            "open_recovery_ticket_count": self.open_recovery_ticket_count,
            "user_claim_proof_count": self.user_claim_proof_count,
            "replay_blocking_claim_count": self.replay_blocking_claim_count,
            "sponsorship_count": self.sponsorship_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "audit_trail_count": self.audit_trail_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "slashable_evidence_count": self.slashable_evidence_count,
            "total_quarantined_units": self.total_quarantined_units,
            "total_stuck_exit_units": self.total_stuck_exit_units,
            "total_deficit_units": self.total_deficit_units,
            "total_sponsor_budget_units": self.total_sponsor_budget_units,
            "total_sponsor_applied_units": self.total_sponsor_applied_units,
            "total_drain_units": self.total_drain_units,
            "total_claim_units": self.total_claim_units,
            "total_slashable_units": self.total_slashable_units,
            "reserve_coverage_bps": self.reserve_coverage_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRecoveryState {
    pub height: u64,
    pub operator_label: String,
    pub emergency_paused: bool,
    pub active_pq_rotation_id: Option<String>,
    pub config: BridgeRecoveryConfig,
    pub witness_attestations: BTreeMap<String, RecoveryWitnessAttestation>,
    pub reorg_quarantines: BTreeMap<String, ReorgQuarantine>,
    pub stuck_exit_recoveries: BTreeMap<String, StuckExitRecovery>,
    pub reserve_deficits: BTreeMap<String, ReserveDeficitRemediation>,
    pub signer_replacements: BTreeMap<String, SignerReplacement>,
    pub pq_rotations: BTreeMap<String, PqEmergencyRotation>,
    pub delayed_drains: BTreeMap<String, DelayedReleaseDrain>,
    pub recovery_tickets: BTreeMap<String, RecoveryTicket>,
    pub user_claim_proofs: BTreeMap<String, UserClaimProof>,
    pub sponsorships: BTreeMap<String, LowFeeRecoverySponsorship>,
    pub audit_trails: BTreeMap<String, RecoveryAuditTrail>,
    pub slashing_evidence: BTreeMap<String, RecoverySlashingEvidence>,
    pub quarantined_subjects: BTreeSet<String>,
    pub claim_nullifier_index: BTreeMap<String, String>,
    pub key_image_index: BTreeMap<String, String>,
    pub ticket_subject_index: BTreeMap<String, String>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for BridgeRecoveryState {
    fn default() -> Self {
        Self::new("bridge-recovery", BridgeRecoveryConfig::default())
            .expect("default bridge recovery config")
    }
}

impl BridgeRecoveryState {
    pub fn new(
        operator_label: impl Into<String>,
        config: BridgeRecoveryConfig,
    ) -> BridgeRecoveryResult<Self> {
        config.validate()?;
        let operator_label = operator_label.into();
        ensure_non_empty(&operator_label, "bridge recovery operator label")?;
        Ok(Self {
            height: 0,
            operator_label,
            emergency_paused: false,
            active_pq_rotation_id: None,
            config,
            witness_attestations: BTreeMap::new(),
            reorg_quarantines: BTreeMap::new(),
            stuck_exit_recoveries: BTreeMap::new(),
            reserve_deficits: BTreeMap::new(),
            signer_replacements: BTreeMap::new(),
            pq_rotations: BTreeMap::new(),
            delayed_drains: BTreeMap::new(),
            recovery_tickets: BTreeMap::new(),
            user_claim_proofs: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            audit_trails: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            quarantined_subjects: BTreeSet::new(),
            claim_nullifier_index: BTreeMap::new(),
            key_image_index: BTreeMap::new(),
            ticket_subject_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> BridgeRecoveryResult<Self> {
        let mut state = Self::new("devnet-bridge-recovery", BridgeRecoveryConfig::default())?;
        state.set_height(128)?;

        let reorg_subject_root = bridge_recovery_payload_root(
            "BRIDGE-RECOVERY-DEVNET-REORG-SUBJECT",
            &json!({
                "txid": "devnet-reorg-txid-0",
                "old_block": "devnet-old-block-73",
                "new_block": "devnet-new-block-73",
            }),
        );
        let mut witness_ids = Vec::new();
        for label in ["devnet-watchtower-a", "devnet-watchtower-b"] {
            let attestation = RecoveryWitnessAttestation::new(
                label,
                bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-WITNESS-KEY", label),
                "watchtower",
                "reorg_quarantine",
                "devnet-reorg-txid-0",
                &reorg_subject_root,
                127,
                128,
                192,
            )?;
            witness_ids.push(attestation.attestation_id.clone());
            state.insert_witness_attestation(attestation)?;
        }

        let quarantine = ReorgQuarantine::new(
            &state.config.monero_network,
            &state.config.asset_id,
            "devnet-reorg-txid-0",
            73,
            "devnet-old-block-73",
            73,
            "devnet-new-block-73",
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-AFFECTED-OUTPUTS", "reorg-0"),
            vec!["devnet-withdrawal-0".to_string()],
            75_000,
            128,
            192,
            witness_ids.clone(),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-REORG-EVIDENCE", "reorg-0"),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-RELEASE-AUTHORITY", "guardian"),
            RecoverySeverity::Critical,
        )?;
        let quarantine_id = quarantine.quarantine_id.clone();
        let quarantine_root = quarantine.quarantine_root();
        state.insert_reorg_quarantine(quarantine)?;

        let ticket = RecoveryTicket::new(
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-REQUESTER", "user-0"),
            "stuck_exit",
            "devnet-withdrawal-0",
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-TICKET-SUBJECT", "withdrawal-0"),
            RecoveryActionKind::StuckExitRecovery,
            RecoveryPriority::Emergency,
            129,
            240,
            RecoverySeverity::Critical,
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-TICKET-NOTES", "withdrawal-0"),
        )?;
        let ticket_id = ticket.ticket_id.clone();
        state.insert_recovery_ticket(ticket)?;

        let mut sponsorship = LowFeeRecoverySponsorship::new(
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-SPONSOR", "sponsor-0"),
            Some(ticket_id.clone()),
            Some("devnet-withdrawal-0".to_string()),
            &state.config.fee_asset_id,
            8_000,
            5_000,
            state.config.low_fee_sponsor_rebate_bps,
            129,
            201,
            RecoverySeverity::Watch,
        )?;
        sponsorship.apply_units(2_500)?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_sponsorship(sponsorship)?;

        let stuck_exit = StuckExitRecovery::new(
            "devnet-withdrawal-0",
            "devnet-exit-0",
            "devnet-account-commitment-0",
            "devnet-recipient-address-hash-0",
            &state.config.asset_id,
            75_000,
            1_250,
            129,
            state.config.stuck_exit_retry_blocks,
            240,
            Some(quarantine_id.clone()),
            Some(sponsorship_id.clone()),
            Some(ticket_id.clone()),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-REPLACEMENT-TX", "exit-0"),
            RecoverySeverity::Critical,
        )?
        .with_sponsor_fee(2_500)?;
        let stuck_recovery_id = stuck_exit.recovery_id.clone();
        state.insert_stuck_exit_recovery(stuck_exit)?;

        let reserve = ReserveDeficitRemediation::new(
            &state.config.asset_id,
            &state.config.monero_network,
            "devnet-reserve-checkpoint-0",
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-RESERVE-ROOT", "reserve-0"),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-LIABILITY-ROOT", "liability-0"),
            975_000,
            1_000_000,
            40_000,
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-BACKFILL", "backfill-0"),
            130,
            154,
            witness_ids.clone(),
            RecoverySeverity::Degraded,
        )?;
        state.insert_reserve_deficit(remediation_with_status(
            reserve,
            ReserveDeficitStatus::Remediating,
        )?)?;

        let guardian_ids = witness_ids.clone();
        let signer_replacement = SignerReplacement::new(
            "devnet-signer-old",
            "devnet-signer-new",
            "devnet-bridge-signer-set",
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-OLD-SIGNER-KEY", "old"),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-NEW-SIGNER-KEY", "new"),
            "reorg quarantine and stale threshold shares",
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-SIGNER-EVIDENCE", "signer"),
            130,
            132,
            180,
            guardian_ids.clone(),
            RecoverySeverity::Critical,
        )?;
        let signer_replacement_id = signer_replacement.replacement_id.clone();
        state.insert_signer_replacement(signer_replacement)?;

        let pq_rotation = PqEmergencyRotation::new(
            "devnet-pq-rotation-0",
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-PREVIOUS-COMMITTEE", "old"),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-NEXT-COMMITTEE", "new"),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-KYBER-EPOCH", "kyber"),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-FALCON-EPOCH", "falcon"),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-DILITHIUM-EPOCH", "dilithium"),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-HYBRID-TRANSCRIPT", "hybrid"),
            Some(signer_replacement_id.clone()),
            true,
            130,
            134,
            190,
            guardian_ids,
            RecoverySeverity::Emergency,
        )?;
        let pq_rotation_id = pq_rotation.rotation_id.clone();
        state.insert_pq_rotation(pq_rotation)?;

        let mut claim = UserClaimProof::new(
            Some(ticket_id.clone()),
            "devnet-withdrawal-0",
            "devnet-exit-0",
            "devnet-account-commitment-0",
            "devnet-claim-nullifier-0",
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-KEY-IMAGE", "claim-0"),
            75_000,
            500,
            "devnet-plonkish-claim-proof",
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-CLAIM-PROOF", "claim-0"),
            "devnet-recipient-commitment-0",
            132,
            228,
            RecoverySeverity::Watch,
        )?;
        claim.status = ClaimProofStatus::Accepted;
        claim.accepted_at_height = Some(136);
        let claim_root = claim.claim_root();
        state.insert_user_claim_proof(claim)?;

        let drain = DelayedReleaseDrain::new(
            "devnet-hot-release-lane",
            &state.config.asset_id,
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-DRAIN-QUEUE", "queue-0"),
            vec!["devnet-queue-item-0".to_string()],
            vec![stuck_recovery_id.clone()],
            vec![ticket_id.clone()],
            75_000,
            2_500,
            134,
            136,
            220,
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-DRAIN-OPERATOR", "operator-0"),
            RecoverySeverity::Critical,
        )?;
        state.insert_delayed_drain(drain)?;

        let slashing_ticket = RecoveryTicket::new(
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-SLASH-REQUESTER", "watchtower"),
            "signer_replacement",
            &signer_replacement_id,
            bridge_recovery_string_root(
                "BRIDGE-RECOVERY-DEVNET-SLASH-TICKET-SUBJECT",
                "signer-replacement",
            ),
            RecoveryActionKind::SlashingEvidence,
            RecoveryPriority::High,
            133,
            240,
            RecoverySeverity::Critical,
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-SLASH-NOTES", "signer"),
        )?;
        let slashing_ticket_id = slashing_ticket.ticket_id.clone();
        state.insert_recovery_ticket(slashing_ticket)?;

        let mut slashing = RecoverySlashingEvidence::new(
            "devnet-signer-old",
            "bridge_threshold_signer",
            "conflicting_reorg_attestation",
            quarantine_root,
            claim_root,
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-SLASH-ATTESTATION", "slash-0"),
            12_500,
            134,
            220,
            Some(slashing_ticket_id),
            RecoverySeverity::Critical,
        )?;
        slashing.status = SlashingEvidenceStatus::Submitted;
        state.insert_slashing_evidence(slashing)?;

        state.active_pq_rotation_id = Some(pq_rotation_id);
        state.emergency_paused = true;
        let audit = RecoveryAuditTrail::new(
            AuditEventKind::StateTransition,
            "bridge_recovery_state",
            "devnet-bridge-recovery",
            state.state_root(),
            bridge_recovery_string_root("BRIDGE-RECOVERY-DEVNET-AUDIT-ACTOR", "operator-0"),
            bridge_recovery_empty_root("BRIDGE-RECOVERY-DEVNET-PREVIOUS-STATE"),
            state.state_root(),
            bridge_recovery_payload_root(
                "BRIDGE-RECOVERY-DEVNET-AUDIT-PAYLOAD",
                &json!({"fixture": "bridge_recovery_devnet", "height": 136_u64}),
            ),
            136,
            0,
            witness_ids,
            RecoverySeverity::Info,
        )?;
        state.insert_audit_trail(audit)?;
        state.set_height(136)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> BridgeRecoveryResult<String> {
        self.height = height;
        for attestation in self.witness_attestations.values_mut() {
            attestation.set_height(height);
        }
        for quarantine in self.reorg_quarantines.values_mut() {
            quarantine.set_height(height);
        }
        for recovery in self.stuck_exit_recoveries.values_mut() {
            recovery.set_height(height, self.config.stuck_exit_retry_blocks);
        }
        for deficit in self.reserve_deficits.values_mut() {
            deficit.set_height(height);
        }
        for replacement in self.signer_replacements.values_mut() {
            replacement.set_height(height);
        }
        for rotation in self.pq_rotations.values_mut() {
            rotation.set_height(height);
        }
        for drain in self.delayed_drains.values_mut() {
            drain.set_height(height);
        }
        for ticket in self.recovery_tickets.values_mut() {
            ticket.set_height(height);
        }
        for claim in self.user_claim_proofs.values_mut() {
            claim.set_height(height);
        }
        for sponsorship in self.sponsorships.values_mut() {
            sponsorship.set_height(height);
        }
        for evidence in self.slashing_evidence.values_mut() {
            evidence.set_height(height);
        }
        self.refresh_indexes()?;
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn insert_witness_attestation(
        &mut self,
        attestation: RecoveryWitnessAttestation,
    ) -> BridgeRecoveryResult<String> {
        attestation.validate()?;
        let attestation_id = attestation.attestation_id.clone();
        insert_unique_record(
            &mut self.witness_attestations,
            attestation_id.clone(),
            attestation,
            "bridge recovery witness attestation",
        )?;
        self.refresh_public_records();
        Ok(attestation_id)
    }

    pub fn insert_reorg_quarantine(
        &mut self,
        quarantine: ReorgQuarantine,
    ) -> BridgeRecoveryResult<String> {
        quarantine.validate()?;
        if quarantine.monero_network != self.config.monero_network {
            return Err("bridge recovery quarantine network mismatch".to_string());
        }
        if quarantine.asset_id != self.config.asset_id {
            return Err("bridge recovery quarantine asset mismatch".to_string());
        }
        self.ensure_attestations_exist(&quarantine.witness_attestation_ids)?;
        if quarantine.status.is_active()
            && self.active_quarantine_count() >= self.config.max_active_quarantines
        {
            return Err("bridge recovery active quarantine limit reached".to_string());
        }
        let quarantine_id = quarantine.quarantine_id.clone();
        insert_unique_record(
            &mut self.reorg_quarantines,
            quarantine_id.clone(),
            quarantine,
            "bridge recovery reorg quarantine",
        )?;
        self.refresh_indexes()?;
        self.refresh_public_records();
        Ok(quarantine_id)
    }

    pub fn insert_stuck_exit_recovery(
        &mut self,
        recovery: StuckExitRecovery,
    ) -> BridgeRecoveryResult<String> {
        recovery.validate()?;
        if recovery.asset_id != self.config.asset_id {
            return Err("bridge recovery stuck exit asset mismatch".to_string());
        }
        if let Some(quarantine_id) = &recovery.quarantine_id {
            if !self.reorg_quarantines.contains_key(quarantine_id) {
                return Err("bridge recovery stuck exit references unknown quarantine".to_string());
            }
        }
        if let Some(ticket_id) = &recovery.recovery_ticket_id {
            if !self.recovery_tickets.contains_key(ticket_id) {
                return Err("bridge recovery stuck exit references unknown ticket".to_string());
            }
        }
        if let Some(sponsorship_id) = &recovery.sponsorship_id {
            let sponsorship = self.sponsorships.get(sponsorship_id).ok_or_else(|| {
                "bridge recovery stuck exit references unknown sponsor".to_string()
            })?;
            if sponsorship.withdrawal_id.as_deref() != Some(recovery.withdrawal_id.as_str()) {
                return Err("bridge recovery stuck exit sponsor withdrawal mismatch".to_string());
            }
        }
        let recovery_id = recovery.recovery_id.clone();
        insert_unique_record(
            &mut self.stuck_exit_recoveries,
            recovery_id.clone(),
            recovery,
            "bridge recovery stuck exit",
        )?;
        self.refresh_public_records();
        Ok(recovery_id)
    }

    pub fn insert_reserve_deficit(
        &mut self,
        deficit: ReserveDeficitRemediation,
    ) -> BridgeRecoveryResult<String> {
        deficit.validate()?;
        if deficit.asset_id != self.config.asset_id {
            return Err("bridge recovery reserve deficit asset mismatch".to_string());
        }
        if deficit.monero_network != self.config.monero_network {
            return Err("bridge recovery reserve deficit network mismatch".to_string());
        }
        self.ensure_attestations_exist(&deficit.witness_attestation_ids)?;
        let remediation_id = deficit.remediation_id.clone();
        insert_unique_record(
            &mut self.reserve_deficits,
            remediation_id.clone(),
            deficit,
            "bridge recovery reserve deficit",
        )?;
        self.refresh_public_records();
        Ok(remediation_id)
    }

    pub fn insert_signer_replacement(
        &mut self,
        replacement: SignerReplacement,
    ) -> BridgeRecoveryResult<String> {
        replacement.validate()?;
        self.ensure_attestations_exist(&replacement.guardian_attestation_ids)?;
        let replacement_id = replacement.replacement_id.clone();
        insert_unique_record(
            &mut self.signer_replacements,
            replacement_id.clone(),
            replacement,
            "bridge recovery signer replacement",
        )?;
        self.refresh_public_records();
        Ok(replacement_id)
    }

    pub fn insert_pq_rotation(
        &mut self,
        rotation: PqEmergencyRotation,
    ) -> BridgeRecoveryResult<String> {
        rotation.validate()?;
        self.ensure_attestations_exist(&rotation.guardian_attestation_ids)?;
        if let Some(replacement_id) = &rotation.signer_replacement_id {
            if !self.signer_replacements.contains_key(replacement_id) {
                return Err(
                    "bridge recovery pq rotation references unknown signer replacement".to_string(),
                );
            }
        }
        let rotation_id = rotation.rotation_id.clone();
        insert_unique_record(
            &mut self.pq_rotations,
            rotation_id.clone(),
            rotation,
            "bridge recovery pq rotation",
        )?;
        self.refresh_public_records();
        Ok(rotation_id)
    }

    pub fn insert_delayed_drain(
        &mut self,
        drain: DelayedReleaseDrain,
    ) -> BridgeRecoveryResult<String> {
        drain.validate()?;
        if drain.asset_id != self.config.asset_id {
            return Err("bridge recovery drain asset mismatch".to_string());
        }
        if drain.queue_item_ids.len() as u64 > self.config.delayed_drain_batch_limit {
            return Err("bridge recovery drain exceeds configured batch limit".to_string());
        }
        for stuck_exit_id in &drain.stuck_exit_ids {
            if !self.stuck_exit_recoveries.contains_key(stuck_exit_id) {
                return Err("bridge recovery drain references unknown stuck exit".to_string());
            }
        }
        for ticket_id in &drain.recovery_ticket_ids {
            if !self.recovery_tickets.contains_key(ticket_id) {
                return Err("bridge recovery drain references unknown ticket".to_string());
            }
        }
        let drain_id = drain.drain_id.clone();
        insert_unique_record(
            &mut self.delayed_drains,
            drain_id.clone(),
            drain,
            "bridge recovery delayed drain",
        )?;
        self.refresh_public_records();
        Ok(drain_id)
    }

    pub fn insert_recovery_ticket(
        &mut self,
        ticket: RecoveryTicket,
    ) -> BridgeRecoveryResult<String> {
        ticket.validate()?;
        if ticket.status.is_open()
            && self.open_recovery_ticket_count() >= self.config.max_open_recovery_tickets
        {
            return Err("bridge recovery open ticket limit reached".to_string());
        }
        let ticket_id = ticket.ticket_id.clone();
        insert_unique_record(
            &mut self.recovery_tickets,
            ticket_id.clone(),
            ticket,
            "bridge recovery ticket",
        )?;
        self.refresh_indexes()?;
        self.refresh_public_records();
        Ok(ticket_id)
    }

    pub fn insert_user_claim_proof(
        &mut self,
        claim: UserClaimProof,
    ) -> BridgeRecoveryResult<String> {
        claim.validate()?;
        if !self
            .stuck_exit_recoveries
            .values()
            .any(|recovery| recovery.exit_id == claim.exit_id)
        {
            return Err("bridge recovery claim references unknown exit".to_string());
        }
        if let Some(ticket_id) = &claim.ticket_id {
            if !self.recovery_tickets.contains_key(ticket_id) {
                return Err("bridge recovery claim references unknown ticket".to_string());
            }
        }
        if let Some(existing) = self.claim_nullifier_index.get(&claim.claim_nullifier) {
            let existing_claim = self
                .user_claim_proofs
                .get(existing)
                .ok_or_else(|| "bridge recovery claim nullifier index missing claim".to_string())?;
            if existing_claim.status.blocks_replay() && claim.status.blocks_replay() {
                return Err("bridge recovery claim nullifier already blocks replay".to_string());
            }
        }
        let claim_id = claim.claim_id.clone();
        insert_unique_record(
            &mut self.user_claim_proofs,
            claim_id.clone(),
            claim,
            "bridge recovery user claim",
        )?;
        self.refresh_indexes()?;
        self.refresh_public_records();
        Ok(claim_id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeRecoverySponsorship,
    ) -> BridgeRecoveryResult<String> {
        sponsorship.validate()?;
        if sponsorship.fee_asset_id != self.config.fee_asset_id {
            return Err("bridge recovery sponsorship fee asset mismatch".to_string());
        }
        if let Some(ticket_id) = &sponsorship.ticket_id {
            if !self.recovery_tickets.contains_key(ticket_id) {
                return Err("bridge recovery sponsorship references unknown ticket".to_string());
            }
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        insert_unique_record(
            &mut self.sponsorships,
            sponsorship_id.clone(),
            sponsorship,
            "bridge recovery sponsorship",
        )?;
        self.refresh_public_records();
        Ok(sponsorship_id)
    }

    pub fn insert_audit_trail(
        &mut self,
        audit: RecoveryAuditTrail,
    ) -> BridgeRecoveryResult<String> {
        audit.validate()?;
        self.ensure_attestations_exist(&audit.witness_attestation_ids)?;
        let audit_id = audit.audit_id.clone();
        insert_unique_record(
            &mut self.audit_trails,
            audit_id.clone(),
            audit,
            "bridge recovery audit trail",
        )?;
        self.refresh_public_records();
        Ok(audit_id)
    }

    pub fn insert_slashing_evidence(
        &mut self,
        evidence: RecoverySlashingEvidence,
    ) -> BridgeRecoveryResult<String> {
        evidence.validate()?;
        if let Some(ticket_id) = &evidence.recovery_ticket_id {
            if !self.recovery_tickets.contains_key(ticket_id) {
                return Err(
                    "bridge recovery slashing evidence references unknown ticket".to_string(),
                );
            }
        }
        let evidence_id = evidence.evidence_id.clone();
        insert_unique_record(
            &mut self.slashing_evidence,
            evidence_id.clone(),
            evidence,
            "bridge recovery slashing evidence",
        )?;
        self.refresh_public_records();
        Ok(evidence_id)
    }

    pub fn insert_public_record(
        &mut self,
        key: impl Into<String>,
        record: Value,
    ) -> BridgeRecoveryResult<String> {
        let key = key.into();
        ensure_non_empty(&key, "bridge recovery public record key")?;
        let record_id = bridge_recovery_payload_root("BRIDGE-RECOVERY-PUBLIC-RECORD", &record);
        self.public_records
            .insert(format!("{key}:{record_id}"), record);
        Ok(record_id)
    }

    pub fn roots(&self) -> BridgeRecoveryRoots {
        let mut roots = self.collection_roots_without_state();
        roots.state_root = self.state_root();
        roots
    }

    pub fn counters(&self) -> BridgeRecoveryCounters {
        let total_reserve_units = self
            .reserve_deficits
            .values()
            .map(|deficit| deficit.observed_reserve_units)
            .sum::<u64>();
        let total_required_units = self
            .reserve_deficits
            .values()
            .map(|deficit| deficit.required_liability_units)
            .sum::<u64>();
        BridgeRecoveryCounters {
            height: self.height,
            emergency_paused: self.emergency_paused,
            witness_attestation_count: self.witness_attestations.len() as u64,
            fresh_witness_attestation_count: self
                .witness_attestations
                .values()
                .filter(|attestation| attestation.status.usable())
                .count() as u64,
            reorg_quarantine_count: self.reorg_quarantines.len() as u64,
            active_quarantine_count: self.active_quarantine_count(),
            stuck_exit_recovery_count: self.stuck_exit_recoveries.len() as u64,
            open_stuck_exit_count: self
                .stuck_exit_recoveries
                .values()
                .filter(|recovery| recovery.status.is_open())
                .count() as u64,
            reserve_deficit_count: self.reserve_deficits.len() as u64,
            unresolved_deficit_count: self
                .reserve_deficits
                .values()
                .filter(|deficit| deficit.status.is_unresolved())
                .count() as u64,
            signer_replacement_count: self.signer_replacements.len() as u64,
            active_signer_replacement_count: self
                .signer_replacements
                .values()
                .filter(|replacement| replacement.status.accepts_signatures())
                .count() as u64,
            pq_rotation_count: self.pq_rotations.len() as u64,
            active_pq_rotation_count: self
                .pq_rotations
                .values()
                .filter(|rotation| rotation.status.is_active())
                .count() as u64,
            delayed_drain_count: self.delayed_drains.len() as u64,
            open_delayed_drain_count: self
                .delayed_drains
                .values()
                .filter(|drain| drain.status.is_open())
                .count() as u64,
            recovery_ticket_count: self.recovery_tickets.len() as u64,
            open_recovery_ticket_count: self.open_recovery_ticket_count(),
            user_claim_proof_count: self.user_claim_proofs.len() as u64,
            replay_blocking_claim_count: self
                .user_claim_proofs
                .values()
                .filter(|claim| claim.status.blocks_replay())
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            active_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.active())
                .count() as u64,
            audit_trail_count: self.audit_trails.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            slashable_evidence_count: self
                .slashing_evidence
                .values()
                .filter(|evidence| evidence.status.slashable())
                .count() as u64,
            total_quarantined_units: self
                .reorg_quarantines
                .values()
                .filter(|quarantine| quarantine.status.is_active())
                .map(|quarantine| quarantine.amount_units)
                .sum::<u64>(),
            total_stuck_exit_units: self
                .stuck_exit_recoveries
                .values()
                .filter(|recovery| recovery.status.is_open())
                .map(|recovery| recovery.amount_units)
                .sum::<u64>(),
            total_deficit_units: self
                .reserve_deficits
                .values()
                .map(|deficit| deficit.deficit_units)
                .sum::<u64>(),
            total_sponsor_budget_units: self
                .sponsorships
                .values()
                .map(|sponsorship| sponsorship.budget_units)
                .sum::<u64>(),
            total_sponsor_applied_units: self
                .sponsorships
                .values()
                .map(|sponsorship| sponsorship.applied_units)
                .sum::<u64>(),
            total_drain_units: self
                .delayed_drains
                .values()
                .map(|drain| drain.total_amount_units)
                .sum::<u64>(),
            total_claim_units: self
                .user_claim_proofs
                .values()
                .filter(|claim| {
                    matches!(
                        claim.status,
                        ClaimProofStatus::Accepted | ClaimProofStatus::Paid
                    )
                })
                .map(|claim| claim.claim_amount_units)
                .sum::<u64>(),
            total_slashable_units: self
                .slashing_evidence
                .values()
                .filter(|evidence| evidence.status.slashable())
                .map(|evidence| evidence.slash_amount_units)
                .sum::<u64>(),
            reserve_coverage_bps: reserve_coverage_bps(total_reserve_units, total_required_units),
        }
    }

    pub fn state_root(&self) -> String {
        bridge_recovery_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("bridge recovery state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.collection_roots_without_state();
        let counters = self.counters();
        json!({
            "kind": "bridge_recovery_state",
            "chain_id": CHAIN_ID,
            "protocol_version": BRIDGE_RECOVERY_PROTOCOL_VERSION,
            "height": self.height,
            "operator_label": self.operator_label,
            "emergency_paused": self.emergency_paused,
            "active_pq_rotation_id": self.active_pq_rotation_id,
            "config": self.config.public_record(),
            "roots": roots.public_record_without_state_root(),
            "counters": counters.public_record(),
        })
    }

    pub fn validate(&self) -> BridgeRecoveryResult<String> {
        self.config.validate()?;
        ensure_non_empty(&self.operator_label, "bridge recovery operator label")?;
        if let Some(rotation_id) = &self.active_pq_rotation_id {
            let rotation = self
                .pq_rotations
                .get(rotation_id)
                .ok_or_else(|| "bridge recovery active pq rotation is unknown".to_string())?;
            if !rotation.status.is_active() && rotation.status != PqRotationStatus::Completed {
                return Err("bridge recovery active pq rotation is not usable".to_string());
            }
        }
        for attestation in self.witness_attestations.values() {
            attestation.validate()?;
        }
        for quarantine in self.reorg_quarantines.values() {
            quarantine.validate()?;
            if quarantine.monero_network != self.config.monero_network {
                return Err("bridge recovery quarantine network mismatch".to_string());
            }
            if quarantine.asset_id != self.config.asset_id {
                return Err("bridge recovery quarantine asset mismatch".to_string());
            }
            self.ensure_attestations_exist(&quarantine.witness_attestation_ids)?;
        }
        if self.active_quarantine_count() > self.config.max_active_quarantines {
            return Err("bridge recovery active quarantine count exceeds config".to_string());
        }
        for recovery in self.stuck_exit_recoveries.values() {
            recovery.validate()?;
            if recovery.asset_id != self.config.asset_id {
                return Err("bridge recovery stuck exit asset mismatch".to_string());
            }
            if let Some(quarantine_id) = &recovery.quarantine_id {
                if !self.reorg_quarantines.contains_key(quarantine_id) {
                    return Err("bridge recovery stuck exit missing quarantine".to_string());
                }
            }
            if let Some(ticket_id) = &recovery.recovery_ticket_id {
                if !self.recovery_tickets.contains_key(ticket_id) {
                    return Err("bridge recovery stuck exit missing ticket".to_string());
                }
            }
            if let Some(sponsorship_id) = &recovery.sponsorship_id {
                if !self.sponsorships.contains_key(sponsorship_id) {
                    return Err("bridge recovery stuck exit missing sponsorship".to_string());
                }
            }
        }
        for deficit in self.reserve_deficits.values() {
            deficit.validate()?;
            if deficit.asset_id != self.config.asset_id {
                return Err("bridge recovery reserve deficit asset mismatch".to_string());
            }
            if deficit.monero_network != self.config.monero_network {
                return Err("bridge recovery reserve deficit network mismatch".to_string());
            }
            self.ensure_attestations_exist(&deficit.witness_attestation_ids)?;
        }
        for replacement in self.signer_replacements.values() {
            replacement.validate()?;
            self.ensure_attestations_exist(&replacement.guardian_attestation_ids)?;
        }
        for rotation in self.pq_rotations.values() {
            rotation.validate()?;
            self.ensure_attestations_exist(&rotation.guardian_attestation_ids)?;
            if let Some(replacement_id) = &rotation.signer_replacement_id {
                if !self.signer_replacements.contains_key(replacement_id) {
                    return Err(
                        "bridge recovery pq rotation missing signer replacement".to_string()
                    );
                }
            }
        }
        for drain in self.delayed_drains.values() {
            drain.validate()?;
            if drain.asset_id != self.config.asset_id {
                return Err("bridge recovery drain asset mismatch".to_string());
            }
            if drain.queue_item_ids.len() as u64 > self.config.delayed_drain_batch_limit {
                return Err("bridge recovery drain exceeds batch limit".to_string());
            }
            for stuck_exit_id in &drain.stuck_exit_ids {
                if !self.stuck_exit_recoveries.contains_key(stuck_exit_id) {
                    return Err("bridge recovery drain missing stuck exit".to_string());
                }
            }
            for ticket_id in &drain.recovery_ticket_ids {
                if !self.recovery_tickets.contains_key(ticket_id) {
                    return Err("bridge recovery drain missing ticket".to_string());
                }
            }
        }
        for ticket in self.recovery_tickets.values() {
            ticket.validate()?;
        }
        if self.open_recovery_ticket_count() > self.config.max_open_recovery_tickets {
            return Err("bridge recovery open ticket count exceeds config".to_string());
        }
        for claim in self.user_claim_proofs.values() {
            claim.validate()?;
            if let Some(ticket_id) = &claim.ticket_id {
                if !self.recovery_tickets.contains_key(ticket_id) {
                    return Err("bridge recovery claim missing ticket".to_string());
                }
            }
        }
        self.validate_claim_indexes()?;
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if sponsorship.fee_asset_id != self.config.fee_asset_id {
                return Err("bridge recovery sponsorship fee asset mismatch".to_string());
            }
            if let Some(ticket_id) = &sponsorship.ticket_id {
                if !self.recovery_tickets.contains_key(ticket_id) {
                    return Err("bridge recovery sponsorship missing ticket".to_string());
                }
            }
        }
        for audit in self.audit_trails.values() {
            audit.validate()?;
            self.ensure_attestations_exist(&audit.witness_attestation_ids)?;
        }
        for evidence in self.slashing_evidence.values() {
            evidence.validate()?;
            if let Some(ticket_id) = &evidence.recovery_ticket_id {
                if !self.recovery_tickets.contains_key(ticket_id) {
                    return Err("bridge recovery slashing evidence missing ticket".to_string());
                }
            }
        }
        self.validate_quarantined_subjects()?;
        self.validate_ticket_subject_index()?;
        Ok(self.state_root())
    }

    fn collection_roots_without_state(&self) -> BridgeRecoveryRoots {
        BridgeRecoveryRoots {
            config_root: self.config.config_root(),
            witness_attestation_root: bridge_recovery_witness_attestation_collection_root(
                &self
                    .witness_attestations
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            reorg_quarantine_root: bridge_recovery_reorg_quarantine_collection_root(
                &self.reorg_quarantines.values().cloned().collect::<Vec<_>>(),
            ),
            stuck_exit_recovery_root: bridge_recovery_stuck_exit_collection_root(
                &self
                    .stuck_exit_recoveries
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            reserve_deficit_root: bridge_recovery_reserve_deficit_collection_root(
                &self.reserve_deficits.values().cloned().collect::<Vec<_>>(),
            ),
            signer_replacement_root: bridge_recovery_signer_replacement_collection_root(
                &self
                    .signer_replacements
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            pq_rotation_root: bridge_recovery_pq_rotation_collection_root(
                &self.pq_rotations.values().cloned().collect::<Vec<_>>(),
            ),
            delayed_drain_root: bridge_recovery_delayed_drain_collection_root(
                &self.delayed_drains.values().cloned().collect::<Vec<_>>(),
            ),
            recovery_ticket_root: bridge_recovery_ticket_collection_root(
                &self.recovery_tickets.values().cloned().collect::<Vec<_>>(),
            ),
            user_claim_proof_root: bridge_recovery_user_claim_collection_root(
                &self.user_claim_proofs.values().cloned().collect::<Vec<_>>(),
            ),
            sponsorship_root: bridge_recovery_sponsorship_collection_root(
                &self.sponsorships.values().cloned().collect::<Vec<_>>(),
            ),
            audit_trail_root: bridge_recovery_audit_collection_root(
                &self.audit_trails.values().cloned().collect::<Vec<_>>(),
            ),
            slashing_evidence_root: bridge_recovery_slashing_evidence_collection_root(
                &self.slashing_evidence.values().cloned().collect::<Vec<_>>(),
            ),
            quarantined_subject_root: bridge_recovery_string_set_root(
                "BRIDGE-RECOVERY-QUARANTINED-SUBJECTS",
                &self
                    .quarantined_subjects
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            public_record_root: keyed_value_root(
                "BRIDGE-RECOVERY-PUBLIC-RECORDS",
                self.public_records
                    .iter()
                    .map(|(key, record)| (key.clone(), record.clone()))
                    .collect(),
            ),
            state_root: String::new(),
        }
    }

    fn active_quarantine_count(&self) -> u64 {
        self.reorg_quarantines
            .values()
            .filter(|quarantine| quarantine.status.is_active())
            .count() as u64
    }

    fn open_recovery_ticket_count(&self) -> u64 {
        self.recovery_tickets
            .values()
            .filter(|ticket| ticket.status.is_open())
            .count() as u64
    }

    fn ensure_attestations_exist(&self, attestation_ids: &[String]) -> BridgeRecoveryResult<()> {
        for attestation_id in attestation_ids {
            if !self.witness_attestations.contains_key(attestation_id) {
                return Err(format!(
                    "bridge recovery references unknown attestation {attestation_id}"
                ));
            }
        }
        Ok(())
    }

    fn refresh_indexes(&mut self) -> BridgeRecoveryResult<()> {
        self.quarantined_subjects = self
            .reorg_quarantines
            .values()
            .filter(|quarantine| quarantine.status.is_active())
            .flat_map(|quarantine| {
                quarantine
                    .affected_withdrawal_ids
                    .iter()
                    .map(|withdrawal_id| format!("withdrawal:{withdrawal_id}"))
                    .collect::<Vec<_>>()
            })
            .collect();
        self.claim_nullifier_index.clear();
        self.key_image_index.clear();
        for claim in self.user_claim_proofs.values() {
            if claim.status.blocks_replay() {
                if let Some(previous) = self
                    .claim_nullifier_index
                    .insert(claim.claim_nullifier.clone(), claim.claim_id.clone())
                {
                    if previous != claim.claim_id {
                        return Err("bridge recovery duplicate active claim nullifier".to_string());
                    }
                }
                if let Some(previous) = self
                    .key_image_index
                    .insert(claim.key_image_root.clone(), claim.claim_id.clone())
                {
                    if previous != claim.claim_id {
                        return Err("bridge recovery duplicate active key image".to_string());
                    }
                }
            }
        }
        self.ticket_subject_index = self
            .recovery_tickets
            .values()
            .map(|ticket| (ticket.subject_key(), ticket.ticket_id.clone()))
            .collect();
        Ok(())
    }

    fn refresh_public_records(&mut self) {
        self.public_records.clear();
        for attestation in self.witness_attestations.values() {
            self.public_records.insert(
                format!("attestation:{}", attestation.attestation_id),
                attestation.public_record(),
            );
        }
        for quarantine in self.reorg_quarantines.values() {
            self.public_records.insert(
                format!("quarantine:{}", quarantine.quarantine_id),
                quarantine.public_record(),
            );
        }
        for recovery in self.stuck_exit_recoveries.values() {
            self.public_records.insert(
                format!("stuck_exit:{}", recovery.recovery_id),
                recovery.public_record(),
            );
        }
        for deficit in self.reserve_deficits.values() {
            self.public_records.insert(
                format!("reserve_deficit:{}", deficit.remediation_id),
                deficit.public_record(),
            );
        }
        for replacement in self.signer_replacements.values() {
            self.public_records.insert(
                format!("signer_replacement:{}", replacement.replacement_id),
                replacement.public_record(),
            );
        }
        for rotation in self.pq_rotations.values() {
            self.public_records.insert(
                format!("pq_rotation:{}", rotation.rotation_id),
                rotation.public_record(),
            );
        }
        for drain in self.delayed_drains.values() {
            self.public_records
                .insert(format!("drain:{}", drain.drain_id), drain.public_record());
        }
        for ticket in self.recovery_tickets.values() {
            self.public_records.insert(
                format!("ticket:{}", ticket.ticket_id),
                ticket.public_record(),
            );
        }
        for claim in self.user_claim_proofs.values() {
            self.public_records
                .insert(format!("claim:{}", claim.claim_id), claim.public_record());
        }
        for sponsorship in self.sponsorships.values() {
            self.public_records.insert(
                format!("sponsorship:{}", sponsorship.sponsorship_id),
                sponsorship.public_record(),
            );
        }
        for audit in self.audit_trails.values() {
            self.public_records
                .insert(format!("audit:{}", audit.audit_id), audit.public_record());
        }
        for evidence in self.slashing_evidence.values() {
            self.public_records.insert(
                format!("slashing:{}", evidence.evidence_id),
                evidence.public_record(),
            );
        }
    }

    fn validate_claim_indexes(&self) -> BridgeRecoveryResult<()> {
        for (nullifier, claim_id) in &self.claim_nullifier_index {
            let claim = self.user_claim_proofs.get(claim_id).ok_or_else(|| {
                "bridge recovery nullifier index points to missing claim".to_string()
            })?;
            if &claim.claim_nullifier != nullifier {
                return Err("bridge recovery nullifier index key mismatch".to_string());
            }
            if !claim.status.blocks_replay() {
                return Err("bridge recovery nullifier index contains inactive claim".to_string());
            }
        }
        for (key_image_root, claim_id) in &self.key_image_index {
            let claim = self.user_claim_proofs.get(claim_id).ok_or_else(|| {
                "bridge recovery key image index points to missing claim".to_string()
            })?;
            if &claim.key_image_root != key_image_root {
                return Err("bridge recovery key image index key mismatch".to_string());
            }
            if !claim.status.blocks_replay() {
                return Err("bridge recovery key image index contains inactive claim".to_string());
            }
        }
        Ok(())
    }

    fn validate_quarantined_subjects(&self) -> BridgeRecoveryResult<()> {
        let expected = self
            .reorg_quarantines
            .values()
            .filter(|quarantine| quarantine.status.is_active())
            .flat_map(|quarantine| {
                quarantine
                    .affected_withdrawal_ids
                    .iter()
                    .map(|withdrawal_id| format!("withdrawal:{withdrawal_id}"))
                    .collect::<Vec<_>>()
            })
            .collect::<BTreeSet<_>>();
        if self.quarantined_subjects != expected {
            return Err("bridge recovery quarantined subject index mismatch".to_string());
        }
        Ok(())
    }

    fn validate_ticket_subject_index(&self) -> BridgeRecoveryResult<()> {
        for (subject_key, ticket_id) in &self.ticket_subject_index {
            let ticket = self
                .recovery_tickets
                .get(ticket_id)
                .ok_or_else(|| "bridge recovery ticket subject index missing ticket".to_string())?;
            if &ticket.subject_key() != subject_key {
                return Err("bridge recovery ticket subject index key mismatch".to_string());
            }
        }
        Ok(())
    }
}

pub fn bridge_recovery_state_root_from_record(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-STATE", record)
}

pub fn bridge_recovery_config_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-CONFIG-ID", record)
}

pub fn bridge_recovery_witness_attestation_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-WITNESS-ATTESTATION-ID", record)
}

pub fn bridge_recovery_reorg_quarantine_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-REORG-QUARANTINE-ID", record)
}

pub fn bridge_recovery_stuck_exit_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-STUCK-EXIT-ID", record)
}

pub fn bridge_recovery_reserve_deficit_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-RESERVE-DEFICIT-ID", record)
}

pub fn bridge_recovery_signer_replacement_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-SIGNER-REPLACEMENT-ID", record)
}

pub fn bridge_recovery_pq_rotation_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-PQ-ROTATION-ID", record)
}

pub fn bridge_recovery_delayed_drain_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-DELAYED-DRAIN-ID", record)
}

pub fn bridge_recovery_ticket_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-TICKET-ID", record)
}

pub fn bridge_recovery_user_claim_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-USER-CLAIM-ID", record)
}

pub fn bridge_recovery_low_fee_sponsorship_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-LOW-FEE-SPONSORSHIP-ID", record)
}

pub fn bridge_recovery_audit_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-AUDIT-ID", record)
}

pub fn bridge_recovery_slashing_evidence_id(record: &Value) -> String {
    bridge_recovery_payload_root("BRIDGE-RECOVERY-SLASHING-EVIDENCE-ID", record)
}

pub fn bridge_recovery_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn bridge_recovery_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn bridge_recovery_signature_root(
    domain: &str,
    signer_label: &str,
    subject_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(BRIDGE_RECOVERY_PROTOCOL_VERSION),
            HashPart::Str(signer_label),
            HashPart::Str(subject_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn bridge_recovery_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn bridge_recovery_string_set_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &ordered_strings(values)
            .iter()
            .map(|value| json!({"value": value}))
            .collect::<Vec<_>>(),
    )
}

pub fn bridge_recovery_witness_attestation_collection_root(
    attestations: &[RecoveryWitnessAttestation],
) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-WITNESS-ATTESTATION-COLLECTION",
        attestations
            .iter()
            .map(|attestation| {
                (
                    attestation.attestation_id.clone(),
                    attestation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn bridge_recovery_reorg_quarantine_collection_root(quarantines: &[ReorgQuarantine]) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-REORG-QUARANTINE-COLLECTION",
        quarantines
            .iter()
            .map(|quarantine| (quarantine.quarantine_id.clone(), quarantine.public_record()))
            .collect(),
    )
}

pub fn bridge_recovery_stuck_exit_collection_root(recoveries: &[StuckExitRecovery]) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-STUCK-EXIT-COLLECTION",
        recoveries
            .iter()
            .map(|recovery| (recovery.recovery_id.clone(), recovery.public_record()))
            .collect(),
    )
}

pub fn bridge_recovery_reserve_deficit_collection_root(
    deficits: &[ReserveDeficitRemediation],
) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-RESERVE-DEFICIT-COLLECTION",
        deficits
            .iter()
            .map(|deficit| (deficit.remediation_id.clone(), deficit.public_record()))
            .collect(),
    )
}

pub fn bridge_recovery_signer_replacement_collection_root(
    replacements: &[SignerReplacement],
) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-SIGNER-REPLACEMENT-COLLECTION",
        replacements
            .iter()
            .map(|replacement| {
                (
                    replacement.replacement_id.clone(),
                    replacement.public_record(),
                )
            })
            .collect(),
    )
}

pub fn bridge_recovery_pq_rotation_collection_root(rotations: &[PqEmergencyRotation]) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-PQ-ROTATION-COLLECTION",
        rotations
            .iter()
            .map(|rotation| (rotation.rotation_id.clone(), rotation.public_record()))
            .collect(),
    )
}

pub fn bridge_recovery_delayed_drain_collection_root(drains: &[DelayedReleaseDrain]) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-DELAYED-DRAIN-COLLECTION",
        drains
            .iter()
            .map(|drain| (drain.drain_id.clone(), drain.public_record()))
            .collect(),
    )
}

pub fn bridge_recovery_ticket_collection_root(tickets: &[RecoveryTicket]) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-TICKET-COLLECTION",
        tickets
            .iter()
            .map(|ticket| (ticket.ticket_id.clone(), ticket.public_record()))
            .collect(),
    )
}

pub fn bridge_recovery_user_claim_collection_root(claims: &[UserClaimProof]) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-USER-CLAIM-COLLECTION",
        claims
            .iter()
            .map(|claim| (claim.claim_id.clone(), claim.public_record()))
            .collect(),
    )
}

pub fn bridge_recovery_sponsorship_collection_root(
    sponsorships: &[LowFeeRecoverySponsorship],
) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-SPONSORSHIP-COLLECTION",
        sponsorships
            .iter()
            .map(|sponsorship| {
                (
                    sponsorship.sponsorship_id.clone(),
                    sponsorship.public_record(),
                )
            })
            .collect(),
    )
}

pub fn bridge_recovery_audit_collection_root(audits: &[RecoveryAuditTrail]) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-AUDIT-COLLECTION",
        audits
            .iter()
            .map(|audit| (audit.audit_id.clone(), audit.public_record()))
            .collect(),
    )
}

pub fn bridge_recovery_slashing_evidence_collection_root(
    evidence: &[RecoverySlashingEvidence],
) -> String {
    keyed_record_root(
        "BRIDGE-RECOVERY-SLASHING-EVIDENCE-COLLECTION",
        evidence
            .iter()
            .map(|evidence| (evidence.evidence_id.clone(), evidence.public_record()))
            .collect(),
    )
}

pub fn reserve_coverage_bps(reserve_units: u64, required_units: u64) -> u64 {
    if required_units == 0 {
        return BRIDGE_RECOVERY_MAX_BPS;
    }
    reserve_units
        .saturating_mul(BRIDGE_RECOVERY_MAX_BPS)
        .checked_div(required_units)
        .unwrap_or(0)
}

fn remediation_with_status(
    mut remediation: ReserveDeficitRemediation,
    status: ReserveDeficitStatus,
) -> BridgeRecoveryResult<ReserveDeficitRemediation> {
    remediation.status = status;
    remediation.validate()?;
    Ok(remediation)
}

fn keyed_record_root(domain: &str, records: Vec<(String, Value)>) -> String {
    keyed_value_root(domain, records)
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(key, record)| json!({"key": key, "record": record}))
            .collect::<Vec<_>>(),
    )
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    record
        .as_object_mut()
        .expect("bridge recovery public record object")
        .insert(field.to_string(), Value::String(root));
    record
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> BridgeRecoveryResult<()> {
    if records.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn ordered_strings(values: &[String]) -> Vec<String> {
    ordered_string_set(values).into_iter().collect()
}

fn ordered_string_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .collect()
}

fn ensure_non_empty(value: &str, label: &str) -> BridgeRecoveryResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> BridgeRecoveryResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> BridgeRecoveryResult<()> {
    if value > BRIDGE_RECOVERY_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> BridgeRecoveryResult<()> {
    if ordered_string_set(values).len() != values.len() {
        Err(format!("{label} must be unique and non-empty"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_bridge_recovery_state_validates() {
        let state = BridgeRecoveryState::devnet().expect("devnet state");
        let root = state.validate().expect("valid devnet state");
        assert_eq!(root, state.state_root());
        assert!(state.counters().active_quarantine_count > 0);
    }

    #[test]
    fn config_id_is_deterministic() {
        let left = BridgeRecoveryConfig::default();
        let right = BridgeRecoveryConfig::default();
        assert_eq!(left.config_id, right.config_id);
        assert_eq!(left.config_root(), right.config_root());
    }
}
