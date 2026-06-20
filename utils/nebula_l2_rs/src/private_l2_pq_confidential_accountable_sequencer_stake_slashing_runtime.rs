use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialAccountableSequencerStakeSlashingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-accountable-sequencer-stake-slashing-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_ACCOUNTABLE_SEQUENCER_STAKE_SLASHING_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-accountable-sequencer-v1";
pub const CONFIDENTIAL_EVIDENCE_SUITE: &str =
    "threshold-encrypted-redacted-sequencer-evidence-bundle-v1";
pub const STAKE_COMMITMENT_SUITE: &str = "confidential-sequencer-stake-commitment-v1";
pub const DEFAULT_CHAIN_ID: &str = CHAIN_ID;
pub const DEFAULT_EPOCH_LENGTH_SLOTS: u64 = 512;
pub const DEFAULT_HEARTBEAT_TTL_SLOTS: u64 = 16;
pub const DEFAULT_EVIDENCE_TTL_SLOTS: u64 = 4_096;
pub const DEFAULT_QUARANTINE_TTL_SLOTS: u64 = 2_048;
pub const DEFAULT_FINALITY_DELAY_SLOTS: u64 = 8;
pub const DEFAULT_TARGET_P95_MS: u64 = 180;
pub const DEFAULT_MAX_P95_MS: u64 = 650;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_REBATE_BPS: u64 = 9;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_OPERATOR_STAKE_MICRO_UNITS: u64 = 50_000_000;
pub const DEFAULT_MIN_WATCHER_STAKE_MICRO_UNITS: u64 = 10_000_000;
pub const DEFAULT_BASE_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 7_500;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_BPS: u64 = 8_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_SEQUENCERS: usize = 524_288;
pub const MAX_STAKE_POSITIONS: usize = 1_048_576;
pub const MAX_HEARTBEATS: usize = 4_194_304;
pub const MAX_EVIDENCE_BUNDLES: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SLASHING_CASES: usize = 524_288;
pub const MAX_QUARANTINE_FENCES: usize = 262_144;
pub const MAX_REBATES: usize = 1_048_576;
pub const MAX_SCORECARDS: usize = 524_288;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SequencerRole {
    Primary,
    Backup,
    Watcher,
    BridgeFinality,
    DataAvailability,
    ProverGateway,
    EmergencyCommittee,
}

impl SequencerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Backup => "backup",
            Self::Watcher => "watcher",
            Self::BridgeFinality => "bridge_finality",
            Self::DataAvailability => "data_availability",
            Self::ProverGateway => "prover_gateway",
            Self::EmergencyCommittee => "emergency_committee",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::Primary => 10_000,
            Self::Backup => 8_500,
            Self::BridgeFinality => 8_200,
            Self::DataAvailability => 7_600,
            Self::ProverGateway => 7_200,
            Self::EmergencyCommittee => 9_000,
            Self::Watcher => 6_500,
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SequencerStatus {
    Candidate,
    Active,
    Degraded,
    Quarantined,
    Slashed,
    Retired,
}

impl SequencerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Equivocation,
    WithheldPreconfirmation,
    InvalidStateDiff,
    DelayedWitness,
    FeeOvercharge,
    PrivacyLeak,
    BridgeFinalityMismatch,
    DaUnavailability,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::WithheldPreconfirmation => "withheld_preconfirmation",
            Self::InvalidStateDiff => "invalid_state_diff",
            Self::DelayedWitness => "delayed_witness",
            Self::FeeOvercharge => "fee_overcharge",
            Self::PrivacyLeak => "privacy_leak",
            Self::BridgeFinalityMismatch => "bridge_finality_mismatch",
            Self::DaUnavailability => "da_unavailability",
        }
    }

    pub fn base_severity_bps(self) -> u64 {
        match self {
            Self::Equivocation => 9_500,
            Self::InvalidStateDiff => 9_200,
            Self::PrivacyLeak => 9_000,
            Self::BridgeFinalityMismatch => 8_700,
            Self::DaUnavailability => 7_800,
            Self::WithheldPreconfirmation => 7_500,
            Self::FeeOvercharge => 6_500,
            Self::DelayedWitness => 5_800,
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignature,
    WatcherQuorum,
    EvidenceDecryptShare,
    MoneroReserveHint,
    PrivacyBudget,
    FeeCap,
    Liveness,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignature => "pq_signature",
            Self::WatcherQuorum => "watcher_quorum",
            Self::EvidenceDecryptShare => "evidence_decrypt_share",
            Self::MoneroReserveHint => "monero_reserve_hint",
            Self::PrivacyBudget => "privacy_budget",
            Self::FeeCap => "fee_cap",
            Self::Liveness => "liveness",
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Open,
    Attesting,
    Quarantined,
    Settled,
    Rejected,
    Appealed,
}

impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attesting => "attesting",
            Self::Quarantined => "quarantined",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Appealed => "appealed",
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Proposed,
    Reserved,
    Paid,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Reserved => "reserved",
            Self::Paid => "paid",
            Self::Expired => "expired",
        }
    }

    pub fn public_record(self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub epoch_length_slots: u64,
    pub heartbeat_ttl_slots: u64,
    pub evidence_ttl_slots: u64,
    pub quarantine_ttl_slots: u64,
    pub finality_delay_slots: u64,
    pub target_p95_ms: u64,
    pub max_p95_ms: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_operator_stake_micro_units: u64,
    pub min_watcher_stake_micro_units: u64,
    pub base_slash_bps: u64,
    pub max_slash_bps: u64,
    pub quorum_bps: u64,
    pub supermajority_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            epoch_length_slots: DEFAULT_EPOCH_LENGTH_SLOTS,
            heartbeat_ttl_slots: DEFAULT_HEARTBEAT_TTL_SLOTS,
            evidence_ttl_slots: DEFAULT_EVIDENCE_TTL_SLOTS,
            quarantine_ttl_slots: DEFAULT_QUARANTINE_TTL_SLOTS,
            finality_delay_slots: DEFAULT_FINALITY_DELAY_SLOTS,
            target_p95_ms: DEFAULT_TARGET_P95_MS,
            max_p95_ms: DEFAULT_MAX_P95_MS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_REBATE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_operator_stake_micro_units: DEFAULT_MIN_OPERATOR_STAKE_MICRO_UNITS,
            min_watcher_stake_micro_units: DEFAULT_MIN_WATCHER_STAKE_MICRO_UNITS,
            base_slash_bps: DEFAULT_BASE_SLASH_BPS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            supermajority_bps: DEFAULT_SUPERMAJORITY_BPS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "protocol_version mismatch: expected {PROTOCOL_VERSION}, got {}",
                self.protocol_version
            ));
        }
        if self.chain_id.is_empty() {
            return Err("chain_id cannot be empty".to_string());
        }
        if self.epoch_length_slots == 0 {
            return Err("epoch_length_slots must be non-zero".to_string());
        }
        if self.heartbeat_ttl_slots == 0 {
            return Err("heartbeat_ttl_slots must be non-zero".to_string());
        }
        if self.max_p95_ms < self.target_p95_ms {
            return Err("max_p95_ms must be >= target_p95_ms".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.target_rebate_bps > MAX_BPS
            || self.base_slash_bps > MAX_BPS
            || self.max_slash_bps > MAX_BPS
            || self.quorum_bps > MAX_BPS
            || self.supermajority_bps > MAX_BPS
        {
            return Err("basis point config exceeds MAX_BPS".to_string());
        }
        if self.max_slash_bps < self.base_slash_bps {
            return Err("max_slash_bps must be >= base_slash_bps".to_string());
        }
        if self.quorum_bps > self.supermajority_bps {
            return Err("quorum_bps must be <= supermajority_bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "epoch_length_slots": self.epoch_length_slots,
            "heartbeat_ttl_slots": self.heartbeat_ttl_slots,
            "evidence_ttl_slots": self.evidence_ttl_slots,
            "quarantine_ttl_slots": self.quarantine_ttl_slots,
            "finality_delay_slots": self.finality_delay_slots,
            "target_p95_ms": self.target_p95_ms,
            "max_p95_ms": self.max_p95_ms,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_operator_stake_micro_units": self.min_operator_stake_micro_units,
            "min_watcher_stake_micro_units": self.min_watcher_stake_micro_units,
            "base_slash_bps": self.base_slash_bps,
            "max_slash_bps": self.max_slash_bps,
            "quorum_bps": self.quorum_bps,
            "supermajority_bps": self.supermajority_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sequencers_registered: u64,
    pub stake_positions_opened: u64,
    pub heartbeats_recorded: u64,
    pub evidence_bundles_submitted: u64,
    pub pq_attestations_recorded: u64,
    pub slashing_cases_opened: u64,
    pub quarantine_fences_opened: u64,
    pub rebates_issued: u64,
    pub slashing_settlements: u64,
    pub redacted_evidence_bytes: u64,
    pub protected_users: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sequencers_registered": self.sequencers_registered,
            "stake_positions_opened": self.stake_positions_opened,
            "heartbeats_recorded": self.heartbeats_recorded,
            "evidence_bundles_submitted": self.evidence_bundles_submitted,
            "pq_attestations_recorded": self.pq_attestations_recorded,
            "slashing_cases_opened": self.slashing_cases_opened,
            "quarantine_fences_opened": self.quarantine_fences_opened,
            "rebates_issued": self.rebates_issued,
            "slashing_settlements": self.slashing_settlements,
            "redacted_evidence_bytes": self.redacted_evidence_bytes,
            "protected_users": self.protected_users,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub state_root: String,
    pub sequencer_root: String,
    pub stake_root: String,
    pub heartbeat_root: String,
    pub evidence_root: String,
    pub attestation_root: String,
    pub slashing_root: String,
    pub quarantine_root: String,
    pub rebate_root: String,
    pub scorecard_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root,
            "sequencer_root": self.sequencer_root,
            "stake_root": self.stake_root,
            "heartbeat_root": self.heartbeat_root,
            "evidence_root": self.evidence_root,
            "attestation_root": self.attestation_root,
            "slashing_root": self.slashing_root,
            "quarantine_root": self.quarantine_root,
            "rebate_root": self.rebate_root,
            "scorecard_root": self.scorecard_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencerRecord {
    pub sequencer_id: String,
    pub operator_commitment: String,
    pub role: SequencerRole,
    pub status: SequencerStatus,
    pub pq_identity_commitment: String,
    pub stake_commitment: String,
    pub endpoint_commitment: String,
    pub jurisdiction_hash: String,
    pub registered_epoch: u64,
    pub last_heartbeat_slot: u64,
    pub target_p95_ms: u64,
    pub max_fee_bps: u64,
    pub privacy_set_floor: u64,
    pub active_case_count: u64,
    pub reputation_bps: u64,
}

impl SequencerRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "sequencer_id": self.sequencer_id,
            "operator_commitment": self.operator_commitment,
            "role": self.role.public_record(),
            "status": self.status.public_record(),
            "pq_identity_commitment": self.pq_identity_commitment,
            "stake_commitment": self.stake_commitment,
            "endpoint_commitment": self.endpoint_commitment,
            "jurisdiction_hash": self.jurisdiction_hash,
            "registered_epoch": self.registered_epoch,
            "last_heartbeat_slot": self.last_heartbeat_slot,
            "target_p95_ms": self.target_p95_ms,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_floor": self.privacy_set_floor,
            "active_case_count": self.active_case_count,
            "reputation_bps": self.reputation_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StakePosition {
    pub stake_id: String,
    pub sequencer_id: String,
    pub staker_commitment: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub locked_until_epoch: u64,
    pub slashable_bps: u64,
    pub reward_share_bps: u64,
    pub stake_nullifier_root: String,
    pub reserve_proof_root: String,
}

impl StakePosition {
    pub fn public_record(&self) -> Value {
        json!({
            "stake_id": self.stake_id,
            "sequencer_id": self.sequencer_id,
            "staker_commitment": self.staker_commitment,
            "asset_id": self.asset_id,
            "amount_micro_units": self.amount_micro_units,
            "locked_until_epoch": self.locked_until_epoch,
            "slashable_bps": self.slashable_bps,
            "reward_share_bps": self.reward_share_bps,
            "stake_nullifier_root": self.stake_nullifier_root,
            "reserve_proof_root": self.reserve_proof_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LivenessHeartbeat {
    pub heartbeat_id: String,
    pub sequencer_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub p95_ms: u64,
    pub pending_preconfirmations: u64,
    pub state_diff_root: String,
    pub witness_availability_root: String,
    pub fee_quote_root: String,
    pub pq_signature_commitment: String,
    pub accepted: bool,
}

impl LivenessHeartbeat {
    pub fn public_record(&self) -> Value {
        json!({
            "heartbeat_id": self.heartbeat_id,
            "sequencer_id": self.sequencer_id,
            "epoch": self.epoch,
            "slot": self.slot,
            "p95_ms": self.p95_ms,
            "pending_preconfirmations": self.pending_preconfirmations,
            "state_diff_root": self.state_diff_root,
            "witness_availability_root": self.witness_availability_root,
            "fee_quote_root": self.fee_quote_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedEvidenceBundle {
    pub evidence_id: String,
    pub reporter_commitment: String,
    pub accused_sequencer_id: String,
    pub kind: EvidenceKind,
    pub epoch: u64,
    pub slot: u64,
    pub sealed_payload_root: String,
    pub redacted_public_root: String,
    pub decrypt_committee_root: String,
    pub affected_user_count: u64,
    pub affected_contract_count: u64,
    pub claimed_fee_overcharge_bps: u64,
    pub observed_latency_ms: u64,
    pub privacy_set_size: u64,
    pub expires_slot: u64,
    pub severity_bps: u64,
}

impl RedactedEvidenceBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "reporter_commitment": self.reporter_commitment,
            "accused_sequencer_id": self.accused_sequencer_id,
            "kind": self.kind.public_record(),
            "epoch": self.epoch,
            "slot": self.slot,
            "sealed_payload_root": self.sealed_payload_root,
            "redacted_public_root": self.redacted_public_root,
            "decrypt_committee_root": self.decrypt_committee_root,
            "affected_user_count": self.affected_user_count,
            "affected_contract_count": self.affected_contract_count,
            "claimed_fee_overcharge_bps": self.claimed_fee_overcharge_bps,
            "observed_latency_ms": self.observed_latency_ms,
            "privacy_set_size": self.privacy_set_size,
            "expires_slot": self.expires_slot,
            "severity_bps": self.severity_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub target_id: String,
    pub attester_commitment: String,
    pub kind: AttestationKind,
    pub epoch: u64,
    pub slot: u64,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub quorum_weight_bps: u64,
    pub accepted: bool,
}

impl PqAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "target_id": self.target_id,
            "attester_commitment": self.attester_commitment,
            "kind": self.kind.public_record(),
            "epoch": self.epoch,
            "slot": self.slot,
            "signature_commitment": self.signature_commitment,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingCase {
    pub case_id: String,
    pub accused_sequencer_id: String,
    pub evidence_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub status: SlashingStatus,
    pub opened_epoch: u64,
    pub opened_slot: u64,
    pub settlement_slot: u64,
    pub slash_bps: u64,
    pub slash_amount_micro_units: u64,
    pub rebate_pool_micro_units: u64,
    pub operator_penalty_root: String,
    pub appeal_window_slots: u64,
}

impl SlashingCase {
    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "accused_sequencer_id": self.accused_sequencer_id,
            "evidence_ids": self.evidence_ids,
            "attestation_ids": self.attestation_ids,
            "status": self.status.public_record(),
            "opened_epoch": self.opened_epoch,
            "opened_slot": self.opened_slot,
            "settlement_slot": self.settlement_slot,
            "slash_bps": self.slash_bps,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "rebate_pool_micro_units": self.rebate_pool_micro_units,
            "operator_penalty_root": self.operator_penalty_root,
            "appeal_window_slots": self.appeal_window_slots,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineFence {
    pub fence_id: String,
    pub sequencer_id: String,
    pub case_id: String,
    pub opened_slot: u64,
    pub expires_slot: u64,
    pub blocked_roles: BTreeSet<SequencerRole>,
    pub safe_exit_root: String,
    pub replacement_committee_root: String,
}

impl QuarantineFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "sequencer_id": self.sequencer_id,
            "case_id": self.case_id,
            "opened_slot": self.opened_slot,
            "expires_slot": self.expires_slot,
            "blocked_roles": self.blocked_roles.iter().map(|role| role.public_record()).collect::<Vec<_>>(),
            "safe_exit_root": self.safe_exit_root,
            "replacement_committee_root": self.replacement_committee_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub case_id: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub status: RebateStatus,
    pub privacy_redaction_root: String,
    pub expires_slot: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "case_id": self.case_id,
            "beneficiary_group_root": self.beneficiary_group_root,
            "asset_id": self.asset_id,
            "amount_micro_units": self.amount_micro_units,
            "fee_rebate_bps": self.fee_rebate_bps,
            "status": self.status.public_record(),
            "privacy_redaction_root": self.privacy_redaction_root,
            "expires_slot": self.expires_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencerScorecard {
    pub scorecard_id: String,
    pub sequencer_id: String,
    pub epoch: u64,
    pub uptime_bps: u64,
    pub p95_latency_ms: u64,
    pub fee_compliance_bps: u64,
    pub pq_attestation_bps: u64,
    pub privacy_floor_bps: u64,
    pub slashing_risk_bps: u64,
    pub composite_score_bps: u64,
    pub public_summary_root: String,
}

impl SequencerScorecard {
    pub fn public_record(&self) -> Value {
        json!({
            "scorecard_id": self.scorecard_id,
            "sequencer_id": self.sequencer_id,
            "epoch": self.epoch,
            "uptime_bps": self.uptime_bps,
            "p95_latency_ms": self.p95_latency_ms,
            "fee_compliance_bps": self.fee_compliance_bps,
            "pq_attestation_bps": self.pq_attestation_bps,
            "privacy_floor_bps": self.privacy_floor_bps,
            "slashing_risk_bps": self.slashing_risk_bps,
            "composite_score_bps": self.composite_score_bps,
            "public_summary_root": self.public_summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterSequencerRequest {
    pub operator_commitment: String,
    pub role: SequencerRole,
    pub pq_identity_commitment: String,
    pub endpoint_commitment: String,
    pub jurisdiction_hash: String,
    pub epoch: u64,
    pub slot: u64,
    pub target_p95_ms: u64,
    pub max_fee_bps: u64,
    pub privacy_set_floor: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StakeRequest {
    pub sequencer_id: String,
    pub staker_commitment: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub locked_until_epoch: u64,
    pub slashable_bps: u64,
    pub reward_share_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeartbeatRequest {
    pub sequencer_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub p95_ms: u64,
    pub pending_preconfirmations: u64,
    pub state_diff_root: String,
    pub witness_availability_root: String,
    pub fee_quote_root: String,
    pub pq_signature_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceRequest {
    pub reporter_commitment: String,
    pub accused_sequencer_id: String,
    pub kind: EvidenceKind,
    pub epoch: u64,
    pub slot: u64,
    pub sealed_payload_root: String,
    pub redacted_public_root: String,
    pub decrypt_committee_root: String,
    pub affected_user_count: u64,
    pub affected_contract_count: u64,
    pub claimed_fee_overcharge_bps: u64,
    pub observed_latency_ms: u64,
    pub privacy_set_size: u64,
    pub redacted_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationRequest {
    pub target_id: String,
    pub attester_commitment: String,
    pub kind: AttestationKind,
    pub epoch: u64,
    pub slot: u64,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub quorum_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenSlashingCaseRequest {
    pub accused_sequencer_id: String,
    pub evidence_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub opened_epoch: u64,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRequest {
    pub sequencer_id: String,
    pub case_id: String,
    pub opened_slot: u64,
    pub blocked_roles: BTreeSet<SequencerRole>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleSlashingRequest {
    pub case_id: String,
    pub settlement_slot: u64,
    pub slash_bps: u64,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRequest {
    pub case_id: String,
    pub beneficiary_group_root: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub fee_rebate_bps: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub sequencers: BTreeMap<String, SequencerRecord>,
    pub stake_positions: BTreeMap<String, StakePosition>,
    pub heartbeats: BTreeMap<String, LivenessHeartbeat>,
    pub evidence_bundles: BTreeMap<String, RedactedEvidenceBundle>,
    pub attestations: BTreeMap<String, PqAttestation>,
    pub slashing_cases: BTreeMap<String, SlashingCase>,
    pub quarantine_fences: BTreeMap<String, QuarantineFence>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub scorecards: BTreeMap<String, SequencerScorecard>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            sequencers: BTreeMap::new(),
            stake_positions: BTreeMap::new(),
            heartbeats: BTreeMap::new(),
            evidence_bundles: BTreeMap::new(),
            attestations: BTreeMap::new(),
            slashing_cases: BTreeMap::new(),
            quarantine_fences: BTreeMap::new(),
            rebates: BTreeMap::new(),
            scorecards: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("valid devnet config");
        let primary = state
            .register_sequencer(RegisterSequencerRequest {
                operator_commitment: "operator:devnet:primary:commitment".to_string(),
                role: SequencerRole::Primary,
                pq_identity_commitment: "ml-dsa-primary-identity-root".to_string(),
                endpoint_commitment: "endpoint:primary:hidden-service-root".to_string(),
                jurisdiction_hash: "jurisdiction:redacted:na".to_string(),
                epoch: 1,
                slot: 512,
                target_p95_ms: 140,
                max_fee_bps: 12,
                privacy_set_floor: 262_144,
            })
            .expect("register primary sequencer");
        let backup = state
            .register_sequencer(RegisterSequencerRequest {
                operator_commitment: "operator:devnet:backup:commitment".to_string(),
                role: SequencerRole::Backup,
                pq_identity_commitment: "ml-dsa-backup-identity-root".to_string(),
                endpoint_commitment: "endpoint:backup:hidden-service-root".to_string(),
                jurisdiction_hash: "jurisdiction:redacted:eu".to_string(),
                epoch: 1,
                slot: 514,
                target_p95_ms: 165,
                max_fee_bps: 14,
                privacy_set_floor: 131_072,
            })
            .expect("register backup sequencer");
        let watcher = state
            .register_sequencer(RegisterSequencerRequest {
                operator_commitment: "operator:devnet:watcher:commitment".to_string(),
                role: SequencerRole::Watcher,
                pq_identity_commitment: "slh-dsa-watcher-identity-root".to_string(),
                endpoint_commitment: "endpoint:watcher:hidden-service-root".to_string(),
                jurisdiction_hash: "jurisdiction:redacted:apac".to_string(),
                epoch: 1,
                slot: 516,
                target_p95_ms: 240,
                max_fee_bps: 10,
                privacy_set_floor: 524_288,
            })
            .expect("register watcher sequencer");

        state
            .bond_stake(StakeRequest {
                sequencer_id: primary.clone(),
                staker_commitment: "stake:primary:reserve-commitment".to_string(),
                asset_id: "piconero-devnet".to_string(),
                amount_micro_units: 250_000_000,
                locked_until_epoch: 16,
                slashable_bps: 8_000,
                reward_share_bps: 6_500,
            })
            .expect("primary stake");
        state
            .bond_stake(StakeRequest {
                sequencer_id: backup.clone(),
                staker_commitment: "stake:backup:reserve-commitment".to_string(),
                asset_id: "piconero-devnet".to_string(),
                amount_micro_units: 150_000_000,
                locked_until_epoch: 16,
                slashable_bps: 6_500,
                reward_share_bps: 5_500,
            })
            .expect("backup stake");
        state
            .bond_stake(StakeRequest {
                sequencer_id: watcher.clone(),
                staker_commitment: "stake:watcher:reserve-commitment".to_string(),
                asset_id: "piconero-devnet".to_string(),
                amount_micro_units: 50_000_000,
                locked_until_epoch: 12,
                slashable_bps: 4_000,
                reward_share_bps: 3_500,
            })
            .expect("watcher stake");

        let hb = state
            .record_heartbeat(HeartbeatRequest {
                sequencer_id: primary.clone(),
                epoch: 2,
                slot: 1_024,
                p95_ms: 132,
                pending_preconfirmations: 8,
                state_diff_root: "state-diff:epoch2:slot1024".to_string(),
                witness_availability_root: "witness:availability:epoch2:slot1024".to_string(),
                fee_quote_root: "fee-quotes:epoch2:slot1024".to_string(),
                pq_signature_commitment: "ml-dsa-signature:heartbeat:primary".to_string(),
            })
            .expect("heartbeat");
        let evidence = state
            .submit_evidence(EvidenceRequest {
                reporter_commitment: "reporter:watcher:sealed".to_string(),
                accused_sequencer_id: backup.clone(),
                kind: EvidenceKind::WithheldPreconfirmation,
                epoch: 2,
                slot: 1_033,
                sealed_payload_root: "sealed:evidence:withheld-preconfirmation".to_string(),
                redacted_public_root: "redacted:evidence:withheld-preconfirmation".to_string(),
                decrypt_committee_root: "decrypt-committee:watcher-quorum".to_string(),
                affected_user_count: 512,
                affected_contract_count: 9,
                claimed_fee_overcharge_bps: 0,
                observed_latency_ms: 870,
                privacy_set_size: 262_144,
                redacted_bytes: 24_576,
            })
            .expect("evidence");
        let attestation = state
            .record_attestation(AttestationRequest {
                target_id: evidence.clone(),
                attester_commitment: "attester:watcher-quorum:commitment".to_string(),
                kind: AttestationKind::WatcherQuorum,
                epoch: 2,
                slot: 1_036,
                signature_commitment: "ml-dsa:watcher-quorum:signature-root".to_string(),
                transcript_root: "transcript:evidence:withheld-preconfirmation".to_string(),
                security_bits: 256,
                quorum_weight_bps: 7_200,
            })
            .expect("attestation");
        let case_id = state
            .open_slashing_case(OpenSlashingCaseRequest {
                accused_sequencer_id: backup.clone(),
                evidence_ids: vec![evidence],
                attestation_ids: vec![attestation],
                opened_epoch: 2,
                opened_slot: 1_040,
            })
            .expect("case");
        state
            .apply_quarantine(QuarantineRequest {
                sequencer_id: backup,
                case_id: case_id.clone(),
                opened_slot: 1_041,
                blocked_roles: [SequencerRole::Primary, SequencerRole::BridgeFinality]
                    .into_iter()
                    .collect(),
            })
            .expect("quarantine");
        state
            .issue_rebate(RebateRequest {
                case_id: case_id.clone(),
                beneficiary_group_root: "beneficiaries:withheld-preconfirmation:batch".to_string(),
                asset_id: "piconero-devnet".to_string(),
                amount_micro_units: 1_500_000,
                fee_rebate_bps: 9,
                expires_slot: 2_048,
            })
            .expect("rebate");
        state
            .settle_slashing(SettleSlashingRequest {
                case_id,
                settlement_slot: 1_080,
                slash_bps: 1_800,
                accepted: true,
            })
            .expect("settle");
        state.update_scorecard(&primary, 2).expect("scorecard");
        state.refresh_roots();
        assert!(state.heartbeats.contains_key(&hb));
        state
    }

    pub fn register_sequencer(&mut self, request: RegisterSequencerRequest) -> Result<String> {
        self.ensure_capacity(self.sequencers.len(), MAX_SEQUENCERS, "sequencers")?;
        if request.operator_commitment.is_empty() || request.pq_identity_commitment.is_empty() {
            return Err("operator and PQ identity commitments are required".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err(format!(
                "max_fee_bps {} exceeds configured limit {}",
                request.max_fee_bps, self.config.max_user_fee_bps
            ));
        }
        if request.privacy_set_floor < self.config.min_privacy_set_size {
            return Err("privacy set floor below configured minimum".to_string());
        }
        let sequencer_id = stable_id(
            "sequencer",
            &[
                HashPart::Str(&request.operator_commitment),
                HashPart::Str(request.role.as_str()),
                HashPart::Str(&request.pq_identity_commitment),
                HashPart::U64(request.epoch),
                HashPart::U64(request.slot),
            ],
        );
        let stake_commitment = domain_hash(
            STAKE_COMMITMENT_SUITE,
            &[
                HashPart::Str(&sequencer_id),
                HashPart::Str(&request.operator_commitment),
            ],
            32,
        );
        self.sequencers.insert(
            sequencer_id.clone(),
            SequencerRecord {
                sequencer_id: sequencer_id.clone(),
                operator_commitment: request.operator_commitment,
                role: request.role,
                status: SequencerStatus::Candidate,
                pq_identity_commitment: request.pq_identity_commitment,
                stake_commitment,
                endpoint_commitment: request.endpoint_commitment,
                jurisdiction_hash: request.jurisdiction_hash,
                registered_epoch: request.epoch,
                last_heartbeat_slot: request.slot,
                target_p95_ms: request.target_p95_ms,
                max_fee_bps: request.max_fee_bps,
                privacy_set_floor: request.privacy_set_floor,
                active_case_count: 0,
                reputation_bps: request.role.weight_bps(),
            },
        );
        self.counters.sequencers_registered += 1;
        self.refresh_roots();
        Ok(sequencer_id)
    }

    pub fn bond_stake(&mut self, request: StakeRequest) -> Result<String> {
        self.ensure_capacity(
            self.stake_positions.len(),
            MAX_STAKE_POSITIONS,
            "stake_positions",
        )?;
        if !self.sequencers.contains_key(&request.sequencer_id) {
            return Err(format!("unknown sequencer_id {}", request.sequencer_id));
        }
        let minimum = if self
            .sequencers
            .get(&request.sequencer_id)
            .map(|seq| seq.role == SequencerRole::Watcher)
            .unwrap_or(false)
        {
            self.config.min_watcher_stake_micro_units
        } else {
            self.config.min_operator_stake_micro_units
        };
        if request.amount_micro_units < minimum {
            return Err(format!(
                "stake {} below minimum {}",
                request.amount_micro_units, minimum
            ));
        }
        if request.slashable_bps > MAX_BPS || request.reward_share_bps > MAX_BPS {
            return Err("stake bps exceeds MAX_BPS".to_string());
        }
        let stake_id = stable_id(
            "stake",
            &[
                HashPart::Str(&request.sequencer_id),
                HashPart::Str(&request.staker_commitment),
                HashPart::Str(&request.asset_id),
                HashPart::U64(request.amount_micro_units),
            ],
        );
        let stake_nullifier_root = domain_hash(
            "accountable-sequencer-stake-nullifier-root",
            &[
                HashPart::Str(&stake_id),
                HashPart::Str(&request.staker_commitment),
            ],
            32,
        );
        let reserve_proof_root = domain_hash(
            "accountable-sequencer-reserve-proof-root",
            &[
                HashPart::Str(&stake_id),
                HashPart::Str(&request.asset_id),
                HashPart::U64(request.amount_micro_units),
            ],
            32,
        );
        self.stake_positions.insert(
            stake_id.clone(),
            StakePosition {
                stake_id: stake_id.clone(),
                sequencer_id: request.sequencer_id.clone(),
                staker_commitment: request.staker_commitment,
                asset_id: request.asset_id,
                amount_micro_units: request.amount_micro_units,
                locked_until_epoch: request.locked_until_epoch,
                slashable_bps: request.slashable_bps,
                reward_share_bps: request.reward_share_bps,
                stake_nullifier_root,
                reserve_proof_root,
            },
        );
        if let Some(sequencer) = self.sequencers.get_mut(&request.sequencer_id) {
            sequencer.status = SequencerStatus::Active;
        }
        self.counters.stake_positions_opened += 1;
        self.refresh_roots();
        Ok(stake_id)
    }

    pub fn record_heartbeat(&mut self, request: HeartbeatRequest) -> Result<String> {
        self.ensure_capacity(self.heartbeats.len(), MAX_HEARTBEATS, "heartbeats")?;
        let sequencer = self
            .sequencers
            .get_mut(&request.sequencer_id)
            .ok_or_else(|| format!("unknown sequencer_id {}", request.sequencer_id))?;
        let accepted = request.p95_ms <= self.config.max_p95_ms
            && request.pq_signature_commitment.len() >= 16
            && sequencer.status != SequencerStatus::Slashed;
        let heartbeat_id = stable_id(
            "heartbeat",
            &[
                HashPart::Str(&request.sequencer_id),
                HashPart::U64(request.epoch),
                HashPart::U64(request.slot),
                HashPart::Str(&request.state_diff_root),
            ],
        );
        sequencer.last_heartbeat_slot = request.slot;
        if accepted && request.p95_ms <= self.config.target_p95_ms {
            sequencer.reputation_bps = bounded_add(sequencer.reputation_bps, 35);
        } else if request.p95_ms > self.config.max_p95_ms {
            sequencer.status = SequencerStatus::Degraded;
            sequencer.reputation_bps = sequencer.reputation_bps.saturating_sub(250);
        }
        self.heartbeats.insert(
            heartbeat_id.clone(),
            LivenessHeartbeat {
                heartbeat_id: heartbeat_id.clone(),
                sequencer_id: request.sequencer_id,
                epoch: request.epoch,
                slot: request.slot,
                p95_ms: request.p95_ms,
                pending_preconfirmations: request.pending_preconfirmations,
                state_diff_root: request.state_diff_root,
                witness_availability_root: request.witness_availability_root,
                fee_quote_root: request.fee_quote_root,
                pq_signature_commitment: request.pq_signature_commitment,
                accepted,
            },
        );
        self.counters.heartbeats_recorded += 1;
        self.refresh_roots();
        Ok(heartbeat_id)
    }

    pub fn submit_evidence(&mut self, request: EvidenceRequest) -> Result<String> {
        self.ensure_capacity(
            self.evidence_bundles.len(),
            MAX_EVIDENCE_BUNDLES,
            "evidence_bundles",
        )?;
        if !self.sequencers.contains_key(&request.accused_sequencer_id) {
            return Err(format!(
                "unknown accused_sequencer_id {}",
                request.accused_sequencer_id
            ));
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("evidence privacy set below minimum".to_string());
        }
        let severity_bps = self.compute_evidence_severity(&request);
        let evidence_id = stable_id(
            "evidence",
            &[
                HashPart::Str(&request.reporter_commitment),
                HashPart::Str(&request.accused_sequencer_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.sealed_payload_root),
                HashPart::U64(request.slot),
            ],
        );
        self.counters.redacted_evidence_bytes = self
            .counters
            .redacted_evidence_bytes
            .saturating_add(request.redacted_bytes);
        self.counters.protected_users = self
            .counters
            .protected_users
            .saturating_add(request.affected_user_count);
        self.evidence_bundles.insert(
            evidence_id.clone(),
            RedactedEvidenceBundle {
                evidence_id: evidence_id.clone(),
                reporter_commitment: request.reporter_commitment,
                accused_sequencer_id: request.accused_sequencer_id,
                kind: request.kind,
                epoch: request.epoch,
                slot: request.slot,
                sealed_payload_root: request.sealed_payload_root,
                redacted_public_root: request.redacted_public_root,
                decrypt_committee_root: request.decrypt_committee_root,
                affected_user_count: request.affected_user_count,
                affected_contract_count: request.affected_contract_count,
                claimed_fee_overcharge_bps: request.claimed_fee_overcharge_bps,
                observed_latency_ms: request.observed_latency_ms,
                privacy_set_size: request.privacy_set_size,
                expires_slot: request.slot.saturating_add(self.config.evidence_ttl_slots),
                severity_bps,
            },
        );
        self.counters.evidence_bundles_submitted += 1;
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn record_attestation(&mut self, request: AttestationRequest) -> Result<String> {
        self.ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("PQ attestation security bits below configured minimum".to_string());
        }
        if request.quorum_weight_bps > MAX_BPS {
            return Err("quorum_weight_bps exceeds MAX_BPS".to_string());
        }
        let accepted = request.quorum_weight_bps >= self.config.quorum_bps;
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.target_id),
                HashPart::Str(&request.attester_commitment),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.signature_commitment),
                HashPart::U64(request.slot),
            ],
        );
        self.attestations.insert(
            attestation_id.clone(),
            PqAttestation {
                attestation_id: attestation_id.clone(),
                target_id: request.target_id,
                attester_commitment: request.attester_commitment,
                kind: request.kind,
                epoch: request.epoch,
                slot: request.slot,
                signature_commitment: request.signature_commitment,
                transcript_root: request.transcript_root,
                security_bits: request.security_bits,
                quorum_weight_bps: request.quorum_weight_bps,
                accepted,
            },
        );
        self.counters.pq_attestations_recorded += 1;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn open_slashing_case(&mut self, request: OpenSlashingCaseRequest) -> Result<String> {
        self.ensure_capacity(
            self.slashing_cases.len(),
            MAX_SLASHING_CASES,
            "slashing_cases",
        )?;
        if request.evidence_ids.is_empty() {
            return Err("slashing case requires at least one evidence id".to_string());
        }
        let total_severity = request
            .evidence_ids
            .iter()
            .map(|id| {
                self.evidence_bundles
                    .get(id)
                    .map(|evidence| evidence.severity_bps)
                    .ok_or_else(|| format!("unknown evidence_id {id}"))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .sum::<u64>();
        let accepted_attestations = request
            .attestation_ids
            .iter()
            .filter_map(|id| self.attestations.get(id))
            .filter(|attestation| attestation.accepted)
            .count() as u64;
        let slash_bps = (self.config.base_slash_bps + total_severity / 8)
            .min(self.config.max_slash_bps)
            .min(MAX_BPS);
        let slash_amount_micro_units =
            self.slashable_stake_for(&request.accused_sequencer_id, slash_bps);
        let rebate_pool_micro_units = slash_amount_micro_units / 4;
        let case_id = stable_id(
            "slashing-case",
            &[
                HashPart::Str(&request.accused_sequencer_id),
                HashPart::U64(request.opened_epoch),
                HashPart::U64(request.opened_slot),
                HashPart::U64(total_severity),
                HashPart::U64(accepted_attestations),
            ],
        );
        let status = if accepted_attestations > 0 {
            SlashingStatus::Attesting
        } else {
            SlashingStatus::Open
        };
        self.slashing_cases.insert(
            case_id.clone(),
            SlashingCase {
                case_id: case_id.clone(),
                accused_sequencer_id: request.accused_sequencer_id.clone(),
                evidence_ids: request.evidence_ids,
                attestation_ids: request.attestation_ids,
                status,
                opened_epoch: request.opened_epoch,
                opened_slot: request.opened_slot,
                settlement_slot: request
                    .opened_slot
                    .saturating_add(self.config.finality_delay_slots),
                slash_bps,
                slash_amount_micro_units,
                rebate_pool_micro_units,
                operator_penalty_root: domain_hash(
                    "accountable-sequencer-operator-penalty-root",
                    &[
                        HashPart::Str(&request.accused_sequencer_id),
                        HashPart::U64(slash_bps),
                    ],
                    32,
                ),
                appeal_window_slots: self.config.finality_delay_slots.saturating_mul(4),
            },
        );
        if let Some(sequencer) = self.sequencers.get_mut(&request.accused_sequencer_id) {
            sequencer.active_case_count = sequencer.active_case_count.saturating_add(1);
            sequencer.status = SequencerStatus::Degraded;
            sequencer.reputation_bps = sequencer.reputation_bps.saturating_sub(slash_bps / 4);
        }
        self.counters.slashing_cases_opened += 1;
        self.refresh_roots();
        Ok(case_id)
    }

    pub fn apply_quarantine(&mut self, request: QuarantineRequest) -> Result<String> {
        self.ensure_capacity(
            self.quarantine_fences.len(),
            MAX_QUARANTINE_FENCES,
            "quarantine_fences",
        )?;
        if !self.slashing_cases.contains_key(&request.case_id) {
            return Err(format!("unknown case_id {}", request.case_id));
        }
        let fence_id = stable_id(
            "quarantine",
            &[
                HashPart::Str(&request.sequencer_id),
                HashPart::Str(&request.case_id),
                HashPart::U64(request.opened_slot),
            ],
        );
        let safe_exit_root = domain_hash(
            "accountable-sequencer-safe-exit-root",
            &[
                HashPart::Str(&request.sequencer_id),
                HashPart::Str(&request.case_id),
                HashPart::U64(request.opened_slot),
            ],
            32,
        );
        let replacement_committee_root = domain_hash(
            "accountable-sequencer-replacement-committee-root",
            &[
                HashPart::Str(&request.case_id),
                HashPart::Json(&json!(&request.blocked_roles)),
            ],
            32,
        );
        self.quarantine_fences.insert(
            fence_id.clone(),
            QuarantineFence {
                fence_id: fence_id.clone(),
                sequencer_id: request.sequencer_id.clone(),
                case_id: request.case_id.clone(),
                opened_slot: request.opened_slot,
                expires_slot: request
                    .opened_slot
                    .saturating_add(self.config.quarantine_ttl_slots),
                blocked_roles: request.blocked_roles,
                safe_exit_root,
                replacement_committee_root,
            },
        );
        if let Some(case) = self.slashing_cases.get_mut(&request.case_id) {
            case.status = SlashingStatus::Quarantined;
        }
        if let Some(sequencer) = self.sequencers.get_mut(&request.sequencer_id) {
            sequencer.status = SequencerStatus::Quarantined;
        }
        self.counters.quarantine_fences_opened += 1;
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn settle_slashing(&mut self, request: SettleSlashingRequest) -> Result<()> {
        let slash_bps = request
            .slash_bps
            .min(self.config.max_slash_bps)
            .min(MAX_BPS);
        let accused_sequencer_id = self
            .slashing_cases
            .get(&request.case_id)
            .ok_or_else(|| format!("unknown case_id {}", request.case_id))?
            .accused_sequencer_id
            .clone();
        let slash_amount_micro_units = self.slashable_stake_for(&accused_sequencer_id, slash_bps);
        {
            let case = self
                .slashing_cases
                .get_mut(&request.case_id)
                .ok_or_else(|| format!("unknown case_id {}", request.case_id))?;
            case.settlement_slot = request.settlement_slot;
            case.slash_bps = slash_bps;
            case.slash_amount_micro_units = slash_amount_micro_units;
            case.rebate_pool_micro_units = slash_amount_micro_units / 4;
            case.status = if request.accepted {
                SlashingStatus::Settled
            } else {
                SlashingStatus::Rejected
            };
        }
        if let Some(sequencer) = self.sequencers.get_mut(&accused_sequencer_id) {
            sequencer.active_case_count = sequencer.active_case_count.saturating_sub(1);
            if request.accepted {
                sequencer.status = SequencerStatus::Slashed;
                sequencer.reputation_bps = sequencer.reputation_bps.saturating_sub(slash_bps);
            } else if sequencer.status == SequencerStatus::Quarantined {
                sequencer.status = SequencerStatus::Active;
            }
        }
        self.counters.slashing_settlements += 1;
        self.refresh_roots();
        Ok(())
    }

    pub fn issue_rebate(&mut self, request: RebateRequest) -> Result<String> {
        self.ensure_capacity(self.rebates.len(), MAX_REBATES, "rebates")?;
        if !self.slashing_cases.contains_key(&request.case_id) {
            return Err(format!("unknown case_id {}", request.case_id));
        }
        if request.fee_rebate_bps > self.config.max_user_fee_bps {
            return Err("fee_rebate_bps exceeds configured max user fee".to_string());
        }
        let rebate_id = stable_id(
            "rebate",
            &[
                HashPart::Str(&request.case_id),
                HashPart::Str(&request.beneficiary_group_root),
                HashPart::Str(&request.asset_id),
                HashPart::U64(request.amount_micro_units),
            ],
        );
        let privacy_redaction_root = domain_hash(
            "accountable-sequencer-rebate-redaction-root",
            &[
                HashPart::Str(&rebate_id),
                HashPart::Str(&request.beneficiary_group_root),
            ],
            32,
        );
        self.rebates.insert(
            rebate_id.clone(),
            FeeRebate {
                rebate_id: rebate_id.clone(),
                case_id: request.case_id,
                beneficiary_group_root: request.beneficiary_group_root,
                asset_id: request.asset_id,
                amount_micro_units: request.amount_micro_units,
                fee_rebate_bps: request.fee_rebate_bps,
                status: RebateStatus::Reserved,
                privacy_redaction_root,
                expires_slot: request.expires_slot,
            },
        );
        self.counters.rebates_issued += 1;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn update_scorecard(&mut self, sequencer_id: &str, epoch: u64) -> Result<String> {
        self.ensure_capacity(self.scorecards.len(), MAX_SCORECARDS, "scorecards")?;
        let sequencer = self
            .sequencers
            .get(sequencer_id)
            .ok_or_else(|| format!("unknown sequencer_id {sequencer_id}"))?;
        let p95_latency_ms = self
            .heartbeats
            .values()
            .filter(|heartbeat| heartbeat.sequencer_id == sequencer_id && heartbeat.epoch == epoch)
            .map(|heartbeat| heartbeat.p95_ms)
            .max()
            .unwrap_or(sequencer.target_p95_ms);
        let active_cases = self
            .slashing_cases
            .values()
            .filter(|case| {
                case.accused_sequencer_id == sequencer_id
                    && matches!(
                        case.status,
                        SlashingStatus::Open
                            | SlashingStatus::Attesting
                            | SlashingStatus::Quarantined
                    )
            })
            .count() as u64;
        let uptime_bps = if sequencer.last_heartbeat_slot > 0 {
            9_800_u64.saturating_sub(active_cases.saturating_mul(250))
        } else {
            0
        };
        let fee_compliance_bps = if sequencer.max_fee_bps <= self.config.max_user_fee_bps {
            10_000
        } else {
            7_000
        };
        let pq_attestation_bps = self
            .attestations
            .values()
            .filter(|attestation| {
                attestation.accepted && attestation.target_id.contains(sequencer_id)
            })
            .count()
            .saturating_mul(500)
            .min(10_000) as u64;
        let privacy_floor_bps = ((sequencer.privacy_set_floor.saturating_mul(MAX_BPS))
            / self.config.min_privacy_set_size.max(1))
        .min(MAX_BPS);
        let slashing_risk_bps = active_cases.saturating_mul(1_000).min(MAX_BPS);
        let latency_bps = if p95_latency_ms <= self.config.target_p95_ms {
            10_000
        } else if p95_latency_ms >= self.config.max_p95_ms {
            5_000
        } else {
            10_000_u64.saturating_sub(
                (p95_latency_ms - self.config.target_p95_ms).saturating_mul(5_000)
                    / (self.config.max_p95_ms - self.config.target_p95_ms).max(1),
            )
        };
        let composite_score_bps = [
            uptime_bps,
            latency_bps,
            fee_compliance_bps,
            pq_attestation_bps.max(7_500),
            privacy_floor_bps,
            MAX_BPS.saturating_sub(slashing_risk_bps),
        ]
        .into_iter()
        .sum::<u64>()
            / 6;
        let scorecard_id = stable_id(
            "scorecard",
            &[
                HashPart::Str(sequencer_id),
                HashPart::U64(epoch),
                HashPart::U64(composite_score_bps),
            ],
        );
        let public_summary_root = domain_hash(
            "accountable-sequencer-scorecard-public-summary-root",
            &[
                HashPart::Str(&scorecard_id),
                HashPart::U64(composite_score_bps),
                HashPart::U64(p95_latency_ms),
            ],
            32,
        );
        self.scorecards.insert(
            scorecard_id.clone(),
            SequencerScorecard {
                scorecard_id: scorecard_id.clone(),
                sequencer_id: sequencer_id.to_string(),
                epoch,
                uptime_bps,
                p95_latency_ms,
                fee_compliance_bps,
                pq_attestation_bps,
                privacy_floor_bps,
                slashing_risk_bps,
                composite_score_bps,
                public_summary_root,
            },
        );
        self.refresh_roots();
        Ok(scorecard_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "confidential_evidence_suite": CONFIDENTIAL_EVIDENCE_SUITE,
            "stake_commitment_suite": STAKE_COMMITMENT_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "sequencers": self.sequencers.values().map(SequencerRecord::public_record).collect::<Vec<_>>(),
            "stake_positions": self.stake_positions.values().map(StakePosition::public_record).collect::<Vec<_>>(),
            "heartbeats": self.heartbeats.values().map(LivenessHeartbeat::public_record).collect::<Vec<_>>(),
            "evidence_bundles": self.evidence_bundles.values().map(RedactedEvidenceBundle::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqAttestation::public_record).collect::<Vec<_>>(),
            "slashing_cases": self.slashing_cases.values().map(SlashingCase::public_record).collect::<Vec<_>>(),
            "quarantine_fences": self.quarantine_fences.values().map(QuarantineFence::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(FeeRebate::public_record).collect::<Vec<_>>(),
            "scorecards": self.scorecards.values().map(SequencerScorecard::public_record).collect::<Vec<_>>(),
            "operator_summary": self.operator_summary(),
        })
    }

    pub fn operator_summary(&self) -> Value {
        let active = self
            .sequencers
            .values()
            .filter(|sequencer| sequencer.status == SequencerStatus::Active)
            .count();
        let quarantined = self
            .sequencers
            .values()
            .filter(|sequencer| sequencer.status == SequencerStatus::Quarantined)
            .count();
        let slashed = self
            .sequencers
            .values()
            .filter(|sequencer| sequencer.status == SequencerStatus::Slashed)
            .count();
        let slashable_stake = self
            .stake_positions
            .values()
            .map(|stake| stake.amount_micro_units.saturating_mul(stake.slashable_bps) / MAX_BPS)
            .sum::<u64>();
        let average_score = if self.scorecards.is_empty() {
            0
        } else {
            self.scorecards
                .values()
                .map(|score| score.composite_score_bps)
                .sum::<u64>()
                / self.scorecards.len() as u64
        };
        json!({
            "active_sequencers": active,
            "quarantined_sequencers": quarantined,
            "slashed_sequencers": slashed,
            "slashable_stake_micro_units": slashable_stake,
            "open_slashing_cases": self.slashing_cases.values().filter(|case| case.status != SlashingStatus::Settled && case.status != SlashingStatus::Rejected).count(),
            "rebate_pool_micro_units": self.rebates.values().map(|rebate| rebate.amount_micro_units).sum::<u64>(),
            "average_score_bps": average_score,
            "latest_state_root": self.roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "accountable-sequencer-runtime-state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&self.roots.sequencer_root),
                HashPart::Str(&self.roots.stake_root),
                HashPart::Str(&self.roots.heartbeat_root),
                HashPart::Str(&self.roots.evidence_root),
                HashPart::Str(&self.roots.attestation_root),
                HashPart::Str(&self.roots.slashing_root),
                HashPart::Str(&self.roots.quarantine_root),
                HashPart::Str(&self.roots.rebate_root),
                HashPart::Str(&self.roots.scorecard_root),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.sequencer_root = root_from_records(
            "accountable-sequencer-sequencer-root",
            self.sequencers
                .values()
                .map(SequencerRecord::public_record)
                .collect(),
        );
        self.roots.stake_root = root_from_records(
            "accountable-sequencer-stake-root",
            self.stake_positions
                .values()
                .map(StakePosition::public_record)
                .collect(),
        );
        self.roots.heartbeat_root = root_from_records(
            "accountable-sequencer-heartbeat-root",
            self.heartbeats
                .values()
                .map(LivenessHeartbeat::public_record)
                .collect(),
        );
        self.roots.evidence_root = root_from_records(
            "accountable-sequencer-evidence-root",
            self.evidence_bundles
                .values()
                .map(RedactedEvidenceBundle::public_record)
                .collect(),
        );
        self.roots.attestation_root = root_from_records(
            "accountable-sequencer-attestation-root",
            self.attestations
                .values()
                .map(PqAttestation::public_record)
                .collect(),
        );
        self.roots.slashing_root = root_from_records(
            "accountable-sequencer-slashing-root",
            self.slashing_cases
                .values()
                .map(SlashingCase::public_record)
                .collect(),
        );
        self.roots.quarantine_root = root_from_records(
            "accountable-sequencer-quarantine-root",
            self.quarantine_fences
                .values()
                .map(QuarantineFence::public_record)
                .collect(),
        );
        self.roots.rebate_root = root_from_records(
            "accountable-sequencer-rebate-root",
            self.rebates
                .values()
                .map(FeeRebate::public_record)
                .collect(),
        );
        self.roots.scorecard_root = root_from_records(
            "accountable-sequencer-scorecard-root",
            self.scorecards
                .values()
                .map(SequencerScorecard::public_record)
                .collect(),
        );
        self.roots.state_root = self.state_root();
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            Err(format!("{label} capacity exceeded: max {max}"))
        } else {
            Ok(())
        }
    }

    fn compute_evidence_severity(&self, request: &EvidenceRequest) -> u64 {
        let latency_penalty = if request.observed_latency_ms <= self.config.target_p95_ms {
            0
        } else {
            (request.observed_latency_ms - self.config.target_p95_ms)
                .saturating_mul(2)
                .min(2_000)
        };
        let fee_penalty = request.claimed_fee_overcharge_bps.min(2_000);
        let privacy_penalty = if request.privacy_set_size >= self.config.min_privacy_set_size {
            0
        } else {
            2_500
        };
        request
            .kind
            .base_severity_bps()
            .saturating_add(latency_penalty)
            .saturating_add(fee_penalty)
            .saturating_add(privacy_penalty)
            .min(MAX_BPS)
    }

    fn slashable_stake_for(&self, sequencer_id: &str, slash_bps: u64) -> u64 {
        self.stake_positions
            .values()
            .filter(|stake| stake.sequencer_id == sequencer_id)
            .map(|stake| {
                stake
                    .amount_micro_units
                    .saturating_mul(stake.slashable_bps.min(MAX_BPS))
                    / MAX_BPS
            })
            .sum::<u64>()
            .saturating_mul(slash_bps.min(MAX_BPS))
            / MAX_BPS
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn bounded_add(value: u64, delta: u64) -> u64 {
    value.saturating_add(delta).min(MAX_BPS)
}

fn root_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("accountable-sequencer-stake-slashing:{domain}"),
        parts,
        16,
    )
}
