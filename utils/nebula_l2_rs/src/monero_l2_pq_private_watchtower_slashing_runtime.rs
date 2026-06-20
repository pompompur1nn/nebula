use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateWatchtowerSlashingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-watchtower-slashing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_DEVNET_HEIGHT: u64 = 744_384;
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_EVIDENCE_SCHEME: &str =
    "ml-kem-1024-encrypted-watchtower-evidence-root-v1";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_REPORT_SCHEME: &str =
    "private-monero-bridge-relay-misconduct-report-root-v1";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_QUORUM_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-watchtower-quorum-v1";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_DISCLOSURE_SCHEME: &str =
    "delayed-selective-disclosure-commitment-v1";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_ESCROW_SCHEME: &str =
    "roots-only-watchtower-slashing-escrow-v1";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_APPEAL_SCHEME: &str =
    "privacy-preserving-slashing-appeal-window-v1";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_RESERVE_SCHEME: &str =
    "bridge-reserve-impact-receipt-root-v1";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_PRIVACY_FENCE_SCHEME: &str =
    "watchtower-nullifier-fence-set-v1";
pub const MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_BATCH_SCHEME: &str =
    "low-fee-watchtower-evidence-batch-v1";
pub const DEFAULT_DISCLOSURE_DELAY_BLOCKS: u64 = 32;
pub const DEFAULT_APPEAL_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 24;
pub const DEFAULT_MIN_WATCHER_QUORUM: u16 = 5;
pub const DEFAULT_MIN_QUORUM_WEIGHT: u64 = 7;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_RESERVE_IMPACT_BPS: u64 = 1_500;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 5_000;
pub const DEFAULT_LOW_FEE_BATCH_SIZE: usize = 128;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 3_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_EVIDENCE: usize = 1_048_576;
pub const MAX_REPORTS: usize = 524_288;
pub const MAX_QUORUM_ATTESTATIONS: usize = 2_097_152;
pub const MAX_DISCLOSURES: usize = 524_288;
pub const MAX_ESCROWS: usize = 524_288;
pub const MAX_APPEALS: usize = 262_144;
pub const MAX_RESERVE_RECEIPTS: usize = 524_288;
pub const MAX_PRIVACY_FENCES: usize = 2_097_152;
pub const MAX_BATCHES: usize = 262_144;
pub const MAX_EVENTS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    RelayEquivocation,
    WithheldFinality,
    FalseHeader,
    InvalidReserveProof,
    DoubleSpendConcealment,
    PrivacyFenceBreach,
    QuorumForgery,
    EmergencyBridgeRisk,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RelayEquivocation => "relay_equivocation",
            Self::WithheldFinality => "withheld_finality",
            Self::FalseHeader => "false_header",
            Self::InvalidReserveProof => "invalid_reserve_proof",
            Self::DoubleSpendConcealment => "double_spend_concealment",
            Self::PrivacyFenceBreach => "privacy_fence_breach",
            Self::QuorumForgery => "quorum_forgery",
            Self::EmergencyBridgeRisk => "emergency_bridge_risk",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Encrypted,
    Fenced,
    Reported,
    QuorumPending,
    QuorumAttested,
    DisclosureDelayed,
    Disclosed,
    EscrowLocked,
    Appealed,
    Accepted,
    Rejected,
    Batched,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Fenced => "fenced",
            Self::Reported => "reported",
            Self::QuorumPending => "quorum_pending",
            Self::QuorumAttested => "quorum_attested",
            Self::DisclosureDelayed => "disclosure_delayed",
            Self::Disclosed => "disclosed",
            Self::EscrowLocked => "escrow_locked",
            Self::Appealed => "appealed",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Batched => "batched",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MisconductKind {
    WrongHeader,
    MissingReserveReceipt,
    InvalidUnlock,
    HiddenReorg,
    DuplicateNullifier,
    WatcherKeyMisuse,
    SafetyHaltViolation,
}

impl MisconductKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrongHeader => "wrong_header",
            Self::MissingReserveReceipt => "missing_reserve_receipt",
            Self::InvalidUnlock => "invalid_unlock",
            Self::HiddenReorg => "hidden_reorg",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::WatcherKeyMisuse => "watcher_key_misuse",
            Self::SafetyHaltViolation => "safety_halt_violation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Filed,
    MatchedEvidence,
    QuorumAttached,
    DisclosureScheduled,
    EscrowOpened,
    Resolved,
    Dismissed,
}

impl ReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::MatchedEvidence => "matched_evidence",
            Self::QuorumAttached => "quorum_attached",
            Self::DisclosureScheduled => "disclosure_scheduled",
            Self::EscrowOpened => "escrow_opened",
            Self::Resolved => "resolved",
            Self::Dismissed => "dismissed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumAttestationKind {
    EvidenceSeen,
    CiphertextWellFormed,
    NullifierUnique,
    RelayMisconduct,
    ReserveImpactBounded,
    DisclosureReady,
    SlashReady,
}

impl QuorumAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceSeen => "evidence_seen",
            Self::CiphertextWellFormed => "ciphertext_well_formed",
            Self::NullifierUnique => "nullifier_unique",
            Self::RelayMisconduct => "relay_misconduct",
            Self::ReserveImpactBounded => "reserve_impact_bounded",
            Self::DisclosureReady => "disclosure_ready",
            Self::SlashReady => "slash_ready",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Committed,
    Waiting,
    Open,
    Revealed,
    Expired,
}

impl DisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Waiting => "waiting",
            Self::Open => "open",
            Self::Revealed => "revealed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Locked,
    AppealOpen,
    AppealSustained,
    SlashPending,
    Slashed,
    Released,
}

impl EscrowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::AppealOpen => "appeal_open",
            Self::AppealSustained => "appeal_sustained",
            Self::SlashPending => "slash_pending",
            Self::Slashed => "slashed",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStatus {
    Open,
    EvidenceSubmitted,
    Sustained,
    Rejected,
    Expired,
}

impl AppealStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveImpactKind {
    NoImpact,
    PendingDebit,
    ProvisionalCredit,
    ReserveDrawdown,
    EmergencyBufferUse,
    Recovered,
}

impl ReserveImpactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoImpact => "no_impact",
            Self::PendingDebit => "pending_debit",
            Self::ProvisionalCredit => "provisional_credit",
            Self::ReserveDrawdown => "reserve_drawdown",
            Self::EmergencyBufferUse => "emergency_buffer_use",
            Self::Recovered => "recovered",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    WatcherNullifier,
    EvidenceNullifier,
    RelayNullifier,
    KeyImage,
    ViewTag,
    DisclosureNullifier,
    AppealNullifier,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatcherNullifier => "watcher_nullifier",
            Self::EvidenceNullifier => "evidence_nullifier",
            Self::RelayNullifier => "relay_nullifier",
            Self::KeyImage => "key_image",
            Self::ViewTag => "view_tag",
            Self::DisclosureNullifier => "disclosure_nullifier",
            Self::AppealNullifier => "appeal_nullifier",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Draft,
    Sealed,
    Submitted,
    Finalized,
    Disputed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub hash_suite: String,
    pub encrypted_evidence_scheme: String,
    pub misconduct_report_scheme: String,
    pub quorum_attestation_scheme: String,
    pub disclosure_scheme: String,
    pub escrow_scheme: String,
    pub appeal_scheme: String,
    pub reserve_receipt_scheme: String,
    pub privacy_fence_scheme: String,
    pub batch_scheme: String,
    pub disclosure_delay_blocks: u64,
    pub appeal_window_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub min_watcher_quorum: u16,
    pub min_quorum_weight: u64,
    pub min_privacy_set_size: u64,
    pub target_pq_security_bits: u16,
    pub max_reserve_impact_bps: u64,
    pub max_slash_bps: u64,
    pub low_fee_batch_size: usize,
    pub low_fee_target_micro_units: u64,
    pub max_evidence: usize,
    pub max_reports: usize,
    pub max_quorum_attestations: usize,
    pub max_disclosures: usize,
    pub max_escrows: usize,
    pub max_appeals: usize,
    pub max_reserve_receipts: usize,
    pub max_privacy_fences: usize,
    pub max_batches: usize,
    pub max_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_L2_NETWORK.to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_HASH_SUITE.to_string(),
            encrypted_evidence_scheme:
                MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_EVIDENCE_SCHEME.to_string(),
            misconduct_report_scheme:
                MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_REPORT_SCHEME.to_string(),
            quorum_attestation_scheme:
                MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_QUORUM_SCHEME.to_string(),
            disclosure_scheme: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_DISCLOSURE_SCHEME
                .to_string(),
            escrow_scheme: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_ESCROW_SCHEME
                .to_string(),
            appeal_scheme: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_APPEAL_SCHEME
                .to_string(),
            reserve_receipt_scheme: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_RESERVE_SCHEME
                .to_string(),
            privacy_fence_scheme:
                MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_PRIVACY_FENCE_SCHEME.to_string(),
            batch_scheme: MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_BATCH_SCHEME.to_string(),
            disclosure_delay_blocks: DEFAULT_DISCLOSURE_DELAY_BLOCKS,
            appeal_window_blocks: DEFAULT_APPEAL_WINDOW_BLOCKS,
            settlement_delay_blocks: DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            min_quorum_weight: DEFAULT_MIN_QUORUM_WEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_reserve_impact_bps: DEFAULT_MAX_RESERVE_IMPACT_BPS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
            low_fee_batch_size: DEFAULT_LOW_FEE_BATCH_SIZE,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            max_evidence: MAX_EVIDENCE,
            max_reports: MAX_REPORTS,
            max_quorum_attestations: MAX_QUORUM_ATTESTATIONS,
            max_disclosures: MAX_DISCLOSURES,
            max_escrows: MAX_ESCROWS,
            max_appeals: MAX_APPEALS,
            max_reserve_receipts: MAX_RESERVE_RECEIPTS,
            max_privacy_fences: MAX_PRIVACY_FENCES,
            max_batches: MAX_BATCHES,
            max_events: MAX_EVENTS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": CHAIN_ID,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "hash_suite": self.hash_suite,
            "encrypted_evidence_scheme": self.encrypted_evidence_scheme,
            "misconduct_report_scheme": self.misconduct_report_scheme,
            "quorum_attestation_scheme": self.quorum_attestation_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "escrow_scheme": self.escrow_scheme,
            "appeal_scheme": self.appeal_scheme,
            "reserve_receipt_scheme": self.reserve_receipt_scheme,
            "privacy_fence_scheme": self.privacy_fence_scheme,
            "batch_scheme": self.batch_scheme,
            "disclosure_delay_blocks": self.disclosure_delay_blocks,
            "appeal_window_blocks": self.appeal_window_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "min_watcher_quorum": self.min_watcher_quorum,
            "min_quorum_weight": self.min_quorum_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_reserve_impact_bps": self.max_reserve_impact_bps,
            "max_slash_bps": self.max_slash_bps,
            "low_fee_batch_size": self.low_fee_batch_size,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "max_evidence": self.max_evidence,
            "max_reports": self.max_reports,
            "max_quorum_attestations": self.max_quorum_attestations,
            "max_disclosures": self.max_disclosures,
            "max_escrows": self.max_escrows,
            "max_appeals": self.max_appeals,
            "max_reserve_receipts": self.max_reserve_receipts,
            "max_privacy_fences": self.max_privacy_fences,
            "max_batches": self.max_batches,
            "max_events": self.max_events,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub encrypted_evidence: u64,
    pub misconduct_reports: u64,
    pub quorum_attestations: u64,
    pub disclosure_commitments: u64,
    pub slashing_escrows: u64,
    pub appeals: u64,
    pub reserve_receipts: u64,
    pub privacy_fences: u64,
    pub low_fee_batches: u64,
    pub accepted_slashes: u64,
    pub rejected_slashes: u64,
    pub released_escrows: u64,
    pub total_locked_micro_units: u128,
    pub total_slashed_micro_units: u128,
    pub total_released_micro_units: u128,
    pub total_reserve_impact_micro_units: u128,
    pub total_batch_fee_micro_units: u128,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "encrypted_evidence": self.encrypted_evidence,
            "misconduct_reports": self.misconduct_reports,
            "quorum_attestations": self.quorum_attestations,
            "disclosure_commitments": self.disclosure_commitments,
            "slashing_escrows": self.slashing_escrows,
            "appeals": self.appeals,
            "reserve_receipts": self.reserve_receipts,
            "privacy_fences": self.privacy_fences,
            "low_fee_batches": self.low_fee_batches,
            "accepted_slashes": self.accepted_slashes,
            "rejected_slashes": self.rejected_slashes,
            "released_escrows": self.released_escrows,
            "total_locked_micro_units": self.total_locked_micro_units.to_string(),
            "total_slashed_micro_units": self.total_slashed_micro_units.to_string(),
            "total_released_micro_units": self.total_released_micro_units.to_string(),
            "total_reserve_impact_micro_units": self.total_reserve_impact_micro_units.to_string(),
            "total_batch_fee_micro_units": self.total_batch_fee_micro_units.to_string(),
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedWatcherEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub status: EvidenceStatus,
    pub watcher_commitment: String,
    pub subject_commitment: String,
    pub relay_session_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub encrypted_payload_root: String,
    pub ciphertext_root: String,
    pub capsule_root: String,
    pub header_root: String,
    pub txset_root: String,
    pub reserve_context_root: String,
    pub privacy_context_root: String,
    pub nullifier_root: String,
    pub previous_evidence_root: String,
    pub metadata_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub opened_report_id: String,
    pub quorum_root: String,
    pub disclosure_id: String,
    pub escrow_id: String,
    pub batch_id: String,
    pub submitted_at_height: u64,
}

impl EncryptedWatcherEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "watcher_commitment": self.watcher_commitment,
            "subject_commitment": self.subject_commitment,
            "relay_session_id": self.relay_session_id,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_root": self.ciphertext_root,
            "capsule_root": self.capsule_root,
            "header_root": self.header_root,
            "txset_root": self.txset_root,
            "reserve_context_root": self.reserve_context_root,
            "privacy_context_root": self.privacy_context_root,
            "nullifier_root": self.nullifier_root,
            "previous_evidence_root": self.previous_evidence_root,
            "metadata_root": self.metadata_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "opened_report_id": self.opened_report_id,
            "quorum_root": self.quorum_root,
            "disclosure_id": self.disclosure_id,
            "escrow_id": self.escrow_id,
            "batch_id": self.batch_id,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRelayMisconductReport {
    pub report_id: String,
    pub evidence_id: String,
    pub misconduct_kind: MisconductKind,
    pub status: ReportStatus,
    pub reporter_commitment: String,
    pub accused_operator_commitment: String,
    pub relay_session_id: String,
    pub bridge_epoch: u64,
    pub report_root: String,
    pub alleged_loss_root: String,
    pub policy_root: String,
    pub reserve_snapshot_root: String,
    pub nullifier_root: String,
    pub filed_at_height: u64,
}

impl BridgeRelayMisconductReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "evidence_id": self.evidence_id,
            "misconduct_kind": self.misconduct_kind.as_str(),
            "status": self.status.as_str(),
            "reporter_commitment": self.reporter_commitment,
            "accused_operator_commitment": self.accused_operator_commitment,
            "relay_session_id": self.relay_session_id,
            "bridge_epoch": self.bridge_epoch,
            "report_root": self.report_root,
            "alleged_loss_root": self.alleged_loss_root,
            "policy_root": self.policy_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "nullifier_root": self.nullifier_root,
            "filed_at_height": self.filed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqQuorumAttestation {
    pub attestation_id: String,
    pub kind: QuorumAttestationKind,
    pub evidence_id: String,
    pub report_id: String,
    pub watcher_commitment: String,
    pub committee_epoch: u64,
    pub weight: u64,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub disclosure_hint_root: String,
    pub reserve_bound_root: String,
    pub nullifier_root: String,
    pub signed_at_height: u64,
}

impl PqQuorumAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "evidence_id": self.evidence_id,
            "report_id": self.report_id,
            "watcher_commitment": self.watcher_commitment,
            "committee_epoch": self.committee_epoch,
            "weight": self.weight,
            "statement_root": self.statement_root,
            "pq_signature_root": self.pq_signature_root,
            "disclosure_hint_root": self.disclosure_hint_root,
            "reserve_bound_root": self.reserve_bound_root,
            "nullifier_root": self.nullifier_root,
            "signed_at_height": self.signed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedDisclosureCommitment {
    pub disclosure_id: String,
    pub evidence_id: String,
    pub report_id: String,
    pub status: DisclosureStatus,
    pub commitment_root: String,
    pub encrypted_key_share_root: String,
    pub reveal_authority_root: String,
    pub quorum_attestation_root: String,
    pub privacy_fence_root: String,
    pub committed_at_height: u64,
    pub reveal_at_height: u64,
    pub expires_at_height: u64,
    pub revealed_root: String,
}

impl DelayedDisclosureCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "disclosure_id": self.disclosure_id,
            "evidence_id": self.evidence_id,
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "commitment_root": self.commitment_root,
            "encrypted_key_share_root": self.encrypted_key_share_root,
            "reveal_authority_root": self.reveal_authority_root,
            "quorum_attestation_root": self.quorum_attestation_root,
            "privacy_fence_root": self.privacy_fence_root,
            "committed_at_height": self.committed_at_height,
            "reveal_at_height": self.reveal_at_height,
            "expires_at_height": self.expires_at_height,
            "revealed_root": self.revealed_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEscrow {
    pub escrow_id: String,
    pub evidence_id: String,
    pub report_id: String,
    pub accused_operator_commitment: String,
    pub status: EscrowStatus,
    pub locked_amount_micro_units: u64,
    pub slash_bps: u64,
    pub slash_amount_micro_units: u64,
    pub bond_root: String,
    pub reserve_receipt_id: String,
    pub quorum_attestation_root: String,
    pub disclosure_root: String,
    pub appeal_id: String,
    pub locked_at_height: u64,
    pub appeal_deadline_height: u64,
    pub settle_at_height: u64,
}

impl SlashingEscrow {
    pub fn public_record(&self) -> Value {
        json!({
            "escrow_id": self.escrow_id,
            "evidence_id": self.evidence_id,
            "report_id": self.report_id,
            "accused_operator_commitment": self.accused_operator_commitment,
            "status": self.status.as_str(),
            "locked_amount_micro_units": self.locked_amount_micro_units,
            "slash_bps": self.slash_bps,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "bond_root": self.bond_root,
            "reserve_receipt_id": self.reserve_receipt_id,
            "quorum_attestation_root": self.quorum_attestation_root,
            "disclosure_root": self.disclosure_root,
            "appeal_id": self.appeal_id,
            "locked_at_height": self.locked_at_height,
            "appeal_deadline_height": self.appeal_deadline_height,
            "settle_at_height": self.settle_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppealWindow {
    pub appeal_id: String,
    pub escrow_id: String,
    pub evidence_id: String,
    pub appellant_commitment: String,
    pub status: AppealStatus,
    pub appeal_root: String,
    pub counter_evidence_root: String,
    pub pq_signature_root: String,
    pub privacy_fence_root: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub resolved_at_height: u64,
    pub resolution_root: String,
}

impl AppealWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "appeal_id": self.appeal_id,
            "escrow_id": self.escrow_id,
            "evidence_id": self.evidence_id,
            "appellant_commitment": self.appellant_commitment,
            "status": self.status.as_str(),
            "appeal_root": self.appeal_root,
            "counter_evidence_root": self.counter_evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_fence_root": self.privacy_fence_root,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "resolved_at_height": self.resolved_at_height,
            "resolution_root": self.resolution_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveImpactReceipt {
    pub receipt_id: String,
    pub evidence_id: String,
    pub report_id: String,
    pub kind: ReserveImpactKind,
    pub bridge_epoch: u64,
    pub reserve_before_root: String,
    pub reserve_after_root: String,
    pub impact_amount_micro_units: u64,
    pub impact_bps: u64,
    pub mitigation_root: String,
    pub accountant_commitment: String,
    pub pq_signature_root: String,
    pub issued_at_height: u64,
}

impl ReserveImpactReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "evidence_id": self.evidence_id,
            "report_id": self.report_id,
            "kind": self.kind.as_str(),
            "bridge_epoch": self.bridge_epoch,
            "reserve_before_root": self.reserve_before_root,
            "reserve_after_root": self.reserve_after_root,
            "impact_amount_micro_units": self.impact_amount_micro_units,
            "impact_bps": self.impact_bps,
            "mitigation_root": self.mitigation_root,
            "accountant_commitment": self.accountant_commitment,
            "pq_signature_root": self.pq_signature_root,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub privacy_set_size: u64,
    pub inserted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "replay_domain": self.replay_domain,
            "privacy_set_size": self.privacy_set_size,
            "inserted_at_height": self.inserted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeEvidenceBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub evidence_ids: Vec<String>,
    pub report_ids: Vec<String>,
    pub escrow_ids: Vec<String>,
    pub evidence_root: String,
    pub report_root: String,
    pub quorum_root: String,
    pub disclosure_root: String,
    pub escrow_root: String,
    pub reserve_receipt_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub estimated_fee_micro_units: u64,
    pub target_fee_micro_units: u64,
    pub built_at_height: u64,
    pub finalized_at_height: u64,
}

impl LowFeeEvidenceBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "evidence_ids": self.evidence_ids,
            "report_ids": self.report_ids,
            "escrow_ids": self.escrow_ids,
            "evidence_root": self.evidence_root,
            "report_root": self.report_root,
            "quorum_root": self.quorum_root,
            "disclosure_root": self.disclosure_root,
            "escrow_root": self.escrow_root,
            "reserve_receipt_root": self.reserve_receipt_root,
            "privacy_fence_root": self.privacy_fence_root,
            "nullifier_root": self.nullifier_root,
            "estimated_fee_micro_units": self.estimated_fee_micro_units,
            "target_fee_micro_units": self.target_fee_micro_units,
            "built_at_height": self.built_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub evidence_root: String,
    pub report_root: String,
    pub quorum_attestation_root: String,
    pub disclosure_root: String,
    pub escrow_root: String,
    pub appeal_root: String,
    pub reserve_receipt_root: String,
    pub privacy_fence_root: String,
    pub batch_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "evidence_root": self.evidence_root,
            "report_root": self.report_root,
            "quorum_attestation_root": self.quorum_attestation_root,
            "disclosure_root": self.disclosure_root,
            "escrow_root": self.escrow_root,
            "appeal_root": self.appeal_root,
            "reserve_receipt_root": self.reserve_receipt_root,
            "privacy_fence_root": self.privacy_fence_root,
            "batch_root": self.batch_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEncryptedEvidenceRequest {
    pub kind: EvidenceKind,
    pub watcher_commitment: String,
    pub subject_commitment: String,
    pub relay_session_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub encrypted_payload_root: String,
    pub ciphertext_root: String,
    pub capsule_root: String,
    pub header_root: String,
    pub txset_root: String,
    pub reserve_context_root: String,
    pub privacy_context_root: String,
    pub nullifier_root: String,
    pub previous_evidence_root: String,
    pub metadata_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMisconductReportRequest {
    pub evidence_id: String,
    pub misconduct_kind: MisconductKind,
    pub reporter_commitment: String,
    pub accused_operator_commitment: String,
    pub relay_session_id: String,
    pub bridge_epoch: u64,
    pub report_root: String,
    pub alleged_loss_root: String,
    pub policy_root: String,
    pub reserve_snapshot_root: String,
    pub nullifier_root: String,
    pub filed_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPqQuorumAttestationRequest {
    pub kind: QuorumAttestationKind,
    pub evidence_id: String,
    pub report_id: String,
    pub watcher_commitment: String,
    pub committee_epoch: u64,
    pub weight: u64,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub disclosure_hint_root: String,
    pub reserve_bound_root: String,
    pub nullifier_root: String,
    pub signed_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitDelayedDisclosureRequest {
    pub evidence_id: String,
    pub report_id: String,
    pub commitment_root: String,
    pub encrypted_key_share_root: String,
    pub reveal_authority_root: String,
    pub privacy_fence_root: String,
    pub committed_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenSlashingEscrowRequest {
    pub evidence_id: String,
    pub report_id: String,
    pub accused_operator_commitment: String,
    pub locked_amount_micro_units: u64,
    pub slash_bps: u64,
    pub bond_root: String,
    pub reserve_receipt_id: String,
    pub quorum_attestation_root: String,
    pub disclosure_root: String,
    pub locked_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAppealRequest {
    pub escrow_id: String,
    pub evidence_id: String,
    pub appellant_commitment: String,
    pub appeal_root: String,
    pub counter_evidence_root: String,
    pub pq_signature_root: String,
    pub privacy_fence_root: String,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordReserveImpactReceiptRequest {
    pub evidence_id: String,
    pub report_id: String,
    pub kind: ReserveImpactKind,
    pub bridge_epoch: u64,
    pub reserve_before_root: String,
    pub reserve_after_root: String,
    pub impact_amount_micro_units: u64,
    pub impact_bps: u64,
    pub mitigation_root: String,
    pub accountant_commitment: String,
    pub pq_signature_root: String,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsertPrivacyFenceRequest {
    pub kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub privacy_set_size: u64,
    pub inserted_at_height: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildLowFeeEvidenceBatchRequest {
    pub evidence_ids: Vec<String>,
    pub report_ids: Vec<String>,
    pub escrow_ids: Vec<String>,
    pub estimated_fee_micro_units: u64,
    pub target_fee_micro_units: u64,
    pub built_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub encrypted_evidence: BTreeMap<String, EncryptedWatcherEvidence>,
    pub misconduct_reports: BTreeMap<String, BridgeRelayMisconductReport>,
    pub quorum_attestations: BTreeMap<String, PqQuorumAttestation>,
    pub disclosures: BTreeMap<String, DelayedDisclosureCommitment>,
    pub slashing_escrows: BTreeMap<String, SlashingEscrow>,
    pub appeals: BTreeMap<String, AppealWindow>,
    pub reserve_receipts: BTreeMap<String, ReserveImpactReceipt>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub low_fee_batches: BTreeMap<String, LowFeeEvidenceBatch>,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub evidence_by_height: BTreeMap<u64, BTreeSet<String>>,
    pub nullifier_index: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::empty(
            Config::default(),
            MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_DEVNET_HEIGHT,
        )
    }
}

impl State {
    pub fn empty(config: Config, height: u64) -> Self {
        Self {
            config,
            counters: Counters::default(),
            height,
            encrypted_evidence: BTreeMap::new(),
            misconduct_reports: BTreeMap::new(),
            quorum_attestations: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            slashing_escrows: BTreeMap::new(),
            appeals: BTreeMap::new(),
            reserve_receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            events: BTreeMap::new(),
            evidence_by_height: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let evidence_id = state
            .submit_encrypted_evidence(SubmitEncryptedEvidenceRequest {
                kind: EvidenceKind::RelayEquivocation,
                watcher_commitment: commitment("devnet-watchtower-alpha"),
                subject_commitment: commitment("devnet-bridge-relayer-7"),
                relay_session_id: commitment("devnet-relay-session-42"),
                monero_height: 3_104_288,
                l2_height: state.height,
                encrypted_payload_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "payload"),
                ciphertext_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "ciphertext"),
                capsule_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "ml-kem-capsule"),
                header_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "header"),
                txset_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "txset"),
                reserve_context_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "reserve"),
                privacy_context_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "privacy"),
                nullifier_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "nullifier"),
                previous_evidence_root: empty_root("DEVNET-WATCHTOWER-EVIDENCE-PREV"),
                metadata_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "metadata"),
                pq_signature_root: string_root("DEVNET-WATCHTOWER-EVIDENCE", "pq-signature"),
                privacy_set_size: 32_768,
                submitted_at_height: state.height,
            })
            .expect("devnet encrypted evidence");
        let report_id = state
            .file_misconduct_report(FileMisconductReportRequest {
                evidence_id: evidence_id.clone(),
                misconduct_kind: MisconductKind::WrongHeader,
                reporter_commitment: commitment("devnet-watchtower-alpha"),
                accused_operator_commitment: commitment("devnet-bridge-relayer-7"),
                relay_session_id: commitment("devnet-relay-session-42"),
                bridge_epoch: 9,
                report_root: string_root("DEVNET-WATCHTOWER-REPORT", "wrong-header-report"),
                alleged_loss_root: string_root("DEVNET-WATCHTOWER-REPORT", "bounded-loss"),
                policy_root: string_root("DEVNET-WATCHTOWER-REPORT", "policy"),
                reserve_snapshot_root: string_root("DEVNET-WATCHTOWER-REPORT", "reserve-snapshot"),
                nullifier_root: string_root("DEVNET-WATCHTOWER-REPORT", "report-nullifier"),
                filed_at_height: state.height + 1,
            })
            .expect("devnet report");
        for n in 0..5 {
            state
                .record_pq_quorum_attestation(RecordPqQuorumAttestationRequest {
                    kind: QuorumAttestationKind::RelayMisconduct,
                    evidence_id: evidence_id.clone(),
                    report_id: report_id.clone(),
                    watcher_commitment: commitment(&format!("devnet-quorum-watchtower-{n}")),
                    committee_epoch: 9,
                    weight: 2,
                    statement_root: string_root(
                        "DEVNET-WATCHTOWER-QUORUM",
                        &format!("statement-{n}"),
                    ),
                    pq_signature_root: string_root("DEVNET-WATCHTOWER-QUORUM", &format!("pq-{n}")),
                    disclosure_hint_root: string_root(
                        "DEVNET-WATCHTOWER-QUORUM",
                        &format!("hint-{n}"),
                    ),
                    reserve_bound_root: string_root(
                        "DEVNET-WATCHTOWER-QUORUM",
                        &format!("reserve-{n}"),
                    ),
                    nullifier_root: string_root(
                        "DEVNET-WATCHTOWER-QUORUM",
                        &format!("nullifier-{n}"),
                    ),
                    signed_at_height: state.height + 3,
                })
                .expect("devnet quorum");
        }
        state
    }

    pub fn submit_encrypted_evidence(
        &mut self,
        request: SubmitEncryptedEvidenceRequest,
    ) -> Result<String> {
        require_capacity(
            "encrypted evidence",
            self.encrypted_evidence.len(),
            self.config.max_evidence,
        )?;
        require_non_empty("watcher commitment", &request.watcher_commitment)?;
        require_non_empty("subject commitment", &request.subject_commitment)?;
        require_non_empty("relay session id", &request.relay_session_id)?;
        require_root("encrypted payload root", &request.encrypted_payload_root)?;
        require_root("ciphertext root", &request.ciphertext_root)?;
        require_root("capsule root", &request.capsule_root)?;
        require_root("header root", &request.header_root)?;
        require_root("txset root", &request.txset_root)?;
        require_root("reserve context root", &request.reserve_context_root)?;
        require_root("privacy context root", &request.privacy_context_root)?;
        require_root("nullifier root", &request.nullifier_root)?;
        require_root("previous evidence root", &request.previous_evidence_root)?;
        require_root("metadata root", &request.metadata_root)?;
        require_root("pq signature root", &request.pq_signature_root)?;
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("evidence privacy set below configured minimum".to_string());
        }
        self.insert_nullifier(&request.nullifier_root)?;
        let evidence_id = encrypted_evidence_id(
            request.kind,
            &request.watcher_commitment,
            &request.subject_commitment,
            &request.ciphertext_root,
            &request.nullifier_root,
            request.submitted_at_height,
        );
        if self.encrypted_evidence.contains_key(&evidence_id) {
            return Err("duplicate encrypted evidence".to_string());
        }
        let evidence = EncryptedWatcherEvidence {
            evidence_id: evidence_id.clone(),
            kind: request.kind,
            status: EvidenceStatus::Encrypted,
            watcher_commitment: request.watcher_commitment,
            subject_commitment: request.subject_commitment,
            relay_session_id: request.relay_session_id,
            monero_height: request.monero_height,
            l2_height: request.l2_height,
            encrypted_payload_root: request.encrypted_payload_root,
            ciphertext_root: request.ciphertext_root,
            capsule_root: request.capsule_root,
            header_root: request.header_root,
            txset_root: request.txset_root,
            reserve_context_root: request.reserve_context_root,
            privacy_context_root: request.privacy_context_root,
            nullifier_root: request.nullifier_root,
            previous_evidence_root: request.previous_evidence_root,
            metadata_root: request.metadata_root,
            pq_signature_root: request.pq_signature_root,
            privacy_set_size: request.privacy_set_size,
            opened_report_id: String::new(),
            quorum_root: empty_root("MONERO-L2-PQ-WATCHTOWER-SLASHING-QUORUM"),
            disclosure_id: String::new(),
            escrow_id: String::new(),
            batch_id: String::new(),
            submitted_at_height: request.submitted_at_height,
        };
        self.evidence_by_height
            .entry(evidence.l2_height)
            .or_default()
            .insert(evidence_id.clone());
        self.encrypted_evidence
            .insert(evidence_id.clone(), evidence);
        self.counters.encrypted_evidence = self.counters.encrypted_evidence.saturating_add(1);
        self.record_event("encrypted_evidence_submitted", &evidence_id)?;
        Ok(evidence_id)
    }

    pub fn file_misconduct_report(
        &mut self,
        request: FileMisconductReportRequest,
    ) -> Result<String> {
        require_capacity(
            "misconduct reports",
            self.misconduct_reports.len(),
            self.config.max_reports,
        )?;
        require_known_evidence(&self.encrypted_evidence, &request.evidence_id)?;
        require_root("report root", &request.report_root)?;
        require_root("alleged loss root", &request.alleged_loss_root)?;
        require_root("policy root", &request.policy_root)?;
        require_root("reserve snapshot root", &request.reserve_snapshot_root)?;
        require_root("nullifier root", &request.nullifier_root)?;
        require_non_empty("reporter commitment", &request.reporter_commitment)?;
        require_non_empty(
            "accused operator commitment",
            &request.accused_operator_commitment,
        )?;
        self.insert_nullifier(&request.nullifier_root)?;
        let report_id = misconduct_report_id(
            request.misconduct_kind,
            &request.evidence_id,
            &request.accused_operator_commitment,
            &request.report_root,
            request.filed_at_height,
        );
        let report = BridgeRelayMisconductReport {
            report_id: report_id.clone(),
            evidence_id: request.evidence_id.clone(),
            misconduct_kind: request.misconduct_kind,
            status: ReportStatus::MatchedEvidence,
            reporter_commitment: request.reporter_commitment,
            accused_operator_commitment: request.accused_operator_commitment,
            relay_session_id: request.relay_session_id,
            bridge_epoch: request.bridge_epoch,
            report_root: request.report_root,
            alleged_loss_root: request.alleged_loss_root,
            policy_root: request.policy_root,
            reserve_snapshot_root: request.reserve_snapshot_root,
            nullifier_root: request.nullifier_root,
            filed_at_height: request.filed_at_height,
        };
        self.misconduct_reports.insert(report_id.clone(), report);
        if let Some(evidence) = self.encrypted_evidence.get_mut(&request.evidence_id) {
            evidence.opened_report_id = report_id.clone();
            evidence.status = EvidenceStatus::Reported;
        }
        self.counters.misconduct_reports = self.counters.misconduct_reports.saturating_add(1);
        self.record_event("misconduct_report_filed", &report_id)?;
        Ok(report_id)
    }

    pub fn record_pq_quorum_attestation(
        &mut self,
        request: RecordPqQuorumAttestationRequest,
    ) -> Result<String> {
        require_capacity(
            "quorum attestations",
            self.quorum_attestations.len(),
            self.config.max_quorum_attestations,
        )?;
        require_known_evidence(&self.encrypted_evidence, &request.evidence_id)?;
        require_known_report(&self.misconduct_reports, &request.report_id)?;
        require_non_empty("watcher commitment", &request.watcher_commitment)?;
        require_root("statement root", &request.statement_root)?;
        require_root("pq signature root", &request.pq_signature_root)?;
        require_root("disclosure hint root", &request.disclosure_hint_root)?;
        require_root("reserve bound root", &request.reserve_bound_root)?;
        require_root("nullifier root", &request.nullifier_root)?;
        if request.weight == 0 {
            return Err("quorum attestation weight must be nonzero".to_string());
        }
        self.insert_nullifier(&request.nullifier_root)?;
        let attestation_id = pq_quorum_attestation_id(
            request.kind,
            &request.evidence_id,
            &request.report_id,
            &request.watcher_commitment,
            &request.statement_root,
            request.signed_at_height,
        );
        let attestation = PqQuorumAttestation {
            attestation_id: attestation_id.clone(),
            kind: request.kind,
            evidence_id: request.evidence_id.clone(),
            report_id: request.report_id.clone(),
            watcher_commitment: request.watcher_commitment,
            committee_epoch: request.committee_epoch,
            weight: request.weight,
            statement_root: request.statement_root,
            pq_signature_root: request.pq_signature_root,
            disclosure_hint_root: request.disclosure_hint_root,
            reserve_bound_root: request.reserve_bound_root,
            nullifier_root: request.nullifier_root,
            signed_at_height: request.signed_at_height,
        };
        self.quorum_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.quorum_attestations = self.counters.quorum_attestations.saturating_add(1);
        self.refresh_quorum_status(&request.evidence_id, &request.report_id);
        self.record_event("pq_quorum_attestation_recorded", &attestation_id)?;
        Ok(attestation_id)
    }

    pub fn commit_delayed_disclosure(
        &mut self,
        request: CommitDelayedDisclosureRequest,
    ) -> Result<String> {
        require_capacity(
            "disclosures",
            self.disclosures.len(),
            self.config.max_disclosures,
        )?;
        require_known_evidence(&self.encrypted_evidence, &request.evidence_id)?;
        require_known_report(&self.misconduct_reports, &request.report_id)?;
        require_root("commitment root", &request.commitment_root)?;
        require_root(
            "encrypted key share root",
            &request.encrypted_key_share_root,
        )?;
        require_root("reveal authority root", &request.reveal_authority_root)?;
        require_root("privacy fence root", &request.privacy_fence_root)?;
        self.require_quorum(&request.evidence_id, &request.report_id)?;
        let quorum_attestation_root = self.quorum_root_for_report(&request.report_id);
        let disclosure_id = delayed_disclosure_id(
            &request.evidence_id,
            &request.report_id,
            &request.commitment_root,
            request.committed_at_height,
        );
        let disclosure = DelayedDisclosureCommitment {
            disclosure_id: disclosure_id.clone(),
            evidence_id: request.evidence_id.clone(),
            report_id: request.report_id.clone(),
            status: DisclosureStatus::Waiting,
            commitment_root: request.commitment_root,
            encrypted_key_share_root: request.encrypted_key_share_root,
            reveal_authority_root: request.reveal_authority_root,
            quorum_attestation_root,
            privacy_fence_root: request.privacy_fence_root,
            committed_at_height: request.committed_at_height,
            reveal_at_height: request
                .committed_at_height
                .saturating_add(self.config.disclosure_delay_blocks),
            expires_at_height: request
                .committed_at_height
                .saturating_add(self.config.disclosure_delay_blocks)
                .saturating_add(self.config.appeal_window_blocks),
            revealed_root: empty_root("MONERO-L2-PQ-WATCHTOWER-SLASHING-DISCLOSURE-REVEAL"),
        };
        self.disclosures.insert(disclosure_id.clone(), disclosure);
        if let Some(evidence) = self.encrypted_evidence.get_mut(&request.evidence_id) {
            evidence.disclosure_id = disclosure_id.clone();
            evidence.status = EvidenceStatus::DisclosureDelayed;
        }
        if let Some(report) = self.misconduct_reports.get_mut(&request.report_id) {
            report.status = ReportStatus::DisclosureScheduled;
        }
        self.counters.disclosure_commitments =
            self.counters.disclosure_commitments.saturating_add(1);
        self.record_event("delayed_disclosure_committed", &disclosure_id)?;
        Ok(disclosure_id)
    }

    pub fn open_slashing_escrow(&mut self, request: OpenSlashingEscrowRequest) -> Result<String> {
        require_capacity(
            "slashing escrows",
            self.slashing_escrows.len(),
            self.config.max_escrows,
        )?;
        require_known_evidence(&self.encrypted_evidence, &request.evidence_id)?;
        require_known_report(&self.misconduct_reports, &request.report_id)?;
        require_known_reserve_receipt(&self.reserve_receipts, &request.reserve_receipt_id)?;
        require_non_empty(
            "accused operator commitment",
            &request.accused_operator_commitment,
        )?;
        require_root("bond root", &request.bond_root)?;
        require_root("quorum attestation root", &request.quorum_attestation_root)?;
        require_root("disclosure root", &request.disclosure_root)?;
        require_bps("slash bps", request.slash_bps)?;
        if request.slash_bps > self.config.max_slash_bps {
            return Err("slash bps exceeds configured maximum".to_string());
        }
        if request.locked_amount_micro_units == 0 {
            return Err("locked amount must be nonzero".to_string());
        }
        self.require_quorum(&request.evidence_id, &request.report_id)?;
        let slash_amount_micro_units = request
            .locked_amount_micro_units
            .saturating_mul(request.slash_bps)
            / MAX_BPS;
        let escrow_id = slashing_escrow_id(
            &request.evidence_id,
            &request.report_id,
            &request.accused_operator_commitment,
            &request.bond_root,
            request.locked_at_height,
        );
        let escrow = SlashingEscrow {
            escrow_id: escrow_id.clone(),
            evidence_id: request.evidence_id.clone(),
            report_id: request.report_id.clone(),
            accused_operator_commitment: request.accused_operator_commitment,
            status: EscrowStatus::AppealOpen,
            locked_amount_micro_units: request.locked_amount_micro_units,
            slash_bps: request.slash_bps,
            slash_amount_micro_units,
            bond_root: request.bond_root,
            reserve_receipt_id: request.reserve_receipt_id,
            quorum_attestation_root: request.quorum_attestation_root,
            disclosure_root: request.disclosure_root,
            appeal_id: String::new(),
            locked_at_height: request.locked_at_height,
            appeal_deadline_height: request
                .locked_at_height
                .saturating_add(self.config.appeal_window_blocks),
            settle_at_height: request
                .locked_at_height
                .saturating_add(self.config.appeal_window_blocks)
                .saturating_add(self.config.settlement_delay_blocks),
        };
        self.slashing_escrows.insert(escrow_id.clone(), escrow);
        if let Some(evidence) = self.encrypted_evidence.get_mut(&request.evidence_id) {
            evidence.escrow_id = escrow_id.clone();
            evidence.status = EvidenceStatus::EscrowLocked;
        }
        self.counters.slashing_escrows = self.counters.slashing_escrows.saturating_add(1);
        self.counters.total_locked_micro_units = self
            .counters
            .total_locked_micro_units
            .saturating_add(request.locked_amount_micro_units as u128);
        self.record_event("slashing_escrow_opened", &escrow_id)?;
        Ok(escrow_id)
    }

    pub fn open_appeal(&mut self, request: OpenAppealRequest) -> Result<String> {
        require_capacity("appeals", self.appeals.len(), self.config.max_appeals)?;
        require_known_evidence(&self.encrypted_evidence, &request.evidence_id)?;
        require_root("appeal root", &request.appeal_root)?;
        require_root("counter evidence root", &request.counter_evidence_root)?;
        require_root("pq signature root", &request.pq_signature_root)?;
        require_root("privacy fence root", &request.privacy_fence_root)?;
        let deadline = self
            .slashing_escrows
            .get(&request.escrow_id)
            .ok_or_else(|| "unknown slashing escrow".to_string())?
            .appeal_deadline_height;
        if request.opened_at_height > deadline {
            return Err("appeal window closed".to_string());
        }
        let appeal_id = appeal_window_id(
            &request.escrow_id,
            &request.evidence_id,
            &request.appellant_commitment,
            &request.appeal_root,
            request.opened_at_height,
        );
        let appeal = AppealWindow {
            appeal_id: appeal_id.clone(),
            escrow_id: request.escrow_id.clone(),
            evidence_id: request.evidence_id.clone(),
            appellant_commitment: request.appellant_commitment,
            status: AppealStatus::EvidenceSubmitted,
            appeal_root: request.appeal_root,
            counter_evidence_root: request.counter_evidence_root,
            pq_signature_root: request.pq_signature_root,
            privacy_fence_root: request.privacy_fence_root,
            opened_at_height: request.opened_at_height,
            deadline_height: deadline,
            resolved_at_height: 0,
            resolution_root: empty_root("MONERO-L2-PQ-WATCHTOWER-SLASHING-APPEAL-RESOLUTION"),
        };
        self.appeals.insert(appeal_id.clone(), appeal);
        if let Some(escrow) = self.slashing_escrows.get_mut(&request.escrow_id) {
            escrow.status = EscrowStatus::AppealOpen;
            escrow.appeal_id = appeal_id.clone();
        }
        if let Some(evidence) = self.encrypted_evidence.get_mut(&request.evidence_id) {
            evidence.status = EvidenceStatus::Appealed;
        }
        self.counters.appeals = self.counters.appeals.saturating_add(1);
        self.record_event("appeal_opened", &appeal_id)?;
        Ok(appeal_id)
    }

    pub fn record_reserve_impact_receipt(
        &mut self,
        request: RecordReserveImpactReceiptRequest,
    ) -> Result<String> {
        require_capacity(
            "reserve impact receipts",
            self.reserve_receipts.len(),
            self.config.max_reserve_receipts,
        )?;
        require_known_evidence(&self.encrypted_evidence, &request.evidence_id)?;
        require_known_report(&self.misconduct_reports, &request.report_id)?;
        require_root("reserve before root", &request.reserve_before_root)?;
        require_root("reserve after root", &request.reserve_after_root)?;
        require_root("mitigation root", &request.mitigation_root)?;
        require_root("pq signature root", &request.pq_signature_root)?;
        require_bps("impact bps", request.impact_bps)?;
        if request.impact_bps > self.config.max_reserve_impact_bps {
            return Err("reserve impact exceeds configured maximum".to_string());
        }
        let receipt_id = reserve_impact_receipt_id(
            request.kind,
            &request.evidence_id,
            &request.report_id,
            &request.reserve_after_root,
            request.issued_at_height,
        );
        let receipt = ReserveImpactReceipt {
            receipt_id: receipt_id.clone(),
            evidence_id: request.evidence_id,
            report_id: request.report_id,
            kind: request.kind,
            bridge_epoch: request.bridge_epoch,
            reserve_before_root: request.reserve_before_root,
            reserve_after_root: request.reserve_after_root,
            impact_amount_micro_units: request.impact_amount_micro_units,
            impact_bps: request.impact_bps,
            mitigation_root: request.mitigation_root,
            accountant_commitment: request.accountant_commitment,
            pq_signature_root: request.pq_signature_root,
            issued_at_height: request.issued_at_height,
        };
        self.reserve_receipts.insert(receipt_id.clone(), receipt);
        self.counters.reserve_receipts = self.counters.reserve_receipts.saturating_add(1);
        self.counters.total_reserve_impact_micro_units = self
            .counters
            .total_reserve_impact_micro_units
            .saturating_add(request.impact_amount_micro_units as u128);
        self.record_event("reserve_impact_receipt_recorded", &receipt_id)?;
        Ok(receipt_id)
    }

    pub fn insert_privacy_fence(&mut self, request: InsertPrivacyFenceRequest) -> Result<String> {
        require_capacity(
            "privacy fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        require_non_empty("subject id", &request.subject_id)?;
        require_root("commitment root", &request.commitment_root)?;
        require_root("nullifier root", &request.nullifier_root)?;
        require_non_empty("replay domain", &request.replay_domain)?;
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy fence set below configured minimum".to_string());
        }
        self.insert_nullifier(&request.nullifier_root)?;
        let fence_id = privacy_fence_id(
            request.kind,
            &request.subject_id,
            &request.commitment_root,
            &request.nullifier_root,
            request.inserted_at_height,
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            kind: request.kind,
            subject_id: request.subject_id,
            commitment_root: request.commitment_root,
            nullifier_root: request.nullifier_root,
            replay_domain: request.replay_domain,
            privacy_set_size: request.privacy_set_size,
            inserted_at_height: request.inserted_at_height,
            expires_at_height: request
                .inserted_at_height
                .saturating_add(request.ttl_blocks),
        };
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        self.record_event("privacy_fence_inserted", &fence_id)?;
        Ok(fence_id)
    }

    pub fn build_low_fee_evidence_batch(
        &mut self,
        request: BuildLowFeeEvidenceBatchRequest,
    ) -> Result<String> {
        require_capacity(
            "low fee batches",
            self.low_fee_batches.len(),
            self.config.max_batches,
        )?;
        if request.evidence_ids.is_empty() {
            return Err("batch requires at least one evidence id".to_string());
        }
        if request.evidence_ids.len() > self.config.low_fee_batch_size.max(1) {
            return Err("batch exceeds configured low fee batch size".to_string());
        }
        let mut seen = BTreeSet::new();
        for evidence_id in &request.evidence_ids {
            if !seen.insert(evidence_id.clone()) {
                return Err("duplicate evidence id in batch".to_string());
            }
            require_known_evidence(&self.encrypted_evidence, evidence_id)?;
        }
        for report_id in &request.report_ids {
            require_known_report(&self.misconduct_reports, report_id)?;
        }
        for escrow_id in &request.escrow_ids {
            if !self.slashing_escrows.contains_key(escrow_id) {
                return Err("batch references unknown slashing escrow".to_string());
            }
        }
        let evidence_records = request
            .evidence_ids
            .iter()
            .filter_map(|id| self.encrypted_evidence.get(id))
            .map(EncryptedWatcherEvidence::public_record)
            .collect::<Vec<_>>();
        let report_records = request
            .report_ids
            .iter()
            .filter_map(|id| self.misconduct_reports.get(id))
            .map(BridgeRelayMisconductReport::public_record)
            .collect::<Vec<_>>();
        let escrow_records = request
            .escrow_ids
            .iter()
            .filter_map(|id| self.slashing_escrows.get(id))
            .map(SlashingEscrow::public_record)
            .collect::<Vec<_>>();
        let evidence_root = merkle_root(
            "MONERO-L2-PQ-WATCHTOWER-SLASHING-BATCH-EVIDENCE",
            &evidence_records,
        );
        let report_root = merkle_root(
            "MONERO-L2-PQ-WATCHTOWER-SLASHING-BATCH-REPORT",
            &report_records,
        );
        let escrow_root = merkle_root(
            "MONERO-L2-PQ-WATCHTOWER-SLASHING-BATCH-ESCROW",
            &escrow_records,
        );
        let quorum_root = self.quorum_root_for_evidence_ids(&request.evidence_ids);
        let disclosure_root = self.disclosure_root_for_evidence_ids(&request.evidence_ids);
        let reserve_receipt_root = self.reserve_root_for_report_ids(&request.report_ids);
        let privacy_fence_root = self.privacy_fence_root_for_subjects(&request.evidence_ids);
        let nullifier_root = self.nullifier_root();
        let batch_id = low_fee_batch_id(
            &evidence_root,
            &report_root,
            &escrow_root,
            request.built_at_height,
        );
        let batch = LowFeeEvidenceBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::Sealed,
            evidence_ids: request.evidence_ids.clone(),
            report_ids: request.report_ids,
            escrow_ids: request.escrow_ids,
            evidence_root,
            report_root,
            quorum_root,
            disclosure_root,
            escrow_root,
            reserve_receipt_root,
            privacy_fence_root,
            nullifier_root,
            estimated_fee_micro_units: request.estimated_fee_micro_units,
            target_fee_micro_units: request.target_fee_micro_units,
            built_at_height: request.built_at_height,
            finalized_at_height: 0,
        };
        self.low_fee_batches.insert(batch_id.clone(), batch);
        for evidence_id in request.evidence_ids {
            if let Some(evidence) = self.encrypted_evidence.get_mut(&evidence_id) {
                evidence.batch_id = batch_id.clone();
                evidence.status = EvidenceStatus::Batched;
            }
        }
        self.counters.low_fee_batches = self.counters.low_fee_batches.saturating_add(1);
        self.counters.total_batch_fee_micro_units = self
            .counters
            .total_batch_fee_micro_units
            .saturating_add(request.estimated_fee_micro_units as u128);
        self.record_event("low_fee_evidence_batch_built", &batch_id)?;
        Ok(batch_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-COUNTERS",
                &self.counters.public_record(),
            ),
            evidence_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-EVIDENCE",
                &self
                    .encrypted_evidence
                    .values()
                    .map(EncryptedWatcherEvidence::public_record)
                    .collect::<Vec<_>>(),
            ),
            report_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-REPORT",
                &self
                    .misconduct_reports
                    .values()
                    .map(BridgeRelayMisconductReport::public_record)
                    .collect::<Vec<_>>(),
            ),
            quorum_attestation_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-QUORUM",
                &self
                    .quorum_attestations
                    .values()
                    .map(PqQuorumAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            disclosure_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-DISCLOSURE",
                &self
                    .disclosures
                    .values()
                    .map(DelayedDisclosureCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            escrow_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-ESCROW",
                &self
                    .slashing_escrows
                    .values()
                    .map(SlashingEscrow::public_record)
                    .collect::<Vec<_>>(),
            ),
            appeal_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-APPEAL",
                &self
                    .appeals
                    .values()
                    .map(AppealWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            reserve_receipt_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-RESERVE",
                &self
                    .reserve_receipts
                    .values()
                    .map(ReserveImpactReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            privacy_fence_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-FENCE",
                &self
                    .privacy_fences
                    .values()
                    .map(PrivacyFence::public_record)
                    .collect::<Vec<_>>(),
            ),
            batch_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-BATCH",
                &self
                    .low_fee_batches
                    .values()
                    .map(LowFeeEvidenceBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            event_root: public_record_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE-EVENT",
                &self
                    .events
                    .values()
                    .map(RuntimeEvent::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_PRIVATE_WATCHTOWER_SLASHING_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "encrypted_evidence_count": self.encrypted_evidence.len(),
            "misconduct_report_count": self.misconduct_reports.len(),
            "quorum_attestation_count": self.quorum_attestations.len(),
            "disclosure_count": self.disclosures.len(),
            "slashing_escrow_count": self.slashing_escrows.len(),
            "appeal_count": self.appeals.len(),
            "reserve_receipt_count": self.reserve_receipts.len(),
            "privacy_fence_count": self.privacy_fences.len(),
            "low_fee_batch_count": self.low_fee_batches.len(),
            "nullifier_count": self.nullifier_index.len(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    fn insert_nullifier(&mut self, nullifier_root: &str) -> Result<()> {
        if self.nullifier_index.contains(nullifier_root) {
            return Err("duplicate privacy nullifier".to_string());
        }
        self.nullifier_index.insert(nullifier_root.to_string());
        Ok(())
    }

    fn require_quorum(&self, evidence_id: &str, report_id: &str) -> Result<()> {
        let mut watchers = BTreeSet::new();
        let mut weight = 0_u64;
        for attestation in self.quorum_attestations.values() {
            if attestation.evidence_id == evidence_id && attestation.report_id == report_id {
                watchers.insert(attestation.watcher_commitment.clone());
                weight = weight.saturating_add(attestation.weight);
            }
        }
        if watchers.len() < self.config.min_watcher_quorum as usize {
            return Err("watchtower quorum count below configured minimum".to_string());
        }
        if weight < self.config.min_quorum_weight {
            return Err("watchtower quorum weight below configured minimum".to_string());
        }
        Ok(())
    }

    fn refresh_quorum_status(&mut self, evidence_id: &str, report_id: &str) {
        if self.require_quorum(evidence_id, report_id).is_err() {
            if let Some(evidence) = self.encrypted_evidence.get_mut(evidence_id) {
                evidence.status = EvidenceStatus::QuorumPending;
            }
            return;
        }
        let quorum_root = self.quorum_root_for_report(report_id);
        if let Some(evidence) = self.encrypted_evidence.get_mut(evidence_id) {
            evidence.status = EvidenceStatus::QuorumAttested;
            evidence.quorum_root = quorum_root;
        }
        if let Some(report) = self.misconduct_reports.get_mut(report_id) {
            report.status = ReportStatus::QuorumAttached;
        }
    }

    fn quorum_root_for_report(&self, report_id: &str) -> String {
        let records = self
            .quorum_attestations
            .values()
            .filter(|attestation| report_id.is_empty() || attestation.report_id == report_id)
            .map(PqQuorumAttestation::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-L2-PQ-WATCHTOWER-SLASHING-QUORUM-ROOT", &records)
    }

    fn quorum_root_for_evidence_ids(&self, evidence_ids: &[String]) -> String {
        let set = evidence_ids.iter().cloned().collect::<BTreeSet<_>>();
        let records = self
            .quorum_attestations
            .values()
            .filter(|attestation| set.contains(&attestation.evidence_id))
            .map(PqQuorumAttestation::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-L2-PQ-WATCHTOWER-SLASHING-BATCH-QUORUM", &records)
    }

    fn disclosure_root_for_evidence_ids(&self, evidence_ids: &[String]) -> String {
        let set = evidence_ids.iter().cloned().collect::<BTreeSet<_>>();
        let records = self
            .disclosures
            .values()
            .filter(|disclosure| set.contains(&disclosure.evidence_id))
            .map(DelayedDisclosureCommitment::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-WATCHTOWER-SLASHING-BATCH-DISCLOSURE",
            &records,
        )
    }

    fn reserve_root_for_report_ids(&self, report_ids: &[String]) -> String {
        let set = report_ids.iter().cloned().collect::<BTreeSet<_>>();
        let records = self
            .reserve_receipts
            .values()
            .filter(|receipt| set.contains(&receipt.report_id))
            .map(ReserveImpactReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-L2-PQ-WATCHTOWER-SLASHING-BATCH-RESERVE", &records)
    }

    fn privacy_fence_root_for_subjects(&self, subject_ids: &[String]) -> String {
        let set = subject_ids.iter().cloned().collect::<BTreeSet<_>>();
        let records = self
            .privacy_fences
            .values()
            .filter(|fence| set.contains(&fence.subject_id))
            .map(PrivacyFence::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-L2-PQ-WATCHTOWER-SLASHING-BATCH-FENCE", &records)
    }

    fn nullifier_root(&self) -> String {
        let records = self
            .nullifier_index
            .iter()
            .map(|nullifier| json!({ "nullifier_root": nullifier }))
            .collect::<Vec<_>>();
        merkle_root("MONERO-L2-PQ-WATCHTOWER-SLASHING-NULLIFIERS", &records)
    }

    fn record_event(&mut self, event_kind: &str, subject_id: &str) -> Result<()> {
        require_capacity("events", self.events.len(), self.config.max_events)?;
        let subject_root = self.subject_root(subject_id);
        let sequence = self.events.len() as u64;
        let event_id =
            runtime_event_id(event_kind, subject_id, &subject_root, self.height, sequence);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            height: self.height,
            sequence,
        };
        self.events.insert(event_id, event);
        self.counters.events = self.counters.events.saturating_add(1);
        Ok(())
    }

    fn subject_root(&self, subject_id: &str) -> String {
        if let Some(value) = self.encrypted_evidence.get(subject_id) {
            return payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-EVIDENCE",
                &value.public_record(),
            );
        }
        if let Some(value) = self.misconduct_reports.get(subject_id) {
            return payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-REPORT",
                &value.public_record(),
            );
        }
        if let Some(value) = self.quorum_attestations.get(subject_id) {
            return payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-QUORUM-ATTESTATION",
                &value.public_record(),
            );
        }
        if let Some(value) = self.disclosures.get(subject_id) {
            return payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-DISCLOSURE",
                &value.public_record(),
            );
        }
        if let Some(value) = self.slashing_escrows.get(subject_id) {
            return payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-ESCROW",
                &value.public_record(),
            );
        }
        if let Some(value) = self.appeals.get(subject_id) {
            return payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-APPEAL",
                &value.public_record(),
            );
        }
        if let Some(value) = self.reserve_receipts.get(subject_id) {
            return payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-RESERVE-RECEIPT",
                &value.public_record(),
            );
        }
        if let Some(value) = self.privacy_fences.get(subject_id) {
            return payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-FENCE",
                &value.public_record(),
            );
        }
        if let Some(value) = self.low_fee_batches.get(subject_id) {
            return payload_root(
                "MONERO-L2-PQ-WATCHTOWER-SLASHING-BATCH",
                &value.public_record(),
            );
        }
        string_root(
            "MONERO-L2-PQ-WATCHTOWER-SLASHING-UNKNOWN-SUBJECT",
            subject_id,
        )
    }
}

pub fn encrypted_evidence_id(
    kind: EvidenceKind,
    watcher_commitment: &str,
    subject_commitment: &str,
    ciphertext_root: &str,
    nullifier_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(watcher_commitment),
            HashPart::Str(subject_commitment),
            HashPart::Str(ciphertext_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(submitted_at_height),
        ],
        32,
    )
}

pub fn misconduct_report_id(
    kind: MisconductKind,
    evidence_id: &str,
    accused_operator_commitment: &str,
    report_root: &str,
    filed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_id),
            HashPart::Str(accused_operator_commitment),
            HashPart::Str(report_root),
            HashPart::U64(filed_at_height),
        ],
        32,
    )
}

pub fn pq_quorum_attestation_id(
    kind: QuorumAttestationKind,
    evidence_id: &str,
    report_id: &str,
    watcher_commitment: &str,
    statement_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-QUORUM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_id),
            HashPart::Str(report_id),
            HashPart::Str(watcher_commitment),
            HashPart::Str(statement_root),
            HashPart::U64(signed_at_height),
        ],
        32,
    )
}

pub fn delayed_disclosure_id(
    evidence_id: &str,
    report_id: &str,
    commitment_root: &str,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_id),
            HashPart::Str(report_id),
            HashPart::Str(commitment_root),
            HashPart::U64(committed_at_height),
        ],
        32,
    )
}

pub fn slashing_escrow_id(
    evidence_id: &str,
    report_id: &str,
    accused_operator_commitment: &str,
    bond_root: &str,
    locked_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-ESCROW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_id),
            HashPart::Str(report_id),
            HashPart::Str(accused_operator_commitment),
            HashPart::Str(bond_root),
            HashPart::U64(locked_at_height),
        ],
        32,
    )
}

pub fn appeal_window_id(
    escrow_id: &str,
    evidence_id: &str,
    appellant_commitment: &str,
    appeal_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-APPEAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(escrow_id),
            HashPart::Str(evidence_id),
            HashPart::Str(appellant_commitment),
            HashPart::Str(appeal_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn reserve_impact_receipt_id(
    kind: ReserveImpactKind,
    evidence_id: &str,
    report_id: &str,
    reserve_after_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-RESERVE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_id),
            HashPart::Str(report_id),
            HashPart::Str(reserve_after_root),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    kind: FenceKind,
    subject_id: &str,
    commitment_root: &str,
    nullifier_root: &str,
    inserted_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(commitment_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(inserted_at_height),
        ],
        32,
    )
}

pub fn low_fee_batch_id(
    evidence_root: &str,
    report_root: &str,
    escrow_root: &str,
    built_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_root),
            HashPart::Str(report_root),
            HashPart::Str(escrow_root),
            HashPart::U64(built_at_height),
        ],
        32,
    )
}

pub fn runtime_event_id(
    event_kind: &str,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHTOWER-SLASHING-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn commitment(label: &str) -> String {
    string_root("MONERO-L2-PQ-WATCHTOWER-SLASHING-COMMITMENT", label)
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require_non_empty(label, value)?;
    if value.len() < 32 {
        return Err(format!("{label} must be a commitment root"));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn require_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require_known_evidence(
    evidence: &BTreeMap<String, EncryptedWatcherEvidence>,
    evidence_id: &str,
) -> Result<()> {
    if evidence.contains_key(evidence_id) {
        Ok(())
    } else {
        Err("unknown encrypted watcher evidence".to_string())
    }
}

fn require_known_report(
    reports: &BTreeMap<String, BridgeRelayMisconductReport>,
    report_id: &str,
) -> Result<()> {
    if reports.contains_key(report_id) {
        Ok(())
    } else {
        Err("unknown bridge relay misconduct report".to_string())
    }
}

fn require_known_reserve_receipt(
    receipts: &BTreeMap<String, ReserveImpactReceipt>,
    receipt_id: &str,
) -> Result<()> {
    if receipts.contains_key(receipt_id) {
        Ok(())
    } else {
        Err("unknown reserve impact receipt".to_string())
    }
}
