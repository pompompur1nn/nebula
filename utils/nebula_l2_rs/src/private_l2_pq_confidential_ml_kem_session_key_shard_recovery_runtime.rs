use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialMlKemSessionKeyShardRecoveryRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_SESSION_KEY_SHARD_RECOVERY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-ml-kem-session-key-shard-recovery-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_ML_KEM_SESSION_KEY_SHARD_RECOVERY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ML_KEM_RECOVERY_SUITE: &str = "ML-KEM-1024-session-key-shard-recovery-envelope-v1";
pub const SHARD_ESCROW_ENVELOPE_SUITE: &str = "private-l2-pq-confidential-shard-escrow-envelope-v1";
pub const RECOVERY_COMMITTEE_SUITE: &str = "ml-kem-session-key-recovery-committee-v1";
pub const THRESHOLD_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-threshold-recovery-attestation-v1";
pub const LEGACY_QUARANTINE_SUITE: &str = "legacy-session-key-quarantine-ledger-v1";
pub const SPONSOR_REBATE_SUITE: &str = "low-fee-session-key-recovery-sponsor-rebate-v1";
pub const PRIVACY_REDACTION_BUDGET_SUITE: &str =
    "operator-safe-session-key-recovery-redaction-budget-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-deterministic-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 4_904_800;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_782_400;
pub const DEVNET_EPOCH: u64 = 23_360;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "pq-session-recovery-rebate-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_ROTATION_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_RECOVERY_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_ESCROW_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_LEGACY_QUARANTINE_BLOCKS: u64 = 43_200;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 4_096;
pub const DEFAULT_MIN_COMMITTEE_SIZE: u16 = 7;
pub const DEFAULT_RECOVERY_THRESHOLD: u16 = 5;
pub const DEFAULT_VETO_THRESHOLD: u16 = 2;
pub const DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const DEFAULT_MIN_OPERATOR_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_REBATE_CAP_MICRONERO: u64 = 250_000;
pub const MAX_BPS: u64 = 10_000;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlKemParameterSet {
    MlKem512,
    MlKem768,
    MlKem1024,
    HybridX25519MlKem768,
    HybridX25519MlKem1024,
}

impl MlKemParameterSet {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem512 => "ml_kem_512",
            Self::MlKem768 => "ml_kem_768",
            Self::MlKem1024 => "ml_kem_1024",
            Self::HybridX25519MlKem768 => "hybrid_x25519_ml_kem_768",
            Self::HybridX25519MlKem1024 => "hybrid_x25519_ml_kem_1024",
        }
    }

    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlKem512 => 128,
            Self::MlKem768 | Self::HybridX25519MlKem768 => 192,
            Self::MlKem1024 | Self::HybridX25519MlKem1024 => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLane {
    WalletSession,
    ContractSession,
    BridgeExitSession,
    PaymasterSponsoredSession,
    WatchtowerEvidenceSession,
    EmergencyEscapeSession,
}

impl RecoveryLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSession => "wallet_session",
            Self::ContractSession => "contract_session",
            Self::BridgeExitSession => "bridge_exit_session",
            Self::PaymasterSponsoredSession => "paymaster_sponsored_session",
            Self::WatchtowerEvidenceSession => "watchtower_evidence_session",
            Self::EmergencyEscapeSession => "emergency_escape_session",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscapeSession => 10_000,
            Self::BridgeExitSession => 9_200,
            Self::WatchtowerEvidenceSession => 8_400,
            Self::ContractSession => 7_600,
            Self::PaymasterSponsoredSession => 7_200,
            Self::WalletSession => 6_400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    ShardCustodian,
    RecoveryAssembler,
    PrivacyAuditor,
    Sponsor,
    Watchtower,
    LegacyQuarantineOfficer,
    Observer,
}

impl CommitteeRole {
    pub fn voting_weight(self) -> u64 {
        match self {
            Self::ShardCustodian => 10_000,
            Self::RecoveryAssembler => 9_200,
            Self::PrivacyAuditor => 8_600,
            Self::Watchtower => 8_000,
            Self::LegacyQuarantineOfficer => 7_300,
            Self::Sponsor => 6_800,
            Self::Observer => 2_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Draft,
    Active,
    Rotating,
    GracePeriod,
    Paused,
    Quarantined,
    Retired,
}

impl CommitteeStatus {
    pub fn accepts_recovery(self) -> bool {
        matches!(self, Self::Active | Self::Rotating | Self::GracePeriod)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Sealed,
    Escrowed,
    CommitteeBound,
    RecoveryOpen,
    Recovered,
    Expired,
    Quarantined,
    Redacted,
}

impl EnvelopeStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Escrowed | Self::CommitteeBound | Self::RecoveryOpen
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accepted,
    ThresholdMet,
    PrivacyBudgetExceeded,
    LegacyQuarantined,
    SponsorRebateIssued,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    LegacyKemParameter,
    MissingRotationTranscript,
    ReusedSessionCiphertext,
    WeakPrivacySet,
    OperatorDispute,
    EmergencyFreeze,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub rotation_window_blocks: u64,
    pub recovery_window_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub escrow_ttl_blocks: u64,
    pub legacy_quarantine_blocks: u64,
    pub redaction_budget_units: u64,
    pub min_committee_size: u16,
    pub recovery_threshold: u16,
    pub veto_threshold: u16,
    pub max_sponsor_rebate_bps: u64,
    pub min_operator_quorum_bps: u64,
    pub rebate_cap_micronero: u64,
    pub require_dual_pq_attestation: bool,
    pub require_monero_anchor: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            rotation_window_blocks: DEFAULT_ROTATION_WINDOW_BLOCKS,
            recovery_window_blocks: DEFAULT_RECOVERY_WINDOW_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            escrow_ttl_blocks: DEFAULT_ESCROW_TTL_BLOCKS,
            legacy_quarantine_blocks: DEFAULT_LEGACY_QUARANTINE_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            min_committee_size: DEFAULT_MIN_COMMITTEE_SIZE,
            recovery_threshold: DEFAULT_RECOVERY_THRESHOLD,
            veto_threshold: DEFAULT_VETO_THRESHOLD,
            max_sponsor_rebate_bps: DEFAULT_MAX_SPONSOR_REBATE_BPS,
            min_operator_quorum_bps: DEFAULT_MIN_OPERATOR_QUORUM_BPS,
            rebate_cap_micronero: DEFAULT_REBATE_CAP_MICRONERO,
            require_dual_pq_attestation: true,
            require_monero_anchor: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security floor below ML-KEM-1024 target"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum"
        );
        ensure!(
            self.recovery_threshold <= self.min_committee_size,
            "recovery threshold exceeds committee size"
        );
        ensure!(
            self.veto_threshold < self.recovery_threshold,
            "veto threshold must be below recovery threshold"
        );
        ensure!(
            self.max_sponsor_rebate_bps <= MAX_BPS,
            "sponsor rebate bps exceeds max"
        );
        ensure!(
            self.min_operator_quorum_bps <= MAX_BPS,
            "operator quorum bps exceeds max"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "rotation_window_blocks": self.rotation_window_blocks,
            "recovery_window_blocks": self.recovery_window_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "escrow_ttl_blocks": self.escrow_ttl_blocks,
            "legacy_quarantine_blocks": self.legacy_quarantine_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "min_committee_size": self.min_committee_size,
            "recovery_threshold": self.recovery_threshold,
            "veto_threshold": self.veto_threshold,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "min_operator_quorum_bps": self.min_operator_quorum_bps,
            "rebate_cap_micronero": self.rebate_cap_micronero,
            "require_dual_pq_attestation": self.require_dual_pq_attestation,
            "require_monero_anchor": self.require_monero_anchor,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-SHARD-RECOVERY-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub committees_registered: u64,
    pub rotation_windows_opened: u64,
    pub shard_envelopes_escrowed: u64,
    pub recovery_requests_opened: u64,
    pub threshold_attestations_accepted: u64,
    pub recoveries_completed: u64,
    pub legacy_items_quarantined: u64,
    pub sponsor_rebates_issued: u64,
    pub privacy_redactions_spent: u64,
    pub deterministic_roots_published: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "committees_registered": self.committees_registered,
            "rotation_windows_opened": self.rotation_windows_opened,
            "shard_envelopes_escrowed": self.shard_envelopes_escrowed,
            "recovery_requests_opened": self.recovery_requests_opened,
            "threshold_attestations_accepted": self.threshold_attestations_accepted,
            "recoveries_completed": self.recoveries_completed,
            "legacy_items_quarantined": self.legacy_items_quarantined,
            "sponsor_rebates_issued": self.sponsor_rebates_issued,
            "privacy_redactions_spent": self.privacy_redactions_spent,
            "deterministic_roots_published": self.deterministic_roots_published,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-SHARD-RECOVERY-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub committee_root: String,
    pub rotation_window_root: String,
    pub shard_envelope_root: String,
    pub recovery_request_root: String,
    pub threshold_attestation_root: String,
    pub legacy_quarantine_root: String,
    pub sponsor_rebate_root: String,
    pub privacy_redaction_budget_root: String,
    pub used_nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "committee_root": self.committee_root,
            "rotation_window_root": self.rotation_window_root,
            "shard_envelope_root": self.shard_envelope_root,
            "recovery_request_root": self.recovery_request_root,
            "threshold_attestation_root": self.threshold_attestation_root,
            "legacy_quarantine_root": self.legacy_quarantine_root,
            "sponsor_rebate_root": self.sponsor_rebate_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "used_nullifier_root": self.used_nullifier_root,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-SHARD-RECOVERY-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RecoveryCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub status: CommitteeStatus,
    pub member_commitment_root: String,
    pub role: CommitteeRole,
    pub member_count: u16,
    pub recovery_threshold: u16,
    pub veto_threshold: u16,
    pub operator_quorum_bps: u64,
    pub privacy_set_size: u64,
    pub activated_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl RecoveryCommittee {
    pub fn public_record(&self) -> Value {
        json!({
            "suite": RECOVERY_COMMITTEE_SUITE,
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "status": self.status,
            "member_commitment_root": self.member_commitment_root,
            "role": self.role,
            "role_weight": self.role.voting_weight(),
            "member_count": self.member_count,
            "recovery_threshold": self.recovery_threshold,
            "veto_threshold": self.veto_threshold,
            "operator_quorum_bps": self.operator_quorum_bps,
            "privacy_set_size": self.privacy_set_size,
            "activated_at_l2_height": self.activated_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-SHARD-RECOVERY-COMMITTEE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RotationWindow {
    pub window_id: String,
    pub committee_id: String,
    pub prior_window_id: Option<String>,
    pub opens_at_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub monero_anchor_height: u64,
    pub rotated_session_root: String,
    pub replacement_committee_root: String,
    pub privacy_floor: u64,
}

impl RotationWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "committee_id": self.committee_id,
            "prior_window_id": self.prior_window_id,
            "opens_at_l2_height": self.opens_at_l2_height,
            "closes_at_l2_height": self.closes_at_l2_height,
            "monero_anchor_height": self.monero_anchor_height,
            "rotated_session_root": self.rotated_session_root,
            "replacement_committee_root": self.replacement_committee_root,
            "privacy_floor": self.privacy_floor,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root(
            "ML-KEM-SHARD-RECOVERY-ROTATION-WINDOW",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ShardEscrowEnvelope {
    pub envelope_id: String,
    pub account_commitment: String,
    pub session_commitment: String,
    pub committee_id: String,
    pub rotation_window_id: String,
    pub lane: RecoveryLane,
    pub kem_parameter_set: MlKemParameterSet,
    pub status: EnvelopeStatus,
    pub shard_count: u16,
    pub threshold: u16,
    pub ciphertext_root: String,
    pub shard_commitment_root: String,
    pub view_tag_redaction_root: String,
    pub created_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl ShardEscrowEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "suite": SHARD_ESCROW_ENVELOPE_SUITE,
            "envelope_id": self.envelope_id,
            "account_commitment": self.account_commitment,
            "session_commitment": self.session_commitment,
            "committee_id": self.committee_id,
            "rotation_window_id": self.rotation_window_id,
            "lane": self.lane,
            "lane_tag": self.lane.as_str(),
            "lane_priority_weight": self.lane.priority_weight(),
            "kem_parameter_set": self.kem_parameter_set,
            "kem_parameter_tag": self.kem_parameter_set.as_str(),
            "pq_security_bits": self.kem_parameter_set.pq_security_bits(),
            "status": self.status,
            "active": self.status.active(),
            "shard_count": self.shard_count,
            "threshold": self.threshold,
            "ciphertext_root": self.ciphertext_root,
            "shard_commitment_root": self.shard_commitment_root,
            "view_tag_redaction_root": self.view_tag_redaction_root,
            "created_at_l2_height": self.created_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root(
            "ML-KEM-SHARD-RECOVERY-ESCROW-ENVELOPE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RecoveryRequest {
    pub request_id: String,
    pub envelope_id: String,
    pub requester_commitment: String,
    pub committee_id: String,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub nullifier: String,
    pub recovery_transcript_root: String,
    pub sponsor_id: Option<String>,
}

impl RecoveryRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "envelope_id": self.envelope_id,
            "requester_commitment": self.requester_commitment,
            "committee_id": self.committee_id,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "nullifier": self.nullifier,
            "recovery_transcript_root": self.recovery_transcript_root,
            "sponsor_id": self.sponsor_id,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-SHARD-RECOVERY-REQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ThresholdRecoveryAttestation {
    pub attestation_id: String,
    pub request_id: String,
    pub committee_id: String,
    pub signer_commitment_root: String,
    pub signature_root: String,
    pub verdict: AttestationVerdict,
    pub signed_weight_bps: u64,
    pub threshold_met: bool,
    pub attested_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl ThresholdRecoveryAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "suite": THRESHOLD_ATTESTATION_SUITE,
            "attestation_id": self.attestation_id,
            "request_id": self.request_id,
            "committee_id": self.committee_id,
            "signer_commitment_root": self.signer_commitment_root,
            "signature_root": self.signature_root,
            "verdict": self.verdict,
            "signed_weight_bps": self.signed_weight_bps,
            "threshold_met": self.threshold_met,
            "attested_at_l2_height": self.attested_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root("ML-KEM-SHARD-RECOVERY-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LegacyQuarantine {
    pub quarantine_id: String,
    pub envelope_id: String,
    pub reason: QuarantineReason,
    pub legacy_ciphertext_root: String,
    pub quarantine_until_l2_height: u64,
    pub operator_note_commitment: String,
}

impl LegacyQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "suite": LEGACY_QUARANTINE_SUITE,
            "quarantine_id": self.quarantine_id,
            "envelope_id": self.envelope_id,
            "reason": self.reason,
            "legacy_ciphertext_root": self.legacy_ciphertext_root,
            "quarantine_until_l2_height": self.quarantine_until_l2_height,
            "operator_note_commitment": self.operator_note_commitment,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root(
            "ML-KEM-SHARD-RECOVERY-LEGACY-QUARANTINE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SponsorFeeRebate {
    pub rebate_id: String,
    pub request_id: String,
    pub sponsor_id: String,
    pub recipient_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_bps: u64,
    pub rebate_micronero: u64,
    pub issued_at_l2_height: u64,
}

impl SponsorFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "suite": SPONSOR_REBATE_SUITE,
            "rebate_id": self.rebate_id,
            "request_id": self.request_id,
            "sponsor_id": self.sponsor_id,
            "recipient_commitment": self.recipient_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_bps": self.rebate_bps,
            "rebate_micronero": self.rebate_micronero,
            "issued_at_l2_height": self.issued_at_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root(
            "ML-KEM-SHARD-RECOVERY-SPONSOR-REBATE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub committee_id: String,
    pub units_granted: u64,
    pub units_spent: u64,
    pub epoch: u64,
    pub disclosure_floor: String,
}

impl PrivacyRedactionBudget {
    pub fn spend(&mut self, units: u64) -> Result<()> {
        ensure!(
            self.units_spent.saturating_add(units) <= self.units_granted,
            "redaction budget exhausted for {}",
            self.budget_id
        );
        self.units_spent += units;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "suite": PRIVACY_REDACTION_BUDGET_SUITE,
            "budget_id": self.budget_id,
            "committee_id": self.committee_id,
            "units_granted": self.units_granted,
            "units_spent": self.units_spent,
            "units_remaining": self.units_granted.saturating_sub(self.units_spent),
            "epoch": self.epoch,
            "disclosure_floor": self.disclosure_floor,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_root(
            "ML-KEM-SHARD-RECOVERY-REDACTION-BUDGET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub committees: BTreeMap<String, RecoveryCommittee>,
    pub rotation_windows: BTreeMap<String, RotationWindow>,
    pub shard_envelopes: BTreeMap<String, ShardEscrowEnvelope>,
    pub recovery_requests: BTreeMap<String, RecoveryRequest>,
    pub threshold_attestations: BTreeMap<String, ThresholdRecoveryAttestation>,
    pub legacy_quarantines: BTreeMap<String, LegacyQuarantine>,
    pub sponsor_rebates: BTreeMap<String, SponsorFeeRebate>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub used_nullifiers: BTreeSet<String>,
    pub active_committee_id: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default shard recovery config is valid")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            committees: BTreeMap::new(),
            rotation_windows: BTreeMap::new(),
            shard_envelopes: BTreeMap::new(),
            recovery_requests: BTreeMap::new(),
            threshold_attestations: BTreeMap::new(),
            legacy_quarantines: BTreeMap::new(),
            sponsor_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            active_committee_id: None,
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
            committee_root: map_root(
                "ML-KEM-SHARD-RECOVERY-COMMITTEES",
                self.committees
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            rotation_window_root: map_root(
                "ML-KEM-SHARD-RECOVERY-ROTATION-WINDOWS",
                self.rotation_windows
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            shard_envelope_root: map_root(
                "ML-KEM-SHARD-RECOVERY-ENVELOPES",
                self.shard_envelopes
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            recovery_request_root: map_root(
                "ML-KEM-SHARD-RECOVERY-REQUESTS",
                self.recovery_requests
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            threshold_attestation_root: map_root(
                "ML-KEM-SHARD-RECOVERY-ATTESTATIONS",
                self.threshold_attestations
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            legacy_quarantine_root: map_root(
                "ML-KEM-SHARD-RECOVERY-LEGACY-QUARANTINES",
                self.legacy_quarantines
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            sponsor_rebate_root: map_root(
                "ML-KEM-SHARD-RECOVERY-SPONSOR-REBATES",
                self.sponsor_rebates
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            privacy_redaction_budget_root: map_root(
                "ML-KEM-SHARD-RECOVERY-REDACTION-BUDGETS",
                self.redaction_budgets
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            used_nullifier_root: set_root(
                "ML-KEM-SHARD-RECOVERY-USED-NULLIFIERS",
                self.used_nullifiers.iter().map(String::as_str),
            ),
        }
    }

    pub fn register_committee(&mut self, committee: RecoveryCommittee) -> Result<String> {
        ensure!(
            committee.member_count >= self.config.min_committee_size,
            "committee {} below minimum size",
            committee.committee_id
        );
        ensure!(
            committee.recovery_threshold >= self.config.recovery_threshold,
            "committee {} below recovery threshold",
            committee.committee_id
        );
        ensure!(
            committee.privacy_set_size >= self.config.min_privacy_set_size,
            "committee {} below privacy floor",
            committee.committee_id
        );
        let id = committee.committee_id.clone();
        if committee.status.accepts_recovery() {
            self.active_committee_id = Some(id.clone());
        }
        self.committees.insert(id.clone(), committee);
        self.counters.committees_registered = self.committees.len() as u64;
        Ok(id)
    }

    pub fn open_rotation_window(&mut self, window: RotationWindow) -> Result<String> {
        ensure!(
            self.committees.contains_key(&window.committee_id),
            "missing committee {} for rotation window",
            window.committee_id
        );
        ensure!(
            window.closes_at_l2_height > window.opens_at_l2_height,
            "rotation window {} closes before it opens",
            window.window_id
        );
        let id = window.window_id.clone();
        self.rotation_windows.insert(id.clone(), window);
        self.counters.rotation_windows_opened = self.rotation_windows.len() as u64;
        Ok(id)
    }

    pub fn escrow_shard_envelope(&mut self, envelope: ShardEscrowEnvelope) -> Result<String> {
        ensure!(
            envelope.kem_parameter_set.pq_security_bits() >= self.config.min_pq_security_bits,
            "envelope {} below pq security floor",
            envelope.envelope_id
        );
        ensure!(
            envelope.threshold <= envelope.shard_count,
            "envelope {} threshold exceeds shard count",
            envelope.envelope_id
        );
        ensure!(
            self.committees.contains_key(&envelope.committee_id),
            "missing committee {} for envelope",
            envelope.committee_id
        );
        ensure!(
            self.rotation_windows
                .contains_key(&envelope.rotation_window_id),
            "missing rotation window {} for envelope",
            envelope.rotation_window_id
        );
        let id = envelope.envelope_id.clone();
        self.shard_envelopes.insert(id.clone(), envelope);
        self.counters.shard_envelopes_escrowed = self.shard_envelopes.len() as u64;
        Ok(id)
    }

    pub fn open_recovery_request(&mut self, request: RecoveryRequest) -> Result<String> {
        ensure!(
            self.shard_envelopes.contains_key(&request.envelope_id),
            "missing envelope {} for recovery request",
            request.envelope_id
        );
        ensure!(
            self.used_nullifiers.insert(request.nullifier.clone()),
            "duplicate recovery nullifier {}",
            request.nullifier
        );
        let id = request.request_id.clone();
        self.recovery_requests.insert(id.clone(), request);
        self.counters.recovery_requests_opened = self.recovery_requests.len() as u64;
        Ok(id)
    }

    pub fn accept_threshold_attestation(
        &mut self,
        attestation: ThresholdRecoveryAttestation,
    ) -> Result<String> {
        ensure!(
            self.recovery_requests.contains_key(&attestation.request_id),
            "missing request {} for attestation",
            attestation.request_id
        );
        ensure!(
            attestation.signed_weight_bps <= MAX_BPS,
            "attestation {} signed weight exceeds max bps",
            attestation.attestation_id
        );
        let id = attestation.attestation_id.clone();
        if attestation.threshold_met {
            self.counters.recoveries_completed += 1;
        }
        self.threshold_attestations.insert(id.clone(), attestation);
        self.counters.threshold_attestations_accepted = self.threshold_attestations.len() as u64;
        Ok(id)
    }

    pub fn quarantine_legacy(&mut self, quarantine: LegacyQuarantine) -> Result<String> {
        ensure!(
            self.shard_envelopes.contains_key(&quarantine.envelope_id),
            "missing envelope {} for quarantine",
            quarantine.envelope_id
        );
        let id = quarantine.quarantine_id.clone();
        self.legacy_quarantines.insert(id.clone(), quarantine);
        self.counters.legacy_items_quarantined = self.legacy_quarantines.len() as u64;
        Ok(id)
    }

    pub fn issue_sponsor_rebate(&mut self, rebate: SponsorFeeRebate) -> Result<String> {
        ensure!(
            rebate.rebate_bps <= self.config.max_sponsor_rebate_bps,
            "rebate {} exceeds configured bps cap",
            rebate.rebate_id
        );
        ensure!(
            rebate.rebate_micronero <= self.config.rebate_cap_micronero,
            "rebate {} exceeds configured amount cap",
            rebate.rebate_id
        );
        let id = rebate.rebate_id.clone();
        self.sponsor_rebates.insert(id.clone(), rebate);
        self.counters.sponsor_rebates_issued = self.sponsor_rebates.len() as u64;
        Ok(id)
    }

    pub fn grant_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<String> {
        ensure!(
            budget.units_granted <= self.config.redaction_budget_units,
            "budget {} exceeds configured grant",
            budget.budget_id
        );
        let id = budget.budget_id.clone();
        self.redaction_budgets.insert(id.clone(), budget);
        Ok(id)
    }

    pub fn spend_redaction_budget(&mut self, budget_id: &str, units: u64) -> Result<()> {
        let budget = self
            .redaction_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("missing redaction budget {budget_id}"))?;
        budget.spend(units)?;
        self.counters.privacy_redactions_spent += units;
        Ok(())
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let mut state = State::new(config.clone()).expect("valid devnet config");

    let committee = RecoveryCommittee {
        committee_id: "committee-devnet-mlkem-shard-recovery-0001".to_string(),
        epoch: DEVNET_EPOCH,
        status: CommitteeStatus::Active,
        member_commitment_root: fixture_root("committee-members", 7),
        role: CommitteeRole::ShardCustodian,
        member_count: config.min_committee_size,
        recovery_threshold: config.recovery_threshold,
        veto_threshold: config.veto_threshold,
        operator_quorum_bps: config.min_operator_quorum_bps,
        privacy_set_size: config.target_privacy_set_size,
        activated_at_l2_height: DEVNET_L2_HEIGHT,
        expires_at_l2_height: DEVNET_L2_HEIGHT + config.escrow_ttl_blocks,
    };
    state
        .register_committee(committee)
        .expect("valid devnet committee");

    let window = RotationWindow {
        window_id: "window-devnet-mlkem-shard-recovery-0001".to_string(),
        committee_id: "committee-devnet-mlkem-shard-recovery-0001".to_string(),
        prior_window_id: None,
        opens_at_l2_height: DEVNET_L2_HEIGHT,
        closes_at_l2_height: DEVNET_L2_HEIGHT + config.rotation_window_blocks,
        monero_anchor_height: DEVNET_MONERO_HEIGHT,
        rotated_session_root: fixture_root("rotated-session-set", 16),
        replacement_committee_root: fixture_root("replacement-committee", 7),
        privacy_floor: config.min_privacy_set_size,
    };
    state
        .open_rotation_window(window)
        .expect("valid devnet rotation window");

    let envelope = ShardEscrowEnvelope {
        envelope_id: "envelope-devnet-mlkem-shard-recovery-0001".to_string(),
        account_commitment: fixture_root("account-commitment", 1),
        session_commitment: fixture_root("session-key-commitment", 1),
        committee_id: "committee-devnet-mlkem-shard-recovery-0001".to_string(),
        rotation_window_id: "window-devnet-mlkem-shard-recovery-0001".to_string(),
        lane: RecoveryLane::PaymasterSponsoredSession,
        kem_parameter_set: MlKemParameterSet::MlKem1024,
        status: EnvelopeStatus::Escrowed,
        shard_count: config.min_committee_size,
        threshold: config.recovery_threshold,
        ciphertext_root: fixture_root("mlkem-ciphertext", 4),
        shard_commitment_root: fixture_root("shard-commitments", 7),
        view_tag_redaction_root: fixture_root("view-tag-redactions", 8),
        created_at_l2_height: DEVNET_L2_HEIGHT + 8,
        expires_at_l2_height: DEVNET_L2_HEIGHT + config.escrow_ttl_blocks,
    };
    state
        .escrow_shard_envelope(envelope)
        .expect("valid devnet envelope");

    let request = RecoveryRequest {
        request_id: "request-devnet-mlkem-shard-recovery-0001".to_string(),
        envelope_id: "envelope-devnet-mlkem-shard-recovery-0001".to_string(),
        requester_commitment: fixture_root("requester-commitment", 1),
        committee_id: "committee-devnet-mlkem-shard-recovery-0001".to_string(),
        opened_at_l2_height: DEVNET_L2_HEIGHT + 16,
        expires_at_l2_height: DEVNET_L2_HEIGHT + 16 + config.recovery_window_blocks,
        nullifier: fixture_root("recovery-nullifier", 1),
        recovery_transcript_root: fixture_root("recovery-transcript", 5),
        sponsor_id: Some("sponsor-devnet-recovery-fees-0001".to_string()),
    };
    state
        .open_recovery_request(request)
        .expect("valid devnet request");

    let attestation = ThresholdRecoveryAttestation {
        attestation_id: "attestation-devnet-mlkem-shard-recovery-0001".to_string(),
        request_id: "request-devnet-mlkem-shard-recovery-0001".to_string(),
        committee_id: "committee-devnet-mlkem-shard-recovery-0001".to_string(),
        signer_commitment_root: fixture_root("attesting-signers", 5),
        signature_root: fixture_root("threshold-signatures", 5),
        verdict: AttestationVerdict::ThresholdMet,
        signed_weight_bps: 7_200,
        threshold_met: true,
        attested_at_l2_height: DEVNET_L2_HEIGHT + 24,
        expires_at_l2_height: DEVNET_L2_HEIGHT + 24 + config.attestation_ttl_blocks,
    };
    state
        .accept_threshold_attestation(attestation)
        .expect("valid devnet attestation");

    let quarantine = LegacyQuarantine {
        quarantine_id: "quarantine-devnet-legacy-session-0001".to_string(),
        envelope_id: "envelope-devnet-mlkem-shard-recovery-0001".to_string(),
        reason: QuarantineReason::MissingRotationTranscript,
        legacy_ciphertext_root: fixture_root("legacy-session-ciphertext", 2),
        quarantine_until_l2_height: DEVNET_L2_HEIGHT + config.legacy_quarantine_blocks,
        operator_note_commitment: fixture_root("legacy-quarantine-note", 1),
    };
    state
        .quarantine_legacy(quarantine)
        .expect("valid devnet quarantine");

    let rebate = SponsorFeeRebate {
        rebate_id: "rebate-devnet-mlkem-shard-recovery-0001".to_string(),
        request_id: "request-devnet-mlkem-shard-recovery-0001".to_string(),
        sponsor_id: "sponsor-devnet-recovery-fees-0001".to_string(),
        recipient_commitment: fixture_root("rebate-recipient", 1),
        rebate_asset_id: config.rebate_asset_id.clone(),
        rebate_bps: 7_500,
        rebate_micronero: 120_000,
        issued_at_l2_height: DEVNET_L2_HEIGHT + 32,
    };
    state
        .issue_sponsor_rebate(rebate)
        .expect("valid devnet rebate");

    let budget = PrivacyRedactionBudget {
        budget_id: "budget-devnet-mlkem-shard-recovery-0001".to_string(),
        committee_id: "committee-devnet-mlkem-shard-recovery-0001".to_string(),
        units_granted: config.redaction_budget_units,
        units_spent: 0,
        epoch: DEVNET_EPOCH,
        disclosure_floor: "roots_only_no_plain_session_material".to_string(),
    };
    state
        .grant_redaction_budget(budget)
        .expect("valid devnet redaction budget");

    state.counters.deterministic_roots_published = 1;
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.spend_redaction_budget("budget-devnet-mlkem-shard-recovery-0001", 128);
    state
}

pub fn public_record(state: &State) -> Value {
    let roots = state.roots();
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "ml_kem_recovery_suite": ML_KEM_RECOVERY_SUITE,
        "shard_escrow_envelope_suite": SHARD_ESCROW_ENVELOPE_SUITE,
        "recovery_committee_suite": RECOVERY_COMMITTEE_SUITE,
        "threshold_attestation_suite": THRESHOLD_ATTESTATION_SUITE,
        "legacy_quarantine_suite": LEGACY_QUARANTINE_SUITE,
        "sponsor_rebate_suite": SPONSOR_REBATE_SUITE,
        "privacy_redaction_budget_suite": PRIVACY_REDACTION_BUDGET_SUITE,
        "public_record_suite": PUBLIC_RECORD_SUITE,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": roots.public_record(),
        "roots_root": roots.state_root(),
        "active_committee_id": state.active_committee_id,
        "committees": map_records(&state.committees, RecoveryCommittee::public_record),
        "rotation_windows": map_records(&state.rotation_windows, RotationWindow::public_record),
        "shard_envelopes": map_records(&state.shard_envelopes, ShardEscrowEnvelope::public_record),
        "recovery_requests": map_records(&state.recovery_requests, RecoveryRequest::public_record),
        "threshold_attestations": map_records(
            &state.threshold_attestations,
            ThresholdRecoveryAttestation::public_record
        ),
        "legacy_quarantines": map_records(&state.legacy_quarantines, LegacyQuarantine::public_record),
        "sponsor_rebates": map_records(&state.sponsor_rebates, SponsorFeeRebate::public_record),
        "redaction_budgets": map_records(
            &state.redaction_budgets,
            PrivacyRedactionBudget::public_record
        ),
        "used_nullifier_count": state.used_nullifiers.len(),
    })
}

pub fn state_root(state: &State) -> String {
    let record = json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "config_root": state.config.state_root(),
        "counters_root": state.counters.state_root(),
        "roots": state.roots().public_record(),
        "active_committee_id": state.active_committee_id,
    });
    runtime_root("ML-KEM-SHARD-RECOVERY-RUNTIME-STATE", &record)
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
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(id),
                    HashPart::Str(root.as_str()),
                ],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root<'a>(domain: &str, items: impl Iterator<Item = &'a str>) -> String {
    let leaves = items
        .map(|item| {
            Value::String(domain_hash(
                domain,
                &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(item)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T>(
    map: &BTreeMap<String, T>,
    record: impl Fn(&T) -> Value,
) -> BTreeMap<String, Value> {
    map.iter()
        .map(|(id, item)| (id.clone(), record(item)))
        .collect()
}

fn fixture_root(label: &str, count: u64) -> String {
    let leaves = (0..count)
        .map(|index| {
            Value::String(domain_hash(
                "ML-KEM-SHARD-RECOVERY-DEVNET-FIXTURE",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(label),
                    HashPart::U64(index),
                ],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}
