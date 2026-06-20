use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroWatchtowerSlashingResult<T> = Result<T, String>;

pub const MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION: &str =
    "nebula-monero-watchtower-slashing-v1";
pub const MONERO_WATCHTOWER_SLASHING_SCHEMA_VERSION: u64 = 1;
pub const MONERO_WATCHTOWER_SLASHING_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_WATCHTOWER_SLASHING_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_WATCHTOWER_SLASHING_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const MONERO_WATCHTOWER_SLASHING_PQ_IDENTITY_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-watchtower-identity-root";
pub const MONERO_WATCHTOWER_SLASHING_SIGNATURE_ROOT_SCHEME: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-transcript-root";
pub const MONERO_WATCHTOWER_SLASHING_ENVELOPE_SCHEME: &str =
    "ML-KEM-768+XChaCha20-Poly1305-private-whistleblower-envelope";
pub const MONERO_WATCHTOWER_SLASHING_PUBLIC_RECORD_SCHEMA: &str =
    "monero-watchtower-slashing-public-record-v1";
pub const MONERO_WATCHTOWER_SLASHING_MAX_BPS: u64 = 10_000;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_WATCHER_BOND_UNITS: u64 = 1_000_000;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_MIN_QUORUM_WEIGHT: u64 = 2;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_APPEAL_WINDOW_BLOCKS: u64 = 72;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_EVIDENCE_TTL_BLOCKS: u64 = 720;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_REORG_REPORT_WINDOW_BLOCKS: u64 = 18;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_DELAYED_EXIT_SLA_BLOCKS: u64 = 24;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_SPONSOR_CREDIT_UNITS: u64 = 100_000;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_MIN_PRIVACY_SCORE_BPS: u64 = 9_500;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_REWARD_BPS: u64 = 2_000;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_RESERVE_FALSE_BPS: u64 = 5_000;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_REORG_WITHHOLD_BPS: u64 = 2_500;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_ENDPOINT_EQUIVOCATION_BPS: u64 = 4_000;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_EXIT_DELAY_BPS: u64 = 1_500;
pub const MONERO_WATCHTOWER_SLASHING_DEFAULT_PRIVATE_EVIDENCE_BPS: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherRole {
    BridgeObserver,
    ReserveAuditor,
    ReorgReporter,
    EndpointSentinel,
    ExitGuardian,
    FeeSponsor,
    PrivacyWhistleblower,
}

impl WatcherRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeObserver => "bridge_observer",
            Self::ReserveAuditor => "reserve_auditor",
            Self::ReorgReporter => "reorg_reporter",
            Self::EndpointSentinel => "endpoint_sentinel",
            Self::ExitGuardian => "exit_guardian",
            Self::FeeSponsor => "fee_sponsor",
            Self::PrivacyWhistleblower => "privacy_whistleblower",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherStatus {
    Active,
    Standby,
    Probation,
    Suspended,
    Slashed,
    Retired,
}

impl WatcherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Probation => "probation",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_submit(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::Probation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAttestationStatus {
    Pending,
    Accepted,
    Disputed,
    Superseded,
    Expired,
    Slashed,
}

impl ReserveAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Disputed => "disputed",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Pending | Self::Accepted | Self::Disputed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgReportStatus {
    Filed,
    QuorumConfirmed,
    Disputed,
    Resolved,
    FalseAlarm,
    Expired,
}

impl ReorgReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::QuorumConfirmed => "quorum_confirmed",
            Self::Disputed => "disputed",
            Self::Resolved => "resolved",
            Self::FalseAlarm => "false_alarm",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Filed | Self::QuorumConfirmed | Self::Disputed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointEquivocationKind {
    ConflictingHeight,
    ConflictingReserveView,
    WithheldMempool,
    EndpointCensorship,
    ForkChoiceFlip,
    InvalidFeeQuote,
}

impl EndpointEquivocationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConflictingHeight => "conflicting_height",
            Self::ConflictingReserveView => "conflicting_reserve_view",
            Self::WithheldMempool => "withheld_mempool",
            Self::EndpointCensorship => "endpoint_censorship",
            Self::ForkChoiceFlip => "fork_choice_flip",
            Self::InvalidFeeQuote => "invalid_fee_quote",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivocationStatus {
    Open,
    Matched,
    Challenged,
    Sustained,
    Dismissed,
    Expired,
}

impl EquivocationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Challenged => "challenged",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitGuaranteeStatus {
    Promised,
    Observing,
    Delayed,
    Released,
    Challenged,
    Breached,
    Expired,
}

impl ExitGuaranteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Promised => "promised",
            Self::Observing => "observing",
            Self::Delayed => "delayed",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Breached => "breached",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Promised | Self::Observing | Self::Delayed | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    ReserveFalseStatement,
    ReserveOmission,
    ReorgWithheld,
    ReorgFalseReport,
    EndpointEquivocation,
    DelayedExit,
    LowFeeChallenge,
    PrivateWhistleblower,
    PqSignatureConflict,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveFalseStatement => "reserve_false_statement",
            Self::ReserveOmission => "reserve_omission",
            Self::ReorgWithheld => "reorg_withheld",
            Self::ReorgFalseReport => "reorg_false_report",
            Self::EndpointEquivocation => "endpoint_equivocation",
            Self::DelayedExit => "delayed_exit",
            Self::LowFeeChallenge => "low_fee_challenge",
            Self::PrivateWhistleblower => "private_whistleblower",
            Self::PqSignatureConflict => "pq_signature_conflict",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateWhistleblower
                | Self::ReserveFalseStatement
                | Self::DelayedExit
                | Self::PqSignatureConflict
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceEnvelopeStatus {
    Sealed,
    Escrowed,
    RevealedToCouncil,
    PublicDigestPublished,
    Quarantined,
    Expired,
}

impl EvidenceEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Escrowed => "escrowed",
            Self::RevealedToCouncil => "revealed_to_council",
            Self::PublicDigestPublished => "public_digest_published",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Escrowed | Self::RevealedToCouncil | Self::PublicDigestPublished
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeTicketKind {
    ReserveMismatch,
    ReorgDeadline,
    EndpointEquivocation,
    ExitDelay,
    LowFeeSponsored,
    PrivateWhistleblowerReveal,
}

impl ChallengeTicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReserveMismatch => "reserve_mismatch",
            Self::ReorgDeadline => "reorg_deadline",
            Self::EndpointEquivocation => "endpoint_equivocation",
            Self::ExitDelay => "exit_delay",
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::PrivateWhistleblowerReveal => "private_whistleblower_reveal",
        }
    }

    pub fn sponsor_eligible(self) -> bool {
        matches!(
            self,
            Self::ReserveMismatch
                | Self::ReorgDeadline
                | Self::EndpointEquivocation
                | Self::ExitDelay
                | Self::LowFeeSponsored
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeTicketStatus {
    Draft,
    Open,
    Sponsored,
    Accepted,
    Rejected,
    Settled,
    Expired,
}

impl ChallengeTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Sponsored => "sponsored",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Sponsored | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    FalseReserveAttestation,
    MissingReserveAttestation,
    ReorgReportSuppressed,
    FalseReorgReport,
    EndpointEquivocation,
    DelayedExitBreach,
    LowFeeChallengeGriefing,
    PrivateEvidenceSuppression,
    PqIdentityEquivocation,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FalseReserveAttestation => "false_reserve_attestation",
            Self::MissingReserveAttestation => "missing_reserve_attestation",
            Self::ReorgReportSuppressed => "reorg_report_suppressed",
            Self::FalseReorgReport => "false_reorg_report",
            Self::EndpointEquivocation => "endpoint_equivocation",
            Self::DelayedExitBreach => "delayed_exit_breach",
            Self::LowFeeChallengeGriefing => "low_fee_challenge_griefing",
            Self::PrivateEvidenceSuppression => "private_evidence_suppression",
            Self::PqIdentityEquivocation => "pq_identity_equivocation",
        }
    }

    pub fn default_slash_bps(self) -> u64 {
        match self {
            Self::FalseReserveAttestation => MONERO_WATCHTOWER_SLASHING_DEFAULT_RESERVE_FALSE_BPS,
            Self::MissingReserveAttestation => 1_500,
            Self::ReorgReportSuppressed => MONERO_WATCHTOWER_SLASHING_DEFAULT_REORG_WITHHOLD_BPS,
            Self::FalseReorgReport => 2_000,
            Self::EndpointEquivocation => {
                MONERO_WATCHTOWER_SLASHING_DEFAULT_ENDPOINT_EQUIVOCATION_BPS
            }
            Self::DelayedExitBreach => MONERO_WATCHTOWER_SLASHING_DEFAULT_EXIT_DELAY_BPS,
            Self::LowFeeChallengeGriefing => 1_000,
            Self::PrivateEvidenceSuppression => {
                MONERO_WATCHTOWER_SLASHING_DEFAULT_PRIVATE_EVIDENCE_BPS
            }
            Self::PqIdentityEquivocation => 7_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingActionStatus {
    Proposed,
    EvidenceLocked,
    AppealOpen,
    Executable,
    Executed,
    Rejected,
    Reversed,
    Expired,
}

impl SlashingActionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::EvidenceLocked => "evidence_locked",
            Self::AppealOpen => "appeal_open",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Reversed => "reversed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::EvidenceLocked | Self::AppealOpen | Self::Executable
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStatus {
    Open,
    EvidenceRequested,
    CouncilReview,
    Accepted,
    Rejected,
    Expired,
}

impl AppealStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceRequested => "evidence_requested",
            Self::CouncilReview => "council_review",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::EvidenceRequested | Self::CouncilReview
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardStatus {
    Pending,
    Claimable,
    Claimed,
    RedirectedToSponsor,
    Revoked,
}

impl RewardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::RedirectedToSponsor => "redirected_to_sponsor",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCreditStatus {
    Active,
    Reserved,
    Spent,
    Exhausted,
    Refunded,
    Expired,
}

impl SponsorCreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Exhausted => "exhausted",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    WatcherRegistered,
    ReserveAttestation,
    ReorgReport,
    EndpointEquivocation,
    DelayedExitGuarantee,
    EvidenceDigest,
    ChallengeTicket,
    SlashingAction,
    AppealWindow,
    RewardReceipt,
    SponsorCredit,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatcherRegistered => "watcher_registered",
            Self::ReserveAttestation => "reserve_attestation",
            Self::ReorgReport => "reorg_report",
            Self::EndpointEquivocation => "endpoint_equivocation",
            Self::DelayedExitGuarantee => "delayed_exit_guarantee",
            Self::EvidenceDigest => "evidence_digest",
            Self::ChallengeTicket => "challenge_ticket",
            Self::SlashingAction => "slashing_action",
            Self::AppealWindow => "appeal_window",
            Self::RewardReceipt => "reward_receipt",
            Self::SponsorCredit => "sponsor_credit",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerSlashingConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub pq_identity_scheme: String,
    pub pq_signature_root_scheme: String,
    pub evidence_envelope_scheme: String,
    pub watcher_bond_units: u64,
    pub min_quorum_weight: u64,
    pub appeal_window_blocks: u64,
    pub evidence_ttl_blocks: u64,
    pub reorg_report_window_blocks: u64,
    pub delayed_exit_sla_blocks: u64,
    pub sponsor_min_credit_units: u64,
    pub min_privacy_score_bps: u64,
    pub whistleblower_reward_bps: u64,
}

impl Default for MoneroWatchtowerSlashingConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl MoneroWatchtowerSlashingConfig {
    pub fn devnet() -> Self {
        let config_id = monero_watchtower_slashing_config_id(
            MONERO_WATCHTOWER_SLASHING_DEVNET_NETWORK,
            MONERO_WATCHTOWER_SLASHING_DEVNET_ASSET_ID,
            MONERO_WATCHTOWER_SLASHING_DEVNET_FEE_ASSET_ID,
        );
        Self {
            config_id,
            protocol_version: MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_WATCHTOWER_SLASHING_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_WATCHTOWER_SLASHING_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_WATCHTOWER_SLASHING_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_WATCHTOWER_SLASHING_DEVNET_FEE_ASSET_ID.to_string(),
            pq_identity_scheme: MONERO_WATCHTOWER_SLASHING_PQ_IDENTITY_SCHEME.to_string(),
            pq_signature_root_scheme: MONERO_WATCHTOWER_SLASHING_SIGNATURE_ROOT_SCHEME.to_string(),
            evidence_envelope_scheme: MONERO_WATCHTOWER_SLASHING_ENVELOPE_SCHEME.to_string(),
            watcher_bond_units: MONERO_WATCHTOWER_SLASHING_DEFAULT_WATCHER_BOND_UNITS,
            min_quorum_weight: MONERO_WATCHTOWER_SLASHING_DEFAULT_MIN_QUORUM_WEIGHT,
            appeal_window_blocks: MONERO_WATCHTOWER_SLASHING_DEFAULT_APPEAL_WINDOW_BLOCKS,
            evidence_ttl_blocks: MONERO_WATCHTOWER_SLASHING_DEFAULT_EVIDENCE_TTL_BLOCKS,
            reorg_report_window_blocks:
                MONERO_WATCHTOWER_SLASHING_DEFAULT_REORG_REPORT_WINDOW_BLOCKS,
            delayed_exit_sla_blocks: MONERO_WATCHTOWER_SLASHING_DEFAULT_DELAYED_EXIT_SLA_BLOCKS,
            sponsor_min_credit_units: MONERO_WATCHTOWER_SLASHING_DEFAULT_SPONSOR_CREDIT_UNITS,
            min_privacy_score_bps: MONERO_WATCHTOWER_SLASHING_DEFAULT_MIN_PRIVACY_SCORE_BPS,
            whistleblower_reward_bps: MONERO_WATCHTOWER_SLASHING_DEFAULT_REWARD_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_watchtower_slashing_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "config_id": self.config_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "pq_identity_scheme": self.pq_identity_scheme,
            "pq_signature_root_scheme": self.pq_signature_root_scheme,
            "evidence_envelope_scheme": self.evidence_envelope_scheme,
            "watcher_bond_units": self.watcher_bond_units,
            "min_quorum_weight": self.min_quorum_weight,
            "appeal_window_blocks": self.appeal_window_blocks,
            "evidence_ttl_blocks": self.evidence_ttl_blocks,
            "reorg_report_window_blocks": self.reorg_report_window_blocks,
            "delayed_exit_sla_blocks": self.delayed_exit_sla_blocks,
            "sponsor_min_credit_units": self.sponsor_min_credit_units,
            "min_privacy_score_bps": self.min_privacy_score_bps,
            "whistleblower_reward_bps": self.whistleblower_reward_bps,
            "config_root": self.config_root(),
        })
    }

    pub fn config_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-CONFIG",
            &json!({
                "config_id": self.config_id,
                "protocol_version": self.protocol_version,
                "schema_version": self.schema_version,
                "chain_id": self.chain_id,
                "monero_network": self.monero_network,
                "asset_id": self.asset_id,
                "fee_asset_id": self.fee_asset_id,
                "watcher_bond_units": self.watcher_bond_units,
                "min_quorum_weight": self.min_quorum_weight,
                "appeal_window_blocks": self.appeal_window_blocks,
                "evidence_ttl_blocks": self.evidence_ttl_blocks,
            }),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.config_id, "slashing config id")?;
        ensure_non_empty(&self.protocol_version, "slashing protocol version")?;
        ensure_non_empty(&self.chain_id, "slashing chain id")?;
        ensure_non_empty(&self.monero_network, "slashing monero network")?;
        ensure_non_empty(&self.asset_id, "slashing asset id")?;
        ensure_non_empty(&self.fee_asset_id, "slashing fee asset id")?;
        ensure_non_empty(&self.pq_identity_scheme, "slashing pq identity scheme")?;
        ensure_non_empty(
            &self.pq_signature_root_scheme,
            "slashing pq signature root scheme",
        )?;
        ensure_non_empty(
            &self.evidence_envelope_scheme,
            "slashing evidence envelope scheme",
        )?;
        if self.protocol_version != MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION {
            return Err("slashing protocol version mismatch".to_string());
        }
        ensure_positive(self.schema_version, "slashing schema version")?;
        ensure_positive(self.watcher_bond_units, "watcher bond units")?;
        ensure_positive(self.min_quorum_weight, "min quorum weight")?;
        ensure_positive(self.appeal_window_blocks, "appeal window blocks")?;
        ensure_positive(self.evidence_ttl_blocks, "evidence ttl blocks")?;
        ensure_positive(
            self.reorg_report_window_blocks,
            "reorg report window blocks",
        )?;
        ensure_positive(self.delayed_exit_sla_blocks, "delayed exit sla blocks")?;
        ensure_positive(self.sponsor_min_credit_units, "sponsor min credit units")?;
        ensure_bps(self.min_privacy_score_bps, "min privacy score bps")?;
        ensure_bps(self.whistleblower_reward_bps, "whistleblower reward bps")?;
        if self.appeal_window_blocks > self.evidence_ttl_blocks {
            return Err("appeal window must fit inside evidence ttl".to_string());
        }
        let expected = monero_watchtower_slashing_config_id(
            &self.monero_network,
            &self.asset_id,
            &self.fee_asset_id,
        );
        if self.config_id != expected {
            return Err("slashing config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatcherIdentity {
    pub watcher_id: String,
    pub operator_commitment: String,
    pub role: WatcherRole,
    pub monero_network: String,
    pub pq_public_key_root: String,
    pub backup_public_key_root: String,
    pub signature_root: String,
    pub bond_commitment_root: String,
    pub endpoint_commitment_root: String,
    pub quorum_weight: u64,
    pub privacy_score_bps: u64,
    pub registered_at_height: u64,
    pub status: WatcherStatus,
}

impl PqWatcherIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_commitment: impl Into<String>,
        role: WatcherRole,
        monero_network: impl Into<String>,
        pq_public_key_root: impl Into<String>,
        backup_public_key_root: impl Into<String>,
        signature_root: impl Into<String>,
        bond_commitment_root: impl Into<String>,
        endpoint_commitment_root: impl Into<String>,
        quorum_weight: u64,
        privacy_score_bps: u64,
        registered_at_height: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let operator_commitment = operator_commitment.into();
        let monero_network = monero_network.into();
        let pq_public_key_root = pq_public_key_root.into();
        let backup_public_key_root = backup_public_key_root.into();
        let signature_root = signature_root.into();
        let bond_commitment_root = bond_commitment_root.into();
        let endpoint_commitment_root = endpoint_commitment_root.into();
        let watcher_id = monero_watchtower_slashing_watcher_id(
            &operator_commitment,
            role,
            &monero_network,
            &pq_public_key_root,
            &endpoint_commitment_root,
        );
        let watcher = Self {
            watcher_id,
            operator_commitment,
            role,
            monero_network,
            pq_public_key_root,
            backup_public_key_root,
            signature_root,
            bond_commitment_root,
            endpoint_commitment_root,
            quorum_weight,
            privacy_score_bps,
            registered_at_height,
            status: WatcherStatus::Active,
        };
        watcher.validate()?;
        Ok(watcher)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "pq_watcher_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "watcher_id": self.watcher_id,
            "operator_commitment": self.operator_commitment,
            "role": self.role.as_str(),
            "monero_network": self.monero_network,
            "pq_public_key_root": self.pq_public_key_root,
            "backup_public_key_root": self.backup_public_key_root,
            "signature_root": self.signature_root,
            "bond_commitment_root": self.bond_commitment_root,
            "endpoint_commitment_root": self.endpoint_commitment_root,
            "quorum_weight": self.quorum_weight,
            "privacy_score_bps": self.privacy_score_bps,
            "registered_at_height": self.registered_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn identity_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-WATCHER",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "identity_root",
            self.identity_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.watcher_id, "watcher id")?;
        ensure_non_empty(&self.operator_commitment, "watcher operator commitment")?;
        ensure_non_empty(&self.monero_network, "watcher monero network")?;
        ensure_non_empty(&self.pq_public_key_root, "watcher pq public key root")?;
        ensure_non_empty(
            &self.backup_public_key_root,
            "watcher backup public key root",
        )?;
        ensure_non_empty(&self.signature_root, "watcher signature root")?;
        ensure_non_empty(&self.bond_commitment_root, "watcher bond commitment root")?;
        ensure_non_empty(
            &self.endpoint_commitment_root,
            "watcher endpoint commitment root",
        )?;
        ensure_positive(self.quorum_weight, "watcher quorum weight")?;
        ensure_bps(self.privacy_score_bps, "watcher privacy score bps")?;
        let expected = monero_watchtower_slashing_watcher_id(
            &self.operator_commitment,
            self.role,
            &self.monero_network,
            &self.pq_public_key_root,
            &self.endpoint_commitment_root,
        );
        if self.watcher_id != expected {
            return Err("watcher id mismatch".to_string());
        }
        Ok(self.identity_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub reserve_epoch_id: String,
    pub reserve_address_set_root: String,
    pub reserve_output_commitment_root: String,
    pub minted_supply_units: u64,
    pub locked_reserve_units: u64,
    pub pending_exit_units: u64,
    pub observed_monero_height: u64,
    pub statement_root: String,
    pub pq_signature_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReserveAttestationStatus,
}

impl ReserveAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watcher_id: impl Into<String>,
        reserve_epoch_id: impl Into<String>,
        reserve_address_set_root: impl Into<String>,
        reserve_output_commitment_root: impl Into<String>,
        minted_supply_units: u64,
        locked_reserve_units: u64,
        pending_exit_units: u64,
        observed_monero_height: u64,
        statement_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        submitted_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let watcher_id = watcher_id.into();
        let reserve_epoch_id = reserve_epoch_id.into();
        let reserve_address_set_root = reserve_address_set_root.into();
        let reserve_output_commitment_root = reserve_output_commitment_root.into();
        let statement_root = statement_root.into();
        let pq_signature_root = pq_signature_root.into();
        let expires_at_height = submitted_at_height.saturating_add(ttl_blocks);
        let attestation_id = monero_watchtower_slashing_reserve_attestation_id(
            &watcher_id,
            &reserve_epoch_id,
            &reserve_output_commitment_root,
            observed_monero_height,
            &statement_root,
        );
        let attestation = Self {
            attestation_id,
            watcher_id,
            reserve_epoch_id,
            reserve_address_set_root,
            reserve_output_commitment_root,
            minted_supply_units,
            locked_reserve_units,
            pending_exit_units,
            observed_monero_height,
            statement_root,
            pq_signature_root,
            submitted_at_height,
            expires_at_height,
            status: ReserveAttestationStatus::Pending,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn coverage_bps(&self) -> u64 {
        ratio_bps(
            self.locked_reserve_units
                .saturating_sub(self.pending_exit_units),
            self.minted_supply_units,
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.open() && height > self.expires_at_height {
            self.status = ReserveAttestationStatus::Expired;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "reserve_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "reserve_epoch_id": self.reserve_epoch_id,
            "reserve_address_set_root": self.reserve_address_set_root,
            "reserve_output_commitment_root": self.reserve_output_commitment_root,
            "minted_supply_units": self.minted_supply_units,
            "locked_reserve_units": self.locked_reserve_units,
            "pending_exit_units": self.pending_exit_units,
            "coverage_bps": self.coverage_bps(),
            "observed_monero_height": self.observed_monero_height,
            "statement_root": self.statement_root,
            "pq_signature_root": self.pq_signature_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-RESERVE-ATTESTATION",
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

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.attestation_id, "reserve attestation id")?;
        ensure_non_empty(&self.watcher_id, "reserve attestation watcher id")?;
        ensure_non_empty(&self.reserve_epoch_id, "reserve epoch id")?;
        ensure_non_empty(&self.reserve_address_set_root, "reserve address set root")?;
        ensure_non_empty(
            &self.reserve_output_commitment_root,
            "reserve output commitment root",
        )?;
        ensure_non_empty(&self.statement_root, "reserve statement root")?;
        ensure_non_empty(&self.pq_signature_root, "reserve pq signature root")?;
        if self.pending_exit_units > self.locked_reserve_units {
            return Err("reserve pending exit exceeds locked reserve".to_string());
        }
        if self.expires_at_height < self.submitted_at_height {
            return Err("reserve attestation expiry precedes submission".to_string());
        }
        let expected = monero_watchtower_slashing_reserve_attestation_id(
            &self.watcher_id,
            &self.reserve_epoch_id,
            &self.reserve_output_commitment_root,
            self.observed_monero_height,
            &self.statement_root,
        );
        if self.attestation_id != expected {
            return Err("reserve attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgReport {
    pub report_id: String,
    pub reporter_watcher_id: String,
    pub monero_network: String,
    pub fork_height: u64,
    pub canonical_block_hash: String,
    pub competing_block_hash: String,
    pub observed_depth: u64,
    pub daemon_endpoint_root: String,
    pub evidence_root: String,
    pub pq_signature_root: String,
    pub filed_at_height: u64,
    pub response_deadline_height: u64,
    pub status: ReorgReportStatus,
}

impl ReorgReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reporter_watcher_id: impl Into<String>,
        monero_network: impl Into<String>,
        fork_height: u64,
        canonical_block_hash: impl Into<String>,
        competing_block_hash: impl Into<String>,
        observed_depth: u64,
        daemon_endpoint_root: impl Into<String>,
        evidence_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        filed_at_height: u64,
        report_window_blocks: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let reporter_watcher_id = reporter_watcher_id.into();
        let monero_network = monero_network.into();
        let canonical_block_hash = canonical_block_hash.into();
        let competing_block_hash = competing_block_hash.into();
        let daemon_endpoint_root = daemon_endpoint_root.into();
        let evidence_root = evidence_root.into();
        let pq_signature_root = pq_signature_root.into();
        let response_deadline_height = filed_at_height.saturating_add(report_window_blocks);
        let report_id = monero_watchtower_slashing_reorg_report_id(
            &reporter_watcher_id,
            &monero_network,
            fork_height,
            &canonical_block_hash,
            &competing_block_hash,
            &evidence_root,
        );
        let report = Self {
            report_id,
            reporter_watcher_id,
            monero_network,
            fork_height,
            canonical_block_hash,
            competing_block_hash,
            observed_depth,
            daemon_endpoint_root,
            evidence_root,
            pq_signature_root,
            filed_at_height,
            response_deadline_height,
            status: ReorgReportStatus::Filed,
        };
        report.validate()?;
        Ok(report)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.response_deadline_height {
            self.status = ReorgReportStatus::Expired;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "reorg_report",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "report_id": self.report_id,
            "reporter_watcher_id": self.reporter_watcher_id,
            "monero_network": self.monero_network,
            "fork_height": self.fork_height,
            "canonical_block_hash": self.canonical_block_hash,
            "competing_block_hash": self.competing_block_hash,
            "observed_depth": self.observed_depth,
            "daemon_endpoint_root": self.daemon_endpoint_root,
            "evidence_root": self.evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "filed_at_height": self.filed_at_height,
            "response_deadline_height": self.response_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn report_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-REORG-REPORT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "report_root",
            self.report_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.report_id, "reorg report id")?;
        ensure_non_empty(&self.reporter_watcher_id, "reorg reporter watcher id")?;
        ensure_non_empty(&self.monero_network, "reorg monero network")?;
        ensure_non_empty(&self.canonical_block_hash, "canonical block hash")?;
        ensure_non_empty(&self.competing_block_hash, "competing block hash")?;
        ensure_non_empty(&self.daemon_endpoint_root, "daemon endpoint root")?;
        ensure_non_empty(&self.evidence_root, "reorg evidence root")?;
        ensure_non_empty(&self.pq_signature_root, "reorg pq signature root")?;
        ensure_positive(self.observed_depth, "reorg observed depth")?;
        if self.canonical_block_hash == self.competing_block_hash {
            return Err("reorg report requires conflicting block hashes".to_string());
        }
        if self.response_deadline_height < self.filed_at_height {
            return Err("reorg response deadline precedes filing".to_string());
        }
        let expected = monero_watchtower_slashing_reorg_report_id(
            &self.reporter_watcher_id,
            &self.monero_network,
            self.fork_height,
            &self.canonical_block_hash,
            &self.competing_block_hash,
            &self.evidence_root,
        );
        if self.report_id != expected {
            return Err("reorg report id mismatch".to_string());
        }
        Ok(self.report_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEquivocation {
    pub equivocation_id: String,
    pub watcher_id: String,
    pub accused_endpoint_root: String,
    pub kind: EndpointEquivocationKind,
    pub first_statement_root: String,
    pub second_statement_root: String,
    pub first_signature_root: String,
    pub second_signature_root: String,
    pub observed_at_height: u64,
    pub status: EquivocationStatus,
}

impl EndpointEquivocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watcher_id: impl Into<String>,
        accused_endpoint_root: impl Into<String>,
        kind: EndpointEquivocationKind,
        first_statement_root: impl Into<String>,
        second_statement_root: impl Into<String>,
        first_signature_root: impl Into<String>,
        second_signature_root: impl Into<String>,
        observed_at_height: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let watcher_id = watcher_id.into();
        let accused_endpoint_root = accused_endpoint_root.into();
        let first_statement_root = first_statement_root.into();
        let second_statement_root = second_statement_root.into();
        let first_signature_root = first_signature_root.into();
        let second_signature_root = second_signature_root.into();
        let equivocation_id = monero_watchtower_slashing_endpoint_equivocation_id(
            &watcher_id,
            &accused_endpoint_root,
            kind,
            &first_statement_root,
            &second_statement_root,
            observed_at_height,
        );
        let equivocation = Self {
            equivocation_id,
            watcher_id,
            accused_endpoint_root,
            kind,
            first_statement_root,
            second_statement_root,
            first_signature_root,
            second_signature_root,
            observed_at_height,
            status: EquivocationStatus::Open,
        };
        equivocation.validate()?;
        Ok(equivocation)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "endpoint_equivocation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "equivocation_id": self.equivocation_id,
            "watcher_id": self.watcher_id,
            "accused_endpoint_root": self.accused_endpoint_root,
            "equivocation_kind": self.kind.as_str(),
            "first_statement_root": self.first_statement_root,
            "second_statement_root": self.second_statement_root,
            "first_signature_root": self.first_signature_root,
            "second_signature_root": self.second_signature_root,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn equivocation_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-ENDPOINT-EQUIVOCATION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "equivocation_root",
            self.equivocation_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.equivocation_id, "equivocation id")?;
        ensure_non_empty(&self.watcher_id, "equivocation watcher id")?;
        ensure_non_empty(
            &self.accused_endpoint_root,
            "equivocation accused endpoint root",
        )?;
        ensure_non_empty(&self.first_statement_root, "first statement root")?;
        ensure_non_empty(&self.second_statement_root, "second statement root")?;
        ensure_non_empty(&self.first_signature_root, "first signature root")?;
        ensure_non_empty(&self.second_signature_root, "second signature root")?;
        if self.first_statement_root == self.second_statement_root {
            return Err("endpoint equivocation needs two distinct statements".to_string());
        }
        let expected = monero_watchtower_slashing_endpoint_equivocation_id(
            &self.watcher_id,
            &self.accused_endpoint_root,
            self.kind,
            &self.first_statement_root,
            &self.second_statement_root,
            self.observed_at_height,
        );
        if self.equivocation_id != expected {
            return Err("endpoint equivocation id mismatch".to_string());
        }
        Ok(self.equivocation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedExitGuarantee {
    pub guarantee_id: String,
    pub watcher_id: String,
    pub exit_id: String,
    pub beneficiary_commitment: String,
    pub amount_bucket_units: u64,
    pub promised_release_height: u64,
    pub grace_deadline_height: u64,
    pub release_tx_commitment: Option<String>,
    pub privacy_receipt_root: String,
    pub status: ExitGuaranteeStatus,
}

impl DelayedExitGuarantee {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watcher_id: impl Into<String>,
        exit_id: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        amount_bucket_units: u64,
        promised_release_height: u64,
        sla_blocks: u64,
        privacy_receipt_root: impl Into<String>,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let watcher_id = watcher_id.into();
        let exit_id = exit_id.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        let privacy_receipt_root = privacy_receipt_root.into();
        let grace_deadline_height = promised_release_height.saturating_add(sla_blocks);
        let guarantee_id = monero_watchtower_slashing_delayed_exit_guarantee_id(
            &watcher_id,
            &exit_id,
            &beneficiary_commitment,
            amount_bucket_units,
            promised_release_height,
        );
        let guarantee = Self {
            guarantee_id,
            watcher_id,
            exit_id,
            beneficiary_commitment,
            amount_bucket_units,
            promised_release_height,
            grace_deadline_height,
            release_tx_commitment: None,
            privacy_receipt_root,
            status: ExitGuaranteeStatus::Promised,
        };
        guarantee.validate()?;
        Ok(guarantee)
    }

    pub fn mark_released(
        &mut self,
        release_tx_commitment: impl Into<String>,
    ) -> MoneroWatchtowerSlashingResult<String> {
        let release_tx_commitment = release_tx_commitment.into();
        ensure_non_empty(&release_tx_commitment, "release tx commitment")?;
        self.release_tx_commitment = Some(release_tx_commitment);
        self.status = ExitGuaranteeStatus::Released;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.grace_deadline_height {
            self.status = ExitGuaranteeStatus::Breached;
        } else if matches!(self.status, ExitGuaranteeStatus::Promised)
            && height >= self.promised_release_height
        {
            self.status = ExitGuaranteeStatus::Observing;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "delayed_exit_guarantee",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "guarantee_id": self.guarantee_id,
            "watcher_id": self.watcher_id,
            "exit_id": self.exit_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "amount_bucket_units": self.amount_bucket_units,
            "promised_release_height": self.promised_release_height,
            "grace_deadline_height": self.grace_deadline_height,
            "release_tx_commitment": self.release_tx_commitment,
            "privacy_receipt_root": self.privacy_receipt_root,
            "status": self.status.as_str(),
        })
    }

    pub fn guarantee_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-DELAYED-EXIT-GUARANTEE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "guarantee_root",
            self.guarantee_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.guarantee_id, "delayed exit guarantee id")?;
        ensure_non_empty(&self.watcher_id, "delayed exit watcher id")?;
        ensure_non_empty(&self.exit_id, "delayed exit id")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "delayed exit beneficiary commitment",
        )?;
        ensure_positive(self.amount_bucket_units, "delayed exit amount bucket")?;
        ensure_non_empty(&self.privacy_receipt_root, "privacy receipt root")?;
        if self.grace_deadline_height < self.promised_release_height {
            return Err("delayed exit grace deadline precedes promise".to_string());
        }
        if let Some(release_tx_commitment) = &self.release_tx_commitment {
            ensure_non_empty(release_tx_commitment, "release tx commitment")?;
        }
        let expected = monero_watchtower_slashing_delayed_exit_guarantee_id(
            &self.watcher_id,
            &self.exit_id,
            &self.beneficiary_commitment,
            self.amount_bucket_units,
            self.promised_release_height,
        );
        if self.guarantee_id != expected {
            return Err("delayed exit guarantee id mismatch".to_string());
        }
        Ok(self.guarantee_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEvidenceEnvelope {
    pub envelope_id: String,
    pub evidence_kind: EvidenceKind,
    pub reporter_watcher_id: String,
    pub accused_watcher_id: Option<String>,
    pub subject_id: String,
    pub sealed_payload_root: String,
    pub ciphertext_root: String,
    pub decryption_policy_root: String,
    pub nullifier: String,
    pub privacy_score_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: EvidenceEnvelopeStatus,
}

impl EncryptedEvidenceEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: EvidenceKind,
        reporter_watcher_id: impl Into<String>,
        accused_watcher_id: Option<String>,
        subject_id: impl Into<String>,
        sealed_payload_root: impl Into<String>,
        ciphertext_root: impl Into<String>,
        decryption_policy_root: impl Into<String>,
        privacy_score_bps: u64,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let reporter_watcher_id = reporter_watcher_id.into();
        let subject_id = subject_id.into();
        let sealed_payload_root = sealed_payload_root.into();
        let ciphertext_root = ciphertext_root.into();
        let decryption_policy_root = decryption_policy_root.into();
        let nullifier = monero_watchtower_slashing_evidence_nullifier(
            &reporter_watcher_id,
            &subject_id,
            &sealed_payload_root,
        );
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let envelope_id = monero_watchtower_slashing_evidence_envelope_id(
            evidence_kind,
            &reporter_watcher_id,
            accused_watcher_id.as_deref(),
            &subject_id,
            &ciphertext_root,
            created_at_height,
        );
        let envelope = Self {
            envelope_id,
            evidence_kind,
            reporter_watcher_id,
            accused_watcher_id,
            subject_id,
            sealed_payload_root,
            ciphertext_root,
            decryption_policy_root,
            nullifier,
            privacy_score_bps,
            created_at_height,
            expires_at_height,
            status: EvidenceEnvelopeStatus::Sealed,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.usable() && height > self.expires_at_height {
            self.status = EvidenceEnvelopeStatus::Expired;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "encrypted_evidence_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "reporter_watcher_id": self.reporter_watcher_id,
            "accused_watcher_id": self.accused_watcher_id,
            "subject_id": self.subject_id,
            "sealed_payload_root": self.sealed_payload_root,
            "ciphertext_root": self.ciphertext_root,
            "decryption_policy_root": self.decryption_policy_root,
            "nullifier": self.nullifier,
            "privacy_score_bps": self.privacy_score_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn envelope_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-EVIDENCE-ENVELOPE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "envelope_root",
            self.envelope_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.envelope_id, "evidence envelope id")?;
        ensure_non_empty(&self.reporter_watcher_id, "evidence reporter watcher id")?;
        ensure_non_empty(&self.subject_id, "evidence subject id")?;
        ensure_non_empty(&self.sealed_payload_root, "evidence sealed payload root")?;
        ensure_non_empty(&self.ciphertext_root, "evidence ciphertext root")?;
        ensure_non_empty(
            &self.decryption_policy_root,
            "evidence decryption policy root",
        )?;
        ensure_non_empty(&self.nullifier, "evidence nullifier")?;
        ensure_bps(self.privacy_score_bps, "evidence privacy score bps")?;
        if self.expires_at_height < self.created_at_height {
            return Err("evidence expiry precedes creation".to_string());
        }
        if let Some(accused_watcher_id) = &self.accused_watcher_id {
            ensure_non_empty(accused_watcher_id, "evidence accused watcher id")?;
        }
        let expected_nullifier = monero_watchtower_slashing_evidence_nullifier(
            &self.reporter_watcher_id,
            &self.subject_id,
            &self.sealed_payload_root,
        );
        if self.nullifier != expected_nullifier {
            return Err("evidence nullifier mismatch".to_string());
        }
        let expected = monero_watchtower_slashing_evidence_envelope_id(
            self.evidence_kind,
            &self.reporter_watcher_id,
            self.accused_watcher_id.as_deref(),
            &self.subject_id,
            &self.ciphertext_root,
            self.created_at_height,
        );
        if self.envelope_id != expected {
            return Err("evidence envelope id mismatch".to_string());
        }
        Ok(self.envelope_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeTicket {
    pub ticket_id: String,
    pub ticket_kind: ChallengeTicketKind,
    pub challenger_watcher_id: String,
    pub accused_watcher_id: Option<String>,
    pub subject_id: String,
    pub evidence_envelope_ids: BTreeSet<String>,
    pub evidence_root: String,
    pub requested_slash_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sponsor_credit_id: Option<String>,
    pub status: ChallengeTicketStatus,
}

impl ChallengeTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket_kind: ChallengeTicketKind,
        challenger_watcher_id: impl Into<String>,
        accused_watcher_id: Option<String>,
        subject_id: impl Into<String>,
        evidence_envelope_ids: BTreeSet<String>,
        requested_slash_bps: u64,
        opened_at_height: u64,
        challenge_window_blocks: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let challenger_watcher_id = challenger_watcher_id.into();
        let subject_id = subject_id.into();
        let evidence_root = monero_watchtower_slashing_string_set_root(
            "MONERO-WATCHTOWER-SLASHING-CHALLENGE-EVIDENCE-IDS",
            &evidence_envelope_ids,
        );
        let expires_at_height = opened_at_height.saturating_add(challenge_window_blocks);
        let ticket_id = monero_watchtower_slashing_challenge_ticket_id(
            ticket_kind,
            &challenger_watcher_id,
            accused_watcher_id.as_deref(),
            &subject_id,
            &evidence_root,
            opened_at_height,
        );
        let ticket = Self {
            ticket_id,
            ticket_kind,
            challenger_watcher_id,
            accused_watcher_id,
            subject_id,
            evidence_envelope_ids,
            evidence_root,
            requested_slash_bps,
            opened_at_height,
            expires_at_height,
            sponsor_credit_id: None,
            status: ChallengeTicketStatus::Open,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn attach_sponsor(
        &mut self,
        sponsor_credit_id: impl Into<String>,
    ) -> MoneroWatchtowerSlashingResult<String> {
        let sponsor_credit_id = sponsor_credit_id.into();
        ensure_non_empty(&sponsor_credit_id, "challenge sponsor credit id")?;
        self.sponsor_credit_id = Some(sponsor_credit_id);
        self.status = ChallengeTicketStatus::Sponsored;
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.expires_at_height {
            self.status = ChallengeTicketStatus::Expired;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "challenge_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "ticket_kind": self.ticket_kind.as_str(),
            "challenger_watcher_id": self.challenger_watcher_id,
            "accused_watcher_id": self.accused_watcher_id,
            "subject_id": self.subject_id,
            "evidence_envelope_ids": self.evidence_envelope_ids,
            "evidence_root": self.evidence_root,
            "requested_slash_bps": self.requested_slash_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sponsor_credit_id": self.sponsor_credit_id,
            "status": self.status.as_str(),
        })
    }

    pub fn ticket_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-CHALLENGE-TICKET",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "ticket_root",
            self.ticket_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.ticket_id, "challenge ticket id")?;
        ensure_non_empty(
            &self.challenger_watcher_id,
            "challenge challenger watcher id",
        )?;
        ensure_non_empty(&self.subject_id, "challenge subject id")?;
        ensure_non_empty(&self.evidence_root, "challenge evidence root")?;
        ensure_bps(self.requested_slash_bps, "challenge requested slash bps")?;
        if self.evidence_envelope_ids.is_empty() {
            return Err("challenge ticket requires evidence".to_string());
        }
        if self.expires_at_height < self.opened_at_height {
            return Err("challenge expiry precedes opening".to_string());
        }
        if let Some(accused_watcher_id) = &self.accused_watcher_id {
            ensure_non_empty(accused_watcher_id, "challenge accused watcher id")?;
        }
        if let Some(sponsor_credit_id) = &self.sponsor_credit_id {
            ensure_non_empty(sponsor_credit_id, "challenge sponsor credit id")?;
        }
        let expected_evidence_root = monero_watchtower_slashing_string_set_root(
            "MONERO-WATCHTOWER-SLASHING-CHALLENGE-EVIDENCE-IDS",
            &self.evidence_envelope_ids,
        );
        if self.evidence_root != expected_evidence_root {
            return Err("challenge evidence root mismatch".to_string());
        }
        let expected = monero_watchtower_slashing_challenge_ticket_id(
            self.ticket_kind,
            &self.challenger_watcher_id,
            self.accused_watcher_id.as_deref(),
            &self.subject_id,
            &self.evidence_root,
            self.opened_at_height,
        );
        if self.ticket_id != expected {
            return Err("challenge ticket id mismatch".to_string());
        }
        Ok(self.ticket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingAction {
    pub action_id: String,
    pub reason: SlashingReason,
    pub accused_watcher_id: String,
    pub challenge_ticket_id: String,
    pub evidence_root: String,
    pub slash_bps: u64,
    pub slash_units: u64,
    pub reward_bps: u64,
    pub opened_at_height: u64,
    pub appeal_deadline_height: u64,
    pub executed_at_height: Option<u64>,
    pub status: SlashingActionStatus,
}

impl SlashingAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reason: SlashingReason,
        accused_watcher_id: impl Into<String>,
        challenge_ticket_id: impl Into<String>,
        evidence_root: impl Into<String>,
        watcher_bond_units: u64,
        slash_bps: u64,
        reward_bps: u64,
        opened_at_height: u64,
        appeal_window_blocks: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let accused_watcher_id = accused_watcher_id.into();
        let challenge_ticket_id = challenge_ticket_id.into();
        let evidence_root = evidence_root.into();
        let slash_units = bps_amount(watcher_bond_units, slash_bps);
        let appeal_deadline_height = opened_at_height.saturating_add(appeal_window_blocks);
        let action_id = monero_watchtower_slashing_action_id(
            reason,
            &accused_watcher_id,
            &challenge_ticket_id,
            &evidence_root,
            slash_bps,
            opened_at_height,
        );
        let action = Self {
            action_id,
            reason,
            accused_watcher_id,
            challenge_ticket_id,
            evidence_root,
            slash_bps,
            slash_units,
            reward_bps,
            opened_at_height,
            appeal_deadline_height,
            executed_at_height: None,
            status: SlashingActionStatus::Proposed,
        };
        action.validate()?;
        Ok(action)
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.status,
            SlashingActionStatus::Proposed
                | SlashingActionStatus::EvidenceLocked
                | SlashingActionStatus::AppealOpen
        ) && height > self.appeal_deadline_height
        {
            self.status = SlashingActionStatus::Executable;
        }
    }

    pub fn execute(&mut self, height: u64) -> MoneroWatchtowerSlashingResult<String> {
        if height <= self.appeal_deadline_height {
            return Err("slashing appeal window is still open".to_string());
        }
        if matches!(
            self.status,
            SlashingActionStatus::Rejected
                | SlashingActionStatus::Reversed
                | SlashingActionStatus::Expired
        ) {
            return Err("slashing action is not executable".to_string());
        }
        self.status = SlashingActionStatus::Executed;
        self.executed_at_height = Some(height);
        self.validate()
    }

    pub fn reward_units(&self) -> u64 {
        bps_amount(self.slash_units, self.reward_bps)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "slashing_action",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "action_id": self.action_id,
            "reason": self.reason.as_str(),
            "accused_watcher_id": self.accused_watcher_id,
            "challenge_ticket_id": self.challenge_ticket_id,
            "evidence_root": self.evidence_root,
            "slash_bps": self.slash_bps,
            "slash_units": self.slash_units,
            "reward_bps": self.reward_bps,
            "reward_units": self.reward_units(),
            "opened_at_height": self.opened_at_height,
            "appeal_deadline_height": self.appeal_deadline_height,
            "executed_at_height": self.executed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn action_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-ACTION",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "action_root",
            self.action_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.action_id, "slashing action id")?;
        ensure_non_empty(&self.accused_watcher_id, "slashing accused watcher id")?;
        ensure_non_empty(&self.challenge_ticket_id, "slashing challenge ticket id")?;
        ensure_non_empty(&self.evidence_root, "slashing evidence root")?;
        ensure_bps(self.slash_bps, "slashing slash bps")?;
        ensure_bps(self.reward_bps, "slashing reward bps")?;
        if self.slash_units == 0 {
            return Err("slashing units must be positive".to_string());
        }
        if self.appeal_deadline_height < self.opened_at_height {
            return Err("slashing appeal deadline precedes opening".to_string());
        }
        if let Some(executed_at_height) = self.executed_at_height {
            if executed_at_height <= self.appeal_deadline_height {
                return Err("slashing executed before appeal deadline".to_string());
            }
        }
        let expected = monero_watchtower_slashing_action_id(
            self.reason,
            &self.accused_watcher_id,
            &self.challenge_ticket_id,
            &self.evidence_root,
            self.slash_bps,
            self.opened_at_height,
        );
        if self.action_id != expected {
            return Err("slashing action id mismatch".to_string());
        }
        Ok(self.action_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppealWindow {
    pub appeal_id: String,
    pub action_id: String,
    pub appellant_watcher_id: String,
    pub counter_evidence_root: String,
    pub requested_relief_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub status: AppealStatus,
}

impl AppealWindow {
    pub fn new(
        action_id: impl Into<String>,
        appellant_watcher_id: impl Into<String>,
        counter_evidence_root: impl Into<String>,
        requested_relief_root: impl Into<String>,
        opened_at_height: u64,
        appeal_window_blocks: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let action_id = action_id.into();
        let appellant_watcher_id = appellant_watcher_id.into();
        let counter_evidence_root = counter_evidence_root.into();
        let requested_relief_root = requested_relief_root.into();
        let closes_at_height = opened_at_height.saturating_add(appeal_window_blocks);
        let appeal_id = monero_watchtower_slashing_appeal_id(
            &action_id,
            &appellant_watcher_id,
            &counter_evidence_root,
            opened_at_height,
        );
        let appeal = Self {
            appeal_id,
            action_id,
            appellant_watcher_id,
            counter_evidence_root,
            requested_relief_root,
            opened_at_height,
            closes_at_height,
            status: AppealStatus::Open,
        };
        appeal.validate()?;
        Ok(appeal)
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.active() && height > self.closes_at_height {
            self.status = AppealStatus::Expired;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "appeal_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "appeal_id": self.appeal_id,
            "action_id": self.action_id,
            "appellant_watcher_id": self.appellant_watcher_id,
            "counter_evidence_root": self.counter_evidence_root,
            "requested_relief_root": self.requested_relief_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn appeal_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-APPEAL",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "appeal_root",
            self.appeal_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.appeal_id, "appeal id")?;
        ensure_non_empty(&self.action_id, "appeal action id")?;
        ensure_non_empty(&self.appellant_watcher_id, "appeal appellant watcher id")?;
        ensure_non_empty(&self.counter_evidence_root, "appeal counter evidence root")?;
        ensure_non_empty(&self.requested_relief_root, "appeal requested relief root")?;
        if self.closes_at_height < self.opened_at_height {
            return Err("appeal close height precedes opening".to_string());
        }
        let expected = monero_watchtower_slashing_appeal_id(
            &self.action_id,
            &self.appellant_watcher_id,
            &self.counter_evidence_root,
            self.opened_at_height,
        );
        if self.appeal_id != expected {
            return Err("appeal id mismatch".to_string());
        }
        Ok(self.appeal_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardReceipt {
    pub receipt_id: String,
    pub action_id: String,
    pub beneficiary_watcher_id: String,
    pub sponsor_credit_id: Option<String>,
    pub amount_units: u64,
    pub payout_commitment_root: String,
    pub privacy_receipt_root: String,
    pub issued_at_height: u64,
    pub status: RewardStatus,
}

impl RewardReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_id: impl Into<String>,
        beneficiary_watcher_id: impl Into<String>,
        sponsor_credit_id: Option<String>,
        amount_units: u64,
        payout_commitment_root: impl Into<String>,
        privacy_receipt_root: impl Into<String>,
        issued_at_height: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let action_id = action_id.into();
        let beneficiary_watcher_id = beneficiary_watcher_id.into();
        let payout_commitment_root = payout_commitment_root.into();
        let privacy_receipt_root = privacy_receipt_root.into();
        let receipt_id = monero_watchtower_slashing_reward_receipt_id(
            &action_id,
            &beneficiary_watcher_id,
            sponsor_credit_id.as_deref(),
            amount_units,
            issued_at_height,
        );
        let receipt = Self {
            receipt_id,
            action_id,
            beneficiary_watcher_id,
            sponsor_credit_id,
            amount_units,
            payout_commitment_root,
            privacy_receipt_root,
            issued_at_height,
            status: RewardStatus::Claimable,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "reward_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "beneficiary_watcher_id": self.beneficiary_watcher_id,
            "sponsor_credit_id": self.sponsor_credit_id,
            "amount_units": self.amount_units,
            "payout_commitment_root": self.payout_commitment_root,
            "privacy_receipt_root": self.privacy_receipt_root,
            "issued_at_height": self.issued_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-REWARD-RECEIPT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "receipt_root",
            self.receipt_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.receipt_id, "reward receipt id")?;
        ensure_non_empty(&self.action_id, "reward action id")?;
        ensure_non_empty(
            &self.beneficiary_watcher_id,
            "reward beneficiary watcher id",
        )?;
        ensure_positive(self.amount_units, "reward amount units")?;
        ensure_non_empty(
            &self.payout_commitment_root,
            "reward payout commitment root",
        )?;
        ensure_non_empty(&self.privacy_receipt_root, "reward privacy receipt root")?;
        if let Some(sponsor_credit_id) = &self.sponsor_credit_id {
            ensure_non_empty(sponsor_credit_id, "reward sponsor credit id")?;
        }
        let expected = monero_watchtower_slashing_reward_receipt_id(
            &self.action_id,
            &self.beneficiary_watcher_id,
            self.sponsor_credit_id.as_deref(),
            self.amount_units,
            self.issued_at_height,
        );
        if self.receipt_id != expected {
            return Err("reward receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorCredit {
    pub credit_id: String,
    pub sponsor_id: String,
    pub sponsor_commitment_root: String,
    pub fee_asset_id: String,
    pub total_credit_units: u64,
    pub reserved_credit_units: u64,
    pub spent_credit_units: u64,
    pub eligible_ticket_kinds: BTreeSet<ChallengeTicketKind>,
    pub privacy_budget_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorCreditStatus,
}

impl SponsorCredit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: impl Into<String>,
        sponsor_commitment_root: impl Into<String>,
        fee_asset_id: impl Into<String>,
        total_credit_units: u64,
        eligible_ticket_kinds: BTreeSet<ChallengeTicketKind>,
        privacy_budget_root: impl Into<String>,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let sponsor_id = sponsor_id.into();
        let sponsor_commitment_root = sponsor_commitment_root.into();
        let fee_asset_id = fee_asset_id.into();
        let privacy_budget_root = privacy_budget_root.into();
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let kind_root = monero_watchtower_slashing_ticket_kind_set_root(
            "MONERO-WATCHTOWER-SLASHING-SPONSOR-KINDS",
            &eligible_ticket_kinds,
        );
        let credit_id = monero_watchtower_slashing_sponsor_credit_id(
            &sponsor_id,
            &sponsor_commitment_root,
            &fee_asset_id,
            &kind_root,
            opened_at_height,
        );
        let credit = Self {
            credit_id,
            sponsor_id,
            sponsor_commitment_root,
            fee_asset_id,
            total_credit_units,
            reserved_credit_units: 0,
            spent_credit_units: 0,
            eligible_ticket_kinds,
            privacy_budget_root,
            opened_at_height,
            expires_at_height,
            status: SponsorCreditStatus::Active,
        };
        credit.validate()?;
        Ok(credit)
    }

    pub fn available_units(&self) -> u64 {
        self.total_credit_units
            .saturating_sub(self.reserved_credit_units)
            .saturating_sub(self.spent_credit_units)
    }

    pub fn reserve(&mut self, amount_units: u64) -> MoneroWatchtowerSlashingResult<String> {
        ensure_positive(amount_units, "sponsor reserve amount")?;
        if amount_units > self.available_units() {
            return Err("sponsor credit reserve exceeds available units".to_string());
        }
        self.reserved_credit_units = self.reserved_credit_units.saturating_add(amount_units);
        self.status = SponsorCreditStatus::Reserved;
        self.validate()
    }

    pub fn spend(&mut self, amount_units: u64) -> MoneroWatchtowerSlashingResult<String> {
        ensure_positive(amount_units, "sponsor spend amount")?;
        if amount_units
            > self
                .reserved_credit_units
                .saturating_add(self.available_units())
        {
            return Err("sponsor credit spend exceeds capacity".to_string());
        }
        let from_reserved = amount_units.min(self.reserved_credit_units);
        self.reserved_credit_units = self.reserved_credit_units.saturating_sub(from_reserved);
        self.spent_credit_units = self.spent_credit_units.saturating_add(amount_units);
        self.status = if self.available_units() == 0 {
            SponsorCreditStatus::Exhausted
        } else {
            SponsorCreditStatus::Spent
        };
        self.validate()
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.usable() && height > self.expires_at_height {
            self.status = SponsorCreditStatus::Expired;
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "sponsor_credit",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "credit_id": self.credit_id,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "fee_asset_id": self.fee_asset_id,
            "total_credit_units": self.total_credit_units,
            "reserved_credit_units": self.reserved_credit_units,
            "spent_credit_units": self.spent_credit_units,
            "available_credit_units": self.available_units(),
            "eligible_ticket_kinds": self.eligible_ticket_kinds,
            "privacy_budget_root": self.privacy_budget_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn credit_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-SPONSOR-CREDIT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "credit_root",
            self.credit_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.credit_id, "sponsor credit id")?;
        ensure_non_empty(&self.sponsor_id, "sponsor id")?;
        ensure_non_empty(&self.sponsor_commitment_root, "sponsor commitment root")?;
        ensure_non_empty(&self.fee_asset_id, "sponsor fee asset id")?;
        ensure_positive(self.total_credit_units, "sponsor total credit")?;
        ensure_non_empty(&self.privacy_budget_root, "sponsor privacy budget root")?;
        if self.eligible_ticket_kinds.is_empty() {
            return Err("sponsor credit requires eligible ticket kinds".to_string());
        }
        if self
            .reserved_credit_units
            .saturating_add(self.spent_credit_units)
            > self.total_credit_units
        {
            return Err("sponsor reserved and spent units exceed total".to_string());
        }
        if self.expires_at_height < self.opened_at_height {
            return Err("sponsor credit expiry precedes opening".to_string());
        }
        let kind_root = monero_watchtower_slashing_ticket_kind_set_root(
            "MONERO-WATCHTOWER-SLASHING-SPONSOR-KINDS",
            &self.eligible_ticket_kinds,
        );
        let expected = monero_watchtower_slashing_sponsor_credit_id(
            &self.sponsor_id,
            &self.sponsor_commitment_root,
            &self.fee_asset_id,
            &kind_root,
            self.opened_at_height,
        );
        if self.credit_id != expected {
            return Err("sponsor credit id mismatch".to_string());
        }
        Ok(self.credit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerSlashingPublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl WatchtowerSlashingPublicRecord {
    pub fn new(
        record_kind: PublicRecordKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        emitted_at_height: u64,
        sequence: u64,
    ) -> MoneroWatchtowerSlashingResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let payload_root = monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-PUBLIC-PAYLOAD",
            &json!({
                "record_kind": record_kind.as_str(),
                "subject_id": subject_id,
                "subject_root": subject_root,
                "emitted_at_height": emitted_at_height,
                "sequence": sequence,
            }),
        );
        let record_id = monero_watchtower_slashing_public_record_id(
            record_kind,
            &subject_id,
            &subject_root,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            record_kind,
            subject_id,
            subject_root,
            payload_root,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "watchtower_slashing_public_record",
            "schema": MONERO_WATCHTOWER_SLASHING_PUBLIC_RECORD_SCHEMA,
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn record_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-PUBLIC-RECORD",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "record_root",
            self.record_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.subject_id, "public record subject id")?;
        ensure_non_empty(&self.subject_root, "public record subject root")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        let expected = monero_watchtower_slashing_public_record_id(
            self.record_kind,
            &self.subject_id,
            &self.subject_root,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerSlashingRoots {
    pub config_root: String,
    pub watcher_root: String,
    pub reserve_attestation_root: String,
    pub reorg_report_root: String,
    pub endpoint_equivocation_root: String,
    pub delayed_exit_guarantee_root: String,
    pub evidence_envelope_root: String,
    pub challenge_ticket_root: String,
    pub slashing_action_root: String,
    pub appeal_window_root: String,
    pub reward_receipt_root: String,
    pub sponsor_credit_root: String,
    pub public_record_root: String,
    pub consumed_nullifier_root: String,
    pub counters_root: String,
}

impl MoneroWatchtowerSlashingRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "watcher_root": self.watcher_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "reorg_report_root": self.reorg_report_root,
            "endpoint_equivocation_root": self.endpoint_equivocation_root,
            "delayed_exit_guarantee_root": self.delayed_exit_guarantee_root,
            "evidence_envelope_root": self.evidence_envelope_root,
            "challenge_ticket_root": self.challenge_ticket_root,
            "slashing_action_root": self.slashing_action_root,
            "appeal_window_root": self.appeal_window_root,
            "reward_receipt_root": self.reward_receipt_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "public_record_root": self.public_record_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "counters_root": self.counters_root,
            "roots_root": self.roots_root(),
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "watcher_root": self.watcher_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "reorg_report_root": self.reorg_report_root,
            "endpoint_equivocation_root": self.endpoint_equivocation_root,
            "delayed_exit_guarantee_root": self.delayed_exit_guarantee_root,
            "evidence_envelope_root": self.evidence_envelope_root,
            "challenge_ticket_root": self.challenge_ticket_root,
            "slashing_action_root": self.slashing_action_root,
            "appeal_window_root": self.appeal_window_root,
            "reward_receipt_root": self.reward_receipt_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "public_record_root": self.public_record_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn roots_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-ROOTS",
            &self.public_record_without_root(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerSlashingCounters {
    pub watcher_count: u64,
    pub active_watcher_count: u64,
    pub reserve_attestation_count: u64,
    pub disputed_reserve_attestation_count: u64,
    pub reorg_report_count: u64,
    pub active_reorg_report_count: u64,
    pub endpoint_equivocation_count: u64,
    pub sustained_endpoint_equivocation_count: u64,
    pub delayed_exit_guarantee_count: u64,
    pub breached_exit_guarantee_count: u64,
    pub evidence_envelope_count: u64,
    pub private_evidence_envelope_count: u64,
    pub challenge_ticket_count: u64,
    pub active_challenge_ticket_count: u64,
    pub slashing_action_count: u64,
    pub executed_slashing_action_count: u64,
    pub appeal_window_count: u64,
    pub active_appeal_window_count: u64,
    pub reward_receipt_count: u64,
    pub total_reward_units: u64,
    pub sponsor_credit_count: u64,
    pub available_sponsor_credit_units: u64,
    pub public_record_count: u64,
    pub consumed_nullifier_count: u64,
}

impl MoneroWatchtowerSlashingCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_count": self.watcher_count,
            "active_watcher_count": self.active_watcher_count,
            "reserve_attestation_count": self.reserve_attestation_count,
            "disputed_reserve_attestation_count": self.disputed_reserve_attestation_count,
            "reorg_report_count": self.reorg_report_count,
            "active_reorg_report_count": self.active_reorg_report_count,
            "endpoint_equivocation_count": self.endpoint_equivocation_count,
            "sustained_endpoint_equivocation_count": self.sustained_endpoint_equivocation_count,
            "delayed_exit_guarantee_count": self.delayed_exit_guarantee_count,
            "breached_exit_guarantee_count": self.breached_exit_guarantee_count,
            "evidence_envelope_count": self.evidence_envelope_count,
            "private_evidence_envelope_count": self.private_evidence_envelope_count,
            "challenge_ticket_count": self.challenge_ticket_count,
            "active_challenge_ticket_count": self.active_challenge_ticket_count,
            "slashing_action_count": self.slashing_action_count,
            "executed_slashing_action_count": self.executed_slashing_action_count,
            "appeal_window_count": self.appeal_window_count,
            "active_appeal_window_count": self.active_appeal_window_count,
            "reward_receipt_count": self.reward_receipt_count,
            "total_reward_units": self.total_reward_units,
            "sponsor_credit_count": self.sponsor_credit_count,
            "available_sponsor_credit_units": self.available_sponsor_credit_units,
            "public_record_count": self.public_record_count,
            "consumed_nullifier_count": self.consumed_nullifier_count,
            "counters_root": self.counters_root(),
        })
    }

    pub fn counters_root(&self) -> String {
        monero_watchtower_slashing_payload_root(
            "MONERO-WATCHTOWER-SLASHING-COUNTERS",
            &json!({
                "watcher_count": self.watcher_count,
                "active_watcher_count": self.active_watcher_count,
                "reserve_attestation_count": self.reserve_attestation_count,
                "disputed_reserve_attestation_count": self.disputed_reserve_attestation_count,
                "reorg_report_count": self.reorg_report_count,
                "active_reorg_report_count": self.active_reorg_report_count,
                "endpoint_equivocation_count": self.endpoint_equivocation_count,
                "sustained_endpoint_equivocation_count": self.sustained_endpoint_equivocation_count,
                "delayed_exit_guarantee_count": self.delayed_exit_guarantee_count,
                "breached_exit_guarantee_count": self.breached_exit_guarantee_count,
                "evidence_envelope_count": self.evidence_envelope_count,
                "private_evidence_envelope_count": self.private_evidence_envelope_count,
                "challenge_ticket_count": self.challenge_ticket_count,
                "active_challenge_ticket_count": self.active_challenge_ticket_count,
                "slashing_action_count": self.slashing_action_count,
                "executed_slashing_action_count": self.executed_slashing_action_count,
                "appeal_window_count": self.appeal_window_count,
                "active_appeal_window_count": self.active_appeal_window_count,
                "reward_receipt_count": self.reward_receipt_count,
                "total_reward_units": self.total_reward_units,
                "sponsor_credit_count": self.sponsor_credit_count,
                "available_sponsor_credit_units": self.available_sponsor_credit_units,
                "public_record_count": self.public_record_count,
                "consumed_nullifier_count": self.consumed_nullifier_count,
            }),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchtowerSlashingState {
    pub config: MoneroWatchtowerSlashingConfig,
    pub height: u64,
    pub watchers: BTreeMap<String, PqWatcherIdentity>,
    pub reserve_attestations: BTreeMap<String, ReserveAttestation>,
    pub reorg_reports: BTreeMap<String, ReorgReport>,
    pub endpoint_equivocations: BTreeMap<String, EndpointEquivocation>,
    pub delayed_exit_guarantees: BTreeMap<String, DelayedExitGuarantee>,
    pub evidence_envelopes: BTreeMap<String, EncryptedEvidenceEnvelope>,
    pub challenge_tickets: BTreeMap<String, ChallengeTicket>,
    pub slashing_actions: BTreeMap<String, SlashingAction>,
    pub appeal_windows: BTreeMap<String, AppealWindow>,
    pub reward_receipts: BTreeMap<String, RewardReceipt>,
    pub sponsor_credits: BTreeMap<String, SponsorCredit>,
    pub public_records: BTreeMap<String, WatchtowerSlashingPublicRecord>,
    pub consumed_evidence_nullifiers: BTreeSet<String>,
    pub next_public_record_sequence: u64,
}

impl Default for MoneroWatchtowerSlashingState {
    fn default() -> Self {
        Self::new(MoneroWatchtowerSlashingConfig::default(), 0)
    }
}

impl MoneroWatchtowerSlashingState {
    pub fn new(config: MoneroWatchtowerSlashingConfig, height: u64) -> Self {
        Self {
            config,
            height,
            watchers: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            reorg_reports: BTreeMap::new(),
            endpoint_equivocations: BTreeMap::new(),
            delayed_exit_guarantees: BTreeMap::new(),
            evidence_envelopes: BTreeMap::new(),
            challenge_tickets: BTreeMap::new(),
            slashing_actions: BTreeMap::new(),
            appeal_windows: BTreeMap::new(),
            reward_receipts: BTreeMap::new(),
            sponsor_credits: BTreeMap::new(),
            public_records: BTreeMap::new(),
            consumed_evidence_nullifiers: BTreeSet::new(),
            next_public_record_sequence: 0,
        }
    }

    pub fn devnet() -> MoneroWatchtowerSlashingResult<Self> {
        let mut state = Self::new(MoneroWatchtowerSlashingConfig::devnet(), 640);
        let reserve_watcher = devnet_watcher(
            "reserve-auditor-a",
            WatcherRole::ReserveAuditor,
            "operator-reserve-a",
            2,
            9_900,
            state.height,
        )?;
        let reorg_watcher = devnet_watcher(
            "reorg-reporter-a",
            WatcherRole::ReorgReporter,
            "operator-reorg-a",
            2,
            9_850,
            state.height,
        )?;
        let exit_watcher = devnet_watcher(
            "exit-guardian-a",
            WatcherRole::ExitGuardian,
            "operator-exit-a",
            1,
            9_800,
            state.height,
        )?;
        let sponsor_watcher = devnet_watcher(
            "fee-sponsor-a",
            WatcherRole::FeeSponsor,
            "operator-sponsor-a",
            1,
            9_750,
            state.height,
        )?;
        let reserve_watcher_id = reserve_watcher.watcher_id.clone();
        let reorg_watcher_id = reorg_watcher.watcher_id.clone();
        let exit_watcher_id = exit_watcher.watcher_id.clone();
        let sponsor_watcher_id = sponsor_watcher.watcher_id.clone();
        state.insert_watcher(reserve_watcher)?;
        state.insert_watcher(reorg_watcher)?;
        state.insert_watcher(exit_watcher)?;
        state.insert_watcher(sponsor_watcher)?;

        let reserve_attestation = ReserveAttestation::new(
            reserve_watcher_id.clone(),
            "devnet-reserve-epoch-640",
            devnet_root("reserve-address-set", "epoch-640"),
            devnet_root("reserve-output-set", "epoch-640"),
            10_000_000,
            10_950_000,
            125_000,
            640,
            devnet_root("reserve-statement", "epoch-640"),
            devnet_signature_root(&reserve_watcher_id, "reserve-epoch-640"),
            state.height,
            state.config.evidence_ttl_blocks,
        )?;
        let reserve_attestation_id = reserve_attestation.attestation_id.clone();
        state.insert_reserve_attestation(reserve_attestation)?;

        let reorg_report = ReorgReport::new(
            reorg_watcher_id.clone(),
            state.config.monero_network.clone(),
            633,
            devnet_root("canonical-block", "633"),
            devnet_root("competing-block", "633"),
            7,
            devnet_root("daemon-endpoint", "reorg-a"),
            devnet_root("reorg-evidence", "633"),
            devnet_signature_root(&reorg_watcher_id, "reorg-633"),
            state.height,
            state.config.reorg_report_window_blocks,
        )?;
        let reorg_report_id = reorg_report.report_id.clone();
        state.insert_reorg_report(reorg_report)?;

        let exit_guarantee = DelayedExitGuarantee::new(
            exit_watcher_id.clone(),
            "devnet-exit-0001",
            devnet_root("beneficiary", "private-exit-0001"),
            25_000,
            650,
            state.config.delayed_exit_sla_blocks,
            devnet_root("privacy-receipt", "private-exit-0001"),
        )?;
        let exit_guarantee_id = exit_guarantee.guarantee_id.clone();
        state.insert_delayed_exit_guarantee(exit_guarantee)?;

        let sponsor_credit = SponsorCredit::new(
            sponsor_watcher_id.clone(),
            devnet_root("sponsor-commitment", "fee-sponsor-a"),
            state.config.fee_asset_id.clone(),
            state.config.sponsor_min_credit_units,
            BTreeSet::from([
                ChallengeTicketKind::ReserveMismatch,
                ChallengeTicketKind::ReorgDeadline,
                ChallengeTicketKind::ExitDelay,
                ChallengeTicketKind::LowFeeSponsored,
            ]),
            devnet_root("privacy-budget", "fee-sponsor-a"),
            state.height,
            state.config.evidence_ttl_blocks,
        )?;
        let sponsor_credit_id = sponsor_credit.credit_id.clone();
        state.insert_sponsor_credit(sponsor_credit)?;

        let envelope = EncryptedEvidenceEnvelope::new(
            EvidenceKind::ReserveFalseStatement,
            reorg_watcher_id.clone(),
            Some(reserve_watcher_id.clone()),
            reserve_attestation_id.clone(),
            devnet_root("sealed-evidence", "reserve-mismatch"),
            devnet_root("ciphertext", "reserve-mismatch"),
            devnet_root("decryption-policy", "council-2of3"),
            9_900,
            state.height,
            state.config.evidence_ttl_blocks,
        )?;
        let envelope_id = envelope.envelope_id.clone();
        state.insert_evidence_envelope(envelope)?;

        let mut evidence_ids = BTreeSet::new();
        evidence_ids.insert(envelope_id);
        let mut ticket = ChallengeTicket::new(
            ChallengeTicketKind::ReserveMismatch,
            reorg_watcher_id.clone(),
            Some(reserve_watcher_id.clone()),
            reserve_attestation_id,
            evidence_ids,
            SlashingReason::FalseReserveAttestation.default_slash_bps(),
            state.height,
            state.config.appeal_window_blocks,
        )?;
        ticket.attach_sponsor(sponsor_credit_id)?;
        let ticket_id = ticket.ticket_id.clone();
        let evidence_root = ticket.evidence_root.clone();
        state.insert_challenge_ticket(ticket)?;

        let action = SlashingAction::new(
            SlashingReason::FalseReserveAttestation,
            reserve_watcher_id,
            ticket_id,
            evidence_root,
            state.config.watcher_bond_units,
            SlashingReason::FalseReserveAttestation.default_slash_bps(),
            state.config.whistleblower_reward_bps,
            state.height,
            state.config.appeal_window_blocks,
        )?;
        state.insert_slashing_action(action)?;

        let reorg_envelope = EncryptedEvidenceEnvelope::new(
            EvidenceKind::ReorgWithheld,
            exit_watcher_id,
            Some(reorg_watcher_id),
            reorg_report_id,
            devnet_root("sealed-evidence", "reorg-withheld"),
            devnet_root("ciphertext", "reorg-withheld"),
            devnet_root("decryption-policy", "fast-reorg-council"),
            9_800,
            state.height,
            state.config.evidence_ttl_blocks,
        )?;
        state.insert_evidence_envelope(reorg_envelope)?;

        let exit_envelope = EncryptedEvidenceEnvelope::new(
            EvidenceKind::DelayedExit,
            sponsor_watcher_id,
            None,
            exit_guarantee_id,
            devnet_root("sealed-evidence", "exit-delay"),
            devnet_root("ciphertext", "exit-delay"),
            devnet_root("decryption-policy", "private-exit-council"),
            9_850,
            state.height,
            state.config.evidence_ttl_blocks,
        )?;
        state.insert_evidence_envelope(exit_envelope)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroWatchtowerSlashingResult<String> {
        self.height = height;
        for attestation in self.reserve_attestations.values_mut() {
            attestation.set_height(height);
        }
        for report in self.reorg_reports.values_mut() {
            report.set_height(height);
        }
        for guarantee in self.delayed_exit_guarantees.values_mut() {
            guarantee.set_height(height);
        }
        for envelope in self.evidence_envelopes.values_mut() {
            envelope.set_height(height);
        }
        for ticket in self.challenge_tickets.values_mut() {
            ticket.set_height(height);
        }
        for action in self.slashing_actions.values_mut() {
            action.set_height(height);
        }
        for appeal in self.appeal_windows.values_mut() {
            appeal.set_height(height);
        }
        for credit in self.sponsor_credits.values_mut() {
            credit.set_height(height);
        }
        self.validate()
    }

    pub fn insert_watcher(
        &mut self,
        watcher: PqWatcherIdentity,
    ) -> MoneroWatchtowerSlashingResult<String> {
        let root = watcher.validate()?;
        let watcher_id = watcher.watcher_id.clone();
        insert_unique(&mut self.watchers, watcher_id.clone(), watcher, "watcher")?;
        self.record_public_record(
            PublicRecordKind::WatcherRegistered,
            watcher_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_reserve_attestation(
        &mut self,
        attestation: ReserveAttestation,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_live_watcher(&attestation.watcher_id)?;
        let root = attestation.validate()?;
        let attestation_id = attestation.attestation_id.clone();
        insert_unique(
            &mut self.reserve_attestations,
            attestation_id.clone(),
            attestation,
            "reserve attestation",
        )?;
        self.record_public_record(
            PublicRecordKind::ReserveAttestation,
            attestation_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_reorg_report(
        &mut self,
        report: ReorgReport,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_live_watcher(&report.reporter_watcher_id)?;
        let root = report.validate()?;
        let report_id = report.report_id.clone();
        insert_unique(
            &mut self.reorg_reports,
            report_id.clone(),
            report,
            "reorg report",
        )?;
        self.record_public_record(PublicRecordKind::ReorgReport, report_id, root.clone())?;
        Ok(root)
    }

    pub fn insert_endpoint_equivocation(
        &mut self,
        equivocation: EndpointEquivocation,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_live_watcher(&equivocation.watcher_id)?;
        let root = equivocation.validate()?;
        let equivocation_id = equivocation.equivocation_id.clone();
        insert_unique(
            &mut self.endpoint_equivocations,
            equivocation_id.clone(),
            equivocation,
            "endpoint equivocation",
        )?;
        self.record_public_record(
            PublicRecordKind::EndpointEquivocation,
            equivocation_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_delayed_exit_guarantee(
        &mut self,
        guarantee: DelayedExitGuarantee,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_live_watcher(&guarantee.watcher_id)?;
        let root = guarantee.validate()?;
        let guarantee_id = guarantee.guarantee_id.clone();
        insert_unique(
            &mut self.delayed_exit_guarantees,
            guarantee_id.clone(),
            guarantee,
            "delayed exit guarantee",
        )?;
        self.record_public_record(
            PublicRecordKind::DelayedExitGuarantee,
            guarantee_id,
            root.clone(),
        )?;
        Ok(root)
    }

    pub fn insert_evidence_envelope(
        &mut self,
        envelope: EncryptedEvidenceEnvelope,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_live_watcher(&envelope.reporter_watcher_id)?;
        if let Some(accused_watcher_id) = &envelope.accused_watcher_id {
            self.require_watcher(accused_watcher_id)?;
        }
        if self
            .consumed_evidence_nullifiers
            .contains(&envelope.nullifier)
        {
            return Err("evidence nullifier already consumed".to_string());
        }
        let root = envelope.validate()?;
        let envelope_id = envelope.envelope_id.clone();
        let nullifier = envelope.nullifier.clone();
        insert_unique(
            &mut self.evidence_envelopes,
            envelope_id.clone(),
            envelope,
            "evidence envelope",
        )?;
        self.consumed_evidence_nullifiers.insert(nullifier);
        self.record_public_record(PublicRecordKind::EvidenceDigest, envelope_id, root.clone())?;
        Ok(root)
    }

    pub fn insert_challenge_ticket(
        &mut self,
        ticket: ChallengeTicket,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_live_watcher(&ticket.challenger_watcher_id)?;
        if let Some(accused_watcher_id) = &ticket.accused_watcher_id {
            self.require_watcher(accused_watcher_id)?;
        }
        for envelope_id in &ticket.evidence_envelope_ids {
            if !self.evidence_envelopes.contains_key(envelope_id) {
                return Err("challenge references missing evidence envelope".to_string());
            }
        }
        if let Some(sponsor_credit_id) = &ticket.sponsor_credit_id {
            if !self.sponsor_credits.contains_key(sponsor_credit_id) {
                return Err("challenge references missing sponsor credit".to_string());
            }
        }
        let root = ticket.validate()?;
        let ticket_id = ticket.ticket_id.clone();
        insert_unique(
            &mut self.challenge_tickets,
            ticket_id.clone(),
            ticket,
            "challenge ticket",
        )?;
        self.record_public_record(PublicRecordKind::ChallengeTicket, ticket_id, root.clone())?;
        Ok(root)
    }

    pub fn insert_slashing_action(
        &mut self,
        action: SlashingAction,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_watcher(&action.accused_watcher_id)?;
        if !self
            .challenge_tickets
            .contains_key(&action.challenge_ticket_id)
        {
            return Err("slashing action references missing challenge ticket".to_string());
        }
        let root = action.validate()?;
        let action_id = action.action_id.clone();
        insert_unique(
            &mut self.slashing_actions,
            action_id.clone(),
            action,
            "slashing action",
        )?;
        self.record_public_record(PublicRecordKind::SlashingAction, action_id, root.clone())?;
        Ok(root)
    }

    pub fn insert_appeal_window(
        &mut self,
        appeal: AppealWindow,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_live_watcher(&appeal.appellant_watcher_id)?;
        if !self.slashing_actions.contains_key(&appeal.action_id) {
            return Err("appeal references missing slashing action".to_string());
        }
        let root = appeal.validate()?;
        let appeal_id = appeal.appeal_id.clone();
        let action_id = appeal.action_id.clone();
        insert_unique(
            &mut self.appeal_windows,
            appeal_id.clone(),
            appeal,
            "appeal window",
        )?;
        if let Some(action) = self.slashing_actions.get_mut(&action_id) {
            action.status = SlashingActionStatus::AppealOpen;
        }
        self.record_public_record(PublicRecordKind::AppealWindow, appeal_id, root.clone())?;
        Ok(root)
    }

    pub fn execute_slashing_action(
        &mut self,
        action_id: &str,
        executor_watcher_id: &str,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_live_watcher(executor_watcher_id)?;
        let reward_units = if let Some(action) = self.slashing_actions.get_mut(action_id) {
            action.execute(self.height)?;
            action.reward_units()
        } else {
            return Err("unknown slashing action".to_string());
        };
        let beneficiary_watcher_id = executor_watcher_id.to_string();
        let receipt = RewardReceipt::new(
            action_id.to_string(),
            beneficiary_watcher_id,
            None,
            reward_units,
            monero_watchtower_slashing_string_root(
                "MONERO-WATCHTOWER-SLASHING-REWARD-PAYOUT",
                action_id,
            ),
            monero_watchtower_slashing_string_root(
                "MONERO-WATCHTOWER-SLASHING-REWARD-PRIVACY",
                executor_watcher_id,
            ),
            self.height,
        )?;
        let receipt_root = receipt.receipt_root();
        let receipt_id = receipt.receipt_id.clone();
        self.reward_receipts.insert(receipt_id.clone(), receipt);
        self.record_public_record(PublicRecordKind::RewardReceipt, receipt_id, receipt_root)?;
        Ok(self.state_root())
    }

    pub fn insert_reward_receipt(
        &mut self,
        receipt: RewardReceipt,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_watcher(&receipt.beneficiary_watcher_id)?;
        if !self.slashing_actions.contains_key(&receipt.action_id) {
            return Err("reward receipt references missing slashing action".to_string());
        }
        if let Some(sponsor_credit_id) = &receipt.sponsor_credit_id {
            if !self.sponsor_credits.contains_key(sponsor_credit_id) {
                return Err("reward receipt references missing sponsor credit".to_string());
            }
        }
        let root = receipt.validate()?;
        let receipt_id = receipt.receipt_id.clone();
        insert_unique(
            &mut self.reward_receipts,
            receipt_id.clone(),
            receipt,
            "reward receipt",
        )?;
        self.record_public_record(PublicRecordKind::RewardReceipt, receipt_id, root.clone())?;
        Ok(root)
    }

    pub fn insert_sponsor_credit(
        &mut self,
        credit: SponsorCredit,
    ) -> MoneroWatchtowerSlashingResult<String> {
        self.require_watcher(&credit.sponsor_id)?;
        if credit.total_credit_units < self.config.sponsor_min_credit_units {
            return Err("sponsor credit below configured minimum".to_string());
        }
        let root = credit.validate()?;
        let credit_id = credit.credit_id.clone();
        insert_unique(
            &mut self.sponsor_credits,
            credit_id.clone(),
            credit,
            "sponsor credit",
        )?;
        self.record_public_record(PublicRecordKind::SponsorCredit, credit_id, root.clone())?;
        Ok(root)
    }

    pub fn counters(&self) -> MoneroWatchtowerSlashingCounters {
        MoneroWatchtowerSlashingCounters {
            watcher_count: self.watchers.len() as u64,
            active_watcher_count: self
                .watchers
                .values()
                .filter(|watcher| watcher.status.can_submit())
                .count() as u64,
            reserve_attestation_count: self.reserve_attestations.len() as u64,
            disputed_reserve_attestation_count: self
                .reserve_attestations
                .values()
                .filter(|attestation| {
                    matches!(
                        attestation.status,
                        ReserveAttestationStatus::Disputed | ReserveAttestationStatus::Slashed
                    )
                })
                .count() as u64,
            reorg_report_count: self.reorg_reports.len() as u64,
            active_reorg_report_count: self
                .reorg_reports
                .values()
                .filter(|report| report.status.active())
                .count() as u64,
            endpoint_equivocation_count: self.endpoint_equivocations.len() as u64,
            sustained_endpoint_equivocation_count: self
                .endpoint_equivocations
                .values()
                .filter(|equivocation| matches!(equivocation.status, EquivocationStatus::Sustained))
                .count() as u64,
            delayed_exit_guarantee_count: self.delayed_exit_guarantees.len() as u64,
            breached_exit_guarantee_count: self
                .delayed_exit_guarantees
                .values()
                .filter(|guarantee| matches!(guarantee.status, ExitGuaranteeStatus::Breached))
                .count() as u64,
            evidence_envelope_count: self.evidence_envelopes.len() as u64,
            private_evidence_envelope_count: self
                .evidence_envelopes
                .values()
                .filter(|envelope| envelope.evidence_kind.privacy_sensitive())
                .count() as u64,
            challenge_ticket_count: self.challenge_tickets.len() as u64,
            active_challenge_ticket_count: self
                .challenge_tickets
                .values()
                .filter(|ticket| ticket.status.active())
                .count() as u64,
            slashing_action_count: self.slashing_actions.len() as u64,
            executed_slashing_action_count: self
                .slashing_actions
                .values()
                .filter(|action| matches!(action.status, SlashingActionStatus::Executed))
                .count() as u64,
            appeal_window_count: self.appeal_windows.len() as u64,
            active_appeal_window_count: self
                .appeal_windows
                .values()
                .filter(|appeal| appeal.status.active())
                .count() as u64,
            reward_receipt_count: self.reward_receipts.len() as u64,
            total_reward_units: self
                .reward_receipts
                .values()
                .map(|receipt| receipt.amount_units)
                .sum(),
            sponsor_credit_count: self.sponsor_credits.len() as u64,
            available_sponsor_credit_units: self
                .sponsor_credits
                .values()
                .map(SponsorCredit::available_units)
                .sum(),
            public_record_count: self.public_records.len() as u64,
            consumed_nullifier_count: self.consumed_evidence_nullifiers.len() as u64,
        }
    }

    pub fn roots(&self) -> MoneroWatchtowerSlashingRoots {
        let counters = self.counters();
        MoneroWatchtowerSlashingRoots {
            config_root: self.config.config_root(),
            watcher_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-WATCHERS",
                self.watchers
                    .values()
                    .map(PqWatcherIdentity::public_record)
                    .collect(),
            ),
            reserve_attestation_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-RESERVE-ATTESTATIONS",
                self.reserve_attestations
                    .values()
                    .map(ReserveAttestation::public_record)
                    .collect(),
            ),
            reorg_report_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-REORG-REPORTS",
                self.reorg_reports
                    .values()
                    .map(ReorgReport::public_record)
                    .collect(),
            ),
            endpoint_equivocation_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-ENDPOINT-EQUIVOCATIONS",
                self.endpoint_equivocations
                    .values()
                    .map(EndpointEquivocation::public_record)
                    .collect(),
            ),
            delayed_exit_guarantee_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-DELAYED-EXIT-GUARANTEES",
                self.delayed_exit_guarantees
                    .values()
                    .map(DelayedExitGuarantee::public_record)
                    .collect(),
            ),
            evidence_envelope_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-EVIDENCE-ENVELOPES",
                self.evidence_envelopes
                    .values()
                    .map(EncryptedEvidenceEnvelope::public_record)
                    .collect(),
            ),
            challenge_ticket_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-CHALLENGE-TICKETS",
                self.challenge_tickets
                    .values()
                    .map(ChallengeTicket::public_record)
                    .collect(),
            ),
            slashing_action_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-ACTIONS",
                self.slashing_actions
                    .values()
                    .map(SlashingAction::public_record)
                    .collect(),
            ),
            appeal_window_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-APPEALS",
                self.appeal_windows
                    .values()
                    .map(AppealWindow::public_record)
                    .collect(),
            ),
            reward_receipt_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-REWARDS",
                self.reward_receipts
                    .values()
                    .map(RewardReceipt::public_record)
                    .collect(),
            ),
            sponsor_credit_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-SPONSOR-CREDITS",
                self.sponsor_credits
                    .values()
                    .map(SponsorCredit::public_record)
                    .collect(),
            ),
            public_record_root: collection_root(
                "MONERO-WATCHTOWER-SLASHING-PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(WatchtowerSlashingPublicRecord::public_record)
                    .collect(),
            ),
            consumed_nullifier_root: monero_watchtower_slashing_string_set_root(
                "MONERO-WATCHTOWER-SLASHING-CONSUMED-NULLIFIERS",
                &self.consumed_evidence_nullifiers,
            ),
            counters_root: counters.counters_root(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_watchtower_slashing_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION,
            "height": self.height,
            "monero_network": self.config.monero_network,
            "asset_id": self.config.asset_id,
            "fee_asset_id": self.config.fee_asset_id,
            "next_public_record_sequence": self.next_public_record_sequence,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        monero_watchtower_slashing_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> MoneroWatchtowerSlashingResult<String> {
        self.config.validate()?;
        validate_map_keys(&self.watchers, |watcher| &watcher.watcher_id, "watcher")?;
        validate_map_keys(
            &self.reserve_attestations,
            |attestation| &attestation.attestation_id,
            "reserve attestation",
        )?;
        validate_map_keys(
            &self.reorg_reports,
            |report| &report.report_id,
            "reorg report",
        )?;
        validate_map_keys(
            &self.endpoint_equivocations,
            |equivocation| &equivocation.equivocation_id,
            "endpoint equivocation",
        )?;
        validate_map_keys(
            &self.delayed_exit_guarantees,
            |guarantee| &guarantee.guarantee_id,
            "delayed exit guarantee",
        )?;
        validate_map_keys(
            &self.evidence_envelopes,
            |envelope| &envelope.envelope_id,
            "evidence envelope",
        )?;
        validate_map_keys(
            &self.challenge_tickets,
            |ticket| &ticket.ticket_id,
            "challenge ticket",
        )?;
        validate_map_keys(
            &self.slashing_actions,
            |action| &action.action_id,
            "slashing action",
        )?;
        validate_map_keys(
            &self.appeal_windows,
            |appeal| &appeal.appeal_id,
            "appeal window",
        )?;
        validate_map_keys(
            &self.reward_receipts,
            |receipt| &receipt.receipt_id,
            "reward receipt",
        )?;
        validate_map_keys(
            &self.sponsor_credits,
            |credit| &credit.credit_id,
            "sponsor credit",
        )?;
        validate_map_keys(
            &self.public_records,
            |record| &record.record_id,
            "public record",
        )?;

        for watcher in self.watchers.values() {
            watcher.validate()?;
            if watcher.privacy_score_bps < self.config.min_privacy_score_bps {
                return Err("watcher privacy score below configured floor".to_string());
            }
        }
        for attestation in self.reserve_attestations.values() {
            attestation.validate()?;
            self.require_watcher(&attestation.watcher_id)?;
        }
        for report in self.reorg_reports.values() {
            report.validate()?;
            self.require_watcher(&report.reporter_watcher_id)?;
        }
        for equivocation in self.endpoint_equivocations.values() {
            equivocation.validate()?;
            self.require_watcher(&equivocation.watcher_id)?;
        }
        for guarantee in self.delayed_exit_guarantees.values() {
            guarantee.validate()?;
            self.require_watcher(&guarantee.watcher_id)?;
        }
        let mut expected_nullifiers = BTreeSet::new();
        for envelope in self.evidence_envelopes.values() {
            envelope.validate()?;
            self.require_watcher(&envelope.reporter_watcher_id)?;
            if let Some(accused_watcher_id) = &envelope.accused_watcher_id {
                self.require_watcher(accused_watcher_id)?;
            }
            if envelope.privacy_score_bps < self.config.min_privacy_score_bps {
                return Err("evidence privacy score below configured floor".to_string());
            }
            if !expected_nullifiers.insert(envelope.nullifier.clone()) {
                return Err("duplicate evidence nullifier".to_string());
            }
        }
        if expected_nullifiers != self.consumed_evidence_nullifiers {
            return Err("consumed evidence nullifier set mismatch".to_string());
        }
        for ticket in self.challenge_tickets.values() {
            ticket.validate()?;
            self.require_watcher(&ticket.challenger_watcher_id)?;
            if let Some(accused_watcher_id) = &ticket.accused_watcher_id {
                self.require_watcher(accused_watcher_id)?;
            }
            for envelope_id in &ticket.evidence_envelope_ids {
                if !self.evidence_envelopes.contains_key(envelope_id) {
                    return Err("challenge references missing evidence envelope".to_string());
                }
            }
            if let Some(sponsor_credit_id) = &ticket.sponsor_credit_id {
                if !self.sponsor_credits.contains_key(sponsor_credit_id) {
                    return Err("challenge references missing sponsor credit".to_string());
                }
            }
        }
        for action in self.slashing_actions.values() {
            action.validate()?;
            self.require_watcher(&action.accused_watcher_id)?;
            if !self
                .challenge_tickets
                .contains_key(&action.challenge_ticket_id)
            {
                return Err("slashing action references missing challenge ticket".to_string());
            }
        }
        for appeal in self.appeal_windows.values() {
            appeal.validate()?;
            self.require_watcher(&appeal.appellant_watcher_id)?;
            if !self.slashing_actions.contains_key(&appeal.action_id) {
                return Err("appeal references missing slashing action".to_string());
            }
        }
        for receipt in self.reward_receipts.values() {
            receipt.validate()?;
            self.require_watcher(&receipt.beneficiary_watcher_id)?;
            if !self.slashing_actions.contains_key(&receipt.action_id) {
                return Err("reward references missing slashing action".to_string());
            }
            if let Some(sponsor_credit_id) = &receipt.sponsor_credit_id {
                if !self.sponsor_credits.contains_key(sponsor_credit_id) {
                    return Err("reward references missing sponsor credit".to_string());
                }
            }
        }
        for credit in self.sponsor_credits.values() {
            credit.validate()?;
            self.require_watcher(&credit.sponsor_id)?;
            if credit.total_credit_units < self.config.sponsor_min_credit_units {
                return Err("sponsor credit below configured minimum".to_string());
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }

    fn require_watcher(&self, watcher_id: &str) -> MoneroWatchtowerSlashingResult<()> {
        if self.watchers.contains_key(watcher_id) {
            Ok(())
        } else {
            Err("unknown slashing watcher".to_string())
        }
    }

    fn require_live_watcher(&self, watcher_id: &str) -> MoneroWatchtowerSlashingResult<()> {
        match self.watchers.get(watcher_id) {
            Some(watcher) if watcher.status.can_submit() => Ok(()),
            Some(_) => Err("slashing watcher is not live".to_string()),
            None => Err("unknown slashing watcher".to_string()),
        }
    }

    fn record_public_record(
        &mut self,
        record_kind: PublicRecordKind,
        subject_id: String,
        subject_root: String,
    ) -> MoneroWatchtowerSlashingResult<String> {
        let sequence = self.next_public_record_sequence;
        self.next_public_record_sequence = self.next_public_record_sequence.saturating_add(1);
        let record = WatchtowerSlashingPublicRecord::new(
            record_kind,
            subject_id,
            subject_root,
            self.height,
            sequence,
        )?;
        let root = record.record_root();
        self.public_records.insert(record.record_id.clone(), record);
        Ok(root)
    }
}

pub fn monero_watchtower_slashing_state_root_from_record(record: &Value) -> String {
    monero_watchtower_slashing_payload_root("MONERO-WATCHTOWER-SLASHING-STATE", record)
}

pub fn monero_watchtower_slashing_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_string_set_root(
    domain: &str,
    values: &BTreeSet<String>,
) -> String {
    let leaves = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn monero_watchtower_slashing_ticket_kind_set_root(
    domain: &str,
    values: &BTreeSet<ChallengeTicketKind>,
) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({"value": value.as_str()}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn monero_watchtower_slashing_config_id(
    monero_network: &str,
    asset_id: &str,
    fee_asset_id: &str,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-CONFIG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(monero_network),
            HashPart::Str(asset_id),
            HashPart::Str(fee_asset_id),
            HashPart::Str(MONERO_WATCHTOWER_SLASHING_PROTOCOL_VERSION),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_watcher_id(
    operator_commitment: &str,
    role: WatcherRole,
    monero_network: &str,
    pq_public_key_root: &str,
    endpoint_commitment_root: &str,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-WATCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(role.as_str()),
            HashPart::Str(monero_network),
            HashPart::Str(pq_public_key_root),
            HashPart::Str(endpoint_commitment_root),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_signature_root(
    signer_id: &str,
    subject_id: &str,
    transcript_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-PQ-SIGNATURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCHTOWER_SLASHING_SIGNATURE_ROOT_SCHEME),
            HashPart::Str(signer_id),
            HashPart::Str(subject_id),
            HashPart::Str(transcript_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_reserve_attestation_id(
    watcher_id: &str,
    reserve_epoch_id: &str,
    reserve_output_commitment_root: &str,
    observed_monero_height: u64,
    statement_root: &str,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-RESERVE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(reserve_epoch_id),
            HashPart::Str(reserve_output_commitment_root),
            HashPart::Int(observed_monero_height as i128),
            HashPart::Str(statement_root),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_reorg_report_id(
    reporter_watcher_id: &str,
    monero_network: &str,
    fork_height: u64,
    canonical_block_hash: &str,
    competing_block_hash: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-REORG-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reporter_watcher_id),
            HashPart::Str(monero_network),
            HashPart::Int(fork_height as i128),
            HashPart::Str(canonical_block_hash),
            HashPart::Str(competing_block_hash),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_endpoint_equivocation_id(
    watcher_id: &str,
    accused_endpoint_root: &str,
    kind: EndpointEquivocationKind,
    first_statement_root: &str,
    second_statement_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-ENDPOINT-EQUIVOCATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(accused_endpoint_root),
            HashPart::Str(kind.as_str()),
            HashPart::Str(first_statement_root),
            HashPart::Str(second_statement_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_delayed_exit_guarantee_id(
    watcher_id: &str,
    exit_id: &str,
    beneficiary_commitment: &str,
    amount_bucket_units: u64,
    promised_release_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-DELAYED-EXIT-GUARANTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(exit_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Int(amount_bucket_units as i128),
            HashPart::Int(promised_release_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_evidence_envelope_id(
    evidence_kind: EvidenceKind,
    reporter_watcher_id: &str,
    accused_watcher_id: Option<&str>,
    subject_id: &str,
    ciphertext_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-EVIDENCE-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(reporter_watcher_id),
            HashPart::Str(optional_str(accused_watcher_id)),
            HashPart::Str(subject_id),
            HashPart::Str(ciphertext_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_evidence_nullifier(
    reporter_watcher_id: &str,
    subject_id: &str,
    sealed_payload_root: &str,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-EVIDENCE-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reporter_watcher_id),
            HashPart::Str(subject_id),
            HashPart::Str(sealed_payload_root),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_challenge_ticket_id(
    ticket_kind: ChallengeTicketKind,
    challenger_watcher_id: &str,
    accused_watcher_id: Option<&str>,
    subject_id: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-CHALLENGE-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_kind.as_str()),
            HashPart::Str(challenger_watcher_id),
            HashPart::Str(optional_str(accused_watcher_id)),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_action_id(
    reason: SlashingReason,
    accused_watcher_id: &str,
    challenge_ticket_id: &str,
    evidence_root: &str,
    slash_bps: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-ACTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reason.as_str()),
            HashPart::Str(accused_watcher_id),
            HashPart::Str(challenge_ticket_id),
            HashPart::Str(evidence_root),
            HashPart::Int(slash_bps as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_appeal_id(
    action_id: &str,
    appellant_watcher_id: &str,
    counter_evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-APPEAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(action_id),
            HashPart::Str(appellant_watcher_id),
            HashPart::Str(counter_evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_reward_receipt_id(
    action_id: &str,
    beneficiary_watcher_id: &str,
    sponsor_credit_id: Option<&str>,
    amount_units: u64,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-REWARD-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(action_id),
            HashPart::Str(beneficiary_watcher_id),
            HashPart::Str(optional_str(sponsor_credit_id)),
            HashPart::Int(amount_units as i128),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_sponsor_credit_id(
    sponsor_id: &str,
    sponsor_commitment_root: &str,
    fee_asset_id: &str,
    eligible_kind_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-SPONSOR-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(sponsor_commitment_root),
            HashPart::Str(fee_asset_id),
            HashPart::Str(eligible_kind_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn monero_watchtower_slashing_public_record_id(
    record_kind: PublicRecordKind,
    subject_id: &str,
    subject_root: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn devnet_watcher(
    label: &str,
    role: WatcherRole,
    operator_commitment: &str,
    quorum_weight: u64,
    privacy_score_bps: u64,
    registered_at_height: u64,
) -> MoneroWatchtowerSlashingResult<PqWatcherIdentity> {
    PqWatcherIdentity::new(
        operator_commitment,
        role,
        MONERO_WATCHTOWER_SLASHING_DEVNET_NETWORK,
        devnet_root("pq-public-key", label),
        devnet_root("backup-public-key", label),
        devnet_signature_root(label, "identity"),
        devnet_root("bond", label),
        devnet_root("endpoint", label),
        quorum_weight,
        privacy_score_bps,
        registered_at_height,
    )
}

fn devnet_signature_root(signer_id: &str, transcript: &str) -> String {
    monero_watchtower_slashing_signature_root(
        signer_id,
        transcript,
        &devnet_root("transcript", transcript),
        640,
    )
}

fn devnet_root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-WATCHTOWER-SLASHING-DEVNET-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn collection_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn with_root_field(mut record: Value, field_name: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field_name.to_string(), Value::String(root));
    }
    record
}

fn insert_unique<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroWatchtowerSlashingResult<()> {
    if records.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn validate_map_keys<T, F>(
    records: &BTreeMap<String, T>,
    mut id_fn: F,
    label: &str,
) -> MoneroWatchtowerSlashingResult<()>
where
    F: FnMut(&T) -> &String,
{
    for (key, value) in records {
        if key != id_fn(value) {
            return Err(format!("{label} map key mismatch"));
        }
    }
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroWatchtowerSlashingResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroWatchtowerSlashingResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroWatchtowerSlashingResult<()> {
    if value > MONERO_WATCHTOWER_SLASHING_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn optional_str(value: Option<&str>) -> &str {
    match value {
        Some(value) => value,
        None => "",
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        let result = (numerator as u128).saturating_mul(MONERO_WATCHTOWER_SLASHING_MAX_BPS as u128)
            / denominator as u128;
        result.min(MONERO_WATCHTOWER_SLASHING_MAX_BPS as u128) as u64
    }
}

fn bps_amount(amount_units: u64, bps: u64) -> u64 {
    let result = (amount_units as u128).saturating_mul(bps as u128)
        / MONERO_WATCHTOWER_SLASHING_MAX_BPS as u128;
    result.min(u64::MAX as u128) as u64
}
