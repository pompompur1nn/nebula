use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type CensorshipResistanceResult<T> = Result<T, String>;

pub const CENSORSHIP_RESISTANCE_PROTOCOL_VERSION: &str = "nebula-censorship-resistance-v1";
pub const CENSORSHIP_RESISTANCE_SCHEMA_VERSION: &str = "censorship-resistance-devnet-state-v1";
pub const CENSORSHIP_RESISTANCE_SECURITY_MODEL: &str =
    "deterministic-devnet-anti-omission-scaffolding-no-production-networking";
pub const CENSORSHIP_RESISTANCE_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-canonical-json";
pub const CENSORSHIP_RESISTANCE_INTENT_ENCRYPTION_SCHEME: &str =
    "ML-KEM-768-sealed-devnet-intent-envelope";
pub const CENSORSHIP_RESISTANCE_PQ_WATCHTOWER_SCHEME: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-watchtower-attestation";
pub const CENSORSHIP_RESISTANCE_RELAY_RECEIPT_SCHEME: &str = "private-relay-root-receipt-v1";
pub const CENSORSHIP_RESISTANCE_LOW_FEE_POLICY_VERSION: &str = "low-fee-inclusion-sponsorship-v1";
pub const CENSORSHIP_RESISTANCE_FAIRNESS_POLICY_VERSION: &str = "operator-fairness-scorecard-v1";
pub const CENSORSHIP_RESISTANCE_DEVNET_LABEL: &str = "devnet-censorship-resistance";
pub const CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID: &str = "nebula-devnet-sequencer";
pub const CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID: &str = "nebula-devnet-watchtower-a";
pub const CENSORSHIP_RESISTANCE_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const CENSORSHIP_RESISTANCE_MAX_BPS: u64 = 10_000;
pub const CENSORSHIP_RESISTANCE_DEFAULT_FORCED_LANE_TTL_BLOCKS: u64 = 720;
pub const CENSORSHIP_RESISTANCE_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const CENSORSHIP_RESISTANCE_DEFAULT_PRIVATE_RELAY_TTL_BLOCKS: u64 = 48;
pub const CENSORSHIP_RESISTANCE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 32;
pub const CENSORSHIP_RESISTANCE_DEFAULT_WATCHDOG_STALE_BLOCKS: u64 = 8;
pub const CENSORSHIP_RESISTANCE_DEFAULT_LOW_FEE_MAX_MICRO_UNITS: u64 = 2_500;
pub const CENSORSHIP_RESISTANCE_DEFAULT_LOW_FEE_SPONSOR_BALANCE_UNITS: u64 = 2_000_000;
pub const CENSORSHIP_RESISTANCE_DEFAULT_EMERGENCY_BYPASS_BLOCKS: u64 = 24;
pub const CENSORSHIP_RESISTANCE_DEFAULT_MIN_WATCHTOWER_QUORUM: u64 = 2;
pub const CENSORSHIP_RESISTANCE_DEFAULT_MIN_PQ_ATTESTATION_WEIGHT: u64 = 100;
pub const CENSORSHIP_RESISTANCE_DEFAULT_MAX_PAYLOAD_BYTES: u64 = 128 * 1024;
pub const CENSORSHIP_RESISTANCE_DEFAULT_OPERATOR_BOND_UNITS: u64 = 1_000_000;
pub const CENSORSHIP_RESISTANCE_DEFAULT_SLASH_OMISSION_BPS: u64 = 2_000;
pub const CENSORSHIP_RESISTANCE_DEFAULT_SLASH_FALSE_STATEMENT_BPS: u64 = 5_000;
pub const CENSORSHIP_RESISTANCE_DEFAULT_FAIRNESS_LOOKBACK_BLOCKS: u64 = 720;
pub const CENSORSHIP_RESISTANCE_MAX_LANES: usize = 128;
pub const CENSORSHIP_RESISTANCE_MAX_RECEIPTS: usize = 8_192;
pub const CENSORSHIP_RESISTANCE_MAX_OMISSION_CLAIMS: usize = 2_048;
pub const CENSORSHIP_RESISTANCE_MAX_WATCHDOG_OBSERVATIONS: usize = 8_192;
pub const CENSORSHIP_RESISTANCE_MAX_RELAY_RECEIPTS: usize = 8_192;
pub const CENSORSHIP_RESISTANCE_MAX_CHALLENGE_WINDOWS: usize = 2_048;
pub const CENSORSHIP_RESISTANCE_MAX_SLASHING_EVIDENCE: usize = 1_024;
pub const CENSORSHIP_RESISTANCE_MAX_EMERGENCY_BYPASSES: usize = 256;
pub const CENSORSHIP_RESISTANCE_MAX_SPONSORS: usize = 256;
pub const CENSORSHIP_RESISTANCE_MAX_SPONSOR_TICKETS: usize = 8_192;
pub const CENSORSHIP_RESISTANCE_MAX_SCORECARDS: usize = 512;
pub const CENSORSHIP_RESISTANCE_MAX_PQ_ATTESTATIONS: usize = 8_192;
pub const CENSORSHIP_RESISTANCE_MAX_PUBLIC_RECORDS: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForcedInclusionLaneKind {
    PrivateTransfer,
    MoneroBridgeExit,
    ContractCall,
    DefiSettlement,
    WalletRecovery,
    Governance,
    EmergencyBypass,
    LowFeeSponsored,
}

impl ForcedInclusionLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::ContractCall => "contract_call",
            Self::DefiSettlement => "defi_settlement",
            Self::WalletRecovery => "wallet_recovery",
            Self::Governance => "governance",
            Self::EmergencyBypass => "emergency_bypass",
            Self::LowFeeSponsored => "low_fee_sponsored",
        }
    }

    pub fn default_priority_score(self) -> u64 {
        match self {
            Self::EmergencyBypass => 1_000_000,
            Self::MoneroBridgeExit => 900_000,
            Self::WalletRecovery => 850_000,
            Self::PrivateTransfer => 800_000,
            Self::LowFeeSponsored => 725_000,
            Self::DefiSettlement => 675_000,
            Self::ContractCall => 625_000,
            Self::Governance => 500_000,
        }
    }

    pub fn default_min_share_bps(self) -> u64 {
        match self {
            Self::EmergencyBypass => 1_000,
            Self::MoneroBridgeExit | Self::WalletRecovery => 2_000,
            Self::PrivateTransfer | Self::LowFeeSponsored => 2_500,
            Self::DefiSettlement | Self::ContractCall => 1_500,
            Self::Governance => 500,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer
                | Self::MoneroBridgeExit
                | Self::WalletRecovery
                | Self::EmergencyBypass
                | Self::LowFeeSponsored
        )
    }

    pub fn emergency(self) -> bool {
        matches!(self, Self::EmergencyBypass | Self::WalletRecovery)
    }

    pub fn low_fee(self) -> bool {
        matches!(self, Self::LowFeeSponsored | Self::MoneroBridgeExit)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Active,
    Standby,
    Congested,
    Paused,
    Draining,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Congested => "congested",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedIntentReceiptStatus {
    Submitted,
    Acknowledged,
    Scheduled,
    Included,
    Omitted,
    Expired,
    Challenged,
    Rescued,
}

impl EncryptedIntentReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Acknowledged => "acknowledged",
            Self::Scheduled => "scheduled",
            Self::Included => "included",
            Self::Omitted => "omitted",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Rescued => "rescued",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Submitted | Self::Acknowledged | Self::Scheduled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionClaimKind {
    MissingReceipt,
    DeadlineMissed,
    ReorderedBehindPublic,
    RelaySuppression,
    SponsorAbuse,
    EmergencyBypassIgnored,
    PqAttestationConflict,
}

impl OmissionClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingReceipt => "missing_receipt",
            Self::DeadlineMissed => "deadline_missed",
            Self::ReorderedBehindPublic => "reordered_behind_public",
            Self::RelaySuppression => "relay_suppression",
            Self::SponsorAbuse => "sponsor_abuse",
            Self::EmergencyBypassIgnored => "emergency_bypass_ignored",
            Self::PqAttestationConflict => "pq_attestation_conflict",
        }
    }

    pub fn default_slash_bps(self) -> u64 {
        match self {
            Self::MissingReceipt | Self::DeadlineMissed => 2_000,
            Self::ReorderedBehindPublic => 1_500,
            Self::RelaySuppression => 2_500,
            Self::SponsorAbuse => 1_000,
            Self::EmergencyBypassIgnored => 3_500,
            Self::PqAttestationConflict => 5_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionClaimStatus {
    Draft,
    Open,
    Challenged,
    Accepted,
    Rejected,
    Expired,
    Resolved,
}

impl OmissionClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Challenged => "challenged",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Resolved => "resolved",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchdogObservationKind {
    MempoolSeen,
    RelayAcknowledged,
    BlockMissing,
    QueueDepth,
    FeeQuote,
    InclusionDeadline,
    EmergencySignal,
    PqHeartbeat,
}

impl WatchdogObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MempoolSeen => "mempool_seen",
            Self::RelayAcknowledged => "relay_acknowledged",
            Self::BlockMissing => "block_missing",
            Self::QueueDepth => "queue_depth",
            Self::FeeQuote => "fee_quote",
            Self::InclusionDeadline => "inclusion_deadline",
            Self::EmergencySignal => "emergency_signal",
            Self::PqHeartbeat => "pq_heartbeat",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Recorded,
    Accepted,
    Disputed,
    Expired,
}

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Accepted => "accepted",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateRelayReceiptKind {
    PrivateRelay,
    WatchtowerMirror,
    SponsorIngress,
    EmergencyBypass,
    PqWitness,
}

impl PrivateRelayReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateRelay => "private_relay",
            Self::WatchtowerMirror => "watchtower_mirror",
            Self::SponsorIngress => "sponsor_ingress",
            Self::EmergencyBypass => "emergency_bypass",
            Self::PqWitness => "pq_witness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayReceiptStatus {
    Accepted,
    Delayed,
    Failed,
    Disputed,
    Expired,
}

impl RelayReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Delayed => "delayed",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeWindowStatus {
    Open,
    AwaitingResponse,
    Accepted,
    Rejected,
    Expired,
    Executed,
}

impl ChallengeWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::AwaitingResponse => "awaiting_response",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Executed => "executed",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::AwaitingResponse)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    Omission,
    Equivocation,
    FalseInclusion,
    LateDisclosure,
    RelaySuppression,
    PqAttestationMismatch,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Omission => "omission",
            Self::Equivocation => "equivocation",
            Self::FalseInclusion => "false_inclusion",
            Self::LateDisclosure => "late_disclosure",
            Self::RelaySuppression => "relay_suppression",
            Self::PqAttestationMismatch => "pq_attestation_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Proposed,
    Accepted,
    Executed,
    Rejected,
    Expired,
}

impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn slashable(self) -> bool {
        matches!(self, Self::Accepted | Self::Executed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyBypassStatus {
    Armed,
    Active,
    Draining,
    Closed,
    Expired,
}

impl EmergencyBypassStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_receipts(self) -> bool {
        matches!(self, Self::Armed | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Active,
    Reserved,
    Spent,
    Exhausted,
    Refunded,
    Expired,
    Paused,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Exhausted => "exhausted",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Paused => "paused",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FairnessGrade {
    Excellent,
    Good,
    Watch,
    Probation,
    SlashEligible,
}

impl FairnessGrade {
    pub fn from_score_bps(score_bps: u64) -> Self {
        if score_bps >= 9_000 {
            Self::Excellent
        } else if score_bps >= 7_500 {
            Self::Good
        } else if score_bps >= 6_000 {
            Self::Watch
        } else if score_bps >= 4_000 {
            Self::Probation
        } else {
            Self::SlashEligible
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Excellent => "excellent",
            Self::Good => "good",
            Self::Watch => "watch",
            Self::Probation => "probation",
            Self::SlashEligible => "slash_eligible",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqWatchtowerAttestationKind {
    InclusionWitness,
    OmissionWitness,
    RelayLiveness,
    FairnessCheckpoint,
    QuantumReadiness,
    EmergencyBypass,
}

impl PqWatchtowerAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InclusionWitness => "inclusion_witness",
            Self::OmissionWitness => "omission_witness",
            Self::RelayLiveness => "relay_liveness",
            Self::FairnessCheckpoint => "fairness_checkpoint",
            Self::QuantumReadiness => "quantum_readiness",
            Self::EmergencyBypass => "emergency_bypass",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Disputed,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensorshipResistanceConfig {
    pub forced_lane_ttl_blocks: u64,
    pub encrypted_receipt_ttl_blocks: u64,
    pub private_relay_receipt_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub watchdog_stale_blocks: u64,
    pub low_fee_max_fee_micro_units: u64,
    pub low_fee_sponsor_min_balance_units: u64,
    pub emergency_bypass_window_blocks: u64,
    pub min_watchtower_quorum: u64,
    pub min_pq_attestation_weight: u64,
    pub max_payload_bytes: u64,
    pub min_operator_bond_units: u64,
    pub slash_bps_omission: u64,
    pub slash_bps_false_statement: u64,
    pub fairness_lookback_blocks: u64,
    pub enable_emergency_bypass: bool,
    pub enable_low_fee_sponsorship: bool,
    pub enable_pq_watchtower_attestations: bool,
}

impl Default for CensorshipResistanceConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl CensorshipResistanceConfig {
    pub fn devnet() -> Self {
        Self {
            forced_lane_ttl_blocks: CENSORSHIP_RESISTANCE_DEFAULT_FORCED_LANE_TTL_BLOCKS,
            encrypted_receipt_ttl_blocks: CENSORSHIP_RESISTANCE_DEFAULT_RECEIPT_TTL_BLOCKS,
            private_relay_receipt_ttl_blocks:
                CENSORSHIP_RESISTANCE_DEFAULT_PRIVATE_RELAY_TTL_BLOCKS,
            challenge_window_blocks: CENSORSHIP_RESISTANCE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            watchdog_stale_blocks: CENSORSHIP_RESISTANCE_DEFAULT_WATCHDOG_STALE_BLOCKS,
            low_fee_max_fee_micro_units: CENSORSHIP_RESISTANCE_DEFAULT_LOW_FEE_MAX_MICRO_UNITS,
            low_fee_sponsor_min_balance_units:
                CENSORSHIP_RESISTANCE_DEFAULT_LOW_FEE_SPONSOR_BALANCE_UNITS,
            emergency_bypass_window_blocks: CENSORSHIP_RESISTANCE_DEFAULT_EMERGENCY_BYPASS_BLOCKS,
            min_watchtower_quorum: CENSORSHIP_RESISTANCE_DEFAULT_MIN_WATCHTOWER_QUORUM,
            min_pq_attestation_weight: CENSORSHIP_RESISTANCE_DEFAULT_MIN_PQ_ATTESTATION_WEIGHT,
            max_payload_bytes: CENSORSHIP_RESISTANCE_DEFAULT_MAX_PAYLOAD_BYTES,
            min_operator_bond_units: CENSORSHIP_RESISTANCE_DEFAULT_OPERATOR_BOND_UNITS,
            slash_bps_omission: CENSORSHIP_RESISTANCE_DEFAULT_SLASH_OMISSION_BPS,
            slash_bps_false_statement: CENSORSHIP_RESISTANCE_DEFAULT_SLASH_FALSE_STATEMENT_BPS,
            fairness_lookback_blocks: CENSORSHIP_RESISTANCE_DEFAULT_FAIRNESS_LOOKBACK_BLOCKS,
            enable_emergency_bypass: true,
            enable_low_fee_sponsorship: true,
            enable_pq_watchtower_attestations: true,
        }
    }

    pub fn validate(&self) -> CensorshipResistanceResult<()> {
        ensure_positive(self.forced_lane_ttl_blocks, "forced lane ttl")?;
        ensure_positive(self.encrypted_receipt_ttl_blocks, "encrypted receipt ttl")?;
        ensure_positive(
            self.private_relay_receipt_ttl_blocks,
            "private relay receipt ttl",
        )?;
        ensure_positive(self.challenge_window_blocks, "challenge window")?;
        ensure_positive(self.watchdog_stale_blocks, "watchdog stale blocks")?;
        ensure_positive(self.low_fee_max_fee_micro_units, "low fee max fee")?;
        ensure_positive(
            self.low_fee_sponsor_min_balance_units,
            "low fee sponsor minimum balance",
        )?;
        ensure_positive(
            self.emergency_bypass_window_blocks,
            "emergency bypass window",
        )?;
        ensure_positive(self.min_watchtower_quorum, "watchtower quorum")?;
        ensure_positive(self.min_pq_attestation_weight, "pq attestation weight")?;
        ensure_positive(self.max_payload_bytes, "max payload bytes")?;
        ensure_positive(self.min_operator_bond_units, "operator bond")?;
        ensure_bps(self.slash_bps_omission, "omission slash bps")?;
        ensure_bps(self.slash_bps_false_statement, "false statement slash bps")?;
        ensure_positive(self.fairness_lookback_blocks, "fairness lookback")?;
        Ok(())
    }

    pub fn config_root(&self) -> String {
        censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-CONFIG", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "censorship_resistance_config",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "schema_version": CENSORSHIP_RESISTANCE_SCHEMA_VERSION,
            "commitment_scheme": CENSORSHIP_RESISTANCE_COMMITMENT_SCHEME,
            "intent_encryption_scheme": CENSORSHIP_RESISTANCE_INTENT_ENCRYPTION_SCHEME,
            "pq_watchtower_scheme": CENSORSHIP_RESISTANCE_PQ_WATCHTOWER_SCHEME,
            "forced_lane_ttl_blocks": self.forced_lane_ttl_blocks,
            "encrypted_receipt_ttl_blocks": self.encrypted_receipt_ttl_blocks,
            "private_relay_receipt_ttl_blocks": self.private_relay_receipt_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "watchdog_stale_blocks": self.watchdog_stale_blocks,
            "low_fee_max_fee_micro_units": self.low_fee_max_fee_micro_units,
            "low_fee_sponsor_min_balance_units": self.low_fee_sponsor_min_balance_units,
            "emergency_bypass_window_blocks": self.emergency_bypass_window_blocks,
            "min_watchtower_quorum": self.min_watchtower_quorum,
            "min_pq_attestation_weight": self.min_pq_attestation_weight,
            "max_payload_bytes": self.max_payload_bytes,
            "min_operator_bond_units": self.min_operator_bond_units,
            "slash_bps_omission": self.slash_bps_omission,
            "slash_bps_false_statement": self.slash_bps_false_statement,
            "fairness_lookback_blocks": self.fairness_lookback_blocks,
            "enable_emergency_bypass": self.enable_emergency_bypass,
            "enable_low_fee_sponsorship": self.enable_low_fee_sponsorship,
            "enable_pq_watchtower_attestations": self.enable_pq_watchtower_attestations,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedInclusionLane {
    pub lane_id: String,
    pub lane_kind: ForcedInclusionLaneKind,
    pub label: String,
    pub operator_id: String,
    pub min_share_bps: u64,
    pub priority_score: u64,
    pub max_pending_intents: u64,
    pub target_inclusion_blocks: u64,
    pub max_fee_micro_units: u64,
    pub accepts_low_fee: bool,
    pub emergency_bypass: bool,
    pub privacy_required: bool,
    pub status: LaneStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sponsor_policy_ids: BTreeSet<String>,
    pub watcher_ids: BTreeSet<String>,
    pub metadata_root: String,
}

impl ForcedInclusionLane {
    pub fn new(
        lane_kind: ForcedInclusionLaneKind,
        label: &str,
        operator_id: &str,
        min_share_bps: u64,
        max_pending_intents: u64,
        target_inclusion_blocks: u64,
        max_fee_micro_units: u64,
        created_at_height: u64,
        ttl_blocks: u64,
        metadata: &Value,
    ) -> CensorshipResistanceResult<Self> {
        ensure_non_empty(label, "forced inclusion lane label")?;
        ensure_non_empty(operator_id, "forced inclusion lane operator")?;
        ensure_bps(min_share_bps, "forced inclusion lane min share")?;
        ensure_positive(max_pending_intents, "forced inclusion lane max pending")?;
        ensure_positive(
            target_inclusion_blocks,
            "forced inclusion lane target inclusion",
        )?;
        ensure_positive(max_fee_micro_units, "forced inclusion lane max fee")?;
        ensure_positive(ttl_blocks, "forced inclusion lane ttl")?;
        let metadata_root =
            censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-LANE-METADATA", metadata);
        let lane_id = forced_inclusion_lane_id(
            lane_kind,
            label,
            operator_id,
            created_at_height,
            &metadata_root,
        );
        Ok(Self {
            lane_id,
            lane_kind,
            label: label.to_string(),
            operator_id: operator_id.to_string(),
            min_share_bps,
            priority_score: lane_kind.default_priority_score(),
            max_pending_intents,
            target_inclusion_blocks,
            max_fee_micro_units,
            accepts_low_fee: lane_kind.low_fee(),
            emergency_bypass: lane_kind.emergency(),
            privacy_required: lane_kind.privacy_sensitive(),
            status: LaneStatus::Active,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            sponsor_policy_ids: BTreeSet::new(),
            watcher_ids: BTreeSet::new(),
            metadata_root,
        })
    }

    pub fn attach_sponsor(&mut self, sponsor_id: impl Into<String>) {
        self.sponsor_policy_ids.insert(sponsor_id.into());
    }

    pub fn attach_watchtower(&mut self, watchtower_id: impl Into<String>) {
        self.watcher_ids.insert(watchtower_id.into());
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.accepts_intents()
            && height >= self.created_at_height
            && height <= self.expires_at_height
    }

    pub fn lane_root(&self) -> String {
        censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-LANE", &self.public_record())
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.lane_id, "forced inclusion lane id")?;
        ensure_non_empty(&self.label, "forced inclusion lane label")?;
        ensure_non_empty(&self.operator_id, "forced inclusion lane operator")?;
        ensure_bps(self.min_share_bps, "forced inclusion lane min share")?;
        ensure_positive(self.priority_score, "forced inclusion lane priority")?;
        ensure_positive(
            self.max_pending_intents,
            "forced inclusion lane max pending",
        )?;
        ensure_positive(
            self.target_inclusion_blocks,
            "forced inclusion lane target inclusion",
        )?;
        ensure_positive(self.max_fee_micro_units, "forced inclusion lane max fee")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("forced inclusion lane expiry must be after creation".to_string());
        }
        let expected_id = forced_inclusion_lane_id(
            self.lane_kind,
            &self.label,
            &self.operator_id,
            self.created_at_height,
            &self.metadata_root,
        );
        if self.lane_id != expected_id {
            return Err("forced inclusion lane id mismatch".to_string());
        }
        Ok(self.lane_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "label": self.label,
            "operator_id": self.operator_id,
            "min_share_bps": self.min_share_bps,
            "priority_score": self.priority_score,
            "max_pending_intents": self.max_pending_intents,
            "target_inclusion_blocks": self.target_inclusion_blocks,
            "max_fee_micro_units": self.max_fee_micro_units,
            "accepts_low_fee": self.accepts_low_fee,
            "emergency_bypass": self.emergency_bypass,
            "privacy_required": self.privacy_required,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sponsor_policy_ids": self.sponsor_policy_ids.iter().cloned().collect::<Vec<_>>(),
            "watcher_ids": self.watcher_ids.iter().cloned().collect::<Vec<_>>(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedIntentReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub submitter_commitment: String,
    pub intent_kind: String,
    pub ciphertext_root: String,
    pub payload_commitment_root: String,
    pub fee_commitment_root: String,
    pub payload_size_bytes: u64,
    pub max_fee_micro_units: u64,
    pub low_fee_sponsor_ticket_id: Option<String>,
    pub relay_receipt_id: Option<String>,
    pub emergency_bypass_id: Option<String>,
    pub nonce: u64,
    pub submitted_at_height: u64,
    pub inclusion_deadline_height: u64,
    pub expires_at_height: u64,
    pub replay_nullifier: String,
    pub status: EncryptedIntentReceiptStatus,
    pub pq_sender_auth_root: String,
    pub metadata_root: String,
}

impl EncryptedIntentReceipt {
    pub fn new(
        lane_id: &str,
        submitter_commitment: &str,
        intent_kind: &str,
        encrypted_payload: &Value,
        payload_size_bytes: u64,
        max_fee_micro_units: u64,
        nonce: u64,
        submitted_at_height: u64,
        inclusion_deadline_height: u64,
        ttl_blocks: u64,
        pq_sender_auth_root: &str,
        metadata: &Value,
    ) -> CensorshipResistanceResult<Self> {
        ensure_non_empty(lane_id, "encrypted intent lane")?;
        ensure_non_empty(submitter_commitment, "encrypted intent submitter")?;
        ensure_non_empty(intent_kind, "encrypted intent kind")?;
        ensure_positive(payload_size_bytes, "encrypted intent payload size")?;
        ensure_positive(max_fee_micro_units, "encrypted intent max fee")?;
        ensure_positive(ttl_blocks, "encrypted intent ttl")?;
        ensure_non_empty(pq_sender_auth_root, "encrypted intent pq sender auth")?;
        if inclusion_deadline_height < submitted_at_height {
            return Err("encrypted intent deadline before submit height".to_string());
        }
        let ciphertext_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-INTENT-CIPHERTEXT",
            encrypted_payload,
        );
        let payload_commitment_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-INTENT-PAYLOAD-COMMITMENT",
            &json!({
                "lane_id": lane_id,
                "intent_kind": intent_kind,
                "ciphertext_root": ciphertext_root,
                "payload_size_bytes": payload_size_bytes,
            }),
        );
        let fee_commitment_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-INTENT-FEE-COMMITMENT",
            &json!({
                "lane_id": lane_id,
                "max_fee_micro_units": max_fee_micro_units,
                "submitter_commitment": submitter_commitment,
            }),
        );
        let metadata_root =
            censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-INTENT-METADATA", metadata);
        let replay_nullifier = encrypted_intent_replay_nullifier(
            lane_id,
            submitter_commitment,
            nonce,
            &payload_commitment_root,
        );
        let receipt_id = encrypted_intent_receipt_id(
            lane_id,
            submitter_commitment,
            intent_kind,
            &payload_commitment_root,
            nonce,
            submitted_at_height,
        );
        Ok(Self {
            receipt_id,
            lane_id: lane_id.to_string(),
            submitter_commitment: submitter_commitment.to_string(),
            intent_kind: intent_kind.to_string(),
            ciphertext_root,
            payload_commitment_root,
            fee_commitment_root,
            payload_size_bytes,
            max_fee_micro_units,
            low_fee_sponsor_ticket_id: None,
            relay_receipt_id: None,
            emergency_bypass_id: None,
            nonce,
            submitted_at_height,
            inclusion_deadline_height,
            expires_at_height: submitted_at_height.saturating_add(ttl_blocks),
            replay_nullifier,
            status: EncryptedIntentReceiptStatus::Submitted,
            pq_sender_auth_root: pq_sender_auth_root.to_string(),
            metadata_root,
        })
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn due_at(&self, height: u64) -> bool {
        height >= self.inclusion_deadline_height && self.status.open()
    }

    pub fn mark_included(&mut self) {
        self.status = EncryptedIntentReceiptStatus::Included;
    }

    pub fn mark_rescued(&mut self) {
        self.status = EncryptedIntentReceiptStatus::Rescued;
    }

    pub fn receipt_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-ENCRYPTED-INTENT-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.receipt_id, "encrypted intent receipt id")?;
        ensure_non_empty(&self.lane_id, "encrypted intent lane")?;
        ensure_non_empty(&self.submitter_commitment, "encrypted intent submitter")?;
        ensure_non_empty(&self.intent_kind, "encrypted intent kind")?;
        ensure_non_empty(&self.ciphertext_root, "encrypted intent ciphertext root")?;
        ensure_non_empty(
            &self.payload_commitment_root,
            "encrypted intent payload commitment root",
        )?;
        ensure_non_empty(&self.fee_commitment_root, "encrypted intent fee root")?;
        ensure_positive(self.payload_size_bytes, "encrypted intent payload size")?;
        ensure_positive(self.max_fee_micro_units, "encrypted intent max fee")?;
        ensure_non_empty(&self.replay_nullifier, "encrypted intent replay nullifier")?;
        ensure_non_empty(&self.pq_sender_auth_root, "encrypted intent pq sender auth")?;
        if self.inclusion_deadline_height < self.submitted_at_height {
            return Err("encrypted intent deadline before submit height".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("encrypted intent expiry must be after submit height".to_string());
        }
        let expected_replay_nullifier = encrypted_intent_replay_nullifier(
            &self.lane_id,
            &self.submitter_commitment,
            self.nonce,
            &self.payload_commitment_root,
        );
        if self.replay_nullifier != expected_replay_nullifier {
            return Err("encrypted intent replay nullifier mismatch".to_string());
        }
        let expected_id = encrypted_intent_receipt_id(
            &self.lane_id,
            &self.submitter_commitment,
            &self.intent_kind,
            &self.payload_commitment_root,
            self.nonce,
            self.submitted_at_height,
        );
        if self.receipt_id != expected_id {
            return Err("encrypted intent receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_intent_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "encryption_scheme": CENSORSHIP_RESISTANCE_INTENT_ENCRYPTION_SCHEME,
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "submitter_commitment": self.submitter_commitment,
            "intent_kind": self.intent_kind,
            "ciphertext_root": self.ciphertext_root,
            "payload_commitment_root": self.payload_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "payload_size_bytes": self.payload_size_bytes,
            "max_fee_micro_units": self.max_fee_micro_units,
            "low_fee_sponsor_ticket_id": self.low_fee_sponsor_ticket_id,
            "relay_receipt_id": self.relay_receipt_id,
            "emergency_bypass_id": self.emergency_bypass_id,
            "nonce": self.nonce,
            "submitted_at_height": self.submitted_at_height,
            "inclusion_deadline_height": self.inclusion_deadline_height,
            "expires_at_height": self.expires_at_height,
            "replay_nullifier": self.replay_nullifier,
            "status": self.status.as_str(),
            "pq_sender_auth_root": self.pq_sender_auth_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRelayReceipt {
    pub relay_receipt_id: String,
    pub receipt_id: String,
    pub lane_id: String,
    pub relay_id: String,
    pub receipt_kind: PrivateRelayReceiptKind,
    pub ingress_height: u64,
    pub ack_height: u64,
    pub expires_at_height: u64,
    pub encrypted_route_root: String,
    pub fee_quote_root: String,
    pub witness_commitment_root: String,
    pub route_hops: u64,
    pub ack_latency_ms: u64,
    pub low_fee: bool,
    pub status: RelayReceiptStatus,
    pub pq_handshake_root: String,
    pub metadata_root: String,
}

impl PrivateRelayReceipt {
    pub fn new(
        receipt: &EncryptedIntentReceipt,
        relay_id: &str,
        receipt_kind: PrivateRelayReceiptKind,
        ingress_height: u64,
        ack_height: u64,
        ttl_blocks: u64,
        encrypted_route: &Value,
        fee_quote: &Value,
        witness_commitment: &Value,
        route_hops: u64,
        ack_latency_ms: u64,
        low_fee: bool,
        pq_handshake_root: &str,
        metadata: &Value,
    ) -> CensorshipResistanceResult<Self> {
        receipt.validate()?;
        ensure_non_empty(relay_id, "private relay id")?;
        ensure_positive(ttl_blocks, "private relay receipt ttl")?;
        ensure_positive(route_hops, "private relay route hops")?;
        ensure_non_empty(pq_handshake_root, "private relay pq handshake")?;
        if ack_height < ingress_height {
            return Err("private relay ack before ingress".to_string());
        }
        let encrypted_route_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-PRIVATE-RELAY-ROUTE",
            encrypted_route,
        );
        let fee_quote_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-PRIVATE-RELAY-FEE-QUOTE",
            fee_quote,
        );
        let witness_commitment_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-PRIVATE-RELAY-WITNESS",
            witness_commitment,
        );
        let metadata_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-PRIVATE-RELAY-METADATA",
            metadata,
        );
        let relay_receipt_id = private_relay_receipt_id(
            &receipt.receipt_id,
            relay_id,
            receipt_kind,
            ingress_height,
            &witness_commitment_root,
        );
        let status = if ack_latency_ms > 1_000 {
            RelayReceiptStatus::Delayed
        } else {
            RelayReceiptStatus::Accepted
        };
        Ok(Self {
            relay_receipt_id,
            receipt_id: receipt.receipt_id.clone(),
            lane_id: receipt.lane_id.clone(),
            relay_id: relay_id.to_string(),
            receipt_kind,
            ingress_height,
            ack_height,
            expires_at_height: ingress_height.saturating_add(ttl_blocks),
            encrypted_route_root,
            fee_quote_root,
            witness_commitment_root,
            route_hops,
            ack_latency_ms,
            low_fee,
            status,
            pq_handshake_root: pq_handshake_root.to_string(),
            metadata_root,
        })
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn relay_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-PRIVATE-RELAY-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.relay_receipt_id, "private relay receipt id")?;
        ensure_non_empty(&self.receipt_id, "private relay receipt intent")?;
        ensure_non_empty(&self.lane_id, "private relay receipt lane")?;
        ensure_non_empty(&self.relay_id, "private relay id")?;
        ensure_non_empty(&self.encrypted_route_root, "private relay route root")?;
        ensure_non_empty(&self.fee_quote_root, "private relay fee quote root")?;
        ensure_non_empty(&self.witness_commitment_root, "private relay witness root")?;
        ensure_positive(self.route_hops, "private relay route hops")?;
        ensure_non_empty(&self.pq_handshake_root, "private relay pq handshake")?;
        if self.ack_height < self.ingress_height {
            return Err("private relay ack before ingress".to_string());
        }
        if self.expires_at_height <= self.ingress_height {
            return Err("private relay expiry must be after ingress".to_string());
        }
        let expected_id = private_relay_receipt_id(
            &self.receipt_id,
            &self.relay_id,
            self.receipt_kind,
            self.ingress_height,
            &self.witness_commitment_root,
        );
        if self.relay_receipt_id != expected_id {
            return Err("private relay receipt id mismatch".to_string());
        }
        Ok(self.relay_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_relay_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "receipt_scheme": CENSORSHIP_RESISTANCE_RELAY_RECEIPT_SCHEME,
            "relay_receipt_id": self.relay_receipt_id,
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "relay_id": self.relay_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "ingress_height": self.ingress_height,
            "ack_height": self.ack_height,
            "expires_at_height": self.expires_at_height,
            "encrypted_route_root": self.encrypted_route_root,
            "fee_quote_root": self.fee_quote_root,
            "witness_commitment_root": self.witness_commitment_root,
            "route_hops": self.route_hops,
            "ack_latency_ms": self.ack_latency_ms,
            "low_fee": self.low_fee,
            "status": self.status.as_str(),
            "pq_handshake_root": self.pq_handshake_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchdogObservation {
    pub observation_id: String,
    pub observation_kind: WatchdogObservationKind,
    pub watchtower_id: String,
    pub operator_id: String,
    pub lane_id: Option<String>,
    pub receipt_id: Option<String>,
    pub observed_height: u64,
    pub observed_latency_blocks: u64,
    pub queue_depth: u64,
    pub sample_root: String,
    pub prior_state_root: String,
    pub observed_state_root: String,
    pub pq_attestation_root: String,
    pub confidence_bps: u64,
    pub weight: u64,
    pub status: ObservationStatus,
}

impl WatchdogObservation {
    pub fn new(
        observation_kind: WatchdogObservationKind,
        watchtower_id: &str,
        operator_id: &str,
        lane_id: Option<String>,
        receipt_id: Option<String>,
        observed_height: u64,
        observed_latency_blocks: u64,
        queue_depth: u64,
        sample: &Value,
        prior_state_root: &str,
        observed_state_root: &str,
        pq_attestation_root: &str,
        confidence_bps: u64,
        weight: u64,
    ) -> CensorshipResistanceResult<Self> {
        ensure_non_empty(watchtower_id, "watchdog observation watchtower")?;
        ensure_non_empty(operator_id, "watchdog observation operator")?;
        ensure_non_empty(prior_state_root, "watchdog observation prior state root")?;
        ensure_non_empty(
            observed_state_root,
            "watchdog observation observed state root",
        )?;
        ensure_non_empty(pq_attestation_root, "watchdog observation pq attestation")?;
        ensure_bps(confidence_bps, "watchdog observation confidence")?;
        ensure_positive(weight, "watchdog observation weight")?;
        let sample_root =
            censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-WATCHDOG-SAMPLE", sample);
        let observation_id = watchdog_observation_id(
            observation_kind,
            watchtower_id,
            operator_id,
            lane_id.as_deref(),
            receipt_id.as_deref(),
            observed_height,
            &sample_root,
        );
        Ok(Self {
            observation_id,
            observation_kind,
            watchtower_id: watchtower_id.to_string(),
            operator_id: operator_id.to_string(),
            lane_id,
            receipt_id,
            observed_height,
            observed_latency_blocks,
            queue_depth,
            sample_root,
            prior_state_root: prior_state_root.to_string(),
            observed_state_root: observed_state_root.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            confidence_bps,
            weight,
            status: ObservationStatus::Recorded,
        })
    }

    pub fn observation_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-WATCHDOG-OBSERVATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.observation_id, "watchdog observation id")?;
        ensure_non_empty(&self.watchtower_id, "watchdog observation watchtower")?;
        ensure_non_empty(&self.operator_id, "watchdog observation operator")?;
        ensure_non_empty(&self.sample_root, "watchdog observation sample root")?;
        ensure_non_empty(
            &self.prior_state_root,
            "watchdog observation prior state root",
        )?;
        ensure_non_empty(
            &self.observed_state_root,
            "watchdog observation observed state root",
        )?;
        ensure_non_empty(
            &self.pq_attestation_root,
            "watchdog observation pq attestation",
        )?;
        ensure_bps(self.confidence_bps, "watchdog observation confidence")?;
        ensure_positive(self.weight, "watchdog observation weight")?;
        let expected_id = watchdog_observation_id(
            self.observation_kind,
            &self.watchtower_id,
            &self.operator_id,
            self.lane_id.as_deref(),
            self.receipt_id.as_deref(),
            self.observed_height,
            &self.sample_root,
        );
        if self.observation_id != expected_id {
            return Err("watchdog observation id mismatch".to_string());
        }
        Ok(self.observation_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "watchdog_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "observation_kind": self.observation_kind.as_str(),
            "watchtower_id": self.watchtower_id,
            "operator_id": self.operator_id,
            "lane_id": self.lane_id,
            "receipt_id": self.receipt_id,
            "observed_height": self.observed_height,
            "observed_latency_blocks": self.observed_latency_blocks,
            "queue_depth": self.queue_depth,
            "sample_root": self.sample_root,
            "prior_state_root": self.prior_state_root,
            "observed_state_root": self.observed_state_root,
            "pq_attestation_root": self.pq_attestation_root,
            "confidence_bps": self.confidence_bps,
            "weight": self.weight,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OmissionClaim {
    pub claim_id: String,
    pub claim_kind: OmissionClaimKind,
    pub receipt_id: String,
    pub lane_id: String,
    pub claimant_id: String,
    pub accused_operator_id: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub claimed_deadline_height: u64,
    pub expected_inclusion_root: String,
    pub observed_block_root: String,
    pub watchdog_observation_ids: BTreeSet<String>,
    pub relay_receipt_ids: BTreeSet<String>,
    pub evidence_root: String,
    pub privacy_preserving_summary_root: String,
    pub bond_units: u64,
    pub status: OmissionClaimStatus,
    pub challenge_window_id: Option<String>,
    pub pq_claimant_auth_root: String,
}

impl OmissionClaim {
    pub fn new(
        claim_kind: OmissionClaimKind,
        receipt: &EncryptedIntentReceipt,
        claimant_id: &str,
        accused_operator_id: &str,
        opened_at_height: u64,
        claimed_deadline_height: u64,
        watchdog_observation_ids: BTreeSet<String>,
        relay_receipt_ids: BTreeSet<String>,
        expected_inclusion: &Value,
        observed_block: &Value,
        privacy_summary: &Value,
        bond_units: u64,
        pq_claimant_auth_root: &str,
    ) -> CensorshipResistanceResult<Self> {
        receipt.validate()?;
        ensure_non_empty(claimant_id, "omission claim claimant")?;
        ensure_non_empty(accused_operator_id, "omission claim accused operator")?;
        ensure_positive(bond_units, "omission claim bond")?;
        ensure_non_empty(pq_claimant_auth_root, "omission claim pq claimant auth")?;
        if opened_at_height < receipt.inclusion_deadline_height {
            return Err("omission claim opened before receipt deadline".to_string());
        }
        let expected_inclusion_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-CLAIM-EXPECTED-INCLUSION",
            expected_inclusion,
        );
        let observed_block_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-CLAIM-OBSERVED-BLOCK",
            observed_block,
        );
        let privacy_preserving_summary_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-CLAIM-PRIVACY-SUMMARY",
            privacy_summary,
        );
        let evidence_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-CLAIM-EVIDENCE",
            &json!({
                "watchdog_observation_ids": watchdog_observation_ids.iter().cloned().collect::<Vec<_>>(),
                "relay_receipt_ids": relay_receipt_ids.iter().cloned().collect::<Vec<_>>(),
                "expected_inclusion_root": expected_inclusion_root,
                "observed_block_root": observed_block_root,
            }),
        );
        let claim_id = omission_claim_id(
            claim_kind,
            &receipt.receipt_id,
            claimant_id,
            accused_operator_id,
            opened_at_height,
            &evidence_root,
        );
        Ok(Self {
            claim_id,
            claim_kind,
            receipt_id: receipt.receipt_id.clone(),
            lane_id: receipt.lane_id.clone(),
            claimant_id: claimant_id.to_string(),
            accused_operator_id: accused_operator_id.to_string(),
            opened_at_height,
            deadline_height: receipt.inclusion_deadline_height,
            claimed_deadline_height,
            expected_inclusion_root,
            observed_block_root,
            watchdog_observation_ids,
            relay_receipt_ids,
            evidence_root,
            privacy_preserving_summary_root,
            bond_units,
            status: OmissionClaimStatus::Open,
            challenge_window_id: None,
            pq_claimant_auth_root: pq_claimant_auth_root.to_string(),
        })
    }

    pub fn claim_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-OMISSION-CLAIM",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.claim_id, "omission claim id")?;
        ensure_non_empty(&self.receipt_id, "omission claim receipt")?;
        ensure_non_empty(&self.lane_id, "omission claim lane")?;
        ensure_non_empty(&self.claimant_id, "omission claim claimant")?;
        ensure_non_empty(&self.accused_operator_id, "omission claim accused")?;
        ensure_non_empty(&self.expected_inclusion_root, "omission expected root")?;
        ensure_non_empty(&self.observed_block_root, "omission observed root")?;
        ensure_non_empty(&self.evidence_root, "omission evidence root")?;
        ensure_non_empty(
            &self.privacy_preserving_summary_root,
            "omission privacy summary",
        )?;
        ensure_positive(self.bond_units, "omission claim bond")?;
        ensure_non_empty(
            &self.pq_claimant_auth_root,
            "omission claim pq claimant auth",
        )?;
        if self.opened_at_height < self.deadline_height {
            return Err("omission claim opened before deadline".to_string());
        }
        let expected_id = omission_claim_id(
            self.claim_kind,
            &self.receipt_id,
            &self.claimant_id,
            &self.accused_operator_id,
            self.opened_at_height,
            &self.evidence_root,
        );
        if self.claim_id != expected_id {
            return Err("omission claim id mismatch".to_string());
        }
        Ok(self.claim_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "omission_claim",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "claim_kind": self.claim_kind.as_str(),
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "claimant_id": self.claimant_id,
            "accused_operator_id": self.accused_operator_id,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "claimed_deadline_height": self.claimed_deadline_height,
            "expected_inclusion_root": self.expected_inclusion_root,
            "observed_block_root": self.observed_block_root,
            "watchdog_observation_ids": self.watchdog_observation_ids.iter().cloned().collect::<Vec<_>>(),
            "relay_receipt_ids": self.relay_receipt_ids.iter().cloned().collect::<Vec<_>>(),
            "evidence_root": self.evidence_root,
            "privacy_preserving_summary_root": self.privacy_preserving_summary_root,
            "bond_units": self.bond_units,
            "status": self.status.as_str(),
            "challenge_window_id": self.challenge_window_id,
            "pq_claimant_auth_root": self.pq_claimant_auth_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeWindow {
    pub window_id: String,
    pub claim_id: String,
    pub lane_id: String,
    pub opened_at_height: u64,
    pub response_due_height: u64,
    pub resolve_after_height: u64,
    pub expires_at_height: u64,
    pub challenger_id: String,
    pub accused_operator_id: String,
    pub requested_action_root: String,
    pub operator_response_root: Option<String>,
    pub watchdog_observation_root: String,
    pub status: ChallengeWindowStatus,
    pub quorum_weight: u64,
    pub pq_quorum_root: String,
}

impl ChallengeWindow {
    pub fn new(
        claim: &OmissionClaim,
        challenger_id: &str,
        opened_at_height: u64,
        response_blocks: u64,
        resolve_blocks: u64,
        expiry_blocks: u64,
        requested_action: &Value,
        watchdog_observation_root: &str,
        quorum_weight: u64,
        pq_quorum_root: &str,
    ) -> CensorshipResistanceResult<Self> {
        claim.validate()?;
        ensure_non_empty(challenger_id, "challenge challenger")?;
        ensure_positive(response_blocks, "challenge response blocks")?;
        ensure_positive(resolve_blocks, "challenge resolve blocks")?;
        ensure_positive(expiry_blocks, "challenge expiry blocks")?;
        ensure_non_empty(watchdog_observation_root, "challenge watchdog root")?;
        ensure_positive(quorum_weight, "challenge quorum weight")?;
        ensure_non_empty(pq_quorum_root, "challenge pq quorum root")?;
        if opened_at_height < claim.opened_at_height {
            return Err("challenge window opened before claim".to_string());
        }
        let requested_action_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-CHALLENGE-REQUESTED-ACTION",
            requested_action,
        );
        let response_due_height = opened_at_height.saturating_add(response_blocks);
        let resolve_after_height = response_due_height.saturating_add(resolve_blocks);
        let expires_at_height = opened_at_height.saturating_add(expiry_blocks);
        let window_id = challenge_window_id(
            &claim.claim_id,
            challenger_id,
            opened_at_height,
            &requested_action_root,
        );
        Ok(Self {
            window_id,
            claim_id: claim.claim_id.clone(),
            lane_id: claim.lane_id.clone(),
            opened_at_height,
            response_due_height,
            resolve_after_height,
            expires_at_height,
            challenger_id: challenger_id.to_string(),
            accused_operator_id: claim.accused_operator_id.clone(),
            requested_action_root,
            operator_response_root: None,
            watchdog_observation_root: watchdog_observation_root.to_string(),
            status: ChallengeWindowStatus::Open,
            quorum_weight,
            pq_quorum_root: pq_quorum_root.to_string(),
        })
    }

    pub fn attach_operator_response(&mut self, response: &Value) {
        self.operator_response_root = Some(censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-CHALLENGE-OPERATOR-RESPONSE",
            response,
        ));
        self.status = ChallengeWindowStatus::AwaitingResponse;
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.active() && height <= self.expires_at_height
    }

    pub fn window_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-CHALLENGE-WINDOW",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.window_id, "challenge window id")?;
        ensure_non_empty(&self.claim_id, "challenge claim")?;
        ensure_non_empty(&self.lane_id, "challenge lane")?;
        ensure_non_empty(&self.challenger_id, "challenge challenger")?;
        ensure_non_empty(&self.accused_operator_id, "challenge accused")?;
        ensure_non_empty(&self.requested_action_root, "challenge requested action")?;
        ensure_non_empty(
            &self.watchdog_observation_root,
            "challenge watchdog observation root",
        )?;
        ensure_positive(self.quorum_weight, "challenge quorum weight")?;
        ensure_non_empty(&self.pq_quorum_root, "challenge pq quorum root")?;
        if self.response_due_height <= self.opened_at_height {
            return Err("challenge response due must be after open".to_string());
        }
        if self.resolve_after_height < self.response_due_height {
            return Err("challenge resolve height before response due".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("challenge expiry must be after open".to_string());
        }
        let expected_id = challenge_window_id(
            &self.claim_id,
            &self.challenger_id,
            self.opened_at_height,
            &self.requested_action_root,
        );
        if self.window_id != expected_id {
            return Err("challenge window id mismatch".to_string());
        }
        Ok(self.window_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "challenge_window",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "claim_id": self.claim_id,
            "lane_id": self.lane_id,
            "opened_at_height": self.opened_at_height,
            "response_due_height": self.response_due_height,
            "resolve_after_height": self.resolve_after_height,
            "expires_at_height": self.expires_at_height,
            "challenger_id": self.challenger_id,
            "accused_operator_id": self.accused_operator_id,
            "requested_action_root": self.requested_action_root,
            "operator_response_root": self.operator_response_root,
            "watchdog_observation_root": self.watchdog_observation_root,
            "status": self.status.as_str(),
            "quorum_weight": self.quorum_weight,
            "pq_quorum_root": self.pq_quorum_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub reason: SlashingReason,
    pub claim_id: Option<String>,
    pub challenge_window_id: Option<String>,
    pub accused_operator_id: String,
    pub reporter_id: String,
    pub before_root: String,
    pub after_root: String,
    pub statement_root: String,
    pub contradiction_root: String,
    pub observation_root: String,
    pub slash_bps: u64,
    pub bond_units: u64,
    pub slash_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SlashingStatus,
    pub pq_attestation_root: String,
}

impl SlashingEvidence {
    pub fn new(
        reason: SlashingReason,
        accused_operator_id: &str,
        reporter_id: &str,
        claim_id: Option<String>,
        challenge_window_id: Option<String>,
        before_root: &str,
        after_root: &str,
        statement: &Value,
        contradiction: &Value,
        observation_root: &str,
        slash_bps: u64,
        bond_units: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
        pq_attestation_root: &str,
    ) -> CensorshipResistanceResult<Self> {
        ensure_non_empty(accused_operator_id, "slashing accused operator")?;
        ensure_non_empty(reporter_id, "slashing reporter")?;
        ensure_non_empty(before_root, "slashing before root")?;
        ensure_non_empty(after_root, "slashing after root")?;
        ensure_non_empty(observation_root, "slashing observation root")?;
        ensure_bps(slash_bps, "slashing bps")?;
        ensure_positive(bond_units, "slashing bond units")?;
        ensure_positive(ttl_blocks, "slashing ttl")?;
        ensure_non_empty(pq_attestation_root, "slashing pq attestation")?;
        let statement_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-SLASHING-STATEMENT",
            statement,
        );
        let contradiction_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-SLASHING-CONTRADICTION",
            contradiction,
        );
        let evidence_id = slashing_evidence_id(
            reason,
            accused_operator_id,
            reporter_id,
            claim_id.as_deref(),
            challenge_window_id.as_deref(),
            opened_at_height,
            &contradiction_root,
        );
        let slash_units = bond_units.saturating_mul(slash_bps) / CENSORSHIP_RESISTANCE_MAX_BPS;
        Ok(Self {
            evidence_id,
            reason,
            claim_id,
            challenge_window_id,
            accused_operator_id: accused_operator_id.to_string(),
            reporter_id: reporter_id.to_string(),
            before_root: before_root.to_string(),
            after_root: after_root.to_string(),
            statement_root,
            contradiction_root,
            observation_root: observation_root.to_string(),
            slash_bps,
            bond_units,
            slash_units,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: SlashingStatus::Proposed,
            pq_attestation_root: pq_attestation_root.to_string(),
        })
    }

    pub fn evidence_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-SLASHING-EVIDENCE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.evidence_id, "slashing evidence id")?;
        ensure_non_empty(&self.accused_operator_id, "slashing accused operator")?;
        ensure_non_empty(&self.reporter_id, "slashing reporter")?;
        ensure_non_empty(&self.before_root, "slashing before root")?;
        ensure_non_empty(&self.after_root, "slashing after root")?;
        ensure_non_empty(&self.statement_root, "slashing statement root")?;
        ensure_non_empty(&self.contradiction_root, "slashing contradiction root")?;
        ensure_non_empty(&self.observation_root, "slashing observation root")?;
        ensure_bps(self.slash_bps, "slashing bps")?;
        ensure_positive(self.bond_units, "slashing bond units")?;
        ensure_non_empty(&self.pq_attestation_root, "slashing pq attestation")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("slashing evidence expiry must be after open".to_string());
        }
        let expected_units =
            self.bond_units.saturating_mul(self.slash_bps) / CENSORSHIP_RESISTANCE_MAX_BPS;
        if self.slash_units != expected_units {
            return Err("slashing evidence slash units mismatch".to_string());
        }
        let expected_id = slashing_evidence_id(
            self.reason,
            &self.accused_operator_id,
            &self.reporter_id,
            self.claim_id.as_deref(),
            self.challenge_window_id.as_deref(),
            self.opened_at_height,
            &self.contradiction_root,
        );
        if self.evidence_id != expected_id {
            return Err("slashing evidence id mismatch".to_string());
        }
        Ok(self.evidence_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "reason": self.reason.as_str(),
            "claim_id": self.claim_id,
            "challenge_window_id": self.challenge_window_id,
            "accused_operator_id": self.accused_operator_id,
            "reporter_id": self.reporter_id,
            "before_root": self.before_root,
            "after_root": self.after_root,
            "statement_root": self.statement_root,
            "contradiction_root": self.contradiction_root,
            "observation_root": self.observation_root,
            "slash_bps": self.slash_bps,
            "bond_units": self.bond_units,
            "slash_units": self.slash_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "pq_attestation_root": self.pq_attestation_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyBypassLane {
    pub bypass_id: String,
    pub lane_id: String,
    pub guardian_set_root: String,
    pub activation_reason_root: String,
    pub activated_by: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub max_batch_size: u64,
    pub consumed_receipt_ids: BTreeSet<String>,
    pub status: EmergencyBypassStatus,
    pub rescue_state_root: String,
    pub pq_guardian_auth_root: String,
}

impl EmergencyBypassLane {
    pub fn new(
        lane_id: &str,
        activated_by: &str,
        guardian_set: &Value,
        activation_reason: &Value,
        activated_at_height: u64,
        ttl_blocks: u64,
        max_batch_size: u64,
        rescue_state_root: &str,
        pq_guardian_auth_root: &str,
    ) -> CensorshipResistanceResult<Self> {
        ensure_non_empty(lane_id, "emergency bypass lane")?;
        ensure_non_empty(activated_by, "emergency bypass activator")?;
        ensure_positive(ttl_blocks, "emergency bypass ttl")?;
        ensure_positive(max_batch_size, "emergency bypass max batch")?;
        ensure_non_empty(rescue_state_root, "emergency bypass rescue state root")?;
        ensure_non_empty(pq_guardian_auth_root, "emergency bypass pq guardian auth")?;
        let guardian_set_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-EMERGENCY-GUARDIAN-SET",
            guardian_set,
        );
        let activation_reason_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-EMERGENCY-ACTIVATION-REASON",
            activation_reason,
        );
        let bypass_id = emergency_bypass_id(
            lane_id,
            activated_by,
            activated_at_height,
            &activation_reason_root,
        );
        Ok(Self {
            bypass_id,
            lane_id: lane_id.to_string(),
            guardian_set_root,
            activation_reason_root,
            activated_by: activated_by.to_string(),
            activated_at_height,
            expires_at_height: activated_at_height.saturating_add(ttl_blocks),
            max_batch_size,
            consumed_receipt_ids: BTreeSet::new(),
            status: EmergencyBypassStatus::Active,
            rescue_state_root: rescue_state_root.to_string(),
            pq_guardian_auth_root: pq_guardian_auth_root.to_string(),
        })
    }

    pub fn attach_receipt(
        &mut self,
        receipt_id: impl Into<String>,
    ) -> CensorshipResistanceResult<()> {
        if self.consumed_receipt_ids.len() as u64 >= self.max_batch_size {
            return Err("emergency bypass batch is full".to_string());
        }
        self.consumed_receipt_ids.insert(receipt_id.into());
        Ok(())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.accepts_receipts() && height <= self.expires_at_height
    }

    pub fn bypass_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-EMERGENCY-BYPASS",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.bypass_id, "emergency bypass id")?;
        ensure_non_empty(&self.lane_id, "emergency bypass lane")?;
        ensure_non_empty(&self.guardian_set_root, "emergency guardian set")?;
        ensure_non_empty(&self.activation_reason_root, "emergency activation reason")?;
        ensure_non_empty(&self.activated_by, "emergency activator")?;
        ensure_positive(self.max_batch_size, "emergency max batch")?;
        ensure_non_empty(&self.rescue_state_root, "emergency rescue state root")?;
        ensure_non_empty(&self.pq_guardian_auth_root, "emergency pq guardian auth")?;
        if self.expires_at_height <= self.activated_at_height {
            return Err("emergency bypass expiry must be after activation".to_string());
        }
        if self.consumed_receipt_ids.len() as u64 > self.max_batch_size {
            return Err("emergency bypass consumed receipts exceed max batch".to_string());
        }
        let expected_id = emergency_bypass_id(
            &self.lane_id,
            &self.activated_by,
            self.activated_at_height,
            &self.activation_reason_root,
        );
        if self.bypass_id != expected_id {
            return Err("emergency bypass id mismatch".to_string());
        }
        Ok(self.bypass_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_bypass_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "bypass_id": self.bypass_id,
            "lane_id": self.lane_id,
            "guardian_set_root": self.guardian_set_root,
            "activation_reason_root": self.activation_reason_root,
            "activated_by": self.activated_by,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "max_batch_size": self.max_batch_size,
            "consumed_receipt_ids": self.consumed_receipt_ids.iter().cloned().collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "rescue_state_root": self.rescue_state_root,
            "pq_guardian_auth_root": self.pq_guardian_auth_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeInclusionSponsor {
    pub sponsor_id: String,
    pub label: String,
    pub funding_account_commitment: String,
    pub asset_id: String,
    pub total_budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_micro_units: u64,
    pub eligible_lane_ids: BTreeSet<String>,
    pub status: SponsorshipStatus,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub pq_sponsor_auth_root: String,
    pub policy_root: String,
}

impl LowFeeInclusionSponsor {
    pub fn new(
        label: &str,
        funding_account_commitment: &str,
        asset_id: &str,
        total_budget_units: u64,
        max_fee_micro_units: u64,
        eligible_lane_ids: BTreeSet<String>,
        valid_from_height: u64,
        ttl_blocks: u64,
        policy: &Value,
        pq_sponsor_auth_root: &str,
    ) -> CensorshipResistanceResult<Self> {
        ensure_non_empty(label, "low fee sponsor label")?;
        ensure_non_empty(
            funding_account_commitment,
            "low fee sponsor funding account",
        )?;
        ensure_non_empty(asset_id, "low fee sponsor asset")?;
        ensure_positive(total_budget_units, "low fee sponsor budget")?;
        ensure_positive(max_fee_micro_units, "low fee sponsor max fee")?;
        ensure_positive(
            eligible_lane_ids.len() as u64,
            "low fee sponsor eligible lanes",
        )?;
        ensure_positive(ttl_blocks, "low fee sponsor ttl")?;
        ensure_non_empty(pq_sponsor_auth_root, "low fee sponsor pq auth")?;
        let policy_root =
            censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-SPONSOR-POLICY", policy);
        let sponsor_id = low_fee_sponsor_id(
            label,
            funding_account_commitment,
            asset_id,
            valid_from_height,
            &policy_root,
        );
        Ok(Self {
            sponsor_id,
            label: label.to_string(),
            funding_account_commitment: funding_account_commitment.to_string(),
            asset_id: asset_id.to_string(),
            total_budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_micro_units,
            eligible_lane_ids,
            status: SponsorshipStatus::Active,
            valid_from_height,
            expires_at_height: valid_from_height.saturating_add(ttl_blocks),
            pq_sponsor_auth_root: pq_sponsor_auth_root.to_string(),
            policy_root,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.total_budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.usable()
            && height >= self.valid_from_height
            && height <= self.expires_at_height
            && self.available_units() > 0
    }

    pub fn reserve_units(&mut self, units: u64) -> CensorshipResistanceResult<()> {
        ensure_positive(units, "low fee sponsor reserve")?;
        if units > self.available_units() {
            return Err("low fee sponsor budget exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        self.status = SponsorshipStatus::Reserved;
        Ok(())
    }

    pub fn spend_reserved(&mut self, units: u64) -> CensorshipResistanceResult<()> {
        ensure_positive(units, "low fee sponsor spend")?;
        if units > self.reserved_units {
            return Err("low fee sponsor spend exceeds reserved units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        if self.available_units() == 0 && self.reserved_units == 0 {
            self.status = SponsorshipStatus::Exhausted;
        }
        Ok(())
    }

    pub fn sponsor_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-LOW-FEE-SPONSOR",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.sponsor_id, "low fee sponsor id")?;
        ensure_non_empty(&self.label, "low fee sponsor label")?;
        ensure_non_empty(
            &self.funding_account_commitment,
            "low fee sponsor funding account",
        )?;
        ensure_non_empty(&self.asset_id, "low fee sponsor asset")?;
        ensure_positive(self.total_budget_units, "low fee sponsor budget")?;
        ensure_positive(self.max_fee_micro_units, "low fee sponsor max fee")?;
        ensure_positive(
            self.eligible_lane_ids.len() as u64,
            "low fee sponsor eligible lanes",
        )?;
        ensure_non_empty(&self.pq_sponsor_auth_root, "low fee sponsor pq auth")?;
        ensure_non_empty(&self.policy_root, "low fee sponsor policy root")?;
        if self.reserved_units.saturating_add(self.spent_units) > self.total_budget_units {
            return Err("low fee sponsor accounting exceeds budget".to_string());
        }
        if self.expires_at_height <= self.valid_from_height {
            return Err("low fee sponsor expiry must be after start".to_string());
        }
        let expected_id = low_fee_sponsor_id(
            &self.label,
            &self.funding_account_commitment,
            &self.asset_id,
            self.valid_from_height,
            &self.policy_root,
        );
        if self.sponsor_id != expected_id {
            return Err("low fee sponsor id mismatch".to_string());
        }
        Ok(self.sponsor_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_inclusion_sponsor",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "policy_version": CENSORSHIP_RESISTANCE_LOW_FEE_POLICY_VERSION,
            "sponsor_id": self.sponsor_id,
            "label": self.label,
            "funding_account_commitment": self.funding_account_commitment,
            "asset_id": self.asset_id,
            "total_budget_units": self.total_budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_micro_units": self.max_fee_micro_units,
            "eligible_lane_ids": self.eligible_lane_ids.iter().cloned().collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "pq_sponsor_auth_root": self.pq_sponsor_auth_root,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorshipTicket {
    pub ticket_id: String,
    pub sponsor_id: String,
    pub receipt_id: String,
    pub lane_id: String,
    pub beneficiary_commitment: String,
    pub max_fee_micro_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
    pub nullifier: String,
    pub privacy_budget_root: String,
}

impl LowFeeSponsorshipTicket {
    pub fn reserve(
        sponsor: &LowFeeInclusionSponsor,
        receipt: &EncryptedIntentReceipt,
        beneficiary_commitment: &str,
        reserved_units: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
        privacy_budget: &Value,
    ) -> CensorshipResistanceResult<Self> {
        sponsor.validate()?;
        receipt.validate()?;
        ensure_non_empty(beneficiary_commitment, "sponsorship ticket beneficiary")?;
        ensure_positive(reserved_units, "sponsorship ticket reserve")?;
        ensure_positive(ttl_blocks, "sponsorship ticket ttl")?;
        if reserved_units > sponsor.available_units() {
            return Err("sponsorship ticket exceeds sponsor available budget".to_string());
        }
        if receipt.max_fee_micro_units > sponsor.max_fee_micro_units {
            return Err("sponsorship ticket receipt fee exceeds sponsor policy".to_string());
        }
        if !sponsor.eligible_lane_ids.contains(&receipt.lane_id) {
            return Err("sponsorship ticket lane is not sponsor eligible".to_string());
        }
        let privacy_budget_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-SPONSORSHIP-PRIVACY-BUDGET",
            privacy_budget,
        );
        let nullifier = low_fee_sponsorship_nullifier(
            &sponsor.sponsor_id,
            &receipt.receipt_id,
            beneficiary_commitment,
            &privacy_budget_root,
        );
        let ticket_id = low_fee_sponsorship_ticket_id(
            &sponsor.sponsor_id,
            &receipt.receipt_id,
            beneficiary_commitment,
            issued_at_height,
            &privacy_budget_root,
        );
        Ok(Self {
            ticket_id,
            sponsor_id: sponsor.sponsor_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            lane_id: receipt.lane_id.clone(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            max_fee_micro_units: sponsor.max_fee_micro_units,
            reserved_units,
            spent_units: 0,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
            status: SponsorshipStatus::Reserved,
            nullifier,
            privacy_budget_root,
        })
    }

    pub fn spend(&mut self, units: u64) -> CensorshipResistanceResult<()> {
        ensure_positive(units, "sponsorship ticket spend")?;
        if self.spent_units.saturating_add(units) > self.reserved_units {
            return Err("sponsorship ticket spend exceeds reserve".to_string());
        }
        self.spent_units = self.spent_units.saturating_add(units);
        if self.spent_units == self.reserved_units {
            self.status = SponsorshipStatus::Spent;
        }
        Ok(())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.usable() && height <= self.expires_at_height
    }

    pub fn ticket_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-SPONSORSHIP-TICKET",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.ticket_id, "sponsorship ticket id")?;
        ensure_non_empty(&self.sponsor_id, "sponsorship ticket sponsor")?;
        ensure_non_empty(&self.receipt_id, "sponsorship ticket receipt")?;
        ensure_non_empty(&self.lane_id, "sponsorship ticket lane")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "sponsorship ticket beneficiary",
        )?;
        ensure_positive(self.max_fee_micro_units, "sponsorship ticket max fee")?;
        ensure_positive(self.reserved_units, "sponsorship ticket reserve")?;
        ensure_non_empty(&self.nullifier, "sponsorship ticket nullifier")?;
        ensure_non_empty(
            &self.privacy_budget_root,
            "sponsorship ticket privacy budget",
        )?;
        if self.spent_units > self.reserved_units {
            return Err("sponsorship ticket spent units exceed reserved units".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("sponsorship ticket expiry must be after issue".to_string());
        }
        let expected_nullifier = low_fee_sponsorship_nullifier(
            &self.sponsor_id,
            &self.receipt_id,
            &self.beneficiary_commitment,
            &self.privacy_budget_root,
        );
        if self.nullifier != expected_nullifier {
            return Err("sponsorship ticket nullifier mismatch".to_string());
        }
        let expected_id = low_fee_sponsorship_ticket_id(
            &self.sponsor_id,
            &self.receipt_id,
            &self.beneficiary_commitment,
            self.issued_at_height,
            &self.privacy_budget_root,
        );
        if self.ticket_id != expected_id {
            return Err("sponsorship ticket id mismatch".to_string());
        }
        Ok(self.ticket_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsorship_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "sponsor_id": self.sponsor_id,
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "nullifier": self.nullifier,
            "privacy_budget_root": self.privacy_budget_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairnessScorecardTotals {
    pub total_seen: u64,
    pub total_included: u64,
    pub total_omitted: u64,
    pub forced_due_count: u64,
    pub forced_included_count: u64,
    pub low_fee_due_count: u64,
    pub low_fee_included_count: u64,
    pub median_inclusion_blocks: u64,
    pub p95_inclusion_blocks: u64,
}

impl FairnessScorecardTotals {
    pub fn public_record(&self) -> Value {
        json!({
            "total_seen": self.total_seen,
            "total_included": self.total_included,
            "total_omitted": self.total_omitted,
            "forced_due_count": self.forced_due_count,
            "forced_included_count": self.forced_included_count,
            "low_fee_due_count": self.low_fee_due_count,
            "low_fee_included_count": self.low_fee_included_count,
            "median_inclusion_blocks": self.median_inclusion_blocks,
            "p95_inclusion_blocks": self.p95_inclusion_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairnessScorecard {
    pub scorecard_id: String,
    pub operator_id: String,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub lane_root: String,
    pub included_receipt_root: String,
    pub omitted_receipt_root: String,
    pub low_fee_receipt_root: String,
    pub emergency_receipt_root: String,
    pub totals: FairnessScorecardTotals,
    pub censorship_risk_bps: u64,
    pub fairness_score_bps: u64,
    pub grade: FairnessGrade,
    pub pq_audit_root: String,
}

impl FairnessScorecard {
    pub fn new(
        operator_id: &str,
        epoch_start_height: u64,
        epoch_end_height: u64,
        lane_root: &str,
        included_receipt_root: &str,
        omitted_receipt_root: &str,
        low_fee_receipt_root: &str,
        emergency_receipt_root: &str,
        totals: FairnessScorecardTotals,
        pq_audit_root: &str,
    ) -> CensorshipResistanceResult<Self> {
        ensure_non_empty(operator_id, "fairness scorecard operator")?;
        ensure_non_empty(lane_root, "fairness lane root")?;
        ensure_non_empty(included_receipt_root, "fairness included root")?;
        ensure_non_empty(omitted_receipt_root, "fairness omitted root")?;
        ensure_non_empty(low_fee_receipt_root, "fairness low fee root")?;
        ensure_non_empty(emergency_receipt_root, "fairness emergency root")?;
        ensure_non_empty(pq_audit_root, "fairness pq audit root")?;
        if epoch_end_height < epoch_start_height {
            return Err("fairness scorecard epoch end before start".to_string());
        }
        if totals.total_included.saturating_add(totals.total_omitted) > totals.total_seen {
            return Err("fairness scorecard totals exceed seen receipts".to_string());
        }
        if totals.forced_included_count > totals.forced_due_count {
            return Err("fairness forced included exceeds forced due".to_string());
        }
        if totals.low_fee_included_count > totals.low_fee_due_count {
            return Err("fairness low fee included exceeds low fee due".to_string());
        }
        let inclusion_ratio = ratio_bps(totals.total_included, totals.total_seen);
        let forced_ratio = ratio_bps_or_full(totals.forced_included_count, totals.forced_due_count);
        let low_fee_ratio =
            ratio_bps_or_full(totals.low_fee_included_count, totals.low_fee_due_count);
        let latency_penalty = totals
            .p95_inclusion_blocks
            .saturating_sub(4)
            .saturating_mul(250)
            .min(4_000);
        let omission_penalty = ratio_bps(totals.total_omitted, totals.total_seen) / 2;
        let latency_score = CENSORSHIP_RESISTANCE_MAX_BPS.saturating_sub(latency_penalty);
        let weighted_score = inclusion_ratio
            .saturating_mul(4)
            .saturating_add(forced_ratio.saturating_mul(3))
            .saturating_add(low_fee_ratio.saturating_mul(2))
            .saturating_add(latency_score)
            / 10;
        let fairness_score_bps = weighted_score.saturating_sub(omission_penalty);
        let censorship_risk_bps = CENSORSHIP_RESISTANCE_MAX_BPS.saturating_sub(fairness_score_bps);
        let grade = FairnessGrade::from_score_bps(fairness_score_bps);
        let scorecard_id = fairness_scorecard_id(
            operator_id,
            epoch_start_height,
            epoch_end_height,
            lane_root,
            pq_audit_root,
        );
        Ok(Self {
            scorecard_id,
            operator_id: operator_id.to_string(),
            epoch_start_height,
            epoch_end_height,
            lane_root: lane_root.to_string(),
            included_receipt_root: included_receipt_root.to_string(),
            omitted_receipt_root: omitted_receipt_root.to_string(),
            low_fee_receipt_root: low_fee_receipt_root.to_string(),
            emergency_receipt_root: emergency_receipt_root.to_string(),
            totals,
            censorship_risk_bps,
            fairness_score_bps,
            grade,
            pq_audit_root: pq_audit_root.to_string(),
        })
    }

    pub fn scorecard_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-FAIRNESS-SCORECARD",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.scorecard_id, "fairness scorecard id")?;
        ensure_non_empty(&self.operator_id, "fairness operator")?;
        ensure_non_empty(&self.lane_root, "fairness lane root")?;
        ensure_non_empty(&self.included_receipt_root, "fairness included root")?;
        ensure_non_empty(&self.omitted_receipt_root, "fairness omitted root")?;
        ensure_non_empty(&self.low_fee_receipt_root, "fairness low fee root")?;
        ensure_non_empty(&self.emergency_receipt_root, "fairness emergency root")?;
        ensure_bps(self.censorship_risk_bps, "fairness risk")?;
        ensure_bps(self.fairness_score_bps, "fairness score")?;
        ensure_non_empty(&self.pq_audit_root, "fairness pq audit")?;
        if self.epoch_end_height < self.epoch_start_height {
            return Err("fairness scorecard epoch end before start".to_string());
        }
        if self
            .totals
            .total_included
            .saturating_add(self.totals.total_omitted)
            > self.totals.total_seen
        {
            return Err("fairness scorecard totals exceed seen receipts".to_string());
        }
        let expected_id = fairness_scorecard_id(
            &self.operator_id,
            self.epoch_start_height,
            self.epoch_end_height,
            &self.lane_root,
            &self.pq_audit_root,
        );
        if self.scorecard_id != expected_id {
            return Err("fairness scorecard id mismatch".to_string());
        }
        Ok(self.scorecard_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fairness_scorecard",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "policy_version": CENSORSHIP_RESISTANCE_FAIRNESS_POLICY_VERSION,
            "scorecard_id": self.scorecard_id,
            "operator_id": self.operator_id,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "lane_root": self.lane_root,
            "included_receipt_root": self.included_receipt_root,
            "omitted_receipt_root": self.omitted_receipt_root,
            "low_fee_receipt_root": self.low_fee_receipt_root,
            "emergency_receipt_root": self.emergency_receipt_root,
            "totals": self.totals.public_record(),
            "censorship_risk_bps": self.censorship_risk_bps,
            "fairness_score_bps": self.fairness_score_bps,
            "grade": self.grade.as_str(),
            "pq_audit_root": self.pq_audit_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatchtowerAttestation {
    pub attestation_id: String,
    pub attestation_kind: PqWatchtowerAttestationKind,
    pub watchtower_id: String,
    pub operator_id: String,
    pub lane_id: Option<String>,
    pub receipt_id: Option<String>,
    pub claim_id: Option<String>,
    pub height: u64,
    pub observed_state_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub backup_signature_root: String,
    pub key_epoch: u64,
    pub weight: u64,
    pub status: AttestationStatus,
}

impl PqWatchtowerAttestation {
    pub fn new(
        attestation_kind: PqWatchtowerAttestationKind,
        watchtower_id: &str,
        operator_id: &str,
        lane_id: Option<String>,
        receipt_id: Option<String>,
        claim_id: Option<String>,
        height: u64,
        observed_state: &Value,
        transcript: &Value,
        pq_signature_root: &str,
        backup_signature_root: &str,
        key_epoch: u64,
        weight: u64,
    ) -> CensorshipResistanceResult<Self> {
        ensure_non_empty(watchtower_id, "pq attestation watchtower")?;
        ensure_non_empty(operator_id, "pq attestation operator")?;
        ensure_non_empty(pq_signature_root, "pq attestation signature")?;
        ensure_non_empty(backup_signature_root, "pq attestation backup signature")?;
        ensure_positive(weight, "pq attestation weight")?;
        let observed_state_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-PQ-OBSERVED-STATE",
            observed_state,
        );
        let transcript_root =
            censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-PQ-TRANSCRIPT", transcript);
        let attestation_id = pq_watchtower_attestation_id(
            attestation_kind,
            watchtower_id,
            operator_id,
            lane_id.as_deref(),
            receipt_id.as_deref(),
            claim_id.as_deref(),
            height,
            &transcript_root,
        );
        Ok(Self {
            attestation_id,
            attestation_kind,
            watchtower_id: watchtower_id.to_string(),
            operator_id: operator_id.to_string(),
            lane_id,
            receipt_id,
            claim_id,
            height,
            observed_state_root,
            transcript_root,
            pq_signature_root: pq_signature_root.to_string(),
            backup_signature_root: backup_signature_root.to_string(),
            key_epoch,
            weight,
            status: AttestationStatus::Pending,
        })
    }

    pub fn attestation_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-PQ-WATCHTOWER-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.attestation_id, "pq attestation id")?;
        ensure_non_empty(&self.watchtower_id, "pq attestation watchtower")?;
        ensure_non_empty(&self.operator_id, "pq attestation operator")?;
        ensure_non_empty(&self.observed_state_root, "pq attestation observed state")?;
        ensure_non_empty(&self.transcript_root, "pq attestation transcript")?;
        ensure_non_empty(&self.pq_signature_root, "pq attestation signature")?;
        ensure_non_empty(
            &self.backup_signature_root,
            "pq attestation backup signature",
        )?;
        ensure_positive(self.weight, "pq attestation weight")?;
        let expected_id = pq_watchtower_attestation_id(
            self.attestation_kind,
            &self.watchtower_id,
            &self.operator_id,
            self.lane_id.as_deref(),
            self.receipt_id.as_deref(),
            self.claim_id.as_deref(),
            self.height,
            &self.transcript_root,
        );
        if self.attestation_id != expected_id {
            return Err("pq attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_watchtower_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "pq_watchtower_scheme": CENSORSHIP_RESISTANCE_PQ_WATCHTOWER_SCHEME,
            "attestation_id": self.attestation_id,
            "attestation_kind": self.attestation_kind.as_str(),
            "watchtower_id": self.watchtower_id,
            "operator_id": self.operator_id,
            "lane_id": self.lane_id,
            "receipt_id": self.receipt_id,
            "claim_id": self.claim_id,
            "height": self.height,
            "observed_state_root": self.observed_state_root,
            "transcript_root": self.transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "backup_signature_root": self.backup_signature_root,
            "key_epoch": self.key_epoch,
            "weight": self.weight,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensorshipPublicRecord {
    pub record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub payload_root: String,
    pub redaction_root: String,
    pub height: u64,
}

impl CensorshipPublicRecord {
    pub fn new(
        object_kind: &str,
        object_id: &str,
        payload: &Value,
        redaction: &Value,
        height: u64,
    ) -> CensorshipResistanceResult<Self> {
        ensure_non_empty(object_kind, "public record object kind")?;
        ensure_non_empty(object_id, "public record object id")?;
        let payload_root =
            censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-PUBLIC-PAYLOAD", payload);
        let redaction_root =
            censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-PUBLIC-REDACTION", redaction);
        let record_id = censorship_public_record_id(object_kind, object_id, height, &payload_root);
        Ok(Self {
            record_id,
            object_kind: object_kind.to_string(),
            object_id: object_id.to_string(),
            payload_root,
            redaction_root,
            height,
        })
    }

    pub fn record_root(&self) -> String {
        censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-PUBLIC-RECORD",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.object_kind, "public record object kind")?;
        ensure_non_empty(&self.object_id, "public record object id")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        ensure_non_empty(&self.redaction_root, "public record redaction root")?;
        let expected_id = censorship_public_record_id(
            &self.object_kind,
            &self.object_id,
            self.height,
            &self.payload_root,
        );
        if self.record_id != expected_id {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "censorship_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "payload_root": self.payload_root,
            "redaction_root": self.redaction_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensorshipResistanceRoots {
    pub config_root: String,
    pub lane_root: String,
    pub encrypted_receipt_root: String,
    pub omission_claim_root: String,
    pub watchdog_observation_root: String,
    pub private_relay_receipt_root: String,
    pub challenge_window_root: String,
    pub slashing_evidence_root: String,
    pub emergency_bypass_root: String,
    pub low_fee_sponsor_root: String,
    pub sponsorship_ticket_root: String,
    pub fairness_scorecard_root: String,
    pub pq_watchtower_attestation_root: String,
    pub replay_nullifier_root: String,
    pub public_record_root: String,
    pub due_receipt_root: String,
    pub active_emergency_bypass_root: String,
    pub state_root: String,
}

impl CensorshipResistanceRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "omission_claim_root": self.omission_claim_root,
            "watchdog_observation_root": self.watchdog_observation_root,
            "private_relay_receipt_root": self.private_relay_receipt_root,
            "challenge_window_root": self.challenge_window_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "emergency_bypass_root": self.emergency_bypass_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "sponsorship_ticket_root": self.sponsorship_ticket_root,
            "fairness_scorecard_root": self.fairness_scorecard_root,
            "pq_watchtower_attestation_root": self.pq_watchtower_attestation_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "public_record_root": self.public_record_root,
            "due_receipt_root": self.due_receipt_root,
            "active_emergency_bypass_root": self.active_emergency_bypass_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensorshipResistanceCounters {
    pub height: u64,
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub encrypted_receipt_count: u64,
    pub pending_receipt_count: u64,
    pub included_receipt_count: u64,
    pub omitted_receipt_count: u64,
    pub expired_receipt_count: u64,
    pub due_receipt_count: u64,
    pub omission_claim_count: u64,
    pub open_claim_count: u64,
    pub accepted_claim_count: u64,
    pub watchdog_observation_count: u64,
    pub accepted_watchdog_observation_count: u64,
    pub private_relay_receipt_count: u64,
    pub delayed_private_relay_receipt_count: u64,
    pub challenge_window_count: u64,
    pub open_challenge_window_count: u64,
    pub slashing_evidence_count: u64,
    pub accepted_slashing_evidence_count: u64,
    pub emergency_bypass_count: u64,
    pub active_emergency_bypass_count: u64,
    pub low_fee_sponsor_count: u64,
    pub active_low_fee_sponsor_count: u64,
    pub sponsorship_ticket_count: u64,
    pub active_sponsorship_ticket_count: u64,
    pub fairness_scorecard_count: u64,
    pub pq_watchtower_attestation_count: u64,
    pub accepted_pq_attestation_count: u64,
    pub replay_nullifier_count: u64,
    pub public_record_count: u64,
    pub total_payload_bytes: u64,
    pub total_fee_micro_units: u64,
    pub total_sponsor_budget_units: u64,
    pub total_sponsor_reserved_units: u64,
    pub total_sponsor_spent_units: u64,
    pub aggregate_watchtower_weight: u64,
    pub average_fairness_score_bps: u64,
}

impl CensorshipResistanceCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "lane_count": self.lane_count,
            "active_lane_count": self.active_lane_count,
            "encrypted_receipt_count": self.encrypted_receipt_count,
            "pending_receipt_count": self.pending_receipt_count,
            "included_receipt_count": self.included_receipt_count,
            "omitted_receipt_count": self.omitted_receipt_count,
            "expired_receipt_count": self.expired_receipt_count,
            "due_receipt_count": self.due_receipt_count,
            "omission_claim_count": self.omission_claim_count,
            "open_claim_count": self.open_claim_count,
            "accepted_claim_count": self.accepted_claim_count,
            "watchdog_observation_count": self.watchdog_observation_count,
            "accepted_watchdog_observation_count": self.accepted_watchdog_observation_count,
            "private_relay_receipt_count": self.private_relay_receipt_count,
            "delayed_private_relay_receipt_count": self.delayed_private_relay_receipt_count,
            "challenge_window_count": self.challenge_window_count,
            "open_challenge_window_count": self.open_challenge_window_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "accepted_slashing_evidence_count": self.accepted_slashing_evidence_count,
            "emergency_bypass_count": self.emergency_bypass_count,
            "active_emergency_bypass_count": self.active_emergency_bypass_count,
            "low_fee_sponsor_count": self.low_fee_sponsor_count,
            "active_low_fee_sponsor_count": self.active_low_fee_sponsor_count,
            "sponsorship_ticket_count": self.sponsorship_ticket_count,
            "active_sponsorship_ticket_count": self.active_sponsorship_ticket_count,
            "fairness_scorecard_count": self.fairness_scorecard_count,
            "pq_watchtower_attestation_count": self.pq_watchtower_attestation_count,
            "accepted_pq_attestation_count": self.accepted_pq_attestation_count,
            "replay_nullifier_count": self.replay_nullifier_count,
            "public_record_count": self.public_record_count,
            "total_payload_bytes": self.total_payload_bytes,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_sponsor_budget_units": self.total_sponsor_budget_units,
            "total_sponsor_reserved_units": self.total_sponsor_reserved_units,
            "total_sponsor_spent_units": self.total_sponsor_spent_units,
            "aggregate_watchtower_weight": self.aggregate_watchtower_weight,
            "average_fairness_score_bps": self.average_fairness_score_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensorshipResistanceState {
    pub height: u64,
    pub operator_label: String,
    pub config: CensorshipResistanceConfig,
    pub lanes: BTreeMap<String, ForcedInclusionLane>,
    pub encrypted_intent_receipts: BTreeMap<String, EncryptedIntentReceipt>,
    pub omission_claims: BTreeMap<String, OmissionClaim>,
    pub watchdog_observations: BTreeMap<String, WatchdogObservation>,
    pub private_relay_receipts: BTreeMap<String, PrivateRelayReceipt>,
    pub challenge_windows: BTreeMap<String, ChallengeWindow>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub emergency_bypass_lanes: BTreeMap<String, EmergencyBypassLane>,
    pub low_fee_sponsors: BTreeMap<String, LowFeeInclusionSponsor>,
    pub sponsorship_tickets: BTreeMap<String, LowFeeSponsorshipTicket>,
    pub fairness_scorecards: BTreeMap<String, FairnessScorecard>,
    pub pq_watchtower_attestations: BTreeMap<String, PqWatchtowerAttestation>,
    pub consumed_replay_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, CensorshipPublicRecord>,
}

impl CensorshipResistanceState {
    pub fn new(
        operator_label: impl Into<String>,
        config: CensorshipResistanceConfig,
    ) -> CensorshipResistanceResult<Self> {
        config.validate()?;
        let operator_label = operator_label.into();
        ensure_non_empty(&operator_label, "censorship resistance operator label")?;
        Ok(Self {
            height: 0,
            operator_label,
            config,
            lanes: BTreeMap::new(),
            encrypted_intent_receipts: BTreeMap::new(),
            omission_claims: BTreeMap::new(),
            watchdog_observations: BTreeMap::new(),
            private_relay_receipts: BTreeMap::new(),
            challenge_windows: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            emergency_bypass_lanes: BTreeMap::new(),
            low_fee_sponsors: BTreeMap::new(),
            sponsorship_tickets: BTreeMap::new(),
            fairness_scorecards: BTreeMap::new(),
            pq_watchtower_attestations: BTreeMap::new(),
            consumed_replay_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> CensorshipResistanceResult<Self> {
        let mut state = Self::new(
            CENSORSHIP_RESISTANCE_DEVNET_LABEL,
            CensorshipResistanceConfig::devnet(),
        )?;
        state.set_height(32);

        let mut private_lane = ForcedInclusionLane::new(
            ForcedInclusionLaneKind::PrivateTransfer,
            "devnet-private-forced-lane",
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            ForcedInclusionLaneKind::PrivateTransfer.default_min_share_bps(),
            2_048,
            4,
            9_000,
            1,
            state.config.forced_lane_ttl_blocks,
            &json!({
                "privacy": "ciphertext_roots_only",
                "relay": "private_mempool",
                "target": "fast_private_transfer",
            }),
        )?;
        private_lane.attach_watchtower(CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID);
        let private_lane_id = state.insert_lane(private_lane)?;

        let mut bridge_lane = ForcedInclusionLane::new(
            ForcedInclusionLaneKind::MoneroBridgeExit,
            "devnet-monero-bridge-forced-lane",
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            ForcedInclusionLaneKind::MoneroBridgeExit.default_min_share_bps(),
            1_024,
            6,
            state.config.low_fee_max_fee_micro_units,
            1,
            state.config.forced_lane_ttl_blocks,
            &json!({
                "privacy": "destination_hash_only",
                "monero_finality": "devnet",
                "sponsored": true,
            }),
        )?;
        bridge_lane.attach_watchtower(CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID);
        let bridge_lane_id = state.insert_lane(bridge_lane)?;

        let mut low_fee_lane = ForcedInclusionLane::new(
            ForcedInclusionLaneKind::LowFeeSponsored,
            "devnet-low-fee-inclusion-lane",
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            ForcedInclusionLaneKind::LowFeeSponsored.default_min_share_bps(),
            4_096,
            8,
            state.config.low_fee_max_fee_micro_units,
            1,
            state.config.forced_lane_ttl_blocks,
            &json!({
                "privacy": "payer_commitments_only",
                "fee_policy": "sponsor_pool",
                "batching": "cheap-but-deadline-bound",
            }),
        )?;
        low_fee_lane.attach_watchtower(CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID);
        let low_fee_lane_id = state.insert_lane(low_fee_lane)?;

        let mut emergency_lane = ForcedInclusionLane::new(
            ForcedInclusionLaneKind::EmergencyBypass,
            "devnet-emergency-bypass-lane",
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            ForcedInclusionLaneKind::EmergencyBypass.default_min_share_bps(),
            512,
            1,
            15_000,
            1,
            state.config.forced_lane_ttl_blocks,
            &json!({
                "guardian_set": "devnet-rescue-committee",
                "privacy": "minimal-public-roots",
                "activation": "watchtower-quorum",
            }),
        )?;
        emergency_lane.attach_watchtower(CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID);
        let emergency_lane_id = state.insert_lane(emergency_lane)?;

        let sponsor = LowFeeInclusionSponsor::new(
            "devnet-low-fee-inclusion-sponsor",
            "commitment:devnet-sponsor-funding-account",
            CENSORSHIP_RESISTANCE_DEVNET_FEE_ASSET_ID,
            3_000_000,
            state.config.low_fee_max_fee_micro_units,
            btree_set([bridge_lane_id.as_str(), low_fee_lane_id.as_str()]),
            1,
            720,
            &json!({
                "beneficiaries": "wallet_commitments",
                "max_claims_per_block": 128,
                "privacy_budget": "aggregate-only",
            }),
            &devnet_pq_root("sponsor-auth", "devnet-low-fee-inclusion-sponsor"),
        )?;
        let sponsor_id = state.register_low_fee_sponsor(sponsor)?;
        if let Some(lane) = state.lanes.get_mut(&bridge_lane_id) {
            lane.attach_sponsor(sponsor_id.clone());
        }
        if let Some(lane) = state.lanes.get_mut(&low_fee_lane_id) {
            lane.attach_sponsor(sponsor_id.clone());
        }

        let alice_receipt = EncryptedIntentReceipt::new(
            &private_lane_id,
            "commitment:alice-submit",
            "private_transfer",
            &json!({
                "ciphertext": "devnet-alice-private-transfer",
                "note_commitment": "alice-note-001",
                "amount_bucket": "medium",
            }),
            2_048,
            8_500,
            1,
            30,
            34,
            state.config.encrypted_receipt_ttl_blocks,
            &devnet_pq_root("sender-auth", "alice-private-transfer"),
            &json!({"view_tag": "encrypted", "speed": "fast"}),
        )?;
        let alice_receipt_id = state.submit_encrypted_intent(alice_receipt)?;

        let bob_receipt = EncryptedIntentReceipt::new(
            &bridge_lane_id,
            "commitment:bob-submit",
            "monero_bridge_exit_low_fee",
            &json!({
                "ciphertext": "devnet-bob-bridge-exit",
                "destination_hash": "monero-destination-root",
                "amount_bucket": "small",
            }),
            2_560,
            1_900,
            2,
            20,
            28,
            state.config.encrypted_receipt_ttl_blocks,
            &devnet_pq_root("sender-auth", "bob-bridge-exit"),
            &json!({"fee": "sponsored", "privacy": "destination_hash_only"}),
        )?;
        let bob_receipt_id = state.submit_encrypted_intent(bob_receipt)?;

        let carol_receipt = EncryptedIntentReceipt::new(
            &emergency_lane_id,
            "commitment:carol-submit",
            "wallet_recovery_emergency_exit",
            &json!({
                "ciphertext": "devnet-carol-emergency-exit",
                "recovery_root": "carol-recovery-root",
                "guardian_hint": "devnet-rescue-committee",
            }),
            3_072,
            12_000,
            3,
            31,
            32,
            state.config.encrypted_receipt_ttl_blocks,
            &devnet_pq_root("sender-auth", "carol-emergency-exit"),
            &json!({"emergency": true, "bypass": "allowed"}),
        )?;
        let carol_receipt_id = state.submit_encrypted_intent(carol_receipt)?;

        let dave_receipt = EncryptedIntentReceipt::new(
            &low_fee_lane_id,
            "commitment:dave-submit",
            "low_fee_private_payment",
            &json!({
                "ciphertext": "devnet-dave-low-fee-payment",
                "recipient_view_tag": "encrypted",
                "amount_bucket": "tiny",
            }),
            1_536,
            1_250,
            4,
            31,
            39,
            state.config.encrypted_receipt_ttl_blocks,
            &devnet_pq_root("sender-auth", "dave-low-fee-payment"),
            &json!({"low_fee": true, "sponsor_optional": true}),
        )?;
        let dave_receipt_id = state.submit_encrypted_intent(dave_receipt)?;

        let bob_ticket_id = state.reserve_sponsorship(
            &sponsor_id,
            &bob_receipt_id,
            "beneficiary:bob-wallet-commitment",
            1_800,
            &json!({
                "bucket": "small-bridge-exit",
                "public_disclosure": "aggregate-only",
            }),
        )?;
        let dave_ticket_id = state.reserve_sponsorship(
            &sponsor_id,
            &dave_receipt_id,
            "beneficiary:dave-wallet-commitment",
            1_000,
            &json!({
                "bucket": "tiny-private-payment",
                "public_disclosure": "none",
            }),
        )?;

        let alice_relay = {
            let receipt = state
                .encrypted_intent_receipts
                .get(&alice_receipt_id)
                .ok_or_else(|| "devnet alice receipt missing".to_string())?;
            PrivateRelayReceipt::new(
                receipt,
                "devnet-private-relay-a",
                PrivateRelayReceiptKind::PrivateRelay,
                30,
                30,
                state.config.private_relay_receipt_ttl_blocks,
                &json!({"route": ["wallet", "private-relay", "sequencer"], "sealed": true}),
                &json!({"fee_micro_units": 8_500, "quote": "accepted"}),
                &json!({"witness": "alice-ingress-root"}),
                3,
                115,
                false,
                &devnet_pq_root("relay-handshake", "private-relay-a"),
                &json!({"ack": "fast"}),
            )?
        };
        let _alice_relay_id = state.record_private_relay_receipt(alice_relay)?;

        let bob_relay = {
            let receipt = state
                .encrypted_intent_receipts
                .get(&bob_receipt_id)
                .ok_or_else(|| "devnet bob receipt missing".to_string())?;
            PrivateRelayReceipt::new(
                receipt,
                "devnet-bridge-relay-a",
                PrivateRelayReceiptKind::SponsorIngress,
                20,
                21,
                state.config.private_relay_receipt_ttl_blocks,
                &json!({"route": ["wallet", "sponsor-edge", "bridge-relay"], "sealed": true}),
                &json!({"fee_micro_units": 1_900, "sponsor_ticket_id": bob_ticket_id}),
                &json!({"witness": "bob-bridge-ingress-root"}),
                3,
                1_240,
                true,
                &devnet_pq_root("relay-handshake", "bridge-relay-a"),
                &json!({"ack": "late-but-before-omission-claim"}),
            )?
        };
        let bob_relay_id = state.record_private_relay_receipt(bob_relay)?;

        let carol_relay = {
            let receipt = state
                .encrypted_intent_receipts
                .get(&carol_receipt_id)
                .ok_or_else(|| "devnet carol receipt missing".to_string())?;
            PrivateRelayReceipt::new(
                receipt,
                "devnet-emergency-relay-a",
                PrivateRelayReceiptKind::EmergencyBypass,
                31,
                31,
                state.config.private_relay_receipt_ttl_blocks,
                &json!({"route": ["wallet", "guardian-relay"], "sealed": true}),
                &json!({"fee_micro_units": 12_000, "emergency": true}),
                &json!({"witness": "carol-emergency-ingress-root"}),
                2,
                80,
                false,
                &devnet_pq_root("relay-handshake", "emergency-relay-a"),
                &json!({"ack": "guardian-fast-path"}),
            )?
        };
        state.record_private_relay_receipt(carol_relay)?;

        if let Some(receipt) = state.encrypted_intent_receipts.get_mut(&alice_receipt_id) {
            receipt.mark_included();
        }

        let prior_root = state.state_root();
        let observed_missing_root = censorship_resistance_payload_root(
            "CENSORSHIP-RESISTANCE-DEVNET-OBSERVED-MISSING-BLOCK",
            &json!({
                "height": 32,
                "missing_receipt": bob_receipt_id,
                "sequencer_batch": "batch-32",
            }),
        );

        let bob_seen_observation = WatchdogObservation::new(
            WatchdogObservationKind::MempoolSeen,
            CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID,
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            Some(bridge_lane_id.clone()),
            Some(bob_receipt_id.clone()),
            21,
            1,
            8,
            &json!({"receipt_id": bob_receipt_id, "relay_receipt_id": bob_relay_id}),
            &prior_root,
            &observed_missing_root,
            &devnet_pq_root("watchdog-observation", "bob-seen"),
            9_500,
            80,
        )?;
        let bob_seen_id = state.record_watchdog_observation(bob_seen_observation)?;

        let bob_missing_observation = WatchdogObservation::new(
            WatchdogObservationKind::BlockMissing,
            CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID,
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            Some(bridge_lane_id.clone()),
            Some(bob_receipt_id.clone()),
            32,
            12,
            11,
            &json!({
                "receipt_id": bob_receipt_id,
                "deadline": 28,
                "included": false,
                "batch_root": observed_missing_root,
            }),
            &prior_root,
            &observed_missing_root,
            &devnet_pq_root("watchdog-observation", "bob-missing"),
            9_800,
            120,
        )?;
        let bob_missing_id = state.record_watchdog_observation(bob_missing_observation)?;

        let pq_liveness = PqWatchtowerAttestation::new(
            PqWatchtowerAttestationKind::RelayLiveness,
            CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID,
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            Some(bridge_lane_id.clone()),
            Some(bob_receipt_id.clone()),
            None,
            32,
            &json!({"state_root": observed_missing_root, "relay": "bridge-relay-a"}),
            &json!({"transcript": "bob-bridge-relay-liveness", "height": 32}),
            &devnet_pq_root("ml-dsa-signature", "bob-relay-liveness"),
            &devnet_pq_root("slh-dsa-signature", "bob-relay-liveness"),
            1,
            120,
        )?;
        state.insert_pq_watchtower_attestation(pq_liveness)?;

        let bob_receipt = state
            .encrypted_intent_receipts
            .get(&bob_receipt_id)
            .ok_or_else(|| "devnet bob receipt missing for claim".to_string())?
            .clone();
        let claim = OmissionClaim::new(
            OmissionClaimKind::DeadlineMissed,
            &bob_receipt,
            CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID,
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            32,
            28,
            btree_set([bob_seen_id.as_str(), bob_missing_id.as_str()]),
            btree_set([bob_relay_id.as_str()]),
            &json!({
                "receipt_id": bob_receipt_id,
                "required_lane": bridge_lane_id,
                "deadline_height": 28,
            }),
            &json!({
                "block_height": 32,
                "receipt_absent": true,
                "public_batch_root": observed_missing_root,
            }),
            &json!({
                "redaction": "ciphertext roots only",
                "fee": "sponsored",
                "sponsor_ticket_id": bob_ticket_id,
            }),
            25_000,
            &devnet_pq_root("claimant-auth", "bob-deadline-claim"),
        )?;
        let claim_id = state.open_omission_claim(claim)?;

        let claim_root = state
            .omission_claims
            .get(&claim_id)
            .map(OmissionClaim::claim_root)
            .ok_or_else(|| "devnet claim root missing".to_string())?;
        let pq_omission = PqWatchtowerAttestation::new(
            PqWatchtowerAttestationKind::OmissionWitness,
            CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID,
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            Some(bridge_lane_id.clone()),
            Some(bob_receipt_id.clone()),
            Some(claim_id.clone()),
            32,
            &json!({"claim_root": claim_root, "watchtower": "accepted"}),
            &json!({"transcript": "bob-omission-witness", "height": 32}),
            &devnet_pq_root("ml-dsa-signature", "bob-omission-witness"),
            &devnet_pq_root("slh-dsa-signature", "bob-omission-witness"),
            1,
            140,
        )?;
        state.insert_pq_watchtower_attestation(pq_omission)?;

        let challenge = {
            let claim = state
                .omission_claims
                .get(&claim_id)
                .ok_or_else(|| "devnet claim missing for challenge".to_string())?;
            ChallengeWindow::new(
                claim,
                "devnet-challenger-bob-watchtower",
                33,
                8,
                8,
                state.config.challenge_window_blocks,
                &json!({
                    "action": "include_or_slash",
                    "receipt_id": bob_receipt_id,
                    "sponsor_ticket_id": bob_ticket_id,
                }),
                &state.watchdog_observation_root(),
                200,
                &devnet_pq_root("watchtower-quorum", "bob-challenge"),
            )?
        };
        let challenge_id = state.open_challenge_window(challenge)?;

        let mut bypass = EmergencyBypassLane::new(
            &emergency_lane_id,
            "devnet-rescue-committee",
            &json!({
                "guardians": [
                    "devnet-guardian-a",
                    "devnet-guardian-b",
                    "devnet-guardian-c"
                ],
                "threshold": 2,
            }),
            &json!({
                "reason": "emergency_wallet_recovery",
                "receipt_id": carol_receipt_id,
            }),
            32,
            state.config.emergency_bypass_window_blocks,
            64,
            &devnet_pq_root("rescue-state", "carol-emergency"),
            &devnet_pq_root("guardian-auth", "carol-emergency"),
        )?;
        bypass.attach_receipt(carol_receipt_id.clone())?;
        let bypass_id = state.activate_emergency_bypass(bypass)?;
        state.attach_receipt_to_emergency_bypass(&bypass_id, &carol_receipt_id)?;

        let observation_root = state.watchdog_observation_root();
        let mut slash = SlashingEvidence::new(
            SlashingReason::Omission,
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID,
            Some(claim_id.clone()),
            Some(challenge_id.clone()),
            &prior_root,
            &state.state_root(),
            &json!({
                "sequencer_statement": "bridge lane was empty",
                "height": 32,
            }),
            &json!({
                "watchtower_seen": bob_seen_id,
                "receipt_id": bob_receipt_id,
                "private_relay_receipt": bob_relay_id,
            }),
            &observation_root,
            state.config.slash_bps_omission,
            state.config.min_operator_bond_units,
            34,
            state.config.challenge_window_blocks,
            &devnet_pq_root("slashing-attestation", "bob-omission"),
        )?;
        slash.status = SlashingStatus::Accepted;
        state.record_slashing_evidence(slash)?;

        state.settle_sponsorship_ticket(&dave_ticket_id, 900)?;

        let totals = FairnessScorecardTotals {
            total_seen: 4,
            total_included: 2,
            total_omitted: 1,
            forced_due_count: 2,
            forced_included_count: 1,
            low_fee_due_count: 2,
            low_fee_included_count: 1,
            median_inclusion_blocks: 3,
            p95_inclusion_blocks: 12,
        };
        let scorecard = FairnessScorecard::new(
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            1,
            32,
            &state.lane_root(),
            &state.included_receipt_root(),
            &state.omitted_receipt_root(),
            &state.low_fee_receipt_root(),
            &state.emergency_receipt_root(),
            totals,
            &devnet_pq_root("fairness-audit", "epoch-1"),
        )?;
        let scorecard_id = state.insert_fairness_scorecard(scorecard)?;

        let fairness_attestation = PqWatchtowerAttestation::new(
            PqWatchtowerAttestationKind::FairnessCheckpoint,
            CENSORSHIP_RESISTANCE_DEVNET_WATCHTOWER_ID,
            CENSORSHIP_RESISTANCE_DEVNET_OPERATOR_ID,
            None,
            None,
            Some(claim_id.clone()),
            32,
            &json!({"scorecard_id": scorecard_id, "state_root": state.state_root()}),
            &json!({"transcript": "fairness-epoch-1", "claims": [claim_id]}),
            &devnet_pq_root("ml-dsa-signature", "fairness-epoch-1"),
            &devnet_pq_root("slh-dsa-signature", "fairness-epoch-1"),
            1,
            160,
        )?;
        state.insert_pq_watchtower_attestation(fairness_attestation)?;

        let lane_payload = state
            .lanes
            .get(&private_lane_id)
            .map(ForcedInclusionLane::public_record)
            .ok_or_else(|| "devnet lane public record source missing".to_string())?;
        state.publish_public_record(
            "lane",
            &private_lane_id,
            &lane_payload,
            &json!({
                "redact_ciphertexts": true,
                "retain_roots": true,
                "privacy": "public-accountability-without-payload-disclosure",
            }),
        )?;

        let claim_payload = state
            .omission_claims
            .get(&claim_id)
            .map(OmissionClaim::public_record)
            .ok_or_else(|| "devnet omission claim public record source missing".to_string())?;
        state.publish_public_record(
            "omission_claim",
            &claim_id,
            &claim_payload,
            &json!({
                "redact_ciphertexts": true,
                "retain_roots": true,
                "privacy": "public-accountability-without-payload-disclosure",
            }),
        )?;

        let scorecard_payload = state
            .fairness_scorecards
            .get(&scorecard_id)
            .map(FairnessScorecard::public_record)
            .ok_or_else(|| "devnet fairness public record source missing".to_string())?;
        state.publish_public_record(
            "fairness_scorecard",
            &scorecard_id,
            &scorecard_payload,
            &json!({
                "redact_ciphertexts": true,
                "retain_roots": true,
                "privacy": "public-accountability-without-payload-disclosure",
            }),
        )?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.expire_records();
    }

    pub fn insert_lane(&mut self, lane: ForcedInclusionLane) -> CensorshipResistanceResult<String> {
        lane.validate()?;
        if self.lanes.len() >= CENSORSHIP_RESISTANCE_MAX_LANES {
            return Err("too many forced inclusion lanes".to_string());
        }
        let lane_id = lane.lane_id.clone();
        if self.lanes.contains_key(&lane_id) {
            return Err("forced inclusion lane already exists".to_string());
        }
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn submit_encrypted_intent(
        &mut self,
        mut receipt: EncryptedIntentReceipt,
    ) -> CensorshipResistanceResult<String> {
        receipt.validate()?;
        if self.encrypted_intent_receipts.len() >= CENSORSHIP_RESISTANCE_MAX_RECEIPTS {
            return Err("too many encrypted intent receipts".to_string());
        }
        let lane = self
            .lanes
            .get(&receipt.lane_id)
            .ok_or_else(|| "encrypted intent references unknown lane".to_string())?;
        if !lane.active_at(self.height) {
            return Err("encrypted intent lane is not active".to_string());
        }
        if receipt.payload_size_bytes > self.config.max_payload_bytes {
            return Err("encrypted intent payload exceeds configured maximum".to_string());
        }
        if receipt.max_fee_micro_units > lane.max_fee_micro_units {
            return Err("encrypted intent fee exceeds lane maximum".to_string());
        }
        if self
            .consumed_replay_nullifiers
            .contains(&receipt.replay_nullifier)
        {
            return Err("encrypted intent replay nullifier already consumed".to_string());
        }
        if receipt.is_expired(self.height) {
            receipt.status = EncryptedIntentReceiptStatus::Expired;
        } else {
            receipt.status = EncryptedIntentReceiptStatus::Acknowledged;
        }
        let receipt_id = receipt.receipt_id.clone();
        self.consumed_replay_nullifiers
            .insert(receipt.replay_nullifier.clone());
        self.encrypted_intent_receipts
            .insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn record_private_relay_receipt(
        &mut self,
        mut relay_receipt: PrivateRelayReceipt,
    ) -> CensorshipResistanceResult<String> {
        relay_receipt.validate()?;
        if self.private_relay_receipts.len() >= CENSORSHIP_RESISTANCE_MAX_RELAY_RECEIPTS {
            return Err("too many private relay receipts".to_string());
        }
        if !self
            .encrypted_intent_receipts
            .contains_key(&relay_receipt.receipt_id)
        {
            return Err("private relay receipt references unknown intent".to_string());
        }
        if !self.lanes.contains_key(&relay_receipt.lane_id) {
            return Err("private relay receipt references unknown lane".to_string());
        }
        if relay_receipt.is_expired(self.height) {
            relay_receipt.status = RelayReceiptStatus::Expired;
        }
        let relay_receipt_id = relay_receipt.relay_receipt_id.clone();
        if let Some(receipt) = self
            .encrypted_intent_receipts
            .get_mut(&relay_receipt.receipt_id)
        {
            receipt.relay_receipt_id = Some(relay_receipt_id.clone());
            if receipt.status.open() {
                receipt.status = EncryptedIntentReceiptStatus::Scheduled;
            }
        }
        self.private_relay_receipts
            .insert(relay_receipt_id.clone(), relay_receipt);
        Ok(relay_receipt_id)
    }

    pub fn record_watchdog_observation(
        &mut self,
        mut observation: WatchdogObservation,
    ) -> CensorshipResistanceResult<String> {
        observation.validate()?;
        if self.watchdog_observations.len() >= CENSORSHIP_RESISTANCE_MAX_WATCHDOG_OBSERVATIONS {
            return Err("too many watchdog observations".to_string());
        }
        if let Some(lane_id) = &observation.lane_id {
            if !self.lanes.contains_key(lane_id) {
                return Err("watchdog observation references unknown lane".to_string());
            }
        }
        if let Some(receipt_id) = &observation.receipt_id {
            if !self.encrypted_intent_receipts.contains_key(receipt_id) {
                return Err("watchdog observation references unknown receipt".to_string());
            }
        }
        if observation
            .observed_height
            .saturating_add(self.config.watchdog_stale_blocks)
            < self.height
        {
            observation.status = ObservationStatus::Expired;
        } else if observation.confidence_bps >= 8_000 {
            observation.status = ObservationStatus::Accepted;
        }
        let observation_id = observation.observation_id.clone();
        self.watchdog_observations
            .insert(observation_id.clone(), observation);
        Ok(observation_id)
    }

    pub fn open_omission_claim(
        &mut self,
        claim: OmissionClaim,
    ) -> CensorshipResistanceResult<String> {
        claim.validate()?;
        if self.omission_claims.len() >= CENSORSHIP_RESISTANCE_MAX_OMISSION_CLAIMS {
            return Err("too many omission claims".to_string());
        }
        if !self
            .encrypted_intent_receipts
            .contains_key(&claim.receipt_id)
        {
            return Err("omission claim references unknown receipt".to_string());
        }
        if !self.lanes.contains_key(&claim.lane_id) {
            return Err("omission claim references unknown lane".to_string());
        }
        for observation_id in &claim.watchdog_observation_ids {
            if !self.watchdog_observations.contains_key(observation_id) {
                return Err("omission claim references unknown watchdog observation".to_string());
            }
        }
        for relay_receipt_id in &claim.relay_receipt_ids {
            if !self.private_relay_receipts.contains_key(relay_receipt_id) {
                return Err("omission claim references unknown private relay receipt".to_string());
            }
        }
        let claim_id = claim.claim_id.clone();
        if let Some(receipt) = self.encrypted_intent_receipts.get_mut(&claim.receipt_id) {
            receipt.status = EncryptedIntentReceiptStatus::Omitted;
        }
        self.omission_claims.insert(claim_id.clone(), claim);
        Ok(claim_id)
    }

    pub fn open_challenge_window(
        &mut self,
        challenge: ChallengeWindow,
    ) -> CensorshipResistanceResult<String> {
        challenge.validate()?;
        if self.challenge_windows.len() >= CENSORSHIP_RESISTANCE_MAX_CHALLENGE_WINDOWS {
            return Err("too many challenge windows".to_string());
        }
        if !self.omission_claims.contains_key(&challenge.claim_id) {
            return Err("challenge window references unknown claim".to_string());
        }
        let receipt_id = self
            .omission_claims
            .get(&challenge.claim_id)
            .map(|claim| claim.receipt_id.clone())
            .ok_or_else(|| "challenge window references unknown claim".to_string())?;
        let challenge_id = challenge.window_id.clone();
        if let Some(claim) = self.omission_claims.get_mut(&challenge.claim_id) {
            claim.status = OmissionClaimStatus::Challenged;
            claim.challenge_window_id = Some(challenge_id.clone());
        }
        if let Some(receipt) = self.encrypted_intent_receipts.get_mut(&receipt_id) {
            receipt.status = EncryptedIntentReceiptStatus::Challenged;
        }
        self.challenge_windows
            .insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn record_slashing_evidence(
        &mut self,
        evidence: SlashingEvidence,
    ) -> CensorshipResistanceResult<String> {
        evidence.validate()?;
        if self.slashing_evidence.len() >= CENSORSHIP_RESISTANCE_MAX_SLASHING_EVIDENCE {
            return Err("too much slashing evidence".to_string());
        }
        if let Some(claim_id) = &evidence.claim_id {
            if !self.omission_claims.contains_key(claim_id) {
                return Err("slashing evidence references unknown claim".to_string());
            }
        }
        if let Some(window_id) = &evidence.challenge_window_id {
            if !self.challenge_windows.contains_key(window_id) {
                return Err("slashing evidence references unknown challenge window".to_string());
            }
        }
        let evidence_id = evidence.evidence_id.clone();
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn activate_emergency_bypass(
        &mut self,
        bypass: EmergencyBypassLane,
    ) -> CensorshipResistanceResult<String> {
        bypass.validate()?;
        if !self.config.enable_emergency_bypass {
            return Err("emergency bypass disabled".to_string());
        }
        if self.emergency_bypass_lanes.len() >= CENSORSHIP_RESISTANCE_MAX_EMERGENCY_BYPASSES {
            return Err("too many emergency bypass lanes".to_string());
        }
        let lane = self
            .lanes
            .get(&bypass.lane_id)
            .ok_or_else(|| "emergency bypass references unknown lane".to_string())?;
        if !lane.emergency_bypass {
            return Err("emergency bypass references non-emergency lane".to_string());
        }
        let bypass_id = bypass.bypass_id.clone();
        self.emergency_bypass_lanes
            .insert(bypass_id.clone(), bypass);
        Ok(bypass_id)
    }

    pub fn attach_receipt_to_emergency_bypass(
        &mut self,
        bypass_id: &str,
        receipt_id: &str,
    ) -> CensorshipResistanceResult<()> {
        let bypass = self
            .emergency_bypass_lanes
            .get_mut(bypass_id)
            .ok_or_else(|| "emergency bypass not found".to_string())?;
        if !bypass.active_at(self.height) {
            return Err("emergency bypass is not active".to_string());
        }
        let receipt = self
            .encrypted_intent_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| "emergency bypass receipt not found".to_string())?;
        if receipt.lane_id != bypass.lane_id {
            return Err("emergency bypass receipt lane mismatch".to_string());
        }
        bypass.attach_receipt(receipt_id.to_string())?;
        receipt.emergency_bypass_id = Some(bypass_id.to_string());
        receipt.mark_rescued();
        Ok(())
    }

    pub fn register_low_fee_sponsor(
        &mut self,
        sponsor: LowFeeInclusionSponsor,
    ) -> CensorshipResistanceResult<String> {
        sponsor.validate()?;
        if !self.config.enable_low_fee_sponsorship {
            return Err("low fee sponsorship disabled".to_string());
        }
        if self.low_fee_sponsors.len() >= CENSORSHIP_RESISTANCE_MAX_SPONSORS {
            return Err("too many low fee sponsors".to_string());
        }
        if sponsor.total_budget_units < self.config.low_fee_sponsor_min_balance_units {
            return Err("low fee sponsor budget below configured minimum".to_string());
        }
        for lane_id in &sponsor.eligible_lane_ids {
            if !self.lanes.contains_key(lane_id) {
                return Err("low fee sponsor references unknown lane".to_string());
            }
        }
        let sponsor_id = sponsor.sponsor_id.clone();
        self.low_fee_sponsors.insert(sponsor_id.clone(), sponsor);
        Ok(sponsor_id)
    }

    pub fn reserve_sponsorship(
        &mut self,
        sponsor_id: &str,
        receipt_id: &str,
        beneficiary_commitment: &str,
        reserved_units: u64,
        privacy_budget: &Value,
    ) -> CensorshipResistanceResult<String> {
        if !self.config.enable_low_fee_sponsorship {
            return Err("low fee sponsorship disabled".to_string());
        }
        let sponsor_snapshot = self
            .low_fee_sponsors
            .get(sponsor_id)
            .cloned()
            .ok_or_else(|| "sponsorship references unknown sponsor".to_string())?;
        let receipt_snapshot = self
            .encrypted_intent_receipts
            .get(receipt_id)
            .cloned()
            .ok_or_else(|| "sponsorship references unknown receipt".to_string())?;
        let ticket = LowFeeSponsorshipTicket::reserve(
            &sponsor_snapshot,
            &receipt_snapshot,
            beneficiary_commitment,
            reserved_units,
            self.height,
            self.config.encrypted_receipt_ttl_blocks,
            privacy_budget,
        )?;
        if self.consumed_replay_nullifiers.contains(&ticket.nullifier) {
            return Err("sponsorship ticket nullifier already consumed".to_string());
        }
        let sponsor = self
            .low_fee_sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| "sponsorship sponsor disappeared".to_string())?;
        sponsor.reserve_units(reserved_units)?;
        let ticket_id = ticket.ticket_id.clone();
        if let Some(receipt) = self.encrypted_intent_receipts.get_mut(receipt_id) {
            receipt.low_fee_sponsor_ticket_id = Some(ticket_id.clone());
        }
        self.consumed_replay_nullifiers
            .insert(ticket.nullifier.clone());
        self.sponsorship_tickets.insert(ticket_id.clone(), ticket);
        Ok(ticket_id)
    }

    pub fn settle_sponsorship_ticket(
        &mut self,
        ticket_id: &str,
        spent_units: u64,
    ) -> CensorshipResistanceResult<()> {
        let sponsor_id = self
            .sponsorship_tickets
            .get(ticket_id)
            .map(|ticket| ticket.sponsor_id.clone())
            .ok_or_else(|| "sponsorship ticket not found".to_string())?;
        {
            let ticket = self
                .sponsorship_tickets
                .get_mut(ticket_id)
                .ok_or_else(|| "sponsorship ticket not found".to_string())?;
            ticket.spend(spent_units)?;
        }
        let sponsor = self
            .low_fee_sponsors
            .get_mut(&sponsor_id)
            .ok_or_else(|| "sponsorship ticket sponsor missing".to_string())?;
        sponsor.spend_reserved(spent_units)?;
        Ok(())
    }

    pub fn insert_fairness_scorecard(
        &mut self,
        scorecard: FairnessScorecard,
    ) -> CensorshipResistanceResult<String> {
        scorecard.validate()?;
        if self.fairness_scorecards.len() >= CENSORSHIP_RESISTANCE_MAX_SCORECARDS {
            return Err("too many fairness scorecards".to_string());
        }
        let scorecard_id = scorecard.scorecard_id.clone();
        self.fairness_scorecards
            .insert(scorecard_id.clone(), scorecard);
        Ok(scorecard_id)
    }

    pub fn insert_pq_watchtower_attestation(
        &mut self,
        mut attestation: PqWatchtowerAttestation,
    ) -> CensorshipResistanceResult<String> {
        attestation.validate()?;
        if !self.config.enable_pq_watchtower_attestations {
            return Err("pq watchtower attestations disabled".to_string());
        }
        if self.pq_watchtower_attestations.len() >= CENSORSHIP_RESISTANCE_MAX_PQ_ATTESTATIONS {
            return Err("too many pq watchtower attestations".to_string());
        }
        if let Some(lane_id) = &attestation.lane_id {
            if !self.lanes.contains_key(lane_id) {
                return Err("pq attestation references unknown lane".to_string());
            }
        }
        if let Some(receipt_id) = &attestation.receipt_id {
            if !self.encrypted_intent_receipts.contains_key(receipt_id) {
                return Err("pq attestation references unknown receipt".to_string());
            }
        }
        if let Some(claim_id) = &attestation.claim_id {
            if !self.omission_claims.contains_key(claim_id) {
                return Err("pq attestation references unknown claim".to_string());
            }
        }
        if attestation.weight >= self.config.min_pq_attestation_weight {
            attestation.status = AttestationStatus::Accepted;
        }
        let attestation_id = attestation.attestation_id.clone();
        self.pq_watchtower_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn publish_public_record(
        &mut self,
        object_kind: &str,
        object_id: &str,
        payload: &Value,
        redaction: &Value,
    ) -> CensorshipResistanceResult<String> {
        if self.public_records.len() >= CENSORSHIP_RESISTANCE_MAX_PUBLIC_RECORDS {
            return Err("too many public censorship records".to_string());
        }
        let record =
            CensorshipPublicRecord::new(object_kind, object_id, payload, redaction, self.height)?;
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    pub fn expire_records(&mut self) {
        for lane in self.lanes.values_mut() {
            if self.height > lane.expires_at_height && lane.status.accepts_intents() {
                lane.status = LaneStatus::Retired;
            }
        }
        for receipt in self.encrypted_intent_receipts.values_mut() {
            if receipt.is_expired(self.height) && receipt.status.open() {
                receipt.status = EncryptedIntentReceiptStatus::Expired;
            }
        }
        for relay_receipt in self.private_relay_receipts.values_mut() {
            if relay_receipt.is_expired(self.height) {
                relay_receipt.status = RelayReceiptStatus::Expired;
            }
        }
        for observation in self.watchdog_observations.values_mut() {
            if observation
                .observed_height
                .saturating_add(self.config.watchdog_stale_blocks)
                < self.height
                && observation.status == ObservationStatus::Recorded
            {
                observation.status = ObservationStatus::Expired;
            }
        }
        for claim in self.omission_claims.values_mut() {
            if claim
                .opened_at_height
                .saturating_add(self.config.challenge_window_blocks)
                < self.height
                && claim.status.active()
            {
                claim.status = OmissionClaimStatus::Expired;
            }
        }
        for window in self.challenge_windows.values_mut() {
            if self.height > window.expires_at_height && window.status.active() {
                window.status = ChallengeWindowStatus::Expired;
            }
        }
        for evidence in self.slashing_evidence.values_mut() {
            if self.height > evidence.expires_at_height
                && evidence.status == SlashingStatus::Proposed
            {
                evidence.status = SlashingStatus::Expired;
            }
        }
        for bypass in self.emergency_bypass_lanes.values_mut() {
            if self.height > bypass.expires_at_height && bypass.status.accepts_receipts() {
                bypass.status = EmergencyBypassStatus::Expired;
            }
        }
        for sponsor in self.low_fee_sponsors.values_mut() {
            if self.height > sponsor.expires_at_height && sponsor.status.usable() {
                sponsor.status = SponsorshipStatus::Expired;
            }
            if sponsor.available_units() == 0 && sponsor.reserved_units == 0 {
                sponsor.status = SponsorshipStatus::Exhausted;
            }
        }
        for ticket in self.sponsorship_tickets.values_mut() {
            if self.height > ticket.expires_at_height && ticket.status.usable() {
                ticket.status = SponsorshipStatus::Expired;
            }
        }
    }

    pub fn lane_root(&self) -> String {
        forced_inclusion_lane_root_from_map(&self.lanes)
    }

    pub fn encrypted_receipt_root(&self) -> String {
        encrypted_intent_receipt_root_from_map(&self.encrypted_intent_receipts)
    }

    pub fn omission_claim_root(&self) -> String {
        omission_claim_root_from_map(&self.omission_claims)
    }

    pub fn watchdog_observation_root(&self) -> String {
        watchdog_observation_root_from_map(&self.watchdog_observations)
    }

    pub fn private_relay_receipt_root(&self) -> String {
        private_relay_receipt_root_from_map(&self.private_relay_receipts)
    }

    pub fn challenge_window_root(&self) -> String {
        challenge_window_root_from_map(&self.challenge_windows)
    }

    pub fn slashing_evidence_root(&self) -> String {
        slashing_evidence_root_from_map(&self.slashing_evidence)
    }

    pub fn emergency_bypass_root(&self) -> String {
        emergency_bypass_root_from_map(&self.emergency_bypass_lanes)
    }

    pub fn low_fee_sponsor_root(&self) -> String {
        low_fee_sponsor_root_from_map(&self.low_fee_sponsors)
    }

    pub fn sponsorship_ticket_root(&self) -> String {
        low_fee_sponsorship_ticket_root_from_map(&self.sponsorship_tickets)
    }

    pub fn fairness_scorecard_root(&self) -> String {
        fairness_scorecard_root_from_map(&self.fairness_scorecards)
    }

    pub fn pq_watchtower_attestation_root(&self) -> String {
        pq_watchtower_attestation_root_from_map(&self.pq_watchtower_attestations)
    }

    pub fn due_receipt_root(&self) -> String {
        let leaves = self
            .encrypted_intent_receipts
            .values()
            .filter(|receipt| receipt.due_at(self.height))
            .map(EncryptedIntentReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("CENSORSHIP-RESISTANCE-DUE-RECEIPTS", &leaves)
    }

    pub fn included_receipt_root(&self) -> String {
        let leaves = self
            .encrypted_intent_receipts
            .values()
            .filter(|receipt| receipt.status == EncryptedIntentReceiptStatus::Included)
            .map(EncryptedIntentReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("CENSORSHIP-RESISTANCE-INCLUDED-RECEIPTS", &leaves)
    }

    pub fn omitted_receipt_root(&self) -> String {
        let leaves = self
            .encrypted_intent_receipts
            .values()
            .filter(|receipt| {
                matches!(
                    receipt.status,
                    EncryptedIntentReceiptStatus::Omitted
                        | EncryptedIntentReceiptStatus::Challenged
                )
            })
            .map(EncryptedIntentReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("CENSORSHIP-RESISTANCE-OMITTED-RECEIPTS", &leaves)
    }

    pub fn low_fee_receipt_root(&self) -> String {
        let leaves = self
            .encrypted_intent_receipts
            .values()
            .filter(|receipt| receipt.low_fee_sponsor_ticket_id.is_some())
            .map(EncryptedIntentReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("CENSORSHIP-RESISTANCE-LOW-FEE-RECEIPTS", &leaves)
    }

    pub fn emergency_receipt_root(&self) -> String {
        let leaves = self
            .encrypted_intent_receipts
            .values()
            .filter(|receipt| receipt.emergency_bypass_id.is_some())
            .map(EncryptedIntentReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("CENSORSHIP-RESISTANCE-EMERGENCY-RECEIPTS", &leaves)
    }

    pub fn active_emergency_bypass_root(&self) -> String {
        let leaves = self
            .emergency_bypass_lanes
            .values()
            .filter(|bypass| bypass.active_at(self.height))
            .map(EmergencyBypassLane::public_record)
            .collect::<Vec<_>>();
        merkle_root("CENSORSHIP-RESISTANCE-ACTIVE-EMERGENCY-BYPASSES", &leaves)
    }

    pub fn replay_nullifier_root(&self) -> String {
        let leaves = self
            .consumed_replay_nullifiers
            .iter()
            .cloned()
            .map(Value::String)
            .collect::<Vec<_>>();
        merkle_root("CENSORSHIP-RESISTANCE-REPLAY-NULLIFIERS", &leaves)
    }

    pub fn public_record_root(&self) -> String {
        censorship_public_record_root_from_map(&self.public_records)
    }

    pub fn roots(&self) -> CensorshipResistanceRoots {
        let config_root = self.config.config_root();
        let lane_root = self.lane_root();
        let encrypted_receipt_root = self.encrypted_receipt_root();
        let omission_claim_root = self.omission_claim_root();
        let watchdog_observation_root = self.watchdog_observation_root();
        let private_relay_receipt_root = self.private_relay_receipt_root();
        let challenge_window_root = self.challenge_window_root();
        let slashing_evidence_root = self.slashing_evidence_root();
        let emergency_bypass_root = self.emergency_bypass_root();
        let low_fee_sponsor_root = self.low_fee_sponsor_root();
        let sponsorship_ticket_root = self.sponsorship_ticket_root();
        let fairness_scorecard_root = self.fairness_scorecard_root();
        let pq_watchtower_attestation_root = self.pq_watchtower_attestation_root();
        let replay_nullifier_root = self.replay_nullifier_root();
        let public_record_root = self.public_record_root();
        let due_receipt_root = self.due_receipt_root();
        let active_emergency_bypass_root = self.active_emergency_bypass_root();
        let state_record = json!({
            "kind": "censorship_resistance_state_root_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "schema_version": CENSORSHIP_RESISTANCE_SCHEMA_VERSION,
            "height": self.height,
            "operator_label_root": censorship_resistance_string_root(
                "CENSORSHIP-RESISTANCE-OPERATOR-LABEL",
                &self.operator_label,
            ),
            "config_root": config_root,
            "lane_root": lane_root,
            "encrypted_receipt_root": encrypted_receipt_root,
            "omission_claim_root": omission_claim_root,
            "watchdog_observation_root": watchdog_observation_root,
            "private_relay_receipt_root": private_relay_receipt_root,
            "challenge_window_root": challenge_window_root,
            "slashing_evidence_root": slashing_evidence_root,
            "emergency_bypass_root": emergency_bypass_root,
            "low_fee_sponsor_root": low_fee_sponsor_root,
            "sponsorship_ticket_root": sponsorship_ticket_root,
            "fairness_scorecard_root": fairness_scorecard_root,
            "pq_watchtower_attestation_root": pq_watchtower_attestation_root,
            "replay_nullifier_root": replay_nullifier_root,
            "public_record_root": public_record_root,
            "due_receipt_root": due_receipt_root,
            "active_emergency_bypass_root": active_emergency_bypass_root,
            "counters": self.counters().public_record(),
        });
        let state_root = censorship_resistance_state_root_from_record(&state_record);
        CensorshipResistanceRoots {
            config_root,
            lane_root,
            encrypted_receipt_root,
            omission_claim_root,
            watchdog_observation_root,
            private_relay_receipt_root,
            challenge_window_root,
            slashing_evidence_root,
            emergency_bypass_root,
            low_fee_sponsor_root,
            sponsorship_ticket_root,
            fairness_scorecard_root,
            pq_watchtower_attestation_root,
            replay_nullifier_root,
            public_record_root,
            due_receipt_root,
            active_emergency_bypass_root,
            state_root,
        }
    }

    pub fn counters(&self) -> CensorshipResistanceCounters {
        let mut counters = CensorshipResistanceCounters {
            height: self.height,
            lane_count: self.lanes.len() as u64,
            encrypted_receipt_count: self.encrypted_intent_receipts.len() as u64,
            omission_claim_count: self.omission_claims.len() as u64,
            watchdog_observation_count: self.watchdog_observations.len() as u64,
            private_relay_receipt_count: self.private_relay_receipts.len() as u64,
            challenge_window_count: self.challenge_windows.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            emergency_bypass_count: self.emergency_bypass_lanes.len() as u64,
            low_fee_sponsor_count: self.low_fee_sponsors.len() as u64,
            sponsorship_ticket_count: self.sponsorship_tickets.len() as u64,
            fairness_scorecard_count: self.fairness_scorecards.len() as u64,
            pq_watchtower_attestation_count: self.pq_watchtower_attestations.len() as u64,
            replay_nullifier_count: self.consumed_replay_nullifiers.len() as u64,
            public_record_count: self.public_records.len() as u64,
            ..CensorshipResistanceCounters::default()
        };
        for lane in self.lanes.values() {
            if lane.active_at(self.height) {
                counters.active_lane_count = counters.active_lane_count.saturating_add(1);
            }
        }
        for receipt in self.encrypted_intent_receipts.values() {
            counters.total_payload_bytes = counters
                .total_payload_bytes
                .saturating_add(receipt.payload_size_bytes);
            counters.total_fee_micro_units = counters
                .total_fee_micro_units
                .saturating_add(receipt.max_fee_micro_units);
            if receipt.due_at(self.height) {
                counters.due_receipt_count = counters.due_receipt_count.saturating_add(1);
            }
            match receipt.status {
                EncryptedIntentReceiptStatus::Submitted
                | EncryptedIntentReceiptStatus::Acknowledged
                | EncryptedIntentReceiptStatus::Scheduled => {
                    counters.pending_receipt_count =
                        counters.pending_receipt_count.saturating_add(1)
                }
                EncryptedIntentReceiptStatus::Included | EncryptedIntentReceiptStatus::Rescued => {
                    counters.included_receipt_count =
                        counters.included_receipt_count.saturating_add(1)
                }
                EncryptedIntentReceiptStatus::Omitted
                | EncryptedIntentReceiptStatus::Challenged => {
                    counters.omitted_receipt_count =
                        counters.omitted_receipt_count.saturating_add(1)
                }
                EncryptedIntentReceiptStatus::Expired => {
                    counters.expired_receipt_count =
                        counters.expired_receipt_count.saturating_add(1)
                }
            }
        }
        for claim in self.omission_claims.values() {
            if claim.status.active() {
                counters.open_claim_count = counters.open_claim_count.saturating_add(1);
            }
            if claim.status == OmissionClaimStatus::Accepted {
                counters.accepted_claim_count = counters.accepted_claim_count.saturating_add(1);
            }
        }
        for observation in self.watchdog_observations.values() {
            counters.aggregate_watchtower_weight = counters
                .aggregate_watchtower_weight
                .saturating_add(observation.weight);
            if observation.status == ObservationStatus::Accepted {
                counters.accepted_watchdog_observation_count = counters
                    .accepted_watchdog_observation_count
                    .saturating_add(1);
            }
        }
        for relay_receipt in self.private_relay_receipts.values() {
            if relay_receipt.status == RelayReceiptStatus::Delayed {
                counters.delayed_private_relay_receipt_count = counters
                    .delayed_private_relay_receipt_count
                    .saturating_add(1);
            }
        }
        for window in self.challenge_windows.values() {
            if window.active_at(self.height) {
                counters.open_challenge_window_count =
                    counters.open_challenge_window_count.saturating_add(1);
            }
        }
        for evidence in self.slashing_evidence.values() {
            if evidence.status.slashable() {
                counters.accepted_slashing_evidence_count =
                    counters.accepted_slashing_evidence_count.saturating_add(1);
            }
        }
        for bypass in self.emergency_bypass_lanes.values() {
            if bypass.active_at(self.height) {
                counters.active_emergency_bypass_count =
                    counters.active_emergency_bypass_count.saturating_add(1);
            }
        }
        for sponsor in self.low_fee_sponsors.values() {
            counters.total_sponsor_budget_units = counters
                .total_sponsor_budget_units
                .saturating_add(sponsor.total_budget_units);
            counters.total_sponsor_reserved_units = counters
                .total_sponsor_reserved_units
                .saturating_add(sponsor.reserved_units);
            counters.total_sponsor_spent_units = counters
                .total_sponsor_spent_units
                .saturating_add(sponsor.spent_units);
            if sponsor.active_at(self.height) {
                counters.active_low_fee_sponsor_count =
                    counters.active_low_fee_sponsor_count.saturating_add(1);
            }
        }
        for ticket in self.sponsorship_tickets.values() {
            if ticket.active_at(self.height) {
                counters.active_sponsorship_ticket_count =
                    counters.active_sponsorship_ticket_count.saturating_add(1);
            }
        }
        let mut fairness_total = 0_u64;
        for scorecard in self.fairness_scorecards.values() {
            fairness_total = fairness_total.saturating_add(scorecard.fairness_score_bps);
        }
        if !self.fairness_scorecards.is_empty() {
            counters.average_fairness_score_bps =
                fairness_total / self.fairness_scorecards.len() as u64;
        }
        for attestation in self.pq_watchtower_attestations.values() {
            if attestation.status == AttestationStatus::Accepted {
                counters.accepted_pq_attestation_count =
                    counters.accepted_pq_attestation_count.saturating_add(1);
            }
        }
        counters
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "censorship_resistance_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CENSORSHIP_RESISTANCE_PROTOCOL_VERSION,
            "schema_version": CENSORSHIP_RESISTANCE_SCHEMA_VERSION,
            "security_model": CENSORSHIP_RESISTANCE_SECURITY_MODEL,
            "height": self.height,
            "operator_label": self.operator_label,
            "config": self.config.public_record(),
            "lanes": self.lanes.values().map(ForcedInclusionLane::public_record).collect::<Vec<_>>(),
            "encrypted_intent_receipts": self.encrypted_intent_receipts.values().map(EncryptedIntentReceipt::public_record).collect::<Vec<_>>(),
            "omission_claims": self.omission_claims.values().map(OmissionClaim::public_record).collect::<Vec<_>>(),
            "watchdog_observations": self.watchdog_observations.values().map(WatchdogObservation::public_record).collect::<Vec<_>>(),
            "private_relay_receipts": self.private_relay_receipts.values().map(PrivateRelayReceipt::public_record).collect::<Vec<_>>(),
            "challenge_windows": self.challenge_windows.values().map(ChallengeWindow::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(SlashingEvidence::public_record).collect::<Vec<_>>(),
            "emergency_bypass_lanes": self.emergency_bypass_lanes.values().map(EmergencyBypassLane::public_record).collect::<Vec<_>>(),
            "low_fee_sponsors": self.low_fee_sponsors.values().map(LowFeeInclusionSponsor::public_record).collect::<Vec<_>>(),
            "sponsorship_tickets": self.sponsorship_tickets.values().map(LowFeeSponsorshipTicket::public_record).collect::<Vec<_>>(),
            "fairness_scorecards": self.fairness_scorecards.values().map(FairnessScorecard::public_record).collect::<Vec<_>>(),
            "pq_watchtower_attestations": self.pq_watchtower_attestations.values().map(PqWatchtowerAttestation::public_record).collect::<Vec<_>>(),
            "consumed_replay_nullifiers": self.consumed_replay_nullifiers.iter().cloned().collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(CensorshipPublicRecord::public_record).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> CensorshipResistanceResult<String> {
        ensure_non_empty(&self.operator_label, "censorship resistance operator label")?;
        self.config.validate()?;
        if self.lanes.len() > CENSORSHIP_RESISTANCE_MAX_LANES {
            return Err("too many forced inclusion lanes".to_string());
        }
        if self.encrypted_intent_receipts.len() > CENSORSHIP_RESISTANCE_MAX_RECEIPTS {
            return Err("too many encrypted intent receipts".to_string());
        }
        if self.omission_claims.len() > CENSORSHIP_RESISTANCE_MAX_OMISSION_CLAIMS {
            return Err("too many omission claims".to_string());
        }
        if self.watchdog_observations.len() > CENSORSHIP_RESISTANCE_MAX_WATCHDOG_OBSERVATIONS {
            return Err("too many watchdog observations".to_string());
        }
        if self.private_relay_receipts.len() > CENSORSHIP_RESISTANCE_MAX_RELAY_RECEIPTS {
            return Err("too many private relay receipts".to_string());
        }
        if self.challenge_windows.len() > CENSORSHIP_RESISTANCE_MAX_CHALLENGE_WINDOWS {
            return Err("too many challenge windows".to_string());
        }
        if self.slashing_evidence.len() > CENSORSHIP_RESISTANCE_MAX_SLASHING_EVIDENCE {
            return Err("too much slashing evidence".to_string());
        }
        if self.emergency_bypass_lanes.len() > CENSORSHIP_RESISTANCE_MAX_EMERGENCY_BYPASSES {
            return Err("too many emergency bypass lanes".to_string());
        }
        if self.low_fee_sponsors.len() > CENSORSHIP_RESISTANCE_MAX_SPONSORS {
            return Err("too many low fee sponsors".to_string());
        }
        if self.sponsorship_tickets.len() > CENSORSHIP_RESISTANCE_MAX_SPONSOR_TICKETS {
            return Err("too many sponsorship tickets".to_string());
        }
        if self.fairness_scorecards.len() > CENSORSHIP_RESISTANCE_MAX_SCORECARDS {
            return Err("too many fairness scorecards".to_string());
        }
        if self.pq_watchtower_attestations.len() > CENSORSHIP_RESISTANCE_MAX_PQ_ATTESTATIONS {
            return Err("too many pq watchtower attestations".to_string());
        }
        if self.public_records.len() > CENSORSHIP_RESISTANCE_MAX_PUBLIC_RECORDS {
            return Err("too many public records".to_string());
        }
        for (lane_id, lane) in &self.lanes {
            if lane_id != &lane.lane_id {
                return Err("forced inclusion lane map key mismatch".to_string());
            }
            lane.validate()?;
        }
        let mut expected_nullifiers = BTreeSet::<String>::new();
        for (receipt_id, receipt) in &self.encrypted_intent_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err("encrypted intent receipt map key mismatch".to_string());
            }
            receipt.validate()?;
            if !self.lanes.contains_key(&receipt.lane_id) {
                return Err("encrypted receipt references missing lane".to_string());
            }
            if !expected_nullifiers.insert(receipt.replay_nullifier.clone()) {
                return Err("duplicate encrypted intent replay nullifier".to_string());
            }
            if let Some(ticket_id) = &receipt.low_fee_sponsor_ticket_id {
                if !self.sponsorship_tickets.contains_key(ticket_id) {
                    return Err("receipt references missing sponsorship ticket".to_string());
                }
            }
            if let Some(relay_receipt_id) = &receipt.relay_receipt_id {
                if !self.private_relay_receipts.contains_key(relay_receipt_id) {
                    return Err("receipt references missing private relay receipt".to_string());
                }
            }
            if let Some(bypass_id) = &receipt.emergency_bypass_id {
                if !self.emergency_bypass_lanes.contains_key(bypass_id) {
                    return Err("receipt references missing emergency bypass".to_string());
                }
            }
        }
        for (relay_id, relay_receipt) in &self.private_relay_receipts {
            if relay_id != &relay_receipt.relay_receipt_id {
                return Err("private relay receipt map key mismatch".to_string());
            }
            relay_receipt.validate()?;
            if !self
                .encrypted_intent_receipts
                .contains_key(&relay_receipt.receipt_id)
            {
                return Err("private relay receipt references missing receipt".to_string());
            }
            if !self.lanes.contains_key(&relay_receipt.lane_id) {
                return Err("private relay receipt references missing lane".to_string());
            }
        }
        for (observation_id, observation) in &self.watchdog_observations {
            if observation_id != &observation.observation_id {
                return Err("watchdog observation map key mismatch".to_string());
            }
            observation.validate()?;
            if let Some(lane_id) = &observation.lane_id {
                if !self.lanes.contains_key(lane_id) {
                    return Err("watchdog observation references missing lane".to_string());
                }
            }
            if let Some(receipt_id) = &observation.receipt_id {
                if !self.encrypted_intent_receipts.contains_key(receipt_id) {
                    return Err("watchdog observation references missing receipt".to_string());
                }
            }
        }
        for (claim_id, claim) in &self.omission_claims {
            if claim_id != &claim.claim_id {
                return Err("omission claim map key mismatch".to_string());
            }
            claim.validate()?;
            if !self
                .encrypted_intent_receipts
                .contains_key(&claim.receipt_id)
            {
                return Err("omission claim references missing receipt".to_string());
            }
            if !self.lanes.contains_key(&claim.lane_id) {
                return Err("omission claim references missing lane".to_string());
            }
            for observation_id in &claim.watchdog_observation_ids {
                if !self.watchdog_observations.contains_key(observation_id) {
                    return Err("omission claim references missing observation".to_string());
                }
            }
            for relay_receipt_id in &claim.relay_receipt_ids {
                if !self.private_relay_receipts.contains_key(relay_receipt_id) {
                    return Err("omission claim references missing relay receipt".to_string());
                }
            }
            if let Some(window_id) = &claim.challenge_window_id {
                if !self.challenge_windows.contains_key(window_id) {
                    return Err("omission claim references missing challenge window".to_string());
                }
            }
        }
        for (window_id, window) in &self.challenge_windows {
            if window_id != &window.window_id {
                return Err("challenge window map key mismatch".to_string());
            }
            window.validate()?;
            if !self.omission_claims.contains_key(&window.claim_id) {
                return Err("challenge window references missing claim".to_string());
            }
        }
        for (evidence_id, evidence) in &self.slashing_evidence {
            if evidence_id != &evidence.evidence_id {
                return Err("slashing evidence map key mismatch".to_string());
            }
            evidence.validate()?;
            if let Some(claim_id) = &evidence.claim_id {
                if !self.omission_claims.contains_key(claim_id) {
                    return Err("slashing evidence references missing claim".to_string());
                }
            }
            if let Some(window_id) = &evidence.challenge_window_id {
                if !self.challenge_windows.contains_key(window_id) {
                    return Err("slashing evidence references missing challenge window".to_string());
                }
            }
        }
        for (bypass_id, bypass) in &self.emergency_bypass_lanes {
            if bypass_id != &bypass.bypass_id {
                return Err("emergency bypass map key mismatch".to_string());
            }
            bypass.validate()?;
            if !self.lanes.contains_key(&bypass.lane_id) {
                return Err("emergency bypass references missing lane".to_string());
            }
            for receipt_id in &bypass.consumed_receipt_ids {
                if !self.encrypted_intent_receipts.contains_key(receipt_id) {
                    return Err("emergency bypass references missing receipt".to_string());
                }
            }
        }
        for (sponsor_id, sponsor) in &self.low_fee_sponsors {
            if sponsor_id != &sponsor.sponsor_id {
                return Err("low fee sponsor map key mismatch".to_string());
            }
            sponsor.validate()?;
            for lane_id in &sponsor.eligible_lane_ids {
                if !self.lanes.contains_key(lane_id) {
                    return Err("low fee sponsor references missing lane".to_string());
                }
            }
        }
        for (ticket_id, ticket) in &self.sponsorship_tickets {
            if ticket_id != &ticket.ticket_id {
                return Err("sponsorship ticket map key mismatch".to_string());
            }
            ticket.validate()?;
            if !self.low_fee_sponsors.contains_key(&ticket.sponsor_id) {
                return Err("sponsorship ticket references missing sponsor".to_string());
            }
            if !self
                .encrypted_intent_receipts
                .contains_key(&ticket.receipt_id)
            {
                return Err("sponsorship ticket references missing receipt".to_string());
            }
            if !expected_nullifiers.insert(ticket.nullifier.clone()) {
                return Err("duplicate sponsorship ticket nullifier".to_string());
            }
        }
        if expected_nullifiers != self.consumed_replay_nullifiers {
            return Err("consumed replay nullifier set mismatch".to_string());
        }
        for (scorecard_id, scorecard) in &self.fairness_scorecards {
            if scorecard_id != &scorecard.scorecard_id {
                return Err("fairness scorecard map key mismatch".to_string());
            }
            scorecard.validate()?;
        }
        for (attestation_id, attestation) in &self.pq_watchtower_attestations {
            if attestation_id != &attestation.attestation_id {
                return Err("pq attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            if let Some(lane_id) = &attestation.lane_id {
                if !self.lanes.contains_key(lane_id) {
                    return Err("pq attestation references missing lane".to_string());
                }
            }
            if let Some(receipt_id) = &attestation.receipt_id {
                if !self.encrypted_intent_receipts.contains_key(receipt_id) {
                    return Err("pq attestation references missing receipt".to_string());
                }
            }
            if let Some(claim_id) = &attestation.claim_id {
                if !self.omission_claims.contains_key(claim_id) {
                    return Err("pq attestation references missing claim".to_string());
                }
            }
        }
        for (record_id, record) in &self.public_records {
            if record_id != &record.record_id {
                return Err("public record map key mismatch".to_string());
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn forced_inclusion_lane_id(
    lane_kind: ForcedInclusionLaneKind,
    label: &str,
    operator_id: &str,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-LANE-ID",
        &[
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(operator_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn encrypted_intent_receipt_id(
    lane_id: &str,
    submitter_commitment: &str,
    intent_kind: &str,
    payload_commitment_root: &str,
    nonce: u64,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-ENCRYPTED-INTENT-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(submitter_commitment),
            HashPart::Str(intent_kind),
            HashPart::Str(payload_commitment_root),
            HashPart::Int(nonce as i128),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn encrypted_intent_replay_nullifier(
    lane_id: &str,
    submitter_commitment: &str,
    nonce: u64,
    payload_commitment_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-INTENT-REPLAY-NULLIFIER",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(submitter_commitment),
            HashPart::Int(nonce as i128),
            HashPart::Str(payload_commitment_root),
        ],
        32,
    )
}

pub fn private_relay_receipt_id(
    receipt_id: &str,
    relay_id: &str,
    receipt_kind: PrivateRelayReceiptKind,
    ingress_height: u64,
    witness_commitment_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-PRIVATE-RELAY-RECEIPT-ID",
        &[
            HashPart::Str(receipt_id),
            HashPart::Str(relay_id),
            HashPart::Str(receipt_kind.as_str()),
            HashPart::Int(ingress_height as i128),
            HashPart::Str(witness_commitment_root),
        ],
        32,
    )
}

pub fn watchdog_observation_id(
    observation_kind: WatchdogObservationKind,
    watchtower_id: &str,
    operator_id: &str,
    lane_id: Option<&str>,
    receipt_id: Option<&str>,
    observed_height: u64,
    sample_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-WATCHDOG-OBSERVATION-ID",
        &[
            HashPart::Str(observation_kind.as_str()),
            HashPart::Str(watchtower_id),
            HashPart::Str(operator_id),
            HashPart::Str(optional_str(lane_id)),
            HashPart::Str(optional_str(receipt_id)),
            HashPart::Int(observed_height as i128),
            HashPart::Str(sample_root),
        ],
        32,
    )
}

pub fn omission_claim_id(
    claim_kind: OmissionClaimKind,
    receipt_id: &str,
    claimant_id: &str,
    accused_operator_id: &str,
    opened_at_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-OMISSION-CLAIM-ID",
        &[
            HashPart::Str(claim_kind.as_str()),
            HashPart::Str(receipt_id),
            HashPart::Str(claimant_id),
            HashPart::Str(accused_operator_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn challenge_window_id(
    claim_id: &str,
    challenger_id: &str,
    opened_at_height: u64,
    requested_action_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-CHALLENGE-WINDOW-ID",
        &[
            HashPart::Str(claim_id),
            HashPart::Str(challenger_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(requested_action_root),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    reason: SlashingReason,
    accused_operator_id: &str,
    reporter_id: &str,
    claim_id: Option<&str>,
    challenge_window_id: Option<&str>,
    opened_at_height: u64,
    contradiction_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(reason.as_str()),
            HashPart::Str(accused_operator_id),
            HashPart::Str(reporter_id),
            HashPart::Str(optional_str(claim_id)),
            HashPart::Str(optional_str(challenge_window_id)),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(contradiction_root),
        ],
        32,
    )
}

pub fn emergency_bypass_id(
    lane_id: &str,
    activated_by: &str,
    activated_at_height: u64,
    activation_reason_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-EMERGENCY-BYPASS-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(activated_by),
            HashPart::Int(activated_at_height as i128),
            HashPart::Str(activation_reason_root),
        ],
        32,
    )
}

pub fn low_fee_sponsor_id(
    label: &str,
    funding_account_commitment: &str,
    asset_id: &str,
    valid_from_height: u64,
    policy_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-LOW-FEE-SPONSOR-ID",
        &[
            HashPart::Str(label),
            HashPart::Str(funding_account_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(valid_from_height as i128),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn low_fee_sponsorship_ticket_id(
    sponsor_id: &str,
    receipt_id: &str,
    beneficiary_commitment: &str,
    issued_at_height: u64,
    privacy_budget_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-SPONSORSHIP-TICKET-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Int(issued_at_height as i128),
            HashPart::Str(privacy_budget_root),
        ],
        32,
    )
}

pub fn low_fee_sponsorship_nullifier(
    sponsor_id: &str,
    receipt_id: &str,
    beneficiary_commitment: &str,
    privacy_budget_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-SPONSORSHIP-NULLIFIER",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(privacy_budget_root),
        ],
        32,
    )
}

pub fn fairness_scorecard_id(
    operator_id: &str,
    epoch_start_height: u64,
    epoch_end_height: u64,
    lane_root: &str,
    pq_audit_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-FAIRNESS-SCORECARD-ID",
        &[
            HashPart::Str(operator_id),
            HashPart::Int(epoch_start_height as i128),
            HashPart::Int(epoch_end_height as i128),
            HashPart::Str(lane_root),
            HashPart::Str(pq_audit_root),
        ],
        32,
    )
}

pub fn pq_watchtower_attestation_id(
    attestation_kind: PqWatchtowerAttestationKind,
    watchtower_id: &str,
    operator_id: &str,
    lane_id: Option<&str>,
    receipt_id: Option<&str>,
    claim_id: Option<&str>,
    height: u64,
    transcript_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-PQ-WATCHTOWER-ATTESTATION-ID",
        &[
            HashPart::Str(attestation_kind.as_str()),
            HashPart::Str(watchtower_id),
            HashPart::Str(operator_id),
            HashPart::Str(optional_str(lane_id)),
            HashPart::Str(optional_str(receipt_id)),
            HashPart::Str(optional_str(claim_id)),
            HashPart::Int(height as i128),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn censorship_public_record_id(
    object_kind: &str,
    object_id: &str,
    height: u64,
    payload_root: &str,
) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Int(height as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn censorship_resistance_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn censorship_resistance_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn censorship_resistance_state_root_from_record(record: &Value) -> String {
    censorship_resistance_payload_root("CENSORSHIP-RESISTANCE-STATE-ROOT", record)
}

pub fn forced_inclusion_lane_root_from_map(
    lanes: &BTreeMap<String, ForcedInclusionLane>,
) -> String {
    let leaves = lanes
        .values()
        .map(ForcedInclusionLane::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-FORCED-INCLUSION-LANES", &leaves)
}

pub fn encrypted_intent_receipt_root_from_map(
    receipts: &BTreeMap<String, EncryptedIntentReceipt>,
) -> String {
    let leaves = receipts
        .values()
        .map(EncryptedIntentReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-ENCRYPTED-INTENT-RECEIPTS", &leaves)
}

pub fn omission_claim_root_from_map(claims: &BTreeMap<String, OmissionClaim>) -> String {
    let leaves = claims
        .values()
        .map(OmissionClaim::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-OMISSION-CLAIMS", &leaves)
}

pub fn watchdog_observation_root_from_map(
    observations: &BTreeMap<String, WatchdogObservation>,
) -> String {
    let leaves = observations
        .values()
        .map(WatchdogObservation::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-WATCHDOG-OBSERVATIONS", &leaves)
}

pub fn private_relay_receipt_root_from_map(
    receipts: &BTreeMap<String, PrivateRelayReceipt>,
) -> String {
    let leaves = receipts
        .values()
        .map(PrivateRelayReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-PRIVATE-RELAY-RECEIPTS", &leaves)
}

pub fn challenge_window_root_from_map(windows: &BTreeMap<String, ChallengeWindow>) -> String {
    let leaves = windows
        .values()
        .map(ChallengeWindow::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-CHALLENGE-WINDOWS", &leaves)
}

pub fn slashing_evidence_root_from_map(evidence: &BTreeMap<String, SlashingEvidence>) -> String {
    let leaves = evidence
        .values()
        .map(SlashingEvidence::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-SLASHING-EVIDENCE", &leaves)
}

pub fn emergency_bypass_root_from_map(bypasses: &BTreeMap<String, EmergencyBypassLane>) -> String {
    let leaves = bypasses
        .values()
        .map(EmergencyBypassLane::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-EMERGENCY-BYPASSES", &leaves)
}

pub fn low_fee_sponsor_root_from_map(
    sponsors: &BTreeMap<String, LowFeeInclusionSponsor>,
) -> String {
    let leaves = sponsors
        .values()
        .map(LowFeeInclusionSponsor::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-LOW-FEE-SPONSORS", &leaves)
}

pub fn low_fee_sponsorship_ticket_root_from_map(
    tickets: &BTreeMap<String, LowFeeSponsorshipTicket>,
) -> String {
    let leaves = tickets
        .values()
        .map(LowFeeSponsorshipTicket::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-LOW-FEE-SPONSORSHIP-TICKETS", &leaves)
}

pub fn fairness_scorecard_root_from_map(
    scorecards: &BTreeMap<String, FairnessScorecard>,
) -> String {
    let leaves = scorecards
        .values()
        .map(FairnessScorecard::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-FAIRNESS-SCORECARDS", &leaves)
}

pub fn pq_watchtower_attestation_root_from_map(
    attestations: &BTreeMap<String, PqWatchtowerAttestation>,
) -> String {
    let leaves = attestations
        .values()
        .map(PqWatchtowerAttestation::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-PQ-WATCHTOWER-ATTESTATIONS", &leaves)
}

pub fn censorship_public_record_root_from_map(
    records: &BTreeMap<String, CensorshipPublicRecord>,
) -> String {
    let leaves = records
        .values()
        .map(CensorshipPublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root("CENSORSHIP-RESISTANCE-PUBLIC-RECORDS", &leaves)
}

pub fn devnet_pq_root(kind: &str, label: &str) -> String {
    domain_hash(
        "CENSORSHIP-RESISTANCE-DEVNET-PQ-ROOT",
        &[HashPart::Str(kind), HashPart::Str(label)],
        32,
    )
}

fn btree_set<const N: usize>(items: [&str; N]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}

fn ensure_non_empty(value: &str, label: &str) -> CensorshipResistanceResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> CensorshipResistanceResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> CensorshipResistanceResult<()> {
    if value > CENSORSHIP_RESISTANCE_MAX_BPS {
        Err(format!("{label} exceeds max bps"))
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
        numerator
            .saturating_mul(CENSORSHIP_RESISTANCE_MAX_BPS)
            .saturating_div(denominator)
            .min(CENSORSHIP_RESISTANCE_MAX_BPS)
    }
}

fn ratio_bps_or_full(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        CENSORSHIP_RESISTANCE_MAX_BPS
    } else {
        ratio_bps(numerator, denominator)
    }
}
