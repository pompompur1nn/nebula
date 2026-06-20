use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        build_kem_envelope, crypto_policy_root, public_key_for_label, sign_authorization_for_role,
        verify_authorization_for_role, Authorization, CryptoRole, KemEnvelope,
    },
    hash::{domain_hash, merkle_root, HashPart},
    ACCOUNT_SIGNATURE_SCHEME, CHAIN_ID, RECOVERY_SIGNATURE_SCHEME, TARGET_BLOCK_MS,
};

pub type DecentralizedSequencerResult<T> = Result<T, String>;

pub const DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION: &str = "nebula-decentralized-sequencer-v1";
pub const PROTOCOL_VERSION: &str = DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION;
pub const DECENTRALIZED_SEQUENCER_SCHEMA_VERSION: &str = "decentralized-sequencer-state-v1";
pub const DECENTRALIZED_SEQUENCER_TRANSCRIPT_HASH: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const DECENTRALIZED_SEQUENCER_PQ_SIGNATURE_SCHEME: &str = ACCOUNT_SIGNATURE_SCHEME;
pub const DECENTRALIZED_SEQUENCER_PQ_RECOVERY_SCHEME: &str = RECOVERY_SIGNATURE_SCHEME;
pub const DECENTRALIZED_SEQUENCER_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const DECENTRALIZED_SEQUENCER_PRIVACY_POLICY: &str =
    "encrypted-private-mempool-public-roots-only";
pub const DECENTRALIZED_SEQUENCER_MONERO_SETTLEMENT_HINT: &str =
    "monero-devnet-anchor-after-bft-certificate";
pub const DECENTRALIZED_SEQUENCER_MAX_BPS: u64 = 10_000;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_EPOCH_LENGTH: u64 = 16;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_MICROBLOCK_TARGET_MS: u64 = 100;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_SOFT_QUORUM_BPS: u64 = 6_000;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_FINAL_QUORUM_BPS: u64 = 6_667;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_VIEW_CHANGE_QUORUM_BPS: u64 = 8_000;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_PRIVATE_SHARE_BPS: u64 = 3_000;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_LOW_FEE_SHARE_BPS: u64 = 2_000;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_MONERO_BRIDGE_SHARE_BPS: u64 = 1_000;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_MAX_MEMPOOL_ITEMS: u64 = 4_096;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_MAX_MICROBLOCK_ITEMS: u64 = 96;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_ENCRYPTED_TTL_BLOCKS: u64 = 8;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_SLASHING_DELAY_BLOCKS: u64 = 4;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_LOW_FEE_BUDGET_UNITS: u64 = 100_000;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_MIN_STAKE_UNITS: u64 = 1_000;
pub const DECENTRALIZED_SEQUENCER_DEFAULT_MAX_JAIL_BLOCKS: u64 = 512;
pub const DECENTRALIZED_SEQUENCER_DEVNET_COMMITTEE_LABEL: &str =
    "devnet-decentralized-sequencer-committee";
pub const DECENTRALIZED_SEQUENCER_DEVNET_OPERATOR_LABEL: &str =
    "devnet-decentralized-sequencer-operator";
pub const DECENTRALIZED_SEQUENCER_DEVNET_PARENT_ID: &str = "genesis-decentralized-sequencer-parent";
pub const DECENTRALIZED_SEQUENCER_STATUS_ACTIVE: &str = "active";
pub const DECENTRALIZED_SEQUENCER_STATUS_JAILED: &str = "jailed";
pub const DECENTRALIZED_SEQUENCER_STATUS_EXITING: &str = "exiting";
pub const DECENTRALIZED_SEQUENCER_STATUS_SLASHED: &str = "slashed";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    Proposer,
    Voter,
    Aggregator,
    MempoolKeyholder,
    Watchtower,
    MoneroAnchor,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposer => "proposer",
            Self::Voter => "voter",
            Self::Aggregator => "aggregator",
            Self::MempoolKeyholder => "mempool_keyholder",
            Self::Watchtower => "watchtower",
            Self::MoneroAnchor => "monero_anchor",
        }
    }

    pub fn crypto_role(self) -> CryptoRole {
        match self {
            Self::Watchtower => CryptoRole::WatchtowerSignature,
            Self::MoneroAnchor => CryptoRole::NetworkSignature,
            Self::MempoolKeyholder => CryptoRole::NetworkSignature,
            _ => CryptoRole::ValidatorSignature,
        }
    }

    pub fn default_weight_bonus(self) -> u64 {
        match self {
            Self::Proposer => 125,
            Self::Voter => 100,
            Self::Aggregator => 75,
            Self::MempoolKeyholder => 50,
            Self::Watchtower => 25,
            Self::MoneroAnchor => 25,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateMempoolLaneKind {
    System,
    MoneroBridge,
    PrivateTransfer,
    PrivateDefi,
    PublicDefi,
    ContractCall,
    LowFee,
    ProofMarket,
    Bulk,
}

impl PrivateMempoolLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefi => "private_defi",
            Self::PublicDefi => "public_defi",
            Self::ContractCall => "contract_call",
            Self::LowFee => "low_fee",
            Self::ProofMarket => "proof_market",
            Self::Bulk => "bulk",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::System => 1_000_000,
            Self::MoneroBridge => 925_000,
            Self::PrivateTransfer => 830_000,
            Self::PrivateDefi => 780_000,
            Self::LowFee => 710_000,
            Self::ProofMarket => 640_000,
            Self::ContractCall => 600_000,
            Self::PublicDefi => 560_000,
            Self::Bulk => 120_000,
        }
    }

    pub fn default_target_latency_ms(self) -> u64 {
        match self {
            Self::System => TARGET_BLOCK_MS / 10,
            Self::MoneroBridge => TARGET_BLOCK_MS / 3,
            Self::PrivateTransfer | Self::LowFee => TARGET_BLOCK_MS / 4,
            Self::PrivateDefi => TARGET_BLOCK_MS / 2,
            Self::ContractCall | Self::PublicDefi => TARGET_BLOCK_MS,
            Self::ProofMarket => TARGET_BLOCK_MS.saturating_mul(2),
            Self::Bulk => TARGET_BLOCK_MS.saturating_mul(4),
        }
        .max(1)
    }

    pub fn is_private(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer | Self::PrivateDefi | Self::LowFee | Self::MoneroBridge
        )
    }

    pub fn low_fee_eligible(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer | Self::PrivateDefi | Self::LowFee | Self::ContractCall
        )
    }

    pub fn monero_sensitive(self) -> bool {
        matches!(self, Self::MoneroBridge)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanePrivacyMode {
    PublicCommitmentsOnly,
    EncryptedPayload,
    ThresholdEncrypted,
    ViewTagOnly,
    DecoyBatch,
}

impl LanePrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicCommitmentsOnly => "public_commitments_only",
            Self::EncryptedPayload => "encrypted_payload",
            Self::ThresholdEncrypted => "threshold_encrypted",
            Self::ViewTagOnly => "view_tag_only",
            Self::DecoyBatch => "decoy_batch",
        }
    }

    pub fn requires_kem(self) -> bool {
        matches!(
            self,
            Self::EncryptedPayload | Self::ThresholdEncrypted | Self::DecoyBatch
        )
    }

    pub fn hides_fee(self) -> bool {
        matches!(self, Self::ThresholdEncrypted | Self::DecoyBatch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneAdmissionPolicy {
    Open,
    Bonded,
    LowFeeSponsored,
    BridgeGuarded,
    CommitteeOnly,
    EmergencyOnly,
}

impl LaneAdmissionPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bonded => "bonded",
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::BridgeGuarded => "bridge_guarded",
            Self::CommitteeOnly => "committee_only",
            Self::EmergencyOnly => "emergency_only",
        }
    }

    pub fn requires_bond(self) -> bool {
        matches!(
            self,
            Self::Bonded | Self::BridgeGuarded | Self::EmergencyOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Throttled,
    Sealed,
    Draining,
    Disabled,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::Sealed => "sealed",
            Self::Draining => "draining",
            Self::Disabled => "disabled",
        }
    }

    pub fn admits(self) -> bool {
        matches!(self, Self::Open | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MempoolEntryStatus {
    Pending,
    Ordered,
    Included,
    Expired,
    Censored,
    Rejected,
}

impl MempoolEntryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ordered => "ordered",
            Self::Included => "included",
            Self::Expired => "expired",
            Self::Censored => "censored",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QosDecisionKind {
    Admit,
    Preconfirm,
    Delay,
    Throttle,
    Shed,
    Reject,
}

impl QosDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Preconfirm => "preconfirm",
            Self::Delay => "delay",
            Self::Throttle => "throttle",
            Self::Shed => "shed",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicroblockStatus {
    Proposed,
    Preconfirmed,
    SoftFinalized,
    Finalized,
    Conflicted,
    RolledBack,
}

impl MicroblockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Preconfirmed => "preconfirmed",
            Self::SoftFinalized => "soft_finalized",
            Self::Finalized => "finalized",
            Self::Conflicted => "conflicted",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityVoteKind {
    Prevote,
    Precommit,
    Commit,
    ViewChange,
}

impl FinalityVoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prevote => "prevote",
            Self::Precommit => "precommit",
            Self::Commit => "commit",
            Self::ViewChange => "view_change",
        }
    }

    pub fn quorum_bps(self, config: &DecentralizedSequencerConfig) -> u64 {
        match self {
            Self::Prevote => config.soft_quorum_bps,
            Self::Precommit | Self::Commit => config.final_quorum_bps,
            Self::ViewChange => config.view_change_quorum_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityCertificateKind {
    Soft,
    Final,
    ViewChange,
}

impl FinalityCertificateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Soft => "soft",
            Self::Final => "final",
            Self::ViewChange => "view_change",
        }
    }

    pub fn vote_kind(self) -> FinalityVoteKind {
        match self {
            Self::Soft => FinalityVoteKind::Prevote,
            Self::Final => FinalityVoteKind::Commit,
            Self::ViewChange => FinalityVoteKind::ViewChange,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderScheduleMode {
    WeightedRoundRobin,
    RandomBeacon,
    FallbackRank,
}

impl LeaderScheduleMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WeightedRoundRobin => "weighted_round_robin",
            Self::RandomBeacon => "random_beacon",
            Self::FallbackRank => "fallback_rank",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivocationKind {
    DoubleProposal,
    ConflictingVote,
    MempoolWithholding,
    PrivateLaneLeak,
    BadDecryptionShare,
    QosViolation,
}

impl EquivocationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleProposal => "double_proposal",
            Self::ConflictingVote => "conflicting_vote",
            Self::MempoolWithholding => "mempool_withholding",
            Self::PrivateLaneLeak => "private_lane_leak",
            Self::BadDecryptionShare => "bad_decryption_share",
            Self::QosViolation => "qos_violation",
        }
    }

    pub fn default_slash_bps(self) -> u64 {
        match self {
            Self::DoubleProposal => 10_000,
            Self::ConflictingVote => 8_500,
            Self::PrivateLaneLeak => 7_500,
            Self::BadDecryptionShare => 6_500,
            Self::MempoolWithholding => 4_000,
            Self::QosViolation => 2_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    Equivocation,
    InvalidVote,
    BadProposal,
    Censorship,
    PrivacyLeak,
    LivenessMiss,
    LowFeeQuotaTheft,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equivocation => "equivocation",
            Self::InvalidVote => "invalid_vote",
            Self::BadProposal => "bad_proposal",
            Self::Censorship => "censorship",
            Self::PrivacyLeak => "privacy_leak",
            Self::LivenessMiss => "liveness_miss",
            Self::LowFeeQuotaTheft => "low_fee_quota_theft",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Observed,
    Challenged,
    Accepted,
    Rejected,
    Expired,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Challenged => "challenged",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Pending,
    Applied,
    Appealed,
    Reverted,
}

impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Appealed => "appealed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedSequencerConfig {
    pub protocol_version: String,
    pub schema_version: String,
    pub epoch_length: u64,
    pub microblock_target_ms: u64,
    pub soft_quorum_bps: u64,
    pub final_quorum_bps: u64,
    pub view_change_quorum_bps: u64,
    pub private_min_share_bps: u64,
    pub low_fee_min_share_bps: u64,
    pub monero_bridge_min_share_bps: u64,
    pub max_mempool_items: u64,
    pub max_microblock_items: u64,
    pub encrypted_lane_ttl_blocks: u64,
    pub slashing_delay_blocks: u64,
    pub min_stake_units: u64,
    pub max_jail_blocks: u64,
    pub leader_schedule_mode: LeaderScheduleMode,
    pub pq_signature_scheme: String,
    pub pq_recovery_scheme: String,
    pub pq_kem_scheme: String,
    pub transcript_hash: String,
    pub privacy_payload_policy: String,
    pub monero_settlement_hint: String,
}

impl Default for DecentralizedSequencerConfig {
    fn default() -> Self {
        Self {
            protocol_version: DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION.to_string(),
            schema_version: DECENTRALIZED_SEQUENCER_SCHEMA_VERSION.to_string(),
            epoch_length: DECENTRALIZED_SEQUENCER_DEFAULT_EPOCH_LENGTH,
            microblock_target_ms: DECENTRALIZED_SEQUENCER_DEFAULT_MICROBLOCK_TARGET_MS,
            soft_quorum_bps: DECENTRALIZED_SEQUENCER_DEFAULT_SOFT_QUORUM_BPS,
            final_quorum_bps: DECENTRALIZED_SEQUENCER_DEFAULT_FINAL_QUORUM_BPS,
            view_change_quorum_bps: DECENTRALIZED_SEQUENCER_DEFAULT_VIEW_CHANGE_QUORUM_BPS,
            private_min_share_bps: DECENTRALIZED_SEQUENCER_DEFAULT_PRIVATE_SHARE_BPS,
            low_fee_min_share_bps: DECENTRALIZED_SEQUENCER_DEFAULT_LOW_FEE_SHARE_BPS,
            monero_bridge_min_share_bps: DECENTRALIZED_SEQUENCER_DEFAULT_MONERO_BRIDGE_SHARE_BPS,
            max_mempool_items: DECENTRALIZED_SEQUENCER_DEFAULT_MAX_MEMPOOL_ITEMS,
            max_microblock_items: DECENTRALIZED_SEQUENCER_DEFAULT_MAX_MICROBLOCK_ITEMS,
            encrypted_lane_ttl_blocks: DECENTRALIZED_SEQUENCER_DEFAULT_ENCRYPTED_TTL_BLOCKS,
            slashing_delay_blocks: DECENTRALIZED_SEQUENCER_DEFAULT_SLASHING_DELAY_BLOCKS,
            min_stake_units: DECENTRALIZED_SEQUENCER_DEFAULT_MIN_STAKE_UNITS,
            max_jail_blocks: DECENTRALIZED_SEQUENCER_DEFAULT_MAX_JAIL_BLOCKS,
            leader_schedule_mode: LeaderScheduleMode::WeightedRoundRobin,
            pq_signature_scheme: DECENTRALIZED_SEQUENCER_PQ_SIGNATURE_SCHEME.to_string(),
            pq_recovery_scheme: DECENTRALIZED_SEQUENCER_PQ_RECOVERY_SCHEME.to_string(),
            pq_kem_scheme: DECENTRALIZED_SEQUENCER_PQ_KEM_SCHEME.to_string(),
            transcript_hash: DECENTRALIZED_SEQUENCER_TRANSCRIPT_HASH.to_string(),
            privacy_payload_policy: DECENTRALIZED_SEQUENCER_PRIVACY_POLICY.to_string(),
            monero_settlement_hint: DECENTRALIZED_SEQUENCER_MONERO_SETTLEMENT_HINT.to_string(),
        }
    }
}

impl DecentralizedSequencerConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_sequencer_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "epoch_length": self.epoch_length,
            "microblock_target_ms": self.microblock_target_ms,
            "soft_quorum_bps": self.soft_quorum_bps,
            "final_quorum_bps": self.final_quorum_bps,
            "view_change_quorum_bps": self.view_change_quorum_bps,
            "private_min_share_bps": self.private_min_share_bps,
            "low_fee_min_share_bps": self.low_fee_min_share_bps,
            "monero_bridge_min_share_bps": self.monero_bridge_min_share_bps,
            "max_mempool_items": self.max_mempool_items,
            "max_microblock_items": self.max_microblock_items,
            "encrypted_lane_ttl_blocks": self.encrypted_lane_ttl_blocks,
            "slashing_delay_blocks": self.slashing_delay_blocks,
            "min_stake_units": self.min_stake_units,
            "max_jail_blocks": self.max_jail_blocks,
            "leader_schedule_mode": self.leader_schedule_mode.as_str(),
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_recovery_scheme": self.pq_recovery_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "transcript_hash": self.transcript_hash,
            "privacy_payload_policy": self.privacy_payload_policy,
            "monero_settlement_hint": self.monero_settlement_hint,
        })
    }

    pub fn config_root(&self) -> String {
        decentralized_sequencer_payload_root(
            "DECENTRALIZED-SEQUENCER-CONFIG-ROOT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> DecentralizedSequencerResult<String> {
        ensure_non_empty(&self.protocol_version, "sequencer protocol version")?;
        ensure_non_empty(&self.schema_version, "sequencer schema version")?;
        if self.protocol_version != DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION {
            return Err("decentralized sequencer protocol version mismatch".to_string());
        }
        if self.schema_version != DECENTRALIZED_SEQUENCER_SCHEMA_VERSION {
            return Err("decentralized sequencer schema version mismatch".to_string());
        }
        ensure_positive(self.epoch_length, "sequencer epoch length")?;
        ensure_positive(
            self.microblock_target_ms,
            "sequencer microblock target milliseconds",
        )?;
        ensure_bps(self.soft_quorum_bps, "sequencer soft quorum bps")?;
        ensure_bps(self.final_quorum_bps, "sequencer final quorum bps")?;
        ensure_bps(
            self.view_change_quorum_bps,
            "sequencer view-change quorum bps",
        )?;
        ensure_bps(
            self.private_min_share_bps,
            "sequencer private lane share bps",
        )?;
        ensure_bps(
            self.low_fee_min_share_bps,
            "sequencer low-fee lane share bps",
        )?;
        ensure_bps(
            self.monero_bridge_min_share_bps,
            "sequencer Monero bridge lane share bps",
        )?;
        if self.soft_quorum_bps > self.final_quorum_bps {
            return Err("sequencer soft quorum cannot exceed final quorum".to_string());
        }
        if self.final_quorum_bps > self.view_change_quorum_bps {
            return Err("sequencer final quorum cannot exceed view-change quorum".to_string());
        }
        ensure_positive(self.max_mempool_items, "sequencer max mempool items")?;
        ensure_positive(self.max_microblock_items, "sequencer max microblock items")?;
        ensure_positive(
            self.encrypted_lane_ttl_blocks,
            "sequencer encrypted lane ttl blocks",
        )?;
        ensure_positive(self.min_stake_units, "sequencer minimum stake")?;
        ensure_non_empty(&self.pq_signature_scheme, "sequencer PQ signature scheme")?;
        ensure_non_empty(&self.pq_recovery_scheme, "sequencer PQ recovery scheme")?;
        ensure_non_empty(&self.pq_kem_scheme, "sequencer PQ KEM scheme")?;
        ensure_non_empty(&self.transcript_hash, "sequencer transcript hash")?;
        ensure_non_empty(
            &self.privacy_payload_policy,
            "sequencer privacy payload policy",
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub label: String,
    pub roles: Vec<CommitteeRole>,
    pub stake_units: u64,
    pub voting_power: u64,
    pub low_fee_budget_units: u64,
    pub consensus_public_key: String,
    pub consensus_public_key_root: String,
    pub recovery_public_key_root: String,
    pub network_public_key_root: String,
    pub mempool_key_id: String,
    pub mempool_public_key_root: String,
    pub activated_at_height: u64,
    pub jailed_until_height: u64,
    pub missed_slots: u64,
    pub status: String,
}

impl CommitteeMember {
    pub fn new(
        label: impl Into<String>,
        roles: Vec<CommitteeRole>,
        stake_units: u64,
        voting_power: u64,
        low_fee_budget_units: u64,
        activated_at_height: u64,
    ) -> DecentralizedSequencerResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "committee member label")?;
        ensure_positive(stake_units, "committee member stake")?;
        ensure_positive(voting_power, "committee member voting power")?;
        if roles.is_empty() {
            return Err("committee member must have at least one role".to_string());
        }
        let consensus_key = public_key_for_label(CryptoRole::ValidatorSignature, &label);
        let recovery_key = public_key_for_label(CryptoRole::RecoverySignature, &label);
        let network_key = public_key_for_label(CryptoRole::NetworkSignature, &label);
        let mempool_key = public_key_for_label(CryptoRole::KeyEstablishment, &label);
        let role_root = committee_role_root(&roles);
        let member_id = committee_member_id(
            &label,
            &role_root,
            stake_units,
            voting_power,
            &consensus_key.public_key,
            activated_at_height,
        );
        Ok(Self {
            member_id,
            label,
            roles: canonical_roles(roles),
            stake_units,
            voting_power,
            low_fee_budget_units,
            consensus_public_key: consensus_key.public_key.clone(),
            consensus_public_key_root: consensus_key.key_id,
            recovery_public_key_root: recovery_key.key_id,
            network_public_key_root: network_key.key_id,
            mempool_key_id: mempool_key.key_id,
            mempool_public_key_root: decentralized_sequencer_string_root(
                "DECENTRALIZED-SEQUENCER-MEMPOOL-PUBLIC-KEY-ROOT",
                &mempool_key.public_key,
            ),
            activated_at_height,
            jailed_until_height: 0,
            missed_slots: 0,
            status: DECENTRALIZED_SEQUENCER_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_sequencer_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "label": self.label,
            "roles": self.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "role_root": committee_role_root(&self.roles),
            "stake_units": self.stake_units,
            "voting_power": self.voting_power,
            "low_fee_budget_units": self.low_fee_budget_units,
            "consensus_public_key_root": self.consensus_public_key_root,
            "recovery_public_key_root": self.recovery_public_key_root,
            "network_public_key_root": self.network_public_key_root,
            "mempool_key_id": self.mempool_key_id,
            "mempool_public_key_root": self.mempool_public_key_root,
            "activated_at_height": self.activated_at_height,
            "jailed_until_height": self.jailed_until_height,
            "missed_slots": self.missed_slots,
            "status": self.status,
        })
    }

    pub fn member_root(&self) -> String {
        committee_member_root(&self.public_record())
    }

    pub fn has_role(&self, role: CommitteeRole) -> bool {
        self.roles.contains(&role)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == DECENTRALIZED_SEQUENCER_STATUS_ACTIVE
            && self.activated_at_height <= height
            && self.jailed_until_height <= height
            && self.voting_power > 0
    }

    pub fn effective_power_at(&self, height: u64) -> u64 {
        if self.is_active_at(height) {
            self.voting_power
        } else {
            0
        }
    }

    pub fn jail(&mut self, until_height: u64) {
        self.jailed_until_height = until_height;
        self.status = DECENTRALIZED_SEQUENCER_STATUS_JAILED.to_string();
    }

    pub fn apply_slash(&mut self, slash_amount: u64, jail_until_height: u64) {
        self.stake_units = self.stake_units.saturating_sub(slash_amount);
        self.voting_power = self.voting_power.saturating_sub(slash_amount);
        if self.stake_units == 0 || self.voting_power == 0 {
            self.status = DECENTRALIZED_SEQUENCER_STATUS_SLASHED.to_string();
        } else {
            self.jail(jail_until_height);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerCommittee {
    pub committee_id: String,
    pub label: String,
    pub epoch: u64,
    pub activation_height: u64,
    pub members: Vec<CommitteeMember>,
    pub total_voting_power: u64,
    pub active_voting_power: u64,
    pub quorum_power: u64,
    pub leader_schedule_root: String,
    pub crypto_policy_root: String,
}

impl SequencerCommittee {
    pub fn new(
        label: impl Into<String>,
        epoch: u64,
        activation_height: u64,
        members: Vec<CommitteeMember>,
        final_quorum_bps: u64,
    ) -> DecentralizedSequencerResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "sequencer committee label")?;
        if members.is_empty() {
            return Err("sequencer committee cannot be empty".to_string());
        }
        ensure_unique_strings(
            &members
                .iter()
                .map(|member| member.member_id.clone())
                .collect::<Vec<_>>(),
            "committee member ids",
        )?;
        let total_voting_power = members
            .iter()
            .map(|member| member.voting_power)
            .sum::<u64>();
        let active_voting_power = members
            .iter()
            .filter(|member| member.is_active_at(activation_height))
            .map(|member| member.voting_power)
            .sum::<u64>();
        let quorum_power = quorum_power(total_voting_power, final_quorum_bps);
        let leader_schedule_root = leader_schedule_root_for_members(
            epoch,
            activation_height,
            &members,
            LeaderScheduleMode::WeightedRoundRobin,
        );
        let committee_id = sequencer_committee_id(
            &label,
            epoch,
            activation_height,
            &committee_member_set_root(&members),
            total_voting_power,
        );
        let committee = Self {
            committee_id,
            label,
            epoch,
            activation_height,
            members,
            total_voting_power,
            active_voting_power,
            quorum_power,
            leader_schedule_root,
            crypto_policy_root: crypto_policy_root(),
        };
        committee.validate()?;
        Ok(committee)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_sequencer_committee",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "label": self.label,
            "epoch": self.epoch,
            "activation_height": self.activation_height,
            "member_root": committee_member_set_root(&self.members),
            "members": self.members.iter().map(CommitteeMember::public_record).collect::<Vec<_>>(),
            "total_voting_power": self.total_voting_power,
            "active_voting_power": self.active_voting_power,
            "quorum_power": self.quorum_power,
            "leader_schedule_root": self.leader_schedule_root,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }

    pub fn committee_root(&self) -> String {
        sequencer_committee_root(&self.public_record())
    }

    pub fn validate(&self) -> DecentralizedSequencerResult<String> {
        ensure_non_empty(&self.committee_id, "sequencer committee id")?;
        ensure_non_empty(&self.label, "sequencer committee label")?;
        if self.members.is_empty() {
            return Err("sequencer committee cannot be empty".to_string());
        }
        let total = self
            .members
            .iter()
            .map(|member| member.voting_power)
            .sum::<u64>();
        if total != self.total_voting_power {
            return Err("sequencer committee total voting power mismatch".to_string());
        }
        if self.quorum_power == 0 || self.quorum_power > self.total_voting_power {
            return Err("sequencer committee quorum power is invalid".to_string());
        }
        ensure_unique_strings(
            &self
                .members
                .iter()
                .map(|member| member.member_id.clone())
                .collect::<Vec<_>>(),
            "sequencer committee member ids",
        )?;
        Ok(self.committee_root())
    }

    pub fn active_members_at(&self, height: u64) -> Vec<CommitteeMember> {
        self.members
            .iter()
            .filter(|member| member.is_active_at(height))
            .cloned()
            .collect()
    }

    pub fn active_voting_power_at(&self, height: u64) -> u64 {
        self.members
            .iter()
            .map(|member| member.effective_power_at(height))
            .sum()
    }

    pub fn member_by_id(&self, member_id: &str) -> Option<&CommitteeMember> {
        self.members
            .iter()
            .find(|member| member.member_id == member_id)
    }

    pub fn member_by_label(&self, label: &str) -> Option<&CommitteeMember> {
        self.members.iter().find(|member| member.label == label)
    }

    pub fn member_by_id_mut(&mut self, member_id: &str) -> Option<&mut CommitteeMember> {
        self.members
            .iter_mut()
            .find(|member| member.member_id == member_id)
    }

    pub fn active_member_ids_at(&self, height: u64) -> Vec<String> {
        self.active_members_at(height)
            .iter()
            .map(|member| member.member_id.clone())
            .collect()
    }

    pub fn leader_for_slot(
        &self,
        height: u64,
        microblock_sequence: u64,
        mode: LeaderScheduleMode,
    ) -> DecentralizedSequencerResult<CommitteeMember> {
        let active = self
            .members
            .iter()
            .filter(|member| {
                member.is_active_at(height) && member.has_role(CommitteeRole::Proposer)
            })
            .cloned()
            .collect::<Vec<_>>();
        if active.is_empty() {
            return Err("sequencer committee has no active proposers".to_string());
        }
        let index = match mode {
            LeaderScheduleMode::WeightedRoundRobin => {
                let total = active.iter().map(|member| member.voting_power).sum::<u64>();
                let mut point = deterministic_u64(
                    "DECENTRALIZED-SEQUENCER-LEADER-WEIGHTED-POINT",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Int(self.epoch as i128),
                        HashPart::Int(height as i128),
                        HashPart::Int(microblock_sequence as i128),
                    ],
                ) % total.max(1);
                let mut selected = 0_usize;
                for (idx, member) in active.iter().enumerate() {
                    if point < member.voting_power {
                        selected = idx;
                        break;
                    }
                    point = point.saturating_sub(member.voting_power);
                }
                selected
            }
            LeaderScheduleMode::RandomBeacon => {
                deterministic_u64(
                    "DECENTRALIZED-SEQUENCER-LEADER-BEACON",
                    &[
                        HashPart::Str(&self.committee_id),
                        HashPart::Int(height as i128),
                        HashPart::Int(microblock_sequence as i128),
                        HashPart::Str(&self.leader_schedule_root),
                    ],
                ) as usize
                    % active.len()
            }
            LeaderScheduleMode::FallbackRank => {
                height
                    .saturating_add(microblock_sequence)
                    .saturating_add(self.epoch) as usize
                    % active.len()
            }
        };
        Ok(active[index].clone())
    }

    pub fn leader_slot(
        &self,
        height: u64,
        microblock_sequence: u64,
        mode: LeaderScheduleMode,
    ) -> DecentralizedSequencerResult<LeaderScheduleSlot> {
        let leader = self.leader_for_slot(height, microblock_sequence, mode)?;
        LeaderScheduleSlot::new(
            self.epoch,
            height,
            microblock_sequence,
            leader.member_id,
            leader.label,
            mode,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderScheduleSlot {
    pub slot_id: String,
    pub epoch: u64,
    pub height: u64,
    pub microblock_sequence: u64,
    pub leader_member_id: String,
    pub leader_label: String,
    pub fallback_rank: u64,
    pub mode: LeaderScheduleMode,
    pub schedule_commitment: String,
}

impl LeaderScheduleSlot {
    pub fn new(
        epoch: u64,
        height: u64,
        microblock_sequence: u64,
        leader_member_id: impl Into<String>,
        leader_label: impl Into<String>,
        mode: LeaderScheduleMode,
    ) -> DecentralizedSequencerResult<Self> {
        let leader_member_id = leader_member_id.into();
        let leader_label = leader_label.into();
        ensure_non_empty(&leader_member_id, "leader member id")?;
        ensure_non_empty(&leader_label, "leader label")?;
        let fallback_rank = height
            .saturating_add(microblock_sequence)
            .saturating_add(epoch)
            % 256;
        let schedule_commitment = leader_schedule_slot_commitment(
            epoch,
            height,
            microblock_sequence,
            &leader_member_id,
            &leader_label,
            fallback_rank,
            mode,
        );
        let slot_id = leader_schedule_slot_id(
            epoch,
            height,
            microblock_sequence,
            &leader_member_id,
            &schedule_commitment,
        );
        Ok(Self {
            slot_id,
            epoch,
            height,
            microblock_sequence,
            leader_member_id,
            leader_label,
            fallback_rank,
            mode,
            schedule_commitment,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_sequencer_leader_slot",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "slot_id": self.slot_id,
            "epoch": self.epoch,
            "height": self.height,
            "microblock_sequence": self.microblock_sequence,
            "leader_member_id": self.leader_member_id,
            "leader_label": self.leader_label,
            "fallback_rank": self.fallback_rank,
            "mode": self.mode.as_str(),
            "schedule_commitment": self.schedule_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMempoolLane {
    pub lane_id: String,
    pub label: String,
    pub lane_kind: PrivateMempoolLaneKind,
    pub privacy_mode: LanePrivacyMode,
    pub admission_policy: LaneAdmissionPolicy,
    pub min_share_bps: u64,
    pub max_share_bps: u64,
    pub target_latency_ms: u64,
    pub min_fee_units: u64,
    pub max_fee_units: u64,
    pub anti_spam_bond_units: u64,
    pub decryption_threshold_bps: u64,
    pub kem_committee_key_id: String,
    pub lane_public_key_root: String,
    pub replay_protection_root: String,
    pub queue_depth: u64,
    pub admitted_count: u64,
    pub sealed_payload_count: u64,
    pub status: LaneStatus,
}

impl PrivateMempoolLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        lane_kind: PrivateMempoolLaneKind,
        privacy_mode: LanePrivacyMode,
        admission_policy: LaneAdmissionPolicy,
        min_share_bps: u64,
        max_share_bps: u64,
        min_fee_units: u64,
        max_fee_units: u64,
        anti_spam_bond_units: u64,
        decryption_threshold_bps: u64,
    ) -> DecentralizedSequencerResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "mempool lane label")?;
        ensure_bps(min_share_bps, "mempool lane min share bps")?;
        ensure_bps(max_share_bps, "mempool lane max share bps")?;
        ensure_bps(
            decryption_threshold_bps,
            "mempool lane decryption threshold bps",
        )?;
        if min_share_bps > max_share_bps {
            return Err("mempool lane min share exceeds max share".to_string());
        }
        if min_fee_units > max_fee_units {
            return Err("mempool lane min fee exceeds max fee".to_string());
        }
        let lane_public_key_root = lane_public_key_root(&label, lane_kind, privacy_mode);
        let kem_committee_key_id =
            lane_kem_committee_key_id(&label, lane_kind, privacy_mode, &lane_public_key_root);
        let replay_protection_root =
            lane_replay_protection_root(&label, lane_kind, privacy_mode, admission_policy);
        let lane_id = private_mempool_lane_id(
            &label,
            lane_kind,
            privacy_mode,
            admission_policy,
            min_share_bps,
            max_share_bps,
            &kem_committee_key_id,
        );
        Ok(Self {
            lane_id,
            label,
            lane_kind,
            privacy_mode,
            admission_policy,
            min_share_bps,
            max_share_bps,
            target_latency_ms: lane_kind.default_target_latency_ms(),
            min_fee_units,
            max_fee_units,
            anti_spam_bond_units,
            decryption_threshold_bps,
            kem_committee_key_id,
            lane_public_key_root,
            replay_protection_root,
            queue_depth: 0,
            admitted_count: 0,
            sealed_payload_count: 0,
            status: LaneStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mempool_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "label": self.label,
            "lane_kind": self.lane_kind.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "admission_policy": self.admission_policy.as_str(),
            "min_share_bps": self.min_share_bps,
            "max_share_bps": self.max_share_bps,
            "target_latency_ms": self.target_latency_ms,
            "min_fee_units": self.min_fee_units,
            "max_fee_units": self.max_fee_units,
            "anti_spam_bond_units": self.anti_spam_bond_units,
            "decryption_threshold_bps": self.decryption_threshold_bps,
            "kem_committee_key_id": self.kem_committee_key_id,
            "lane_public_key_root": self.lane_public_key_root,
            "replay_protection_root": self.replay_protection_root,
            "queue_depth": self.queue_depth,
            "admitted_count": self.admitted_count,
            "sealed_payload_count": self.sealed_payload_count,
            "status": self.status.as_str(),
        })
    }

    pub fn lane_root(&self) -> String {
        private_mempool_lane_root(&self.public_record())
    }

    pub fn admits(&self) -> bool {
        self.status.admits()
    }

    pub fn is_private(&self) -> bool {
        self.lane_kind.is_private() || self.privacy_mode.requires_kem()
    }

    pub fn low_fee_eligible(&self) -> bool {
        self.lane_kind.low_fee_eligible()
            || self.admission_policy == LaneAdmissionPolicy::LowFeeSponsored
    }

    pub fn base_priority(&self) -> u64 {
        self.lane_kind
            .default_priority()
            .saturating_add(self.min_share_bps)
            .saturating_sub(self.queue_depth.min(10_000))
    }

    pub fn register_admission(&mut self, sealed_payload: bool) {
        self.queue_depth = self.queue_depth.saturating_add(1);
        self.admitted_count = self.admitted_count.saturating_add(1);
        if sealed_payload {
            self.sealed_payload_count = self.sealed_payload_count.saturating_add(1);
        }
    }

    pub fn register_inclusion(&mut self) {
        self.queue_depth = self.queue_depth.saturating_sub(1);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMempoolEntry {
    pub entry_id: String,
    pub lane_id: String,
    pub sender_commitment: String,
    pub tx_public_hash: String,
    pub encrypted_payload_hash: String,
    pub nullifier_root: String,
    pub fee_asset_id: String,
    pub offered_fee_units: u64,
    pub max_fee_units: u64,
    pub gas_limit_units: u64,
    pub qos_tier: u64,
    pub arrival_slot: u64,
    pub local_sequence: u64,
    pub encrypted_at_height: u64,
    pub expires_at_height: u64,
    pub kem_envelope: KemEnvelope,
    pub low_fee_eligible: bool,
    pub privacy_budget_units: u64,
    pub monotonic_fee_score: u64,
    pub ordering_commitment: String,
    pub public_metadata_root: String,
    pub status: MempoolEntryStatus,
}

impl PrivateMempoolEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: &PrivateMempoolLane,
        sender_label: impl Into<String>,
        tx_public_record: &Value,
        encrypted_payload_record: &Value,
        fee_asset_id: impl Into<String>,
        offered_fee_units: u64,
        max_fee_units: u64,
        gas_limit_units: u64,
        qos_tier: u64,
        arrival_slot: u64,
        local_sequence: u64,
        encrypted_at_height: u64,
        expires_at_height: u64,
    ) -> DecentralizedSequencerResult<Self> {
        if !lane.admits() {
            return Err("mempool lane is not admitting entries".to_string());
        }
        if expires_at_height <= encrypted_at_height {
            return Err("mempool entry expiry must be after encryption height".to_string());
        }
        if offered_fee_units > max_fee_units {
            return Err("mempool entry offered fee exceeds max fee".to_string());
        }
        let sender_label = sender_label.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&sender_label, "mempool sender label")?;
        ensure_non_empty(&fee_asset_id, "mempool fee asset id")?;
        ensure_positive(gas_limit_units, "mempool gas limit")?;
        let sender_commitment = sender_commitment(&sender_label);
        let tx_public_hash = decentralized_sequencer_payload_root(
            "DECENTRALIZED-SEQUENCER-TX-PUBLIC-HASH",
            tx_public_record,
        );
        let encrypted_payload_hash = decentralized_sequencer_payload_root(
            "DECENTRALIZED-SEQUENCER-ENCRYPTED-PAYLOAD-HASH",
            encrypted_payload_record,
        );
        let nullifier_root = mempool_entry_nullifier_root(
            &sender_commitment,
            &tx_public_hash,
            &encrypted_payload_hash,
            local_sequence,
        );
        let kem_transcript = json!({
            "kind": "decentralized_sequencer_mempool_entry_kem_transcript",
            "chain_id": CHAIN_ID,
            "lane_id": lane.lane_id,
            "tx_public_hash": tx_public_hash,
            "encrypted_payload_hash": encrypted_payload_hash,
            "arrival_slot": arrival_slot,
            "local_sequence": local_sequence,
            "encrypted_at_height": encrypted_at_height,
            "expires_at_height": expires_at_height,
        });
        let kem_envelope = build_kem_envelope(
            CryptoRole::KeyEstablishment,
            &lane.kem_committee_key_id,
            &lane.lane_public_key_root,
            &kem_transcript,
        );
        let public_metadata_root = mempool_entry_public_metadata_root(
            &fee_asset_id,
            offered_fee_units,
            max_fee_units,
            gas_limit_units,
            qos_tier,
            lane.privacy_mode,
        );
        let monotonic_fee_score = monotonic_fee_score(
            lane,
            offered_fee_units,
            max_fee_units,
            gas_limit_units,
            qos_tier,
            arrival_slot,
        );
        let ordering_commitment = mempool_entry_ordering_commitment(
            &lane.lane_id,
            &tx_public_hash,
            &encrypted_payload_hash,
            &nullifier_root,
            monotonic_fee_score,
            arrival_slot,
            local_sequence,
        );
        let entry_id = private_mempool_entry_id(
            &lane.lane_id,
            &sender_commitment,
            &tx_public_hash,
            &encrypted_payload_hash,
            &ordering_commitment,
            arrival_slot,
            local_sequence,
        );
        Ok(Self {
            entry_id,
            lane_id: lane.lane_id.clone(),
            sender_commitment,
            tx_public_hash,
            encrypted_payload_hash,
            nullifier_root,
            fee_asset_id,
            offered_fee_units,
            max_fee_units,
            gas_limit_units,
            qos_tier,
            arrival_slot,
            local_sequence,
            encrypted_at_height,
            expires_at_height,
            kem_envelope,
            low_fee_eligible: lane.low_fee_eligible(),
            privacy_budget_units: if lane.is_private() {
                gas_limit_units / 4
            } else {
                0
            },
            monotonic_fee_score,
            ordering_commitment,
            public_metadata_root,
            status: MempoolEntryStatus::Pending,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_mempool_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "entry_id": self.entry_id,
            "lane_id": self.lane_id,
            "sender_commitment": self.sender_commitment,
            "tx_public_hash": self.tx_public_hash,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "nullifier_root": self.nullifier_root,
            "fee_asset_id": self.fee_asset_id,
            "offered_fee_units": self.offered_fee_units,
            "max_fee_units": self.max_fee_units,
            "gas_limit_units": self.gas_limit_units,
            "qos_tier": self.qos_tier,
            "arrival_slot": self.arrival_slot,
            "local_sequence": self.local_sequence,
            "encrypted_at_height": self.encrypted_at_height,
            "expires_at_height": self.expires_at_height,
            "kem_envelope": self.kem_envelope.public_record(),
            "low_fee_eligible": self.low_fee_eligible,
            "privacy_budget_units": self.privacy_budget_units,
            "monotonic_fee_score": self.monotonic_fee_score,
            "ordering_commitment": self.ordering_commitment,
            "public_metadata_root": self.public_metadata_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("mempool entry object")
            .insert("status_rank".to_string(), json!(self.status_rank()));
        record
    }

    pub fn entry_root(&self) -> String {
        private_mempool_entry_root(&self.public_record())
    }

    pub fn status_rank(&self) -> u64 {
        match self.status {
            MempoolEntryStatus::Pending => 0,
            MempoolEntryStatus::Ordered => 1,
            MempoolEntryStatus::Included => 2,
            MempoolEntryStatus::Expired => 3,
            MempoolEntryStatus::Censored => 4,
            MempoolEntryStatus::Rejected => 5,
        }
    }

    pub fn priority_score(&self, lane: &PrivateMempoolLane) -> u64 {
        lane.base_priority()
            .saturating_add(self.monotonic_fee_score)
            .saturating_add(self.qos_tier.saturating_mul(10_000))
            .saturating_sub(self.arrival_slot.min(10_000))
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        self.expires_at_height <= height
    }

    pub fn mark_ordered(&mut self) {
        self.status = MempoolEntryStatus::Ordered;
    }

    pub fn mark_included(&mut self) {
        self.status = MempoolEntryStatus::Included;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeQosPolicy {
    pub policy_id: String,
    pub epoch: u64,
    pub budget_units: u64,
    pub remaining_budget_units: u64,
    pub min_low_fee_share_bps: u64,
    pub max_rebate_bps: u64,
    pub min_settled_fee_units: u64,
    pub sponsored_lane_root: String,
    pub fairness_salt_root: String,
}

impl LowFeeQosPolicy {
    pub fn new(
        epoch: u64,
        budget_units: u64,
        min_low_fee_share_bps: u64,
        max_rebate_bps: u64,
        min_settled_fee_units: u64,
        sponsored_lane_ids: &[String],
    ) -> DecentralizedSequencerResult<Self> {
        ensure_positive(budget_units, "low-fee QoS budget")?;
        ensure_bps(min_low_fee_share_bps, "low-fee QoS min share")?;
        ensure_bps(max_rebate_bps, "low-fee QoS max rebate")?;
        let sponsored_lane_root = decentralized_sequencer_string_set_root(
            "DECENTRALIZED-SEQUENCER-SPONSORED-LANE-ROOT",
            sponsored_lane_ids,
        );
        let fairness_salt_root = low_fee_fairness_salt_root(epoch, &sponsored_lane_root);
        let policy_id = low_fee_qos_policy_id(
            epoch,
            budget_units,
            min_low_fee_share_bps,
            max_rebate_bps,
            min_settled_fee_units,
            &sponsored_lane_root,
        );
        Ok(Self {
            policy_id,
            epoch,
            budget_units,
            remaining_budget_units: budget_units,
            min_low_fee_share_bps,
            max_rebate_bps,
            min_settled_fee_units,
            sponsored_lane_root,
            fairness_salt_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_qos_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "epoch": self.epoch,
            "budget_units": self.budget_units,
            "remaining_budget_units": self.remaining_budget_units,
            "min_low_fee_share_bps": self.min_low_fee_share_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_settled_fee_units": self.min_settled_fee_units,
            "sponsored_lane_root": self.sponsored_lane_root,
            "fairness_salt_root": self.fairness_salt_root,
        })
    }

    pub fn policy_root(&self) -> String {
        low_fee_qos_policy_root(&self.public_record())
    }

    pub fn reserve_rebate(&mut self, requested_fee_units: u64) -> u64 {
        let cap = requested_fee_units
            .saturating_mul(self.max_rebate_bps)
            .saturating_div(DECENTRALIZED_SEQUENCER_MAX_BPS);
        let rebate = cap.min(self.remaining_budget_units);
        self.remaining_budget_units = self.remaining_budget_units.saturating_sub(rebate);
        rebate
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosDecision {
    pub decision_id: String,
    pub entry_id: String,
    pub lane_id: String,
    pub decision_kind: QosDecisionKind,
    pub reason: String,
    pub priority_score: u64,
    pub reserved_budget_units: u64,
    pub charged_fee_units: u64,
    pub rebate_units: u64,
    pub promised_inclusion_height: u64,
    pub expires_at_height: u64,
    pub decision_root: String,
}

impl QosDecision {
    pub fn assess(
        entry: &PrivateMempoolEntry,
        lane: &PrivateMempoolLane,
        policy: &mut LowFeeQosPolicy,
        current_height: u64,
    ) -> DecentralizedSequencerResult<Self> {
        if !entry.status.is_pending() {
            return Err("QoS can only assess pending mempool entries".to_string());
        }
        let priority_score = entry.priority_score(lane);
        let mut decision_kind = QosDecisionKind::Admit;
        let mut reason = "lane_admission_ok".to_string();
        let mut charged_fee_units = entry.offered_fee_units.max(lane.min_fee_units);
        let mut reserved_budget_units = 0_u64;
        let mut rebate_units = 0_u64;
        if entry.is_expired_at(current_height) {
            decision_kind = QosDecisionKind::Reject;
            reason = "entry_expired".to_string();
        } else if !lane.admits() {
            decision_kind = QosDecisionKind::Throttle;
            reason = "lane_not_admitting".to_string();
        } else if lane.admission_policy.requires_bond()
            && entry.max_fee_units < lane.anti_spam_bond_units
        {
            decision_kind = QosDecisionKind::Delay;
            reason = "bond_required".to_string();
        } else if entry.low_fee_eligible && lane.low_fee_eligible() {
            rebate_units = policy.reserve_rebate(charged_fee_units);
            reserved_budget_units = rebate_units;
            charged_fee_units = charged_fee_units.saturating_sub(rebate_units);
            decision_kind = QosDecisionKind::Preconfirm;
            reason = "low_fee_sponsored_preconfirm".to_string();
        }
        let promised_inclusion_height = current_height
            .saturating_add(1)
            .saturating_add(lane.target_latency_ms / TARGET_BLOCK_MS.max(1));
        let expires_at_height = entry.expires_at_height.min(
            promised_inclusion_height
                .saturating_add(DECENTRALIZED_SEQUENCER_DEFAULT_ENCRYPTED_TTL_BLOCKS),
        );
        let decision_root = qos_decision_transcript_root(
            &entry.entry_id,
            &lane.lane_id,
            decision_kind,
            &reason,
            priority_score,
            reserved_budget_units,
            charged_fee_units,
            rebate_units,
            promised_inclusion_height,
            expires_at_height,
        );
        let decision_id = qos_decision_id(
            &entry.entry_id,
            &lane.lane_id,
            decision_kind,
            priority_score,
            &decision_root,
        );
        Ok(Self {
            decision_id,
            entry_id: entry.entry_id.clone(),
            lane_id: lane.lane_id.clone(),
            decision_kind,
            reason,
            priority_score,
            reserved_budget_units,
            charged_fee_units,
            rebate_units,
            promised_inclusion_height,
            expires_at_height,
            decision_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_sequencer_qos_decision",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "decision_id": self.decision_id,
            "entry_id": self.entry_id,
            "lane_id": self.lane_id,
            "decision_kind": self.decision_kind.as_str(),
            "reason": self.reason,
            "priority_score": self.priority_score,
            "reserved_budget_units": self.reserved_budget_units,
            "charged_fee_units": self.charged_fee_units,
            "rebate_units": self.rebate_units,
            "promised_inclusion_height": self.promised_inclusion_height,
            "expires_at_height": self.expires_at_height,
            "decision_root": self.decision_root,
        })
    }

    pub fn admits(&self) -> bool {
        matches!(
            self.decision_kind,
            QosDecisionKind::Admit | QosDecisionKind::Preconfirm
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairOrderingBatch {
    pub batch_id: String,
    pub height: u64,
    pub microblock_sequence: u64,
    pub lane_id: String,
    pub lane_kind: PrivateMempoolLaneKind,
    pub ordered_entry_ids: Vec<String>,
    pub omitted_entry_ids: Vec<String>,
    pub ordering_seed: String,
    pub fairness_root: String,
    pub private_order_root: String,
    pub low_fee_root: String,
    pub fee_bucket_root: String,
    pub qos_decision_root: String,
    pub total_fee_units: u64,
    pub low_fee_count: u64,
    pub private_count: u64,
    pub monero_bridge_count: u64,
}

impl FairOrderingBatch {
    pub fn build(
        height: u64,
        microblock_sequence: u64,
        lane: &PrivateMempoolLane,
        entries: &[PrivateMempoolEntry],
        qos_decisions: &[QosDecision],
        max_items: u64,
    ) -> Self {
        let mut scored = entries
            .iter()
            .filter(|entry| entry.status.is_pending() && entry.lane_id == lane.lane_id)
            .map(|entry| {
                let decision_score = qos_decisions
                    .iter()
                    .find(|decision| decision.entry_id == entry.entry_id)
                    .map(|decision| decision.priority_score)
                    .unwrap_or_else(|| entry.priority_score(lane));
                (
                    std::cmp::Reverse(decision_score),
                    entry.arrival_slot,
                    entry.local_sequence,
                    entry.entry_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        scored.sort();
        let ordered_entry_ids = scored
            .iter()
            .take(max_items as usize)
            .map(|(_, _, _, entry_id)| entry_id.clone())
            .collect::<Vec<_>>();
        let ordered_set = ordered_entry_ids.iter().cloned().collect::<BTreeSet<_>>();
        let omitted_entry_ids = scored
            .iter()
            .filter(|(_, _, _, entry_id)| !ordered_set.contains(entry_id))
            .map(|(_, _, _, entry_id)| entry_id.clone())
            .collect::<Vec<_>>();
        let selected_entries = entries
            .iter()
            .filter(|entry| ordered_set.contains(&entry.entry_id))
            .cloned()
            .collect::<Vec<_>>();
        let selected_decisions = qos_decisions
            .iter()
            .filter(|decision| ordered_set.contains(&decision.entry_id))
            .cloned()
            .collect::<Vec<_>>();
        let total_fee_units = selected_entries
            .iter()
            .map(|entry| entry.offered_fee_units)
            .sum::<u64>();
        let low_fee_count = selected_entries
            .iter()
            .filter(|entry| entry.low_fee_eligible)
            .count() as u64;
        let private_count = selected_entries
            .iter()
            .filter(|entry| entry.privacy_budget_units > 0)
            .count() as u64;
        let monero_bridge_count = if lane.lane_kind.monero_sensitive() {
            ordered_entry_ids.len() as u64
        } else {
            0
        };
        let ordering_seed = fair_ordering_seed(
            height,
            microblock_sequence,
            &lane.lane_id,
            &ordered_entry_ids,
        );
        let fairness_root = fair_ordering_fairness_root(
            height,
            microblock_sequence,
            lane,
            &ordered_entry_ids,
            &omitted_entry_ids,
        );
        let private_order_root = private_order_root(&selected_entries);
        let low_fee_root = low_fee_order_root(&selected_entries);
        let fee_bucket_root = fee_bucket_order_root(&selected_entries);
        let qos_decision_root = qos_decision_set_root(&selected_decisions);
        let batch_id = fair_ordering_batch_id(
            height,
            microblock_sequence,
            &lane.lane_id,
            &ordering_seed,
            &fairness_root,
            &qos_decision_root,
        );
        Self {
            batch_id,
            height,
            microblock_sequence,
            lane_id: lane.lane_id.clone(),
            lane_kind: lane.lane_kind,
            ordered_entry_ids,
            omitted_entry_ids,
            ordering_seed,
            fairness_root,
            private_order_root,
            low_fee_root,
            fee_bucket_root,
            qos_decision_root,
            total_fee_units,
            low_fee_count,
            private_count,
            monero_bridge_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fair_ordering_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "height": self.height,
            "microblock_sequence": self.microblock_sequence,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "ordered_entry_ids": self.ordered_entry_ids,
            "omitted_entry_ids": self.omitted_entry_ids,
            "ordering_seed": self.ordering_seed,
            "fairness_root": self.fairness_root,
            "private_order_root": self.private_order_root,
            "low_fee_root": self.low_fee_root,
            "fee_bucket_root": self.fee_bucket_root,
            "qos_decision_root": self.qos_decision_root,
            "total_fee_units": self.total_fee_units,
            "low_fee_count": self.low_fee_count,
            "private_count": self.private_count,
            "monero_bridge_count": self.monero_bridge_count,
        })
    }

    pub fn batch_root(&self) -> String {
        fair_ordering_batch_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSequencerAttestation {
    pub attestation_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub member_id: String,
    pub member_label: String,
    pub committee_role: CommitteeRole,
    pub crypto_role: CryptoRole,
    pub public_key: String,
    pub public_key_root: String,
    pub transcript_root: String,
    pub signature_scheme: String,
    pub signature_root: String,
    pub attested_at_height: u64,
    pub attested_at_microblock: u64,
    pub voting_power: u64,
    pub authorization: Authorization,
}

impl PqSequencerAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        member: &CommitteeMember,
        committee_role: CommitteeRole,
        transcript: &Value,
        attested_at_height: u64,
        attested_at_microblock: u64,
    ) -> DecentralizedSequencerResult<Self> {
        let subject_kind = subject_kind.into();
        let subject_id = subject_id.into();
        ensure_non_empty(&subject_kind, "attestation subject kind")?;
        ensure_non_empty(&subject_id, "attestation subject id")?;
        if !member.has_role(committee_role) && committee_role != CommitteeRole::Voter {
            return Err("committee member does not have attestation role".to_string());
        }
        let crypto_role = committee_role.crypto_role();
        let public_key_record = public_key_for_label(crypto_role.clone(), &member.label);
        let transcript_root = decentralized_sequencer_payload_root(
            "DECENTRALIZED-SEQUENCER-PQ-ATTESTATION-TRANSCRIPT",
            transcript,
        );
        let signature_root = pq_attestation_signature_root(
            &member.member_id,
            &public_key_record.key_id,
            crypto_role.scheme(),
            &transcript_root,
        );
        let attestation_id = pq_attestation_id(
            &subject_kind,
            &subject_id,
            &member.member_id,
            committee_role,
            &public_key_record.key_id,
            &transcript_root,
            member.voting_power,
            attested_at_height,
            attested_at_microblock,
        );
        let mut attestation = Self {
            attestation_id,
            subject_kind,
            subject_id,
            member_id: member.member_id.clone(),
            member_label: member.label.clone(),
            committee_role,
            crypto_role: crypto_role.clone(),
            public_key: public_key_record.public_key,
            public_key_root: public_key_record.key_id,
            transcript_root,
            signature_scheme: crypto_role.scheme().to_string(),
            signature_root,
            attested_at_height,
            attested_at_microblock,
            voting_power: member.voting_power,
            authorization: empty_authorization(),
        };
        attestation.authorization = sign_authorization_for_role(
            attestation.crypto_role.clone(),
            &attestation.member_label,
            "decentralized_sequencer_pq_attestation",
            &attestation.unsigned_record(),
        );
        Ok(attestation)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "pq_sequencer_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "member_id": self.member_id,
            "member_label": self.member_label,
            "committee_role": self.committee_role.as_str(),
            "crypto_role": self.crypto_role.as_str(),
            "public_key_root": self.public_key_root,
            "transcript_root": self.transcript_root,
            "signature_scheme": self.signature_scheme,
            "signature_root": self.signature_root,
            "attested_at_height": self.attested_at_height,
            "attested_at_microblock": self.attested_at_microblock,
            "voting_power": self.voting_power,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("attestation object")
            .insert("authorization".to_string(), json!(self.authorization));
        record
    }

    pub fn verify_authorization(&self) -> bool {
        verify_authorization_for_role(
            self.crypto_role.clone(),
            &self.public_key,
            "decentralized_sequencer_pq_attestation",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn attestation_root(&self) -> String {
        pq_attestation_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroblockProposal {
    pub proposal_id: String,
    pub height: u64,
    pub microblock_sequence: u64,
    pub epoch: u64,
    pub leader_member_id: String,
    pub leader_label: String,
    pub parent_microblock_id: String,
    pub parent_state_root: String,
    pub ordering_batch_root: String,
    pub included_entry_ids: Vec<String>,
    pub private_payload_root: String,
    pub public_tx_root: String,
    pub qos_decision_root: String,
    pub fee_summary_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub created_at_ms: u64,
    pub attestation: PqSequencerAttestation,
    pub status: MicroblockStatus,
}

impl MicroblockProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        microblock_sequence: u64,
        epoch: u64,
        leader: &CommitteeMember,
        parent_microblock_id: impl Into<String>,
        parent_state_root: impl Into<String>,
        batch: &FairOrderingBatch,
        qos_decisions: &[QosDecision],
        state_root_before: impl Into<String>,
        created_at_ms: u64,
    ) -> DecentralizedSequencerResult<Self> {
        if !leader.has_role(CommitteeRole::Proposer) {
            return Err("microblock leader is not a proposer".to_string());
        }
        let parent_microblock_id = parent_microblock_id.into();
        let parent_state_root = parent_state_root.into();
        let state_root_before = state_root_before.into();
        ensure_non_empty(&parent_microblock_id, "microblock parent id")?;
        ensure_non_empty(&parent_state_root, "microblock parent state root")?;
        ensure_non_empty(&state_root_before, "microblock state root before")?;
        let included_entry_ids = batch.ordered_entry_ids.clone();
        let private_payload_root = batch.private_order_root.clone();
        let public_tx_root = decentralized_sequencer_string_set_root(
            "DECENTRALIZED-SEQUENCER-MICROBLOCK-PUBLIC-TX-ROOT",
            &included_entry_ids,
        );
        let selected_decisions = qos_decisions
            .iter()
            .filter(|decision| included_entry_ids.contains(&decision.entry_id))
            .cloned()
            .collect::<Vec<_>>();
        let qos_decision_root = qos_decision_set_root(&selected_decisions);
        let fee_summary_root = microblock_fee_summary_root(batch, &selected_decisions);
        let state_root_after = microblock_state_transition_root(
            &parent_state_root,
            &state_root_before,
            &batch.batch_id,
            &public_tx_root,
            &private_payload_root,
            &qos_decision_root,
        );
        let ordering_batch_root = batch.batch_root();
        let proposal_id = microblock_proposal_id(
            height,
            microblock_sequence,
            epoch,
            &leader.member_id,
            &parent_microblock_id,
            &parent_state_root,
            &ordering_batch_root,
            &state_root_after,
        );
        let unsigned = microblock_proposal_unsigned_record(
            &proposal_id,
            height,
            microblock_sequence,
            epoch,
            &leader.member_id,
            &leader.label,
            &parent_microblock_id,
            &parent_state_root,
            &ordering_batch_root,
            &included_entry_ids,
            &private_payload_root,
            &public_tx_root,
            &qos_decision_root,
            &fee_summary_root,
            &state_root_before,
            &state_root_after,
            created_at_ms,
            MicroblockStatus::Proposed,
        );
        let attestation = PqSequencerAttestation::new(
            "microblock_proposal",
            &proposal_id,
            leader,
            CommitteeRole::Proposer,
            &unsigned,
            height,
            microblock_sequence,
        )?;
        Ok(Self {
            proposal_id,
            height,
            microblock_sequence,
            epoch,
            leader_member_id: leader.member_id.clone(),
            leader_label: leader.label.clone(),
            parent_microblock_id,
            parent_state_root,
            ordering_batch_root,
            included_entry_ids,
            private_payload_root,
            public_tx_root,
            qos_decision_root,
            fee_summary_root,
            state_root_before,
            state_root_after,
            created_at_ms,
            attestation,
            status: MicroblockStatus::Proposed,
        })
    }

    pub fn unsigned_record(&self) -> Value {
        microblock_proposal_unsigned_record(
            &self.proposal_id,
            self.height,
            self.microblock_sequence,
            self.epoch,
            &self.leader_member_id,
            &self.leader_label,
            &self.parent_microblock_id,
            &self.parent_state_root,
            &self.ordering_batch_root,
            &self.included_entry_ids,
            &self.private_payload_root,
            &self.public_tx_root,
            &self.qos_decision_root,
            &self.fee_summary_root,
            &self.state_root_before,
            &self.state_root_after,
            self.created_at_ms,
            self.status,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("microblock proposal object")
            .insert("attestation".to_string(), self.attestation.public_record());
        record
    }

    pub fn proposal_root(&self) -> String {
        microblock_proposal_root(&self.public_record())
    }

    pub fn mark_soft_finalized(&mut self) {
        self.status = MicroblockStatus::SoftFinalized;
    }

    pub fn mark_finalized(&mut self) {
        self.status = MicroblockStatus::Finalized;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroblockFinalityVote {
    pub vote_id: String,
    pub vote_kind: FinalityVoteKind,
    pub proposal_id: String,
    pub height: u64,
    pub microblock_sequence: u64,
    pub state_root: String,
    pub block_root: String,
    pub voter_member_id: String,
    pub voter_label: String,
    pub voting_power: u64,
    pub lock_round: u64,
    pub attestation: PqSequencerAttestation,
    pub status: String,
}

impl MicroblockFinalityVote {
    pub fn new(
        vote_kind: FinalityVoteKind,
        proposal: &MicroblockProposal,
        voter: &CommitteeMember,
        lock_round: u64,
    ) -> DecentralizedSequencerResult<Self> {
        if !voter.has_role(CommitteeRole::Voter) {
            return Err("finality voter is not a committee voter".to_string());
        }
        let block_root = proposal.proposal_root();
        let vote_id = microblock_finality_vote_id(
            vote_kind,
            &proposal.proposal_id,
            proposal.height,
            proposal.microblock_sequence,
            &proposal.state_root_after,
            &voter.member_id,
            lock_round,
        );
        let unsigned = microblock_finality_vote_unsigned_record(
            &vote_id,
            vote_kind,
            &proposal.proposal_id,
            proposal.height,
            proposal.microblock_sequence,
            &proposal.state_root_after,
            &block_root,
            &voter.member_id,
            &voter.label,
            voter.voting_power,
            lock_round,
            "accepted",
        );
        let attestation = PqSequencerAttestation::new(
            "microblock_finality_vote",
            &vote_id,
            voter,
            CommitteeRole::Voter,
            &unsigned,
            proposal.height,
            proposal.microblock_sequence,
        )?;
        Ok(Self {
            vote_id,
            vote_kind,
            proposal_id: proposal.proposal_id.clone(),
            height: proposal.height,
            microblock_sequence: proposal.microblock_sequence,
            state_root: proposal.state_root_after.clone(),
            block_root,
            voter_member_id: voter.member_id.clone(),
            voter_label: voter.label.clone(),
            voting_power: voter.voting_power,
            lock_round,
            attestation,
            status: "accepted".to_string(),
        })
    }

    pub fn unsigned_record(&self) -> Value {
        microblock_finality_vote_unsigned_record(
            &self.vote_id,
            self.vote_kind,
            &self.proposal_id,
            self.height,
            self.microblock_sequence,
            &self.state_root,
            &self.block_root,
            &self.voter_member_id,
            &self.voter_label,
            self.voting_power,
            self.lock_round,
            &self.status,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("finality vote object")
            .insert("attestation".to_string(), self.attestation.public_record());
        record
    }

    pub fn vote_root(&self) -> String {
        microblock_finality_vote_root(&self.public_record())
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.voter_member_id == other.voter_member_id
            && self.vote_kind == other.vote_kind
            && self.height == other.height
            && self.microblock_sequence == other.microblock_sequence
            && (self.proposal_id != other.proposal_id || self.state_root != other.state_root)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCertificate {
    pub certificate_id: String,
    pub certificate_kind: FinalityCertificateKind,
    pub proposal_id: String,
    pub height: u64,
    pub microblock_sequence: u64,
    pub state_root: String,
    pub block_root: String,
    pub vote_root: String,
    pub voter_root: String,
    pub total_voting_power: u64,
    pub signed_voting_power: u64,
    pub quorum_bps: u64,
    pub quorum_reached: bool,
    pub finalized_at_height: u64,
    pub finalized_at_microblock: u64,
    pub status: String,
}

impl FinalityCertificate {
    pub fn build(
        certificate_kind: FinalityCertificateKind,
        proposal: &MicroblockProposal,
        votes: &[MicroblockFinalityVote],
        committee: &SequencerCommittee,
        config: &DecentralizedSequencerConfig,
        finalized_at_height: u64,
        finalized_at_microblock: u64,
    ) -> DecentralizedSequencerResult<Self> {
        let vote_kind = certificate_kind.vote_kind();
        let matching = votes
            .iter()
            .filter(|vote| {
                vote.vote_kind == vote_kind
                    && vote.proposal_id == proposal.proposal_id
                    && vote.state_root == proposal.state_root_after
            })
            .cloned()
            .collect::<Vec<_>>();
        let voter_ids = matching
            .iter()
            .map(|vote| vote.voter_member_id.clone())
            .collect::<Vec<_>>();
        ensure_unique_strings(&voter_ids, "finality certificate voters")?;
        let signed_voting_power = matching
            .iter()
            .map(|vote| {
                committee
                    .member_by_id(&vote.voter_member_id)
                    .map(|member| member.effective_power_at(proposal.height))
                    .unwrap_or(0)
            })
            .sum::<u64>();
        let total_voting_power = committee.active_voting_power_at(proposal.height);
        let quorum_bps = vote_kind.quorum_bps(config);
        let quorum_reached = reaches_quorum(signed_voting_power, total_voting_power, quorum_bps);
        let vote_root = microblock_finality_vote_set_root(&matching);
        let voter_root = decentralized_sequencer_string_set_root(
            "DECENTRALIZED-SEQUENCER-FINALITY-VOTER-ROOT",
            &voter_ids,
        );
        let certificate_id = finality_certificate_id(
            certificate_kind,
            &proposal.proposal_id,
            proposal.height,
            proposal.microblock_sequence,
            &proposal.state_root_after,
            &vote_root,
            signed_voting_power,
            quorum_bps,
        );
        Ok(Self {
            certificate_id,
            certificate_kind,
            proposal_id: proposal.proposal_id.clone(),
            height: proposal.height,
            microblock_sequence: proposal.microblock_sequence,
            state_root: proposal.state_root_after.clone(),
            block_root: proposal.proposal_root(),
            vote_root,
            voter_root,
            total_voting_power,
            signed_voting_power,
            quorum_bps,
            quorum_reached,
            finalized_at_height,
            finalized_at_microblock,
            status: if quorum_reached {
                "quorum_reached".to_string()
            } else {
                "insufficient_power".to_string()
            },
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_sequencer_finality_certificate",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "certificate_id": self.certificate_id,
            "certificate_kind": self.certificate_kind.as_str(),
            "proposal_id": self.proposal_id,
            "height": self.height,
            "microblock_sequence": self.microblock_sequence,
            "state_root": self.state_root,
            "block_root": self.block_root,
            "vote_root": self.vote_root,
            "voter_root": self.voter_root,
            "total_voting_power": self.total_voting_power,
            "signed_voting_power": self.signed_voting_power,
            "quorum_bps": self.quorum_bps,
            "quorum_reached": self.quorum_reached,
            "finalized_at_height": self.finalized_at_height,
            "finalized_at_microblock": self.finalized_at_microblock,
            "status": self.status,
        })
    }

    pub fn certificate_root(&self) -> String {
        finality_certificate_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    pub evidence_id: String,
    pub kind: EquivocationKind,
    pub offender_member_id: String,
    pub offender_label: String,
    pub height: u64,
    pub microblock_sequence: u64,
    pub first_subject_id: String,
    pub second_subject_id: String,
    pub first_root: String,
    pub second_root: String,
    pub shared_lock_round: u64,
    pub detected_by: String,
    pub detected_at_height: u64,
    pub slash_bps: u64,
    pub evidence_root: String,
    pub status: EvidenceStatus,
}

impl EquivocationEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: EquivocationKind,
        offender_member_id: impl Into<String>,
        offender_label: impl Into<String>,
        height: u64,
        microblock_sequence: u64,
        first_subject_id: impl Into<String>,
        second_subject_id: impl Into<String>,
        first_root: impl Into<String>,
        second_root: impl Into<String>,
        shared_lock_round: u64,
        detected_by: impl Into<String>,
        detected_at_height: u64,
    ) -> DecentralizedSequencerResult<Self> {
        let offender_member_id = offender_member_id.into();
        let offender_label = offender_label.into();
        let first_subject_id = first_subject_id.into();
        let second_subject_id = second_subject_id.into();
        let first_root = first_root.into();
        let second_root = second_root.into();
        let detected_by = detected_by.into();
        ensure_non_empty(&offender_member_id, "equivocation offender id")?;
        ensure_non_empty(&offender_label, "equivocation offender label")?;
        ensure_non_empty(&first_subject_id, "equivocation first subject")?;
        ensure_non_empty(&second_subject_id, "equivocation second subject")?;
        ensure_non_empty(&first_root, "equivocation first root")?;
        ensure_non_empty(&second_root, "equivocation second root")?;
        ensure_non_empty(&detected_by, "equivocation detector")?;
        if first_subject_id == second_subject_id && first_root == second_root {
            return Err("equivocation evidence subjects are identical".to_string());
        }
        let slash_bps = kind.default_slash_bps();
        let evidence_root = equivocation_evidence_payload_root(
            kind,
            &offender_member_id,
            height,
            microblock_sequence,
            &first_subject_id,
            &second_subject_id,
            &first_root,
            &second_root,
            shared_lock_round,
        );
        let evidence_id = equivocation_evidence_id(
            kind,
            &offender_member_id,
            height,
            microblock_sequence,
            &first_subject_id,
            &second_subject_id,
            &evidence_root,
        );
        Ok(Self {
            evidence_id,
            kind,
            offender_member_id,
            offender_label,
            height,
            microblock_sequence,
            first_subject_id,
            second_subject_id,
            first_root,
            second_root,
            shared_lock_round,
            detected_by,
            detected_at_height,
            slash_bps,
            evidence_root,
            status: EvidenceStatus::Observed,
        })
    }

    pub fn from_conflicting_votes(
        first: &MicroblockFinalityVote,
        second: &MicroblockFinalityVote,
        detected_by: impl Into<String>,
        detected_at_height: u64,
    ) -> DecentralizedSequencerResult<Self> {
        if !first.conflicts_with(second) {
            return Err("votes do not conflict".to_string());
        }
        Self::new(
            EquivocationKind::ConflictingVote,
            &first.voter_member_id,
            &first.voter_label,
            first.height,
            first.microblock_sequence,
            &first.vote_id,
            &second.vote_id,
            first.vote_root(),
            second.vote_root(),
            first.lock_round,
            detected_by,
            detected_at_height,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_sequencer_equivocation_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "equivocation_kind": self.kind.as_str(),
            "offender_member_id": self.offender_member_id,
            "offender_label": self.offender_label,
            "height": self.height,
            "microblock_sequence": self.microblock_sequence,
            "first_subject_id": self.first_subject_id,
            "second_subject_id": self.second_subject_id,
            "first_root": self.first_root,
            "second_root": self.second_root,
            "shared_lock_round": self.shared_lock_round,
            "detected_by": self.detected_by,
            "detected_at_height": self.detected_at_height,
            "slash_bps": self.slash_bps,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecord {
    pub slash_id: String,
    pub offender_member_id: String,
    pub offender_label: String,
    pub reason: SlashingReason,
    pub evidence_id: String,
    pub stake_before: u64,
    pub slash_bps: u64,
    pub slash_amount: u64,
    pub stake_after: u64,
    pub jail_until_height: u64,
    pub created_at_height: u64,
    pub status: SlashingStatus,
}

impl SlashingRecord {
    pub fn from_evidence(
        evidence: &EquivocationEvidence,
        offender: &CommitteeMember,
        created_at_height: u64,
        config: &DecentralizedSequencerConfig,
    ) -> Self {
        let slash_amount = offender
            .stake_units
            .saturating_mul(evidence.slash_bps)
            .saturating_div(DECENTRALIZED_SEQUENCER_MAX_BPS);
        let stake_after = offender.stake_units.saturating_sub(slash_amount);
        let jail_until_height = created_at_height
            .saturating_add(config.slashing_delay_blocks)
            .saturating_add(
                config
                    .max_jail_blocks
                    .saturating_mul(evidence.slash_bps)
                    .saturating_div(DECENTRALIZED_SEQUENCER_MAX_BPS),
            );
        let slash_id = slashing_record_id(
            &offender.member_id,
            SlashingReason::Equivocation,
            &evidence.evidence_id,
            offender.stake_units,
            evidence.slash_bps,
            slash_amount,
            created_at_height,
        );
        Self {
            slash_id,
            offender_member_id: offender.member_id.clone(),
            offender_label: offender.label.clone(),
            reason: SlashingReason::Equivocation,
            evidence_id: evidence.evidence_id.clone(),
            stake_before: offender.stake_units,
            slash_bps: evidence.slash_bps,
            slash_amount,
            stake_after,
            jail_until_height,
            created_at_height,
            status: SlashingStatus::Applied,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_sequencer_slashing_record",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "slash_id": self.slash_id,
            "offender_member_id": self.offender_member_id,
            "offender_label": self.offender_label,
            "reason": self.reason.as_str(),
            "evidence_id": self.evidence_id,
            "stake_before": self.stake_before,
            "slash_bps": self.slash_bps,
            "slash_amount": self.slash_amount,
            "stake_after": self.stake_after,
            "jail_until_height": self.jail_until_height,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedSequencerPublicRoots {
    pub config_root: String,
    pub committee_root: String,
    pub lane_root: String,
    pub mempool_entry_root: String,
    pub low_fee_policy_root: String,
    pub qos_decision_root: String,
    pub ordering_batch_root: String,
    pub microblock_proposal_root: String,
    pub finality_vote_root: String,
    pub finality_certificate_root: String,
    pub equivocation_evidence_root: String,
    pub slashing_record_root: String,
    pub public_mempool_root: String,
    pub private_mempool_root: String,
    pub finality_root: String,
    pub state_root: String,
}

impl DecentralizedSequencerPublicRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "decentralized_sequencer_public_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "committee_root": self.committee_root,
            "lane_root": self.lane_root,
            "mempool_entry_root": self.mempool_entry_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "qos_decision_root": self.qos_decision_root,
            "ordering_batch_root": self.ordering_batch_root,
            "microblock_proposal_root": self.microblock_proposal_root,
            "finality_vote_root": self.finality_vote_root,
            "finality_certificate_root": self.finality_certificate_root,
            "equivocation_evidence_root": self.equivocation_evidence_root,
            "slashing_record_root": self.slashing_record_root,
            "public_mempool_root": self.public_mempool_root,
            "private_mempool_root": self.private_mempool_root,
            "finality_root": self.finality_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecentralizedSequencerState {
    pub config: DecentralizedSequencerConfig,
    pub height: u64,
    pub epoch: u64,
    pub committee: SequencerCommittee,
    pub lanes: BTreeMap<String, PrivateMempoolLane>,
    pub mempool_entries: BTreeMap<String, PrivateMempoolEntry>,
    pub low_fee_policy: LowFeeQosPolicy,
    pub qos_decisions: Vec<QosDecision>,
    pub ordering_batches: Vec<FairOrderingBatch>,
    pub microblock_proposals: Vec<MicroblockProposal>,
    pub finality_votes: Vec<MicroblockFinalityVote>,
    pub finality_certificates: Vec<FinalityCertificate>,
    pub equivocation_evidence: Vec<EquivocationEvidence>,
    pub slashing_records: Vec<SlashingRecord>,
    pub deterministic_state_tag: String,
    pub monero_anchor_hint: String,
}

impl DecentralizedSequencerState {
    pub fn new(
        config: DecentralizedSequencerConfig,
        height: u64,
        committee: SequencerCommittee,
        lanes: Vec<PrivateMempoolLane>,
    ) -> DecentralizedSequencerResult<Self> {
        config.validate()?;
        committee.validate()?;
        if lanes.is_empty() {
            return Err("decentralized sequencer needs at least one mempool lane".to_string());
        }
        ensure_unique_strings(
            &lanes
                .iter()
                .map(|lane| lane.lane_id.clone())
                .collect::<Vec<_>>(),
            "decentralized sequencer lane ids",
        )?;
        let sponsored_lane_ids = lanes
            .iter()
            .filter(|lane| lane.low_fee_eligible())
            .map(|lane| lane.lane_id.clone())
            .collect::<Vec<_>>();
        let epoch = epoch_for_height(height, config.epoch_length);
        let low_fee_policy = LowFeeQosPolicy::new(
            epoch,
            DECENTRALIZED_SEQUENCER_DEFAULT_LOW_FEE_BUDGET_UNITS,
            config.low_fee_min_share_bps,
            9_500,
            1,
            &sponsored_lane_ids,
        )?;
        let lanes = lanes
            .into_iter()
            .map(|lane| (lane.lane_id.clone(), lane))
            .collect::<BTreeMap<_, _>>();
        let deterministic_state_tag = deterministic_state_tag(
            height,
            epoch,
            &committee.committee_id,
            &private_mempool_lane_set_root_from_map(&lanes),
        );
        Ok(Self {
            config,
            height,
            epoch,
            committee,
            lanes,
            mempool_entries: BTreeMap::new(),
            low_fee_policy,
            qos_decisions: Vec::new(),
            ordering_batches: Vec::new(),
            microblock_proposals: Vec::new(),
            finality_votes: Vec::new(),
            finality_certificates: Vec::new(),
            equivocation_evidence: Vec::new(),
            slashing_records: Vec::new(),
            deterministic_state_tag,
            monero_anchor_hint: DECENTRALIZED_SEQUENCER_MONERO_SETTLEMENT_HINT.to_string(),
        })
    }

    pub fn devnet() -> DecentralizedSequencerResult<Self> {
        let config = DecentralizedSequencerConfig::default();
        let members = vec![
            CommitteeMember::new(
                "devnet-seq-alice",
                vec![
                    CommitteeRole::Proposer,
                    CommitteeRole::Voter,
                    CommitteeRole::Aggregator,
                    CommitteeRole::MempoolKeyholder,
                ],
                4_000,
                4_000,
                25_000,
                0,
            )?,
            CommitteeMember::new(
                "devnet-seq-bob",
                vec![
                    CommitteeRole::Proposer,
                    CommitteeRole::Voter,
                    CommitteeRole::MempoolKeyholder,
                    CommitteeRole::MoneroAnchor,
                ],
                3_000,
                3_000,
                20_000,
                0,
            )?,
            CommitteeMember::new(
                "devnet-seq-carol",
                vec![
                    CommitteeRole::Proposer,
                    CommitteeRole::Voter,
                    CommitteeRole::Aggregator,
                    CommitteeRole::Watchtower,
                ],
                2_000,
                2_000,
                15_000,
                0,
            )?,
            CommitteeMember::new(
                "devnet-seq-dave",
                vec![
                    CommitteeRole::Voter,
                    CommitteeRole::MempoolKeyholder,
                    CommitteeRole::Watchtower,
                ],
                1_500,
                1_500,
                10_000,
                0,
            )?,
            CommitteeMember::new(
                "devnet-seq-erin",
                vec![
                    CommitteeRole::Voter,
                    CommitteeRole::MempoolKeyholder,
                    CommitteeRole::MoneroAnchor,
                ],
                1_000,
                1_000,
                8_000,
                0,
            )?,
        ];
        let committee = SequencerCommittee::new(
            DECENTRALIZED_SEQUENCER_DEVNET_COMMITTEE_LABEL,
            0,
            0,
            members,
            config.final_quorum_bps,
        )?;
        let lanes = vec![
            PrivateMempoolLane::new(
                "devnet-system-lane",
                PrivateMempoolLaneKind::System,
                LanePrivacyMode::PublicCommitmentsOnly,
                LaneAdmissionPolicy::CommitteeOnly,
                500,
                2_000,
                0,
                1,
                0,
                6_667,
            )?,
            PrivateMempoolLane::new(
                "devnet-monero-bridge-lane",
                PrivateMempoolLaneKind::MoneroBridge,
                LanePrivacyMode::ThresholdEncrypted,
                LaneAdmissionPolicy::BridgeGuarded,
                config.monero_bridge_min_share_bps,
                3_500,
                1,
                500,
                10,
                6_667,
            )?,
            PrivateMempoolLane::new(
                "devnet-private-transfer-lane",
                PrivateMempoolLaneKind::PrivateTransfer,
                LanePrivacyMode::ThresholdEncrypted,
                LaneAdmissionPolicy::LowFeeSponsored,
                config.private_min_share_bps,
                5_000,
                1,
                250,
                5,
                6_667,
            )?,
            PrivateMempoolLane::new(
                "devnet-private-defi-lane",
                PrivateMempoolLaneKind::PrivateDefi,
                LanePrivacyMode::DecoyBatch,
                LaneAdmissionPolicy::Bonded,
                1_500,
                4_000,
                2,
                1_000,
                25,
                6_667,
            )?,
            PrivateMempoolLane::new(
                "devnet-contract-low-fee-lane",
                PrivateMempoolLaneKind::LowFee,
                LanePrivacyMode::EncryptedPayload,
                LaneAdmissionPolicy::LowFeeSponsored,
                config.low_fee_min_share_bps,
                4_500,
                1,
                100,
                2,
                6_000,
            )?,
            PrivateMempoolLane::new(
                "devnet-public-defi-lane",
                PrivateMempoolLaneKind::PublicDefi,
                LanePrivacyMode::PublicCommitmentsOnly,
                LaneAdmissionPolicy::Open,
                500,
                3_000,
                2,
                2_000,
                0,
                6_000,
            )?,
        ];
        let mut state = Self::new(config, 1, committee, lanes)?;
        let lane_ids = state.lanes.keys().cloned().collect::<Vec<_>>();
        for (index, lane_id) in lane_ids.iter().enumerate() {
            for offset in 0..3_u64 {
                let seed = index as u64 * 10 + offset;
                let tx_public = json!({
                    "kind": "devnet_tx_public",
                    "seed": seed,
                    "lane_id": lane_id,
                    "recipient_commitment": devnet_commitment("recipient", seed),
                    "amount_bucket": 10_u64.saturating_add(seed).saturating_mul(100),
                });
                let encrypted_payload = json!({
                    "kind": "devnet_encrypted_tx_payload",
                    "seed": seed,
                    "encrypted_note_root": devnet_commitment("encrypted-note", seed),
                    "view_tag_root": devnet_commitment("view-tag", seed),
                    "nullifier_hint_root": devnet_commitment("nullifier-hint", seed),
                });
                let offered_fee = 1 + (seed % 7);
                let max_fee = offered_fee.saturating_add(25 + seed);
                state.admit_private_entry(
                    lane_id,
                    format!("devnet-wallet-{seed}"),
                    &tx_public,
                    &encrypted_payload,
                    "wxmr-devnet",
                    offered_fee,
                    max_fee,
                    1_000 + seed * 10,
                    seed % 4,
                )?;
            }
        }
        let first_lane_id = state
            .lanes
            .values()
            .find(|lane| lane.lane_kind == PrivateMempoolLaneKind::PrivateTransfer)
            .map(|lane| lane.lane_id.clone())
            .ok_or_else(|| "devnet private transfer lane missing".to_string())?;
        let batch = state.build_fair_ordering_batch(&first_lane_id, 0)?;
        let proposal = state.propose_microblock(&batch.batch_id)?;
        let voter_ids = state
            .committee
            .active_members_at(state.height)
            .into_iter()
            .filter(|member| member.has_role(CommitteeRole::Voter))
            .map(|member| member.member_id)
            .collect::<Vec<_>>();
        for voter_id in voter_ids.iter().take(4) {
            state.cast_finality_vote(
                FinalityVoteKind::Prevote,
                &proposal.proposal_id,
                voter_id,
                0,
            )?;
            state.cast_finality_vote(
                FinalityVoteKind::Commit,
                &proposal.proposal_id,
                voter_id,
                1,
            )?;
        }
        state.certify_microblock(
            FinalityCertificateKind::Soft,
            &proposal.proposal_id,
            state.height,
            0,
        )?;
        state.certify_microblock(
            FinalityCertificateKind::Final,
            &proposal.proposal_id,
            state.height,
            0,
        )?;
        let offender_id = voter_ids
            .get(1)
            .cloned()
            .ok_or_else(|| "devnet missing second voter".to_string())?;
        let conflict = state.devnet_conflicting_vote(&proposal.proposal_id, &offender_id)?;
        state.record_equivocation_evidence(conflict)?;
        state.apply_slashing_for_evidence(0)?;
        state.refresh_deterministic_tag();
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.epoch = epoch_for_height(height, self.config.epoch_length);
        for entry in self.mempool_entries.values_mut() {
            if entry.status == MempoolEntryStatus::Pending && entry.is_expired_at(height) {
                entry.status = MempoolEntryStatus::Expired;
            }
        }
        for member in self.committee.members.iter_mut() {
            if member.status == DECENTRALIZED_SEQUENCER_STATUS_JAILED
                && member.jailed_until_height <= height
                && member.voting_power > 0
            {
                member.status = DECENTRALIZED_SEQUENCER_STATUS_ACTIVE.to_string();
            }
        }
        self.refresh_deterministic_tag();
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit_private_entry(
        &mut self,
        lane_id: &str,
        sender_label: impl Into<String>,
        tx_public_record: &Value,
        encrypted_payload_record: &Value,
        fee_asset_id: impl Into<String>,
        offered_fee_units: u64,
        max_fee_units: u64,
        gas_limit_units: u64,
        qos_tier: u64,
    ) -> DecentralizedSequencerResult<PrivateMempoolEntry> {
        if self.mempool_entries.len() as u64 >= self.config.max_mempool_items {
            return Err("decentralized sequencer mempool is full".to_string());
        }
        let lane = self
            .lanes
            .get(lane_id)
            .cloned()
            .ok_or_else(|| format!("unknown private mempool lane: {lane_id}"))?;
        let arrival_slot = self.mempool_entries.len() as u64;
        let local_sequence = arrival_slot.saturating_add(self.height.saturating_mul(1_000));
        let expires_at_height = self
            .height
            .saturating_add(self.config.encrypted_lane_ttl_blocks);
        let entry = PrivateMempoolEntry::new(
            &lane,
            sender_label,
            tx_public_record,
            encrypted_payload_record,
            fee_asset_id,
            offered_fee_units,
            max_fee_units,
            gas_limit_units,
            qos_tier,
            arrival_slot,
            local_sequence,
            self.height,
            expires_at_height,
        )?;
        let mut policy = self.low_fee_policy.clone();
        let decision = QosDecision::assess(&entry, &lane, &mut policy, self.height)?;
        self.low_fee_policy = policy;
        if decision.admits() {
            if let Some(lane_mut) = self.lanes.get_mut(lane_id) {
                lane_mut.register_admission(entry.privacy_budget_units > 0);
            }
            self.qos_decisions.push(decision);
            self.mempool_entries
                .insert(entry.entry_id.clone(), entry.clone());
            self.refresh_deterministic_tag();
            Ok(entry)
        } else {
            self.qos_decisions.push(decision);
            Err("decentralized sequencer QoS rejected mempool entry".to_string())
        }
    }

    pub fn build_fair_ordering_batch(
        &mut self,
        lane_id: &str,
        microblock_sequence: u64,
    ) -> DecentralizedSequencerResult<FairOrderingBatch> {
        let lane = self
            .lanes
            .get(lane_id)
            .cloned()
            .ok_or_else(|| format!("unknown private mempool lane: {lane_id}"))?;
        let entries = self.mempool_entries.values().cloned().collect::<Vec<_>>();
        let batch = FairOrderingBatch::build(
            self.height,
            microblock_sequence,
            &lane,
            &entries,
            &self.qos_decisions,
            self.config.max_microblock_items,
        );
        for entry_id in batch.ordered_entry_ids.iter() {
            if let Some(entry) = self.mempool_entries.get_mut(entry_id) {
                entry.mark_ordered();
            }
            if let Some(lane_mut) = self.lanes.get_mut(lane_id) {
                lane_mut.register_inclusion();
            }
        }
        self.ordering_batches.push(batch.clone());
        self.refresh_deterministic_tag();
        Ok(batch)
    }

    pub fn propose_microblock(
        &mut self,
        batch_id: &str,
    ) -> DecentralizedSequencerResult<MicroblockProposal> {
        let batch = self
            .ordering_batches
            .iter()
            .find(|batch| batch.batch_id == batch_id)
            .cloned()
            .ok_or_else(|| format!("unknown ordering batch: {batch_id}"))?;
        let leader = self.committee.leader_for_slot(
            self.height,
            batch.microblock_sequence,
            self.config.leader_schedule_mode,
        )?;
        let parent_id = self
            .microblock_proposals
            .last()
            .map(|proposal| proposal.proposal_id.clone())
            .unwrap_or_else(|| DECENTRALIZED_SEQUENCER_DEVNET_PARENT_ID.to_string());
        let parent_state_root = self
            .microblock_proposals
            .last()
            .map(|proposal| proposal.state_root_after.clone())
            .unwrap_or_else(|| decentralized_sequencer_genesis_root(&self.committee.committee_id));
        let state_root_before = self.state_root();
        let proposal = MicroblockProposal::new(
            self.height,
            batch.microblock_sequence,
            self.epoch,
            &leader,
            parent_id,
            parent_state_root,
            &batch,
            &self.qos_decisions,
            state_root_before,
            self.height.saturating_mul(TARGET_BLOCK_MS).saturating_add(
                batch
                    .microblock_sequence
                    .saturating_mul(self.config.microblock_target_ms),
            ),
        )?;
        for entry_id in proposal.included_entry_ids.iter() {
            if let Some(entry) = self.mempool_entries.get_mut(entry_id) {
                entry.mark_included();
            }
        }
        self.microblock_proposals.push(proposal.clone());
        self.refresh_deterministic_tag();
        Ok(proposal)
    }

    pub fn cast_finality_vote(
        &mut self,
        vote_kind: FinalityVoteKind,
        proposal_id: &str,
        voter_member_id: &str,
        lock_round: u64,
    ) -> DecentralizedSequencerResult<MicroblockFinalityVote> {
        let proposal = self
            .microblock_proposals
            .iter()
            .find(|proposal| proposal.proposal_id == proposal_id)
            .cloned()
            .ok_or_else(|| format!("unknown microblock proposal: {proposal_id}"))?;
        let voter = self
            .committee
            .member_by_id(voter_member_id)
            .cloned()
            .ok_or_else(|| format!("unknown voter member id: {voter_member_id}"))?;
        if !voter.is_active_at(self.height) {
            return Err("voter is not active at current height".to_string());
        }
        let vote = MicroblockFinalityVote::new(vote_kind, &proposal, &voter, lock_round)?;
        for existing in self.finality_votes.iter() {
            if vote.conflicts_with(existing) {
                return Err("conflicting finality vote detected before insertion".to_string());
            }
        }
        self.finality_votes.push(vote.clone());
        self.refresh_deterministic_tag();
        Ok(vote)
    }

    pub fn certify_microblock(
        &mut self,
        certificate_kind: FinalityCertificateKind,
        proposal_id: &str,
        finalized_at_height: u64,
        finalized_at_microblock: u64,
    ) -> DecentralizedSequencerResult<FinalityCertificate> {
        let proposal = self
            .microblock_proposals
            .iter()
            .find(|proposal| proposal.proposal_id == proposal_id)
            .cloned()
            .ok_or_else(|| format!("unknown microblock proposal: {proposal_id}"))?;
        let certificate = FinalityCertificate::build(
            certificate_kind,
            &proposal,
            &self.finality_votes,
            &self.committee,
            &self.config,
            finalized_at_height,
            finalized_at_microblock,
        )?;
        if !certificate.quorum_reached {
            return Err("finality certificate quorum was not reached".to_string());
        }
        if let Some(proposal_mut) = self
            .microblock_proposals
            .iter_mut()
            .find(|proposal_mut| proposal_mut.proposal_id == proposal_id)
        {
            match certificate_kind {
                FinalityCertificateKind::Soft => proposal_mut.mark_soft_finalized(),
                FinalityCertificateKind::Final => proposal_mut.mark_finalized(),
                FinalityCertificateKind::ViewChange => {
                    proposal_mut.status = MicroblockStatus::RolledBack;
                }
            }
        }
        self.finality_certificates.push(certificate.clone());
        self.refresh_deterministic_tag();
        Ok(certificate)
    }

    pub fn record_equivocation_evidence(
        &mut self,
        mut evidence: EquivocationEvidence,
    ) -> DecentralizedSequencerResult<EquivocationEvidence> {
        if self
            .equivocation_evidence
            .iter()
            .any(|existing| existing.evidence_id == evidence.evidence_id)
        {
            return Err("duplicate equivocation evidence".to_string());
        }
        evidence.status = EvidenceStatus::Accepted;
        self.equivocation_evidence.push(evidence.clone());
        self.refresh_deterministic_tag();
        Ok(evidence)
    }

    pub fn apply_slashing_for_evidence(
        &mut self,
        evidence_index: usize,
    ) -> DecentralizedSequencerResult<SlashingRecord> {
        let evidence = self
            .equivocation_evidence
            .get(evidence_index)
            .cloned()
            .ok_or_else(|| format!("unknown evidence index: {evidence_index}"))?;
        let offender = self
            .committee
            .member_by_id(&evidence.offender_member_id)
            .cloned()
            .ok_or_else(|| "slashing offender not found in committee".to_string())?;
        let record = SlashingRecord::from_evidence(&evidence, &offender, self.height, &self.config);
        if let Some(member) = self.committee.member_by_id_mut(&record.offender_member_id) {
            member.apply_slash(record.slash_amount, record.jail_until_height);
        }
        self.slashing_records.push(record.clone());
        self.refresh_deterministic_tag();
        Ok(record)
    }

    pub fn public_roots(&self) -> DecentralizedSequencerPublicRoots {
        let mut roots = self.public_roots_with_state_root(String::new());
        roots.state_root = decentralized_sequencer_state_root_from_record(
            &self.public_record_without_root_from_roots(&roots),
        );
        roots
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.public_roots_with_state_root(String::new());
        self.public_record_without_root_from_roots(&roots)
    }

    pub fn public_record_without_root_from_roots(
        &self,
        roots: &DecentralizedSequencerPublicRoots,
    ) -> Value {
        json!({
            "kind": "decentralized_sequencer_state",
            "chain_id": CHAIN_ID,
            "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
            "schema_version": DECENTRALIZED_SEQUENCER_SCHEMA_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "committee": self.committee.public_record(),
            "lanes": self.lanes.values().map(PrivateMempoolLane::public_record).collect::<Vec<_>>(),
            "mempool_entries": self.mempool_entries.values().map(PrivateMempoolEntry::public_record).collect::<Vec<_>>(),
            "low_fee_policy": self.low_fee_policy.public_record(),
            "qos_decisions": self.qos_decisions.iter().map(QosDecision::public_record).collect::<Vec<_>>(),
            "ordering_batches": self.ordering_batches.iter().map(FairOrderingBatch::public_record).collect::<Vec<_>>(),
            "microblock_proposals": self.microblock_proposals.iter().map(MicroblockProposal::public_record).collect::<Vec<_>>(),
            "finality_votes": self.finality_votes.iter().map(MicroblockFinalityVote::public_record).collect::<Vec<_>>(),
            "finality_certificates": self.finality_certificates.iter().map(FinalityCertificate::public_record).collect::<Vec<_>>(),
            "equivocation_evidence": self.equivocation_evidence.iter().map(EquivocationEvidence::public_record).collect::<Vec<_>>(),
            "slashing_records": self.slashing_records.iter().map(SlashingRecord::public_record).collect::<Vec<_>>(),
            "public_roots": roots.public_record(),
            "deterministic_state_tag": self.deterministic_state_tag,
            "monero_anchor_hint": self.monero_anchor_hint,
        })
    }

    pub fn public_record(&self) -> Value {
        let roots = self.public_roots();
        let mut record = self.public_record_without_root_from_roots(&roots);
        record
            .as_object_mut()
            .expect("decentralized sequencer state object")
            .insert("state_root".to_string(), json!(roots.state_root));
        record
    }

    pub fn state_root(&self) -> String {
        decentralized_sequencer_state_root_from_record(&self.public_record_without_root())
    }

    pub fn finality_head(&self) -> Option<&FinalityCertificate> {
        self.finality_certificates.iter().rev().find(|certificate| {
            certificate.certificate_kind == FinalityCertificateKind::Final
                && certificate.quorum_reached
        })
    }

    pub fn pending_private_count(&self) -> u64 {
        self.mempool_entries
            .values()
            .filter(|entry| {
                entry.status == MempoolEntryStatus::Pending && entry.privacy_budget_units > 0
            })
            .count() as u64
    }

    pub fn low_fee_pressure_bps(&self) -> u64 {
        ratio_bps(
            self.low_fee_policy
                .budget_units
                .saturating_sub(self.low_fee_policy.remaining_budget_units),
            self.low_fee_policy.budget_units,
        )
    }

    pub fn refresh_deterministic_tag(&mut self) {
        self.deterministic_state_tag = deterministic_state_tag(
            self.height,
            self.epoch,
            &self.committee.committee_id,
            &self
                .public_roots_with_state_root(String::new())
                .public_mempool_root,
        );
    }

    fn public_roots_with_state_root(
        &self,
        state_root: String,
    ) -> DecentralizedSequencerPublicRoots {
        let config_root = self.config.config_root();
        let committee_root = self.committee.committee_root();
        let lane_root = private_mempool_lane_set_root_from_map(&self.lanes);
        let mempool_entry_root = private_mempool_entry_set_root_from_map(&self.mempool_entries);
        let low_fee_policy_root = self.low_fee_policy.policy_root();
        let qos_decision_root = qos_decision_set_root(&self.qos_decisions);
        let ordering_batch_root = fair_ordering_batch_set_root(&self.ordering_batches);
        let microblock_proposal_root = microblock_proposal_set_root(&self.microblock_proposals);
        let finality_vote_root = microblock_finality_vote_set_root(&self.finality_votes);
        let finality_certificate_root = finality_certificate_set_root(&self.finality_certificates);
        let equivocation_evidence_root =
            equivocation_evidence_set_root(&self.equivocation_evidence);
        let slashing_record_root = slashing_record_set_root(&self.slashing_records);
        let public_mempool_root = public_mempool_root_from_parts(
            &lane_root,
            &mempool_entry_root,
            &qos_decision_root,
            &ordering_batch_root,
        );
        let private_mempool_root = private_mempool_root_from_parts(
            &mempool_entry_root,
            &ordering_batch_root,
            &low_fee_policy_root,
            self.pending_private_count(),
        );
        let finality_root = finality_root_from_parts(
            &microblock_proposal_root,
            &finality_vote_root,
            &finality_certificate_root,
            &equivocation_evidence_root,
            &slashing_record_root,
        );
        DecentralizedSequencerPublicRoots {
            config_root,
            committee_root,
            lane_root,
            mempool_entry_root,
            low_fee_policy_root,
            qos_decision_root,
            ordering_batch_root,
            microblock_proposal_root,
            finality_vote_root,
            finality_certificate_root,
            equivocation_evidence_root,
            slashing_record_root,
            public_mempool_root,
            private_mempool_root,
            finality_root,
            state_root,
        }
    }

    fn devnet_conflicting_vote(
        &self,
        proposal_id: &str,
        offender_member_id: &str,
    ) -> DecentralizedSequencerResult<EquivocationEvidence> {
        let first = self
            .finality_votes
            .iter()
            .find(|vote| {
                vote.proposal_id == proposal_id && vote.voter_member_id == offender_member_id
            })
            .cloned()
            .ok_or_else(|| "devnet conflicting vote base vote missing".to_string())?;
        let proposal = self
            .microblock_proposals
            .iter()
            .find(|proposal| proposal.proposal_id == proposal_id)
            .cloned()
            .ok_or_else(|| "devnet conflicting vote proposal missing".to_string())?;
        let offender = self
            .committee
            .member_by_id(offender_member_id)
            .cloned()
            .ok_or_else(|| "devnet conflicting vote offender missing".to_string())?;
        let mut conflicting_proposal = proposal.clone();
        conflicting_proposal.state_root_after = decentralized_sequencer_string_root(
            "DECENTRALIZED-SEQUENCER-DEVNET-CONFLICTING-STATE",
            &proposal.state_root_after,
        );
        conflicting_proposal.proposal_id = microblock_proposal_id(
            proposal.height,
            proposal.microblock_sequence,
            proposal.epoch,
            &proposal.leader_member_id,
            &proposal.parent_microblock_id,
            &proposal.parent_state_root,
            &proposal.ordering_batch_root,
            &conflicting_proposal.state_root_after,
        );
        let second = MicroblockFinalityVote::new(
            first.vote_kind,
            &conflicting_proposal,
            &offender,
            first.lock_round,
        )?;
        EquivocationEvidence::from_conflicting_votes(
            &first,
            &second,
            DECENTRALIZED_SEQUENCER_DEVNET_OPERATOR_LABEL,
            self.height,
        )
    }
}

pub fn decentralized_sequencer_state_root_from_record(record: &Value) -> String {
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-STATE-ROOT", record)
}

pub fn decentralized_sequencer_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn decentralized_sequencer_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn decentralized_sequencer_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn committee_member_id(
    label: &str,
    role_root: &str,
    stake_units: u64,
    voting_power: u64,
    consensus_public_key: &str,
    activated_at_height: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-COMMITTEE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(role_root),
            HashPart::Int(stake_units as i128),
            HashPart::Int(voting_power as i128),
            HashPart::Str(consensus_public_key),
            HashPart::Int(activated_at_height as i128),
        ],
        32,
    )
}

pub fn committee_member_root(record: &Value) -> String {
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-COMMITTEE-MEMBER-ROOT", record)
}

pub fn committee_member_set_root(members: &[CommitteeMember]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-COMMITTEE-MEMBER-SET",
        &members
            .iter()
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn committee_role_root(roles: &[CommitteeRole]) -> String {
    let mut roles = roles.iter().map(|role| role.as_str()).collect::<Vec<_>>();
    roles.sort();
    let leaves = roles
        .iter()
        .map(|role| json!({ "role": role }))
        .collect::<Vec<_>>();
    merkle_root("DECENTRALIZED-SEQUENCER-COMMITTEE-ROLE-ROOT", &leaves)
}

pub fn sequencer_committee_id(
    label: &str,
    epoch: u64,
    activation_height: u64,
    member_root: &str,
    total_voting_power: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(epoch as i128),
            HashPart::Int(activation_height as i128),
            HashPart::Str(member_root),
            HashPart::Int(total_voting_power as i128),
        ],
        32,
    )
}

pub fn sequencer_committee_root(record: &Value) -> String {
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-COMMITTEE-ROOT", record)
}

pub fn leader_schedule_root_for_members(
    epoch: u64,
    activation_height: u64,
    members: &[CommitteeMember],
    mode: LeaderScheduleMode,
) -> String {
    let leaves = members
        .iter()
        .filter(|member| member.has_role(CommitteeRole::Proposer))
        .map(|member| {
            json!({
                "epoch": epoch,
                "activation_height": activation_height,
                "member_id": member.member_id,
                "label": member.label,
                "voting_power": member.voting_power,
                "mode": mode.as_str(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("DECENTRALIZED-SEQUENCER-LEADER-SCHEDULE", &leaves)
}

pub fn leader_schedule_slot_commitment(
    epoch: u64,
    height: u64,
    microblock_sequence: u64,
    leader_member_id: &str,
    leader_label: &str,
    fallback_rank: u64,
    mode: LeaderScheduleMode,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-LEADER-SLOT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(leader_member_id),
            HashPart::Str(leader_label),
            HashPart::Int(fallback_rank as i128),
            HashPart::Str(mode.as_str()),
        ],
        32,
    )
}

pub fn leader_schedule_slot_id(
    epoch: u64,
    height: u64,
    microblock_sequence: u64,
    leader_member_id: &str,
    schedule_commitment: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-LEADER-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(leader_member_id),
            HashPart::Str(schedule_commitment),
        ],
        32,
    )
}

pub fn lane_public_key_root(
    label: &str,
    lane_kind: PrivateMempoolLaneKind,
    privacy_mode: LanePrivacyMode,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-LANE-PUBLIC-KEY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(privacy_mode.as_str()),
            HashPart::Str(DECENTRALIZED_SEQUENCER_PQ_KEM_SCHEME),
        ],
        32,
    )
}

pub fn lane_kem_committee_key_id(
    label: &str,
    lane_kind: PrivateMempoolLaneKind,
    privacy_mode: LanePrivacyMode,
    lane_public_key_root: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-LANE-KEM-COMMITTEE-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(privacy_mode.as_str()),
            HashPart::Str(lane_public_key_root),
        ],
        32,
    )
}

pub fn lane_replay_protection_root(
    label: &str,
    lane_kind: PrivateMempoolLaneKind,
    privacy_mode: LanePrivacyMode,
    admission_policy: LaneAdmissionPolicy,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-LANE-REPLAY-PROTECTION-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(privacy_mode.as_str()),
            HashPart::Str(admission_policy.as_str()),
        ],
        32,
    )
}

pub fn private_mempool_lane_id(
    label: &str,
    lane_kind: PrivateMempoolLaneKind,
    privacy_mode: LanePrivacyMode,
    admission_policy: LaneAdmissionPolicy,
    min_share_bps: u64,
    max_share_bps: u64,
    kem_committee_key_id: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-PRIVATE-MEMPOOL-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(privacy_mode.as_str()),
            HashPart::Str(admission_policy.as_str()),
            HashPart::Int(min_share_bps as i128),
            HashPart::Int(max_share_bps as i128),
            HashPart::Str(kem_committee_key_id),
        ],
        32,
    )
}

pub fn private_mempool_lane_root(record: &Value) -> String {
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-MEMPOOL-LANE-ROOT", record)
}

pub fn private_mempool_lane_set_root_from_map(
    lanes: &BTreeMap<String, PrivateMempoolLane>,
) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-MEMPOOL-LANE-SET",
        &lanes
            .values()
            .map(PrivateMempoolLane::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn sender_commitment(label: &str) -> String {
    decentralized_sequencer_string_root("DECENTRALIZED-SEQUENCER-SENDER-COMMITMENT", label)
}

pub fn mempool_entry_nullifier_root(
    sender_commitment: &str,
    tx_public_hash: &str,
    encrypted_payload_hash: &str,
    local_sequence: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-MEMPOOL-ENTRY-NULLIFIER-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sender_commitment),
            HashPart::Str(tx_public_hash),
            HashPart::Str(encrypted_payload_hash),
            HashPart::Int(local_sequence as i128),
        ],
        32,
    )
}

pub fn mempool_entry_public_metadata_root(
    fee_asset_id: &str,
    offered_fee_units: u64,
    max_fee_units: u64,
    gas_limit_units: u64,
    qos_tier: u64,
    privacy_mode: LanePrivacyMode,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-MEMPOOL-ENTRY-PUBLIC-METADATA-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(fee_asset_id),
            HashPart::Int(offered_fee_units as i128),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(gas_limit_units as i128),
            HashPart::Int(qos_tier as i128),
            HashPart::Str(privacy_mode.as_str()),
        ],
        32,
    )
}

pub fn mempool_entry_ordering_commitment(
    lane_id: &str,
    tx_public_hash: &str,
    encrypted_payload_hash: &str,
    nullifier_root: &str,
    monotonic_fee_score: u64,
    arrival_slot: u64,
    local_sequence: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-MEMPOOL-ENTRY-ORDERING-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(tx_public_hash),
            HashPart::Str(encrypted_payload_hash),
            HashPart::Str(nullifier_root),
            HashPart::Int(monotonic_fee_score as i128),
            HashPart::Int(arrival_slot as i128),
            HashPart::Int(local_sequence as i128),
        ],
        32,
    )
}

pub fn private_mempool_entry_id(
    lane_id: &str,
    sender_commitment: &str,
    tx_public_hash: &str,
    encrypted_payload_hash: &str,
    ordering_commitment: &str,
    arrival_slot: u64,
    local_sequence: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-PRIVATE-MEMPOOL-ENTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(sender_commitment),
            HashPart::Str(tx_public_hash),
            HashPart::Str(encrypted_payload_hash),
            HashPart::Str(ordering_commitment),
            HashPart::Int(arrival_slot as i128),
            HashPart::Int(local_sequence as i128),
        ],
        32,
    )
}

pub fn private_mempool_entry_root(record: &Value) -> String {
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-MEMPOOL-ENTRY-ROOT", record)
}

pub fn private_mempool_entry_set_root_from_map(
    entries: &BTreeMap<String, PrivateMempoolEntry>,
) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-MEMPOOL-ENTRY-SET",
        &entries
            .values()
            .map(PrivateMempoolEntry::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn monotonic_fee_score(
    lane: &PrivateMempoolLane,
    offered_fee_units: u64,
    max_fee_units: u64,
    gas_limit_units: u64,
    qos_tier: u64,
    arrival_slot: u64,
) -> u64 {
    let fee_density = offered_fee_units
        .saturating_mul(1_000_000)
        .saturating_div(gas_limit_units.max(1));
    let fee_headroom = max_fee_units.saturating_sub(offered_fee_units);
    lane.base_priority()
        .saturating_add(fee_density)
        .saturating_add(fee_headroom.saturating_mul(100))
        .saturating_add(qos_tier.saturating_mul(10_000))
        .saturating_sub(arrival_slot)
}

pub fn low_fee_qos_policy_id(
    epoch: u64,
    budget_units: u64,
    min_low_fee_share_bps: u64,
    max_rebate_bps: u64,
    min_settled_fee_units: u64,
    sponsored_lane_root: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-LOW-FEE-QOS-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Int(budget_units as i128),
            HashPart::Int(min_low_fee_share_bps as i128),
            HashPart::Int(max_rebate_bps as i128),
            HashPart::Int(min_settled_fee_units as i128),
            HashPart::Str(sponsored_lane_root),
        ],
        32,
    )
}

pub fn low_fee_qos_policy_root(record: &Value) -> String {
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-LOW-FEE-QOS-POLICY-ROOT", record)
}

pub fn low_fee_fairness_salt_root(epoch: u64, sponsored_lane_root: &str) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-LOW-FEE-FAIRNESS-SALT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(sponsored_lane_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn qos_decision_transcript_root(
    entry_id: &str,
    lane_id: &str,
    decision_kind: QosDecisionKind,
    reason: &str,
    priority_score: u64,
    reserved_budget_units: u64,
    charged_fee_units: u64,
    rebate_units: u64,
    promised_inclusion_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-QOS-DECISION-TRANSCRIPT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(entry_id),
            HashPart::Str(lane_id),
            HashPart::Str(decision_kind.as_str()),
            HashPart::Str(reason),
            HashPart::Int(priority_score as i128),
            HashPart::Int(reserved_budget_units as i128),
            HashPart::Int(charged_fee_units as i128),
            HashPart::Int(rebate_units as i128),
            HashPart::Int(promised_inclusion_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn qos_decision_id(
    entry_id: &str,
    lane_id: &str,
    decision_kind: QosDecisionKind,
    priority_score: u64,
    decision_root: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-QOS-DECISION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(entry_id),
            HashPart::Str(lane_id),
            HashPart::Str(decision_kind.as_str()),
            HashPart::Int(priority_score as i128),
            HashPart::Str(decision_root),
        ],
        32,
    )
}

pub fn qos_decision_set_root(decisions: &[QosDecision]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-QOS-DECISION-SET",
        &decisions
            .iter()
            .map(QosDecision::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fair_ordering_seed(
    height: u64,
    microblock_sequence: u64,
    lane_id: &str,
    ordered_entry_ids: &[String],
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-FAIR-ORDERING-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(lane_id),
            HashPart::Str(&decentralized_sequencer_string_set_root(
                "DECENTRALIZED-SEQUENCER-FAIR-ORDERING-SEED-ENTRIES",
                ordered_entry_ids,
            )),
        ],
        32,
    )
}

pub fn fair_ordering_fairness_root(
    height: u64,
    microblock_sequence: u64,
    lane: &PrivateMempoolLane,
    ordered_entry_ids: &[String],
    omitted_entry_ids: &[String],
) -> String {
    let record = json!({
        "height": height,
        "microblock_sequence": microblock_sequence,
        "lane": lane.public_record(),
        "ordered_root": decentralized_sequencer_string_set_root("DECENTRALIZED-SEQUENCER-FAIR-ORDERED-IDS", ordered_entry_ids),
        "omitted_root": decentralized_sequencer_string_set_root("DECENTRALIZED-SEQUENCER-FAIR-OMITTED-IDS", omitted_entry_ids),
    });
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-FAIRNESS-ROOT", &record)
}

pub fn private_order_root(entries: &[PrivateMempoolEntry]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-PRIVATE-ORDER-ROOT",
        &entries
            .iter()
            .map(|entry| {
                json!({
                    "entry_id": entry.entry_id,
                    "encrypted_payload_hash": entry.encrypted_payload_hash,
                    "nullifier_root": entry.nullifier_root,
                    "privacy_budget_units": entry.privacy_budget_units,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_order_root(entries: &[PrivateMempoolEntry]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-LOW-FEE-ORDER-ROOT",
        &entries
            .iter()
            .filter(|entry| entry.low_fee_eligible)
            .map(|entry| {
                json!({
                    "entry_id": entry.entry_id,
                    "offered_fee_units": entry.offered_fee_units,
                    "max_fee_units": entry.max_fee_units,
                    "fee_asset_id": entry.fee_asset_id,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn fee_bucket_order_root(entries: &[PrivateMempoolEntry]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-FEE-BUCKET-ORDER-ROOT",
        &entries
            .iter()
            .map(|entry| {
                json!({
                    "entry_id": entry.entry_id,
                    "fee_bucket": amount_bucket(entry.offered_fee_units, 10),
                    "gas_bucket": amount_bucket(entry.gas_limit_units, 1_000),
                    "score": entry.monotonic_fee_score,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn fair_ordering_batch_id(
    height: u64,
    microblock_sequence: u64,
    lane_id: &str,
    ordering_seed: &str,
    fairness_root: &str,
    qos_decision_root: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-FAIR-ORDERING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(lane_id),
            HashPart::Str(ordering_seed),
            HashPart::Str(fairness_root),
            HashPart::Str(qos_decision_root),
        ],
        32,
    )
}

pub fn fair_ordering_batch_root(record: &Value) -> String {
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-FAIR-ORDERING-BATCH-ROOT", record)
}

pub fn fair_ordering_batch_set_root(batches: &[FairOrderingBatch]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-FAIR-ORDERING-BATCH-SET",
        &batches
            .iter()
            .map(FairOrderingBatch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_attestation_signature_root(
    member_id: &str,
    public_key_root: &str,
    signature_scheme: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-PQ-ATTESTATION-SIGNATURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(member_id),
            HashPart::Str(public_key_root),
            HashPart::Str(signature_scheme),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_attestation_id(
    subject_kind: &str,
    subject_id: &str,
    member_id: &str,
    committee_role: CommitteeRole,
    public_key_root: &str,
    transcript_root: &str,
    voting_power: u64,
    attested_at_height: u64,
    attested_at_microblock: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(member_id),
            HashPart::Str(committee_role.as_str()),
            HashPart::Str(public_key_root),
            HashPart::Str(transcript_root),
            HashPart::Int(voting_power as i128),
            HashPart::Int(attested_at_height as i128),
            HashPart::Int(attested_at_microblock as i128),
        ],
        32,
    )
}

pub fn pq_attestation_root(record: &Value) -> String {
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-PQ-ATTESTATION-ROOT", record)
}

#[allow(clippy::too_many_arguments)]
pub fn microblock_proposal_unsigned_record(
    proposal_id: &str,
    height: u64,
    microblock_sequence: u64,
    epoch: u64,
    leader_member_id: &str,
    leader_label: &str,
    parent_microblock_id: &str,
    parent_state_root: &str,
    ordering_batch_root: &str,
    included_entry_ids: &[String],
    private_payload_root: &str,
    public_tx_root: &str,
    qos_decision_root: &str,
    fee_summary_root: &str,
    state_root_before: &str,
    state_root_after: &str,
    created_at_ms: u64,
    status: MicroblockStatus,
) -> Value {
    json!({
        "kind": "decentralized_sequencer_microblock_proposal",
        "chain_id": CHAIN_ID,
        "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
        "proposal_id": proposal_id,
        "height": height,
        "microblock_sequence": microblock_sequence,
        "epoch": epoch,
        "leader_member_id": leader_member_id,
        "leader_label": leader_label,
        "parent_microblock_id": parent_microblock_id,
        "parent_state_root": parent_state_root,
        "ordering_batch_root": ordering_batch_root,
        "included_entry_ids": included_entry_ids,
        "included_entry_root": decentralized_sequencer_string_set_root("DECENTRALIZED-SEQUENCER-MICROBLOCK-INCLUDED-ENTRY-ROOT", included_entry_ids),
        "private_payload_root": private_payload_root,
        "public_tx_root": public_tx_root,
        "qos_decision_root": qos_decision_root,
        "fee_summary_root": fee_summary_root,
        "state_root_before": state_root_before,
        "state_root_after": state_root_after,
        "created_at_ms": created_at_ms,
        "status": status.as_str(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn microblock_proposal_id(
    height: u64,
    microblock_sequence: u64,
    epoch: u64,
    leader_member_id: &str,
    parent_microblock_id: &str,
    parent_state_root: &str,
    ordering_batch_root: &str,
    state_root_after: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-MICROBLOCK-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Int(epoch as i128),
            HashPart::Str(leader_member_id),
            HashPart::Str(parent_microblock_id),
            HashPart::Str(parent_state_root),
            HashPart::Str(ordering_batch_root),
            HashPart::Str(state_root_after),
        ],
        32,
    )
}

pub fn microblock_proposal_root(record: &Value) -> String {
    decentralized_sequencer_payload_root("DECENTRALIZED-SEQUENCER-MICROBLOCK-PROPOSAL-ROOT", record)
}

pub fn microblock_proposal_set_root(proposals: &[MicroblockProposal]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-MICROBLOCK-PROPOSAL-SET",
        &proposals
            .iter()
            .map(MicroblockProposal::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn microblock_fee_summary_root(batch: &FairOrderingBatch, decisions: &[QosDecision]) -> String {
    let record = json!({
        "batch_id": batch.batch_id,
        "total_fee_units": batch.total_fee_units,
        "low_fee_count": batch.low_fee_count,
        "private_count": batch.private_count,
        "monero_bridge_count": batch.monero_bridge_count,
        "charged_fee_units": decisions.iter().map(|decision| decision.charged_fee_units).sum::<u64>(),
        "rebate_units": decisions.iter().map(|decision| decision.rebate_units).sum::<u64>(),
    });
    decentralized_sequencer_payload_root(
        "DECENTRALIZED-SEQUENCER-MICROBLOCK-FEE-SUMMARY-ROOT",
        &record,
    )
}

pub fn microblock_state_transition_root(
    parent_state_root: &str,
    state_root_before: &str,
    batch_id: &str,
    public_tx_root: &str,
    private_payload_root: &str,
    qos_decision_root: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-MICROBLOCK-STATE-TRANSITION-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(parent_state_root),
            HashPart::Str(state_root_before),
            HashPart::Str(batch_id),
            HashPart::Str(public_tx_root),
            HashPart::Str(private_payload_root),
            HashPart::Str(qos_decision_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn microblock_finality_vote_unsigned_record(
    vote_id: &str,
    vote_kind: FinalityVoteKind,
    proposal_id: &str,
    height: u64,
    microblock_sequence: u64,
    state_root: &str,
    block_root: &str,
    voter_member_id: &str,
    voter_label: &str,
    voting_power: u64,
    lock_round: u64,
    status: &str,
) -> Value {
    json!({
        "kind": "decentralized_sequencer_microblock_finality_vote",
        "chain_id": CHAIN_ID,
        "protocol_version": DECENTRALIZED_SEQUENCER_PROTOCOL_VERSION,
        "vote_id": vote_id,
        "vote_kind": vote_kind.as_str(),
        "proposal_id": proposal_id,
        "height": height,
        "microblock_sequence": microblock_sequence,
        "state_root": state_root,
        "block_root": block_root,
        "voter_member_id": voter_member_id,
        "voter_label": voter_label,
        "voting_power": voting_power,
        "lock_round": lock_round,
        "status": status,
    })
}

pub fn microblock_finality_vote_id(
    vote_kind: FinalityVoteKind,
    proposal_id: &str,
    height: u64,
    microblock_sequence: u64,
    state_root: &str,
    voter_member_id: &str,
    lock_round: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-MICROBLOCK-FINALITY-VOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(vote_kind.as_str()),
            HashPart::Str(proposal_id),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(state_root),
            HashPart::Str(voter_member_id),
            HashPart::Int(lock_round as i128),
        ],
        32,
    )
}

pub fn microblock_finality_vote_root(record: &Value) -> String {
    decentralized_sequencer_payload_root(
        "DECENTRALIZED-SEQUENCER-MICROBLOCK-FINALITY-VOTE-ROOT",
        record,
    )
}

pub fn microblock_finality_vote_set_root(votes: &[MicroblockFinalityVote]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-MICROBLOCK-FINALITY-VOTE-SET",
        &votes
            .iter()
            .map(MicroblockFinalityVote::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn finality_certificate_id(
    certificate_kind: FinalityCertificateKind,
    proposal_id: &str,
    height: u64,
    microblock_sequence: u64,
    state_root: &str,
    vote_root: &str,
    signed_voting_power: u64,
    quorum_bps: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-FINALITY-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(certificate_kind.as_str()),
            HashPart::Str(proposal_id),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(state_root),
            HashPart::Str(vote_root),
            HashPart::Int(signed_voting_power as i128),
            HashPart::Int(quorum_bps as i128),
        ],
        32,
    )
}

pub fn finality_certificate_root(record: &Value) -> String {
    decentralized_sequencer_payload_root(
        "DECENTRALIZED-SEQUENCER-FINALITY-CERTIFICATE-ROOT",
        record,
    )
}

pub fn finality_certificate_set_root(certificates: &[FinalityCertificate]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-FINALITY-CERTIFICATE-SET",
        &certificates
            .iter()
            .map(FinalityCertificate::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn equivocation_evidence_payload_root(
    kind: EquivocationKind,
    offender_member_id: &str,
    height: u64,
    microblock_sequence: u64,
    first_subject_id: &str,
    second_subject_id: &str,
    first_root: &str,
    second_root: &str,
    shared_lock_round: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-EQUIVOCATION-EVIDENCE-PAYLOAD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(offender_member_id),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(first_subject_id),
            HashPart::Str(second_subject_id),
            HashPart::Str(first_root),
            HashPart::Str(second_root),
            HashPart::Int(shared_lock_round as i128),
        ],
        32,
    )
}

pub fn equivocation_evidence_id(
    kind: EquivocationKind,
    offender_member_id: &str,
    height: u64,
    microblock_sequence: u64,
    first_subject_id: &str,
    second_subject_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-EQUIVOCATION-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(offender_member_id),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(first_subject_id),
            HashPart::Str(second_subject_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn equivocation_evidence_set_root(evidence: &[EquivocationEvidence]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-EQUIVOCATION-EVIDENCE-SET",
        &evidence
            .iter()
            .map(EquivocationEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn slashing_record_id(
    offender_member_id: &str,
    reason: SlashingReason,
    evidence_id: &str,
    stake_before: u64,
    slash_bps: u64,
    slash_amount: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-SLASHING-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(offender_member_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_id),
            HashPart::Int(stake_before as i128),
            HashPart::Int(slash_bps as i128),
            HashPart::Int(slash_amount as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn slashing_record_set_root(records: &[SlashingRecord]) -> String {
    merkle_root(
        "DECENTRALIZED-SEQUENCER-SLASHING-RECORD-SET",
        &records
            .iter()
            .map(SlashingRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn public_mempool_root_from_parts(
    lane_root: &str,
    mempool_entry_root: &str,
    qos_decision_root: &str,
    ordering_batch_root: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-PUBLIC-MEMPOOL-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_root),
            HashPart::Str(mempool_entry_root),
            HashPart::Str(qos_decision_root),
            HashPart::Str(ordering_batch_root),
        ],
        32,
    )
}

pub fn private_mempool_root_from_parts(
    mempool_entry_root: &str,
    ordering_batch_root: &str,
    low_fee_policy_root: &str,
    pending_private_count: u64,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-PRIVATE-MEMPOOL-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(mempool_entry_root),
            HashPart::Str(ordering_batch_root),
            HashPart::Str(low_fee_policy_root),
            HashPart::Int(pending_private_count as i128),
        ],
        32,
    )
}

pub fn finality_root_from_parts(
    microblock_proposal_root: &str,
    finality_vote_root: &str,
    finality_certificate_root: &str,
    equivocation_evidence_root: &str,
    slashing_record_root: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-FINALITY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(microblock_proposal_root),
            HashPart::Str(finality_vote_root),
            HashPart::Str(finality_certificate_root),
            HashPart::Str(equivocation_evidence_root),
            HashPart::Str(slashing_record_root),
        ],
        32,
    )
}

pub fn deterministic_state_tag(
    height: u64,
    epoch: u64,
    committee_id: &str,
    root_hint: &str,
) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-DETERMINISTIC-STATE-TAG",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(epoch as i128),
            HashPart::Str(committee_id),
            HashPart::Str(root_hint),
        ],
        32,
    )
}

pub fn decentralized_sequencer_genesis_root(committee_id: &str) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-GENESIS-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(committee_id)],
        32,
    )
}

pub fn devnet_commitment(kind: &str, seed: u64) -> String {
    domain_hash(
        "DECENTRALIZED-SEQUENCER-DEVNET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Int(seed as i128),
        ],
        32,
    )
}

pub fn epoch_for_height(height: u64, epoch_length: u64) -> u64 {
    if epoch_length == 0 {
        0
    } else {
        height / epoch_length
    }
}

pub fn quorum_power(total_voting_power: u64, quorum_bps: u64) -> u64 {
    total_voting_power
        .saturating_mul(quorum_bps)
        .saturating_add(DECENTRALIZED_SEQUENCER_MAX_BPS - 1)
        .saturating_div(DECENTRALIZED_SEQUENCER_MAX_BPS)
}

pub fn reaches_quorum(signed_voting_power: u64, total_voting_power: u64, quorum_bps: u64) -> bool {
    signed_voting_power >= quorum_power(total_voting_power, quorum_bps)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(DECENTRALIZED_SEQUENCER_MAX_BPS)
        .saturating_div(denominator)
        .min(DECENTRALIZED_SEQUENCER_MAX_BPS)
}

pub fn amount_bucket(amount: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        amount
    } else {
        amount
            .saturating_add(bucket_size.saturating_sub(1))
            .saturating_div(bucket_size)
            .saturating_mul(bucket_size)
    }
}

pub fn deterministic_u64(domain: &str, parts: &[HashPart<'_>]) -> u64 {
    let hash = domain_hash(domain, parts, 8);
    u64::from_str_radix(&hash, 16).unwrap_or(0)
}

pub fn canonical_roles(roles: Vec<CommitteeRole>) -> Vec<CommitteeRole> {
    roles
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn ensure_non_empty(value: &str, label: &str) -> DecentralizedSequencerResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_positive(value: u64, label: &str) -> DecentralizedSequencerResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

pub fn ensure_bps(value: u64, label: &str) -> DecentralizedSequencerResult<()> {
    if value > DECENTRALIZED_SEQUENCER_MAX_BPS {
        Err(format!("{label} exceeds max bps"))
    } else {
        Ok(())
    }
}

pub fn ensure_unique_strings(values: &[String], label: &str) -> DecentralizedSequencerResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        Err(format!("{label} must be unique"))
    } else {
        Ok(())
    }
}

fn empty_authorization() -> Authorization {
    Authorization {
        signer_label: String::new(),
        auth_scheme: String::new(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_has_finality_and_slashing_roots() {
        let state = DecentralizedSequencerState::devnet().expect("devnet state");
        assert_eq!(state.config.protocol_version, PROTOCOL_VERSION);
        assert!(!state.committee.members.is_empty());
        assert!(!state.lanes.is_empty());
        assert!(!state.mempool_entries.is_empty());
        assert!(!state.finality_certificates.is_empty());
        assert!(!state.equivocation_evidence.is_empty());
        assert!(!state.slashing_records.is_empty());
        assert_eq!(
            state.state_root(),
            decentralized_sequencer_state_root_from_record(&state.public_record_without_root())
        );
    }

    #[test]
    fn leader_rotation_is_deterministic() {
        let state = DecentralizedSequencerState::devnet().expect("devnet state");
        let first = state
            .committee
            .leader_for_slot(10, 0, state.config.leader_schedule_mode)
            .expect("leader");
        let second = state
            .committee
            .leader_for_slot(10, 0, state.config.leader_schedule_mode)
            .expect("leader");
        assert_eq!(first.member_id, second.member_id);
    }

    #[test]
    fn qos_reserves_low_fee_budget() {
        let mut state = DecentralizedSequencerState::devnet().expect("devnet state");
        let before = state.low_fee_policy.remaining_budget_units;
        let lane_id = state
            .lanes
            .values()
            .find(|lane| lane.low_fee_eligible())
            .map(|lane| lane.lane_id.clone())
            .expect("low fee lane");
        let tx_public = json!({"kind": "test_tx", "nonce": 99});
        let encrypted_payload = json!({"kind": "test_payload", "ciphertext": "devnet"});
        let _ = state
            .admit_private_entry(
                &lane_id,
                "test-low-fee-wallet",
                &tx_public,
                &encrypted_payload,
                "wxmr-devnet",
                4,
                30,
                2_000,
                3,
            )
            .expect("admission");
        assert!(state.low_fee_policy.remaining_budget_units <= before);
    }

    #[test]
    fn conflicting_votes_generate_evidence() {
        let state = DecentralizedSequencerState::devnet().expect("devnet state");
        let first = state.finality_votes[0].clone();
        let proposal = state
            .microblock_proposals
            .iter()
            .find(|proposal| proposal.proposal_id == first.proposal_id)
            .cloned()
            .expect("proposal");
        let voter = state
            .committee
            .member_by_id(&first.voter_member_id)
            .cloned()
            .expect("voter");
        let mut conflicting = proposal.clone();
        conflicting.state_root_after =
            decentralized_sequencer_string_root("TEST-CONFLICT", &proposal.state_root_after);
        conflicting.proposal_id = microblock_proposal_id(
            proposal.height,
            proposal.microblock_sequence,
            proposal.epoch,
            &proposal.leader_member_id,
            &proposal.parent_microblock_id,
            &proposal.parent_state_root,
            &proposal.ordering_batch_root,
            &conflicting.state_root_after,
        );
        let second =
            MicroblockFinalityVote::new(first.vote_kind, &conflicting, &voter, first.lock_round)
                .expect("conflicting vote");
        let evidence =
            EquivocationEvidence::from_conflicting_votes(&first, &second, "test-watchtower", 7)
                .expect("evidence");
        assert_eq!(evidence.kind, EquivocationKind::ConflictingVote);
        assert_eq!(evidence.offender_member_id, first.voter_member_id);
    }
}
