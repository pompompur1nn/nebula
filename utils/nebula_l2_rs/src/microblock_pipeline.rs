use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type MicroblockPipelineResult<T> = Result<T, String>;

pub const MICROBLOCK_PIPELINE_PROTOCOL_VERSION: &str = "nebula-microblock-pipeline-v1";
pub const MICROBLOCK_PIPELINE_SCHEMA_VERSION: &str = "microblock-pipeline-state-v1";
pub const MICROBLOCK_PIPELINE_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const MICROBLOCK_PIPELINE_PQ_COMMITTEE_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const MICROBLOCK_PIPELINE_TRANSCRIPT_HASH: &str = "SHA3-256";
pub const MICROBLOCK_PIPELINE_REPLAY_ENGINE: &str = "deterministic-wasm-pq-vm-v1";
pub const MICROBLOCK_PIPELINE_PRIVATE_VISIBILITY: &str = "private_payload_roots_only";
pub const MICROBLOCK_PIPELINE_MAX_BPS: u64 = 10_000;
pub const MICROBLOCK_DEFAULT_TARGET_MS: u64 = 80;
pub const MICROBLOCK_DEFAULT_MAX_ADMISSIONS: u64 = 64;
pub const MICROBLOCK_DEFAULT_MAX_PRIVATE_PAYLOAD_ROOTS: u64 = 64;
pub const MICROBLOCK_DEFAULT_MAX_OPTIMISTIC_WINDOWS: u64 = 8;
pub const MICROBLOCK_DEFAULT_FINALITY_DEPTH: u64 = 6;
pub const MICROBLOCK_DEFAULT_RECEIPT_TTL_MICROBLOCKS: u64 = 24;
pub const MICROBLOCK_DEFAULT_REPLAY_RETENTION_MICROBLOCKS: u64 = 96;
pub const MICROBLOCK_DEFAULT_LOW_FEE_SHARE_BPS: u64 = 2_000;
pub const MICROBLOCK_DEFAULT_PRIVATE_SHARE_BPS: u64 = 3_500;
pub const MICROBLOCK_DEFAULT_BRIDGE_SHARE_BPS: u64 = 1_000;
pub const MICROBLOCK_DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const MICROBLOCK_DEFAULT_FAST_LANE_QUOTA_UNITS: u64 = 10_000;
pub const MICROBLOCK_DEFAULT_SPONSORSHIP_TTL_MICROBLOCKS: u64 = 48;
pub const MICROBLOCK_DEFAULT_WITHDRAWAL_GUARD_DELAY_BLOCKS: u64 = 4;
pub const MICROBLOCK_DEFAULT_WITHDRAWAL_MAX_FAST_UNITS: u64 = 250;
pub const MICROBLOCK_DEFAULT_LATENCY_BUDGET_MS: u64 = TARGET_BLOCK_MS;
pub const MICROBLOCK_DEFAULT_CAPACITY_UNITS: u64 = 1_000_000;
pub const MICROBLOCK_STATUS_PROPOSED: &str = "proposed";
pub const MICROBLOCK_STATUS_PRECONFIRMED: &str = "preconfirmed";
pub const MICROBLOCK_STATUS_FINALIZED: &str = "finalized";
pub const MICROBLOCK_STATUS_CONFLICTED: &str = "conflicted";
pub const MICROBLOCK_STATUS_ROLLED_BACK: &str = "rolled_back";
pub const MICROBLOCK_DEVNET_SEQUENCER_ID: &str = "devnet-fast-sequencer";
pub const MICROBLOCK_DEVNET_COMMITTEE_ID: &str = "devnet-pq-committee";
pub const MICROBLOCK_DEVNET_SPONSOR_ID: &str = "devnet-low-fee-sponsor";
pub const MICROBLOCK_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const MICROBLOCK_DEVNET_MONERO_NETWORK: &str = "monero-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicroblockLane {
    System,
    LowFeeFast,
    PrivateTransfer,
    PrivateDefi,
    PublicDefi,
    ContractCall,
    Token,
    BridgeDeposit,
    BridgeWithdrawal,
    ProofMarket,
    Bulk,
}

impl MicroblockLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::LowFeeFast => "low_fee_fast",
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefi => "private_defi",
            Self::PublicDefi => "public_defi",
            Self::ContractCall => "contract_call",
            Self::Token => "token",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::ProofMarket => "proof_market",
            Self::Bulk => "bulk",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::System => 1_000_000,
            Self::BridgeWithdrawal => 900_000,
            Self::BridgeDeposit => 850_000,
            Self::PrivateTransfer => 760_000,
            Self::PrivateDefi => 720_000,
            Self::LowFeeFast => 680_000,
            Self::ProofMarket => 620_000,
            Self::ContractCall => 580_000,
            Self::PublicDefi => 540_000,
            Self::Token => 500_000,
            Self::Bulk => 100_000,
        }
    }

    pub fn target_latency_ms(self) -> u64 {
        match self {
            Self::System => TARGET_BLOCK_MS / 8,
            Self::LowFeeFast => TARGET_BLOCK_MS / 5,
            Self::PrivateTransfer => TARGET_BLOCK_MS / 4,
            Self::PrivateDefi => TARGET_BLOCK_MS / 3,
            Self::BridgeWithdrawal | Self::BridgeDeposit => TARGET_BLOCK_MS / 2,
            Self::ContractCall | Self::PublicDefi | Self::Token => TARGET_BLOCK_MS,
            Self::ProofMarket => TARGET_BLOCK_MS.saturating_mul(2),
            Self::Bulk => TARGET_BLOCK_MS.saturating_mul(4),
        }
        .max(1)
    }

    pub fn low_fee_eligible(self) -> bool {
        matches!(
            self,
            Self::LowFeeFast
                | Self::PrivateTransfer
                | Self::PrivateDefi
                | Self::ContractCall
                | Self::Token
        )
    }

    pub fn bridge_sensitive(self) -> bool {
        matches!(self, Self::BridgeDeposit | Self::BridgeWithdrawal)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MicroblockOrderingClass {
    SequencerLocal,
    EncryptedArrivalSlot,
    FeeBucket,
    LowFeeQuota,
    BridgeGuarded,
    DeterministicReplay,
}

impl MicroblockOrderingClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerLocal => "sequencer_local",
            Self::EncryptedArrivalSlot => "encrypted_arrival_slot",
            Self::FeeBucket => "fee_bucket",
            Self::LowFeeQuota => "low_fee_quota",
            Self::BridgeGuarded => "bridge_guarded",
            Self::DeterministicReplay => "deterministic_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimisticWindowStatus {
    Open,
    Replayed,
    Settled,
    Conflicted,
    RolledBack,
    Expired,
}

impl OptimisticWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Replayed => "replayed",
            Self::Settled => "settled",
            Self::Conflicted => "conflicted",
            Self::RolledBack => "rolled_back",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationReceiptStatus {
    Promised,
    Preconfirmed,
    Finalized,
    Expired,
    Conflicted,
    RolledBack,
}

impl PreconfirmationReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Promised => "promised",
            Self::Preconfirmed => "preconfirmed",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Conflicted => "conflicted",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityPromotionStatus {
    Pending,
    Promoted,
    Anchored,
    Rejected,
    Reorged,
}

impl FinalityPromotionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Promoted => "promoted",
            Self::Anchored => "anchored",
            Self::Rejected => "rejected",
            Self::Reorged => "reorged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    DoubleSpendNullifier,
    StateWriteConflict,
    ReplayMismatch,
    EquivocatedMicroblock,
    InvalidBridgeWithdrawal,
    QuotaOverspend,
    BadCommitteeQuorum,
}

impl ConflictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::StateWriteConflict => "state_write_conflict",
            Self::ReplayMismatch => "replay_mismatch",
            Self::EquivocatedMicroblock => "equivocated_microblock",
            Self::InvalidBridgeWithdrawal => "invalid_bridge_withdrawal",
            Self::QuotaOverspend => "quota_overspend",
            Self::BadCommitteeQuorum => "bad_committee_quorum",
        }
    }

    pub fn slash_bps(self) -> u64 {
        match self {
            Self::EquivocatedMicroblock => 10_000,
            Self::DoubleSpendNullifier => 9_000,
            Self::InvalidBridgeWithdrawal => 8_500,
            Self::ReplayMismatch => 7_500,
            Self::StateWriteConflict => 6_000,
            Self::QuotaOverspend => 3_000,
            Self::BadCommitteeQuorum => 5_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackReason {
    ConflictCertificate,
    BridgeGuardrail,
    ReplayDivergence,
    CommitteeChallenge,
    ExpiredOptimisticWindow,
}

impl RollbackReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConflictCertificate => "conflict_certificate",
            Self::BridgeGuardrail => "bridge_guardrail",
            Self::ReplayDivergence => "replay_divergence",
            Self::CommitteeChallenge => "committee_challenge",
            Self::ExpiredOptimisticWindow => "expired_optimistic_window",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    Sequencer,
    CommitteeMember,
    Watchtower,
    BridgeGuardian,
    ReplayExecutor,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::CommitteeMember => "committee_member",
            Self::Watchtower => "watchtower",
            Self::BridgeGuardian => "bridge_guardian",
            Self::ReplayExecutor => "replay_executor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    Accepted,
    Delayed,
    Sponsored,
    QuotaExhausted,
    BridgeGuarded,
    Rejected,
}

impl AdmissionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Delayed => "delayed",
            Self::Sponsored => "sponsored",
            Self::QuotaExhausted => "quota_exhausted",
            Self::BridgeGuarded => "bridge_guarded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacitySignal {
    Green,
    Saturating,
    Throttled,
    Exhausted,
}

impl CapacitySignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Saturating => "saturating",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalGuardStatus {
    Pending,
    SoftLocked,
    Eligible,
    Delayed,
    Paused,
    Released,
    Rejected,
}

impl WithdrawalGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::SoftLocked => "soft_locked",
            Self::Eligible => "eligible",
            Self::Delayed => "delayed",
            Self::Paused => "paused",
            Self::Released => "released",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Consumed,
    Refunded,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroblockPipelineConfig {
    pub protocol_version: String,
    pub schema_version: String,
    pub target_microblock_ms: u64,
    pub max_admissions_per_microblock: u64,
    pub max_private_payload_roots: u64,
    pub max_optimistic_windows: u64,
    pub finality_depth_microblocks: u64,
    pub receipt_ttl_microblocks: u64,
    pub replay_retention_microblocks: u64,
    pub low_fee_min_share_bps: u64,
    pub private_min_share_bps: u64,
    pub bridge_min_share_bps: u64,
    pub committee_quorum_bps: u64,
    pub pq_signature_scheme: String,
    pub pq_committee_scheme: String,
    pub transcript_hash: String,
    pub replay_engine: String,
    pub visibility_policy: String,
    pub max_capacity_units_per_microblock: u64,
    pub withdrawal_guard_delay_blocks: u64,
    pub withdrawal_max_fast_lane_units: u64,
    pub fee_asset_id: String,
    pub metadata_root: String,
}

impl Default for MicroblockPipelineConfig {
    fn default() -> Self {
        Self {
            protocol_version: MICROBLOCK_PIPELINE_PROTOCOL_VERSION.to_string(),
            schema_version: MICROBLOCK_PIPELINE_SCHEMA_VERSION.to_string(),
            target_microblock_ms: MICROBLOCK_DEFAULT_TARGET_MS,
            max_admissions_per_microblock: MICROBLOCK_DEFAULT_MAX_ADMISSIONS,
            max_private_payload_roots: MICROBLOCK_DEFAULT_MAX_PRIVATE_PAYLOAD_ROOTS,
            max_optimistic_windows: MICROBLOCK_DEFAULT_MAX_OPTIMISTIC_WINDOWS,
            finality_depth_microblocks: MICROBLOCK_DEFAULT_FINALITY_DEPTH,
            receipt_ttl_microblocks: MICROBLOCK_DEFAULT_RECEIPT_TTL_MICROBLOCKS,
            replay_retention_microblocks: MICROBLOCK_DEFAULT_REPLAY_RETENTION_MICROBLOCKS,
            low_fee_min_share_bps: MICROBLOCK_DEFAULT_LOW_FEE_SHARE_BPS,
            private_min_share_bps: MICROBLOCK_DEFAULT_PRIVATE_SHARE_BPS,
            bridge_min_share_bps: MICROBLOCK_DEFAULT_BRIDGE_SHARE_BPS,
            committee_quorum_bps: MICROBLOCK_DEFAULT_COMMITTEE_QUORUM_BPS,
            pq_signature_scheme: MICROBLOCK_PIPELINE_PQ_SIGNATURE_SCHEME.to_string(),
            pq_committee_scheme: MICROBLOCK_PIPELINE_PQ_COMMITTEE_SCHEME.to_string(),
            transcript_hash: MICROBLOCK_PIPELINE_TRANSCRIPT_HASH.to_string(),
            replay_engine: MICROBLOCK_PIPELINE_REPLAY_ENGINE.to_string(),
            visibility_policy: MICROBLOCK_PIPELINE_PRIVATE_VISIBILITY.to_string(),
            max_capacity_units_per_microblock: MICROBLOCK_DEFAULT_CAPACITY_UNITS,
            withdrawal_guard_delay_blocks: MICROBLOCK_DEFAULT_WITHDRAWAL_GUARD_DELAY_BLOCKS,
            withdrawal_max_fast_lane_units: MICROBLOCK_DEFAULT_WITHDRAWAL_MAX_FAST_UNITS,
            fee_asset_id: MICROBLOCK_DEVNET_FEE_ASSET_ID.to_string(),
            metadata_root: microblock_pipeline_payload_root(
                "MICROBLOCK-CONFIG-METADATA",
                &json!({
                    "mode": "devnet",
                    "privacy": "only roots and commitments are public",
                    "goal": "instant confirmations with deterministic rollback"
                }),
            ),
        }
    }
}

impl MicroblockPipelineConfig {
    pub fn validate(&self) -> MicroblockPipelineResult<()> {
        ensure_non_empty(&self.protocol_version, "microblock protocol version")?;
        ensure_non_empty(&self.schema_version, "microblock schema version")?;
        ensure_non_empty(&self.pq_signature_scheme, "microblock PQ signature scheme")?;
        ensure_non_empty(&self.pq_committee_scheme, "microblock PQ committee scheme")?;
        ensure_non_empty(&self.transcript_hash, "microblock transcript hash")?;
        ensure_non_empty(&self.replay_engine, "microblock replay engine")?;
        ensure_non_empty(&self.visibility_policy, "microblock visibility policy")?;
        ensure_non_empty(&self.fee_asset_id, "microblock fee asset")?;
        ensure_non_empty(&self.metadata_root, "microblock metadata root")?;
        ensure_positive(self.target_microblock_ms, "microblock target ms")?;
        ensure_positive(
            self.max_admissions_per_microblock,
            "microblock max admissions",
        )?;
        ensure_positive(
            self.max_private_payload_roots,
            "microblock max private payload roots",
        )?;
        ensure_positive(
            self.max_optimistic_windows,
            "microblock max optimistic windows",
        )?;
        ensure_positive(self.finality_depth_microblocks, "microblock finality depth")?;
        ensure_positive(self.receipt_ttl_microblocks, "microblock receipt ttl")?;
        ensure_positive(
            self.replay_retention_microblocks,
            "microblock replay retention",
        )?;
        ensure_positive(
            self.max_capacity_units_per_microblock,
            "microblock capacity units",
        )?;
        ensure_bps(self.low_fee_min_share_bps, "microblock low fee share")?;
        ensure_bps(self.private_min_share_bps, "microblock private share")?;
        ensure_bps(self.bridge_min_share_bps, "microblock bridge share")?;
        ensure_bps(self.committee_quorum_bps, "microblock committee quorum")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "microblock_pipeline_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "target_microblock_ms": self.target_microblock_ms,
            "max_admissions_per_microblock": self.max_admissions_per_microblock,
            "max_private_payload_roots": self.max_private_payload_roots,
            "max_optimistic_windows": self.max_optimistic_windows,
            "finality_depth_microblocks": self.finality_depth_microblocks,
            "receipt_ttl_microblocks": self.receipt_ttl_microblocks,
            "replay_retention_microblocks": self.replay_retention_microblocks,
            "low_fee_min_share_bps": self.low_fee_min_share_bps,
            "private_min_share_bps": self.private_min_share_bps,
            "bridge_min_share_bps": self.bridge_min_share_bps,
            "committee_quorum_bps": self.committee_quorum_bps,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_committee_scheme": self.pq_committee_scheme,
            "transcript_hash": self.transcript_hash,
            "replay_engine": self.replay_engine,
            "visibility_policy": self.visibility_policy,
            "max_capacity_units_per_microblock": self.max_capacity_units_per_microblock,
            "withdrawal_guard_delay_blocks": self.withdrawal_guard_delay_blocks,
            "withdrawal_max_fast_lane_units": self.withdrawal_max_fast_lane_units,
            "fee_asset_id": self.fee_asset_id,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySafeOrderingMetadata {
    pub ordering_id: String,
    pub lane: MicroblockLane,
    pub ordering_class: MicroblockOrderingClass,
    pub lane_sequence: u64,
    pub priority_score: u64,
    pub fee_bucket: u64,
    pub arrival_slot: u64,
    pub entropy_commitment: String,
    pub tie_breaker_root: String,
    pub visible_after_height: u64,
}

impl PrivacySafeOrderingMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: MicroblockLane,
        ordering_class: MicroblockOrderingClass,
        lane_sequence: u64,
        priority_score: u64,
        fee_bucket: u64,
        arrival_slot: u64,
        entropy_commitment: &str,
        visible_after_height: u64,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(entropy_commitment, "ordering entropy commitment")?;
        let tie_breaker_root = microblock_pipeline_string_root(
            "MICROBLOCK-ORDERING-TIE-BREAKER",
            &format!("{}:{lane_sequence}:{arrival_slot}", lane.as_str()),
        );
        let ordering_id = microblock_ordering_metadata_id(
            lane,
            ordering_class,
            lane_sequence,
            priority_score,
            fee_bucket,
            arrival_slot,
            entropy_commitment,
            &tie_breaker_root,
        );
        Ok(Self {
            ordering_id,
            lane,
            ordering_class,
            lane_sequence,
            priority_score,
            fee_bucket,
            arrival_slot,
            entropy_commitment: entropy_commitment.to_string(),
            tie_breaker_root,
            visible_after_height,
        })
    }

    pub fn devnet(
        label: &str,
        lane: MicroblockLane,
        lane_sequence: u64,
        height: u64,
    ) -> MicroblockPipelineResult<Self> {
        let ordering_class = if lane.bridge_sensitive() {
            MicroblockOrderingClass::BridgeGuarded
        } else if lane == MicroblockLane::LowFeeFast {
            MicroblockOrderingClass::LowFeeQuota
        } else {
            MicroblockOrderingClass::EncryptedArrivalSlot
        };
        Self::new(
            lane,
            ordering_class,
            lane_sequence,
            lane.default_priority().saturating_add(lane_sequence),
            amount_bucket(lane_sequence.saturating_mul(17).saturating_add(31), 10),
            height.saturating_mul(1_000).saturating_add(lane_sequence),
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-ORDERING-ENTROPY", label),
            height.saturating_add(2),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_safe_ordering_metadata",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "ordering_id": self.ordering_id,
            "lane": self.lane.as_str(),
            "ordering_class": self.ordering_class.as_str(),
            "lane_sequence": self.lane_sequence,
            "priority_score": self.priority_score,
            "fee_bucket": self.fee_bucket,
            "arrival_slot": self.arrival_slot,
            "entropy_commitment": self.entropy_commitment,
            "tie_breaker_root": self.tie_breaker_root,
            "visible_after_height": self.visible_after_height,
        })
    }

    pub fn ordering_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-ORDERING-METADATA", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.ordering_id, "ordering id")?;
        ensure_non_empty(&self.entropy_commitment, "ordering entropy commitment")?;
        ensure_non_empty(&self.tie_breaker_root, "ordering tie breaker root")?;
        let expected = microblock_ordering_metadata_id(
            self.lane,
            self.ordering_class,
            self.lane_sequence,
            self.priority_score,
            self.fee_bucket,
            self.arrival_slot,
            &self.entropy_commitment,
            &self.tie_breaker_root,
        );
        if self.ordering_id != expected {
            return Err("ordering metadata id mismatch".to_string());
        }
        Ok(self.ordering_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolAdmissionCommitment {
    pub admission_id: String,
    pub lane: MicroblockLane,
    pub tx_public_hash: String,
    pub account_commitment: String,
    pub nullifier_root: String,
    pub private_payload_root: String,
    pub ordering_metadata: PrivacySafeOrderingMetadata,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub low_fee_requested: bool,
    pub sponsor_commitment: Option<String>,
    pub bridge_guardrail_id: Option<String>,
    pub bridge_amount_bucket: u64,
    pub decision: AdmissionDecision,
    pub nonce: u64,
    pub admitted_at_height: u64,
    pub admitted_at_microblock: u64,
    pub expires_at_height: u64,
}

impl MempoolAdmissionCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: MicroblockLane,
        account_commitment: &str,
        nullifier_root: &str,
        private_payload_root: &str,
        ordering_metadata: PrivacySafeOrderingMetadata,
        fee_asset_id: &str,
        max_fee_units: u64,
        low_fee_requested: bool,
        sponsor_commitment: Option<String>,
        bridge_guardrail_id: Option<String>,
        bridge_amount_bucket: u64,
        nonce: u64,
        admitted_at_height: u64,
        admitted_at_microblock: u64,
        ttl_blocks: u64,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(account_commitment, "mempool account commitment")?;
        ensure_non_empty(nullifier_root, "mempool nullifier root")?;
        ensure_non_empty(private_payload_root, "mempool private payload root")?;
        ensure_non_empty(fee_asset_id, "mempool fee asset")?;
        if low_fee_requested && !lane.low_fee_eligible() {
            return Err("lane is not low-fee eligible".to_string());
        }
        if lane == MicroblockLane::BridgeWithdrawal && bridge_guardrail_id.is_none() {
            return Err("bridge withdrawal admission needs guardrail id".to_string());
        }
        let tx_public_hash = microblock_pipeline_payload_root(
            "MICROBLOCK-MEMPOOL-TX-PUBLIC",
            &json!({
                "lane": lane.as_str(),
                "account_commitment": account_commitment,
                "nullifier_root": nullifier_root,
                "ordering_root": ordering_metadata.ordering_root(),
                "fee_asset_id": fee_asset_id,
                "low_fee_requested": low_fee_requested,
                "bridge_amount_bucket": bridge_amount_bucket,
            }),
        );
        let decision = if bridge_guardrail_id.is_some() {
            AdmissionDecision::BridgeGuarded
        } else if sponsor_commitment.is_some() {
            AdmissionDecision::Sponsored
        } else {
            AdmissionDecision::Accepted
        };
        let admission_id = microblock_mempool_admission_id(
            lane,
            &tx_public_hash,
            account_commitment,
            nullifier_root,
            private_payload_root,
            ordering_metadata.lane_sequence,
            nonce,
            admitted_at_height,
        );
        Ok(Self {
            admission_id,
            lane,
            tx_public_hash,
            account_commitment: account_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            private_payload_root: private_payload_root.to_string(),
            ordering_metadata,
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            low_fee_requested,
            sponsor_commitment,
            bridge_guardrail_id,
            bridge_amount_bucket,
            decision,
            nonce,
            admitted_at_height,
            admitted_at_microblock,
            expires_at_height: admitted_at_height.saturating_add(ttl_blocks.max(1)),
        })
    }

    pub fn devnet(
        label: &str,
        lane: MicroblockLane,
        lane_sequence: u64,
        height: u64,
        microblock_sequence: u64,
        sponsor_commitment: Option<String>,
        bridge_guardrail_id: Option<String>,
    ) -> MicroblockPipelineResult<Self> {
        let ordering = PrivacySafeOrderingMetadata::devnet(label, lane, lane_sequence, height)?;
        let bridge_amount_bucket = if lane == MicroblockLane::BridgeWithdrawal {
            amount_bucket(125 + lane_sequence.saturating_mul(25), 25)
        } else {
            0
        };
        Self::new(
            lane,
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-ACCOUNT", label),
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-NULLIFIER", label),
            &microblock_pipeline_payload_root(
                "MICROBLOCK-DEVNET-PRIVATE-PAYLOAD",
                &json!({
                    "label": label,
                    "payload": "redacted",
                    "visibility": MICROBLOCK_PIPELINE_PRIVATE_VISIBILITY,
                }),
            ),
            ordering,
            MICROBLOCK_DEVNET_FEE_ASSET_ID,
            10_u64.saturating_add(lane_sequence),
            lane.low_fee_eligible(),
            sponsor_commitment,
            bridge_guardrail_id,
            bridge_amount_bucket,
            lane_sequence,
            height,
            microblock_sequence,
            12,
        )
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "mempool_admission_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "admission_id": self.admission_id,
            "lane": self.lane.as_str(),
            "tx_public_hash": self.tx_public_hash,
            "account_commitment": self.account_commitment,
            "nullifier_root": self.nullifier_root,
            "private_payload_root": self.private_payload_root,
            "payload_visibility": MICROBLOCK_PIPELINE_PRIVATE_VISIBILITY,
            "ordering_root": self.ordering_metadata.ordering_root(),
            "ordering_metadata": self.ordering_metadata.public_record(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "low_fee_requested": self.low_fee_requested,
            "sponsor_commitment": self.sponsor_commitment,
            "bridge_guardrail_id": self.bridge_guardrail_id,
            "bridge_amount_bucket": self.bridge_amount_bucket,
            "decision": self.decision.as_str(),
            "nonce": self.nonce,
            "admitted_at_height": self.admitted_at_height,
            "admitted_at_microblock": self.admitted_at_microblock,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn admission_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-MEMPOOL-ADMISSION", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.admission_id, "mempool admission id")?;
        ensure_non_empty(&self.tx_public_hash, "mempool tx public hash")?;
        ensure_non_empty(&self.account_commitment, "mempool account commitment")?;
        ensure_non_empty(&self.nullifier_root, "mempool nullifier root")?;
        ensure_non_empty(&self.private_payload_root, "mempool private payload root")?;
        ensure_non_empty(&self.fee_asset_id, "mempool fee asset")?;
        self.ordering_metadata.validate()?;
        if self.low_fee_requested && !self.lane.low_fee_eligible() {
            return Err("mempool admission requests low fee on ineligible lane".to_string());
        }
        if self.lane == MicroblockLane::BridgeWithdrawal && self.bridge_guardrail_id.is_none() {
            return Err("bridge withdrawal admission is missing guardrail".to_string());
        }
        if self.expires_at_height <= self.admitted_at_height {
            return Err("mempool admission expiry must be after admission height".to_string());
        }
        let expected = microblock_mempool_admission_id(
            self.lane,
            &self.tx_public_hash,
            &self.account_commitment,
            &self.nullifier_root,
            &self.private_payload_root,
            self.ordering_metadata.lane_sequence,
            self.nonce,
            self.admitted_at_height,
        );
        if self.admission_id != expected {
            return Err("mempool admission id mismatch".to_string());
        }
        Ok(self.admission_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeFastLaneQuota {
    pub quota_id: String,
    pub lane: MicroblockLane,
    pub sponsor_commitment: String,
    pub quota_window_start: u64,
    pub quota_window_end: u64,
    pub quota_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub min_fee_asset_id: String,
    pub sponsorship_root: String,
    pub status: SponsorshipStatus,
}

impl LowFeeFastLaneQuota {
    pub fn new(
        lane: MicroblockLane,
        sponsor_commitment: &str,
        quota_window_start: u64,
        quota_window_end: u64,
        quota_units: u64,
        min_fee_asset_id: &str,
        sponsorship_root: &str,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(sponsor_commitment, "low fee quota sponsor")?;
        ensure_non_empty(min_fee_asset_id, "low fee quota fee asset")?;
        ensure_non_empty(sponsorship_root, "low fee quota sponsorship root")?;
        if !lane.low_fee_eligible() {
            return Err("low fee quota lane is not eligible".to_string());
        }
        if quota_window_end <= quota_window_start {
            return Err("low fee quota window ends before it starts".to_string());
        }
        ensure_positive(quota_units, "low fee quota units")?;
        let quota_id = microblock_low_fee_quota_id(
            lane,
            sponsor_commitment,
            quota_window_start,
            quota_window_end,
            quota_units,
            min_fee_asset_id,
        );
        Ok(Self {
            quota_id,
            lane,
            sponsor_commitment: sponsor_commitment.to_string(),
            quota_window_start,
            quota_window_end,
            quota_units,
            reserved_units: 0,
            consumed_units: 0,
            min_fee_asset_id: min_fee_asset_id.to_string(),
            sponsorship_root: sponsorship_root.to_string(),
            status: SponsorshipStatus::Reserved,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.quota_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }

    pub fn reserve_units(&mut self, units: u64) -> MicroblockPipelineResult<()> {
        if units > self.available_units() {
            return Err("low fee quota reserve exceeds available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn consume_reserved(&mut self, units: u64) -> MicroblockPipelineResult<()> {
        if units > self.reserved_units {
            return Err("low fee quota consume exceeds reserved units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.consumed_units = self.consumed_units.saturating_add(units);
        self.status = SponsorshipStatus::Consumed;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_fast_lane_quota",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "quota_id": self.quota_id,
            "lane": self.lane.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "quota_window_start": self.quota_window_start,
            "quota_window_end": self.quota_window_end,
            "quota_units": self.quota_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "available_units": self.available_units(),
            "min_fee_asset_id": self.min_fee_asset_id,
            "sponsorship_root": self.sponsorship_root,
            "status": self.status.as_str(),
        })
    }

    pub fn quota_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-LOW-FEE-QUOTA", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.quota_id, "low fee quota id")?;
        ensure_non_empty(&self.sponsor_commitment, "low fee quota sponsor")?;
        ensure_non_empty(&self.min_fee_asset_id, "low fee quota asset")?;
        ensure_non_empty(&self.sponsorship_root, "low fee quota sponsorship root")?;
        if !self.lane.low_fee_eligible() {
            return Err("low fee quota lane is ineligible".to_string());
        }
        if self.quota_window_end <= self.quota_window_start {
            return Err("low fee quota window invalid".to_string());
        }
        if self.reserved_units.saturating_add(self.consumed_units) > self.quota_units {
            return Err("low fee quota accounting exceeds quota".to_string());
        }
        let expected = microblock_low_fee_quota_id(
            self.lane,
            &self.sponsor_commitment,
            self.quota_window_start,
            self.quota_window_end,
            self.quota_units,
            &self.min_fee_asset_id,
        );
        if self.quota_id != expected {
            return Err("low fee quota id mismatch".to_string());
        }
        Ok(self.quota_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorshipLedgerEntry {
    pub sponsorship_id: String,
    pub quota_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub admission_id: String,
    pub fee_asset_id: String,
    pub sponsored_units: u64,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl SponsorshipLedgerEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        quota_id: &str,
        sponsor_commitment: &str,
        beneficiary_commitment: &str,
        admission_id: &str,
        fee_asset_id: &str,
        sponsored_units: u64,
        rebate_bps: u64,
        issued_at_height: u64,
        ttl_microblocks: u64,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(quota_id, "sponsorship quota id")?;
        ensure_non_empty(sponsor_commitment, "sponsorship sponsor")?;
        ensure_non_empty(beneficiary_commitment, "sponsorship beneficiary")?;
        ensure_non_empty(admission_id, "sponsorship admission")?;
        ensure_non_empty(fee_asset_id, "sponsorship fee asset")?;
        ensure_positive(sponsored_units, "sponsorship units")?;
        ensure_bps(rebate_bps, "sponsorship rebate")?;
        let sponsorship_id = microblock_sponsorship_id(
            quota_id,
            sponsor_commitment,
            beneficiary_commitment,
            admission_id,
            fee_asset_id,
            sponsored_units,
            issued_at_height,
        );
        Ok(Self {
            sponsorship_id,
            quota_id: quota_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            admission_id: admission_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            sponsored_units,
            rebate_bps,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_microblocks.max(1)),
            status: SponsorshipStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsorship_ledger_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "quota_id": self.quota_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "admission_id": self.admission_id,
            "fee_asset_id": self.fee_asset_id,
            "sponsored_units": self.sponsored_units,
            "rebate_bps": self.rebate_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.quota_id, "sponsorship quota id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor")?;
        ensure_non_empty(&self.beneficiary_commitment, "sponsorship beneficiary")?;
        ensure_non_empty(&self.admission_id, "sponsorship admission")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee asset")?;
        ensure_positive(self.sponsored_units, "sponsorship units")?;
        ensure_bps(self.rebate_bps, "sponsorship rebate")?;
        if self.expires_at_height <= self.issued_at_height {
            return Err("sponsorship expiry must be after issue height".to_string());
        }
        let expected = microblock_sponsorship_id(
            &self.quota_id,
            &self.sponsor_commitment,
            &self.beneficiary_commitment,
            &self.admission_id,
            &self.fee_asset_id,
            self.sponsored_units,
            self.issued_at_height,
        );
        if self.sponsorship_id != expected {
            return Err("sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalGuardrail {
    pub guardrail_id: String,
    pub withdrawal_id: String,
    pub recipient_commitment: String,
    pub amount_bucket: u64,
    pub monero_network: String,
    pub reserve_root: String,
    pub signer_set_root: String,
    pub min_mature_height: u64,
    pub max_release_units_per_microblock: u64,
    pub requires_finality_promotion: bool,
    pub risk_signal_root: String,
    pub status: WithdrawalGuardStatus,
}

impl BridgeWithdrawalGuardrail {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        withdrawal_id: &str,
        recipient_commitment: &str,
        amount_bucket: u64,
        monero_network: &str,
        reserve_root: &str,
        signer_set_root: &str,
        min_mature_height: u64,
        max_release_units_per_microblock: u64,
        requires_finality_promotion: bool,
        risk_signal_root: &str,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(withdrawal_id, "bridge withdrawal id")?;
        ensure_non_empty(recipient_commitment, "bridge withdrawal recipient")?;
        ensure_non_empty(monero_network, "bridge withdrawal network")?;
        ensure_non_empty(reserve_root, "bridge withdrawal reserve root")?;
        ensure_non_empty(signer_set_root, "bridge withdrawal signer set root")?;
        ensure_non_empty(risk_signal_root, "bridge withdrawal risk root")?;
        ensure_positive(
            max_release_units_per_microblock,
            "bridge withdrawal max release units",
        )?;
        let guardrail_id = microblock_bridge_guardrail_id(
            withdrawal_id,
            recipient_commitment,
            amount_bucket,
            monero_network,
            reserve_root,
            signer_set_root,
            min_mature_height,
        );
        Ok(Self {
            guardrail_id,
            withdrawal_id: withdrawal_id.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            amount_bucket,
            monero_network: monero_network.to_string(),
            reserve_root: reserve_root.to_string(),
            signer_set_root: signer_set_root.to_string(),
            min_mature_height,
            max_release_units_per_microblock,
            requires_finality_promotion,
            risk_signal_root: risk_signal_root.to_string(),
            status: WithdrawalGuardStatus::Pending,
        })
    }

    pub fn devnet(label: &str, height: u64) -> MicroblockPipelineResult<Self> {
        Self::new(
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-WITHDRAWAL", label),
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-WITHDRAWAL-RECIPIENT", label),
            amount_bucket(175, 25),
            MICROBLOCK_DEVNET_MONERO_NETWORK,
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-RESERVE", "bridge-reserve"),
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-SIGNERS", "bridge-signers"),
            height.saturating_add(MICROBLOCK_DEFAULT_WITHDRAWAL_GUARD_DELAY_BLOCKS),
            MICROBLOCK_DEFAULT_WITHDRAWAL_MAX_FAST_UNITS,
            true,
            &microblock_pipeline_payload_root(
                "MICROBLOCK-DEVNET-WITHDRAWAL-RISK",
                &json!({ "risk": "devnet-low", "privacy": "bucketed" }),
            ),
        )
    }

    pub fn allows_release(&self, height: u64, units: u64, finality_promoted: bool) -> bool {
        matches!(
            self.status,
            WithdrawalGuardStatus::Pending
                | WithdrawalGuardStatus::SoftLocked
                | WithdrawalGuardStatus::Eligible
        ) && height >= self.min_mature_height
            && units <= self.max_release_units_per_microblock
            && (!self.requires_finality_promotion || finality_promoted)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_withdrawal_guardrail",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "guardrail_id": self.guardrail_id,
            "withdrawal_id": self.withdrawal_id,
            "recipient_commitment": self.recipient_commitment,
            "amount_bucket": self.amount_bucket,
            "monero_network": self.monero_network,
            "reserve_root": self.reserve_root,
            "signer_set_root": self.signer_set_root,
            "min_mature_height": self.min_mature_height,
            "max_release_units_per_microblock": self.max_release_units_per_microblock,
            "requires_finality_promotion": self.requires_finality_promotion,
            "risk_signal_root": self.risk_signal_root,
            "status": self.status.as_str(),
        })
    }

    pub fn guardrail_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-BRIDGE-GUARDRAIL", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.guardrail_id, "bridge guardrail id")?;
        ensure_non_empty(&self.withdrawal_id, "bridge withdrawal id")?;
        ensure_non_empty(&self.recipient_commitment, "bridge withdrawal recipient")?;
        ensure_non_empty(&self.monero_network, "bridge withdrawal network")?;
        ensure_non_empty(&self.reserve_root, "bridge reserve root")?;
        ensure_non_empty(&self.signer_set_root, "bridge signer set root")?;
        ensure_non_empty(&self.risk_signal_root, "bridge risk root")?;
        ensure_positive(
            self.max_release_units_per_microblock,
            "bridge max release units",
        )?;
        let expected = microblock_bridge_guardrail_id(
            &self.withdrawal_id,
            &self.recipient_commitment,
            self.amount_bucket,
            &self.monero_network,
            &self.reserve_root,
            &self.signer_set_root,
            self.min_mature_height,
        );
        if self.guardrail_id != expected {
            return Err("bridge guardrail id mismatch".to_string());
        }
        Ok(self.guardrail_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyBudget {
    pub budget_id: String,
    pub lane: MicroblockLane,
    pub target_ms: u64,
    pub admission_ms: u64,
    pub sequencing_ms: u64,
    pub execution_ms: u64,
    pub attestation_ms: u64,
    pub finality_ms: u64,
    pub capacity_units: u64,
    pub used_capacity_units: u64,
    pub max_concurrent_windows: u64,
    pub measured_p50_ms: u64,
    pub measured_p95_ms: u64,
}

impl LatencyBudget {
    pub fn for_lane(lane: MicroblockLane, capacity_units: u64) -> MicroblockPipelineResult<Self> {
        ensure_positive(capacity_units, "latency budget capacity")?;
        let target_ms = lane.target_latency_ms().max(MICROBLOCK_DEFAULT_TARGET_MS);
        let admission_ms = (target_ms / 5).max(1);
        let sequencing_ms = (target_ms / 5).max(1);
        let execution_ms = (target_ms / 3).max(1);
        let attestation_ms = (target_ms / 5).max(1);
        let finality_ms = target_ms.saturating_sub(
            admission_ms
                .saturating_add(sequencing_ms)
                .saturating_add(execution_ms)
                .saturating_add(attestation_ms),
        );
        let budget_id = microblock_latency_budget_id(
            lane,
            target_ms,
            admission_ms,
            sequencing_ms,
            execution_ms,
            attestation_ms,
            finality_ms,
            capacity_units,
        );
        Ok(Self {
            budget_id,
            lane,
            target_ms,
            admission_ms,
            sequencing_ms,
            execution_ms,
            attestation_ms,
            finality_ms,
            capacity_units,
            used_capacity_units: 0,
            max_concurrent_windows: MICROBLOCK_DEFAULT_MAX_OPTIMISTIC_WINDOWS,
            measured_p50_ms: target_ms / 2,
            measured_p95_ms: target_ms,
        })
    }

    pub fn total_planned_ms(&self) -> u64 {
        self.admission_ms
            .saturating_add(self.sequencing_ms)
            .saturating_add(self.execution_ms)
            .saturating_add(self.attestation_ms)
            .saturating_add(self.finality_ms)
    }

    pub fn remaining_capacity_units(&self) -> u64 {
        self.capacity_units.saturating_sub(self.used_capacity_units)
    }

    pub fn pressure_bps(&self) -> u64 {
        ratio_bps(self.used_capacity_units, self.capacity_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "latency_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "lane": self.lane.as_str(),
            "target_ms": self.target_ms,
            "admission_ms": self.admission_ms,
            "sequencing_ms": self.sequencing_ms,
            "execution_ms": self.execution_ms,
            "attestation_ms": self.attestation_ms,
            "finality_ms": self.finality_ms,
            "total_planned_ms": self.total_planned_ms(),
            "capacity_units": self.capacity_units,
            "used_capacity_units": self.used_capacity_units,
            "remaining_capacity_units": self.remaining_capacity_units(),
            "pressure_bps": self.pressure_bps(),
            "max_concurrent_windows": self.max_concurrent_windows,
            "measured_p50_ms": self.measured_p50_ms,
            "measured_p95_ms": self.measured_p95_ms,
        })
    }

    pub fn budget_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-LATENCY-BUDGET", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.budget_id, "latency budget id")?;
        ensure_positive(self.target_ms, "latency budget target")?;
        ensure_positive(self.capacity_units, "latency budget capacity")?;
        ensure_positive(
            self.max_concurrent_windows,
            "latency budget concurrent windows",
        )?;
        if self.total_planned_ms() > self.target_ms.saturating_mul(2) {
            return Err("latency budget planned time is above tolerance".to_string());
        }
        if self.used_capacity_units > self.capacity_units {
            return Err("latency budget used capacity exceeds capacity".to_string());
        }
        let expected = microblock_latency_budget_id(
            self.lane,
            self.target_ms,
            self.admission_ms,
            self.sequencing_ms,
            self.execution_ms,
            self.attestation_ms,
            self.finality_ms,
            self.capacity_units,
        );
        if self.budget_id != expected {
            return Err("latency budget id mismatch".to_string());
        }
        Ok(self.budget_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityAccount {
    pub capacity_id: String,
    pub height: u64,
    pub microblock_sequence: u64,
    pub lane: MicroblockLane,
    pub available_fuel_units: u64,
    pub reserved_fuel_units: u64,
    pub used_fuel_units: u64,
    pub pq_auth_bytes: u64,
    pub proof_bytes: u64,
    pub da_bytes: u64,
    pub low_fee_units: u64,
    pub bridge_units: u64,
    pub capacity_signal: CapacitySignal,
}

impl CapacityAccount {
    pub fn new(
        height: u64,
        microblock_sequence: u64,
        lane: MicroblockLane,
        available_fuel_units: u64,
    ) -> MicroblockPipelineResult<Self> {
        ensure_positive(available_fuel_units, "capacity fuel units")?;
        let capacity_id =
            microblock_capacity_account_id(height, microblock_sequence, lane, available_fuel_units);
        Ok(Self {
            capacity_id,
            height,
            microblock_sequence,
            lane,
            available_fuel_units,
            reserved_fuel_units: 0,
            used_fuel_units: 0,
            pq_auth_bytes: 0,
            proof_bytes: 0,
            da_bytes: 0,
            low_fee_units: 0,
            bridge_units: 0,
            capacity_signal: CapacitySignal::Green,
        })
    }

    pub fn reserve(&mut self, fuel_units: u64) -> MicroblockPipelineResult<()> {
        if self
            .reserved_fuel_units
            .saturating_add(self.used_fuel_units)
            .saturating_add(fuel_units)
            > self.available_fuel_units
        {
            return Err("capacity reserve exceeds available fuel".to_string());
        }
        self.reserved_fuel_units = self.reserved_fuel_units.saturating_add(fuel_units);
        self.refresh_signal();
        Ok(())
    }

    pub fn consume(&mut self, fuel_units: u64) -> MicroblockPipelineResult<()> {
        if fuel_units > self.reserved_fuel_units {
            return Err("capacity consume exceeds reserved fuel".to_string());
        }
        self.reserved_fuel_units = self.reserved_fuel_units.saturating_sub(fuel_units);
        self.used_fuel_units = self.used_fuel_units.saturating_add(fuel_units);
        self.refresh_signal();
        Ok(())
    }

    pub fn pressure_bps(&self) -> u64 {
        ratio_bps(
            self.reserved_fuel_units
                .saturating_add(self.used_fuel_units),
            self.available_fuel_units,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "capacity_account",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "capacity_id": self.capacity_id,
            "height": self.height,
            "microblock_sequence": self.microblock_sequence,
            "lane": self.lane.as_str(),
            "available_fuel_units": self.available_fuel_units,
            "reserved_fuel_units": self.reserved_fuel_units,
            "used_fuel_units": self.used_fuel_units,
            "pq_auth_bytes": self.pq_auth_bytes,
            "proof_bytes": self.proof_bytes,
            "da_bytes": self.da_bytes,
            "low_fee_units": self.low_fee_units,
            "bridge_units": self.bridge_units,
            "pressure_bps": self.pressure_bps(),
            "capacity_signal": self.capacity_signal.as_str(),
        })
    }

    pub fn capacity_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-CAPACITY-ACCOUNT", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.capacity_id, "capacity id")?;
        ensure_positive(self.available_fuel_units, "capacity available fuel")?;
        if self
            .reserved_fuel_units
            .saturating_add(self.used_fuel_units)
            > self.available_fuel_units
        {
            return Err("capacity accounting exceeds available fuel".to_string());
        }
        let expected = microblock_capacity_account_id(
            self.height,
            self.microblock_sequence,
            self.lane,
            self.available_fuel_units,
        );
        if self.capacity_id != expected {
            return Err("capacity id mismatch".to_string());
        }
        Ok(self.capacity_root())
    }

    fn refresh_signal(&mut self) {
        self.capacity_signal = match self.pressure_bps() {
            0..=6_999 => CapacitySignal::Green,
            7_000..=8_999 => CapacitySignal::Saturating,
            9_000..=9_999 => CapacitySignal::Throttled,
            _ => CapacitySignal::Exhausted,
        };
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrobatchProposal {
    pub proposal_id: String,
    pub parent_microblock_id: String,
    pub proposer_id: String,
    pub height: u64,
    pub microblock_sequence: u64,
    pub lane: MicroblockLane,
    pub admission_ids: Vec<String>,
    pub admission_root: String,
    pub private_payload_root: String,
    pub ordering_root: String,
    pub low_fee_quota_root: String,
    pub bridge_guardrail_root: String,
    pub latency_budget_id: String,
    pub capacity_account_id: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub status: String,
}

impl MicrobatchProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn from_admissions(
        parent_microblock_id: &str,
        proposer_id: &str,
        height: u64,
        microblock_sequence: u64,
        lane: MicroblockLane,
        admissions: &[MempoolAdmissionCommitment],
        low_fee_quota_root: &str,
        bridge_guardrail_root: &str,
        latency_budget_id: &str,
        capacity_account_id: &str,
        created_at_ms: u64,
        ttl_ms: u64,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(parent_microblock_id, "microbatch parent id")?;
        ensure_non_empty(proposer_id, "microbatch proposer")?;
        ensure_non_empty(low_fee_quota_root, "microbatch low fee quota root")?;
        ensure_non_empty(bridge_guardrail_root, "microbatch bridge guardrail root")?;
        ensure_non_empty(latency_budget_id, "microbatch latency budget id")?;
        ensure_non_empty(capacity_account_id, "microbatch capacity account id")?;
        if admissions.is_empty() {
            return Err("microbatch proposal needs at least one admission".to_string());
        }
        let mut admission_ids = Vec::with_capacity(admissions.len());
        let mut private_payload_roots = Vec::with_capacity(admissions.len());
        let mut ordering_records = Vec::with_capacity(admissions.len());
        let mut seen = BTreeSet::new();
        for admission in admissions {
            admission.validate()?;
            if admission.lane != lane {
                return Err("microbatch proposal admission lane mismatch".to_string());
            }
            if !seen.insert(admission.admission_id.clone()) {
                return Err("microbatch proposal contains duplicate admission".to_string());
            }
            admission_ids.push(admission.admission_id.clone());
            private_payload_roots.push(admission.private_payload_root.clone());
            ordering_records.push(admission.ordering_metadata.public_record());
        }
        let admission_root = microblock_mempool_admission_root(admissions);
        let private_payload_root = microblock_private_payload_root(&private_payload_roots);
        let ordering_root = merkle_root("MICROBLOCK-ORDERING-METADATA", &ordering_records);
        let proposal_id = microbatch_proposal_id(
            parent_microblock_id,
            proposer_id,
            height,
            microblock_sequence,
            lane,
            &admission_root,
            &private_payload_root,
            &ordering_root,
        );
        Ok(Self {
            proposal_id,
            parent_microblock_id: parent_microblock_id.to_string(),
            proposer_id: proposer_id.to_string(),
            height,
            microblock_sequence,
            lane,
            admission_ids,
            admission_root,
            private_payload_root,
            ordering_root,
            low_fee_quota_root: low_fee_quota_root.to_string(),
            bridge_guardrail_root: bridge_guardrail_root.to_string(),
            latency_budget_id: latency_budget_id.to_string(),
            capacity_account_id: capacity_account_id.to_string(),
            created_at_ms,
            expires_at_ms: created_at_ms.saturating_add(ttl_ms.max(1)),
            status: MICROBLOCK_STATUS_PROPOSED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "microbatch_proposal",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "proposal_id": self.proposal_id,
            "parent_microblock_id": self.parent_microblock_id,
            "proposer_id": self.proposer_id,
            "height": self.height,
            "microblock_sequence": self.microblock_sequence,
            "lane": self.lane.as_str(),
            "admission_count": self.admission_ids.len() as u64,
            "admission_root": self.admission_root,
            "private_payload_root": self.private_payload_root,
            "payload_visibility": MICROBLOCK_PIPELINE_PRIVATE_VISIBILITY,
            "ordering_root": self.ordering_root,
            "low_fee_quota_root": self.low_fee_quota_root,
            "bridge_guardrail_root": self.bridge_guardrail_root,
            "latency_budget_id": self.latency_budget_id,
            "capacity_account_id": self.capacity_account_id,
            "created_at_ms": self.created_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "status": self.status,
        })
    }

    pub fn proposal_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-PROPOSAL", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.proposal_id, "microbatch proposal id")?;
        ensure_non_empty(&self.parent_microblock_id, "microbatch parent id")?;
        ensure_non_empty(&self.proposer_id, "microbatch proposer")?;
        ensure_non_empty(&self.admission_root, "microbatch admission root")?;
        ensure_non_empty(
            &self.private_payload_root,
            "microbatch private payload root",
        )?;
        ensure_non_empty(&self.ordering_root, "microbatch ordering root")?;
        ensure_non_empty(&self.low_fee_quota_root, "microbatch low fee quota root")?;
        ensure_non_empty(
            &self.bridge_guardrail_root,
            "microbatch bridge guardrail root",
        )?;
        ensure_non_empty(&self.latency_budget_id, "microbatch latency budget id")?;
        ensure_non_empty(&self.capacity_account_id, "microbatch capacity account id")?;
        if self.admission_ids.is_empty() {
            return Err("microbatch proposal has no admissions".to_string());
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err("microbatch proposal expires before creation".to_string());
        }
        let mut seen = BTreeSet::new();
        for admission_id in &self.admission_ids {
            ensure_non_empty(admission_id, "microbatch admission id")?;
            if !seen.insert(admission_id.clone()) {
                return Err("microbatch proposal has duplicate admission id".to_string());
            }
        }
        let expected = microbatch_proposal_id(
            &self.parent_microblock_id,
            &self.proposer_id,
            self.height,
            self.microblock_sequence,
            self.lane,
            &self.admission_root,
            &self.private_payload_root,
            &self.ordering_root,
        );
        if self.proposal_id != expected {
            return Err("microbatch proposal id mismatch".to_string());
        }
        Ok(self.proposal_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicReplayCommitment {
    pub replay_id: String,
    pub proposal_id: String,
    pub execution_engine: String,
    pub vm_config_root: String,
    pub ordered_admission_root: String,
    pub input_state_root: String,
    pub expected_output_root: String,
    pub deterministic_seed_root: String,
    pub transcript_root: String,
    pub max_fuel_units: u64,
    pub created_at_height: u64,
}

impl DeterministicReplayCommitment {
    pub fn for_proposal(
        proposal: &MicrobatchProposal,
        input_state_root: &str,
        expected_output_root: &str,
        max_fuel_units: u64,
    ) -> MicroblockPipelineResult<Self> {
        proposal.validate()?;
        ensure_non_empty(input_state_root, "replay input state root")?;
        ensure_non_empty(expected_output_root, "replay expected output root")?;
        ensure_positive(max_fuel_units, "replay max fuel")?;
        let vm_config_root = microblock_pipeline_payload_root(
            "MICROBLOCK-REPLAY-VM-CONFIG",
            &json!({
                "engine": MICROBLOCK_PIPELINE_REPLAY_ENGINE,
                "pq_signature_scheme": MICROBLOCK_PIPELINE_PQ_SIGNATURE_SCHEME,
                "transcript_hash": MICROBLOCK_PIPELINE_TRANSCRIPT_HASH,
                "payload_policy": MICROBLOCK_PIPELINE_PRIVATE_VISIBILITY,
            }),
        );
        let deterministic_seed_root = microblock_pipeline_payload_root(
            "MICROBLOCK-REPLAY-SEED",
            &json!({
                "proposal_id": proposal.proposal_id,
                "height": proposal.height,
                "microblock_sequence": proposal.microblock_sequence,
                "ordering_root": proposal.ordering_root,
            }),
        );
        let transcript_root = microblock_pipeline_payload_root(
            "MICROBLOCK-REPLAY-TRANSCRIPT",
            &json!({
                "proposal_root": proposal.proposal_root(),
                "input_state_root": input_state_root,
                "expected_output_root": expected_output_root,
                "seed_root": deterministic_seed_root,
            }),
        );
        let replay_id = deterministic_replay_commitment_id(
            &proposal.proposal_id,
            MICROBLOCK_PIPELINE_REPLAY_ENGINE,
            &vm_config_root,
            &proposal.admission_root,
            input_state_root,
            expected_output_root,
            &deterministic_seed_root,
            max_fuel_units,
        );
        Ok(Self {
            replay_id,
            proposal_id: proposal.proposal_id.clone(),
            execution_engine: MICROBLOCK_PIPELINE_REPLAY_ENGINE.to_string(),
            vm_config_root,
            ordered_admission_root: proposal.admission_root.clone(),
            input_state_root: input_state_root.to_string(),
            expected_output_root: expected_output_root.to_string(),
            deterministic_seed_root,
            transcript_root,
            max_fuel_units,
            created_at_height: proposal.height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deterministic_replay_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "replay_id": self.replay_id,
            "proposal_id": self.proposal_id,
            "execution_engine": self.execution_engine,
            "vm_config_root": self.vm_config_root,
            "ordered_admission_root": self.ordered_admission_root,
            "input_state_root": self.input_state_root,
            "expected_output_root": self.expected_output_root,
            "deterministic_seed_root": self.deterministic_seed_root,
            "transcript_root": self.transcript_root,
            "max_fuel_units": self.max_fuel_units,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn replay_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-REPLAY-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.replay_id, "replay id")?;
        ensure_non_empty(&self.proposal_id, "replay proposal id")?;
        ensure_non_empty(&self.execution_engine, "replay execution engine")?;
        ensure_non_empty(&self.vm_config_root, "replay vm config root")?;
        ensure_non_empty(
            &self.ordered_admission_root,
            "replay ordered admission root",
        )?;
        ensure_non_empty(&self.input_state_root, "replay input state root")?;
        ensure_non_empty(&self.expected_output_root, "replay expected output root")?;
        ensure_non_empty(&self.deterministic_seed_root, "replay seed root")?;
        ensure_non_empty(&self.transcript_root, "replay transcript root")?;
        ensure_positive(self.max_fuel_units, "replay max fuel")?;
        let expected = deterministic_replay_commitment_id(
            &self.proposal_id,
            &self.execution_engine,
            &self.vm_config_root,
            &self.ordered_admission_root,
            &self.input_state_root,
            &self.expected_output_root,
            &self.deterministic_seed_root,
            self.max_fuel_units,
        );
        if self.replay_id != expected {
            return Err("replay commitment id mismatch".to_string());
        }
        Ok(self.replay_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimisticExecutionWindow {
    pub window_id: String,
    pub proposal_id: String,
    pub replay_id: String,
    pub base_state_root: String,
    pub optimistic_state_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub fuel_budget_units: u64,
    pub capacity_cost_units: u64,
    pub status: OptimisticWindowStatus,
}

impl OptimisticExecutionWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        proposal: &MicrobatchProposal,
        replay: &DeterministicReplayCommitment,
        read_set_root: &str,
        write_set_root: &str,
        fuel_budget_units: u64,
        capacity_cost_units: u64,
        ttl_microblocks: u64,
    ) -> MicroblockPipelineResult<Self> {
        proposal.validate()?;
        replay.validate()?;
        ensure_non_empty(read_set_root, "optimistic read set root")?;
        ensure_non_empty(write_set_root, "optimistic write set root")?;
        ensure_positive(fuel_budget_units, "optimistic fuel budget")?;
        ensure_positive(capacity_cost_units, "optimistic capacity cost")?;
        if replay.proposal_id != proposal.proposal_id {
            return Err("optimistic window replay proposal mismatch".to_string());
        }
        let optimistic_state_root = replay.expected_output_root.clone();
        let window_id = optimistic_execution_window_id(
            &proposal.proposal_id,
            &replay.replay_id,
            &replay.input_state_root,
            &optimistic_state_root,
            read_set_root,
            write_set_root,
            proposal.height,
        );
        Ok(Self {
            window_id,
            proposal_id: proposal.proposal_id.clone(),
            replay_id: replay.replay_id.clone(),
            base_state_root: replay.input_state_root.clone(),
            optimistic_state_root,
            read_set_root: read_set_root.to_string(),
            write_set_root: write_set_root.to_string(),
            opened_at_height: proposal.height,
            expires_at_height: proposal.height.saturating_add(ttl_microblocks.max(1)),
            fuel_budget_units,
            capacity_cost_units,
            status: OptimisticWindowStatus::Open,
        })
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.status == OptimisticWindowStatus::Open
            && height >= self.opened_at_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "optimistic_execution_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "proposal_id": self.proposal_id,
            "replay_id": self.replay_id,
            "base_state_root": self.base_state_root,
            "optimistic_state_root": self.optimistic_state_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "fuel_budget_units": self.fuel_budget_units,
            "capacity_cost_units": self.capacity_cost_units,
            "status": self.status.as_str(),
        })
    }

    pub fn window_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-OPTIMISTIC-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.window_id, "optimistic window id")?;
        ensure_non_empty(&self.proposal_id, "optimistic proposal id")?;
        ensure_non_empty(&self.replay_id, "optimistic replay id")?;
        ensure_non_empty(&self.base_state_root, "optimistic base root")?;
        ensure_non_empty(&self.optimistic_state_root, "optimistic state root")?;
        ensure_non_empty(&self.read_set_root, "optimistic read set root")?;
        ensure_non_empty(&self.write_set_root, "optimistic write set root")?;
        ensure_positive(self.fuel_budget_units, "optimistic fuel budget")?;
        ensure_positive(self.capacity_cost_units, "optimistic capacity cost")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("optimistic window expiry must be after open height".to_string());
        }
        let expected = optimistic_execution_window_id(
            &self.proposal_id,
            &self.replay_id,
            &self.base_state_root,
            &self.optimistic_state_root,
            &self.read_set_root,
            &self.write_set_root,
            self.opened_at_height,
        );
        if self.window_id != expected {
            return Err("optimistic window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMicroblockAttestation {
    pub attestation_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub signer_id: String,
    pub role: AttestationRole,
    pub public_key_root: String,
    pub signature_scheme: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub weight_bps: u64,
    pub attested_at_height: u64,
    pub attested_at_microblock: u64,
}

impl PqMicroblockAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        signer_id: &str,
        role: AttestationRole,
        public_key_root: &str,
        weight_bps: u64,
        attested_at_height: u64,
        attested_at_microblock: u64,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(subject_kind, "attestation subject kind")?;
        ensure_non_empty(subject_id, "attestation subject id")?;
        ensure_non_empty(subject_root, "attestation subject root")?;
        ensure_non_empty(signer_id, "attestation signer id")?;
        ensure_non_empty(public_key_root, "attestation public key root")?;
        ensure_bps(weight_bps, "attestation weight")?;
        let signature_scheme = if role == AttestationRole::CommitteeMember {
            MICROBLOCK_PIPELINE_PQ_COMMITTEE_SCHEME
        } else {
            MICROBLOCK_PIPELINE_PQ_SIGNATURE_SCHEME
        }
        .to_string();
        let transcript_root = microblock_pipeline_payload_root(
            "MICROBLOCK-PQ-ATTESTATION-TRANSCRIPT",
            &json!({
                "subject_kind": subject_kind,
                "subject_id": subject_id,
                "subject_root": subject_root,
                "signer_id": signer_id,
                "role": role.as_str(),
                "public_key_root": public_key_root,
                "signature_scheme": signature_scheme,
                "height": attested_at_height,
                "microblock_sequence": attested_at_microblock,
            }),
        );
        let signature_root = microblock_pq_signature_root(
            signer_id,
            public_key_root,
            &signature_scheme,
            &transcript_root,
        );
        let attestation_id = microblock_pq_attestation_id(
            subject_kind,
            subject_id,
            signer_id,
            role,
            public_key_root,
            &transcript_root,
            weight_bps,
            attested_at_height,
            attested_at_microblock,
        );
        Ok(Self {
            attestation_id,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            signer_id: signer_id.to_string(),
            role,
            public_key_root: public_key_root.to_string(),
            signature_scheme,
            transcript_root,
            signature_root,
            weight_bps,
            attested_at_height,
            attested_at_microblock,
        })
    }

    pub fn devnet_for_subject(
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        role: AttestationRole,
        height: u64,
        microblock_sequence: u64,
    ) -> MicroblockPipelineResult<Self> {
        let signer_id = match role {
            AttestationRole::Sequencer => MICROBLOCK_DEVNET_SEQUENCER_ID,
            AttestationRole::CommitteeMember => MICROBLOCK_DEVNET_COMMITTEE_ID,
            AttestationRole::BridgeGuardian => "devnet-bridge-guardian",
            AttestationRole::Watchtower => "devnet-watchtower",
            AttestationRole::ReplayExecutor => "devnet-replay-executor",
        };
        Self::new(
            subject_kind,
            subject_id,
            subject_root,
            signer_id,
            role,
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-PQ-KEY", signer_id),
            if role == AttestationRole::CommitteeMember {
                MICROBLOCK_DEFAULT_COMMITTEE_QUORUM_BPS
            } else {
                10_000
            },
            height,
            microblock_sequence,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_microblock_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "signer_id": self.signer_id,
            "role": self.role.as_str(),
            "public_key_root": self.public_key_root,
            "signature_scheme": self.signature_scheme,
            "transcript_hash": MICROBLOCK_PIPELINE_TRANSCRIPT_HASH,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "weight_bps": self.weight_bps,
            "attested_at_height": self.attested_at_height,
            "attested_at_microblock": self.attested_at_microblock,
        })
    }

    pub fn attestation_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-PQ-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.attestation_id, "attestation id")?;
        ensure_non_empty(&self.subject_kind, "attestation subject kind")?;
        ensure_non_empty(&self.subject_id, "attestation subject id")?;
        ensure_non_empty(&self.signer_id, "attestation signer")?;
        ensure_non_empty(&self.public_key_root, "attestation public key")?;
        ensure_non_empty(&self.signature_scheme, "attestation signature scheme")?;
        ensure_non_empty(&self.transcript_root, "attestation transcript root")?;
        ensure_non_empty(&self.signature_root, "attestation signature root")?;
        ensure_bps(self.weight_bps, "attestation weight")?;
        let expected_signature = microblock_pq_signature_root(
            &self.signer_id,
            &self.public_key_root,
            &self.signature_scheme,
            &self.transcript_root,
        );
        if self.signature_root != expected_signature {
            return Err("attestation signature root mismatch".to_string());
        }
        let expected = microblock_pq_attestation_id(
            &self.subject_kind,
            &self.subject_id,
            &self.signer_id,
            self.role,
            &self.public_key_root,
            &self.transcript_root,
            self.weight_bps,
            self.attested_at_height,
            self.attested_at_microblock,
        );
        if self.attestation_id != expected {
            return Err("attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroblockRecord {
    pub microblock_id: String,
    pub proposal_id: String,
    pub parent_microblock_id: String,
    pub height: u64,
    pub microblock_sequence: u64,
    pub lane: MicroblockLane,
    pub admission_root: String,
    pub private_payload_root: String,
    pub execution_window_root: String,
    pub preconfirmation_receipt_root: String,
    pub finality_promotion_root: String,
    pub conflict_certificate_root: String,
    pub rollback_envelope_root: String,
    pub pq_attestation_root: String,
    pub capacity_account_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub timestamp_ms: u64,
    pub status: String,
}

impl MicroblockRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn from_proposal(
        proposal: &MicrobatchProposal,
        execution_window: &OptimisticExecutionWindow,
        receipts: &[PreconfirmationReceipt],
        attestations: &[PqMicroblockAttestation],
        capacity: &CapacityAccount,
        state_root_before: &str,
        state_root_after: &str,
        timestamp_ms: u64,
    ) -> MicroblockPipelineResult<Self> {
        proposal.validate()?;
        execution_window.validate()?;
        capacity.validate()?;
        ensure_non_empty(state_root_before, "microblock state root before")?;
        ensure_non_empty(state_root_after, "microblock state root after")?;
        if execution_window.proposal_id != proposal.proposal_id {
            return Err("microblock execution window proposal mismatch".to_string());
        }
        if capacity.capacity_id != proposal.capacity_account_id {
            return Err("microblock capacity account mismatch".to_string());
        }
        for receipt in receipts {
            receipt.validate()?;
        }
        for attestation in attestations {
            attestation.validate()?;
        }
        let execution_window_root = execution_window.window_root();
        let preconfirmation_receipt_root = microblock_preconfirmation_receipt_root(receipts);
        let pq_attestation_root = microblock_pq_attestation_root(attestations);
        let capacity_account_root = capacity.capacity_root();
        let finality_promotion_root = microblock_empty_root("MICROBLOCK-FINALITY-PROMOTION");
        let conflict_certificate_root = microblock_empty_root("MICROBLOCK-CONFLICT-CERTIFICATE");
        let rollback_envelope_root = microblock_empty_root("MICROBLOCK-ROLLBACK-ENVELOPE");
        let microblock_id = microblock_record_id(
            &proposal.parent_microblock_id,
            &proposal.proposal_id,
            proposal.height,
            proposal.microblock_sequence,
            proposal.lane,
            &proposal.admission_root,
            &proposal.private_payload_root,
            &execution_window_root,
            state_root_before,
            state_root_after,
        );
        Ok(Self {
            microblock_id,
            proposal_id: proposal.proposal_id.clone(),
            parent_microblock_id: proposal.parent_microblock_id.clone(),
            height: proposal.height,
            microblock_sequence: proposal.microblock_sequence,
            lane: proposal.lane,
            admission_root: proposal.admission_root.clone(),
            private_payload_root: proposal.private_payload_root.clone(),
            execution_window_root,
            preconfirmation_receipt_root,
            finality_promotion_root,
            conflict_certificate_root,
            rollback_envelope_root,
            pq_attestation_root,
            capacity_account_root,
            state_root_before: state_root_before.to_string(),
            state_root_after: state_root_after.to_string(),
            timestamp_ms,
            status: MICROBLOCK_STATUS_PRECONFIRMED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "microblock_record",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "microblock_id": self.microblock_id,
            "proposal_id": self.proposal_id,
            "parent_microblock_id": self.parent_microblock_id,
            "height": self.height,
            "microblock_sequence": self.microblock_sequence,
            "lane": self.lane.as_str(),
            "admission_root": self.admission_root,
            "private_payload_root": self.private_payload_root,
            "payload_visibility": MICROBLOCK_PIPELINE_PRIVATE_VISIBILITY,
            "execution_window_root": self.execution_window_root,
            "preconfirmation_receipt_root": self.preconfirmation_receipt_root,
            "finality_promotion_root": self.finality_promotion_root,
            "conflict_certificate_root": self.conflict_certificate_root,
            "rollback_envelope_root": self.rollback_envelope_root,
            "pq_attestation_root": self.pq_attestation_root,
            "capacity_account_root": self.capacity_account_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "timestamp_ms": self.timestamp_ms,
            "status": self.status,
        })
    }

    pub fn microblock_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.microblock_id, "microblock id")?;
        ensure_non_empty(&self.proposal_id, "microblock proposal id")?;
        ensure_non_empty(&self.parent_microblock_id, "microblock parent id")?;
        ensure_non_empty(&self.admission_root, "microblock admission root")?;
        ensure_non_empty(
            &self.private_payload_root,
            "microblock private payload root",
        )?;
        ensure_non_empty(
            &self.execution_window_root,
            "microblock execution window root",
        )?;
        ensure_non_empty(
            &self.preconfirmation_receipt_root,
            "microblock receipt root",
        )?;
        ensure_non_empty(&self.finality_promotion_root, "microblock finality root")?;
        ensure_non_empty(&self.conflict_certificate_root, "microblock conflict root")?;
        ensure_non_empty(&self.rollback_envelope_root, "microblock rollback root")?;
        ensure_non_empty(&self.pq_attestation_root, "microblock attestation root")?;
        ensure_non_empty(&self.capacity_account_root, "microblock capacity root")?;
        ensure_non_empty(&self.state_root_before, "microblock state root before")?;
        ensure_non_empty(&self.state_root_after, "microblock state root after")?;
        let expected = microblock_record_id(
            &self.parent_microblock_id,
            &self.proposal_id,
            self.height,
            self.microblock_sequence,
            self.lane,
            &self.admission_root,
            &self.private_payload_root,
            &self.execution_window_root,
            &self.state_root_before,
            &self.state_root_after,
        );
        if self.microblock_id != expected {
            return Err("microblock id mismatch".to_string());
        }
        Ok(self.microblock_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub admission_id: String,
    pub proposal_id: String,
    pub microblock_id: String,
    pub promised_state_root: String,
    pub replay_id: String,
    pub receipt_status: PreconfirmationReceiptStatus,
    pub issued_at_height: u64,
    pub issued_at_microblock: u64,
    pub expires_at_height: u64,
    pub latency_ms: u64,
    pub sequencer_attestation_root: String,
}

impl PreconfirmationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_id: &str,
        proposal_id: &str,
        microblock_id: &str,
        promised_state_root: &str,
        replay_id: &str,
        issued_at_height: u64,
        issued_at_microblock: u64,
        ttl_microblocks: u64,
        latency_ms: u64,
        sequencer_attestation_root: &str,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(admission_id, "preconfirmation admission id")?;
        ensure_non_empty(proposal_id, "preconfirmation proposal id")?;
        ensure_non_empty(microblock_id, "preconfirmation microblock id")?;
        ensure_non_empty(promised_state_root, "preconfirmation promised state root")?;
        ensure_non_empty(replay_id, "preconfirmation replay id")?;
        ensure_non_empty(
            sequencer_attestation_root,
            "preconfirmation sequencer attestation root",
        )?;
        let expires_at_height = issued_at_height.saturating_add(ttl_microblocks.max(1));
        let receipt_id = preconfirmation_receipt_id(
            admission_id,
            proposal_id,
            microblock_id,
            promised_state_root,
            replay_id,
            issued_at_height,
            issued_at_microblock,
        );
        Ok(Self {
            receipt_id,
            admission_id: admission_id.to_string(),
            proposal_id: proposal_id.to_string(),
            microblock_id: microblock_id.to_string(),
            promised_state_root: promised_state_root.to_string(),
            replay_id: replay_id.to_string(),
            receipt_status: PreconfirmationReceiptStatus::Preconfirmed,
            issued_at_height,
            issued_at_microblock,
            expires_at_height,
            latency_ms,
            sequencer_attestation_root: sequencer_attestation_root.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "preconfirmation_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "admission_id": self.admission_id,
            "proposal_id": self.proposal_id,
            "microblock_id": self.microblock_id,
            "promised_state_root": self.promised_state_root,
            "replay_id": self.replay_id,
            "receipt_status": self.receipt_status.as_str(),
            "issued_at_height": self.issued_at_height,
            "issued_at_microblock": self.issued_at_microblock,
            "expires_at_height": self.expires_at_height,
            "latency_ms": self.latency_ms,
            "sequencer_attestation_root": self.sequencer_attestation_root,
        })
    }

    pub fn receipt_root(&self) -> String {
        microblock_pipeline_payload_root(
            "MICROBLOCK-PRECONFIRMATION-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.receipt_id, "preconfirmation receipt id")?;
        ensure_non_empty(&self.admission_id, "preconfirmation admission id")?;
        ensure_non_empty(&self.proposal_id, "preconfirmation proposal id")?;
        ensure_non_empty(&self.microblock_id, "preconfirmation microblock id")?;
        ensure_non_empty(&self.promised_state_root, "preconfirmation state root")?;
        ensure_non_empty(&self.replay_id, "preconfirmation replay id")?;
        ensure_non_empty(
            &self.sequencer_attestation_root,
            "preconfirmation attestation root",
        )?;
        if self.expires_at_height <= self.issued_at_height {
            return Err("preconfirmation receipt expires before issue height".to_string());
        }
        let expected = preconfirmation_receipt_id(
            &self.admission_id,
            &self.proposal_id,
            &self.microblock_id,
            &self.promised_state_root,
            &self.replay_id,
            self.issued_at_height,
            self.issued_at_microblock,
        );
        if self.receipt_id != expected {
            return Err("preconfirmation receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityPromotion {
    pub promotion_id: String,
    pub microblock_id: String,
    pub preconfirmation_receipt_root: String,
    pub final_state_root: String,
    pub settlement_anchor_root: String,
    pub committee_attestation_root: String,
    pub promoted_at_height: u64,
    pub promoted_at_microblock: u64,
    pub status: FinalityPromotionStatus,
}

impl FinalityPromotion {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        microblock_id: &str,
        preconfirmation_receipt_root: &str,
        final_state_root: &str,
        settlement_anchor_root: &str,
        committee_attestation_root: &str,
        promoted_at_height: u64,
        promoted_at_microblock: u64,
        status: FinalityPromotionStatus,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(microblock_id, "finality microblock id")?;
        ensure_non_empty(
            preconfirmation_receipt_root,
            "finality preconfirmation receipt root",
        )?;
        ensure_non_empty(final_state_root, "finality state root")?;
        ensure_non_empty(settlement_anchor_root, "finality settlement anchor")?;
        ensure_non_empty(committee_attestation_root, "finality committee attestation")?;
        let promotion_id = finality_promotion_id(
            microblock_id,
            preconfirmation_receipt_root,
            final_state_root,
            settlement_anchor_root,
            committee_attestation_root,
            promoted_at_height,
            promoted_at_microblock,
        );
        Ok(Self {
            promotion_id,
            microblock_id: microblock_id.to_string(),
            preconfirmation_receipt_root: preconfirmation_receipt_root.to_string(),
            final_state_root: final_state_root.to_string(),
            settlement_anchor_root: settlement_anchor_root.to_string(),
            committee_attestation_root: committee_attestation_root.to_string(),
            promoted_at_height,
            promoted_at_microblock,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "finality_promotion",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "promotion_id": self.promotion_id,
            "microblock_id": self.microblock_id,
            "preconfirmation_receipt_root": self.preconfirmation_receipt_root,
            "final_state_root": self.final_state_root,
            "settlement_anchor_root": self.settlement_anchor_root,
            "committee_attestation_root": self.committee_attestation_root,
            "promoted_at_height": self.promoted_at_height,
            "promoted_at_microblock": self.promoted_at_microblock,
            "status": self.status.as_str(),
        })
    }

    pub fn promotion_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-FINALITY-PROMOTION", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.promotion_id, "finality promotion id")?;
        ensure_non_empty(&self.microblock_id, "finality microblock id")?;
        ensure_non_empty(&self.preconfirmation_receipt_root, "finality receipt root")?;
        ensure_non_empty(&self.final_state_root, "finality state root")?;
        ensure_non_empty(&self.settlement_anchor_root, "finality settlement anchor")?;
        ensure_non_empty(
            &self.committee_attestation_root,
            "finality committee attestation",
        )?;
        let expected = finality_promotion_id(
            &self.microblock_id,
            &self.preconfirmation_receipt_root,
            &self.final_state_root,
            &self.settlement_anchor_root,
            &self.committee_attestation_root,
            self.promoted_at_height,
            self.promoted_at_microblock,
        );
        if self.promotion_id != expected {
            return Err("finality promotion id mismatch".to_string());
        }
        Ok(self.promotion_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictCertificate {
    pub certificate_id: String,
    pub conflict_kind: ConflictKind,
    pub left_microblock_id: String,
    pub right_microblock_id: String,
    pub left_commitment_root: String,
    pub right_commitment_root: String,
    pub conflicting_resource_root: String,
    pub evidence_root: String,
    pub reporter_id: String,
    pub detected_at_height: u64,
    pub slash_bps: u64,
}

impl ConflictCertificate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conflict_kind: ConflictKind,
        left_microblock_id: &str,
        right_microblock_id: &str,
        left_commitment_root: &str,
        right_commitment_root: &str,
        conflicting_resource_root: &str,
        evidence_root: &str,
        reporter_id: &str,
        detected_at_height: u64,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(left_microblock_id, "conflict left microblock")?;
        ensure_non_empty(right_microblock_id, "conflict right microblock")?;
        ensure_non_empty(left_commitment_root, "conflict left root")?;
        ensure_non_empty(right_commitment_root, "conflict right root")?;
        ensure_non_empty(conflicting_resource_root, "conflict resource root")?;
        ensure_non_empty(evidence_root, "conflict evidence root")?;
        ensure_non_empty(reporter_id, "conflict reporter")?;
        if left_microblock_id == right_microblock_id {
            return Err("conflict certificate needs two distinct microblocks".to_string());
        }
        let slash_bps = conflict_kind.slash_bps();
        let certificate_id = conflict_certificate_id(
            conflict_kind,
            left_microblock_id,
            right_microblock_id,
            left_commitment_root,
            right_commitment_root,
            conflicting_resource_root,
            evidence_root,
            detected_at_height,
        );
        Ok(Self {
            certificate_id,
            conflict_kind,
            left_microblock_id: left_microblock_id.to_string(),
            right_microblock_id: right_microblock_id.to_string(),
            left_commitment_root: left_commitment_root.to_string(),
            right_commitment_root: right_commitment_root.to_string(),
            conflicting_resource_root: conflicting_resource_root.to_string(),
            evidence_root: evidence_root.to_string(),
            reporter_id: reporter_id.to_string(),
            detected_at_height,
            slash_bps,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "conflict_certificate",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "certificate_id": self.certificate_id,
            "conflict_kind": self.conflict_kind.as_str(),
            "left_microblock_id": self.left_microblock_id,
            "right_microblock_id": self.right_microblock_id,
            "left_commitment_root": self.left_commitment_root,
            "right_commitment_root": self.right_commitment_root,
            "conflicting_resource_root": self.conflicting_resource_root,
            "evidence_root": self.evidence_root,
            "reporter_id": self.reporter_id,
            "detected_at_height": self.detected_at_height,
            "slash_bps": self.slash_bps,
        })
    }

    pub fn certificate_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-CONFLICT-CERTIFICATE", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.certificate_id, "conflict certificate id")?;
        ensure_non_empty(&self.left_microblock_id, "conflict left microblock")?;
        ensure_non_empty(&self.right_microblock_id, "conflict right microblock")?;
        ensure_non_empty(&self.left_commitment_root, "conflict left root")?;
        ensure_non_empty(&self.right_commitment_root, "conflict right root")?;
        ensure_non_empty(&self.conflicting_resource_root, "conflict resource")?;
        ensure_non_empty(&self.evidence_root, "conflict evidence")?;
        ensure_non_empty(&self.reporter_id, "conflict reporter")?;
        ensure_bps(self.slash_bps, "conflict slash")?;
        if self.left_microblock_id == self.right_microblock_id {
            return Err("conflict certificate has identical microblock ids".to_string());
        }
        let expected = conflict_certificate_id(
            self.conflict_kind,
            &self.left_microblock_id,
            &self.right_microblock_id,
            &self.left_commitment_root,
            &self.right_commitment_root,
            &self.conflicting_resource_root,
            &self.evidence_root,
            self.detected_at_height,
        );
        if self.certificate_id != expected {
            return Err("conflict certificate id mismatch".to_string());
        }
        Ok(self.certificate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackEnvelope {
    pub rollback_id: String,
    pub certificate_id: String,
    pub from_microblock_id: String,
    pub to_parent_microblock_id: String,
    pub reverted_window_root: String,
    pub receipt_root: String,
    pub compensation_root: String,
    pub replay_checkpoint_root: String,
    pub reason: RollbackReason,
    pub issued_at_height: u64,
    pub issued_at_microblock: u64,
    pub status: String,
}

impl RollbackEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificate_id: &str,
        from_microblock_id: &str,
        to_parent_microblock_id: &str,
        reverted_window_root: &str,
        receipt_root: &str,
        compensation_root: &str,
        replay_checkpoint_root: &str,
        reason: RollbackReason,
        issued_at_height: u64,
        issued_at_microblock: u64,
    ) -> MicroblockPipelineResult<Self> {
        ensure_non_empty(certificate_id, "rollback certificate id")?;
        ensure_non_empty(from_microblock_id, "rollback source microblock")?;
        ensure_non_empty(to_parent_microblock_id, "rollback parent microblock")?;
        ensure_non_empty(reverted_window_root, "rollback window root")?;
        ensure_non_empty(receipt_root, "rollback receipt root")?;
        ensure_non_empty(compensation_root, "rollback compensation root")?;
        ensure_non_empty(replay_checkpoint_root, "rollback replay checkpoint")?;
        let rollback_id = rollback_envelope_id(
            certificate_id,
            from_microblock_id,
            to_parent_microblock_id,
            reverted_window_root,
            receipt_root,
            compensation_root,
            replay_checkpoint_root,
            reason,
            issued_at_height,
            issued_at_microblock,
        );
        Ok(Self {
            rollback_id,
            certificate_id: certificate_id.to_string(),
            from_microblock_id: from_microblock_id.to_string(),
            to_parent_microblock_id: to_parent_microblock_id.to_string(),
            reverted_window_root: reverted_window_root.to_string(),
            receipt_root: receipt_root.to_string(),
            compensation_root: compensation_root.to_string(),
            replay_checkpoint_root: replay_checkpoint_root.to_string(),
            reason,
            issued_at_height,
            issued_at_microblock,
            status: MICROBLOCK_STATUS_ROLLED_BACK.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollback_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "rollback_id": self.rollback_id,
            "certificate_id": self.certificate_id,
            "from_microblock_id": self.from_microblock_id,
            "to_parent_microblock_id": self.to_parent_microblock_id,
            "reverted_window_root": self.reverted_window_root,
            "receipt_root": self.receipt_root,
            "compensation_root": self.compensation_root,
            "replay_checkpoint_root": self.replay_checkpoint_root,
            "reason": self.reason.as_str(),
            "issued_at_height": self.issued_at_height,
            "issued_at_microblock": self.issued_at_microblock,
            "status": self.status,
        })
    }

    pub fn rollback_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-ROLLBACK-ENVELOPE", &self.public_record())
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        ensure_non_empty(&self.rollback_id, "rollback id")?;
        ensure_non_empty(&self.certificate_id, "rollback certificate id")?;
        ensure_non_empty(&self.from_microblock_id, "rollback source microblock")?;
        ensure_non_empty(&self.to_parent_microblock_id, "rollback parent microblock")?;
        ensure_non_empty(&self.reverted_window_root, "rollback window root")?;
        ensure_non_empty(&self.receipt_root, "rollback receipt root")?;
        ensure_non_empty(&self.compensation_root, "rollback compensation root")?;
        ensure_non_empty(&self.replay_checkpoint_root, "rollback checkpoint root")?;
        let expected = rollback_envelope_id(
            &self.certificate_id,
            &self.from_microblock_id,
            &self.to_parent_microblock_id,
            &self.reverted_window_root,
            &self.receipt_root,
            &self.compensation_root,
            &self.replay_checkpoint_root,
            self.reason,
            self.issued_at_height,
            self.issued_at_microblock,
        );
        if self.rollback_id != expected {
            return Err("rollback envelope id mismatch".to_string());
        }
        Ok(self.rollback_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroblockPipelineRoots {
    pub config_root: String,
    pub admission_root: String,
    pub proposal_root: String,
    pub replay_root: String,
    pub optimistic_window_root: String,
    pub receipt_root: String,
    pub finality_promotion_root: String,
    pub conflict_certificate_root: String,
    pub rollback_envelope_root: String,
    pub low_fee_quota_root: String,
    pub sponsorship_root: String,
    pub bridge_guardrail_root: String,
    pub pq_attestation_root: String,
    pub latency_budget_root: String,
    pub capacity_account_root: String,
    pub microblock_root: String,
}

impl MicroblockPipelineRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "microblock_pipeline_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "admission_root": self.admission_root,
            "proposal_root": self.proposal_root,
            "replay_root": self.replay_root,
            "optimistic_window_root": self.optimistic_window_root,
            "receipt_root": self.receipt_root,
            "finality_promotion_root": self.finality_promotion_root,
            "conflict_certificate_root": self.conflict_certificate_root,
            "rollback_envelope_root": self.rollback_envelope_root,
            "low_fee_quota_root": self.low_fee_quota_root,
            "sponsorship_root": self.sponsorship_root,
            "bridge_guardrail_root": self.bridge_guardrail_root,
            "pq_attestation_root": self.pq_attestation_root,
            "latency_budget_root": self.latency_budget_root,
            "capacity_account_root": self.capacity_account_root,
            "microblock_root": self.microblock_root,
        })
    }

    pub fn roots_root(&self) -> String {
        microblock_pipeline_payload_root("MICROBLOCK-PIPELINE-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroblockPipelineState {
    pub height: u64,
    pub current_microblock_sequence: u64,
    pub config: MicroblockPipelineConfig,
    pub admissions: BTreeMap<String, MempoolAdmissionCommitment>,
    pub proposals: BTreeMap<String, MicrobatchProposal>,
    pub replay_commitments: BTreeMap<String, DeterministicReplayCommitment>,
    pub optimistic_windows: BTreeMap<String, OptimisticExecutionWindow>,
    pub preconfirmation_receipts: BTreeMap<String, PreconfirmationReceipt>,
    pub finality_promotions: BTreeMap<String, FinalityPromotion>,
    pub conflict_certificates: BTreeMap<String, ConflictCertificate>,
    pub rollback_envelopes: BTreeMap<String, RollbackEnvelope>,
    pub low_fee_quotas: BTreeMap<String, LowFeeFastLaneQuota>,
    pub sponsorships: BTreeMap<String, SponsorshipLedgerEntry>,
    pub bridge_guardrails: BTreeMap<String, BridgeWithdrawalGuardrail>,
    pub pq_attestations: BTreeMap<String, PqMicroblockAttestation>,
    pub latency_budgets: BTreeMap<String, LatencyBudget>,
    pub capacity_accounts: BTreeMap<String, CapacityAccount>,
    pub microblocks: BTreeMap<String, MicroblockRecord>,
}

impl MicroblockPipelineState {
    pub fn new(config: MicroblockPipelineConfig) -> MicroblockPipelineResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            current_microblock_sequence: 0,
            config,
            admissions: BTreeMap::new(),
            proposals: BTreeMap::new(),
            replay_commitments: BTreeMap::new(),
            optimistic_windows: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            finality_promotions: BTreeMap::new(),
            conflict_certificates: BTreeMap::new(),
            rollback_envelopes: BTreeMap::new(),
            low_fee_quotas: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            bridge_guardrails: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            latency_budgets: BTreeMap::new(),
            capacity_accounts: BTreeMap::new(),
            microblocks: BTreeMap::new(),
        })
    }

    pub fn devnet() -> MicroblockPipelineResult<Self> {
        let mut state = Self::new(MicroblockPipelineConfig::default())?;
        state.set_height(7);

        let budget = LatencyBudget::for_lane(
            MicroblockLane::LowFeeFast,
            MICROBLOCK_DEFAULT_CAPACITY_UNITS / 2,
        )?;
        let budget_id = budget.budget_id.clone();
        state.insert_latency_budget(budget)?;

        let mut capacity = CapacityAccount::new(
            state.height,
            1,
            MicroblockLane::LowFeeFast,
            MICROBLOCK_DEFAULT_CAPACITY_UNITS / 2,
        )?;
        capacity.reserve(60_000)?;
        capacity.pq_auth_bytes = 7_168;
        capacity.proof_bytes = 4_096;
        capacity.da_bytes = 2_048;
        capacity.low_fee_units = 2_500;
        let capacity_id = capacity.capacity_id.clone();
        state.insert_capacity_account(capacity.clone())?;

        let sponsor_commitment = microblock_pipeline_string_root(
            "MICROBLOCK-DEVNET-SPONSOR",
            MICROBLOCK_DEVNET_SPONSOR_ID,
        );
        let quota = LowFeeFastLaneQuota::new(
            MicroblockLane::LowFeeFast,
            &sponsor_commitment,
            state.height,
            state
                .height
                .saturating_add(MICROBLOCK_DEFAULT_SPONSORSHIP_TTL_MICROBLOCKS),
            MICROBLOCK_DEFAULT_FAST_LANE_QUOTA_UNITS,
            MICROBLOCK_DEVNET_FEE_ASSET_ID,
            &microblock_pipeline_payload_root(
                "MICROBLOCK-DEVNET-SPONSORSHIP-POLICY",
                &json!({ "sponsor": MICROBLOCK_DEVNET_SPONSOR_ID, "rebate_bps": 10_000 }),
            ),
        )?;
        let quota_id = quota.quota_id.clone();
        state.insert_low_fee_quota(quota)?;

        let guardrail = BridgeWithdrawalGuardrail::devnet("wxmr-fast-withdrawal", state.height)?;
        let guardrail_id = guardrail.guardrail_id.clone();
        state.insert_bridge_guardrail(guardrail)?;

        let admission_a = MempoolAdmissionCommitment::devnet(
            "alice-private-transfer",
            MicroblockLane::LowFeeFast,
            1,
            state.height,
            1,
            Some(sponsor_commitment.clone()),
            None,
        )?;
        let admission_b = MempoolAdmissionCommitment::devnet(
            "bob-private-defi",
            MicroblockLane::LowFeeFast,
            2,
            state.height,
            1,
            Some(sponsor_commitment.clone()),
            None,
        )?;
        let bridge_admission = MempoolAdmissionCommitment::devnet(
            "carol-bridge-withdrawal",
            MicroblockLane::BridgeWithdrawal,
            3,
            state.height,
            2,
            None,
            Some(guardrail_id.clone()),
        )?;
        let admission_a_id = state.admit_commitment(admission_a.clone())?;
        let admission_b_id = state.admit_commitment(admission_b.clone())?;
        state.admit_commitment(bridge_admission.clone())?;

        let sponsorship = SponsorshipLedgerEntry::new(
            &quota_id,
            &sponsor_commitment,
            &admission_a.account_commitment,
            &admission_a_id,
            MICROBLOCK_DEVNET_FEE_ASSET_ID,
            1_000,
            10_000,
            state.height,
            MICROBLOCK_DEFAULT_SPONSORSHIP_TTL_MICROBLOCKS,
        )?;
        state.record_sponsorship(sponsorship)?;

        let proposal_id = state.propose_microbatch(
            "genesis-microblock",
            MICROBLOCK_DEVNET_SEQUENCER_ID,
            MicroblockLane::LowFeeFast,
            &[admission_a_id, admission_b_id],
            Some(&quota_id),
            None,
            &budget_id,
            &capacity_id,
            1_700_000_000_080,
        )?;
        let proposal = state
            .proposals
            .get(&proposal_id)
            .cloned()
            .ok_or_else(|| "devnet proposal missing after insert".to_string())?;
        let replay = DeterministicReplayCommitment::for_proposal(
            &proposal,
            &microblock_empty_root("MICROBLOCK-DEVNET-STATE-BEFORE"),
            &microblock_pipeline_payload_root(
                "MICROBLOCK-DEVNET-STATE-AFTER",
                &json!({ "proposal_id": proposal.proposal_id, "height": state.height }),
            ),
            60_000,
        )?;
        let replay_id = replay.replay_id.clone();
        state.insert_replay_commitment(replay.clone())?;
        let window = OptimisticExecutionWindow::open(
            &proposal,
            &replay,
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-READ-SET", "read-set-a"),
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-WRITE-SET", "write-set-a"),
            60_000,
            55_000,
            MICROBLOCK_DEFAULT_REPLAY_RETENTION_MICROBLOCKS,
        )?;
        let window_root = state.open_optimistic_window(window.clone())?;
        let proposal_attestation = PqMicroblockAttestation::devnet_for_subject(
            "microbatch_proposal",
            &proposal.proposal_id,
            &proposal.proposal_root(),
            AttestationRole::Sequencer,
            state.height,
            proposal.microblock_sequence,
        )?;
        state.insert_pq_attestation(proposal_attestation.clone())?;
        let microblock = MicroblockRecord::from_proposal(
            &proposal,
            &window,
            &[],
            &[proposal_attestation.clone()],
            &capacity,
            &replay.input_state_root,
            &replay.expected_output_root,
            1_700_000_000_120,
        )?;
        let microblock_id = state.insert_microblock(microblock.clone())?;
        let committee_attestation = PqMicroblockAttestation::devnet_for_subject(
            "microblock",
            &microblock_id,
            &microblock.microblock_root(),
            AttestationRole::CommitteeMember,
            state.height,
            proposal.microblock_sequence,
        )?;
        state.insert_pq_attestation(committee_attestation.clone())?;

        for admission_id in &proposal.admission_ids {
            let receipt = PreconfirmationReceipt::new(
                admission_id,
                &proposal.proposal_id,
                &microblock_id,
                &replay.expected_output_root,
                &replay_id,
                state.height,
                proposal.microblock_sequence,
                MICROBLOCK_DEFAULT_RECEIPT_TTL_MICROBLOCKS,
                proposal.lane.target_latency_ms(),
                &proposal_attestation.attestation_root(),
            )?;
            state.issue_preconfirmation_receipt(receipt)?;
        }

        let promotion = FinalityPromotion::new(
            &microblock_id,
            &state.preconfirmation_receipt_root(),
            &replay.expected_output_root,
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-SETTLEMENT-ANCHOR", "anchor-7"),
            &committee_attestation.attestation_root(),
            state.height.saturating_add(1),
            0,
            FinalityPromotionStatus::Promoted,
        )?;
        state.promote_finality(promotion)?;

        let bridge_budget = LatencyBudget::for_lane(MicroblockLane::BridgeWithdrawal, 250_000)?;
        let bridge_budget_id = bridge_budget.budget_id.clone();
        state.insert_latency_budget(bridge_budget)?;
        let mut bridge_capacity =
            CapacityAccount::new(state.height, 2, MicroblockLane::BridgeWithdrawal, 250_000)?;
        bridge_capacity.bridge_units = bridge_admission.bridge_amount_bucket;
        let bridge_capacity_id = bridge_capacity.capacity_id.clone();
        state.insert_capacity_account(bridge_capacity)?;
        state.propose_microbatch(
            &microblock_id,
            MICROBLOCK_DEVNET_SEQUENCER_ID,
            MicroblockLane::BridgeWithdrawal,
            &[bridge_admission.admission_id],
            None,
            Some(&guardrail_id),
            &bridge_budget_id,
            &bridge_capacity_id,
            1_700_000_000_200,
        )?;

        let conflict = ConflictCertificate::new(
            ConflictKind::ReplayMismatch,
            &microblock_id,
            "external-conflicting-microblock",
            &microblock.microblock_root(),
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-CONFLICTING-ROOT", "external"),
            &window.write_set_root,
            &microblock_pipeline_payload_root(
                "MICROBLOCK-DEVNET-CONFLICT-EVIDENCE",
                &json!({ "kind": "replay_trace_mismatch", "trace": "commitment_only" }),
            ),
            "devnet-watchtower",
            state.height.saturating_add(1),
        )?;
        let certificate_id = state.record_conflict_certificate(conflict.clone())?;
        let rollback = RollbackEnvelope::new(
            &certificate_id,
            &microblock_id,
            &microblock.parent_microblock_id,
            &window_root,
            &state.preconfirmation_receipt_root(),
            &microblock_pipeline_string_root("MICROBLOCK-DEVNET-COMPENSATION", "rebate-bucket"),
            &replay.replay_root(),
            RollbackReason::ReplayDivergence,
            state.height.saturating_add(1),
            1,
        )?;
        state.record_rollback_envelope(rollback)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn admit_commitment(
        &mut self,
        admission: MempoolAdmissionCommitment,
    ) -> MicroblockPipelineResult<String> {
        admission.validate()?;
        if admission.is_expired_at(self.height) {
            return Err("mempool admission is expired".to_string());
        }
        if let Some(guardrail_id) = &admission.bridge_guardrail_id {
            if !self.bridge_guardrails.contains_key(guardrail_id) {
                return Err("mempool admission references missing bridge guardrail".to_string());
            }
        }
        let admission_id = admission.admission_id.clone();
        self.admissions.insert(admission_id.clone(), admission);
        Ok(admission_id)
    }

    pub fn insert_low_fee_quota(
        &mut self,
        quota: LowFeeFastLaneQuota,
    ) -> MicroblockPipelineResult<String> {
        quota.validate()?;
        let quota_id = quota.quota_id.clone();
        self.low_fee_quotas.insert(quota_id.clone(), quota);
        Ok(quota_id)
    }

    pub fn record_sponsorship(
        &mut self,
        sponsorship: SponsorshipLedgerEntry,
    ) -> MicroblockPipelineResult<String> {
        sponsorship.validate()?;
        if !self.low_fee_quotas.contains_key(&sponsorship.quota_id) {
            return Err("sponsorship references missing quota".to_string());
        }
        if !self.admissions.contains_key(&sponsorship.admission_id) {
            return Err("sponsorship references missing admission".to_string());
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn insert_bridge_guardrail(
        &mut self,
        guardrail: BridgeWithdrawalGuardrail,
    ) -> MicroblockPipelineResult<String> {
        guardrail.validate()?;
        let guardrail_id = guardrail.guardrail_id.clone();
        self.bridge_guardrails
            .insert(guardrail_id.clone(), guardrail);
        Ok(guardrail_id)
    }

    pub fn insert_latency_budget(
        &mut self,
        budget: LatencyBudget,
    ) -> MicroblockPipelineResult<String> {
        budget.validate()?;
        let budget_id = budget.budget_id.clone();
        self.latency_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn insert_capacity_account(
        &mut self,
        capacity: CapacityAccount,
    ) -> MicroblockPipelineResult<String> {
        capacity.validate()?;
        let capacity_id = capacity.capacity_id.clone();
        self.capacity_accounts.insert(capacity_id.clone(), capacity);
        Ok(capacity_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn propose_microbatch(
        &mut self,
        parent_microblock_id: &str,
        proposer_id: &str,
        lane: MicroblockLane,
        admission_ids: &[String],
        low_fee_quota_id: Option<&str>,
        bridge_guardrail_id: Option<&str>,
        latency_budget_id: &str,
        capacity_account_id: &str,
        created_at_ms: u64,
    ) -> MicroblockPipelineResult<String> {
        if admission_ids.is_empty() {
            return Err("microbatch proposal requires admissions".to_string());
        }
        let mut admissions = Vec::with_capacity(admission_ids.len());
        for admission_id in admission_ids {
            let admission = self
                .admissions
                .get(admission_id)
                .ok_or_else(|| "microbatch proposal references unknown admission".to_string())?;
            admissions.push(admission.clone());
        }
        if admissions.len() as u64 > self.config.max_admissions_per_microblock {
            return Err("microbatch proposal exceeds max admissions".to_string());
        }
        let private_payload_count = admissions
            .iter()
            .map(|admission| admission.private_payload_root.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64;
        if private_payload_count > self.config.max_private_payload_roots {
            return Err("microbatch proposal exceeds private payload root limit".to_string());
        }
        let low_fee_quota_root = if let Some(quota_id) = low_fee_quota_id {
            self.low_fee_quotas
                .get(quota_id)
                .ok_or_else(|| "microbatch proposal references missing low fee quota".to_string())?
                .quota_root()
        } else {
            microblock_empty_root("MICROBLOCK-LOW-FEE-QUOTA")
        };
        let bridge_guardrail_root = if let Some(guardrail_id) = bridge_guardrail_id {
            self.bridge_guardrails
                .get(guardrail_id)
                .ok_or_else(|| {
                    "microbatch proposal references missing bridge guardrail".to_string()
                })?
                .guardrail_root()
        } else {
            microblock_empty_root("MICROBLOCK-BRIDGE-GUARDRAIL")
        };
        if !self.latency_budgets.contains_key(latency_budget_id) {
            return Err("microbatch proposal references missing latency budget".to_string());
        }
        if !self.capacity_accounts.contains_key(capacity_account_id) {
            return Err("microbatch proposal references missing capacity account".to_string());
        }
        let proposal = MicrobatchProposal::from_admissions(
            parent_microblock_id,
            proposer_id,
            self.height,
            self.current_microblock_sequence.saturating_add(1),
            lane,
            &admissions,
            &low_fee_quota_root,
            &bridge_guardrail_root,
            latency_budget_id,
            capacity_account_id,
            created_at_ms,
            self.config.target_microblock_ms,
        )?;
        self.current_microblock_sequence = proposal.microblock_sequence;
        let proposal_id = proposal.proposal_id.clone();
        self.proposals.insert(proposal_id.clone(), proposal);
        Ok(proposal_id)
    }

    pub fn insert_replay_commitment(
        &mut self,
        replay: DeterministicReplayCommitment,
    ) -> MicroblockPipelineResult<String> {
        replay.validate()?;
        if !self.proposals.contains_key(&replay.proposal_id) {
            return Err("replay commitment references missing proposal".to_string());
        }
        let replay_id = replay.replay_id.clone();
        self.replay_commitments.insert(replay_id.clone(), replay);
        Ok(replay_id)
    }

    pub fn open_optimistic_window(
        &mut self,
        window: OptimisticExecutionWindow,
    ) -> MicroblockPipelineResult<String> {
        let root = window.validate()?;
        if !self.proposals.contains_key(&window.proposal_id) {
            return Err("optimistic window references missing proposal".to_string());
        }
        if !self.replay_commitments.contains_key(&window.replay_id) {
            return Err("optimistic window references missing replay".to_string());
        }
        let active_windows = self
            .optimistic_windows
            .values()
            .filter(|candidate| candidate.is_open_at(self.height))
            .count() as u64;
        if active_windows >= self.config.max_optimistic_windows {
            return Err("too many active optimistic execution windows".to_string());
        }
        let window_id = window.window_id.clone();
        self.optimistic_windows.insert(window_id, window);
        Ok(root)
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqMicroblockAttestation,
    ) -> MicroblockPipelineResult<String> {
        attestation.validate()?;
        let attestation_id = attestation.attestation_id.clone();
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn insert_microblock(
        &mut self,
        microblock: MicroblockRecord,
    ) -> MicroblockPipelineResult<String> {
        microblock.validate()?;
        if !self.proposals.contains_key(&microblock.proposal_id) {
            return Err("microblock references missing proposal".to_string());
        }
        let microblock_id = microblock.microblock_id.clone();
        self.microblocks.insert(microblock_id.clone(), microblock);
        Ok(microblock_id)
    }

    pub fn issue_preconfirmation_receipt(
        &mut self,
        receipt: PreconfirmationReceipt,
    ) -> MicroblockPipelineResult<String> {
        receipt.validate()?;
        if !self.admissions.contains_key(&receipt.admission_id) {
            return Err("preconfirmation receipt references missing admission".to_string());
        }
        if !self.proposals.contains_key(&receipt.proposal_id) {
            return Err("preconfirmation receipt references missing proposal".to_string());
        }
        if !self.microblocks.contains_key(&receipt.microblock_id) {
            return Err("preconfirmation receipt references missing microblock".to_string());
        }
        if !self.replay_commitments.contains_key(&receipt.replay_id) {
            return Err("preconfirmation receipt references missing replay".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.preconfirmation_receipts
            .insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn promote_finality(
        &mut self,
        promotion: FinalityPromotion,
    ) -> MicroblockPipelineResult<String> {
        let root = promotion.validate()?;
        let microblock = self
            .microblocks
            .get_mut(&promotion.microblock_id)
            .ok_or_else(|| "finality promotion references missing microblock".to_string())?;
        microblock.status = MICROBLOCK_STATUS_FINALIZED.to_string();
        microblock.finality_promotion_root = root;
        let promotion_id = promotion.promotion_id.clone();
        self.finality_promotions
            .insert(promotion_id.clone(), promotion);
        Ok(promotion_id)
    }

    pub fn record_conflict_certificate(
        &mut self,
        certificate: ConflictCertificate,
    ) -> MicroblockPipelineResult<String> {
        let root = certificate.validate()?;
        if let Some(microblock) = self.microblocks.get_mut(&certificate.left_microblock_id) {
            microblock.status = MICROBLOCK_STATUS_CONFLICTED.to_string();
            microblock.conflict_certificate_root = root;
        }
        let certificate_id = certificate.certificate_id.clone();
        self.conflict_certificates
            .insert(certificate_id.clone(), certificate);
        Ok(certificate_id)
    }

    pub fn record_rollback_envelope(
        &mut self,
        rollback: RollbackEnvelope,
    ) -> MicroblockPipelineResult<String> {
        let root = rollback.validate()?;
        if !self
            .conflict_certificates
            .contains_key(&rollback.certificate_id)
        {
            return Err("rollback references missing conflict certificate".to_string());
        }
        if let Some(microblock) = self.microblocks.get_mut(&rollback.from_microblock_id) {
            microblock.status = MICROBLOCK_STATUS_ROLLED_BACK.to_string();
            microblock.rollback_envelope_root = root;
        }
        let rollback_id = rollback.rollback_id.clone();
        self.rollback_envelopes
            .insert(rollback_id.clone(), rollback);
        Ok(rollback_id)
    }

    pub fn roots(&self) -> MicroblockPipelineRoots {
        MicroblockPipelineRoots {
            config_root: self.config.config_root(),
            admission_root: self.admission_root(),
            proposal_root: self.proposal_root(),
            replay_root: self.replay_root(),
            optimistic_window_root: self.optimistic_window_root(),
            receipt_root: self.preconfirmation_receipt_root(),
            finality_promotion_root: self.finality_promotion_root(),
            conflict_certificate_root: self.conflict_certificate_root(),
            rollback_envelope_root: self.rollback_envelope_root(),
            low_fee_quota_root: self.low_fee_quota_root(),
            sponsorship_root: self.sponsorship_root(),
            bridge_guardrail_root: self.bridge_guardrail_root(),
            pq_attestation_root: self.pq_attestation_root(),
            latency_budget_root: self.latency_budget_root(),
            capacity_account_root: self.capacity_account_root(),
            microblock_root: self.microblock_root(),
        }
    }

    pub fn admission_root(&self) -> String {
        microblock_mempool_admission_root(
            &self
                .admissions
                .values()
                .cloned()
                .collect::<Vec<MempoolAdmissionCommitment>>(),
        )
    }

    pub fn proposal_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-PROPOSAL",
            &self
                .proposals
                .values()
                .map(MicrobatchProposal::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn replay_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-REPLAY-COMMITMENT",
            &self
                .replay_commitments
                .values()
                .map(DeterministicReplayCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn optimistic_window_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-OPTIMISTIC-WINDOW",
            &self
                .optimistic_windows
                .values()
                .map(OptimisticExecutionWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn preconfirmation_receipt_root(&self) -> String {
        microblock_preconfirmation_receipt_root(
            &self
                .preconfirmation_receipts
                .values()
                .cloned()
                .collect::<Vec<PreconfirmationReceipt>>(),
        )
    }

    pub fn finality_promotion_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-FINALITY-PROMOTION",
            &self
                .finality_promotions
                .values()
                .map(FinalityPromotion::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn conflict_certificate_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-CONFLICT-CERTIFICATE",
            &self
                .conflict_certificates
                .values()
                .map(ConflictCertificate::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn rollback_envelope_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-ROLLBACK-ENVELOPE",
            &self
                .rollback_envelopes
                .values()
                .map(RollbackEnvelope::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_quota_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-LOW-FEE-QUOTA",
            &self
                .low_fee_quotas
                .values()
                .map(LowFeeFastLaneQuota::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsorship_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-SPONSORSHIP",
            &self
                .sponsorships
                .values()
                .map(SponsorshipLedgerEntry::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn bridge_guardrail_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-BRIDGE-GUARDRAIL",
            &self
                .bridge_guardrails
                .values()
                .map(BridgeWithdrawalGuardrail::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        microblock_pq_attestation_root(
            &self
                .pq_attestations
                .values()
                .cloned()
                .collect::<Vec<PqMicroblockAttestation>>(),
        )
    }

    pub fn latency_budget_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-LATENCY-BUDGET",
            &self
                .latency_budgets
                .values()
                .map(LatencyBudget::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn capacity_account_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-CAPACITY-ACCOUNT",
            &self
                .capacity_accounts
                .values()
                .map(CapacityAccount::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn microblock_root(&self) -> String {
        merkle_root(
            "MICROBLOCK-RECORD",
            &self
                .microblocks
                .values()
                .map(MicroblockRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn open_optimistic_window_count(&self) -> u64 {
        self.optimistic_windows
            .values()
            .filter(|window| window.is_open_at(self.height))
            .count() as u64
    }

    pub fn finalized_microblock_count(&self) -> u64 {
        self.microblocks
            .values()
            .filter(|microblock| microblock.status == MICROBLOCK_STATUS_FINALIZED)
            .count() as u64
    }

    pub fn low_fee_available_units(&self) -> u64 {
        self.low_fee_quotas.values().fold(0_u64, |total, quota| {
            total.saturating_add(quota.available_units())
        })
    }

    pub fn total_capacity_pressure_bps(&self) -> u64 {
        let used = self
            .capacity_accounts
            .values()
            .map(|account| {
                account
                    .reserved_fuel_units
                    .saturating_add(account.used_fuel_units)
            })
            .fold(0_u64, u64::saturating_add);
        let available = self
            .capacity_accounts
            .values()
            .map(|account| account.available_fuel_units)
            .fold(0_u64, u64::saturating_add);
        ratio_bps(used, available)
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "microblock_pipeline_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MICROBLOCK_PIPELINE_PROTOCOL_VERSION,
            "schema_version": MICROBLOCK_PIPELINE_SCHEMA_VERSION,
            "height": self.height,
            "current_microblock_sequence": self.current_microblock_sequence,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "admission_count": self.admissions.len() as u64,
            "proposal_count": self.proposals.len() as u64,
            "replay_commitment_count": self.replay_commitments.len() as u64,
            "optimistic_window_count": self.optimistic_windows.len() as u64,
            "open_optimistic_window_count": self.open_optimistic_window_count(),
            "preconfirmation_receipt_count": self.preconfirmation_receipts.len() as u64,
            "finality_promotion_count": self.finality_promotions.len() as u64,
            "finalized_microblock_count": self.finalized_microblock_count(),
            "conflict_certificate_count": self.conflict_certificates.len() as u64,
            "rollback_envelope_count": self.rollback_envelopes.len() as u64,
            "low_fee_quota_count": self.low_fee_quotas.len() as u64,
            "low_fee_available_units": self.low_fee_available_units(),
            "sponsorship_count": self.sponsorships.len() as u64,
            "bridge_guardrail_count": self.bridge_guardrails.len() as u64,
            "pq_attestation_count": self.pq_attestations.len() as u64,
            "latency_budget_count": self.latency_budgets.len() as u64,
            "capacity_account_count": self.capacity_accounts.len() as u64,
            "microblock_count": self.microblocks.len() as u64,
            "capacity_pressure_bps": self.total_capacity_pressure_bps(),
            "payload_visibility": MICROBLOCK_PIPELINE_PRIVATE_VISIBILITY,
        })
    }

    pub fn state_root(&self) -> String {
        microblock_pipeline_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("microblock pipeline state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> MicroblockPipelineResult<String> {
        self.config.validate()?;
        for guardrail in self.bridge_guardrails.values() {
            guardrail.validate()?;
        }
        for quota in self.low_fee_quotas.values() {
            quota.validate()?;
        }
        for budget in self.latency_budgets.values() {
            budget.validate()?;
        }
        for capacity in self.capacity_accounts.values() {
            capacity.validate()?;
        }
        for admission in self.admissions.values() {
            admission.validate()?;
            if let Some(guardrail_id) = &admission.bridge_guardrail_id {
                if !self.bridge_guardrails.contains_key(guardrail_id) {
                    return Err("admission references missing bridge guardrail".to_string());
                }
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if !self.low_fee_quotas.contains_key(&sponsorship.quota_id) {
                return Err("sponsorship references missing quota".to_string());
            }
            if !self.admissions.contains_key(&sponsorship.admission_id) {
                return Err("sponsorship references missing admission".to_string());
            }
        }
        for proposal in self.proposals.values() {
            proposal.validate()?;
            if !self
                .latency_budgets
                .contains_key(&proposal.latency_budget_id)
            {
                return Err("proposal references missing latency budget".to_string());
            }
            if !self
                .capacity_accounts
                .contains_key(&proposal.capacity_account_id)
            {
                return Err("proposal references missing capacity account".to_string());
            }
            for admission_id in &proposal.admission_ids {
                if !self.admissions.contains_key(admission_id) {
                    return Err("proposal references missing admission".to_string());
                }
            }
        }
        for replay in self.replay_commitments.values() {
            replay.validate()?;
            if !self.proposals.contains_key(&replay.proposal_id) {
                return Err("replay references missing proposal".to_string());
            }
        }
        for window in self.optimistic_windows.values() {
            window.validate()?;
            if !self.proposals.contains_key(&window.proposal_id) {
                return Err("optimistic window references missing proposal".to_string());
            }
            if !self.replay_commitments.contains_key(&window.replay_id) {
                return Err("optimistic window references missing replay".to_string());
            }
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
        }
        for microblock in self.microblocks.values() {
            microblock.validate()?;
            if !self.proposals.contains_key(&microblock.proposal_id) {
                return Err("microblock references missing proposal".to_string());
            }
        }
        for receipt in self.preconfirmation_receipts.values() {
            receipt.validate()?;
            if !self.admissions.contains_key(&receipt.admission_id) {
                return Err("receipt references missing admission".to_string());
            }
            if !self.proposals.contains_key(&receipt.proposal_id) {
                return Err("receipt references missing proposal".to_string());
            }
            if !self.microblocks.contains_key(&receipt.microblock_id) {
                return Err("receipt references missing microblock".to_string());
            }
            if !self.replay_commitments.contains_key(&receipt.replay_id) {
                return Err("receipt references missing replay".to_string());
            }
        }
        for promotion in self.finality_promotions.values() {
            promotion.validate()?;
            if !self.microblocks.contains_key(&promotion.microblock_id) {
                return Err("finality promotion references missing microblock".to_string());
            }
        }
        for certificate in self.conflict_certificates.values() {
            certificate.validate()?;
        }
        for rollback in self.rollback_envelopes.values() {
            rollback.validate()?;
            if !self
                .conflict_certificates
                .contains_key(&rollback.certificate_id)
            {
                return Err("rollback references missing conflict certificate".to_string());
            }
        }
        Ok(self.state_root())
    }
}

impl Default for MicroblockPipelineState {
    fn default() -> Self {
        Self::new(MicroblockPipelineConfig::default())
            .expect("default microblock pipeline config is valid")
    }
}

pub fn microblock_pipeline_state_root_from_record(record: &Value) -> String {
    microblock_pipeline_payload_root("MICROBLOCK-PIPELINE-STATE", record)
}

pub fn microblock_pipeline_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn microblock_pipeline_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn microblock_pipeline_string_set_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    merkle_root(
        domain,
        &sorted
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

pub fn microblock_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn microblock_ordering_metadata_id(
    lane: MicroblockLane,
    ordering_class: MicroblockOrderingClass,
    lane_sequence: u64,
    priority_score: u64,
    fee_bucket: u64,
    arrival_slot: u64,
    entropy_commitment: &str,
    tie_breaker_root: &str,
) -> String {
    domain_hash(
        "MICROBLOCK-ORDERING-METADATA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(ordering_class.as_str()),
            HashPart::Int(lane_sequence as i128),
            HashPart::Int(priority_score as i128),
            HashPart::Int(fee_bucket as i128),
            HashPart::Int(arrival_slot as i128),
            HashPart::Str(entropy_commitment),
            HashPart::Str(tie_breaker_root),
        ],
        32,
    )
}

pub fn microblock_mempool_admission_id(
    lane: MicroblockLane,
    tx_public_hash: &str,
    account_commitment: &str,
    nullifier_root: &str,
    private_payload_root: &str,
    lane_sequence: u64,
    nonce: u64,
    admitted_at_height: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-MEMPOOL-ADMISSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(tx_public_hash),
            HashPart::Str(account_commitment),
            HashPart::Str(nullifier_root),
            HashPart::Str(private_payload_root),
            HashPart::Int(lane_sequence as i128),
            HashPart::Int(nonce as i128),
            HashPart::Int(admitted_at_height as i128),
        ],
        32,
    )
}

pub fn microblock_mempool_admission_root(admissions: &[MempoolAdmissionCommitment]) -> String {
    merkle_root(
        "MICROBLOCK-MEMPOOL-ADMISSION",
        &admissions
            .iter()
            .map(MempoolAdmissionCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn microblock_private_payload_root(private_payload_roots: &[String]) -> String {
    microblock_pipeline_string_set_root("MICROBLOCK-PRIVATE-PAYLOAD-ROOT", private_payload_roots)
}

pub fn microblock_low_fee_quota_id(
    lane: MicroblockLane,
    sponsor_commitment: &str,
    quota_window_start: u64,
    quota_window_end: u64,
    quota_units: u64,
    min_fee_asset_id: &str,
) -> String {
    domain_hash(
        "MICROBLOCK-LOW-FEE-QUOTA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sponsor_commitment),
            HashPart::Int(quota_window_start as i128),
            HashPart::Int(quota_window_end as i128),
            HashPart::Int(quota_units as i128),
            HashPart::Str(min_fee_asset_id),
        ],
        32,
    )
}

pub fn microblock_sponsorship_id(
    quota_id: &str,
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    admission_id: &str,
    fee_asset_id: &str,
    sponsored_units: u64,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quota_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(admission_id),
            HashPart::Str(fee_asset_id),
            HashPart::Int(sponsored_units as i128),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn microblock_bridge_guardrail_id(
    withdrawal_id: &str,
    recipient_commitment: &str,
    amount_bucket: u64,
    monero_network: &str,
    reserve_root: &str,
    signer_set_root: &str,
    min_mature_height: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-BRIDGE-GUARDRAIL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(recipient_commitment),
            HashPart::Int(amount_bucket as i128),
            HashPart::Str(monero_network),
            HashPart::Str(reserve_root),
            HashPart::Str(signer_set_root),
            HashPart::Int(min_mature_height as i128),
        ],
        32,
    )
}

pub fn microblock_latency_budget_id(
    lane: MicroblockLane,
    target_ms: u64,
    admission_ms: u64,
    sequencing_ms: u64,
    execution_ms: u64,
    attestation_ms: u64,
    finality_ms: u64,
    capacity_units: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-LATENCY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Int(target_ms as i128),
            HashPart::Int(admission_ms as i128),
            HashPart::Int(sequencing_ms as i128),
            HashPart::Int(execution_ms as i128),
            HashPart::Int(attestation_ms as i128),
            HashPart::Int(finality_ms as i128),
            HashPart::Int(capacity_units as i128),
        ],
        32,
    )
}

pub fn microblock_capacity_account_id(
    height: u64,
    microblock_sequence: u64,
    lane: MicroblockLane,
    available_fuel_units: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-CAPACITY-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Int(available_fuel_units as i128),
        ],
        32,
    )
}

pub fn microbatch_proposal_id(
    parent_microblock_id: &str,
    proposer_id: &str,
    height: u64,
    microblock_sequence: u64,
    lane: MicroblockLane,
    admission_root: &str,
    private_payload_root: &str,
    ordering_root: &str,
) -> String {
    domain_hash(
        "MICROBLOCK-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(parent_microblock_id),
            HashPart::Str(proposer_id),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Str(admission_root),
            HashPart::Str(private_payload_root),
            HashPart::Str(ordering_root),
        ],
        32,
    )
}

pub fn deterministic_replay_commitment_id(
    proposal_id: &str,
    execution_engine: &str,
    vm_config_root: &str,
    ordered_admission_root: &str,
    input_state_root: &str,
    expected_output_root: &str,
    deterministic_seed_root: &str,
    max_fuel_units: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-DETERMINISTIC-REPLAY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(execution_engine),
            HashPart::Str(vm_config_root),
            HashPart::Str(ordered_admission_root),
            HashPart::Str(input_state_root),
            HashPart::Str(expected_output_root),
            HashPart::Str(deterministic_seed_root),
            HashPart::Int(max_fuel_units as i128),
        ],
        32,
    )
}

pub fn optimistic_execution_window_id(
    proposal_id: &str,
    replay_id: &str,
    base_state_root: &str,
    optimistic_state_root: &str,
    read_set_root: &str,
    write_set_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-OPTIMISTIC-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(replay_id),
            HashPart::Str(base_state_root),
            HashPart::Str(optimistic_state_root),
            HashPart::Str(read_set_root),
            HashPart::Str(write_set_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn microblock_pq_signature_root(
    signer_id: &str,
    public_key_root: &str,
    signature_scheme: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MICROBLOCK-PQ-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_id),
            HashPart::Str(public_key_root),
            HashPart::Str(signature_scheme),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn microblock_pq_attestation_id(
    subject_kind: &str,
    subject_id: &str,
    signer_id: &str,
    role: AttestationRole,
    public_key_root: &str,
    transcript_root: &str,
    weight_bps: u64,
    attested_at_height: u64,
    attested_at_microblock: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(signer_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(public_key_root),
            HashPart::Str(transcript_root),
            HashPart::Int(weight_bps as i128),
            HashPart::Int(attested_at_height as i128),
            HashPart::Int(attested_at_microblock as i128),
        ],
        32,
    )
}

pub fn microblock_pq_attestation_root(attestations: &[PqMicroblockAttestation]) -> String {
    merkle_root(
        "MICROBLOCK-PQ-ATTESTATION",
        &attestations
            .iter()
            .map(PqMicroblockAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn microblock_record_id(
    parent_microblock_id: &str,
    proposal_id: &str,
    height: u64,
    microblock_sequence: u64,
    lane: MicroblockLane,
    admission_root: &str,
    private_payload_root: &str,
    execution_window_root: &str,
    state_root_before: &str,
    state_root_after: &str,
) -> String {
    domain_hash(
        "MICROBLOCK-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(parent_microblock_id),
            HashPart::Str(proposal_id),
            HashPart::Int(height as i128),
            HashPart::Int(microblock_sequence as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Str(admission_root),
            HashPart::Str(private_payload_root),
            HashPart::Str(execution_window_root),
            HashPart::Str(state_root_before),
            HashPart::Str(state_root_after),
        ],
        32,
    )
}

pub fn preconfirmation_receipt_id(
    admission_id: &str,
    proposal_id: &str,
    microblock_id: &str,
    promised_state_root: &str,
    replay_id: &str,
    issued_at_height: u64,
    issued_at_microblock: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-PRECONFIRMATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(admission_id),
            HashPart::Str(proposal_id),
            HashPart::Str(microblock_id),
            HashPart::Str(promised_state_root),
            HashPart::Str(replay_id),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(issued_at_microblock as i128),
        ],
        32,
    )
}

pub fn microblock_preconfirmation_receipt_root(receipts: &[PreconfirmationReceipt]) -> String {
    merkle_root(
        "MICROBLOCK-PRECONFIRMATION-RECEIPT",
        &receipts
            .iter()
            .map(PreconfirmationReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn finality_promotion_id(
    microblock_id: &str,
    preconfirmation_receipt_root: &str,
    final_state_root: &str,
    settlement_anchor_root: &str,
    committee_attestation_root: &str,
    promoted_at_height: u64,
    promoted_at_microblock: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-FINALITY-PROMOTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(microblock_id),
            HashPart::Str(preconfirmation_receipt_root),
            HashPart::Str(final_state_root),
            HashPart::Str(settlement_anchor_root),
            HashPart::Str(committee_attestation_root),
            HashPart::Int(promoted_at_height as i128),
            HashPart::Int(promoted_at_microblock as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn conflict_certificate_id(
    conflict_kind: ConflictKind,
    left_microblock_id: &str,
    right_microblock_id: &str,
    left_commitment_root: &str,
    right_commitment_root: &str,
    conflicting_resource_root: &str,
    evidence_root: &str,
    detected_at_height: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-CONFLICT-CERTIFICATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(conflict_kind.as_str()),
            HashPart::Str(left_microblock_id),
            HashPart::Str(right_microblock_id),
            HashPart::Str(left_commitment_root),
            HashPart::Str(right_commitment_root),
            HashPart::Str(conflicting_resource_root),
            HashPart::Str(evidence_root),
            HashPart::Int(detected_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn rollback_envelope_id(
    certificate_id: &str,
    from_microblock_id: &str,
    to_parent_microblock_id: &str,
    reverted_window_root: &str,
    receipt_root: &str,
    compensation_root: &str,
    replay_checkpoint_root: &str,
    reason: RollbackReason,
    issued_at_height: u64,
    issued_at_microblock: u64,
) -> String {
    domain_hash(
        "MICROBLOCK-ROLLBACK-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(certificate_id),
            HashPart::Str(from_microblock_id),
            HashPart::Str(to_parent_microblock_id),
            HashPart::Str(reverted_window_root),
            HashPart::Str(receipt_root),
            HashPart::Str(compensation_root),
            HashPart::Str(replay_checkpoint_root),
            HashPart::Str(reason.as_str()),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(issued_at_microblock as i128),
        ],
        32,
    )
}

pub fn amount_bucket(amount: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        return amount;
    }
    amount
        .saturating_add(bucket_size.saturating_sub(1))
        .saturating_div(bucket_size)
        .saturating_mul(bucket_size)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(MICROBLOCK_PIPELINE_MAX_BPS)
        .saturating_div(denominator)
        .min(MICROBLOCK_PIPELINE_MAX_BPS)
}

pub fn ensure_bps(value: u64, label: &str) -> MicroblockPipelineResult<()> {
    if value > MICROBLOCK_PIPELINE_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

pub fn ensure_positive(value: u64, label: &str) -> MicroblockPipelineResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

pub fn ensure_non_empty(value: &str, label: &str) -> MicroblockPipelineResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}
