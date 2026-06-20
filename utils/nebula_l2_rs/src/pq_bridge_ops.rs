use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqBridgeOpsResult<T> = Result<T, String>;

pub const PQ_BRIDGE_OPS_PROTOCOL_VERSION: &str = "nebula-pq-bridge-ops-v1";
pub const PQ_BRIDGE_OPS_DEVNET_HEIGHT: u64 = 216;
pub const PQ_BRIDGE_OPS_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const PQ_BRIDGE_OPS_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_BRIDGE_OPS_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_BRIDGE_OPS_KYBER_LABEL: &str = "kyber-1024-devnet-placeholder-kem";
pub const PQ_BRIDGE_OPS_FALCON_LABEL: &str = "falcon-1024-devnet-placeholder-sig";
pub const PQ_BRIDGE_OPS_DILITHIUM_LABEL: &str = "dilithium5-devnet-placeholder-sig";
pub const PQ_BRIDGE_OPS_HYBRID_ATTESTATION_LABEL: &str = "kyber-falcon-dilithium-threshold-devnet";
pub const PQ_BRIDGE_OPS_DEFAULT_EPOCH_DURATION_BLOCKS: u64 = 720;
pub const PQ_BRIDGE_OPS_DEFAULT_EPOCH_GRACE_BLOCKS: u64 = 48;
pub const PQ_BRIDGE_OPS_DEFAULT_OBSERVATION_FINALITY_DEPTH: u64 = 10;
pub const PQ_BRIDGE_OPS_DEFAULT_EXIT_QUEUE_TTL_BLOCKS: u64 = 144;
pub const PQ_BRIDGE_OPS_DEFAULT_CLAIM_TTL_BLOCKS: u64 = 96;
pub const PQ_BRIDGE_OPS_DEFAULT_REPLAY_RETENTION_BLOCKS: u64 = 4_320;
pub const PQ_BRIDGE_OPS_DEFAULT_RESERVE_CHECKPOINT_INTERVAL_BLOCKS: u64 = 24;
pub const PQ_BRIDGE_OPS_DEFAULT_MAX_EXIT_QUEUE_ITEMS: usize = 512;
pub const PQ_BRIDGE_OPS_DEFAULT_MAX_OBSERVATION_BATCH_ITEMS: usize = 256;
pub const PQ_BRIDGE_OPS_DEFAULT_MIN_COMMITTEE_WEIGHT_BPS: u64 = 6_700;
pub const PQ_BRIDGE_OPS_DEFAULT_MIN_ATTESTATION_WEIGHT_BPS: u64 = 6_700;
pub const PQ_BRIDGE_OPS_DEFAULT_EMERGENCY_PAUSE_QUORUM: u64 = 2;
pub const PQ_BRIDGE_OPS_DEFAULT_UNPAUSE_QUORUM: u64 = 3;
pub const PQ_BRIDGE_OPS_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_500;
pub const PQ_BRIDGE_OPS_DEFAULT_MAX_SPONSOR_REBATE_UNITS: u64 = 50_000;
pub const PQ_BRIDGE_OPS_DEFAULT_READINESS_STALE_AFTER_BLOCKS: u64 = 18;
pub const PQ_BRIDGE_OPS_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqBridgeAlgorithm {
    KyberKem,
    FalconSignature,
    DilithiumSignature,
    HybridThreshold,
}

impl PqBridgeAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KyberKem => PQ_BRIDGE_OPS_KYBER_LABEL,
            Self::FalconSignature => PQ_BRIDGE_OPS_FALCON_LABEL,
            Self::DilithiumSignature => PQ_BRIDGE_OPS_DILITHIUM_LABEL,
            Self::HybridThreshold => PQ_BRIDGE_OPS_HYBRID_ATTESTATION_LABEL,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    Observer,
    Attester,
    ExitScheduler,
    ReserveAuditor,
    EmergencyGuardian,
    SponsorAuditor,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observer => "observer",
            Self::Attester => "attester",
            Self::ExitScheduler => "exit_scheduler",
            Self::ReserveAuditor => "reserve_auditor",
            Self::EmergencyGuardian => "emergency_guardian",
            Self::SponsorAuditor => "sponsor_auditor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeEpochStatus {
    Proposed,
    Active,
    Grace,
    Retired,
    Slashed,
    Expired,
}

impl CommitteeEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationSubjectKind {
    CommitteeEpoch,
    MoneroObservationBatch,
    ExitQueueCommitment,
    ReserveDeltaCheckpoint,
    EmergencyCeremony,
    WithdrawalClaim,
    SponsorRebate,
    ReadinessSnapshot,
}

impl AttestationSubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitteeEpoch => "committee_epoch",
            Self::MoneroObservationBatch => "monero_observation_batch",
            Self::ExitQueueCommitment => "exit_queue_commitment",
            Self::ReserveDeltaCheckpoint => "reserve_delta_checkpoint",
            Self::EmergencyCeremony => "emergency_ceremony",
            Self::WithdrawalClaim => "withdrawal_claim",
            Self::SponsorRebate => "sponsor_rebate",
            Self::ReadinessSnapshot => "readiness_snapshot",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    ThresholdMet,
    Superseded,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ThresholdMet => "threshold_met",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::ThresholdMet)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroObservationKind {
    Deposit,
    WithdrawalBroadcast,
    ReserveScan,
    Reorg,
    FeeSample,
    KeyImageSeen,
}

impl MoneroObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::WithdrawalBroadcast => "withdrawal_broadcast",
            Self::ReserveScan => "reserve_scan",
            Self::Reorg => "reorg",
            Self::FeeSample => "fee_sample",
            Self::KeyImageSeen => "key_image_seen",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationBatchStatus {
    Open,
    Sealed,
    Attested,
    Challenged,
    Finalized,
    Reorged,
    Expired,
}

impl ObservationBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
        }
    }

    pub fn is_final(self) -> bool {
        matches!(self, Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitQueueStatus {
    Queued,
    Sponsored,
    Attested,
    Ready,
    Claimed,
    Cancelled,
    Expired,
    Paused,
}

impl ExitQueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sponsored => "sponsored",
            Self::Attested => "attested",
            Self::Ready => "ready",
            Self::Claimed => "claimed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Paused => "paused",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Sponsored | Self::Attested | Self::Ready | Self::Paused
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseCeremonyAction {
    Pause,
    Unpause,
}

impl PauseCeremonyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Unpause => "unpause",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseCeremonyStatus {
    Proposed,
    ThresholdMet,
    Applied,
    Superseded,
    Rejected,
    Expired,
}

impl PauseCeremonyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ThresholdMet => "threshold_met",
            Self::Applied => "applied",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivocationEvidenceStatus {
    Reported,
    Verified,
    Slashed,
    Rejected,
    Expired,
}

impl EquivocationEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reported => "reported",
            Self::Verified => "verified",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn slashable(self) -> bool {
        matches!(self, Self::Verified | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveDeltaDirection {
    Inflow,
    Outflow,
    Neutral,
}

impl ReserveDeltaDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inflow => "inflow",
            Self::Outflow => "outflow",
            Self::Neutral => "neutral",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveCheckpointStatus {
    Proposed,
    Attested,
    Applied,
    Disputed,
    Superseded,
}

impl ReserveCheckpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Attested => "attested",
            Self::Applied => "applied",
            Self::Disputed => "disputed",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalClaimStatus {
    Submitted,
    NullifierReserved,
    Attested,
    Ready,
    Fulfilled,
    Rejected,
    Expired,
    Replayed,
}

impl WithdrawalClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::NullifierReserved => "nullifier_reserved",
            Self::Attested => "attested",
            Self::Ready => "ready",
            Self::Fulfilled => "fulfilled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Replayed => "replayed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayEntryStatus {
    Reserved,
    Observed,
    Spent,
    Replayed,
    Expired,
}

impl ReplayEntryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Observed => "observed",
            Self::Spent => "spent",
            Self::Replayed => "replayed",
            Self::Expired => "expired",
        }
    }

    pub fn blocks_replay(self) -> bool {
        !matches!(self, Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorRebateStatus {
    Offered,
    Reserved,
    Applied,
    Settled,
    Expired,
    Cancelled,
}

impl SponsorRebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Ready,
    Degraded,
    Offline,
    Jailed,
}

impl ReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Offline => "offline",
            Self::Jailed => "jailed",
        }
    }

    pub fn contributes_to_quorum(self) -> bool {
        matches!(self, Self::Ready | Self::Degraded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeOpsConfig {
    pub config_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub min_committee_weight_bps: u64,
    pub min_attestation_weight_bps: u64,
    pub emergency_pause_quorum: u64,
    pub unpause_quorum: u64,
    pub epoch_duration_blocks: u64,
    pub epoch_grace_blocks: u64,
    pub observation_finality_depth: u64,
    pub exit_queue_ttl_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub replay_retention_blocks: u64,
    pub reserve_checkpoint_interval_blocks: u64,
    pub max_exit_queue_items: u64,
    pub max_observation_batch_items: u64,
    pub low_fee_rebate_bps: u64,
    pub max_sponsor_rebate_units: u64,
    pub readiness_stale_after_blocks: u64,
    pub require_hybrid_attestations: bool,
    pub status: String,
}

impl Default for PqBridgeOpsConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            monero_network: PQ_BRIDGE_OPS_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: PQ_BRIDGE_OPS_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: PQ_BRIDGE_OPS_DEVNET_FEE_ASSET_ID.to_string(),
            min_committee_weight_bps: PQ_BRIDGE_OPS_DEFAULT_MIN_COMMITTEE_WEIGHT_BPS,
            min_attestation_weight_bps: PQ_BRIDGE_OPS_DEFAULT_MIN_ATTESTATION_WEIGHT_BPS,
            emergency_pause_quorum: PQ_BRIDGE_OPS_DEFAULT_EMERGENCY_PAUSE_QUORUM,
            unpause_quorum: PQ_BRIDGE_OPS_DEFAULT_UNPAUSE_QUORUM,
            epoch_duration_blocks: PQ_BRIDGE_OPS_DEFAULT_EPOCH_DURATION_BLOCKS,
            epoch_grace_blocks: PQ_BRIDGE_OPS_DEFAULT_EPOCH_GRACE_BLOCKS,
            observation_finality_depth: PQ_BRIDGE_OPS_DEFAULT_OBSERVATION_FINALITY_DEPTH,
            exit_queue_ttl_blocks: PQ_BRIDGE_OPS_DEFAULT_EXIT_QUEUE_TTL_BLOCKS,
            claim_ttl_blocks: PQ_BRIDGE_OPS_DEFAULT_CLAIM_TTL_BLOCKS,
            replay_retention_blocks: PQ_BRIDGE_OPS_DEFAULT_REPLAY_RETENTION_BLOCKS,
            reserve_checkpoint_interval_blocks:
                PQ_BRIDGE_OPS_DEFAULT_RESERVE_CHECKPOINT_INTERVAL_BLOCKS,
            max_exit_queue_items: PQ_BRIDGE_OPS_DEFAULT_MAX_EXIT_QUEUE_ITEMS as u64,
            max_observation_batch_items: PQ_BRIDGE_OPS_DEFAULT_MAX_OBSERVATION_BATCH_ITEMS as u64,
            low_fee_rebate_bps: PQ_BRIDGE_OPS_DEFAULT_LOW_FEE_REBATE_BPS,
            max_sponsor_rebate_units: PQ_BRIDGE_OPS_DEFAULT_MAX_SPONSOR_REBATE_UNITS,
            readiness_stale_after_blocks: PQ_BRIDGE_OPS_DEFAULT_READINESS_STALE_AFTER_BLOCKS,
            require_hybrid_attestations: true,
            status: "active".to_string(),
        };
        config.config_id = pq_bridge_ops_config_id(&config.identity_record());
        config
    }
}

impl PqBridgeOpsConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_ops_config_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "min_committee_weight_bps": self.min_committee_weight_bps,
            "min_attestation_weight_bps": self.min_attestation_weight_bps,
            "emergency_pause_quorum": self.emergency_pause_quorum,
            "unpause_quorum": self.unpause_quorum,
            "epoch_duration_blocks": self.epoch_duration_blocks,
            "epoch_grace_blocks": self.epoch_grace_blocks,
            "observation_finality_depth": self.observation_finality_depth,
            "exit_queue_ttl_blocks": self.exit_queue_ttl_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "replay_retention_blocks": self.replay_retention_blocks,
            "reserve_checkpoint_interval_blocks": self.reserve_checkpoint_interval_blocks,
            "max_exit_queue_items": self.max_exit_queue_items,
            "max_observation_batch_items": self.max_observation_batch_items,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_sponsor_rebate_units": self.max_sponsor_rebate_units,
            "readiness_stale_after_blocks": self.readiness_stale_after_blocks,
            "require_hybrid_attestations": self.require_hybrid_attestations,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("pq bridge config identity record object");
        object.insert(
            "kind".to_string(),
            Value::String("pq_bridge_ops_config".to_string()),
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
        pq_bridge_ops_payload_root("PQ-BRIDGE-OPS-CONFIG", &self.identity_record())
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.config_id, "pq bridge config id")?;
        ensure_non_empty(&self.monero_network, "pq bridge monero network")?;
        ensure_non_empty(&self.asset_id, "pq bridge asset id")?;
        ensure_non_empty(&self.fee_asset_id, "pq bridge fee asset id")?;
        ensure_bps(
            self.min_committee_weight_bps,
            "pq bridge min committee weight",
        )?;
        ensure_bps(
            self.min_attestation_weight_bps,
            "pq bridge min attestation weight",
        )?;
        ensure_positive(self.emergency_pause_quorum, "pq bridge pause quorum")?;
        ensure_positive(self.unpause_quorum, "pq bridge unpause quorum")?;
        ensure_positive(self.epoch_duration_blocks, "pq bridge epoch duration")?;
        ensure_positive(self.observation_finality_depth, "pq bridge finality depth")?;
        ensure_positive(self.exit_queue_ttl_blocks, "pq bridge exit ttl")?;
        ensure_positive(self.claim_ttl_blocks, "pq bridge claim ttl")?;
        ensure_positive(self.replay_retention_blocks, "pq bridge replay retention")?;
        ensure_positive(
            self.reserve_checkpoint_interval_blocks,
            "pq bridge reserve checkpoint interval",
        )?;
        ensure_positive(self.max_exit_queue_items, "pq bridge max exit queue items")?;
        ensure_positive(
            self.max_observation_batch_items,
            "pq bridge max observation batch items",
        )?;
        ensure_bps(self.low_fee_rebate_bps, "pq bridge low fee rebate bps")?;
        ensure_positive(
            self.readiness_stale_after_blocks,
            "pq bridge readiness stale blocks",
        )?;
        let expected_id = pq_bridge_ops_config_id(&self.identity_record());
        if self.config_id != expected_id {
            return Err("pq bridge config id does not match identity record".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_commitment: String,
    pub display_label: String,
    pub roles: Vec<CommitteeRole>,
    pub kyber_public_key_root: String,
    pub falcon_public_key_root: String,
    pub dilithium_public_key_root: String,
    pub stake_weight_bps: u64,
    pub readiness_weight_bps: u64,
    pub joined_at_height: u64,
    pub jailed_until_height: u64,
    pub status: ReadinessStatus,
}

impl CommitteeMember {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_commitment: impl Into<String>,
        display_label: impl Into<String>,
        roles: Vec<CommitteeRole>,
        kyber_public_key_root: impl Into<String>,
        falcon_public_key_root: impl Into<String>,
        dilithium_public_key_root: impl Into<String>,
        stake_weight_bps: u64,
        readiness_weight_bps: u64,
        joined_at_height: u64,
        jailed_until_height: u64,
        status: ReadinessStatus,
    ) -> PqBridgeOpsResult<Self> {
        let operator_commitment = operator_commitment.into();
        let display_label = display_label.into();
        let kyber_public_key_root = kyber_public_key_root.into();
        let falcon_public_key_root = falcon_public_key_root.into();
        let dilithium_public_key_root = dilithium_public_key_root.into();
        let identity = json!({
            "kind": "pq_bridge_committee_member_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "operator_commitment": operator_commitment,
            "display_label": display_label,
            "roles": roles,
            "kyber_public_key_root": kyber_public_key_root,
            "falcon_public_key_root": falcon_public_key_root,
            "dilithium_public_key_root": dilithium_public_key_root,
            "stake_weight_bps": stake_weight_bps,
            "readiness_weight_bps": readiness_weight_bps,
            "joined_at_height": joined_at_height,
        });
        let mut member = Self {
            member_id: pq_bridge_ops_member_id(&identity),
            operator_commitment,
            display_label,
            roles,
            kyber_public_key_root,
            falcon_public_key_root,
            dilithium_public_key_root,
            stake_weight_bps,
            readiness_weight_bps,
            joined_at_height,
            jailed_until_height,
            status,
        };
        member.member_id = pq_bridge_ops_member_id(&member.identity_record());
        member.validate()?;
        Ok(member)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_committee_member_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "operator_commitment": self.operator_commitment,
            "display_label": self.display_label,
            "roles": self.roles,
            "kyber_public_key_root": self.kyber_public_key_root,
            "falcon_public_key_root": self.falcon_public_key_root,
            "dilithium_public_key_root": self.dilithium_public_key_root,
            "stake_weight_bps": self.stake_weight_bps,
            "readiness_weight_bps": self.readiness_weight_bps,
            "joined_at_height": self.joined_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "display_label": self.display_label,
            "roles": self.roles,
            "kyber_public_key_root": self.kyber_public_key_root,
            "falcon_public_key_root": self.falcon_public_key_root,
            "dilithium_public_key_root": self.dilithium_public_key_root,
            "stake_weight_bps": self.stake_weight_bps,
            "readiness_weight_bps": self.readiness_weight_bps,
            "joined_at_height": self.joined_at_height,
            "jailed_until_height": self.jailed_until_height,
            "status": self.status,
        })
    }

    pub fn member_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-COMMITTEE-MEMBER", &self.public_record())
    }

    pub fn active_weight_at(&self, height: u64) -> u64 {
        if self.joined_at_height <= height
            && self.jailed_until_height <= height
            && self.status.contributes_to_quorum()
        {
            self.stake_weight_bps.min(self.readiness_weight_bps)
        } else {
            0
        }
    }

    pub fn has_role(&self, role: CommitteeRole) -> bool {
        self.roles.contains(&role)
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.member_id, "pq bridge member id")?;
        ensure_non_empty(&self.operator_commitment, "pq bridge operator commitment")?;
        ensure_non_empty(&self.display_label, "pq bridge display label")?;
        ensure_non_empty(&self.kyber_public_key_root, "pq bridge kyber key root")?;
        ensure_non_empty(&self.falcon_public_key_root, "pq bridge falcon key root")?;
        ensure_non_empty(
            &self.dilithium_public_key_root,
            "pq bridge dilithium key root",
        )?;
        ensure_bps(self.stake_weight_bps, "pq bridge member stake weight")?;
        ensure_bps(
            self.readiness_weight_bps,
            "pq bridge member readiness weight",
        )?;
        ensure_unique_roles(&self.roles, "pq bridge member roles")?;
        let expected = pq_bridge_ops_member_id(&self.identity_record());
        if self.member_id != expected {
            return Err("pq bridge member id does not match identity".to_string());
        }
        Ok(self.member_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeCommitteeEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
    pub grace_ends_at_height: u64,
    pub quorum_weight_bps: u64,
    pub emergency_quorum: u64,
    pub algorithm_labels: Vec<PqBridgeAlgorithm>,
    pub member_ids: Vec<String>,
    pub member_root: String,
    pub total_member_weight_bps: u64,
    pub previous_epoch_root: String,
    pub status: CommitteeEpochStatus,
}

impl PqBridgeCommitteeEpoch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_index: u64,
        starts_at_height: u64,
        ends_at_height: u64,
        grace_ends_at_height: u64,
        quorum_weight_bps: u64,
        emergency_quorum: u64,
        algorithm_labels: Vec<PqBridgeAlgorithm>,
        members: &[CommitteeMember],
        previous_epoch_root: impl Into<String>,
        status: CommitteeEpochStatus,
    ) -> PqBridgeOpsResult<Self> {
        let previous_epoch_root = previous_epoch_root.into();
        let member_ids = members
            .iter()
            .map(|member| member.member_id.clone())
            .collect::<Vec<_>>();
        let member_root = pq_bridge_ops_committee_member_collection_root(members);
        let total_member_weight_bps = members
            .iter()
            .map(|member| member.stake_weight_bps)
            .sum::<u64>();
        let mut epoch = Self {
            epoch_id: String::new(),
            epoch_index,
            starts_at_height,
            ends_at_height,
            grace_ends_at_height,
            quorum_weight_bps,
            emergency_quorum,
            algorithm_labels,
            member_ids,
            member_root,
            total_member_weight_bps,
            previous_epoch_root,
            status,
        };
        epoch.epoch_id = pq_bridge_ops_committee_epoch_id(&epoch.identity_record());
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_committee_epoch_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "epoch_index": self.epoch_index,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "grace_ends_at_height": self.grace_ends_at_height,
            "quorum_weight_bps": self.quorum_weight_bps,
            "emergency_quorum": self.emergency_quorum,
            "algorithm_labels": self.algorithm_labels,
            "member_ids": self.member_ids,
            "member_root": self.member_root,
            "total_member_weight_bps": self.total_member_weight_bps,
            "previous_epoch_root": self.previous_epoch_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_committee_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "grace_ends_at_height": self.grace_ends_at_height,
            "quorum_weight_bps": self.quorum_weight_bps,
            "emergency_quorum": self.emergency_quorum,
            "algorithm_labels": self.algorithm_labels,
            "member_ids": self.member_ids,
            "member_root": self.member_root,
            "total_member_weight_bps": self.total_member_weight_bps,
            "previous_epoch_root": self.previous_epoch_root,
            "status": self.status,
        })
    }

    pub fn subject_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-COMMITTEE-EPOCH-SUBJECT", &self.identity_record())
    }

    pub fn epoch_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-COMMITTEE-EPOCH", &self.public_record())
    }

    pub fn contains_height(&self, height: u64) -> bool {
        self.starts_at_height <= height && height <= self.grace_ends_at_height
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.epoch_id, "pq bridge epoch id")?;
        ensure_ordered_window(
            self.starts_at_height,
            self.ends_at_height,
            "pq bridge epoch active window",
        )?;
        ensure_ordered_window(
            self.ends_at_height,
            self.grace_ends_at_height,
            "pq bridge epoch grace window",
        )?;
        ensure_bps(self.quorum_weight_bps, "pq bridge epoch quorum weight")?;
        ensure_positive(self.emergency_quorum, "pq bridge epoch emergency quorum")?;
        ensure_unique_algorithms(&self.algorithm_labels, "pq bridge epoch algorithms")?;
        ensure_unique_strings(&self.member_ids, "pq bridge epoch member ids")?;
        ensure_non_empty(&self.member_root, "pq bridge epoch member root")?;
        ensure_non_empty(
            &self.previous_epoch_root,
            "pq bridge epoch previous epoch root",
        )?;
        if self.total_member_weight_bps < self.quorum_weight_bps {
            return Err("pq bridge epoch total member weight below quorum".to_string());
        }
        let expected = pq_bridge_ops_committee_epoch_id(&self.identity_record());
        if self.epoch_id != expected {
            return Err("pq bridge epoch id does not match identity".to_string());
        }
        Ok(self.epoch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSignerShare {
    pub member_id: String,
    pub role: CommitteeRole,
    pub signature_algorithm: PqBridgeAlgorithm,
    pub signature_share_root: String,
    pub readiness_counter: u64,
    pub signer_weight_bps: u64,
    pub signed_at_height: u64,
}

impl ThresholdSignerShare {
    pub fn new(
        member_id: impl Into<String>,
        role: CommitteeRole,
        signature_algorithm: PqBridgeAlgorithm,
        signature_share_root: impl Into<String>,
        readiness_counter: u64,
        signer_weight_bps: u64,
        signed_at_height: u64,
    ) -> PqBridgeOpsResult<Self> {
        let share = Self {
            member_id: member_id.into(),
            role,
            signature_algorithm,
            signature_share_root: signature_share_root.into(),
            readiness_counter,
            signer_weight_bps,
            signed_at_height,
        };
        share.validate()?;
        Ok(share)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_threshold_signer_share",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "role": self.role,
            "signature_algorithm": self.signature_algorithm,
            "signature_share_root": self.signature_share_root,
            "readiness_counter": self.readiness_counter,
            "signer_weight_bps": self.signer_weight_bps,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn share_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-THRESHOLD-SIGNER-SHARE", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.member_id, "pq bridge signer share member id")?;
        ensure_non_empty(&self.signature_share_root, "pq bridge signature share root")?;
        ensure_bps(self.signer_weight_bps, "pq bridge signer share weight")?;
        Ok(self.share_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeThresholdAttestation {
    pub attestation_id: String,
    pub subject_kind: AttestationSubjectKind,
    pub subject_id: String,
    pub subject_root: String,
    pub epoch_id: String,
    pub committee_root: String,
    pub aggregate_algorithm: PqBridgeAlgorithm,
    pub threshold_weight_bps: u64,
    pub observed_weight_bps: u64,
    pub signer_ids: Vec<String>,
    pub signer_share_root: String,
    pub aggregate_signature_root: String,
    pub produced_at_height: u64,
    pub expires_at_height: u64,
    pub status: AttestationStatus,
}

impl PqBridgeThresholdAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: AttestationSubjectKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        epoch_id: impl Into<String>,
        committee_root: impl Into<String>,
        aggregate_algorithm: PqBridgeAlgorithm,
        threshold_weight_bps: u64,
        shares: &[ThresholdSignerShare],
        aggregate_signature_root: impl Into<String>,
        produced_at_height: u64,
        expires_at_height: u64,
    ) -> PqBridgeOpsResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let epoch_id = epoch_id.into();
        let committee_root = committee_root.into();
        let aggregate_signature_root = aggregate_signature_root.into();
        let signer_ids = shares
            .iter()
            .map(|share| share.member_id.clone())
            .collect::<Vec<_>>();
        let observed_weight_bps = shares
            .iter()
            .map(|share| share.signer_weight_bps)
            .sum::<u64>()
            .min(PQ_BRIDGE_OPS_MAX_BPS);
        let signer_share_root = pq_bridge_ops_signer_share_collection_root(shares);
        let status = if observed_weight_bps >= threshold_weight_bps {
            AttestationStatus::ThresholdMet
        } else {
            AttestationStatus::Pending
        };
        let mut attestation = Self {
            attestation_id: String::new(),
            subject_kind,
            subject_id,
            subject_root,
            epoch_id,
            committee_root,
            aggregate_algorithm,
            threshold_weight_bps,
            observed_weight_bps,
            signer_ids,
            signer_share_root,
            aggregate_signature_root,
            produced_at_height,
            expires_at_height,
            status,
        };
        attestation.attestation_id = pq_bridge_ops_attestation_id(&attestation.identity_record());
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_threshold_attestation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "epoch_id": self.epoch_id,
            "committee_root": self.committee_root,
            "aggregate_algorithm": self.aggregate_algorithm,
            "threshold_weight_bps": self.threshold_weight_bps,
            "observed_weight_bps": self.observed_weight_bps,
            "signer_ids": self.signer_ids,
            "signer_share_root": self.signer_share_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_threshold_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "epoch_id": self.epoch_id,
            "committee_root": self.committee_root,
            "aggregate_algorithm": self.aggregate_algorithm,
            "threshold_weight_bps": self.threshold_weight_bps,
            "observed_weight_bps": self.observed_weight_bps,
            "signer_ids": self.signer_ids,
            "signer_share_root": self.signer_share_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn attestation_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-THRESHOLD-ATTESTATION", &self.public_record())
    }

    pub fn threshold_met(&self) -> bool {
        self.observed_weight_bps >= self.threshold_weight_bps && self.status.usable()
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status == AttestationStatus::Pending && height > self.expires_at_height {
            self.status = AttestationStatus::Expired;
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.attestation_id, "pq bridge attestation id")?;
        ensure_non_empty(&self.subject_id, "pq bridge attestation subject id")?;
        ensure_non_empty(&self.subject_root, "pq bridge attestation subject root")?;
        ensure_non_empty(&self.epoch_id, "pq bridge attestation epoch id")?;
        ensure_non_empty(&self.committee_root, "pq bridge attestation committee root")?;
        ensure_bps(
            self.threshold_weight_bps,
            "pq bridge attestation threshold weight",
        )?;
        ensure_bps(
            self.observed_weight_bps,
            "pq bridge attestation observed weight",
        )?;
        ensure_unique_strings(&self.signer_ids, "pq bridge attestation signer ids")?;
        ensure_non_empty(
            &self.signer_share_root,
            "pq bridge attestation signer share root",
        )?;
        ensure_non_empty(
            &self.aggregate_signature_root,
            "pq bridge attestation aggregate signature root",
        )?;
        ensure_ordered_window(
            self.produced_at_height,
            self.expires_at_height,
            "pq bridge attestation validity window",
        )?;
        let expected = pq_bridge_ops_attestation_id(&self.identity_record());
        if self.attestation_id != expected {
            return Err("pq bridge attestation id does not match identity".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroObservation {
    pub observation_id: String,
    pub observation_kind: MoneroObservationKind,
    pub monero_txid_root: String,
    pub key_image_root: String,
    pub output_commitment_root: String,
    pub amount_bucket: u64,
    pub monero_height: u64,
    pub observed_by_member_id: String,
    pub note_root: String,
}

impl MoneroObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_kind: MoneroObservationKind,
        monero_txid_root: impl Into<String>,
        key_image_root: impl Into<String>,
        output_commitment_root: impl Into<String>,
        amount_bucket: u64,
        monero_height: u64,
        observed_by_member_id: impl Into<String>,
        note_root: impl Into<String>,
    ) -> PqBridgeOpsResult<Self> {
        let mut observation = Self {
            observation_id: String::new(),
            observation_kind,
            monero_txid_root: monero_txid_root.into(),
            key_image_root: key_image_root.into(),
            output_commitment_root: output_commitment_root.into(),
            amount_bucket,
            monero_height,
            observed_by_member_id: observed_by_member_id.into(),
            note_root: note_root.into(),
        };
        observation.observation_id = pq_bridge_ops_observation_id(&observation.identity_record());
        observation.validate()?;
        Ok(observation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_monero_observation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "observation_kind": self.observation_kind,
            "monero_txid_root": self.monero_txid_root,
            "key_image_root": self.key_image_root,
            "output_commitment_root": self.output_commitment_root,
            "amount_bucket": self.amount_bucket,
            "monero_height": self.monero_height,
            "observed_by_member_id": self.observed_by_member_id,
            "note_root": self.note_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_monero_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "observation_kind": self.observation_kind,
            "monero_txid_root": self.monero_txid_root,
            "key_image_root": self.key_image_root,
            "output_commitment_root": self.output_commitment_root,
            "amount_bucket": self.amount_bucket,
            "monero_height": self.monero_height,
            "observed_by_member_id": self.observed_by_member_id,
            "note_root": self.note_root,
        })
    }

    pub fn observation_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-MONERO-OBSERVATION", &self.public_record())
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.observation_id, "pq bridge observation id")?;
        ensure_non_empty(&self.monero_txid_root, "pq bridge observation txid root")?;
        ensure_non_empty(&self.key_image_root, "pq bridge observation key image root")?;
        ensure_non_empty(
            &self.output_commitment_root,
            "pq bridge observation output root",
        )?;
        ensure_non_empty(
            &self.observed_by_member_id,
            "pq bridge observation member id",
        )?;
        ensure_non_empty(&self.note_root, "pq bridge observation note root")?;
        let expected = pq_bridge_ops_observation_id(&self.identity_record());
        if self.observation_id != expected {
            return Err("pq bridge observation id does not match identity".to_string());
        }
        Ok(self.observation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroObservationBatch {
    pub batch_id: String,
    pub monero_network: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub observation_ids: Vec<String>,
    pub observation_root: String,
    pub reserve_delta_units: u64,
    pub reserve_delta_direction: ReserveDeltaDirection,
    pub attestation_root: String,
    pub status: ObservationBatchStatus,
}

impl MoneroObservationBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        monero_network: impl Into<String>,
        opened_at_height: u64,
        sealed_at_height: u64,
        monero_start_height: u64,
        monero_end_height: u64,
        observations: &[MoneroObservation],
        reserve_delta_units: u64,
        reserve_delta_direction: ReserveDeltaDirection,
        attestation_root: impl Into<String>,
        status: ObservationBatchStatus,
    ) -> PqBridgeOpsResult<Self> {
        let observation_ids = observations
            .iter()
            .map(|observation| observation.observation_id.clone())
            .collect::<Vec<_>>();
        let observation_root = pq_bridge_ops_observation_collection_root(observations);
        let mut batch = Self {
            batch_id: String::new(),
            monero_network: monero_network.into(),
            opened_at_height,
            sealed_at_height,
            monero_start_height,
            monero_end_height,
            observation_ids,
            observation_root,
            reserve_delta_units,
            reserve_delta_direction,
            attestation_root: attestation_root.into(),
            status,
        };
        batch.batch_id = pq_bridge_ops_observation_batch_id(&batch.identity_record());
        batch.validate()?;
        Ok(batch)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_monero_observation_batch_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "monero_network": self.monero_network,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "observation_ids": self.observation_ids,
            "observation_root": self.observation_root,
            "reserve_delta_units": self.reserve_delta_units,
            "reserve_delta_direction": self.reserve_delta_direction,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_monero_observation_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "monero_network": self.monero_network,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "observation_ids": self.observation_ids,
            "observation_root": self.observation_root,
            "reserve_delta_units": self.reserve_delta_units,
            "reserve_delta_direction": self.reserve_delta_direction,
            "attestation_root": self.attestation_root,
            "status": self.status,
        })
    }

    pub fn subject_root(&self) -> String {
        pq_bridge_ops_payload_root(
            "PQ-BRIDGE-MONERO-OBSERVATION-BATCH-SUBJECT",
            &self.identity_record(),
        )
    }

    pub fn batch_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-MONERO-OBSERVATION-BATCH", &self.public_record())
    }

    pub fn set_attestation_root(&mut self, attestation_root: impl Into<String>) {
        self.attestation_root = attestation_root.into();
        if self.status == ObservationBatchStatus::Sealed {
            self.status = ObservationBatchStatus::Attested;
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.batch_id, "pq bridge observation batch id")?;
        ensure_non_empty(
            &self.monero_network,
            "pq bridge observation batch monero network",
        )?;
        ensure_ordered_window(
            self.opened_at_height,
            self.sealed_at_height,
            "pq bridge observation batch l2 window",
        )?;
        ensure_ordered_window(
            self.monero_start_height,
            self.monero_end_height,
            "pq bridge observation batch monero window",
        )?;
        ensure_unique_strings(
            &self.observation_ids,
            "pq bridge observation batch observation ids",
        )?;
        ensure_non_empty(
            &self.observation_root,
            "pq bridge observation batch observation root",
        )?;
        ensure_non_empty(
            &self.attestation_root,
            "pq bridge observation batch attestation root",
        )?;
        if self.reserve_delta_direction == ReserveDeltaDirection::Neutral
            && self.reserve_delta_units != 0
        {
            return Err("pq bridge neutral reserve delta must be zero".to_string());
        }
        let expected = pq_bridge_ops_observation_batch_id(&self.identity_record());
        if self.batch_id != expected {
            return Err("pq bridge observation batch id does not match identity".to_string());
        }
        Ok(self.batch_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitQueueCommitment {
    pub exit_id: String,
    pub requester_commitment: String,
    pub recipient_address_root: String,
    pub amount_commitment: String,
    pub amount_bucket: u64,
    pub fee_commitment: String,
    pub priority: u64,
    pub nullifier: String,
    pub claim_commitment_root: String,
    pub sponsor_commitment: Option<String>,
    pub enqueued_at_height: u64,
    pub expires_at_height: u64,
    pub attestation_root: String,
    pub status: ExitQueueStatus,
}

impl ExitQueueCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requester_commitment: impl Into<String>,
        recipient_address_root: impl Into<String>,
        amount_commitment: impl Into<String>,
        amount_bucket: u64,
        fee_commitment: impl Into<String>,
        priority: u64,
        nullifier: impl Into<String>,
        claim_commitment_root: impl Into<String>,
        sponsor_commitment: Option<String>,
        enqueued_at_height: u64,
        expires_at_height: u64,
        attestation_root: impl Into<String>,
        status: ExitQueueStatus,
    ) -> PqBridgeOpsResult<Self> {
        let mut exit = Self {
            exit_id: String::new(),
            requester_commitment: requester_commitment.into(),
            recipient_address_root: recipient_address_root.into(),
            amount_commitment: amount_commitment.into(),
            amount_bucket,
            fee_commitment: fee_commitment.into(),
            priority,
            nullifier: nullifier.into(),
            claim_commitment_root: claim_commitment_root.into(),
            sponsor_commitment,
            enqueued_at_height,
            expires_at_height,
            attestation_root: attestation_root.into(),
            status,
        };
        exit.exit_id = pq_bridge_ops_exit_queue_id(&exit.identity_record());
        exit.validate()?;
        Ok(exit)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_exit_queue_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "requester_commitment": self.requester_commitment,
            "recipient_address_root": self.recipient_address_root,
            "amount_commitment": self.amount_commitment,
            "amount_bucket": self.amount_bucket,
            "fee_commitment": self.fee_commitment,
            "priority": self.priority,
            "nullifier": self.nullifier,
            "claim_commitment_root": self.claim_commitment_root,
            "sponsor_commitment": self.sponsor_commitment,
            "enqueued_at_height": self.enqueued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_exit_queue_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "exit_id": self.exit_id,
            "requester_commitment": self.requester_commitment,
            "recipient_address_root": self.recipient_address_root,
            "amount_commitment": self.amount_commitment,
            "amount_bucket": self.amount_bucket,
            "fee_commitment": self.fee_commitment,
            "priority": self.priority,
            "nullifier": self.nullifier,
            "claim_commitment_root": self.claim_commitment_root,
            "sponsor_commitment": self.sponsor_commitment,
            "enqueued_at_height": self.enqueued_at_height,
            "expires_at_height": self.expires_at_height,
            "attestation_root": self.attestation_root,
            "status": self.status,
        })
    }

    pub fn subject_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-EXIT-QUEUE-SUBJECT", &self.identity_record())
    }

    pub fn queue_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-EXIT-QUEUE-COMMITMENT", &self.public_record())
    }

    pub fn set_attestation_root(&mut self, attestation_root: impl Into<String>) {
        self.attestation_root = attestation_root.into();
        if matches!(
            self.status,
            ExitQueueStatus::Queued | ExitQueueStatus::Sponsored
        ) {
            self.status = ExitQueueStatus::Attested;
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.is_open() && height > self.expires_at_height {
            self.status = ExitQueueStatus::Expired;
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.exit_id, "pq bridge exit id")?;
        ensure_non_empty(&self.requester_commitment, "pq bridge exit requester")?;
        ensure_non_empty(
            &self.recipient_address_root,
            "pq bridge exit recipient root",
        )?;
        ensure_non_empty(&self.amount_commitment, "pq bridge exit amount commitment")?;
        ensure_non_empty(&self.fee_commitment, "pq bridge exit fee commitment")?;
        ensure_non_empty(&self.nullifier, "pq bridge exit nullifier")?;
        ensure_non_empty(
            &self.claim_commitment_root,
            "pq bridge exit claim commitment root",
        )?;
        ensure_ordered_window(
            self.enqueued_at_height,
            self.expires_at_height,
            "pq bridge exit queue ttl",
        )?;
        ensure_non_empty(&self.attestation_root, "pq bridge exit attestation root")?;
        if let Some(sponsor) = &self.sponsor_commitment {
            ensure_non_empty(sponsor, "pq bridge exit sponsor commitment")?;
        }
        let expected = pq_bridge_ops_exit_queue_id(&self.identity_record());
        if self.exit_id != expected {
            return Err("pq bridge exit id does not match identity".to_string());
        }
        Ok(self.queue_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyPauseCeremony {
    pub ceremony_id: String,
    pub action: PauseCeremonyAction,
    pub reason_root: String,
    pub initiated_by_member_id: String,
    pub epoch_id: String,
    pub threshold_attestation_root: String,
    pub signer_ids: Vec<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub applied_at_height: Option<u64>,
    pub status: PauseCeremonyStatus,
}

impl EmergencyPauseCeremony {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action: PauseCeremonyAction,
        reason_root: impl Into<String>,
        initiated_by_member_id: impl Into<String>,
        epoch_id: impl Into<String>,
        threshold_attestation_root: impl Into<String>,
        signer_ids: Vec<String>,
        opened_at_height: u64,
        expires_at_height: u64,
        applied_at_height: Option<u64>,
        status: PauseCeremonyStatus,
    ) -> PqBridgeOpsResult<Self> {
        let mut ceremony = Self {
            ceremony_id: String::new(),
            action,
            reason_root: reason_root.into(),
            initiated_by_member_id: initiated_by_member_id.into(),
            epoch_id: epoch_id.into(),
            threshold_attestation_root: threshold_attestation_root.into(),
            signer_ids,
            opened_at_height,
            expires_at_height,
            applied_at_height,
            status,
        };
        ceremony.ceremony_id = pq_bridge_ops_pause_ceremony_id(&ceremony.identity_record());
        ceremony.validate()?;
        Ok(ceremony)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_emergency_pause_ceremony_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "action": self.action,
            "reason_root": self.reason_root,
            "initiated_by_member_id": self.initiated_by_member_id,
            "epoch_id": self.epoch_id,
            "signer_ids": self.signer_ids,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_emergency_pause_ceremony",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "ceremony_id": self.ceremony_id,
            "action": self.action,
            "reason_root": self.reason_root,
            "initiated_by_member_id": self.initiated_by_member_id,
            "epoch_id": self.epoch_id,
            "threshold_attestation_root": self.threshold_attestation_root,
            "signer_ids": self.signer_ids,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "applied_at_height": self.applied_at_height,
            "status": self.status,
        })
    }

    pub fn subject_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-PAUSE-CEREMONY-SUBJECT", &self.identity_record())
    }

    pub fn ceremony_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-EMERGENCY-PAUSE-CEREMONY", &self.public_record())
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.status,
            PauseCeremonyStatus::Proposed | PauseCeremonyStatus::ThresholdMet
        ) && height > self.expires_at_height
        {
            self.status = PauseCeremonyStatus::Expired;
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.ceremony_id, "pq bridge pause ceremony id")?;
        ensure_non_empty(&self.reason_root, "pq bridge pause reason root")?;
        ensure_non_empty(&self.initiated_by_member_id, "pq bridge pause initiator id")?;
        ensure_non_empty(&self.epoch_id, "pq bridge pause epoch id")?;
        ensure_non_empty(
            &self.threshold_attestation_root,
            "pq bridge pause attestation root",
        )?;
        ensure_unique_strings(&self.signer_ids, "pq bridge pause signer ids")?;
        ensure_ordered_window(
            self.opened_at_height,
            self.expires_at_height,
            "pq bridge pause ceremony window",
        )?;
        if let Some(applied_at_height) = self.applied_at_height {
            if applied_at_height < self.opened_at_height {
                return Err("pq bridge pause applied height before open height".to_string());
            }
        }
        let expected = pq_bridge_ops_pause_ceremony_id(&self.identity_record());
        if self.ceremony_id != expected {
            return Err("pq bridge pause ceremony id does not match identity".to_string());
        }
        Ok(self.ceremony_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashableEquivocationEvidence {
    pub evidence_id: String,
    pub offender_member_id: String,
    pub subject_kind: AttestationSubjectKind,
    pub first_subject_id: String,
    pub second_subject_id: String,
    pub first_statement_root: String,
    pub second_statement_root: String,
    pub witness_root: String,
    pub reporter_commitment: String,
    pub reported_at_height: u64,
    pub expires_at_height: u64,
    pub slash_weight_bps: u64,
    pub status: EquivocationEvidenceStatus,
}

impl SlashableEquivocationEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        offender_member_id: impl Into<String>,
        subject_kind: AttestationSubjectKind,
        first_subject_id: impl Into<String>,
        second_subject_id: impl Into<String>,
        first_statement_root: impl Into<String>,
        second_statement_root: impl Into<String>,
        witness_root: impl Into<String>,
        reporter_commitment: impl Into<String>,
        reported_at_height: u64,
        expires_at_height: u64,
        slash_weight_bps: u64,
        status: EquivocationEvidenceStatus,
    ) -> PqBridgeOpsResult<Self> {
        let mut evidence = Self {
            evidence_id: String::new(),
            offender_member_id: offender_member_id.into(),
            subject_kind,
            first_subject_id: first_subject_id.into(),
            second_subject_id: second_subject_id.into(),
            first_statement_root: first_statement_root.into(),
            second_statement_root: second_statement_root.into(),
            witness_root: witness_root.into(),
            reporter_commitment: reporter_commitment.into(),
            reported_at_height,
            expires_at_height,
            slash_weight_bps,
            status,
        };
        evidence.evidence_id = pq_bridge_ops_equivocation_evidence_id(&evidence.identity_record());
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_equivocation_evidence_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "offender_member_id": self.offender_member_id,
            "subject_kind": self.subject_kind,
            "first_subject_id": self.first_subject_id,
            "second_subject_id": self.second_subject_id,
            "first_statement_root": self.first_statement_root,
            "second_statement_root": self.second_statement_root,
            "witness_root": self.witness_root,
            "reporter_commitment": self.reporter_commitment,
            "reported_at_height": self.reported_at_height,
            "expires_at_height": self.expires_at_height,
            "slash_weight_bps": self.slash_weight_bps,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_equivocation_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "offender_member_id": self.offender_member_id,
            "subject_kind": self.subject_kind,
            "first_subject_id": self.first_subject_id,
            "second_subject_id": self.second_subject_id,
            "first_statement_root": self.first_statement_root,
            "second_statement_root": self.second_statement_root,
            "witness_root": self.witness_root,
            "reporter_commitment": self.reporter_commitment,
            "reported_at_height": self.reported_at_height,
            "expires_at_height": self.expires_at_height,
            "slash_weight_bps": self.slash_weight_bps,
            "status": self.status,
        })
    }

    pub fn evidence_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-EQUIVOCATION-EVIDENCE", &self.public_record())
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.status,
            EquivocationEvidenceStatus::Reported | EquivocationEvidenceStatus::Verified
        ) && height > self.expires_at_height
        {
            self.status = EquivocationEvidenceStatus::Expired;
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.evidence_id, "pq bridge equivocation evidence id")?;
        ensure_non_empty(
            &self.offender_member_id,
            "pq bridge equivocation offender id",
        )?;
        ensure_non_empty(
            &self.first_subject_id,
            "pq bridge equivocation first subject id",
        )?;
        ensure_non_empty(
            &self.second_subject_id,
            "pq bridge equivocation second subject id",
        )?;
        ensure_non_empty(
            &self.first_statement_root,
            "pq bridge equivocation first statement root",
        )?;
        ensure_non_empty(
            &self.second_statement_root,
            "pq bridge equivocation second statement root",
        )?;
        ensure_non_empty(&self.witness_root, "pq bridge equivocation witness root")?;
        ensure_non_empty(
            &self.reporter_commitment,
            "pq bridge equivocation reporter commitment",
        )?;
        ensure_ordered_window(
            self.reported_at_height,
            self.expires_at_height,
            "pq bridge equivocation report window",
        )?;
        ensure_bps(self.slash_weight_bps, "pq bridge equivocation slash weight")?;
        if self.first_subject_id == self.second_subject_id
            && self.first_statement_root == self.second_statement_root
        {
            return Err("pq bridge equivocation evidence statements are identical".to_string());
        }
        let expected = pq_bridge_ops_equivocation_evidence_id(&self.identity_record());
        if self.evidence_id != expected {
            return Err("pq bridge equivocation evidence id does not match identity".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveDeltaCheckpoint {
    pub checkpoint_id: String,
    pub previous_checkpoint_id: Option<String>,
    pub monero_network: String,
    pub asset_id: String,
    pub observed_batch_ids: Vec<String>,
    pub previous_reserve_root: String,
    pub new_reserve_root: String,
    pub delta_direction: ReserveDeltaDirection,
    pub delta_units: u64,
    pub liabilities_units: u64,
    pub reserve_units: u64,
    pub coverage_bps: u64,
    pub attestation_root: String,
    pub produced_at_height: u64,
    pub status: ReserveCheckpointStatus,
}

impl ReserveDeltaCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        previous_checkpoint_id: Option<String>,
        monero_network: impl Into<String>,
        asset_id: impl Into<String>,
        observed_batch_ids: Vec<String>,
        previous_reserve_root: impl Into<String>,
        new_reserve_root: impl Into<String>,
        delta_direction: ReserveDeltaDirection,
        delta_units: u64,
        liabilities_units: u64,
        reserve_units: u64,
        attestation_root: impl Into<String>,
        produced_at_height: u64,
        status: ReserveCheckpointStatus,
    ) -> PqBridgeOpsResult<Self> {
        let coverage_bps = reserve_coverage_bps(reserve_units, liabilities_units);
        let mut checkpoint = Self {
            checkpoint_id: String::new(),
            previous_checkpoint_id,
            monero_network: monero_network.into(),
            asset_id: asset_id.into(),
            observed_batch_ids,
            previous_reserve_root: previous_reserve_root.into(),
            new_reserve_root: new_reserve_root.into(),
            delta_direction,
            delta_units,
            liabilities_units,
            reserve_units,
            coverage_bps,
            attestation_root: attestation_root.into(),
            produced_at_height,
            status,
        };
        checkpoint.checkpoint_id =
            pq_bridge_ops_reserve_checkpoint_id(&checkpoint.identity_record());
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_reserve_delta_checkpoint_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "previous_checkpoint_id": self.previous_checkpoint_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "observed_batch_ids": self.observed_batch_ids,
            "previous_reserve_root": self.previous_reserve_root,
            "new_reserve_root": self.new_reserve_root,
            "delta_direction": self.delta_direction,
            "delta_units": self.delta_units,
            "liabilities_units": self.liabilities_units,
            "reserve_units": self.reserve_units,
            "coverage_bps": self.coverage_bps,
            "produced_at_height": self.produced_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_reserve_delta_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "previous_checkpoint_id": self.previous_checkpoint_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "observed_batch_ids": self.observed_batch_ids,
            "previous_reserve_root": self.previous_reserve_root,
            "new_reserve_root": self.new_reserve_root,
            "delta_direction": self.delta_direction,
            "delta_units": self.delta_units,
            "liabilities_units": self.liabilities_units,
            "reserve_units": self.reserve_units,
            "coverage_bps": self.coverage_bps,
            "attestation_root": self.attestation_root,
            "produced_at_height": self.produced_at_height,
            "status": self.status,
        })
    }

    pub fn subject_root(&self) -> String {
        pq_bridge_ops_payload_root(
            "PQ-BRIDGE-RESERVE-DELTA-CHECKPOINT-SUBJECT",
            &self.identity_record(),
        )
    }

    pub fn checkpoint_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-RESERVE-DELTA-CHECKPOINT", &self.public_record())
    }

    pub fn set_attestation_root(&mut self, attestation_root: impl Into<String>) {
        self.attestation_root = attestation_root.into();
        if self.status == ReserveCheckpointStatus::Proposed {
            self.status = ReserveCheckpointStatus::Attested;
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.checkpoint_id, "pq bridge reserve checkpoint id")?;
        if let Some(previous) = &self.previous_checkpoint_id {
            ensure_non_empty(previous, "pq bridge previous reserve checkpoint id")?;
        }
        ensure_non_empty(
            &self.monero_network,
            "pq bridge reserve checkpoint monero network",
        )?;
        ensure_non_empty(&self.asset_id, "pq bridge reserve checkpoint asset id")?;
        ensure_unique_strings(
            &self.observed_batch_ids,
            "pq bridge reserve checkpoint batch ids",
        )?;
        ensure_non_empty(
            &self.previous_reserve_root,
            "pq bridge previous reserve root",
        )?;
        ensure_non_empty(&self.new_reserve_root, "pq bridge new reserve root")?;
        ensure_bps(self.coverage_bps, "pq bridge reserve coverage bps")?;
        ensure_non_empty(
            &self.attestation_root,
            "pq bridge reserve checkpoint attestation root",
        )?;
        if self.delta_direction == ReserveDeltaDirection::Neutral && self.delta_units != 0 {
            return Err("pq bridge neutral checkpoint delta must be zero".to_string());
        }
        let expected = pq_bridge_ops_reserve_checkpoint_id(&self.identity_record());
        if self.checkpoint_id != expected {
            return Err("pq bridge reserve checkpoint id does not match identity".to_string());
        }
        Ok(self.checkpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyWithdrawalClaim {
    pub claim_id: String,
    pub exit_id: String,
    pub claimant_commitment: String,
    pub recipient_view_tag_root: String,
    pub amount_bucket: u64,
    pub nullifier: String,
    pub key_image_root: String,
    pub membership_proof_root: String,
    pub spend_authorization_root: String,
    pub attestation_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: WithdrawalClaimStatus,
}

impl PrivacyWithdrawalClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exit_id: impl Into<String>,
        claimant_commitment: impl Into<String>,
        recipient_view_tag_root: impl Into<String>,
        amount_bucket: u64,
        nullifier: impl Into<String>,
        key_image_root: impl Into<String>,
        membership_proof_root: impl Into<String>,
        spend_authorization_root: impl Into<String>,
        attestation_root: impl Into<String>,
        submitted_at_height: u64,
        expires_at_height: u64,
        status: WithdrawalClaimStatus,
    ) -> PqBridgeOpsResult<Self> {
        let mut claim = Self {
            claim_id: String::new(),
            exit_id: exit_id.into(),
            claimant_commitment: claimant_commitment.into(),
            recipient_view_tag_root: recipient_view_tag_root.into(),
            amount_bucket,
            nullifier: nullifier.into(),
            key_image_root: key_image_root.into(),
            membership_proof_root: membership_proof_root.into(),
            spend_authorization_root: spend_authorization_root.into(),
            attestation_root: attestation_root.into(),
            submitted_at_height,
            expires_at_height,
            status,
        };
        claim.claim_id = pq_bridge_ops_withdrawal_claim_id(&claim.identity_record());
        claim.validate()?;
        Ok(claim)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_withdrawal_claim_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "exit_id": self.exit_id,
            "claimant_commitment": self.claimant_commitment,
            "recipient_view_tag_root": self.recipient_view_tag_root,
            "amount_bucket": self.amount_bucket,
            "nullifier": self.nullifier,
            "key_image_root": self.key_image_root,
            "membership_proof_root": self.membership_proof_root,
            "spend_authorization_root": self.spend_authorization_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_withdrawal_claim",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "claim_id": self.claim_id,
            "exit_id": self.exit_id,
            "claimant_commitment": self.claimant_commitment,
            "recipient_view_tag_root": self.recipient_view_tag_root,
            "amount_bucket": self.amount_bucket,
            "nullifier": self.nullifier,
            "key_image_root": self.key_image_root,
            "membership_proof_root": self.membership_proof_root,
            "spend_authorization_root": self.spend_authorization_root,
            "attestation_root": self.attestation_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn subject_root(&self) -> String {
        pq_bridge_ops_payload_root(
            "PQ-BRIDGE-WITHDRAWAL-CLAIM-SUBJECT",
            &self.identity_record(),
        )
    }

    pub fn claim_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-WITHDRAWAL-CLAIM", &self.public_record())
    }

    pub fn set_attestation_root(&mut self, attestation_root: impl Into<String>) {
        self.attestation_root = attestation_root.into();
        if matches!(
            self.status,
            WithdrawalClaimStatus::Submitted | WithdrawalClaimStatus::NullifierReserved
        ) {
            self.status = WithdrawalClaimStatus::Attested;
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.status,
            WithdrawalClaimStatus::Submitted
                | WithdrawalClaimStatus::NullifierReserved
                | WithdrawalClaimStatus::Attested
                | WithdrawalClaimStatus::Ready
        ) && height > self.expires_at_height
        {
            self.status = WithdrawalClaimStatus::Expired;
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.claim_id, "pq bridge claim id")?;
        ensure_non_empty(&self.exit_id, "pq bridge claim exit id")?;
        ensure_non_empty(&self.claimant_commitment, "pq bridge claimant commitment")?;
        ensure_non_empty(
            &self.recipient_view_tag_root,
            "pq bridge claim recipient view tag root",
        )?;
        ensure_non_empty(&self.nullifier, "pq bridge claim nullifier")?;
        ensure_non_empty(&self.key_image_root, "pq bridge claim key image root")?;
        ensure_non_empty(
            &self.membership_proof_root,
            "pq bridge claim membership proof root",
        )?;
        ensure_non_empty(
            &self.spend_authorization_root,
            "pq bridge claim spend authorization root",
        )?;
        ensure_non_empty(&self.attestation_root, "pq bridge claim attestation root")?;
        ensure_ordered_window(
            self.submitted_at_height,
            self.expires_at_height,
            "pq bridge claim ttl",
        )?;
        let expected = pq_bridge_ops_withdrawal_claim_id(&self.identity_record());
        if self.claim_id != expected {
            return Err("pq bridge claim id does not match identity".to_string());
        }
        Ok(self.claim_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayNullifierEntry {
    pub entry_id: String,
    pub nullifier: String,
    pub key_image_root: String,
    pub subject_kind: AttestationSubjectKind,
    pub subject_id: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub status: ReplayEntryStatus,
}

impl ReplayNullifierEntry {
    pub fn new(
        nullifier: impl Into<String>,
        key_image_root: impl Into<String>,
        subject_kind: AttestationSubjectKind,
        subject_id: impl Into<String>,
        first_seen_height: u64,
        expires_at_height: u64,
        status: ReplayEntryStatus,
    ) -> PqBridgeOpsResult<Self> {
        let mut entry = Self {
            entry_id: String::new(),
            nullifier: nullifier.into(),
            key_image_root: key_image_root.into(),
            subject_kind,
            subject_id: subject_id.into(),
            first_seen_height,
            expires_at_height,
            status,
        };
        entry.entry_id = pq_bridge_ops_replay_entry_id(&entry.identity_record());
        entry.validate()?;
        Ok(entry)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_replay_nullifier_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "nullifier": self.nullifier,
            "key_image_root": self.key_image_root,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_replay_nullifier_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "entry_id": self.entry_id,
            "nullifier": self.nullifier,
            "key_image_root": self.key_image_root,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn entry_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-REPLAY-NULLIFIER-ENTRY", &self.public_record())
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.blocks_replay() && height > self.expires_at_height {
            self.status = ReplayEntryStatus::Expired;
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.entry_id, "pq bridge replay entry id")?;
        ensure_non_empty(&self.nullifier, "pq bridge replay nullifier")?;
        ensure_non_empty(&self.key_image_root, "pq bridge replay key image root")?;
        ensure_non_empty(&self.subject_id, "pq bridge replay subject id")?;
        ensure_ordered_window(
            self.first_seen_height,
            self.expires_at_height,
            "pq bridge replay retention window",
        )?;
        let expected = pq_bridge_ops_replay_entry_id(&self.identity_record());
        if self.entry_id != expected {
            return Err("pq bridge replay entry id does not match identity".to_string());
        }
        Ok(self.entry_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExitSponsorRebate {
    pub rebate_id: String,
    pub sponsor_commitment: String,
    pub exit_id: String,
    pub claim_id: String,
    pub fee_asset_id: String,
    pub rebate_units: u64,
    pub max_rebate_units: u64,
    pub eligibility_root: String,
    pub privacy_budget_bps: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
    pub status: SponsorRebateStatus,
}

impl LowFeeExitSponsorRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        exit_id: impl Into<String>,
        claim_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        rebate_units: u64,
        max_rebate_units: u64,
        eligibility_root: impl Into<String>,
        privacy_budget_bps: u64,
        reserved_at_height: u64,
        expires_at_height: u64,
        settled_at_height: Option<u64>,
        status: SponsorRebateStatus,
    ) -> PqBridgeOpsResult<Self> {
        let mut rebate = Self {
            rebate_id: String::new(),
            sponsor_commitment: sponsor_commitment.into(),
            exit_id: exit_id.into(),
            claim_id: claim_id.into(),
            fee_asset_id: fee_asset_id.into(),
            rebate_units,
            max_rebate_units,
            eligibility_root: eligibility_root.into(),
            privacy_budget_bps,
            reserved_at_height,
            expires_at_height,
            settled_at_height,
            status,
        };
        rebate.rebate_id = pq_bridge_ops_sponsor_rebate_id(&rebate.identity_record());
        rebate.validate()?;
        Ok(rebate)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_low_fee_sponsor_rebate_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "sponsor_commitment": self.sponsor_commitment,
            "exit_id": self.exit_id,
            "claim_id": self.claim_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_units": self.rebate_units,
            "max_rebate_units": self.max_rebate_units,
            "eligibility_root": self.eligibility_root,
            "privacy_budget_bps": self.privacy_budget_bps,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_low_fee_sponsor_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "sponsor_commitment": self.sponsor_commitment,
            "exit_id": self.exit_id,
            "claim_id": self.claim_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_units": self.rebate_units,
            "max_rebate_units": self.max_rebate_units,
            "eligibility_root": self.eligibility_root,
            "privacy_budget_bps": self.privacy_budget_bps,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }

    pub fn subject_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-SPONSOR-REBATE-SUBJECT", &self.identity_record())
    }

    pub fn rebate_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-LOW-FEE-SPONSOR-REBATE", &self.public_record())
    }

    pub fn set_height(&mut self, height: u64) {
        if matches!(
            self.status,
            SponsorRebateStatus::Offered | SponsorRebateStatus::Reserved
        ) && height > self.expires_at_height
        {
            self.status = SponsorRebateStatus::Expired;
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.rebate_id, "pq bridge sponsor rebate id")?;
        ensure_non_empty(
            &self.sponsor_commitment,
            "pq bridge sponsor rebate commitment",
        )?;
        ensure_non_empty(&self.exit_id, "pq bridge sponsor rebate exit id")?;
        ensure_non_empty(&self.claim_id, "pq bridge sponsor rebate claim id")?;
        ensure_non_empty(&self.fee_asset_id, "pq bridge sponsor rebate fee asset")?;
        ensure_non_empty(
            &self.eligibility_root,
            "pq bridge sponsor rebate eligibility root",
        )?;
        ensure_bps(
            self.privacy_budget_bps,
            "pq bridge sponsor rebate privacy budget",
        )?;
        ensure_ordered_window(
            self.reserved_at_height,
            self.expires_at_height,
            "pq bridge sponsor rebate ttl",
        )?;
        if self.rebate_units > self.max_rebate_units {
            return Err("pq bridge sponsor rebate exceeds max rebate units".to_string());
        }
        if let Some(settled_at_height) = self.settled_at_height {
            if settled_at_height < self.reserved_at_height {
                return Err("pq bridge sponsor rebate settled before reserved".to_string());
            }
        }
        let expected = pq_bridge_ops_sponsor_rebate_id(&self.identity_record());
        if self.rebate_id != expected {
            return Err("pq bridge sponsor rebate id does not match identity".to_string());
        }
        Ok(self.rebate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorReadinessCounter {
    pub counter_id: String,
    pub member_id: String,
    pub epoch_id: String,
    pub ready_rounds: u64,
    pub missed_rounds: u64,
    pub stale_rounds: u64,
    pub last_observed_height: u64,
    pub last_ready_height: u64,
    pub readiness_root: String,
    pub status: ReadinessStatus,
}

impl OperatorReadinessCounter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        member_id: impl Into<String>,
        epoch_id: impl Into<String>,
        ready_rounds: u64,
        missed_rounds: u64,
        stale_rounds: u64,
        last_observed_height: u64,
        last_ready_height: u64,
        readiness_root: impl Into<String>,
        status: ReadinessStatus,
    ) -> PqBridgeOpsResult<Self> {
        let mut counter = Self {
            counter_id: String::new(),
            member_id: member_id.into(),
            epoch_id: epoch_id.into(),
            ready_rounds,
            missed_rounds,
            stale_rounds,
            last_observed_height,
            last_ready_height,
            readiness_root: readiness_root.into(),
            status,
        };
        counter.counter_id = pq_bridge_ops_readiness_counter_id(&counter.identity_record());
        counter.validate()?;
        Ok(counter)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_operator_readiness_counter_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "epoch_id": self.epoch_id,
            "last_observed_height": self.last_observed_height,
            "readiness_root": self.readiness_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_operator_readiness_counter",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "counter_id": self.counter_id,
            "member_id": self.member_id,
            "epoch_id": self.epoch_id,
            "ready_rounds": self.ready_rounds,
            "missed_rounds": self.missed_rounds,
            "stale_rounds": self.stale_rounds,
            "last_observed_height": self.last_observed_height,
            "last_ready_height": self.last_ready_height,
            "readiness_root": self.readiness_root,
            "readiness_score_bps": self.readiness_score_bps(),
            "status": self.status,
        })
    }

    pub fn subject_root(&self) -> String {
        pq_bridge_ops_payload_root(
            "PQ-BRIDGE-OPERATOR-READINESS-SUBJECT",
            &self.identity_record(),
        )
    }

    pub fn counter_root(&self) -> String {
        pq_bridge_ops_payload_root(
            "PQ-BRIDGE-OPERATOR-READINESS-COUNTER",
            &self.public_record(),
        )
    }

    pub fn readiness_score_bps(&self) -> u64 {
        let total = self
            .ready_rounds
            .saturating_add(self.missed_rounds)
            .saturating_add(self.stale_rounds);
        if total == 0 {
            0
        } else {
            self.ready_rounds
                .saturating_mul(PQ_BRIDGE_OPS_MAX_BPS)
                .saturating_div(total)
        }
    }

    pub fn mark_stale_if_needed(&mut self, height: u64, stale_after_blocks: u64) {
        if height > self.last_observed_height.saturating_add(stale_after_blocks)
            && self.status == ReadinessStatus::Ready
        {
            self.status = ReadinessStatus::Degraded;
            self.stale_rounds = self.stale_rounds.saturating_add(1);
        }
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&self.counter_id, "pq bridge readiness counter id")?;
        ensure_non_empty(&self.member_id, "pq bridge readiness member id")?;
        ensure_non_empty(&self.epoch_id, "pq bridge readiness epoch id")?;
        ensure_non_empty(&self.readiness_root, "pq bridge readiness root")?;
        if self.last_ready_height > self.last_observed_height {
            return Err("pq bridge readiness ready height after observed height".to_string());
        }
        let expected = pq_bridge_ops_readiness_counter_id(&self.identity_record());
        if self.counter_id != expected {
            return Err("pq bridge readiness counter id does not match identity".to_string());
        }
        Ok(self.counter_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeOpsRoots {
    pub config_root: String,
    pub committee_member_root: String,
    pub committee_epoch_root: String,
    pub attestation_root: String,
    pub observation_root: String,
    pub observation_batch_root: String,
    pub exit_queue_root: String,
    pub pause_ceremony_root: String,
    pub equivocation_evidence_root: String,
    pub reserve_checkpoint_root: String,
    pub withdrawal_claim_root: String,
    pub replay_registry_root: String,
    pub sponsor_rebate_root: String,
    pub readiness_counter_root: String,
    pub public_record_root: String,
}

impl PqBridgeOpsRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_ops_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "committee_member_root": self.committee_member_root,
            "committee_epoch_root": self.committee_epoch_root,
            "attestation_root": self.attestation_root,
            "observation_root": self.observation_root,
            "observation_batch_root": self.observation_batch_root,
            "exit_queue_root": self.exit_queue_root,
            "pause_ceremony_root": self.pause_ceremony_root,
            "equivocation_evidence_root": self.equivocation_evidence_root,
            "reserve_checkpoint_root": self.reserve_checkpoint_root,
            "withdrawal_claim_root": self.withdrawal_claim_root,
            "replay_registry_root": self.replay_registry_root,
            "sponsor_rebate_root": self.sponsor_rebate_root,
            "readiness_counter_root": self.readiness_counter_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        pq_bridge_ops_payload_root("PQ-BRIDGE-OPS-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeOpsCounters {
    pub height: u64,
    pub paused: bool,
    pub committee_member_count: u64,
    pub active_committee_member_count: u64,
    pub committee_epoch_count: u64,
    pub active_epoch_count: u64,
    pub attestation_count: u64,
    pub threshold_attestation_count: u64,
    pub observation_count: u64,
    pub observation_batch_count: u64,
    pub finalized_observation_batch_count: u64,
    pub queued_exit_count: u64,
    pub ready_exit_count: u64,
    pub withdrawal_claim_count: u64,
    pub replay_entry_count: u64,
    pub blocked_replay_count: u64,
    pub pause_ceremony_count: u64,
    pub applied_pause_count: u64,
    pub equivocation_evidence_count: u64,
    pub slashable_evidence_count: u64,
    pub reserve_checkpoint_count: u64,
    pub sponsor_rebate_count: u64,
    pub applied_rebate_units: u64,
    pub readiness_counter_count: u64,
    pub ready_operator_count: u64,
    pub total_reserve_units: u64,
    pub total_liabilities_units: u64,
    pub reserve_coverage_bps: u64,
}

impl PqBridgeOpsCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_bridge_ops_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "height": self.height,
            "paused": self.paused,
            "committee_member_count": self.committee_member_count,
            "active_committee_member_count": self.active_committee_member_count,
            "committee_epoch_count": self.committee_epoch_count,
            "active_epoch_count": self.active_epoch_count,
            "attestation_count": self.attestation_count,
            "threshold_attestation_count": self.threshold_attestation_count,
            "observation_count": self.observation_count,
            "observation_batch_count": self.observation_batch_count,
            "finalized_observation_batch_count": self.finalized_observation_batch_count,
            "queued_exit_count": self.queued_exit_count,
            "ready_exit_count": self.ready_exit_count,
            "withdrawal_claim_count": self.withdrawal_claim_count,
            "replay_entry_count": self.replay_entry_count,
            "blocked_replay_count": self.blocked_replay_count,
            "pause_ceremony_count": self.pause_ceremony_count,
            "applied_pause_count": self.applied_pause_count,
            "equivocation_evidence_count": self.equivocation_evidence_count,
            "slashable_evidence_count": self.slashable_evidence_count,
            "reserve_checkpoint_count": self.reserve_checkpoint_count,
            "sponsor_rebate_count": self.sponsor_rebate_count,
            "applied_rebate_units": self.applied_rebate_units,
            "readiness_counter_count": self.readiness_counter_count,
            "ready_operator_count": self.ready_operator_count,
            "total_reserve_units": self.total_reserve_units,
            "total_liabilities_units": self.total_liabilities_units,
            "reserve_coverage_bps": self.reserve_coverage_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBridgeOpsState {
    pub height: u64,
    pub paused: bool,
    pub active_epoch_id: Option<String>,
    pub config: PqBridgeOpsConfig,
    pub committee_members: BTreeMap<String, CommitteeMember>,
    pub committee_epochs: BTreeMap<String, PqBridgeCommitteeEpoch>,
    pub attestations: BTreeMap<String, PqBridgeThresholdAttestation>,
    pub observations: BTreeMap<String, MoneroObservation>,
    pub observation_batches: BTreeMap<String, MoneroObservationBatch>,
    pub exit_queue: BTreeMap<String, ExitQueueCommitment>,
    pub pause_ceremonies: BTreeMap<String, EmergencyPauseCeremony>,
    pub equivocation_evidence: BTreeMap<String, SlashableEquivocationEvidence>,
    pub reserve_checkpoints: BTreeMap<String, ReserveDeltaCheckpoint>,
    pub withdrawal_claims: BTreeMap<String, PrivacyWithdrawalClaim>,
    pub replay_registry: BTreeMap<String, ReplayNullifierEntry>,
    pub replay_index: BTreeMap<String, String>,
    pub key_image_index: BTreeMap<String, String>,
    pub sponsor_rebates: BTreeMap<String, LowFeeExitSponsorRebate>,
    pub readiness_counters: BTreeMap<String, OperatorReadinessCounter>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for PqBridgeOpsState {
    fn default() -> Self {
        Self::new(PqBridgeOpsConfig::default()).expect("default pq bridge ops config")
    }
}

impl PqBridgeOpsState {
    pub fn new(config: PqBridgeOpsConfig) -> PqBridgeOpsResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            paused: false,
            active_epoch_id: None,
            config,
            committee_members: BTreeMap::new(),
            committee_epochs: BTreeMap::new(),
            attestations: BTreeMap::new(),
            observations: BTreeMap::new(),
            observation_batches: BTreeMap::new(),
            exit_queue: BTreeMap::new(),
            pause_ceremonies: BTreeMap::new(),
            equivocation_evidence: BTreeMap::new(),
            reserve_checkpoints: BTreeMap::new(),
            withdrawal_claims: BTreeMap::new(),
            replay_registry: BTreeMap::new(),
            replay_index: BTreeMap::new(),
            key_image_index: BTreeMap::new(),
            sponsor_rebates: BTreeMap::new(),
            readiness_counters: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> PqBridgeOpsResult<Self> {
        let mut state = Self::new(PqBridgeOpsConfig::default())?;
        state.set_height(PQ_BRIDGE_OPS_DEVNET_HEIGHT);

        let member_a = CommitteeMember::new(
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-OPERATOR", "operator-a"),
            "devnet-pq-bridge-operator-a",
            vec![
                CommitteeRole::Observer,
                CommitteeRole::Attester,
                CommitteeRole::ExitScheduler,
                CommitteeRole::EmergencyGuardian,
            ],
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-KYBER", "operator-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-FALCON", "operator-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-DILITHIUM", "operator-a"),
            3_700,
            3_700,
            64,
            0,
            ReadinessStatus::Ready,
        )?;
        let member_b = CommitteeMember::new(
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-OPERATOR", "operator-b"),
            "devnet-pq-bridge-operator-b",
            vec![
                CommitteeRole::Observer,
                CommitteeRole::Attester,
                CommitteeRole::ReserveAuditor,
                CommitteeRole::EmergencyGuardian,
            ],
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-KYBER", "operator-b"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-FALCON", "operator-b"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-DILITHIUM", "operator-b"),
            3_500,
            3_500,
            64,
            0,
            ReadinessStatus::Ready,
        )?;
        let member_c = CommitteeMember::new(
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-OPERATOR", "operator-c"),
            "devnet-pq-bridge-operator-c",
            vec![
                CommitteeRole::Observer,
                CommitteeRole::Attester,
                CommitteeRole::SponsorAuditor,
                CommitteeRole::EmergencyGuardian,
            ],
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-KYBER", "operator-c"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-FALCON", "operator-c"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-DILITHIUM", "operator-c"),
            2_800,
            2_800,
            64,
            0,
            ReadinessStatus::Ready,
        )?;
        let member_a_id = member_a.member_id.clone();
        let member_b_id = member_b.member_id.clone();
        let member_c_id = member_c.member_id.clone();
        state.insert_committee_member(member_a)?;
        state.insert_committee_member(member_b)?;
        state.insert_committee_member(member_c)?;

        let members = state
            .committee_members
            .values()
            .cloned()
            .collect::<Vec<CommitteeMember>>();
        let epoch = PqBridgeCommitteeEpoch::new(
            0,
            96,
            state.config.epoch_duration_blocks.saturating_add(96),
            state
                .config
                .epoch_duration_blocks
                .saturating_add(96)
                .saturating_add(state.config.epoch_grace_blocks),
            state.config.min_committee_weight_bps,
            state.config.emergency_pause_quorum,
            vec![
                PqBridgeAlgorithm::KyberKem,
                PqBridgeAlgorithm::FalconSignature,
                PqBridgeAlgorithm::DilithiumSignature,
                PqBridgeAlgorithm::HybridThreshold,
            ],
            &members,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-PREVIOUS-EPOCH", "genesis"),
            CommitteeEpochStatus::Active,
        )?;
        let epoch_id = epoch.epoch_id.clone();
        let epoch_subject_root = epoch.subject_root();
        let epoch_committee_root = epoch.member_root.clone();
        state.insert_committee_epoch(epoch)?;
        state.active_epoch_id = Some(epoch_id.clone());

        let shares = state.devnet_signer_shares(
            &[
                member_a_id.clone(),
                member_b_id.clone(),
                member_c_id.clone(),
            ],
            CommitteeRole::Attester,
            PqBridgeAlgorithm::DilithiumSignature,
            "epoch-0",
            state.height.saturating_sub(80),
        )?;
        let epoch_attestation = PqBridgeThresholdAttestation::new(
            AttestationSubjectKind::CommitteeEpoch,
            &epoch_id,
            &epoch_subject_root,
            &epoch_id,
            &epoch_committee_root,
            PqBridgeAlgorithm::HybridThreshold,
            state.config.min_attestation_weight_bps,
            &shares,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-AGGREGATE-SIGNATURE", "epoch-0"),
            state.height.saturating_sub(80),
            state.height.saturating_add(1_000),
        )?;
        state.insert_attestation(epoch_attestation)?;

        let obs_a = MoneroObservation::new(
            MoneroObservationKind::Deposit,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-MONERO-TX", "deposit-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-KEY-IMAGE", "deposit-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-OUTPUT", "deposit-a"),
            120_000,
            80,
            &member_a_id,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-OBS-NOTE", "deposit-a"),
        )?;
        let obs_b = MoneroObservation::new(
            MoneroObservationKind::ReserveScan,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-MONERO-TX", "reserve-scan-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-KEY-IMAGE", "reserve-scan-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-OUTPUT", "reserve-scan-a"),
            0,
            81,
            &member_b_id,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-OBS-NOTE", "reserve-scan-a"),
        )?;
        let obs_c = MoneroObservation::new(
            MoneroObservationKind::WithdrawalBroadcast,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-MONERO-TX", "withdrawal-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-KEY-IMAGE", "withdrawal-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-OUTPUT", "withdrawal-a"),
            80_000,
            82,
            &member_c_id,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-OBS-NOTE", "withdrawal-a"),
        )?;
        state.insert_observation(obs_a.clone())?;
        state.insert_observation(obs_b.clone())?;
        state.insert_observation(obs_c.clone())?;

        let mut observation_batch = MoneroObservationBatch::new(
            &state.config.monero_network,
            state.height.saturating_sub(12),
            state.height.saturating_sub(2),
            80,
            82,
            &[obs_a.clone(), obs_b.clone(), obs_c.clone()],
            40_000,
            ReserveDeltaDirection::Inflow,
            pq_bridge_ops_string_root("PQ-BRIDGE-PENDING-ATTESTATION", "observation-batch"),
            ObservationBatchStatus::Sealed,
        )?;
        let observation_batch_subject = observation_batch.subject_root();
        let observation_batch_id = observation_batch.batch_id.clone();
        let shares = state.devnet_signer_shares(
            &[member_a_id.clone(), member_b_id.clone()],
            CommitteeRole::Observer,
            PqBridgeAlgorithm::DilithiumSignature,
            "observation-batch",
            state.height.saturating_sub(1),
        )?;
        let observation_attestation = PqBridgeThresholdAttestation::new(
            AttestationSubjectKind::MoneroObservationBatch,
            &observation_batch_id,
            &observation_batch_subject,
            &epoch_id,
            &epoch_committee_root,
            PqBridgeAlgorithm::HybridThreshold,
            state.config.min_attestation_weight_bps,
            &shares,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-AGGREGATE-SIGNATURE", "observation-batch"),
            state.height.saturating_sub(1),
            state.height.saturating_add(72),
        )?;
        let observation_attestation_root = observation_attestation.attestation_root();
        state.insert_attestation(observation_attestation)?;
        observation_batch.set_attestation_root(observation_attestation_root);
        observation_batch.status = ObservationBatchStatus::Finalized;
        state.insert_observation_batch(observation_batch.clone())?;

        let mut reserve_checkpoint = ReserveDeltaCheckpoint::new(
            None,
            &state.config.monero_network,
            &state.config.asset_id,
            vec![observation_batch.batch_id.clone()],
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-RESERVE", "previous"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-RESERVE", "new"),
            ReserveDeltaDirection::Inflow,
            40_000,
            860_000,
            1_250_000,
            pq_bridge_ops_string_root("PQ-BRIDGE-PENDING-ATTESTATION", "reserve-checkpoint"),
            state.height,
            ReserveCheckpointStatus::Proposed,
        )?;
        let checkpoint_subject = reserve_checkpoint.subject_root();
        let checkpoint_id = reserve_checkpoint.checkpoint_id.clone();
        let shares = state.devnet_signer_shares(
            &[member_a_id.clone(), member_b_id.clone()],
            CommitteeRole::ReserveAuditor,
            PqBridgeAlgorithm::FalconSignature,
            "reserve-checkpoint",
            state.height,
        )?;
        let checkpoint_attestation = PqBridgeThresholdAttestation::new(
            AttestationSubjectKind::ReserveDeltaCheckpoint,
            &checkpoint_id,
            &checkpoint_subject,
            &epoch_id,
            &epoch_committee_root,
            PqBridgeAlgorithm::HybridThreshold,
            state.config.min_attestation_weight_bps,
            &shares,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-AGGREGATE-SIGNATURE", "reserve-checkpoint"),
            state.height,
            state.height.saturating_add(72),
        )?;
        let checkpoint_attestation_root = checkpoint_attestation.attestation_root();
        state.insert_attestation(checkpoint_attestation)?;
        reserve_checkpoint.set_attestation_root(checkpoint_attestation_root);
        reserve_checkpoint.status = ReserveCheckpointStatus::Applied;
        state.insert_reserve_checkpoint(reserve_checkpoint)?;

        let mut exit = ExitQueueCommitment::new(
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-REQUESTER", "alice"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-RECIPIENT", "alice-monero"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-AMOUNT-COMMITMENT", "alice-80k"),
            80_000,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-FEE-COMMITMENT", "alice-low-fee"),
            50,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-NULLIFIER", "alice-exit"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-CLAIM-COMMITMENT", "alice-exit"),
            Some(pq_bridge_ops_string_root(
                "PQ-BRIDGE-DEVNET-SPONSOR",
                "low-fee-sponsor",
            )),
            state.height,
            state
                .height
                .saturating_add(state.config.exit_queue_ttl_blocks),
            pq_bridge_ops_string_root("PQ-BRIDGE-PENDING-ATTESTATION", "exit-alice"),
            ExitQueueStatus::Sponsored,
        )?;
        let exit_subject = exit.subject_root();
        let exit_id = exit.exit_id.clone();
        let shares = state.devnet_signer_shares(
            &[member_a_id.clone(), member_b_id.clone()],
            CommitteeRole::ExitScheduler,
            PqBridgeAlgorithm::DilithiumSignature,
            "exit-alice",
            state.height,
        )?;
        let exit_attestation = PqBridgeThresholdAttestation::new(
            AttestationSubjectKind::ExitQueueCommitment,
            &exit_id,
            &exit_subject,
            &epoch_id,
            &epoch_committee_root,
            PqBridgeAlgorithm::HybridThreshold,
            state.config.min_attestation_weight_bps,
            &shares,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-AGGREGATE-SIGNATURE", "exit-alice"),
            state.height,
            state.height.saturating_add(72),
        )?;
        let exit_attestation_root = exit_attestation.attestation_root();
        state.insert_attestation(exit_attestation)?;
        exit.set_attestation_root(exit_attestation_root);
        exit.status = ExitQueueStatus::Ready;
        state.insert_exit_queue_commitment(exit.clone())?;

        let mut claim = PrivacyWithdrawalClaim::new(
            &exit.exit_id,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-CLAIMANT", "alice"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-VIEW-TAG", "alice"),
            80_000,
            exit.nullifier.clone(),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-KEY-IMAGE", "alice-claim"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-MEMBERSHIP", "alice-exit"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-SPEND-AUTH", "alice-exit"),
            pq_bridge_ops_string_root("PQ-BRIDGE-PENDING-ATTESTATION", "claim-alice"),
            state.height.saturating_add(1),
            state.height.saturating_add(state.config.claim_ttl_blocks),
            WithdrawalClaimStatus::NullifierReserved,
        )?;
        let claim_subject = claim.subject_root();
        let claim_id = claim.claim_id.clone();
        let shares = state.devnet_signer_shares(
            &[member_a_id.clone(), member_b_id.clone()],
            CommitteeRole::Attester,
            PqBridgeAlgorithm::FalconSignature,
            "claim-alice",
            state.height.saturating_add(1),
        )?;
        let claim_attestation = PqBridgeThresholdAttestation::new(
            AttestationSubjectKind::WithdrawalClaim,
            &claim_id,
            &claim_subject,
            &epoch_id,
            &epoch_committee_root,
            PqBridgeAlgorithm::HybridThreshold,
            state.config.min_attestation_weight_bps,
            &shares,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-AGGREGATE-SIGNATURE", "claim-alice"),
            state.height.saturating_add(1),
            state.height.saturating_add(72),
        )?;
        let claim_attestation_root = claim_attestation.attestation_root();
        state.insert_attestation(claim_attestation)?;
        claim.set_attestation_root(claim_attestation_root);
        claim.status = WithdrawalClaimStatus::Ready;
        state.insert_withdrawal_claim(claim.clone())?;

        let replay = ReplayNullifierEntry::new(
            claim.nullifier.clone(),
            claim.key_image_root.clone(),
            AttestationSubjectKind::WithdrawalClaim,
            claim.claim_id.clone(),
            claim.submitted_at_height,
            claim
                .submitted_at_height
                .saturating_add(state.config.replay_retention_blocks),
            ReplayEntryStatus::Reserved,
        )?;
        state.insert_replay_entry(replay)?;

        let rebate_units = exit
            .amount_bucket
            .saturating_mul(state.config.low_fee_rebate_bps)
            .saturating_div(PQ_BRIDGE_OPS_MAX_BPS)
            .min(state.config.max_sponsor_rebate_units);
        let rebate = LowFeeExitSponsorRebate::new(
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-SPONSOR", "low-fee-sponsor"),
            &exit.exit_id,
            &claim.claim_id,
            &state.config.fee_asset_id,
            rebate_units,
            state.config.max_sponsor_rebate_units,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-REBATE-ELIGIBILITY", "alice"),
            250,
            state.height,
            state.height.saturating_add(96),
            Some(state.height.saturating_add(4)),
            SponsorRebateStatus::Applied,
        )?;
        state.insert_sponsor_rebate(rebate)?;

        let pause_ceremony = EmergencyPauseCeremony::new(
            PauseCeremonyAction::Pause,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-PAUSE-REASON", "reserve-watch"),
            &member_a_id,
            &epoch_id,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-PAUSE-ATTESTATION", "pause"),
            vec![member_a_id.clone(), member_b_id.clone()],
            state.height.saturating_sub(20),
            state.height.saturating_add(20),
            Some(state.height.saturating_sub(18)),
            PauseCeremonyStatus::Applied,
        )?;
        state.insert_pause_ceremony(pause_ceremony)?;
        let unpause_ceremony = EmergencyPauseCeremony::new(
            PauseCeremonyAction::Unpause,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-PAUSE-REASON", "reserve-watch-clear"),
            &member_b_id,
            &epoch_id,
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-PAUSE-ATTESTATION", "unpause"),
            vec![
                member_a_id.clone(),
                member_b_id.clone(),
                member_c_id.clone(),
            ],
            state.height.saturating_sub(12),
            state.height.saturating_add(32),
            Some(state.height.saturating_sub(8)),
            PauseCeremonyStatus::Applied,
        )?;
        state.insert_pause_ceremony(unpause_ceremony)?;
        state.paused = false;

        let equivocation = SlashableEquivocationEvidence::new(
            &member_c_id,
            AttestationSubjectKind::MoneroObservationBatch,
            "devnet-conflicting-batch-a",
            "devnet-conflicting-batch-b",
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-EQUIVOCATION", "statement-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-EQUIVOCATION", "statement-b"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-EQUIVOCATION-WITNESS", "watchtower-a"),
            pq_bridge_ops_string_root("PQ-BRIDGE-DEVNET-REPORTER", "watchtower-a"),
            state.height.saturating_sub(4),
            state.height.saturating_add(240),
            500,
            EquivocationEvidenceStatus::Verified,
        )?;
        state.insert_equivocation_evidence(equivocation)?;

        for (member_id, ready_rounds, missed_rounds) in [
            (member_a_id.clone(), 128_u64, 1_u64),
            (member_b_id.clone(), 126_u64, 2_u64),
            (member_c_id.clone(), 121_u64, 5_u64),
        ] {
            let counter = OperatorReadinessCounter::new(
                member_id.clone(),
                &epoch_id,
                ready_rounds,
                missed_rounds,
                0,
                state.height,
                state.height,
                pq_bridge_ops_payload_root(
                    "PQ-BRIDGE-DEVNET-READINESS",
                    &json!({"member_id": member_id, "round": state.height}),
                ),
                ReadinessStatus::Ready,
            )?;
            state.insert_readiness_counter(counter)?;
        }

        state.insert_public_record(
            "devnet_fixture".to_string(),
            json!({
                "kind": "pq_bridge_ops_devnet_fixture",
                "height": state.height,
                "monero_network": state.config.monero_network,
                "asset_id": state.config.asset_id,
                "note": "deterministic post-quantum bridge operations fixture"
            }),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for epoch in self.committee_epochs.values_mut() {
            if epoch.status == CommitteeEpochStatus::Active && height > epoch.ends_at_height {
                epoch.status = CommitteeEpochStatus::Grace;
            }
            if matches!(
                epoch.status,
                CommitteeEpochStatus::Active | CommitteeEpochStatus::Grace
            ) && height > epoch.grace_ends_at_height
            {
                epoch.status = CommitteeEpochStatus::Expired;
            }
        }
        for attestation in self.attestations.values_mut() {
            attestation.set_height(height);
        }
        for exit in self.exit_queue.values_mut() {
            exit.set_height(height);
        }
        for ceremony in self.pause_ceremonies.values_mut() {
            ceremony.set_height(height);
        }
        for evidence in self.equivocation_evidence.values_mut() {
            evidence.set_height(height);
        }
        for claim in self.withdrawal_claims.values_mut() {
            claim.set_height(height);
        }
        for entry in self.replay_registry.values_mut() {
            entry.set_height(height);
        }
        for rebate in self.sponsor_rebates.values_mut() {
            rebate.set_height(height);
        }
        for counter in self.readiness_counters.values_mut() {
            counter.mark_stale_if_needed(height, self.config.readiness_stale_after_blocks);
        }
    }

    pub fn insert_committee_member(
        &mut self,
        member: CommitteeMember,
    ) -> PqBridgeOpsResult<String> {
        member.validate()?;
        let member_id = member.member_id.clone();
        self.committee_members.insert(member_id.clone(), member);
        Ok(member_id)
    }

    pub fn insert_committee_epoch(
        &mut self,
        epoch: PqBridgeCommitteeEpoch,
    ) -> PqBridgeOpsResult<String> {
        epoch.validate()?;
        for member_id in &epoch.member_ids {
            if !self.committee_members.contains_key(member_id) {
                return Err(format!(
                    "pq bridge epoch references unknown member {member_id}"
                ));
            }
        }
        let epoch_id = epoch.epoch_id.clone();
        self.committee_epochs.insert(epoch_id.clone(), epoch);
        Ok(epoch_id)
    }

    pub fn insert_attestation(
        &mut self,
        attestation: PqBridgeThresholdAttestation,
    ) -> PqBridgeOpsResult<String> {
        attestation.validate()?;
        if !self.committee_epochs.contains_key(&attestation.epoch_id) {
            return Err("pq bridge attestation references unknown epoch".to_string());
        }
        for signer_id in &attestation.signer_ids {
            if !self.committee_members.contains_key(signer_id) {
                return Err(format!(
                    "pq bridge attestation references unknown signer {signer_id}"
                ));
            }
        }
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn insert_observation(
        &mut self,
        observation: MoneroObservation,
    ) -> PqBridgeOpsResult<String> {
        observation.validate()?;
        if !self
            .committee_members
            .contains_key(&observation.observed_by_member_id)
        {
            return Err("pq bridge observation references unknown observer".to_string());
        }
        let observation_id = observation.observation_id.clone();
        self.observations
            .insert(observation_id.clone(), observation);
        Ok(observation_id)
    }

    pub fn insert_observation_batch(
        &mut self,
        batch: MoneroObservationBatch,
    ) -> PqBridgeOpsResult<String> {
        batch.validate()?;
        for observation_id in &batch.observation_ids {
            if !self.observations.contains_key(observation_id) {
                return Err(format!(
                    "pq bridge observation batch references unknown observation {observation_id}"
                ));
            }
        }
        let batch_id = batch.batch_id.clone();
        self.observation_batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn insert_exit_queue_commitment(
        &mut self,
        exit: ExitQueueCommitment,
    ) -> PqBridgeOpsResult<String> {
        exit.validate()?;
        if self.exit_queue.len() >= self.config.max_exit_queue_items as usize {
            return Err("pq bridge exit queue item limit reached".to_string());
        }
        if self.replay_index.contains_key(&exit.nullifier) {
            return Err("pq bridge exit nullifier already tracked".to_string());
        }
        let exit_id = exit.exit_id.clone();
        self.exit_queue.insert(exit_id.clone(), exit);
        Ok(exit_id)
    }

    pub fn insert_pause_ceremony(
        &mut self,
        ceremony: EmergencyPauseCeremony,
    ) -> PqBridgeOpsResult<String> {
        ceremony.validate()?;
        if !self.committee_epochs.contains_key(&ceremony.epoch_id) {
            return Err("pq bridge pause ceremony references unknown epoch".to_string());
        }
        for signer_id in &ceremony.signer_ids {
            if !self.committee_members.contains_key(signer_id) {
                return Err("pq bridge pause ceremony references unknown signer".to_string());
            }
        }
        if ceremony.status == PauseCeremonyStatus::Applied {
            self.paused = ceremony.action == PauseCeremonyAction::Pause;
        }
        let ceremony_id = ceremony.ceremony_id.clone();
        self.pause_ceremonies.insert(ceremony_id.clone(), ceremony);
        Ok(ceremony_id)
    }

    pub fn insert_equivocation_evidence(
        &mut self,
        evidence: SlashableEquivocationEvidence,
    ) -> PqBridgeOpsResult<String> {
        evidence.validate()?;
        if !self
            .committee_members
            .contains_key(&evidence.offender_member_id)
        {
            return Err("pq bridge equivocation evidence references unknown offender".to_string());
        }
        let evidence_id = evidence.evidence_id.clone();
        self.equivocation_evidence
            .insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn insert_reserve_checkpoint(
        &mut self,
        checkpoint: ReserveDeltaCheckpoint,
    ) -> PqBridgeOpsResult<String> {
        checkpoint.validate()?;
        for batch_id in &checkpoint.observed_batch_ids {
            if !self.observation_batches.contains_key(batch_id) {
                return Err("pq bridge reserve checkpoint references unknown batch".to_string());
            }
        }
        if let Some(previous) = &checkpoint.previous_checkpoint_id {
            if !self.reserve_checkpoints.contains_key(previous) {
                return Err("pq bridge reserve checkpoint references unknown previous".to_string());
            }
        }
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        self.reserve_checkpoints
            .insert(checkpoint_id.clone(), checkpoint);
        Ok(checkpoint_id)
    }

    pub fn insert_withdrawal_claim(
        &mut self,
        claim: PrivacyWithdrawalClaim,
    ) -> PqBridgeOpsResult<String> {
        claim.validate()?;
        if !self.exit_queue.contains_key(&claim.exit_id) {
            return Err("pq bridge withdrawal claim references unknown exit".to_string());
        }
        if let Some(entry_id) = self.replay_index.get(&claim.nullifier) {
            let existing = self
                .replay_registry
                .get(entry_id)
                .ok_or_else(|| "pq bridge replay index points to missing entry".to_string())?;
            if existing.status.blocks_replay() && existing.subject_id != claim.claim_id {
                return Err("pq bridge withdrawal claim reuses active nullifier".to_string());
            }
        }
        let claim_id = claim.claim_id.clone();
        self.withdrawal_claims.insert(claim_id.clone(), claim);
        Ok(claim_id)
    }

    pub fn insert_replay_entry(
        &mut self,
        entry: ReplayNullifierEntry,
    ) -> PqBridgeOpsResult<String> {
        entry.validate()?;
        if let Some(existing_id) = self.replay_index.get(&entry.nullifier) {
            let existing = self
                .replay_registry
                .get(existing_id)
                .ok_or_else(|| "pq bridge replay index points to missing entry".to_string())?;
            if existing.status.blocks_replay() && entry.status.blocks_replay() {
                return Err("pq bridge replay nullifier already blocks replay".to_string());
            }
        }
        if let Some(existing_id) = self.key_image_index.get(&entry.key_image_root) {
            let existing = self
                .replay_registry
                .get(existing_id)
                .ok_or_else(|| "pq bridge key image index points to missing entry".to_string())?;
            if existing.status.blocks_replay() && entry.status.blocks_replay() {
                return Err("pq bridge replay key image already blocks replay".to_string());
            }
        }
        let entry_id = entry.entry_id.clone();
        self.replay_index
            .insert(entry.nullifier.clone(), entry_id.clone());
        self.key_image_index
            .insert(entry.key_image_root.clone(), entry_id.clone());
        self.replay_registry.insert(entry_id.clone(), entry);
        Ok(entry_id)
    }

    pub fn insert_sponsor_rebate(
        &mut self,
        rebate: LowFeeExitSponsorRebate,
    ) -> PqBridgeOpsResult<String> {
        rebate.validate()?;
        if !self.exit_queue.contains_key(&rebate.exit_id) {
            return Err("pq bridge sponsor rebate references unknown exit".to_string());
        }
        if !self.withdrawal_claims.contains_key(&rebate.claim_id) {
            return Err("pq bridge sponsor rebate references unknown claim".to_string());
        }
        if rebate.rebate_units > self.config.max_sponsor_rebate_units {
            return Err("pq bridge sponsor rebate exceeds configured max".to_string());
        }
        let rebate_id = rebate.rebate_id.clone();
        self.sponsor_rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn insert_readiness_counter(
        &mut self,
        counter: OperatorReadinessCounter,
    ) -> PqBridgeOpsResult<String> {
        counter.validate()?;
        if !self.committee_members.contains_key(&counter.member_id) {
            return Err("pq bridge readiness counter references unknown member".to_string());
        }
        if !self.committee_epochs.contains_key(&counter.epoch_id) {
            return Err("pq bridge readiness counter references unknown epoch".to_string());
        }
        let counter_id = counter.counter_id.clone();
        self.readiness_counters.insert(counter_id.clone(), counter);
        Ok(counter_id)
    }

    pub fn insert_public_record(
        &mut self,
        key: String,
        record: Value,
    ) -> PqBridgeOpsResult<String> {
        ensure_non_empty(&key, "pq bridge public record key")?;
        let record_id = pq_bridge_ops_payload_root("PQ-BRIDGE-PUBLIC-RECORD", &record);
        self.public_records
            .insert(format!("{key}:{record_id}"), record);
        Ok(record_id)
    }

    pub fn roots(&self) -> PqBridgeOpsRoots {
        PqBridgeOpsRoots {
            config_root: self.config.config_root(),
            committee_member_root: pq_bridge_ops_committee_member_collection_root(
                &self.committee_members.values().cloned().collect::<Vec<_>>(),
            ),
            committee_epoch_root: pq_bridge_ops_committee_epoch_collection_root(
                &self.committee_epochs.values().cloned().collect::<Vec<_>>(),
            ),
            attestation_root: pq_bridge_ops_attestation_collection_root(
                &self.attestations.values().cloned().collect::<Vec<_>>(),
            ),
            observation_root: pq_bridge_ops_observation_collection_root(
                &self.observations.values().cloned().collect::<Vec<_>>(),
            ),
            observation_batch_root: pq_bridge_ops_observation_batch_collection_root(
                &self
                    .observation_batches
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            exit_queue_root: pq_bridge_ops_exit_queue_collection_root(
                &self.exit_queue.values().cloned().collect::<Vec<_>>(),
            ),
            pause_ceremony_root: pq_bridge_ops_pause_ceremony_collection_root(
                &self.pause_ceremonies.values().cloned().collect::<Vec<_>>(),
            ),
            equivocation_evidence_root: pq_bridge_ops_equivocation_evidence_collection_root(
                &self
                    .equivocation_evidence
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            reserve_checkpoint_root: pq_bridge_ops_reserve_checkpoint_collection_root(
                &self
                    .reserve_checkpoints
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            withdrawal_claim_root: pq_bridge_ops_withdrawal_claim_collection_root(
                &self.withdrawal_claims.values().cloned().collect::<Vec<_>>(),
            ),
            replay_registry_root: pq_bridge_ops_replay_registry_collection_root(
                &self.replay_registry.values().cloned().collect::<Vec<_>>(),
            ),
            sponsor_rebate_root: pq_bridge_ops_sponsor_rebate_collection_root(
                &self.sponsor_rebates.values().cloned().collect::<Vec<_>>(),
            ),
            readiness_counter_root: pq_bridge_ops_readiness_counter_collection_root(
                &self
                    .readiness_counters
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            public_record_root: pq_bridge_ops_value_collection_root(
                "PQ-BRIDGE-PUBLIC-RECORD-COLLECTION",
                &self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> PqBridgeOpsCounters {
        let active_epoch_count = self
            .committee_epochs
            .values()
            .filter(|epoch| epoch.status.accepts_attestations())
            .count() as u64;
        let active_committee_member_count = self
            .committee_members
            .values()
            .filter(|member| member.active_weight_at(self.height) > 0)
            .count() as u64;
        let latest_checkpoint = self
            .reserve_checkpoints
            .values()
            .max_by_key(|checkpoint| checkpoint.produced_at_height);
        let total_reserve_units = latest_checkpoint
            .map(|checkpoint| checkpoint.reserve_units)
            .unwrap_or(0);
        let total_liabilities_units = latest_checkpoint
            .map(|checkpoint| checkpoint.liabilities_units)
            .unwrap_or(0);
        PqBridgeOpsCounters {
            height: self.height,
            paused: self.paused,
            committee_member_count: self.committee_members.len() as u64,
            active_committee_member_count,
            committee_epoch_count: self.committee_epochs.len() as u64,
            active_epoch_count,
            attestation_count: self.attestations.len() as u64,
            threshold_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.threshold_met())
                .count() as u64,
            observation_count: self.observations.len() as u64,
            observation_batch_count: self.observation_batches.len() as u64,
            finalized_observation_batch_count: self
                .observation_batches
                .values()
                .filter(|batch| batch.status.is_final())
                .count() as u64,
            queued_exit_count: self
                .exit_queue
                .values()
                .filter(|exit| exit.status.is_open())
                .count() as u64,
            ready_exit_count: self
                .exit_queue
                .values()
                .filter(|exit| exit.status == ExitQueueStatus::Ready)
                .count() as u64,
            withdrawal_claim_count: self.withdrawal_claims.len() as u64,
            replay_entry_count: self.replay_registry.len() as u64,
            blocked_replay_count: self
                .replay_registry
                .values()
                .filter(|entry| entry.status.blocks_replay())
                .count() as u64,
            pause_ceremony_count: self.pause_ceremonies.len() as u64,
            applied_pause_count: self
                .pause_ceremonies
                .values()
                .filter(|ceremony| ceremony.status == PauseCeremonyStatus::Applied)
                .count() as u64,
            equivocation_evidence_count: self.equivocation_evidence.len() as u64,
            slashable_evidence_count: self
                .equivocation_evidence
                .values()
                .filter(|evidence| evidence.status.slashable())
                .count() as u64,
            reserve_checkpoint_count: self.reserve_checkpoints.len() as u64,
            sponsor_rebate_count: self.sponsor_rebates.len() as u64,
            applied_rebate_units: self
                .sponsor_rebates
                .values()
                .filter(|rebate| {
                    matches!(
                        rebate.status,
                        SponsorRebateStatus::Applied | SponsorRebateStatus::Settled
                    )
                })
                .map(|rebate| rebate.rebate_units)
                .sum::<u64>(),
            readiness_counter_count: self.readiness_counters.len() as u64,
            ready_operator_count: self
                .readiness_counters
                .values()
                .filter(|counter| counter.status == ReadinessStatus::Ready)
                .count() as u64,
            total_reserve_units,
            total_liabilities_units,
            reserve_coverage_bps: reserve_coverage_bps(
                total_reserve_units,
                total_liabilities_units,
            ),
        }
    }

    pub fn state_root(&self) -> String {
        pq_bridge_ops_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        let object = record
            .as_object_mut()
            .expect("pq bridge ops state record object");
        object.insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> PqBridgeOpsResult<String> {
        self.config.validate()?;
        if let Some(active_epoch_id) = &self.active_epoch_id {
            if !self.committee_epochs.contains_key(active_epoch_id) {
                return Err("pq bridge active epoch id is unknown".to_string());
            }
        }
        for member in self.committee_members.values() {
            member.validate()?;
        }
        for epoch in self.committee_epochs.values() {
            epoch.validate()?;
            for member_id in &epoch.member_ids {
                if !self.committee_members.contains_key(member_id) {
                    return Err("pq bridge epoch references unknown member".to_string());
                }
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.committee_epochs.contains_key(&attestation.epoch_id) {
                return Err("pq bridge attestation references unknown epoch".to_string());
            }
        }
        for observation in self.observations.values() {
            observation.validate()?;
            if !self
                .committee_members
                .contains_key(&observation.observed_by_member_id)
            {
                return Err("pq bridge observation references unknown member".to_string());
            }
        }
        for batch in self.observation_batches.values() {
            batch.validate()?;
            if batch.observation_ids.len() > self.config.max_observation_batch_items as usize {
                return Err("pq bridge observation batch exceeds item limit".to_string());
            }
            for observation_id in &batch.observation_ids {
                if !self.observations.contains_key(observation_id) {
                    return Err(
                        "pq bridge observation batch references unknown observation".to_string()
                    );
                }
            }
        }
        for exit in self.exit_queue.values() {
            exit.validate()?;
        }
        if self.exit_queue.len() > self.config.max_exit_queue_items as usize {
            return Err("pq bridge exit queue exceeds configured item limit".to_string());
        }
        for ceremony in self.pause_ceremonies.values() {
            ceremony.validate()?;
            if !self.committee_epochs.contains_key(&ceremony.epoch_id) {
                return Err("pq bridge ceremony references unknown epoch".to_string());
            }
        }
        for evidence in self.equivocation_evidence.values() {
            evidence.validate()?;
            if !self
                .committee_members
                .contains_key(&evidence.offender_member_id)
            {
                return Err("pq bridge evidence references unknown offender".to_string());
            }
        }
        for checkpoint in self.reserve_checkpoints.values() {
            checkpoint.validate()?;
            for batch_id in &checkpoint.observed_batch_ids {
                if !self.observation_batches.contains_key(batch_id) {
                    return Err("pq bridge checkpoint references unknown batch".to_string());
                }
            }
        }
        for claim in self.withdrawal_claims.values() {
            claim.validate()?;
            if !self.exit_queue.contains_key(&claim.exit_id) {
                return Err("pq bridge claim references unknown exit".to_string());
            }
        }
        self.validate_replay_indexes()?;
        for rebate in self.sponsor_rebates.values() {
            rebate.validate()?;
            if rebate.rebate_units > self.config.max_sponsor_rebate_units {
                return Err("pq bridge sponsor rebate exceeds configured max".to_string());
            }
        }
        for counter in self.readiness_counters.values() {
            counter.validate()?;
            if !self.committee_members.contains_key(&counter.member_id) {
                return Err("pq bridge readiness counter references unknown member".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_bridge_ops_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_BRIDGE_OPS_PROTOCOL_VERSION,
            "height": self.height,
            "paused": self.paused,
            "active_epoch_id": self.active_epoch_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    fn validate_replay_indexes(&self) -> PqBridgeOpsResult<()> {
        for entry in self.replay_registry.values() {
            entry.validate()?;
            if self.replay_index.get(&entry.nullifier) != Some(&entry.entry_id) {
                return Err("pq bridge replay nullifier index mismatch".to_string());
            }
            if self.key_image_index.get(&entry.key_image_root) != Some(&entry.entry_id) {
                return Err("pq bridge replay key image index mismatch".to_string());
            }
        }
        for (nullifier, entry_id) in &self.replay_index {
            let entry = self
                .replay_registry
                .get(entry_id)
                .ok_or_else(|| "pq bridge replay index references missing entry".to_string())?;
            if &entry.nullifier != nullifier {
                return Err("pq bridge replay index nullifier key mismatch".to_string());
            }
        }
        for (key_image_root, entry_id) in &self.key_image_index {
            let entry = self
                .replay_registry
                .get(entry_id)
                .ok_or_else(|| "pq bridge key image index references missing entry".to_string())?;
            if &entry.key_image_root != key_image_root {
                return Err("pq bridge key image index key mismatch".to_string());
            }
        }
        Ok(())
    }

    fn devnet_signer_shares(
        &self,
        member_ids: &[String],
        role: CommitteeRole,
        signature_algorithm: PqBridgeAlgorithm,
        label: &str,
        signed_at_height: u64,
    ) -> PqBridgeOpsResult<Vec<ThresholdSignerShare>> {
        member_ids
            .iter()
            .enumerate()
            .map(|(index, member_id)| {
                let member = self
                    .committee_members
                    .get(member_id)
                    .ok_or_else(|| "pq bridge devnet signer missing member".to_string())?;
                ThresholdSignerShare::new(
                    member_id,
                    role,
                    signature_algorithm,
                    pq_bridge_ops_payload_root(
                        "PQ-BRIDGE-DEVNET-SIGNER-SHARE",
                        &json!({
                            "label": label,
                            "member_id": member_id,
                            "index": index,
                        }),
                    ),
                    index as u64,
                    member.stake_weight_bps,
                    signed_at_height,
                )
            })
            .collect()
    }
}

pub fn pq_bridge_ops_state_root_from_record(record: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-OPS-STATE", record)
}

pub fn pq_bridge_ops_config_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-OPS-CONFIG-ID", payload)
}

pub fn pq_bridge_ops_member_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-COMMITTEE-MEMBER-ID", payload)
}

pub fn pq_bridge_ops_committee_epoch_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-COMMITTEE-EPOCH-ID", payload)
}

pub fn pq_bridge_ops_attestation_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-THRESHOLD-ATTESTATION-ID", payload)
}

pub fn pq_bridge_ops_observation_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-MONERO-OBSERVATION-ID", payload)
}

pub fn pq_bridge_ops_observation_batch_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-MONERO-OBSERVATION-BATCH-ID", payload)
}

pub fn pq_bridge_ops_exit_queue_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-EXIT-QUEUE-ID", payload)
}

pub fn pq_bridge_ops_pause_ceremony_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-PAUSE-CEREMONY-ID", payload)
}

pub fn pq_bridge_ops_equivocation_evidence_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-EQUIVOCATION-EVIDENCE-ID", payload)
}

pub fn pq_bridge_ops_reserve_checkpoint_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-RESERVE-CHECKPOINT-ID", payload)
}

pub fn pq_bridge_ops_withdrawal_claim_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-WITHDRAWAL-CLAIM-ID", payload)
}

pub fn pq_bridge_ops_replay_entry_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-REPLAY-ENTRY-ID", payload)
}

pub fn pq_bridge_ops_sponsor_rebate_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-SPONSOR-REBATE-ID", payload)
}

pub fn pq_bridge_ops_readiness_counter_id(payload: &Value) -> String {
    pq_bridge_ops_payload_root("PQ-BRIDGE-READINESS-COUNTER-ID", payload)
}

pub fn pq_bridge_ops_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn pq_bridge_ops_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn pq_bridge_ops_value_collection_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn pq_bridge_ops_committee_member_collection_root(members: &[CommitteeMember]) -> String {
    merkle_root(
        "PQ-BRIDGE-COMMITTEE-MEMBER-COLLECTION",
        &members
            .iter()
            .map(CommitteeMember::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_committee_epoch_collection_root(epochs: &[PqBridgeCommitteeEpoch]) -> String {
    merkle_root(
        "PQ-BRIDGE-COMMITTEE-EPOCH-COLLECTION",
        &epochs
            .iter()
            .map(PqBridgeCommitteeEpoch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_signer_share_collection_root(shares: &[ThresholdSignerShare]) -> String {
    merkle_root(
        "PQ-BRIDGE-SIGNER-SHARE-COLLECTION",
        &shares
            .iter()
            .map(ThresholdSignerShare::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_attestation_collection_root(
    attestations: &[PqBridgeThresholdAttestation],
) -> String {
    merkle_root(
        "PQ-BRIDGE-ATTESTATION-COLLECTION",
        &attestations
            .iter()
            .map(PqBridgeThresholdAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_observation_collection_root(observations: &[MoneroObservation]) -> String {
    merkle_root(
        "PQ-BRIDGE-OBSERVATION-COLLECTION",
        &observations
            .iter()
            .map(MoneroObservation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_observation_batch_collection_root(
    batches: &[MoneroObservationBatch],
) -> String {
    merkle_root(
        "PQ-BRIDGE-OBSERVATION-BATCH-COLLECTION",
        &batches
            .iter()
            .map(MoneroObservationBatch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_exit_queue_collection_root(exits: &[ExitQueueCommitment]) -> String {
    merkle_root(
        "PQ-BRIDGE-EXIT-QUEUE-COLLECTION",
        &exits
            .iter()
            .map(ExitQueueCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_pause_ceremony_collection_root(
    ceremonies: &[EmergencyPauseCeremony],
) -> String {
    merkle_root(
        "PQ-BRIDGE-PAUSE-CEREMONY-COLLECTION",
        &ceremonies
            .iter()
            .map(EmergencyPauseCeremony::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_equivocation_evidence_collection_root(
    evidence: &[SlashableEquivocationEvidence],
) -> String {
    merkle_root(
        "PQ-BRIDGE-EQUIVOCATION-EVIDENCE-COLLECTION",
        &evidence
            .iter()
            .map(SlashableEquivocationEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_reserve_checkpoint_collection_root(
    checkpoints: &[ReserveDeltaCheckpoint],
) -> String {
    merkle_root(
        "PQ-BRIDGE-RESERVE-CHECKPOINT-COLLECTION",
        &checkpoints
            .iter()
            .map(ReserveDeltaCheckpoint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_withdrawal_claim_collection_root(claims: &[PrivacyWithdrawalClaim]) -> String {
    merkle_root(
        "PQ-BRIDGE-WITHDRAWAL-CLAIM-COLLECTION",
        &claims
            .iter()
            .map(PrivacyWithdrawalClaim::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_replay_registry_collection_root(entries: &[ReplayNullifierEntry]) -> String {
    merkle_root(
        "PQ-BRIDGE-REPLAY-REGISTRY-COLLECTION",
        &entries
            .iter()
            .map(ReplayNullifierEntry::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_sponsor_rebate_collection_root(rebates: &[LowFeeExitSponsorRebate]) -> String {
    merkle_root(
        "PQ-BRIDGE-SPONSOR-REBATE-COLLECTION",
        &rebates
            .iter()
            .map(LowFeeExitSponsorRebate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_bridge_ops_readiness_counter_collection_root(
    counters: &[OperatorReadinessCounter],
) -> String {
    merkle_root(
        "PQ-BRIDGE-READINESS-COUNTER-COLLECTION",
        &counters
            .iter()
            .map(OperatorReadinessCounter::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn reserve_coverage_bps(reserve_units: u64, liabilities_units: u64) -> u64 {
    if liabilities_units == 0 {
        PQ_BRIDGE_OPS_MAX_BPS
    } else {
        reserve_units
            .saturating_mul(PQ_BRIDGE_OPS_MAX_BPS)
            .saturating_div(liabilities_units)
            .min(PQ_BRIDGE_OPS_MAX_BPS)
    }
}

fn ensure_non_empty(value: &str, label: &str) -> PqBridgeOpsResult<()> {
    if value.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> PqBridgeOpsResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> PqBridgeOpsResult<()> {
    if value > PQ_BRIDGE_OPS_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_window(start: u64, end: u64, label: &str) -> PqBridgeOpsResult<()> {
    if end < start {
        Err(format!("{label} end is before start"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> PqBridgeOpsResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}

fn ensure_unique_roles(values: &[CommitteeRole], label: &str) -> PqBridgeOpsResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}

fn ensure_unique_algorithms(values: &[PqBridgeAlgorithm], label: &str) -> PqBridgeOpsResult<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}
