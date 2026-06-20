use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqThresholdFastFinalityBridgeResult<T> = Result<T, String>;

pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_PROTOCOL_VERSION: &str =
    "nebula-pq-threshold-fast-finality-bridge-v1";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_SCHEMA_VERSION: u64 = 1;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_SECURITY_MODEL: &str =
    "deterministic-devnet-records-not-real-crypto";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_HASH_SUITE: &str = "SHAKE256";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_PRIMARY_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-192s";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_AGGREGATE_ATTESTATION_SCHEME: &str =
    "weighted-threshold-pq-finality-attestation-v1";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_MONERO_ANCHOR_SCHEME: &str =
    "monero-anchor-commitment-v1";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_RECEIPT_SCHEME: &str =
    "low-latency-finality-receipt-v1";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_ROTATION_SCHEME: &str =
    "overlapping-quorum-rotation-v1";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_NETWORK: &str = "monero-devnet";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_COMMITTEE_ID: &str =
    "pq-threshold-fast-finality-devnet-quorum";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_OPERATOR_ID: &str =
    "pq-threshold-fast-finality-devnet-operator";
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_HEIGHT: u64 = 18_432;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_ROTATION_NOTICE_BLOCKS: u64 = 180;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_ROTATION_OVERLAP_BLOCKS: u64 = 96;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_MONERO_REORG_DELAY_BLOCKS: u64 = 36;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_L2_REORG_DELAY_BLOCKS: u64 = 8;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_FAST_QUORUM_BPS: u64 = 8_000;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_SAFE_QUORUM_BPS: u64 = 6_700;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_EMERGENCY_QUORUM_BPS: u64 = 7_500;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_WATCHER_QUORUM: u64 = 2;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_MAX_RECEIPT_LATENCY_MS: u64 = 1_500;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_MAX_ANCHORS_PER_RECEIPT: u64 = 32;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PQ_THRESHOLD_FAST_FINALITY_BRIDGE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorRole {
    BridgeValidator,
    MoneroWatcher,
    SequencerObserver,
    ChallengeGuardian,
    RotationCoordinator,
    EmergencySigner,
}

impl ValidatorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeValidator => "bridge_validator",
            Self::MoneroWatcher => "monero_watcher",
            Self::SequencerObserver => "sequencer_observer",
            Self::ChallengeGuardian => "challenge_guardian",
            Self::RotationCoordinator => "rotation_coordinator",
            Self::EmergencySigner => "emergency_signer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorStatus {
    Pending,
    Active,
    Rotating,
    Jailed,
    Retired,
}

impl ValidatorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Jailed => "jailed",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    MlDsa,
    SlhDsa,
    Hybrid,
}

impl SignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa => "ml_dsa",
            Self::SlhDsa => "slh_dsa",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorStatus {
    Observed,
    SafeDepth,
    Attested,
    ChallengeOpen,
    Finalized,
    Reorged,
    Rejected,
}

impl AnchorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::SafeDepth => "safe_depth",
            Self::Attested => "attested",
            Self::ChallengeOpen => "challenge_open",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Rejected => "rejected",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Reorged | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Draft,
    Collecting,
    QuorumReached,
    ChallengeOpen,
    Accepted,
    Rejected,
    Superseded,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Collecting => "collecting",
            Self::QuorumReached => "quorum_reached",
            Self::ChallengeOpen => "challenge_open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }

    pub fn usable_for_receipt(self) -> bool {
        matches!(
            self,
            Self::QuorumReached | Self::ChallengeOpen | Self::Accepted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Prepared,
    Released,
    Settled,
    Expired,
    Challenged,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Released => "released",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Prepared | Self::Released | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationStatus {
    Announced,
    Warming,
    Overlap,
    Active,
    Retired,
    Cancelled,
}

impl RotationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Warming => "warming",
            Self::Overlap => "overlap",
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidMlDsaShare,
    InvalidSlhDsaShare,
    InsufficientWeight,
    WrongAnchorRoot,
    MoneroReorg,
    L2Reorg,
    RotationFraud,
    ReceiptLatencyExceeded,
    Equivocation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidMlDsaShare => "invalid_ml_dsa_share",
            Self::InvalidSlhDsaShare => "invalid_slh_dsa_share",
            Self::InsufficientWeight => "insufficient_weight",
            Self::WrongAnchorRoot => "wrong_anchor_root",
            Self::MoneroReorg => "monero_reorg",
            Self::L2Reorg => "l2_reorg",
            Self::RotationFraud => "rotation_fraud",
            Self::ReceiptLatencyExceeded => "receipt_latency_exceeded",
            Self::Equivocation => "equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidencePosted,
    Accepted,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidencePosted => "evidence_posted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::EvidencePosted)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub monero_network: String,
    pub asset_id: String,
    pub committee_id: String,
    pub operator_id: String,
    pub epoch_blocks: u64,
    pub rotation_notice_blocks: u64,
    pub rotation_overlap_blocks: u64,
    pub monero_reorg_delay_blocks: u64,
    pub l2_reorg_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub fast_quorum_bps: u64,
    pub safe_quorum_bps: u64,
    pub emergency_quorum_bps: u64,
    pub watcher_quorum: u64,
    pub max_receipt_latency_ms: u64,
    pub max_anchors_per_receipt: u64,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_PROTOCOL_VERSION.to_string(),
            monero_network: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_NETWORK.to_string(),
            asset_id: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_ASSET_ID.to_string(),
            committee_id: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_COMMITTEE_ID.to_string(),
            operator_id: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_OPERATOR_ID.to_string(),
            epoch_blocks: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_EPOCH_BLOCKS,
            rotation_notice_blocks:
                PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_ROTATION_NOTICE_BLOCKS,
            rotation_overlap_blocks:
                PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_ROTATION_OVERLAP_BLOCKS,
            monero_reorg_delay_blocks:
                PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_MONERO_REORG_DELAY_BLOCKS,
            l2_reorg_delay_blocks: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_L2_REORG_DELAY_BLOCKS,
            challenge_window_blocks:
                PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            receipt_ttl_blocks: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_RECEIPT_TTL_BLOCKS,
            fast_quorum_bps: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_FAST_QUORUM_BPS,
            safe_quorum_bps: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_SAFE_QUORUM_BPS,
            emergency_quorum_bps: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_EMERGENCY_QUORUM_BPS,
            watcher_quorum: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_WATCHER_QUORUM,
            max_receipt_latency_ms:
                PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_MAX_RECEIPT_LATENCY_MS,
            max_anchors_per_receipt:
                PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_MAX_ANCHORS_PER_RECEIPT,
            min_pq_security_bits: PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn validate(&self) -> PqThresholdFastFinalityBridgeResult<()> {
        if self.chain_id.is_empty() {
            return Err("chain_id must not be empty".to_string());
        }
        if self.protocol_version != PQ_THRESHOLD_FAST_FINALITY_BRIDGE_PROTOCOL_VERSION {
            return Err("unsupported protocol version".to_string());
        }
        if self.monero_network.is_empty() {
            return Err("monero_network must not be empty".to_string());
        }
        if self.asset_id.is_empty() {
            return Err("asset_id must not be empty".to_string());
        }
        if self.committee_id.is_empty() {
            return Err("committee_id must not be empty".to_string());
        }
        if self.operator_id.is_empty() {
            return Err("operator_id must not be empty".to_string());
        }
        if self.epoch_blocks == 0 {
            return Err("epoch_blocks must be greater than zero".to_string());
        }
        if self.rotation_notice_blocks == 0 {
            return Err("rotation_notice_blocks must be greater than zero".to_string());
        }
        if self.rotation_overlap_blocks == 0 {
            return Err("rotation_overlap_blocks must be greater than zero".to_string());
        }
        if self.monero_reorg_delay_blocks == 0 || self.l2_reorg_delay_blocks == 0 {
            return Err("reorg delay blocks must be greater than zero".to_string());
        }
        if self.challenge_window_blocks == 0 || self.receipt_ttl_blocks == 0 {
            return Err("challenge and receipt windows must be greater than zero".to_string());
        }
        validate_bps("fast_quorum_bps", self.fast_quorum_bps)?;
        validate_bps("safe_quorum_bps", self.safe_quorum_bps)?;
        validate_bps("emergency_quorum_bps", self.emergency_quorum_bps)?;
        if self.fast_quorum_bps < self.safe_quorum_bps {
            return Err("fast_quorum_bps must be at least safe_quorum_bps".to_string());
        }
        if self.watcher_quorum == 0 {
            return Err("watcher_quorum must be greater than zero".to_string());
        }
        if self.max_receipt_latency_ms == 0 {
            return Err("max_receipt_latency_ms must be greater than zero".to_string());
        }
        if self.max_anchors_per_receipt == 0 {
            return Err("max_anchors_per_receipt must be greater than zero".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits must be at least 128".to_string());
        }
        Ok(())
    }

    pub fn record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "chain_id": self.chain_id,
            "challenge_window_blocks": self.challenge_window_blocks,
            "committee_id": self.committee_id,
            "emergency_quorum_bps": self.emergency_quorum_bps,
            "epoch_blocks": self.epoch_blocks,
            "fast_quorum_bps": self.fast_quorum_bps,
            "l2_reorg_delay_blocks": self.l2_reorg_delay_blocks,
            "max_anchors_per_receipt": self.max_anchors_per_receipt,
            "max_receipt_latency_ms": self.max_receipt_latency_ms,
            "min_pq_security_bits": self.min_pq_security_bits,
            "monero_network": self.monero_network,
            "monero_reorg_delay_blocks": self.monero_reorg_delay_blocks,
            "operator_id": self.operator_id,
            "protocol_version": self.protocol_version,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "rotation_notice_blocks": self.rotation_notice_blocks,
            "rotation_overlap_blocks": self.rotation_overlap_blocks,
            "safe_quorum_bps": self.safe_quorum_bps,
            "watcher_quorum": self.watcher_quorum
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub id: String,
    pub role: ValidatorRole,
    pub status: ValidatorStatus,
    pub weight: u64,
    pub activation_height: u64,
    pub retirement_height: Option<u64>,
    pub ml_dsa_public_key_commitment: String,
    pub slh_dsa_public_key_commitment: String,
    pub attestation_endpoint_commitment: String,
    pub watcher: bool,
    pub slash_count: u64,
    pub metadata_root: String,
}

impl Validator {
    pub fn record(&self) -> Value {
        json!({
            "activation_height": self.activation_height,
            "attestation_endpoint_commitment": self.attestation_endpoint_commitment,
            "id": self.id,
            "metadata_root": self.metadata_root,
            "ml_dsa_public_key_commitment": self.ml_dsa_public_key_commitment,
            "retirement_height": self.retirement_height,
            "role": self.role.as_str(),
            "slash_count": self.slash_count,
            "slh_dsa_public_key_commitment": self.slh_dsa_public_key_commitment,
            "status": self.status.as_str(),
            "watcher": self.watcher,
            "weight": self.weight
        })
    }

    pub fn signing_power(&self) -> u64 {
        if self.status.can_attest() {
            self.weight
        } else {
            0
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorQuorum {
    pub id: String,
    pub epoch: u64,
    pub status: RotationStatus,
    pub activation_height: u64,
    pub expiry_height: u64,
    pub threshold_bps: u64,
    pub emergency_threshold_bps: u64,
    pub validator_ids: BTreeSet<String>,
    pub aggregate_key_commitment: String,
    pub backup_key_commitment: String,
    pub membership_root: String,
}

impl ValidatorQuorum {
    pub fn record(&self) -> Value {
        json!({
            "activation_height": self.activation_height,
            "aggregate_key_commitment": self.aggregate_key_commitment,
            "backup_key_commitment": self.backup_key_commitment,
            "emergency_threshold_bps": self.emergency_threshold_bps,
            "epoch": self.epoch,
            "expiry_height": self.expiry_height,
            "id": self.id,
            "membership_root": self.membership_root,
            "status": self.status.as_str(),
            "threshold_bps": self.threshold_bps,
            "validator_ids": sorted_strings(&self.validator_ids)
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroAnchorCommitment {
    pub id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub monero_block_hash: String,
    pub monero_tx_root: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub bridge_event_root: String,
    pub observed_by: BTreeSet<String>,
    pub status: AnchorStatus,
    pub eligible_after_l2_height: u64,
    pub eligible_after_monero_height: u64,
    pub challenge_deadline_height: u64,
    pub commitment_root: String,
}

impl MoneroAnchorCommitment {
    pub fn record(&self) -> Value {
        json!({
            "bridge_event_root": self.bridge_event_root,
            "challenge_deadline_height": self.challenge_deadline_height,
            "commitment_root": self.commitment_root,
            "eligible_after_l2_height": self.eligible_after_l2_height,
            "eligible_after_monero_height": self.eligible_after_monero_height,
            "id": self.id,
            "key_image_root": self.key_image_root,
            "l2_height": self.l2_height,
            "monero_block_hash": self.monero_block_hash,
            "monero_height": self.monero_height,
            "monero_tx_root": self.monero_tx_root,
            "observed_by": sorted_strings(&self.observed_by),
            "output_commitment_root": self.output_commitment_root,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureShare {
    pub validator_id: String,
    pub scheme: SignatureScheme,
    pub weight: u64,
    pub message_root: String,
    pub signature_commitment: String,
    pub received_height: u64,
    pub latency_ms: u64,
}

impl SignatureShare {
    pub fn record(&self) -> Value {
        json!({
            "latency_ms": self.latency_ms,
            "message_root": self.message_root,
            "received_height": self.received_height,
            "scheme": self.scheme.as_str(),
            "signature_commitment": self.signature_commitment,
            "validator_id": self.validator_id,
            "weight": self.weight
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregateFinalityAttestation {
    pub id: String,
    pub quorum_id: String,
    pub anchor_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub status: AttestationStatus,
    pub required_weight: u64,
    pub signed_weight: u64,
    pub threshold_bps: u64,
    pub message_root: String,
    pub ml_dsa_aggregate_commitment: String,
    pub slh_dsa_aggregate_commitment: String,
    pub signer_ids: BTreeSet<String>,
    pub shares: BTreeMap<String, SignatureShare>,
    pub opened_at_height: u64,
    pub challenge_deadline_height: u64,
    pub attestation_root: String,
}

impl AggregateFinalityAttestation {
    pub fn record(&self) -> Value {
        let shares = self
            .shares
            .values()
            .map(SignatureShare::record)
            .collect::<Vec<_>>();
        json!({
            "anchor_id": self.anchor_id,
            "attestation_root": self.attestation_root,
            "challenge_deadline_height": self.challenge_deadline_height,
            "id": self.id,
            "l2_height": self.l2_height,
            "message_root": self.message_root,
            "ml_dsa_aggregate_commitment": self.ml_dsa_aggregate_commitment,
            "monero_height": self.monero_height,
            "opened_at_height": self.opened_at_height,
            "quorum_id": self.quorum_id,
            "required_weight": self.required_weight,
            "shares": shares,
            "signed_weight": self.signed_weight,
            "signer_ids": sorted_strings(&self.signer_ids),
            "slh_dsa_aggregate_commitment": self.slh_dsa_aggregate_commitment,
            "status": self.status.as_str(),
            "threshold_bps": self.threshold_bps
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityReceipt {
    pub id: String,
    pub attestation_id: String,
    pub anchor_id: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub latency_ms: u64,
    pub status: ReceiptStatus,
    pub release_lane: String,
    pub receipt_root: String,
    pub included_anchor_ids: BTreeSet<String>,
}

impl FinalityReceipt {
    pub fn record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "attestation_id": self.attestation_id,
            "expires_height": self.expires_height,
            "id": self.id,
            "included_anchor_ids": sorted_strings(&self.included_anchor_ids),
            "issued_height": self.issued_height,
            "latency_ms": self.latency_ms,
            "receipt_root": self.receipt_root,
            "release_lane": self.release_lane,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumRotation {
    pub id: String,
    pub from_quorum_id: String,
    pub to_quorum_id: String,
    pub status: RotationStatus,
    pub notice_height: u64,
    pub overlap_start_height: u64,
    pub activation_height: u64,
    pub retired_height: u64,
    pub handoff_root: String,
    pub outgoing_signers: BTreeSet<String>,
    pub incoming_signers: BTreeSet<String>,
}

impl QuorumRotation {
    pub fn record(&self) -> Value {
        json!({
            "activation_height": self.activation_height,
            "from_quorum_id": self.from_quorum_id,
            "handoff_root": self.handoff_root,
            "id": self.id,
            "incoming_signers": sorted_strings(&self.incoming_signers),
            "notice_height": self.notice_height,
            "outgoing_signers": sorted_strings(&self.outgoing_signers),
            "overlap_start_height": self.overlap_start_height,
            "retired_height": self.retired_height,
            "status": self.status.as_str(),
            "to_quorum_id": self.to_quorum_id
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeWindow {
    pub id: String,
    pub challenge_kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub subject_id: String,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub challenger_id: String,
    pub evidence_root: String,
    pub bond_amount: u64,
}

impl ChallengeWindow {
    pub fn record(&self) -> Value {
        json!({
            "bond_amount": self.bond_amount,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_id": self.challenger_id,
            "deadline_height": self.deadline_height,
            "evidence_root": self.evidence_root,
            "id": self.id,
            "opened_height": self.opened_height,
            "status": self.status.as_str(),
            "subject_id": self.subject_id
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReorgDelayPolicy {
    pub monero_reorg_delay_blocks: u64,
    pub l2_reorg_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub policy_root: String,
}

impl ReorgDelayPolicy {
    pub fn devnet(config: &Config) -> Self {
        let mut policy = Self {
            monero_reorg_delay_blocks: config.monero_reorg_delay_blocks,
            l2_reorg_delay_blocks: config.l2_reorg_delay_blocks,
            challenge_window_blocks: config.challenge_window_blocks,
            receipt_ttl_blocks: config.receipt_ttl_blocks,
            policy_root: String::new(),
        };
        policy.policy_root = root_from_record(&policy.record_without_root());
        policy
    }

    pub fn record_without_root(&self) -> Value {
        json!({
            "challenge_window_blocks": self.challenge_window_blocks,
            "l2_reorg_delay_blocks": self.l2_reorg_delay_blocks,
            "monero_reorg_delay_blocks": self.monero_reorg_delay_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks
        })
    }

    pub fn record(&self) -> Value {
        json!({
            "challenge_window_blocks": self.challenge_window_blocks,
            "l2_reorg_delay_blocks": self.l2_reorg_delay_blocks,
            "monero_reorg_delay_blocks": self.monero_reorg_delay_blocks,
            "policy_root": self.policy_root,
            "receipt_ttl_blocks": self.receipt_ttl_blocks
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub validators_root: String,
    pub quorums_root: String,
    pub anchors_root: String,
    pub attestations_root: String,
    pub receipts_root: String,
    pub rotations_root: String,
    pub challenges_root: String,
    pub policy_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn record(&self) -> Value {
        json!({
            "anchors_root": self.anchors_root,
            "attestations_root": self.attestations_root,
            "challenges_root": self.challenges_root,
            "policy_root": self.policy_root,
            "quorums_root": self.quorums_root,
            "receipts_root": self.receipts_root,
            "rotations_root": self.rotations_root,
            "state_root": self.state_root,
            "validators_root": self.validators_root
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub validators: u64,
    pub active_validators: u64,
    pub watcher_validators: u64,
    pub total_signing_weight: u64,
    pub quorums: u64,
    pub anchors: u64,
    pub finalized_anchors: u64,
    pub aggregate_attestations: u64,
    pub accepted_attestations: u64,
    pub receipts: u64,
    pub live_receipts: u64,
    pub rotations: u64,
    pub active_challenges: u64,
}

impl Counters {
    pub fn record(&self) -> Value {
        json!({
            "accepted_attestations": self.accepted_attestations,
            "active_challenges": self.active_challenges,
            "active_validators": self.active_validators,
            "aggregate_attestations": self.aggregate_attestations,
            "anchors": self.anchors,
            "finalized_anchors": self.finalized_anchors,
            "live_receipts": self.live_receipts,
            "quorums": self.quorums,
            "receipts": self.receipts,
            "rotations": self.rotations,
            "total_signing_weight": self.total_signing_weight,
            "validators": self.validators,
            "watcher_validators": self.watcher_validators
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub validators: BTreeMap<String, Validator>,
    pub quorums: BTreeMap<String, ValidatorQuorum>,
    pub anchors: BTreeMap<String, MoneroAnchorCommitment>,
    pub attestations: BTreeMap<String, AggregateFinalityAttestation>,
    pub receipts: BTreeMap<String, FinalityReceipt>,
    pub rotations: BTreeMap<String, QuorumRotation>,
    pub challenges: BTreeMap<String, ChallengeWindow>,
    pub reorg_delay_policy: ReorgDelayPolicy,
}

impl State {
    pub fn devnet() -> PqThresholdFastFinalityBridgeResult<State> {
        let config = Config::devnet();
        config.validate()?;
        let height = PQ_THRESHOLD_FAST_FINALITY_BRIDGE_DEVNET_HEIGHT;
        let validators = devnet_validators(height);
        let quorums = devnet_quorums(&config, height, &validators)?;
        let anchors = devnet_anchors(&config, height)?;
        let attestations = devnet_attestations(&config, height, &validators, &quorums, &anchors)?;
        let receipts = devnet_receipts(&config, height, &anchors, &attestations)?;
        let rotations = devnet_rotations(&config, height, &quorums)?;
        let challenges = devnet_challenges(&config, height, &attestations)?;
        let reorg_delay_policy = ReorgDelayPolicy::devnet(&config);
        let state = State {
            config,
            height,
            validators,
            quorums,
            anchors,
            attestations,
            receipts,
            rotations,
            challenges,
            reorg_delay_policy,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PqThresholdFastFinalityBridgeResult<()> {
        self.config.validate()?;
        if self.height == 0 {
            return Err("height must be greater than zero".to_string());
        }
        if self.validators.is_empty() {
            return Err("validator set must not be empty".to_string());
        }
        if self.quorums.is_empty() {
            return Err("quorum set must not be empty".to_string());
        }
        let total_weight = self.total_signing_weight();
        if total_weight == 0 {
            return Err("total signing weight must be greater than zero".to_string());
        }
        let watchers = self
            .validators
            .values()
            .filter(|validator| validator.watcher)
            .count();
        if watchers < self.config.watcher_quorum as usize {
            return Err("not enough watcher validators for watcher quorum".to_string());
        }
        for (id, validator) in &self.validators {
            if id != &validator.id {
                return Err(format!("validator key mismatch for {id}"));
            }
            if validator.weight == 0 {
                return Err(format!("validator {id} has zero weight"));
            }
            if validator.ml_dsa_public_key_commitment.is_empty()
                || validator.slh_dsa_public_key_commitment.is_empty()
            {
                return Err(format!("validator {id} has empty pq key commitment"));
            }
        }
        for quorum in self.quorums.values() {
            validate_bps("quorum.threshold_bps", quorum.threshold_bps)?;
            validate_bps(
                "quorum.emergency_threshold_bps",
                quorum.emergency_threshold_bps,
            )?;
            if quorum.validator_ids.is_empty() {
                return Err(format!("quorum {} has no validators", quorum.id));
            }
            for validator_id in &quorum.validator_ids {
                if !self.validators.contains_key(validator_id) {
                    return Err(format!(
                        "quorum {} references missing validator {}",
                        quorum.id, validator_id
                    ));
                }
            }
            if quorum.activation_height >= quorum.expiry_height {
                return Err(format!("quorum {} has invalid height window", quorum.id));
            }
        }
        for anchor in self.anchors.values() {
            if anchor.id.is_empty() {
                return Err("anchor id must not be empty".to_string());
            }
            if anchor.monero_block_hash.is_empty() || anchor.commitment_root.is_empty() {
                return Err(format!("anchor {} has empty commitment data", anchor.id));
            }
            if anchor.eligible_after_l2_height < anchor.l2_height {
                return Err(format!("anchor {} has invalid l2 delay", anchor.id));
            }
            if anchor.eligible_after_monero_height < anchor.monero_height {
                return Err(format!("anchor {} has invalid monero delay", anchor.id));
            }
            if anchor.observed_by.len() < self.config.watcher_quorum as usize {
                return Err(format!("anchor {} does not meet watcher quorum", anchor.id));
            }
            for watcher_id in &anchor.observed_by {
                match self.validators.get(watcher_id) {
                    Some(validator) if validator.watcher => {}
                    Some(_) => {
                        return Err(format!(
                            "anchor {} observed by non-watcher {}",
                            anchor.id, watcher_id
                        ))
                    }
                    None => {
                        return Err(format!(
                            "anchor {} observed by missing watcher {}",
                            anchor.id, watcher_id
                        ))
                    }
                }
            }
        }
        for attestation in self.attestations.values() {
            if !self.quorums.contains_key(&attestation.quorum_id) {
                return Err(format!(
                    "attestation {} references missing quorum {}",
                    attestation.id, attestation.quorum_id
                ));
            }
            if !self.anchors.contains_key(&attestation.anchor_id) {
                return Err(format!(
                    "attestation {} references missing anchor {}",
                    attestation.id, attestation.anchor_id
                ));
            }
            if attestation.required_weight == 0 {
                return Err(format!(
                    "attestation {} requires zero weight",
                    attestation.id
                ));
            }
            if attestation.status.usable_for_receipt()
                && attestation.signed_weight < attestation.required_weight
            {
                return Err(format!(
                    "attestation {} has insufficient signed weight",
                    attestation.id
                ));
            }
            for signer_id in &attestation.signer_ids {
                if !self.validators.contains_key(signer_id) {
                    return Err(format!(
                        "attestation {} references missing signer {}",
                        attestation.id, signer_id
                    ));
                }
            }
            for (share_id, share) in &attestation.shares {
                if share_id != &share.validator_id {
                    return Err(format!("attestation {} share key mismatch", attestation.id));
                }
                if share.message_root != attestation.message_root {
                    return Err(format!(
                        "attestation {} share message root mismatch",
                        attestation.id
                    ));
                }
            }
        }
        for receipt in self.receipts.values() {
            if !self.attestations.contains_key(&receipt.attestation_id) {
                return Err(format!(
                    "receipt {} references missing attestation {}",
                    receipt.id, receipt.attestation_id
                ));
            }
            if receipt.latency_ms > self.config.max_receipt_latency_ms {
                return Err(format!("receipt {} exceeds latency budget", receipt.id));
            }
            if receipt.issued_height >= receipt.expires_height {
                return Err(format!("receipt {} has invalid ttl", receipt.id));
            }
            if receipt.included_anchor_ids.len() > self.config.max_anchors_per_receipt as usize {
                return Err(format!("receipt {} includes too many anchors", receipt.id));
            }
        }
        for rotation in self.rotations.values() {
            if !self.quorums.contains_key(&rotation.from_quorum_id)
                || !self.quorums.contains_key(&rotation.to_quorum_id)
            {
                return Err(format!(
                    "rotation {} references missing quorum",
                    rotation.id
                ));
            }
            if rotation.notice_height >= rotation.activation_height {
                return Err(format!(
                    "rotation {} has invalid notice window",
                    rotation.id
                ));
            }
            if rotation.overlap_start_height > rotation.activation_height {
                return Err(format!(
                    "rotation {} has invalid overlap window",
                    rotation.id
                ));
            }
        }
        for challenge in self.challenges.values() {
            if challenge.opened_height >= challenge.deadline_height {
                return Err(format!("challenge {} has invalid window", challenge.id));
            }
            if challenge.evidence_root.is_empty() {
                return Err(format!(
                    "challenge {} has empty evidence root",
                    challenge.id
                ));
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PqThresholdFastFinalityBridgeResult<()> {
        if height == 0 {
            return Err("height must be greater than zero".to_string());
        }
        self.height = height;
        self.recompute_time_dependent_statuses();
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> PqThresholdFastFinalityBridgeResult<()> {
        if height < self.height {
            return Err("height must not move backwards".to_string());
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let validators = self
            .validators
            .values()
            .map(Validator::record)
            .collect::<Vec<_>>();
        let quorums = self
            .quorums
            .values()
            .map(ValidatorQuorum::record)
            .collect::<Vec<_>>();
        let anchors = self
            .anchors
            .values()
            .map(MoneroAnchorCommitment::record)
            .collect::<Vec<_>>();
        let attestations = self
            .attestations
            .values()
            .map(AggregateFinalityAttestation::record)
            .collect::<Vec<_>>();
        let receipts = self
            .receipts
            .values()
            .map(FinalityReceipt::record)
            .collect::<Vec<_>>();
        let rotations = self
            .rotations
            .values()
            .map(QuorumRotation::record)
            .collect::<Vec<_>>();
        let challenges = self
            .challenges
            .values()
            .map(ChallengeWindow::record)
            .collect::<Vec<_>>();
        let validators_root =
            merkle_root("pq-threshold-fast-finality-bridge:validators", &validators);
        let quorums_root = merkle_root("pq-threshold-fast-finality-bridge:quorums", &quorums);
        let anchors_root = merkle_root("pq-threshold-fast-finality-bridge:anchors", &anchors);
        let attestations_root = merkle_root(
            "pq-threshold-fast-finality-bridge:attestations",
            &attestations,
        );
        let receipts_root = merkle_root("pq-threshold-fast-finality-bridge:receipts", &receipts);
        let rotations_root = merkle_root("pq-threshold-fast-finality-bridge:rotations", &rotations);
        let challenges_root =
            merkle_root("pq-threshold-fast-finality-bridge:challenges", &challenges);
        let policy_root = self.reorg_delay_policy.policy_root.clone();
        let root_record = json!({
            "anchors_root": anchors_root,
            "attestations_root": attestations_root,
            "chain_id": self.config.chain_id,
            "challenges_root": challenges_root,
            "height": self.height,
            "policy_root": policy_root,
            "protocol_version": self.config.protocol_version,
            "quorums_root": quorums_root,
            "receipts_root": receipts_root,
            "rotations_root": rotations_root,
            "validators_root": validators_root
        });
        let state_root = root_from_record(&root_record);
        Roots {
            validators_root,
            quorums_root,
            anchors_root,
            attestations_root,
            receipts_root,
            rotations_root,
            challenges_root,
            policy_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            validators: self.validators.len() as u64,
            active_validators: self
                .validators
                .values()
                .filter(|validator| validator.status.can_attest())
                .count() as u64,
            watcher_validators: self
                .validators
                .values()
                .filter(|validator| validator.watcher)
                .count() as u64,
            total_signing_weight: self.total_signing_weight(),
            quorums: self.quorums.len() as u64,
            anchors: self.anchors.len() as u64,
            finalized_anchors: self
                .anchors
                .values()
                .filter(|anchor| anchor.status == AnchorStatus::Finalized)
                .count() as u64,
            aggregate_attestations: self.attestations.len() as u64,
            accepted_attestations: self
                .attestations
                .values()
                .filter(|attestation| attestation.status == AttestationStatus::Accepted)
                .count() as u64,
            receipts: self.receipts.len() as u64,
            live_receipts: self
                .receipts
                .values()
                .filter(|receipt| receipt.status.live())
                .count() as u64,
            rotations: self.rotations.len() as u64,
            active_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status.active())
                .count() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.record(),
            "counters": self.counters().record(),
            "height": self.height,
            "protocol": {
                "aggregate_attestation_scheme": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_AGGREGATE_ATTESTATION_SCHEME,
                "backup_signature_scheme": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_BACKUP_SIGNATURE_SCHEME,
                "hash_suite": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_HASH_SUITE,
                "monero_anchor_scheme": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_MONERO_ANCHOR_SCHEME,
                "primary_signature_scheme": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_PRIMARY_SIGNATURE_SCHEME,
                "receipt_scheme": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_RECEIPT_SCHEME,
                "rotation_scheme": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_ROTATION_SCHEME,
                "schema_version": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_SCHEMA_VERSION,
                "security_model": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_SECURITY_MODEL,
                "version": PQ_THRESHOLD_FAST_FINALITY_BRIDGE_PROTOCOL_VERSION
            },
            "reorg_delay_policy": self.reorg_delay_policy.record(),
            "roots": self.roots().record()
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn total_signing_weight(&self) -> u64 {
        self.validators
            .values()
            .map(Validator::signing_power)
            .sum::<u64>()
    }

    pub fn active_quorum_id(&self) -> Option<String> {
        self.quorums
            .values()
            .filter(|quorum| {
                quorum.activation_height <= self.height
                    && self.height < quorum.expiry_height
                    && matches!(
                        quorum.status,
                        RotationStatus::Active | RotationStatus::Overlap | RotationStatus::Warming
                    )
            })
            .map(|quorum| quorum.id.clone())
            .next()
    }

    pub fn required_weight(&self, threshold_bps: u64) -> u64 {
        required_weight(self.total_signing_weight(), threshold_bps)
    }

    pub fn anchor_ready_for_fast_finality(&self, anchor_id: &str) -> bool {
        self.anchors.get(anchor_id).map_or(false, |anchor| {
            self.height >= anchor.eligible_after_l2_height
                && !matches!(
                    anchor.status,
                    AnchorStatus::Reorged | AnchorStatus::Rejected
                )
        })
    }

    pub fn receipt_by_anchor(&self, anchor_id: &str) -> Option<&FinalityReceipt> {
        self.receipts
            .values()
            .find(|receipt| receipt.anchor_id == anchor_id)
    }

    fn recompute_time_dependent_statuses(&mut self) {
        for anchor in self.anchors.values_mut() {
            if !anchor.status.terminal()
                && self.height >= anchor.challenge_deadline_height
                && self.height >= anchor.eligible_after_l2_height
            {
                anchor.status = AnchorStatus::Finalized;
            } else if !anchor.status.terminal() && self.height >= anchor.eligible_after_l2_height {
                anchor.status = AnchorStatus::ChallengeOpen;
            }
        }
        for receipt in self.receipts.values_mut() {
            if receipt.status.live() && self.height > receipt.expires_height {
                receipt.status = ReceiptStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status.active() && self.height > challenge.deadline_height {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        for rotation in self.rotations.values_mut() {
            if rotation.status == RotationStatus::Cancelled {
                continue;
            }
            rotation.status = if self.height >= rotation.retired_height {
                RotationStatus::Retired
            } else if self.height >= rotation.activation_height {
                RotationStatus::Active
            } else if self.height >= rotation.overlap_start_height {
                RotationStatus::Overlap
            } else if self.height >= rotation.notice_height {
                RotationStatus::Warming
            } else {
                RotationStatus::Announced
            };
        }
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "pq-threshold-fast-finality-bridge:record-root",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PqThresholdFastFinalityBridgeResult<State> {
    State::devnet()
}

fn validate_bps(name: &str, value: u64) -> PqThresholdFastFinalityBridgeResult<()> {
    if value == 0 || value > PQ_THRESHOLD_FAST_FINALITY_BRIDGE_MAX_BPS {
        return Err(format!("{name} must be in 1..=10000"));
    }
    Ok(())
}

fn required_weight(total_weight: u64, threshold_bps: u64) -> u64 {
    let numerator = total_weight.saturating_mul(threshold_bps);
    numerator.div_ceil(PQ_THRESHOLD_FAST_FINALITY_BRIDGE_MAX_BPS)
}

fn sorted_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect::<Vec<_>>()
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 16)
}

fn commitment(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn devnet_validators(height: u64) -> BTreeMap<String, Validator> {
    let specs = [
        (
            "aurora",
            ValidatorRole::BridgeValidator,
            ValidatorStatus::Active,
            18_u64,
            true,
        ),
        (
            "boron",
            ValidatorRole::MoneroWatcher,
            ValidatorStatus::Active,
            16_u64,
            true,
        ),
        (
            "cobalt",
            ValidatorRole::SequencerObserver,
            ValidatorStatus::Active,
            15_u64,
            false,
        ),
        (
            "dahlia",
            ValidatorRole::ChallengeGuardian,
            ValidatorStatus::Active,
            14_u64,
            true,
        ),
        (
            "ember",
            ValidatorRole::RotationCoordinator,
            ValidatorStatus::Rotating,
            13_u64,
            false,
        ),
        (
            "fluorine",
            ValidatorRole::EmergencySigner,
            ValidatorStatus::Active,
            12_u64,
            true,
        ),
        (
            "garnet",
            ValidatorRole::BridgeValidator,
            ValidatorStatus::Active,
            12_u64,
            false,
        ),
    ];
    specs
        .into_iter()
        .map(|(name, role, status, weight, watcher)| {
            let id = format!("pqtfb-validator-{name}");
            let metadata = json!({
                "activation_height": height.saturating_sub(2_000),
                "name": name,
                "role": role.as_str(),
                "watcher": watcher
            });
            let validator = Validator {
                id: id.clone(),
                role,
                status,
                weight,
                activation_height: height.saturating_sub(2_000),
                retirement_height: None,
                ml_dsa_public_key_commitment: commitment(
                    "pq-threshold-fast-finality-bridge:ml-dsa-key",
                    &[HashPart::Str(&id), HashPart::Int(weight as i128)],
                ),
                slh_dsa_public_key_commitment: commitment(
                    "pq-threshold-fast-finality-bridge:slh-dsa-key",
                    &[HashPart::Str(&id), HashPart::Str(role.as_str())],
                ),
                attestation_endpoint_commitment: commitment(
                    "pq-threshold-fast-finality-bridge:endpoint",
                    &[HashPart::Str(&id), HashPart::Int(height as i128)],
                ),
                watcher,
                slash_count: 0,
                metadata_root: root_from_record(&metadata),
            };
            (id, validator)
        })
        .collect::<BTreeMap<_, _>>()
}

fn devnet_quorums(
    config: &Config,
    height: u64,
    validators: &BTreeMap<String, Validator>,
) -> PqThresholdFastFinalityBridgeResult<BTreeMap<String, ValidatorQuorum>> {
    let all_ids = validators.keys().cloned().collect::<BTreeSet<_>>();
    let next_ids = validators
        .keys()
        .filter(|id| !id.ends_with("ember"))
        .cloned()
        .collect::<BTreeSet<_>>();
    let current_id = format!(
        "{}-epoch-{}",
        config.committee_id,
        height / config.epoch_blocks
    );
    let next_id = format!(
        "{}-epoch-{}",
        config.committee_id,
        height / config.epoch_blocks + 1
    );
    let current_membership = membership_root(&all_ids);
    let next_membership = membership_root(&next_ids);
    let current = ValidatorQuorum {
        id: current_id.clone(),
        epoch: height / config.epoch_blocks,
        status: RotationStatus::Active,
        activation_height: height.saturating_sub(config.epoch_blocks),
        expiry_height: height + config.rotation_overlap_blocks,
        threshold_bps: config.fast_quorum_bps,
        emergency_threshold_bps: config.emergency_quorum_bps,
        validator_ids: all_ids,
        aggregate_key_commitment: commitment(
            "pq-threshold-fast-finality-bridge:aggregate-key",
            &[
                HashPart::Str(&current_id),
                HashPart::Str(&current_membership),
            ],
        ),
        backup_key_commitment: commitment(
            "pq-threshold-fast-finality-bridge:backup-key",
            &[HashPart::Str(&current_id), HashPart::Str(&next_membership)],
        ),
        membership_root: current_membership,
    };
    let next = ValidatorQuorum {
        id: next_id.clone(),
        epoch: height / config.epoch_blocks + 1,
        status: RotationStatus::Warming,
        activation_height: height + config.rotation_notice_blocks,
        expiry_height: height + config.rotation_notice_blocks + config.epoch_blocks,
        threshold_bps: config.fast_quorum_bps,
        emergency_threshold_bps: config.emergency_quorum_bps,
        validator_ids: next_ids,
        aggregate_key_commitment: commitment(
            "pq-threshold-fast-finality-bridge:aggregate-key",
            &[HashPart::Str(&next_id), HashPart::Str(&next_membership)],
        ),
        backup_key_commitment: commitment(
            "pq-threshold-fast-finality-bridge:backup-key",
            &[
                HashPart::Str(&next_id),
                HashPart::Str(&current.membership_root),
            ],
        ),
        membership_root: next_membership,
    };
    let mut quorums = BTreeMap::new();
    quorums.insert(current.id.clone(), current);
    quorums.insert(next.id.clone(), next);
    if quorums.is_empty() {
        return Err("failed to create devnet quorums".to_string());
    }
    Ok(quorums)
}

fn devnet_anchors(
    config: &Config,
    height: u64,
) -> PqThresholdFastFinalityBridgeResult<BTreeMap<String, MoneroAnchorCommitment>> {
    let watcher_a = "pqtfb-validator-aurora".to_string();
    let watcher_b = "pqtfb-validator-boron".to_string();
    let watcher_c = "pqtfb-validator-dahlia".to_string();
    let rows = [
        (0_u64, 91_200_u64, AnchorStatus::Finalized),
        (1_u64, 91_232_u64, AnchorStatus::ChallengeOpen),
        (2_u64, 91_264_u64, AnchorStatus::Attested),
    ];
    let mut anchors = BTreeMap::new();
    for (index, monero_height, status) in rows {
        let l2_height = height.saturating_sub(24).saturating_add(index * 4);
        let id = format!("pqtfb-anchor-{monero_height}");
        let observed_by = [watcher_a.clone(), watcher_b.clone(), watcher_c.clone()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let monero_block_hash = commitment(
            "pq-threshold-fast-finality-bridge:monero-block",
            &[
                HashPart::Str(config.monero_network.as_str()),
                HashPart::Int(monero_height as i128),
            ],
        );
        let monero_tx_root = commitment(
            "pq-threshold-fast-finality-bridge:monero-tx-root",
            &[HashPart::Str(&id), HashPart::Int(index as i128)],
        );
        let output_commitment_root = commitment(
            "pq-threshold-fast-finality-bridge:output-root",
            &[HashPart::Str(&id), HashPart::Str(config.asset_id.as_str())],
        );
        let key_image_root = commitment(
            "pq-threshold-fast-finality-bridge:key-image-root",
            &[HashPart::Str(&id), HashPart::Int(monero_height as i128)],
        );
        let bridge_event_root = commitment(
            "pq-threshold-fast-finality-bridge:bridge-event-root",
            &[HashPart::Str(&id), HashPart::Int(l2_height as i128)],
        );
        let record = json!({
            "bridge_event_root": bridge_event_root.clone(),
            "id": id.clone(),
            "key_image_root": key_image_root.clone(),
            "monero_block_hash": monero_block_hash.clone(),
            "monero_height": monero_height,
            "monero_tx_root": monero_tx_root.clone(),
            "output_commitment_root": output_commitment_root.clone()
        });
        let anchor = MoneroAnchorCommitment {
            id: id.clone(),
            monero_height,
            l2_height,
            monero_block_hash,
            monero_tx_root,
            output_commitment_root,
            key_image_root,
            bridge_event_root,
            observed_by,
            status,
            eligible_after_l2_height: l2_height + config.l2_reorg_delay_blocks,
            eligible_after_monero_height: monero_height + config.monero_reorg_delay_blocks,
            challenge_deadline_height: l2_height + config.challenge_window_blocks,
            commitment_root: root_from_record(&record),
        };
        anchors.insert(id, anchor);
    }
    if anchors.is_empty() {
        return Err("failed to create devnet anchors".to_string());
    }
    Ok(anchors)
}

fn devnet_attestations(
    config: &Config,
    height: u64,
    validators: &BTreeMap<String, Validator>,
    quorums: &BTreeMap<String, ValidatorQuorum>,
    anchors: &BTreeMap<String, MoneroAnchorCommitment>,
) -> PqThresholdFastFinalityBridgeResult<BTreeMap<String, AggregateFinalityAttestation>> {
    let quorum = match quorums
        .values()
        .find(|quorum| quorum.status == RotationStatus::Active)
    {
        Some(quorum) => quorum,
        None => return Err("missing active devnet quorum".to_string()),
    };
    let total_weight = validators
        .values()
        .map(Validator::signing_power)
        .sum::<u64>();
    let required = required_weight(total_weight, config.fast_quorum_bps);
    let mut attestations = BTreeMap::new();
    for (index, anchor) in anchors.values().enumerate() {
        let id = format!("pqtfb-attestation-{}", anchor.monero_height);
        let message = json!({
            "anchor_commitment_root": anchor.commitment_root.clone(),
            "anchor_id": anchor.id.clone(),
            "chain_id": config.chain_id.clone(),
            "l2_height": anchor.l2_height,
            "monero_height": anchor.monero_height,
            "quorum_id": quorum.id.clone()
        });
        let message_root = root_from_record(&message);
        let signer_ids = validators
            .values()
            .filter(|validator| validator.status.can_attest())
            .take(if index == 2 { 5 } else { 6 })
            .map(|validator| validator.id.clone())
            .collect::<BTreeSet<_>>();
        let mut signed_weight = 0_u64;
        let mut shares = BTreeMap::new();
        for signer_id in &signer_ids {
            if let Some(validator) = validators.get(signer_id) {
                signed_weight = signed_weight.saturating_add(validator.signing_power());
                let scheme = if signer_id.ends_with("boron") || signer_id.ends_with("fluorine") {
                    SignatureScheme::SlhDsa
                } else {
                    SignatureScheme::MlDsa
                };
                let share = SignatureShare {
                    validator_id: signer_id.clone(),
                    scheme,
                    weight: validator.signing_power(),
                    message_root: message_root.clone(),
                    signature_commitment: commitment(
                        "pq-threshold-fast-finality-bridge:signature-share",
                        &[
                            HashPart::Str(signer_id),
                            HashPart::Str(&message_root),
                            HashPart::Str(scheme.as_str()),
                        ],
                    ),
                    received_height: anchor.l2_height + 1,
                    latency_ms: 180 + (index as u64 * 70),
                };
                shares.insert(signer_id.clone(), share);
            }
        }
        let status = if signed_weight >= required {
            if index == 0 {
                AttestationStatus::Accepted
            } else {
                AttestationStatus::ChallengeOpen
            }
        } else {
            AttestationStatus::Collecting
        };
        let ml_dsa_aggregate_commitment = commitment(
            "pq-threshold-fast-finality-bridge:ml-dsa-aggregate",
            &[HashPart::Str(&id), HashPart::Str(&message_root)],
        );
        let slh_dsa_aggregate_commitment = commitment(
            "pq-threshold-fast-finality-bridge:slh-dsa-aggregate",
            &[HashPart::Str(&id), HashPart::Int(signed_weight as i128)],
        );
        let attestation_root = root_from_record(&json!({
            "id": id.clone(),
            "message_root": message_root.clone(),
            "ml_dsa_aggregate_commitment": ml_dsa_aggregate_commitment.clone(),
            "signed_weight": signed_weight,
            "slh_dsa_aggregate_commitment": slh_dsa_aggregate_commitment.clone()
        }));
        let attestation = AggregateFinalityAttestation {
            id: id.clone(),
            quorum_id: quorum.id.clone(),
            anchor_id: anchor.id.clone(),
            l2_height: anchor.l2_height,
            monero_height: anchor.monero_height,
            status,
            required_weight: required,
            signed_weight,
            threshold_bps: config.fast_quorum_bps,
            message_root,
            ml_dsa_aggregate_commitment,
            slh_dsa_aggregate_commitment,
            signer_ids,
            shares,
            opened_at_height: anchor.l2_height + 1,
            challenge_deadline_height: anchor.challenge_deadline_height,
            attestation_root,
        };
        let _ = height;
        attestations.insert(id, attestation);
    }
    Ok(attestations)
}

fn devnet_receipts(
    config: &Config,
    height: u64,
    anchors: &BTreeMap<String, MoneroAnchorCommitment>,
    attestations: &BTreeMap<String, AggregateFinalityAttestation>,
) -> PqThresholdFastFinalityBridgeResult<BTreeMap<String, FinalityReceipt>> {
    let mut receipts = BTreeMap::new();
    for attestation in attestations.values() {
        if !attestation.status.usable_for_receipt() {
            continue;
        }
        let anchor = match anchors.get(&attestation.anchor_id) {
            Some(anchor) => anchor,
            None => return Err("attestation references missing anchor during receipts".to_string()),
        };
        let id = format!("pqtfb-receipt-{}", anchor.monero_height);
        let included_anchor_ids = [anchor.id.clone()].into_iter().collect::<BTreeSet<_>>();
        let latency_ms = 360 + (receipts.len() as u64 * 90);
        let receipt_record = json!({
            "anchor_id": anchor.id.clone(),
            "attestation_id": attestation.id.clone(),
            "issued_height": height,
            "latency_ms": latency_ms
        });
        let receipt = FinalityReceipt {
            id: id.clone(),
            attestation_id: attestation.id.clone(),
            anchor_id: anchor.id.clone(),
            issued_height: height,
            expires_height: height + config.receipt_ttl_blocks,
            latency_ms,
            status: if anchor.status == AnchorStatus::Finalized {
                ReceiptStatus::Settled
            } else {
                ReceiptStatus::Released
            },
            release_lane: "low_latency_monero_bridge".to_string(),
            receipt_root: root_from_record(&receipt_record),
            included_anchor_ids,
        };
        receipts.insert(id, receipt);
    }
    Ok(receipts)
}

fn devnet_rotations(
    config: &Config,
    height: u64,
    quorums: &BTreeMap<String, ValidatorQuorum>,
) -> PqThresholdFastFinalityBridgeResult<BTreeMap<String, QuorumRotation>> {
    let mut values = quorums.values().collect::<Vec<_>>();
    values.sort_by_key(|quorum| quorum.epoch);
    if values.len() < 2 {
        return Ok(BTreeMap::new());
    }
    let from = values[0];
    let to = values[1];
    let id = stable_id(
        "pq-threshold-fast-finality-bridge:rotation-id",
        &[HashPart::Str(&from.id), HashPart::Str(&to.id)],
    );
    let overlap_start_height = to
        .activation_height
        .saturating_sub(config.rotation_overlap_blocks);
    let record = json!({
        "from_quorum_id": from.id.clone(),
        "overlap_start_height": overlap_start_height,
        "to_quorum_id": to.id.clone()
    });
    let rotation = QuorumRotation {
        id: format!("pqtfb-rotation-{id}"),
        from_quorum_id: from.id.clone(),
        to_quorum_id: to.id.clone(),
        status: if height >= overlap_start_height {
            RotationStatus::Overlap
        } else {
            RotationStatus::Warming
        },
        notice_height: height,
        overlap_start_height,
        activation_height: to.activation_height,
        retired_height: to.activation_height + config.rotation_overlap_blocks,
        handoff_root: root_from_record(&record),
        outgoing_signers: from.validator_ids.clone(),
        incoming_signers: to.validator_ids.clone(),
    };
    let mut rotations = BTreeMap::new();
    rotations.insert(rotation.id.clone(), rotation);
    Ok(rotations)
}

fn devnet_challenges(
    config: &Config,
    height: u64,
    attestations: &BTreeMap<String, AggregateFinalityAttestation>,
) -> PqThresholdFastFinalityBridgeResult<BTreeMap<String, ChallengeWindow>> {
    let mut challenges = BTreeMap::new();
    for attestation in attestations
        .values()
        .filter(|attestation| attestation.status == AttestationStatus::ChallengeOpen)
        .take(1)
    {
        let id = format!("pqtfb-challenge-{}", attestation.monero_height);
        let evidence = json!({
            "attestation_id": attestation.id,
            "kind": ChallengeKind::ReceiptLatencyExceeded.as_str(),
            "message_root": attestation.message_root
        });
        let challenge = ChallengeWindow {
            id: id.clone(),
            challenge_kind: ChallengeKind::ReceiptLatencyExceeded,
            status: ChallengeStatus::Open,
            subject_id: attestation.id.clone(),
            opened_height: height,
            deadline_height: height + config.challenge_window_blocks,
            challenger_id: "pqtfb-validator-dahlia".to_string(),
            evidence_root: root_from_record(&evidence),
            bond_amount: 25_000,
        };
        challenges.insert(id, challenge);
    }
    Ok(challenges)
}

fn membership_root(ids: &BTreeSet<String>) -> String {
    let leaves = ids
        .iter()
        .map(|id| json!({ "validator_id": id }))
        .collect::<Vec<_>>();
    merkle_root(
        "pq-threshold-fast-finality-bridge:quorum-membership",
        &leaves,
    )
}
