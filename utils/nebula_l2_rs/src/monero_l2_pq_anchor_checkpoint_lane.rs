use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqAnchorCheckpointLaneResult<T> = Result<T, String>;

pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-anchor-checkpoint-lane-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEVNET_COMMITTEE_ID: &str =
    "monero-l2-pq-anchor-checkpoint-lane-devnet-committee";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_HEADER_CHECKPOINT_SCHEME: &str =
    "monero-header-checkpoint-root-shake256-v1";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_L2_STATE_SCHEME: &str =
    "nebula-l2-state-root-bundle-v1";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_BRIDGE_STATE_SCHEME: &str =
    "monero-l2-bridge-state-roots-only-v1";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-anchor-committee-v1";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_WATCHER_QUORUM_SCHEME: &str =
    "privacy-preserving-watcher-quorum-roots-only-v1";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_REORG_WINDOW_SCHEME: &str =
    "monero-reorg-window-root-v1";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_CHALLENGE_SCHEME: &str =
    "monero-l2-anchor-challenge-resolution-v1";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_RECEIPT_SCHEME: &str =
    "monero-l2-finalized-anchor-receipt-v1";
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MONERO_FINALITY_DEPTH: u64 = 20;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_L2_FINALITY_DEPTH: u64 = 12;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_REORG_WINDOW_BLOCKS: u64 = 48;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 67;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MIN_WATCHER_WEIGHT: u64 = 3;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MIN_WATCHER_COUNT: u64 = 2;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_PROPOSALS: usize = 262_144;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_CHALLENGES: usize = 262_144;
pub const MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_RECEIPTS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorStatus {
    Proposed,
    ChallengeOpen,
    Challenged,
    ReorgReview,
    Accepted,
    Finalized,
    Rejected,
    Superseded,
    Expired,
}

impl AnchorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ChallengeOpen => "challenge_open",
            Self::Challenged => "challenged",
            Self::ReorgReview => "reorg_review",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Finalized | Self::Rejected | Self::Superseded | Self::Expired
        )
    }

    pub fn challengeable(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::ChallengeOpen | Self::Challenged | Self::ReorgReview
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    HeaderReorg,
    InvalidHeaderChain,
    InvalidL2StateRoot,
    InvalidBridgeRoot,
    WeakPqQuorum,
    WeakWatcherQuorum,
    PrivacyLeak,
    ReplayOrStaleAnchor,
    ReserveSafety,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderReorg => "header_reorg",
            Self::InvalidHeaderChain => "invalid_header_chain",
            Self::InvalidL2StateRoot => "invalid_l2_state_root",
            Self::InvalidBridgeRoot => "invalid_bridge_root",
            Self::WeakPqQuorum => "weak_pq_quorum",
            Self::WeakWatcherQuorum => "weak_watcher_quorum",
            Self::PrivacyLeak => "privacy_leak",
            Self::ReplayOrStaleAnchor => "replay_or_stale_anchor",
            Self::ReserveSafety => "reserve_safety",
        }
    }

    pub fn safety_critical(self) -> bool {
        matches!(
            self,
            Self::HeaderReorg | Self::InvalidBridgeRoot | Self::WeakPqQuorum | Self::ReserveSafety
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Sustained,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sustained => "sustained",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Sustained | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionKind {
    NoChallenge,
    ChallengeRejected,
    ChallengeSustained,
    WindowExpired,
    CommitteeOverride,
    ReorgConfirmed,
}

impl ResolutionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoChallenge => "no_challenge",
            Self::ChallengeRejected => "challenge_rejected",
            Self::ChallengeSustained => "challenge_sustained",
            Self::WindowExpired => "window_expired",
            Self::CommitteeOverride => "committee_override",
            Self::ReorgConfirmed => "reorg_confirmed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Proposed,
    Challenged,
    ChallengeResolved,
    Finalized,
    Rejected,
    Expired,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Challenged => "challenged",
            Self::ChallengeResolved => "challenge_resolved",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub committee_id: String,
    pub header_checkpoint_scheme: String,
    pub l2_state_scheme: String,
    pub bridge_state_scheme: String,
    pub pq_attestation_scheme: String,
    pub watcher_quorum_scheme: String,
    pub reorg_window_scheme: String,
    pub challenge_scheme: String,
    pub receipt_scheme: String,
    pub monero_finality_depth: u64,
    pub l2_finality_depth: u64,
    pub reorg_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_committee_weight: u64,
    pub committee_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_watcher_weight: u64,
    pub min_watcher_count: u64,
    pub min_pq_security_bits: u16,
    pub roots_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEVNET_NETWORK.to_string(),
            l2_network: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEVNET_ASSET_ID.to_string(),
            committee_id: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEVNET_COMMITTEE_ID.to_string(),
            header_checkpoint_scheme: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_HEADER_CHECKPOINT_SCHEME
                .to_string(),
            l2_state_scheme: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_L2_STATE_SCHEME.to_string(),
            bridge_state_scheme: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_BRIDGE_STATE_SCHEME
                .to_string(),
            pq_attestation_scheme: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_PQ_ATTESTATION_SCHEME
                .to_string(),
            watcher_quorum_scheme: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_WATCHER_QUORUM_SCHEME
                .to_string(),
            reorg_window_scheme: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_REORG_WINDOW_SCHEME
                .to_string(),
            challenge_scheme: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_CHALLENGE_SCHEME.to_string(),
            receipt_scheme: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_RECEIPT_SCHEME.to_string(),
            monero_finality_depth:
                MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MONERO_FINALITY_DEPTH,
            l2_finality_depth: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_L2_FINALITY_DEPTH,
            reorg_window_blocks: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_REORG_WINDOW_BLOCKS,
            challenge_window_blocks:
                MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_committee_weight: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MIN_COMMITTEE_WEIGHT,
            committee_quorum_bps: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_COMMITTEE_QUORUM_BPS,
            strong_quorum_bps: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_STRONG_QUORUM_BPS,
            min_watcher_weight: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MIN_WATCHER_WEIGHT,
            min_watcher_count: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MIN_WATCHER_COUNT,
            min_pq_security_bits: MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_DEFAULT_MIN_PQ_SECURITY_BITS,
            roots_only: true,
        }
    }

    pub fn validate(&self) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported pq anchor checkpoint lane protocol version".to_string());
        }
        if self.schema_version != MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_SCHEMA_VERSION {
            return Err("unsupported pq anchor checkpoint lane schema version".to_string());
        }
        if !self.roots_only {
            return Err("pq anchor checkpoint lane must remain roots-only".to_string());
        }
        if self.monero_finality_depth == 0 || self.l2_finality_depth == 0 {
            return Err("finality depths must be nonzero".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("challenge window must be nonzero".to_string());
        }
        if self.reorg_window_blocks < self.monero_finality_depth {
            return Err("reorg window must cover Monero finality depth".to_string());
        }
        if self.min_committee_weight == 0 || self.min_watcher_weight == 0 {
            return Err("quorum weights must be nonzero".to_string());
        }
        if self.committee_quorum_bps == 0
            || self.committee_quorum_bps > MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_BPS
        {
            return Err("committee quorum bps is out of range".to_string());
        }
        if self.strong_quorum_bps < self.committee_quorum_bps
            || self.strong_quorum_bps > MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_BPS
        {
            return Err("strong quorum bps must be at least committee quorum bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": CHAIN_ID,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "committee_id": self.committee_id,
            "header_checkpoint_scheme": self.header_checkpoint_scheme,
            "l2_state_scheme": self.l2_state_scheme,
            "bridge_state_scheme": self.bridge_state_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "watcher_quorum_scheme": self.watcher_quorum_scheme,
            "reorg_window_scheme": self.reorg_window_scheme,
            "challenge_scheme": self.challenge_scheme,
            "receipt_scheme": self.receipt_scheme,
            "monero_finality_depth": self.monero_finality_depth,
            "l2_finality_depth": self.l2_finality_depth,
            "reorg_window_blocks": self.reorg_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_committee_weight": self.min_committee_weight,
            "committee_quorum_bps": self.committee_quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "min_watcher_weight": self.min_watcher_weight,
            "min_watcher_count": self.min_watcher_count,
            "min_pq_security_bits": self.min_pq_security_bits,
            "roots_only": self.roots_only,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_anchor_sequence: u64,
    pub next_challenge_sequence: u64,
    pub next_receipt_sequence: u64,
    pub anchors_proposed: u64,
    pub anchors_challenged: u64,
    pub anchors_finalized: u64,
    pub anchors_rejected: u64,
    pub challenges_sustained: u64,
    pub challenges_rejected: u64,
    pub challenges_expired: u64,
    pub reorg_reviews_opened: u64,
    pub receipts_issued: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_anchor_sequence": self.next_anchor_sequence,
            "next_challenge_sequence": self.next_challenge_sequence,
            "next_receipt_sequence": self.next_receipt_sequence,
            "anchors_proposed": self.anchors_proposed,
            "anchors_challenged": self.anchors_challenged,
            "anchors_finalized": self.anchors_finalized,
            "anchors_rejected": self.anchors_rejected,
            "challenges_sustained": self.challenges_sustained,
            "challenges_rejected": self.challenges_rejected,
            "challenges_expired": self.challenges_expired,
            "reorg_reviews_opened": self.reorg_reviews_opened,
            "receipts_issued": self.receipts_issued,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroHeaderCheckpoint {
    pub monero_height: u64,
    pub block_hash_root: String,
    pub previous_block_hash_root: String,
    pub cumulative_difficulty_root: String,
    pub pow_context_root: String,
    pub tx_tree_root: String,
    pub output_root: String,
    pub key_image_root: String,
    pub timestamp_root: String,
    pub header_chain_root: String,
}

impl MoneroHeaderCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "monero_height": self.monero_height,
            "block_hash_root": self.block_hash_root,
            "previous_block_hash_root": self.previous_block_hash_root,
            "cumulative_difficulty_root": self.cumulative_difficulty_root,
            "pow_context_root": self.pow_context_root,
            "tx_tree_root": self.tx_tree_root,
            "output_root": self.output_root,
            "key_image_root": self.key_image_root,
            "timestamp_root": self.timestamp_root,
            "header_chain_root": self.header_chain_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-HEADER",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
        validate_root("block_hash_root", &self.block_hash_root)?;
        validate_root("previous_block_hash_root", &self.previous_block_hash_root)?;
        validate_root(
            "cumulative_difficulty_root",
            &self.cumulative_difficulty_root,
        )?;
        validate_root("pow_context_root", &self.pow_context_root)?;
        validate_root("tx_tree_root", &self.tx_tree_root)?;
        validate_root("output_root", &self.output_root)?;
        validate_root("key_image_root", &self.key_image_root)?;
        validate_root("timestamp_root", &self.timestamp_root)?;
        validate_root("header_chain_root", &self.header_chain_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeL2StateRoots {
    pub l2_height: u64,
    pub l2_state_root: String,
    pub l2_block_root: String,
    pub bridge_state_root: String,
    pub reserve_root: String,
    pub exit_queue_root: String,
    pub withdrawal_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub da_root: String,
    pub proof_batch_root: String,
    pub fee_market_root: String,
}

impl BridgeL2StateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "l2_height": self.l2_height,
            "l2_state_root": self.l2_state_root,
            "l2_block_root": self.l2_block_root,
            "bridge_state_root": self.bridge_state_root,
            "reserve_root": self.reserve_root,
            "exit_queue_root": self.exit_queue_root,
            "withdrawal_root": self.withdrawal_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "da_root": self.da_root,
            "proof_batch_root": self.proof_batch_root,
            "fee_market_root": self.fee_market_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-L2-BRIDGE-STATE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
        validate_root("l2_state_root", &self.l2_state_root)?;
        validate_root("l2_block_root", &self.l2_block_root)?;
        validate_root("bridge_state_root", &self.bridge_state_root)?;
        validate_root("reserve_root", &self.reserve_root)?;
        validate_root("exit_queue_root", &self.exit_queue_root)?;
        validate_root("withdrawal_root", &self.withdrawal_root)?;
        validate_root("nullifier_root", &self.nullifier_root)?;
        validate_root("replay_fence_root", &self.replay_fence_root)?;
        validate_root("da_root", &self.da_root)?;
        validate_root("proof_batch_root", &self.proof_batch_root)?;
        validate_root("fee_market_root", &self.fee_market_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeAttestation {
    pub committee_id: String,
    pub epoch: u64,
    pub signer_count: u64,
    pub signer_weight: u64,
    pub total_weight: u64,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub signer_set_root: String,
    pub key_rotation_root: String,
    pub attestation_context_root: String,
}

impl PqCommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "signer_count": self.signer_count,
            "signer_weight": self.signer_weight,
            "total_weight": self.total_weight,
            "quorum_bps": self.quorum_bps,
            "pq_security_bits": self.pq_security_bits,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "slh_dsa_signature_root": self.slh_dsa_signature_root,
            "signer_set_root": self.signer_set_root,
            "key_rotation_root": self.key_rotation_root,
            "attestation_context_root": self.attestation_context_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-COMMITTEE-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &Config) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
        if self.committee_id != config.committee_id {
            return Err("pq committee id mismatch".to_string());
        }
        if self.signer_count == 0 {
            return Err("pq committee signer count must be nonzero".to_string());
        }
        if self.signer_weight < config.min_committee_weight {
            return Err("pq committee signer weight below minimum".to_string());
        }
        if self.total_weight == 0 || self.signer_weight > self.total_weight {
            return Err("pq committee total weight is invalid".to_string());
        }
        let observed_bps = bps(self.signer_weight, self.total_weight);
        if observed_bps < config.committee_quorum_bps
            || self.quorum_bps < config.committee_quorum_bps
        {
            return Err("pq committee quorum is insufficient".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq security bits below minimum".to_string());
        }
        validate_root("ml_dsa_signature_root", &self.ml_dsa_signature_root)?;
        validate_root("slh_dsa_signature_root", &self.slh_dsa_signature_root)?;
        validate_root("signer_set_root", &self.signer_set_root)?;
        validate_root("key_rotation_root", &self.key_rotation_root)?;
        validate_root("attestation_context_root", &self.attestation_context_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherQuorumCertificate {
    pub watcher_set_id: String,
    pub watcher_count: u64,
    pub watcher_weight: u64,
    pub min_disclosure_count: u64,
    pub watcher_root: String,
    pub encrypted_evidence_root: String,
    pub selective_disclosure_root: String,
    pub fraud_signal_root: String,
    pub reserve_observation_root: String,
    pub bridge_safety_root: String,
}

impl WatcherQuorumCertificate {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_set_id": self.watcher_set_id,
            "watcher_count": self.watcher_count,
            "watcher_weight": self.watcher_weight,
            "min_disclosure_count": self.min_disclosure_count,
            "watcher_root": self.watcher_root,
            "encrypted_evidence_root": self.encrypted_evidence_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "fraud_signal_root": self.fraud_signal_root,
            "reserve_observation_root": self.reserve_observation_root,
            "bridge_safety_root": self.bridge_safety_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-WATCHER-QUORUM",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &Config) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
        if self.watcher_set_id.trim().is_empty() {
            return Err("watcher_set_id is required".to_string());
        }
        if self.watcher_count < config.min_watcher_count {
            return Err("watcher count below minimum".to_string());
        }
        if self.watcher_weight < config.min_watcher_weight {
            return Err("watcher weight below minimum".to_string());
        }
        validate_root("watcher_root", &self.watcher_root)?;
        validate_root("encrypted_evidence_root", &self.encrypted_evidence_root)?;
        validate_root("selective_disclosure_root", &self.selective_disclosure_root)?;
        validate_root("fraud_signal_root", &self.fraud_signal_root)?;
        validate_root("reserve_observation_root", &self.reserve_observation_root)?;
        validate_root("bridge_safety_root", &self.bridge_safety_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgWindow {
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub canonical_tip_height: u64,
    pub canonical_tip_root: String,
    pub competing_tip_root: String,
    pub observed_reorg_depth: u64,
    pub reorg_evidence_root: String,
    pub stability_score_bps: u64,
}

impl ReorgWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "canonical_tip_height": self.canonical_tip_height,
            "canonical_tip_root": self.canonical_tip_root,
            "competing_tip_root": self.competing_tip_root,
            "observed_reorg_depth": self.observed_reorg_depth,
            "reorg_evidence_root": self.reorg_evidence_root,
            "stability_score_bps": self.stability_score_bps,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-REORG-WINDOW",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &Config) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
        if self.window_end_height < self.window_start_height {
            return Err("reorg window end precedes start".to_string());
        }
        if self
            .window_end_height
            .saturating_sub(self.window_start_height)
            < config.reorg_window_blocks
        {
            return Err("reorg window shorter than configured hold".to_string());
        }
        if self.canonical_tip_height < self.window_start_height {
            return Err("canonical tip is before reorg window".to_string());
        }
        if self.stability_score_bps > MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_BPS {
            return Err("stability score exceeds bps limit".to_string());
        }
        validate_root("canonical_tip_root", &self.canonical_tip_root)?;
        validate_root("competing_tip_root", &self.competing_tip_root)?;
        validate_root("reorg_evidence_root", &self.reorg_evidence_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposeAnchorRequest {
    pub proposer_id: String,
    pub epoch: u64,
    pub submitted_l2_height: u64,
    pub header_checkpoint: MoneroHeaderCheckpoint,
    pub bridge_state: BridgeL2StateRoots,
    pub pq_attestation: PqCommitteeAttestation,
    pub watcher_quorum: WatcherQuorumCertificate,
    pub reorg_window: ReorgWindow,
    pub previous_anchor_root: String,
    pub proposal_nonce: String,
}

impl ProposeAnchorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposer_id": self.proposer_id,
            "epoch": self.epoch,
            "submitted_l2_height": self.submitted_l2_height,
            "header_checkpoint": self.header_checkpoint.public_record(),
            "bridge_state": self.bridge_state.public_record(),
            "pq_attestation": self.pq_attestation.public_record(),
            "watcher_quorum": self.watcher_quorum.public_record(),
            "reorg_window": self.reorg_window.public_record(),
            "previous_anchor_root": self.previous_anchor_root,
            "proposal_nonce": self.proposal_nonce,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-PROPOSE-REQUEST",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeAnchorRequest {
    pub anchor_id: String,
    pub challenger_id: String,
    pub kind: ChallengeKind,
    pub opened_l2_height: u64,
    pub allegation_root: String,
    pub counter_header_root: String,
    pub counter_state_root: String,
    pub counter_watcher_root: String,
    pub encrypted_evidence_root: String,
    pub selective_disclosure_root: String,
    pub pq_signature_root: String,
    pub challenge_nonce: String,
}

impl ChallengeAnchorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "challenger_id": self.challenger_id,
            "kind": self.kind.as_str(),
            "opened_l2_height": self.opened_l2_height,
            "allegation_root": self.allegation_root,
            "counter_header_root": self.counter_header_root,
            "counter_state_root": self.counter_state_root,
            "counter_watcher_root": self.counter_watcher_root,
            "encrypted_evidence_root": self.encrypted_evidence_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "pq_signature_root": self.pq_signature_root,
            "challenge_nonce": self.challenge_nonce,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-CHALLENGE-REQUEST",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResolutionRequest {
    pub challenge_id: String,
    pub sustained: bool,
    pub resolver_id: String,
    pub resolved_l2_height: u64,
    pub resolution_kind: ResolutionKind,
    pub resolution_root: String,
    pub pq_signature_root: String,
    pub public_note_root: String,
}

impl ChallengeResolutionRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "sustained": self.sustained,
            "resolver_id": self.resolver_id,
            "resolved_l2_height": self.resolved_l2_height,
            "resolution_kind": self.resolution_kind.as_str(),
            "resolution_root": self.resolution_root,
            "pq_signature_root": self.pq_signature_root,
            "public_note_root": self.public_note_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-RESOLUTION-REQUEST",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeAnchorRequest {
    pub anchor_id: String,
    pub finalizer_id: String,
    pub finalized_l2_height: u64,
    pub observed_monero_height: u64,
    pub finality_attestation_root: String,
    pub settlement_batch_root: String,
    pub release_authorization_root: String,
    pub pq_signature_root: String,
    pub challenge_resolutions: Vec<ChallengeResolutionRequest>,
    pub finalize_nonce: String,
}

impl FinalizeAnchorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "finalizer_id": self.finalizer_id,
            "finalized_l2_height": self.finalized_l2_height,
            "observed_monero_height": self.observed_monero_height,
            "finality_attestation_root": self.finality_attestation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "release_authorization_root": self.release_authorization_root,
            "pq_signature_root": self.pq_signature_root,
            "challenge_resolutions": self
                .challenge_resolutions
                .iter()
                .map(ChallengeResolutionRequest::public_record)
                .collect::<Vec<_>>(),
            "finalize_nonce": self.finalize_nonce,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-FINALIZE-REQUEST",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorProposal {
    pub anchor_id: String,
    pub sequence: u64,
    pub status: AnchorStatus,
    pub proposer_id: String,
    pub epoch: u64,
    pub submitted_l2_height: u64,
    pub challenge_deadline_l2_height: u64,
    pub monero_unlock_height: u64,
    pub reorg_hold_until_height: u64,
    pub header_checkpoint: MoneroHeaderCheckpoint,
    pub bridge_state: BridgeL2StateRoots,
    pub pq_attestation: PqCommitteeAttestation,
    pub watcher_quorum: WatcherQuorumCertificate,
    pub reorg_window: ReorgWindow,
    pub proposal_root: String,
    pub header_checkpoint_root: String,
    pub bridge_state_root: String,
    pub pq_attestation_root: String,
    pub watcher_quorum_root: String,
    pub reorg_window_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
    pub previous_anchor_root: String,
    pub finalized_receipt_id: Option<String>,
}

impl AnchorProposal {
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "proposer_id": self.proposer_id,
            "epoch": self.epoch,
            "submitted_l2_height": self.submitted_l2_height,
            "challenge_deadline_l2_height": self.challenge_deadline_l2_height,
            "monero_unlock_height": self.monero_unlock_height,
            "reorg_hold_until_height": self.reorg_hold_until_height,
            "header_checkpoint": self.header_checkpoint.public_record(),
            "bridge_state": self.bridge_state.public_record(),
            "pq_attestation": self.pq_attestation.public_record(),
            "watcher_quorum": self.watcher_quorum.public_record(),
            "reorg_window": self.reorg_window.public_record(),
            "proposal_root": self.proposal_root,
            "header_checkpoint_root": self.header_checkpoint_root,
            "bridge_state_root": self.bridge_state_root,
            "pq_attestation_root": self.pq_attestation_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "reorg_window_root": self.reorg_window_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
            "previous_anchor_root": self.previous_anchor_root,
            "finalized_receipt_id": self.finalized_receipt_id,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-PROPOSAL",
            &self.public_record(),
        )
    }

    pub fn roots_record(&self) -> Value {
        json!({
            "anchor_id": self.anchor_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "monero_height": self.header_checkpoint.monero_height,
            "l2_height": self.bridge_state.l2_height,
            "proposal_root": self.proposal_root,
            "header_checkpoint_root": self.header_checkpoint_root,
            "bridge_state_root": self.bridge_state_root,
            "pq_attestation_root": self.pq_attestation_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "reorg_window_root": self.reorg_window_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorChallenge {
    pub challenge_id: String,
    pub anchor_id: String,
    pub sequence: u64,
    pub status: ChallengeStatus,
    pub challenger_id: String,
    pub kind: ChallengeKind,
    pub opened_l2_height: u64,
    pub deadline_l2_height: u64,
    pub allegation_root: String,
    pub counter_header_root: String,
    pub counter_state_root: String,
    pub counter_watcher_root: String,
    pub encrypted_evidence_root: String,
    pub selective_disclosure_root: String,
    pub pq_signature_root: String,
    pub challenge_root: String,
    pub resolution_root: String,
}

impl AnchorChallenge {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "anchor_id": self.anchor_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "challenger_id": self.challenger_id,
            "kind": self.kind.as_str(),
            "safety_critical": self.kind.safety_critical(),
            "opened_l2_height": self.opened_l2_height,
            "deadline_l2_height": self.deadline_l2_height,
            "allegation_root": self.allegation_root,
            "counter_header_root": self.counter_header_root,
            "counter_state_root": self.counter_state_root,
            "counter_watcher_root": self.counter_watcher_root,
            "encrypted_evidence_root": self.encrypted_evidence_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "pq_signature_root": self.pq_signature_root,
            "challenge_root": self.challenge_root,
            "resolution_root": self.resolution_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-CHALLENGE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorChallengeResolution {
    pub resolution_id: String,
    pub challenge_id: String,
    pub anchor_id: String,
    pub sustained: bool,
    pub resolver_id: String,
    pub resolved_l2_height: u64,
    pub resolution_kind: ResolutionKind,
    pub resolution_root: String,
    pub pq_signature_root: String,
    pub public_note_root: String,
}

impl AnchorChallengeResolution {
    pub fn public_record(&self) -> Value {
        json!({
            "resolution_id": self.resolution_id,
            "challenge_id": self.challenge_id,
            "anchor_id": self.anchor_id,
            "sustained": self.sustained,
            "resolver_id": self.resolver_id,
            "resolved_l2_height": self.resolved_l2_height,
            "resolution_kind": self.resolution_kind.as_str(),
            "resolution_root": self.resolution_root,
            "pq_signature_root": self.pq_signature_root,
            "public_note_root": self.public_note_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-RESOLUTION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedAnchorReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub anchor_id: String,
    pub status: AnchorStatus,
    pub kind: ReceiptKind,
    pub finalizer_id: String,
    pub finalized_l2_height: u64,
    pub observed_monero_height: u64,
    pub finality_attestation_root: String,
    pub settlement_batch_root: String,
    pub release_authorization_root: String,
    pub pq_signature_root: String,
    pub challenge_resolution_root: String,
    pub anchor_root: String,
    pub receipt_root: String,
}

impl FinalizedAnchorReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "anchor_id": self.anchor_id,
            "status": self.status.as_str(),
            "kind": self.kind.as_str(),
            "finalizer_id": self.finalizer_id,
            "finalized_l2_height": self.finalized_l2_height,
            "observed_monero_height": self.observed_monero_height,
            "finality_attestation_root": self.finality_attestation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "release_authorization_root": self.release_authorization_root,
            "pq_signature_root": self.pq_signature_root,
            "challenge_resolution_root": self.challenge_resolution_root,
            "anchor_root": self.anchor_root,
            "receipt_root": self.receipt_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub anchor_root: String,
    pub open_anchor_root: String,
    pub finalized_anchor_root: String,
    pub challenge_root: String,
    pub open_challenge_root: String,
    pub resolution_root: String,
    pub receipt_root: String,
    pub header_checkpoint_root: String,
    pub bridge_state_root: String,
    pub pq_attestation_root: String,
    pub watcher_quorum_root: String,
    pub reorg_window_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_root": self.anchor_root,
            "open_anchor_root": self.open_anchor_root,
            "finalized_anchor_root": self.finalized_anchor_root,
            "challenge_root": self.challenge_root,
            "open_challenge_root": self.open_challenge_root,
            "resolution_root": self.resolution_root,
            "receipt_root": self.receipt_root,
            "header_checkpoint_root": self.header_checkpoint_root,
            "bridge_state_root": self.bridge_state_root,
            "pq_attestation_root": self.pq_attestation_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "reorg_window_root": self.reorg_window_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub anchors: BTreeMap<String, AnchorProposal>,
    pub challenges: BTreeMap<String, AnchorChallenge>,
    pub resolutions: BTreeMap<String, AnchorChallengeResolution>,
    pub receipts: BTreeMap<String, FinalizedAnchorReceipt>,
    pub anchors_by_monero_height: BTreeMap<u64, BTreeSet<String>>,
    pub anchors_by_l2_height: BTreeMap<u64, BTreeSet<String>>,
    pub challenges_by_anchor: BTreeMap<String, BTreeSet<String>>,
    pub open_challenges_by_deadline: BTreeMap<u64, BTreeSet<String>>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            anchors: BTreeMap::new(),
            challenges: BTreeMap::new(),
            resolutions: BTreeMap::new(),
            receipts: BTreeMap::new(),
            anchors_by_monero_height: BTreeMap::new(),
            anchors_by_l2_height: BTreeMap::new(),
            challenges_by_anchor: BTreeMap::new(),
            open_challenges_by_deadline: BTreeMap::new(),
        }
    }

    pub fn propose_anchor(
        &mut self,
        request: ProposeAnchorRequest,
    ) -> MoneroL2PqAnchorCheckpointLaneResult<AnchorProposal> {
        self.config.validate()?;
        if self.anchors.len() >= MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_PROPOSALS {
            return Err("pq anchor proposal capacity reached".to_string());
        }
        validate_propose_request(&request, &self.config)?;

        let sequence = self.counters.next_anchor_sequence;
        self.counters.next_anchor_sequence = self.counters.next_anchor_sequence.saturating_add(1);
        let header_checkpoint_root = request.header_checkpoint.root();
        let bridge_state_root = request.bridge_state.root();
        let pq_attestation_root = request.pq_attestation.root();
        let watcher_quorum_root = request.watcher_quorum.root();
        let reorg_window_root = request.reorg_window.root();
        let proposal_seed = json!({
            "sequence": sequence,
            "request_root": request.root(),
            "header_checkpoint_root": header_checkpoint_root,
            "bridge_state_root": bridge_state_root,
            "pq_attestation_root": pq_attestation_root,
            "watcher_quorum_root": watcher_quorum_root,
            "reorg_window_root": reorg_window_root,
            "previous_anchor_root": request.previous_anchor_root,
        });
        let proposal_root = lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-PROPOSAL-SEED",
            &proposal_seed,
        );
        let anchor_id = anchor_id(
            sequence,
            request.epoch,
            request.header_checkpoint.monero_height,
            request.bridge_state.l2_height,
            &proposal_root,
            &request.proposal_nonce,
        );
        if self.anchors.contains_key(&anchor_id) {
            return Err("pq anchor proposal already exists".to_string());
        }

        let status = if request.reorg_window.observed_reorg_depth > 0 {
            self.counters.reorg_reviews_opened =
                self.counters.reorg_reviews_opened.saturating_add(1);
            AnchorStatus::ReorgReview
        } else {
            AnchorStatus::ChallengeOpen
        };
        let challenge_deadline_l2_height = request
            .submitted_l2_height
            .saturating_add(self.config.challenge_window_blocks);
        let monero_unlock_height = request
            .header_checkpoint
            .monero_height
            .saturating_add(self.config.monero_finality_depth);
        let reorg_hold_until_height = request
            .header_checkpoint
            .monero_height
            .saturating_add(self.config.reorg_window_blocks);
        let proposal = AnchorProposal {
            anchor_id: anchor_id.clone(),
            sequence,
            status,
            proposer_id: request.proposer_id,
            epoch: request.epoch,
            submitted_l2_height: request.submitted_l2_height,
            challenge_deadline_l2_height,
            monero_unlock_height,
            reorg_hold_until_height,
            header_checkpoint: request.header_checkpoint,
            bridge_state: request.bridge_state,
            pq_attestation: request.pq_attestation,
            watcher_quorum: request.watcher_quorum,
            reorg_window: request.reorg_window,
            proposal_root,
            header_checkpoint_root,
            bridge_state_root,
            pq_attestation_root,
            watcher_quorum_root,
            reorg_window_root,
            challenge_root: empty_root("MONERO-L2-PQ-ANCHOR-CHECKPOINT-ANCHOR-CHALLENGES"),
            receipt_root: empty_root("MONERO-L2-PQ-ANCHOR-CHECKPOINT-ANCHOR-RECEIPTS"),
            previous_anchor_root: request.previous_anchor_root,
            finalized_receipt_id: None,
        };

        let receipt = self.issue_receipt(
            &proposal.anchor_id,
            AnchorStatus::ChallengeOpen,
            ReceiptKind::Proposed,
            proposal.submitted_l2_height,
            proposal.header_checkpoint.monero_height,
            &proposal.proposer_id,
            &proposal.proposal_root,
            &proposal.proposal_root,
            &proposal.proposal_root,
            &proposal.proposal_root,
            &proposal.pq_attestation_root,
            empty_root("MONERO-L2-PQ-ANCHOR-CHECKPOINT-NO-RESOLUTION"),
        )?;
        let mut proposal = proposal;
        proposal.receipt_root = receipt.root();
        self.anchors_by_monero_height
            .entry(proposal.header_checkpoint.monero_height)
            .or_default()
            .insert(anchor_id.clone());
        self.anchors_by_l2_height
            .entry(proposal.bridge_state.l2_height)
            .or_default()
            .insert(anchor_id.clone());
        self.anchors.insert(anchor_id, proposal.clone());
        self.counters.anchors_proposed = self.counters.anchors_proposed.saturating_add(1);
        Ok(proposal)
    }

    pub fn challenge_anchor(
        &mut self,
        request: ChallengeAnchorRequest,
    ) -> MoneroL2PqAnchorCheckpointLaneResult<AnchorChallenge> {
        self.config.validate()?;
        if self.challenges.len() >= MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_CHALLENGES {
            return Err("pq anchor challenge capacity reached".to_string());
        }
        validate_challenge_request(&request)?;
        self.expire_open_challenges(request.opened_l2_height)?;

        let anchor = self
            .anchors
            .get(&request.anchor_id)
            .ok_or_else(|| "pq anchor proposal not found".to_string())?;
        if !anchor.status.challengeable() {
            return Err("pq anchor proposal no longer accepts challenges".to_string());
        }
        if request.opened_l2_height > anchor.challenge_deadline_l2_height {
            return Err("pq anchor challenge window has closed".to_string());
        }

        let sequence = self.counters.next_challenge_sequence;
        self.counters.next_challenge_sequence =
            self.counters.next_challenge_sequence.saturating_add(1);
        let challenge_root = lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-CHALLENGE-SEED",
            &json!({
                "sequence": sequence,
                "request_root": request.root(),
                "anchor_root": anchor.root(),
            }),
        );
        let challenge_id = challenge_id(
            sequence,
            &request.anchor_id,
            request.kind,
            &request.challenger_id,
            &request.allegation_root,
            &request.challenge_nonce,
        );
        let challenge = AnchorChallenge {
            challenge_id: challenge_id.clone(),
            anchor_id: request.anchor_id.clone(),
            sequence,
            status: ChallengeStatus::Open,
            challenger_id: request.challenger_id.clone(),
            kind: request.kind,
            opened_l2_height: request.opened_l2_height,
            deadline_l2_height: anchor.challenge_deadline_l2_height,
            allegation_root: request.allegation_root,
            counter_header_root: request.counter_header_root,
            counter_state_root: request.counter_state_root,
            counter_watcher_root: request.counter_watcher_root,
            encrypted_evidence_root: request.encrypted_evidence_root,
            selective_disclosure_root: request.selective_disclosure_root,
            pq_signature_root: request.pq_signature_root,
            challenge_root,
            resolution_root: empty_root("MONERO-L2-PQ-ANCHOR-CHECKPOINT-UNRESOLVED-CHALLENGE"),
        };

        self.challenges
            .insert(challenge_id.clone(), challenge.clone());
        self.challenges_by_anchor
            .entry(request.anchor_id.clone())
            .or_default()
            .insert(challenge_id.clone());
        self.open_challenges_by_deadline
            .entry(challenge.deadline_l2_height)
            .or_default()
            .insert(challenge_id);
        self.refresh_anchor_challenge_root(&request.anchor_id)?;
        let anchor_status = if request.kind.safety_critical() {
            AnchorStatus::ReorgReview
        } else {
            AnchorStatus::Challenged
        };
        let (actor_id, event_root, pq_root, monero_height) = {
            let anchor = self
                .anchors
                .get_mut(&request.anchor_id)
                .ok_or_else(|| "pq anchor proposal not found".to_string())?;
            anchor.status = anchor_status;
            (
                request.challenger_id,
                anchor.challenge_root.clone(),
                challenge.pq_signature_root.clone(),
                anchor.header_checkpoint.monero_height,
            )
        };
        let receipt = self.issue_receipt(
            &request.anchor_id,
            anchor_status,
            ReceiptKind::Challenged,
            challenge.opened_l2_height,
            monero_height,
            &actor_id,
            &event_root,
            &event_root,
            &event_root,
            &event_root,
            &pq_root,
            empty_root("MONERO-L2-PQ-ANCHOR-CHECKPOINT-NO-RESOLUTION"),
        )?;
        if let Some(anchor) = self.anchors.get_mut(&request.anchor_id) {
            anchor.receipt_root = receipt.root();
        }
        self.counters.anchors_challenged = self.counters.anchors_challenged.saturating_add(1);
        Ok(challenge)
    }

    pub fn finalize_anchor(
        &mut self,
        request: FinalizeAnchorRequest,
    ) -> MoneroL2PqAnchorCheckpointLaneResult<FinalizedAnchorReceipt> {
        self.config.validate()?;
        validate_finalize_request(&request)?;
        self.expire_open_challenges(request.finalized_l2_height)?;

        let anchor = self
            .anchors
            .get(&request.anchor_id)
            .ok_or_else(|| "pq anchor proposal not found".to_string())?
            .clone();
        if anchor.status.terminal() {
            return Err("pq anchor proposal is already terminal".to_string());
        }
        if request.finalized_l2_height < anchor.challenge_deadline_l2_height {
            return Err("pq anchor challenge window is still open".to_string());
        }
        if request.finalized_l2_height
            < anchor
                .bridge_state
                .l2_height
                .saturating_add(self.config.l2_finality_depth)
        {
            return Err("l2 finality depth has not elapsed".to_string());
        }
        if request.observed_monero_height < anchor.monero_unlock_height {
            return Err("monero finality depth has not elapsed".to_string());
        }
        if request.observed_monero_height < anchor.reorg_hold_until_height {
            return Err("monero reorg hold has not elapsed".to_string());
        }

        let mut resolution_records = Vec::new();
        for resolution_request in &request.challenge_resolutions {
            let resolution =
                self.apply_challenge_resolution(&request.anchor_id, resolution_request.clone())?;
            resolution_records.push(resolution.public_record());
        }
        self.expire_anchor_open_challenges(&request.anchor_id, request.finalized_l2_height)?;
        let challenge_resolution_root = merkle_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-FINALIZE-RESOLUTIONS",
            &resolution_records,
        );

        let challenge_ids = self
            .challenges_by_anchor
            .get(&request.anchor_id)
            .cloned()
            .unwrap_or_default();
        let mut has_sustained = false;
        let mut has_open = false;
        for challenge_id in challenge_ids {
            let Some(challenge) = self.challenges.get(&challenge_id) else {
                continue;
            };
            match challenge.status {
                ChallengeStatus::Sustained => has_sustained = true,
                ChallengeStatus::Open => has_open = true,
                ChallengeStatus::Rejected | ChallengeStatus::Expired => {}
            }
        }
        if has_open {
            return Err("pq anchor has unresolved open challenges".to_string());
        }

        let final_status = if has_sustained {
            AnchorStatus::Rejected
        } else {
            AnchorStatus::Finalized
        };
        let receipt_kind = if has_sustained {
            ReceiptKind::Rejected
        } else {
            ReceiptKind::Finalized
        };
        let anchor_root_before = anchor.root();
        let receipt = self.issue_receipt(
            &request.anchor_id,
            final_status,
            receipt_kind,
            request.finalized_l2_height,
            request.observed_monero_height,
            &request.finalizer_id,
            &request.finality_attestation_root,
            &request.settlement_batch_root,
            &request.release_authorization_root,
            &anchor_root_before,
            &request.pq_signature_root,
            challenge_resolution_root,
        )?;

        let receipt_root = receipt.root();
        if let Some(anchor) = self.anchors.get_mut(&request.anchor_id) {
            anchor.status = final_status;
            anchor.receipt_root = receipt_root;
            anchor.finalized_receipt_id = Some(receipt.receipt_id.clone());
        }
        if has_sustained {
            self.counters.anchors_rejected = self.counters.anchors_rejected.saturating_add(1);
        } else {
            self.counters.anchors_finalized = self.counters.anchors_finalized.saturating_add(1);
        }

        let mut receipt = receipt;
        receipt.anchor_root = anchor_root_before;
        let updated_receipt_root = receipt.root();
        receipt.receipt_root = updated_receipt_root;
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let anchor_records = self
            .anchors
            .values()
            .map(AnchorProposal::public_record)
            .collect::<Vec<_>>();
        let open_anchor_records = self
            .anchors
            .values()
            .filter(|anchor| !anchor.status.terminal())
            .map(AnchorProposal::roots_record)
            .collect::<Vec<_>>();
        let finalized_anchor_records = self
            .anchors
            .values()
            .filter(|anchor| anchor.status == AnchorStatus::Finalized)
            .map(AnchorProposal::roots_record)
            .collect::<Vec<_>>();
        let challenge_records = self
            .challenges
            .values()
            .map(AnchorChallenge::public_record)
            .collect::<Vec<_>>();
        let open_challenge_records = self
            .challenges
            .values()
            .filter(|challenge| challenge.status == ChallengeStatus::Open)
            .map(AnchorChallenge::public_record)
            .collect::<Vec<_>>();
        let resolution_records = self
            .resolutions
            .values()
            .map(AnchorChallengeResolution::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(FinalizedAnchorReceipt::public_record)
            .collect::<Vec<_>>();
        let header_records = self
            .anchors
            .values()
            .map(|anchor| {
                json!({
                    "anchor_id": anchor.anchor_id,
                    "monero_height": anchor.header_checkpoint.monero_height,
                    "root": anchor.header_checkpoint_root,
                })
            })
            .collect::<Vec<_>>();
        let bridge_state_records = self
            .anchors
            .values()
            .map(|anchor| {
                json!({
                    "anchor_id": anchor.anchor_id,
                    "l2_height": anchor.bridge_state.l2_height,
                    "root": anchor.bridge_state_root,
                })
            })
            .collect::<Vec<_>>();
        let pq_records = self
            .anchors
            .values()
            .map(
                |anchor| json!({"anchor_id": anchor.anchor_id, "root": anchor.pq_attestation_root}),
            )
            .collect::<Vec<_>>();
        let watcher_records = self
            .anchors
            .values()
            .map(
                |anchor| json!({"anchor_id": anchor.anchor_id, "root": anchor.watcher_quorum_root}),
            )
            .collect::<Vec<_>>();
        let reorg_records = self
            .anchors
            .values()
            .map(|anchor| json!({"anchor_id": anchor.anchor_id, "root": anchor.reorg_window_root}))
            .collect::<Vec<_>>();

        Roots {
            anchor_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-ANCHORS",
                &anchor_records,
            ),
            open_anchor_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-OPEN-ANCHORS",
                &open_anchor_records,
            ),
            finalized_anchor_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-FINALIZED-ANCHORS",
                &finalized_anchor_records,
            ),
            challenge_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-CHALLENGES",
                &challenge_records,
            ),
            open_challenge_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-OPEN-CHALLENGES",
                &open_challenge_records,
            ),
            resolution_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-RESOLUTIONS",
                &resolution_records,
            ),
            receipt_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-RECEIPTS",
                &receipt_records,
            ),
            header_checkpoint_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-HEADERS",
                &header_records,
            ),
            bridge_state_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-BRIDGE",
                &bridge_state_records,
            ),
            pq_attestation_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-PQ",
                &pq_records,
            ),
            watcher_quorum_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-WATCHERS",
                &watcher_records,
            ),
            reorg_window_root: merkle_root(
                "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE-REORG-WINDOWS",
                &reorg_records,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "privacy_boundary": "roots_only_no_plaintext_monero_addresses_no_amounts_no_view_keys",
            "config": self.config.public_record(),
            "config_root": self.config.root(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "anchor_count": self.anchors.len(),
            "challenge_count": self.challenges.len(),
            "resolution_count": self.resolutions.len(),
            "receipt_count": self.receipts.len(),
        })
    }

    pub fn state_root(&self) -> String {
        lane_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-STATE",
            &self.public_record(),
        )
    }

    fn apply_challenge_resolution(
        &mut self,
        anchor_id: &str,
        request: ChallengeResolutionRequest,
    ) -> MoneroL2PqAnchorCheckpointLaneResult<AnchorChallengeResolution> {
        validate_resolution_request(&request)?;
        let challenge = self
            .challenges
            .get(&request.challenge_id)
            .ok_or_else(|| "pq anchor challenge not found".to_string())?
            .clone();
        if challenge.anchor_id != anchor_id {
            return Err("challenge resolution anchor mismatch".to_string());
        }
        if challenge.status.terminal() {
            return Err("pq anchor challenge is already terminal".to_string());
        }
        if request.resolved_l2_height < challenge.opened_l2_height {
            return Err("challenge resolution precedes challenge open height".to_string());
        }
        let status = if request.sustained {
            ChallengeStatus::Sustained
        } else {
            ChallengeStatus::Rejected
        };
        let resolution_id = resolution_id(
            &request.challenge_id,
            anchor_id,
            request.sustained,
            &request.resolution_root,
            &request.pq_signature_root,
        );
        let resolution = AnchorChallengeResolution {
            resolution_id: resolution_id.clone(),
            challenge_id: request.challenge_id.clone(),
            anchor_id: anchor_id.to_string(),
            sustained: request.sustained,
            resolver_id: request.resolver_id.clone(),
            resolved_l2_height: request.resolved_l2_height,
            resolution_kind: request.resolution_kind,
            resolution_root: request.resolution_root,
            pq_signature_root: request.pq_signature_root,
            public_note_root: request.public_note_root,
        };
        let resolution_root = resolution.root();
        if let Some(challenge) = self.challenges.get_mut(&request.challenge_id) {
            challenge.status = status;
            challenge.resolution_root = resolution_root.clone();
        }
        self.resolutions.insert(resolution_id, resolution.clone());
        self.remove_open_challenge(&request.challenge_id);
        self.refresh_anchor_challenge_root(anchor_id)?;
        match status {
            ChallengeStatus::Sustained => {
                self.counters.challenges_sustained =
                    self.counters.challenges_sustained.saturating_add(1)
            }
            ChallengeStatus::Rejected => {
                self.counters.challenges_rejected =
                    self.counters.challenges_rejected.saturating_add(1)
            }
            ChallengeStatus::Open | ChallengeStatus::Expired => {}
        }
        let monero_height = self
            .anchors
            .get(anchor_id)
            .map(|anchor| anchor.header_checkpoint.monero_height)
            .unwrap_or_default();
        let _ = self.issue_receipt(
            anchor_id,
            if request.sustained {
                AnchorStatus::Rejected
            } else {
                AnchorStatus::Challenged
            },
            ReceiptKind::ChallengeResolved,
            request.resolved_l2_height,
            monero_height,
            &request.resolver_id,
            &resolution_root,
            &resolution_root,
            &resolution_root,
            &resolution_root,
            &resolution.pq_signature_root,
            resolution_root.clone(),
        )?;
        Ok(resolution)
    }

    fn expire_open_challenges(
        &mut self,
        current_l2_height: u64,
    ) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
        let expired_deadlines = self
            .open_challenges_by_deadline
            .range(..current_l2_height)
            .map(|(deadline, _)| *deadline)
            .collect::<Vec<_>>();
        for deadline in expired_deadlines {
            let Some(challenge_ids) = self.open_challenges_by_deadline.remove(&deadline) else {
                continue;
            };
            for challenge_id in challenge_ids {
                if let Some(challenge) = self.challenges.get_mut(&challenge_id) {
                    if challenge.status == ChallengeStatus::Open {
                        challenge.status = ChallengeStatus::Expired;
                        self.counters.challenges_expired =
                            self.counters.challenges_expired.saturating_add(1);
                    }
                }
            }
        }
        let anchor_ids = self.anchors.keys().cloned().collect::<Vec<_>>();
        for anchor_id in anchor_ids {
            self.refresh_anchor_challenge_root(&anchor_id)?;
        }
        Ok(())
    }

    fn expire_anchor_open_challenges(
        &mut self,
        anchor_id: &str,
        current_l2_height: u64,
    ) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
        let challenge_ids = self
            .challenges_by_anchor
            .get(anchor_id)
            .cloned()
            .unwrap_or_default();
        for challenge_id in challenge_ids {
            let should_expire = self
                .challenges
                .get(&challenge_id)
                .map(|challenge| {
                    challenge.status == ChallengeStatus::Open
                        && current_l2_height >= challenge.deadline_l2_height
                })
                .unwrap_or(false);
            if should_expire {
                if let Some(challenge) = self.challenges.get_mut(&challenge_id) {
                    challenge.status = ChallengeStatus::Expired;
                    self.counters.challenges_expired =
                        self.counters.challenges_expired.saturating_add(1);
                }
                self.remove_open_challenge(&challenge_id);
            }
        }
        self.refresh_anchor_challenge_root(anchor_id)?;
        Ok(())
    }

    fn refresh_anchor_challenge_root(
        &mut self,
        anchor_id: &str,
    ) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
        let challenge_ids = self
            .challenges_by_anchor
            .get(anchor_id)
            .cloned()
            .unwrap_or_default();
        let challenge_records = challenge_ids
            .iter()
            .filter_map(|challenge_id| self.challenges.get(challenge_id))
            .map(AnchorChallenge::public_record)
            .collect::<Vec<_>>();
        let challenge_root = merkle_root(
            "MONERO-L2-PQ-ANCHOR-CHECKPOINT-ANCHOR-CHALLENGES",
            &challenge_records,
        );
        if let Some(anchor) = self.anchors.get_mut(anchor_id) {
            anchor.challenge_root = challenge_root;
            Ok(())
        } else {
            Err("pq anchor proposal not found".to_string())
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_receipt(
        &mut self,
        anchor_id: &str,
        status: AnchorStatus,
        kind: ReceiptKind,
        l2_height: u64,
        monero_height: u64,
        actor_id: &str,
        finality_attestation_root: &str,
        settlement_batch_root: &str,
        release_authorization_root: &str,
        anchor_root: &str,
        pq_signature_root: &str,
        challenge_resolution_root: String,
    ) -> MoneroL2PqAnchorCheckpointLaneResult<FinalizedAnchorReceipt> {
        if self.receipts.len() >= MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_RECEIPTS {
            return Err("pq anchor receipt capacity reached".to_string());
        }
        validate_root("finality_attestation_root", finality_attestation_root)?;
        validate_root("settlement_batch_root", settlement_batch_root)?;
        validate_root("release_authorization_root", release_authorization_root)?;
        validate_root("anchor_root", anchor_root)?;
        validate_root("pq_signature_root", pq_signature_root)?;
        validate_root("challenge_resolution_root", &challenge_resolution_root)?;
        if actor_id.trim().is_empty() {
            return Err("receipt actor id is required".to_string());
        }
        let sequence = self.counters.next_receipt_sequence;
        self.counters.next_receipt_sequence = self.counters.next_receipt_sequence.saturating_add(1);
        let receipt_root = receipt_root(
            sequence,
            anchor_id,
            status,
            kind,
            l2_height,
            monero_height,
            actor_id,
            finality_attestation_root,
            pq_signature_root,
            &challenge_resolution_root,
        );
        let receipt_id = receipt_id(sequence, anchor_id, &receipt_root);
        let receipt = FinalizedAnchorReceipt {
            receipt_id: receipt_id.clone(),
            sequence,
            anchor_id: anchor_id.to_string(),
            status,
            kind,
            finalizer_id: actor_id.to_string(),
            finalized_l2_height: l2_height,
            observed_monero_height: monero_height,
            finality_attestation_root: finality_attestation_root.to_string(),
            settlement_batch_root: settlement_batch_root.to_string(),
            release_authorization_root: release_authorization_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            challenge_resolution_root,
            anchor_root: anchor_root.to_string(),
            receipt_root,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        self.counters.receipts_issued = self.counters.receipts_issued.saturating_add(1);
        Ok(receipt)
    }

    fn remove_open_challenge(&mut self, challenge_id: &str) {
        let empty_deadlines = self
            .open_challenges_by_deadline
            .iter_mut()
            .filter_map(|(deadline, ids)| {
                ids.remove(challenge_id);
                ids.is_empty().then_some(*deadline)
            })
            .collect::<Vec<_>>();
        for deadline in empty_deadlines {
            self.open_challenges_by_deadline.remove(&deadline);
        }
    }
}

pub fn monero_header_checkpoint_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PQ-ANCHOR-CHECKPOINT-HEADER-ROOT", records)
}

pub fn bridge_l2_state_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PQ-ANCHOR-CHECKPOINT-BRIDGE-STATE-ROOT", records)
}

pub fn pq_committee_attestation_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-ANCHOR-CHECKPOINT-COMMITTEE-ATTESTATION-ROOT",
        records,
    )
}

pub fn watcher_quorum_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-ANCHOR-CHECKPOINT-WATCHER-QUORUM-ROOT",
        records,
    )
}

pub fn reorg_window_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PQ-ANCHOR-CHECKPOINT-REORG-WINDOW-ROOT", records)
}

fn validate_propose_request(
    request: &ProposeAnchorRequest,
    config: &Config,
) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
    if request.proposer_id.trim().is_empty() {
        return Err("proposer_id is required".to_string());
    }
    if request.proposal_nonce.trim().is_empty() {
        return Err("proposal_nonce is required".to_string());
    }
    if request.bridge_state.l2_height > request.submitted_l2_height {
        return Err("submitted l2 height precedes bridge state height".to_string());
    }
    request.header_checkpoint.validate()?;
    request.bridge_state.validate()?;
    request.pq_attestation.validate(config)?;
    request.watcher_quorum.validate(config)?;
    request.reorg_window.validate(config)?;
    validate_root("previous_anchor_root", &request.previous_anchor_root)?;
    Ok(())
}

fn validate_challenge_request(
    request: &ChallengeAnchorRequest,
) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
    if request.anchor_id.trim().is_empty() {
        return Err("anchor_id is required".to_string());
    }
    if request.challenger_id.trim().is_empty() {
        return Err("challenger_id is required".to_string());
    }
    if request.challenge_nonce.trim().is_empty() {
        return Err("challenge_nonce is required".to_string());
    }
    validate_root("allegation_root", &request.allegation_root)?;
    validate_root("counter_header_root", &request.counter_header_root)?;
    validate_root("counter_state_root", &request.counter_state_root)?;
    validate_root("counter_watcher_root", &request.counter_watcher_root)?;
    validate_root("encrypted_evidence_root", &request.encrypted_evidence_root)?;
    validate_root(
        "selective_disclosure_root",
        &request.selective_disclosure_root,
    )?;
    validate_root("pq_signature_root", &request.pq_signature_root)?;
    Ok(())
}

fn validate_resolution_request(
    request: &ChallengeResolutionRequest,
) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
    if request.challenge_id.trim().is_empty() {
        return Err("challenge_id is required".to_string());
    }
    if request.resolver_id.trim().is_empty() {
        return Err("resolver_id is required".to_string());
    }
    validate_root("resolution_root", &request.resolution_root)?;
    validate_root("pq_signature_root", &request.pq_signature_root)?;
    validate_root("public_note_root", &request.public_note_root)?;
    Ok(())
}

fn validate_finalize_request(
    request: &FinalizeAnchorRequest,
) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
    if request.anchor_id.trim().is_empty() {
        return Err("anchor_id is required".to_string());
    }
    if request.finalizer_id.trim().is_empty() {
        return Err("finalizer_id is required".to_string());
    }
    if request.finalize_nonce.trim().is_empty() {
        return Err("finalize_nonce is required".to_string());
    }
    validate_root(
        "finality_attestation_root",
        &request.finality_attestation_root,
    )?;
    validate_root("settlement_batch_root", &request.settlement_batch_root)?;
    validate_root(
        "release_authorization_root",
        &request.release_authorization_root,
    )?;
    validate_root("pq_signature_root", &request.pq_signature_root)?;
    Ok(())
}

fn anchor_id(
    sequence: u64,
    epoch: u64,
    monero_height: u64,
    l2_height: u64,
    proposal_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-ANCHOR-CHECKPOINT-ANCHOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Int(epoch as i128),
            HashPart::Int(monero_height as i128),
            HashPart::Int(l2_height as i128),
            HashPart::Str(proposal_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

fn challenge_id(
    sequence: u64,
    anchor_id: &str,
    kind: ChallengeKind,
    challenger_id: &str,
    allegation_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-ANCHOR-CHECKPOINT-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(anchor_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(challenger_id),
            HashPart::Str(allegation_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

fn resolution_id(
    challenge_id: &str,
    anchor_id: &str,
    sustained: bool,
    resolution_root: &str,
    pq_signature_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-ANCHOR-CHECKPOINT-RESOLUTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(challenge_id),
            HashPart::Str(anchor_id),
            HashPart::Str(if sustained { "sustained" } else { "rejected" }),
            HashPart::Str(resolution_root),
            HashPart::Str(pq_signature_root),
        ],
        32,
    )
}

fn receipt_id(sequence: u64, anchor_id: &str, receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-ANCHOR-CHECKPOINT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(anchor_id),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn receipt_root(
    sequence: u64,
    anchor_id: &str,
    status: AnchorStatus,
    kind: ReceiptKind,
    l2_height: u64,
    monero_height: u64,
    actor_id: &str,
    event_root: &str,
    pq_signature_root: &str,
    challenge_resolution_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-ANCHOR-CHECKPOINT-RECEIPT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(anchor_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Int(l2_height as i128),
            HashPart::Int(monero_height as i128),
            HashPart::Str(actor_id),
            HashPart::Str(event_root),
            HashPart::Str(pq_signature_root),
            HashPart::Str(challenge_resolution_root),
        ],
        32,
    )
}

fn lane_root(domain: &str, record: &Value) -> String {
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

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn validate_root(name: &str, root: &str) -> MoneroL2PqAnchorCheckpointLaneResult<()> {
    if root.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(MONERO_L2_PQ_ANCHOR_CHECKPOINT_LANE_MAX_BPS) / denominator
}
