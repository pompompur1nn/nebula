use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqReorgRescueRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-reorg-rescue-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_REORG_RESCUE_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_PQ_WATCHER_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192f-reorg-rescue-watcher-v1";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_CHECKPOINT_SCHEME: &str =
    "monero-watched-checkpoint-roots-only-v1";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_REPLAY_FENCE_SCHEME: &str =
    "monero-l2-private-deposit-withdrawal-replay-fence-v1";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_REORG_EVIDENCE_SCHEME: &str =
    "monero-l2-reorg-rescue-evidence-roots-only-v1";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_LIQUIDITY_RESCUE_SCHEME: &str =
    "emergency-liquidity-rescue-window-v1";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_LOW_FEE_BATCH_SCHEME: &str =
    "low-fee-reorg-rescue-batch-settlement-v1";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_RECEIPT_SCHEME: &str =
    "monero-l2-pq-reorg-rescue-receipt-v1";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_COMMITTEE_ID: &str =
    "monero-l2-pq-reorg-rescue-devnet-watchers";
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_HEIGHT: u64 = 372_000;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MONERO_FINALITY_DEPTH: u64 = 20;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_REORG_ALERT_DEPTH: u64 = 12;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_REORG_RESCUE_DEPTH: u64 = 32;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_RESCUE_WINDOW_BLOCKS: u64 = 144;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 288;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MIN_WATCHER_WEIGHT: u64 = 3;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MIN_WATCHER_COUNT: u64 = 2;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 5;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MAX_BATCH_SIZE: usize = 256;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_CHECKPOINTS: usize = 262_144;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_REPLAY_FENCES: usize = 1_048_576;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_ATTESTATIONS: usize = 524_288;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_WINDOWS: usize = 131_072;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_BATCHES: usize = 262_144;
pub const MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_RECEIPTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgSeverity {
    Watch,
    Alert,
    Rescue,
    Halt,
}

impl ReorgSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Alert => "alert",
            Self::Rescue => "rescue",
            Self::Halt => "halt",
        }
    }

    pub fn opens_rescue(self) -> bool {
        matches!(self, Self::Rescue | Self::Halt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStatus {
    Watched,
    QuorumAttested,
    ReorgDetected,
    RescueOpen,
    Batched,
    Superseded,
}

impl CheckpointStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watched => "watched",
            Self::QuorumAttested => "quorum_attested",
            Self::ReorgDetected => "reorg_detected",
            Self::RescueOpen => "rescue_open",
            Self::Batched => "batched",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    PrivateDeposit,
    PrivateWithdrawal,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDeposit => "private_deposit",
            Self::PrivateWithdrawal => "private_withdrawal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Registered,
    Quarantined,
    Rescued,
    Replayed,
    Expired,
}

impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Quarantined => "quarantined",
            Self::Rescued => "rescued",
            Self::Replayed => "replayed",
            Self::Expired => "expired",
        }
    }

    pub fn rescue_eligible(self) -> bool {
        matches!(self, Self::Registered | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherAttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    Superseded,
}

impl WatcherAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::WeakQuorum => "weak_quorum",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RescueWindowStatus {
    Open,
    Settling,
    Settled,
    Expired,
    Halted,
}

impl RescueWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Halted => "halted",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RescueBatchStatus {
    Built,
    Submitted,
    Settled,
    Rejected,
}

impl RescueBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RescueReceiptKind {
    CheckpointWatched,
    ReplayFenceRegistered,
    WatcherQuorumAccepted,
    WindowOpened,
    BatchSettled,
}

impl RescueReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CheckpointWatched => "checkpoint_watched",
            Self::ReplayFenceRegistered => "replay_fence_registered",
            Self::WatcherQuorumAccepted => "watcher_quorum_accepted",
            Self::WindowOpened => "window_opened",
            Self::BatchSettled => "batch_settled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub committee_id: String,
    pub hash_suite: String,
    pub pq_watcher_suite: String,
    pub checkpoint_scheme: String,
    pub replay_fence_scheme: String,
    pub reorg_evidence_scheme: String,
    pub liquidity_rescue_scheme: String,
    pub low_fee_batch_scheme: String,
    pub receipt_scheme: String,
    pub monero_finality_depth: u64,
    pub reorg_alert_depth: u64,
    pub reorg_rescue_depth: u64,
    pub rescue_window_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_watcher_weight: u64,
    pub min_watcher_count: u64,
    pub watcher_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_batch_size: usize,
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
            schema_version: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_MONERO_NETWORK.to_string(),
            l2_network: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_FEE_ASSET_ID.to_string(),
            committee_id: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_COMMITTEE_ID.to_string(),
            hash_suite: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_HASH_SUITE.to_string(),
            pq_watcher_suite: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_PQ_WATCHER_SUITE.to_string(),
            checkpoint_scheme: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_CHECKPOINT_SCHEME.to_string(),
            replay_fence_scheme: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_REPLAY_FENCE_SCHEME.to_string(),
            reorg_evidence_scheme: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_REORG_EVIDENCE_SCHEME
                .to_string(),
            liquidity_rescue_scheme: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_LIQUIDITY_RESCUE_SCHEME
                .to_string(),
            low_fee_batch_scheme: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_LOW_FEE_BATCH_SCHEME
                .to_string(),
            receipt_scheme: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_RECEIPT_SCHEME.to_string(),
            monero_finality_depth: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MONERO_FINALITY_DEPTH,
            reorg_alert_depth: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_REORG_ALERT_DEPTH,
            reorg_rescue_depth: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_REORG_RESCUE_DEPTH,
            rescue_window_blocks: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_RESCUE_WINDOW_BLOCKS,
            settlement_ttl_blocks: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_watcher_weight: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MIN_WATCHER_WEIGHT,
            min_watcher_count: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MIN_WATCHER_COUNT,
            watcher_quorum_bps: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_WATCHER_QUORUM_BPS,
            strong_quorum_bps: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_STRONG_QUORUM_BPS,
            min_pq_security_bits: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_bps: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_batch_size: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEFAULT_MAX_BATCH_SIZE,
            roots_only: true,
        }
    }

    pub fn validate(&self) -> MoneroL2PqReorgRescueRuntimeResult<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol mismatch",
        )?;
        require(
            self.schema_version == MONERO_L2_PQ_REORG_RESCUE_RUNTIME_SCHEMA_VERSION,
            "schema mismatch",
        )?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(
            self.roots_only,
            "reorg rescue runtime must remain roots-only",
        )?;
        required("monero_network", &self.monero_network)?;
        required("l2_network", &self.l2_network)?;
        required("asset_id", &self.asset_id)?;
        required("fee_asset_id", &self.fee_asset_id)?;
        required("committee_id", &self.committee_id)?;
        require(
            self.monero_finality_depth > 0
                && self.reorg_alert_depth > 0
                && self.reorg_rescue_depth >= self.reorg_alert_depth,
            "invalid reorg depth policy",
        )?;
        require(self.rescue_window_blocks > 0, "rescue window is zero")?;
        require(self.settlement_ttl_blocks > 0, "settlement ttl is zero")?;
        require(
            self.min_watcher_weight > 0 && self.min_watcher_count > 0,
            "watcher quorum minimums must be nonzero",
        )?;
        require(
            self.watcher_quorum_bps > 0
                && self.watcher_quorum_bps <= MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_BPS
                && self.strong_quorum_bps >= self.watcher_quorum_bps
                && self.strong_quorum_bps <= MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_BPS,
            "watcher quorum bps policy invalid",
        )?;
        require(
            self.min_pq_security_bits >= 192,
            "minimum PQ security bits too low",
        )?;
        require(
            self.low_fee_bps <= MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_BPS,
            "low fee bps exceeds max bps",
        )?;
        require(self.max_batch_size > 0, "max batch size is zero")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "committee_id": self.committee_id,
            "hash_suite": self.hash_suite,
            "pq_watcher_suite": self.pq_watcher_suite,
            "checkpoint_scheme": self.checkpoint_scheme,
            "replay_fence_scheme": self.replay_fence_scheme,
            "reorg_evidence_scheme": self.reorg_evidence_scheme,
            "liquidity_rescue_scheme": self.liquidity_rescue_scheme,
            "low_fee_batch_scheme": self.low_fee_batch_scheme,
            "receipt_scheme": self.receipt_scheme,
            "monero_finality_depth": self.monero_finality_depth,
            "reorg_alert_depth": self.reorg_alert_depth,
            "reorg_rescue_depth": self.reorg_rescue_depth,
            "rescue_window_blocks": self.rescue_window_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "min_watcher_weight": self.min_watcher_weight,
            "min_watcher_count": self.min_watcher_count,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_bps": self.low_fee_bps,
            "max_batch_size": self.max_batch_size,
            "roots_only": self.roots_only,
        })
    }

    pub fn root(&self) -> String {
        record_hash("MONERO-L2-PQ-REORG-RESCUE-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub checkpoint_counter: u64,
    pub replay_fence_counter: u64,
    pub watcher_attestation_counter: u64,
    pub rescue_window_counter: u64,
    pub rescue_batch_counter: u64,
    pub receipt_counter: u64,
    pub consumed_replay_fence_counter: u64,
    pub reorgs_detected: u64,
    pub low_fee_batches_settled: u64,
    pub rescued_private_items: u64,
    pub total_rescued_amount: u128,
    pub total_low_fee: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_counter": self.checkpoint_counter,
            "replay_fence_counter": self.replay_fence_counter,
            "watcher_attestation_counter": self.watcher_attestation_counter,
            "rescue_window_counter": self.rescue_window_counter,
            "rescue_batch_counter": self.rescue_batch_counter,
            "receipt_counter": self.receipt_counter,
            "consumed_replay_fence_counter": self.consumed_replay_fence_counter,
            "reorgs_detected": self.reorgs_detected,
            "low_fee_batches_settled": self.low_fee_batches_settled,
            "rescued_private_items": self.rescued_private_items,
            "total_rescued_amount": self.total_rescued_amount,
            "total_low_fee": self.total_low_fee,
        })
    }

    pub fn root(&self) -> String {
        record_hash("MONERO-L2-PQ-REORG-RESCUE-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitWatchedCheckpointRequest {
    pub watcher_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub observed_l2_height: u64,
    pub block_hash_root: String,
    pub previous_block_hash_root: String,
    pub header_chain_root: String,
    pub txset_root: String,
    pub output_root: String,
    pub key_image_root: String,
    pub anchor_state_root: String,
    pub prior_checkpoint_root: String,
    pub checkpoint_nonce: String,
}

impl SubmitWatchedCheckpointRequest {
    pub fn validate(&self) -> MoneroL2PqReorgRescueRuntimeResult<()> {
        required("watcher_id", &self.watcher_id)?;
        required("block_hash_root", &self.block_hash_root)?;
        required("previous_block_hash_root", &self.previous_block_hash_root)?;
        required("header_chain_root", &self.header_chain_root)?;
        required("txset_root", &self.txset_root)?;
        required("output_root", &self.output_root)?;
        required("key_image_root", &self.key_image_root)?;
        required("anchor_state_root", &self.anchor_state_root)?;
        required("prior_checkpoint_root", &self.prior_checkpoint_root)?;
        required("checkpoint_nonce", &self.checkpoint_nonce)?;
        require(
            self.observed_l2_height >= self.l2_height,
            "checkpoint observed before l2 height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "observed_l2_height": self.observed_l2_height,
            "block_hash_root": self.block_hash_root,
            "previous_block_hash_root": self.previous_block_hash_root,
            "header_chain_root": self.header_chain_root,
            "txset_root": self.txset_root,
            "output_root": self.output_root,
            "key_image_root": self.key_image_root,
            "anchor_state_root": self.anchor_state_root,
            "prior_checkpoint_root": self.prior_checkpoint_root,
            "checkpoint_nonce": self.checkpoint_nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedMoneroCheckpoint {
    pub checkpoint_id: String,
    pub sequence: u64,
    pub status: CheckpointStatus,
    pub watcher_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub observed_l2_height: u64,
    pub block_hash_root: String,
    pub previous_block_hash_root: String,
    pub header_chain_root: String,
    pub txset_root: String,
    pub output_root: String,
    pub key_image_root: String,
    pub anchor_state_root: String,
    pub prior_checkpoint_root: String,
    pub watcher_attestation_root: String,
    pub rescue_window_id: Option<String>,
}

impl WatchedMoneroCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "watcher_id": self.watcher_id,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "observed_l2_height": self.observed_l2_height,
            "block_hash_root": self.block_hash_root,
            "previous_block_hash_root": self.previous_block_hash_root,
            "header_chain_root": self.header_chain_root,
            "txset_root": self.txset_root,
            "output_root": self.output_root,
            "key_image_root": self.key_image_root,
            "anchor_state_root": self.anchor_state_root,
            "prior_checkpoint_root": self.prior_checkpoint_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "rescue_window_id": self.rescue_window_id,
        })
    }

    pub fn root(&self) -> String {
        record_hash(
            "MONERO-L2-PQ-REORG-RESCUE-WATCHED-CHECKPOINT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterPrivateReplayFenceRequest {
    pub checkpoint_id: String,
    pub fence_kind: FenceKind,
    pub private_note_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub amount_commitment_root: String,
    pub owner_commitment_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub amount: u128,
    pub registered_l2_height: u64,
    pub expires_l2_height: u64,
}

impl RegisterPrivateReplayFenceRequest {
    pub fn validate(&self) -> MoneroL2PqReorgRescueRuntimeResult<()> {
        required("checkpoint_id", &self.checkpoint_id)?;
        required("private_note_root", &self.private_note_root)?;
        required("nullifier_root", &self.nullifier_root)?;
        required("replay_fence_root", &self.replay_fence_root)?;
        required("amount_commitment_root", &self.amount_commitment_root)?;
        required("owner_commitment_root", &self.owner_commitment_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        require(self.amount > 0, "private replay fence amount is zero")?;
        require(
            self.expires_l2_height > self.registered_l2_height,
            "private replay fence must expire after registration",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "fence_kind": self.fence_kind.as_str(),
            "private_note_root": self.private_note_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "amount_commitment_root": self.amount_commitment_root,
            "owner_commitment_root": self.owner_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "amount": self.amount,
            "registered_l2_height": self.registered_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateReplayFenceRecord {
    pub replay_fence_id: String,
    pub sequence: u64,
    pub checkpoint_id: String,
    pub fence_kind: FenceKind,
    pub status: FenceStatus,
    pub private_note_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub amount_commitment_root: String,
    pub owner_commitment_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub amount: u128,
    pub registered_l2_height: u64,
    pub expires_l2_height: u64,
    pub rescue_window_id: Option<String>,
    pub rescue_batch_id: Option<String>,
}

impl PrivateReplayFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_fence_id": self.replay_fence_id,
            "sequence": self.sequence,
            "checkpoint_id": self.checkpoint_id,
            "fence_kind": self.fence_kind.as_str(),
            "status": self.status.as_str(),
            "private_note_root": self.private_note_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "amount_commitment_root": self.amount_commitment_root,
            "owner_commitment_root": self.owner_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "amount": self.amount,
            "registered_l2_height": self.registered_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "rescue_window_id": self.rescue_window_id,
            "rescue_batch_id": self.rescue_batch_id,
        })
    }

    pub fn root(&self) -> String {
        record_hash(
            "MONERO-L2-PQ-REORG-RESCUE-PRIVATE-REPLAY-FENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPqWatcherAttestationRequest {
    pub checkpoint_id: String,
    pub severity: ReorgSeverity,
    pub watcher_set_root: String,
    pub reorg_evidence_root: String,
    pub alternative_header_root: String,
    pub affected_private_fence_root: String,
    pub liquidity_snapshot_root: String,
    pub rescue_policy_root: String,
    pub aggregate_pq_signature_root: String,
    pub watcher_count: u64,
    pub watcher_weight: u64,
    pub total_watcher_weight: u64,
    pub pq_security_bits: u16,
    pub attested_l2_height: u64,
    pub attestation_nonce: String,
}

impl SubmitPqWatcherAttestationRequest {
    pub fn validate(&self, config: &Config) -> MoneroL2PqReorgRescueRuntimeResult<()> {
        required("checkpoint_id", &self.checkpoint_id)?;
        required("watcher_set_root", &self.watcher_set_root)?;
        required("reorg_evidence_root", &self.reorg_evidence_root)?;
        required("alternative_header_root", &self.alternative_header_root)?;
        required(
            "affected_private_fence_root",
            &self.affected_private_fence_root,
        )?;
        required("liquidity_snapshot_root", &self.liquidity_snapshot_root)?;
        required("rescue_policy_root", &self.rescue_policy_root)?;
        required(
            "aggregate_pq_signature_root",
            &self.aggregate_pq_signature_root,
        )?;
        required("attestation_nonce", &self.attestation_nonce)?;
        require(
            self.watcher_count >= config.min_watcher_count,
            "watcher count below quorum floor",
        )?;
        require(
            self.watcher_weight >= config.min_watcher_weight,
            "watcher weight below quorum floor",
        )?;
        require(
            self.total_watcher_weight >= self.watcher_weight && self.total_watcher_weight > 0,
            "watcher total weight invalid",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "watcher PQ security bits below floor",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "severity": self.severity.as_str(),
            "watcher_set_root": self.watcher_set_root,
            "reorg_evidence_root": self.reorg_evidence_root,
            "alternative_header_root": self.alternative_header_root,
            "affected_private_fence_root": self.affected_private_fence_root,
            "liquidity_snapshot_root": self.liquidity_snapshot_root,
            "rescue_policy_root": self.rescue_policy_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "watcher_count": self.watcher_count,
            "watcher_weight": self.watcher_weight,
            "total_watcher_weight": self.total_watcher_weight,
            "pq_security_bits": self.pq_security_bits,
            "attested_l2_height": self.attested_l2_height,
            "attestation_nonce": self.attestation_nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatcherQuorumAttestation {
    pub attestation_id: String,
    pub sequence: u64,
    pub checkpoint_id: String,
    pub status: WatcherAttestationStatus,
    pub severity: ReorgSeverity,
    pub watcher_set_root: String,
    pub reorg_evidence_root: String,
    pub alternative_header_root: String,
    pub affected_private_fence_root: String,
    pub liquidity_snapshot_root: String,
    pub rescue_policy_root: String,
    pub aggregate_pq_signature_root: String,
    pub watcher_count: u64,
    pub watcher_weight: u64,
    pub total_watcher_weight: u64,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
    pub attested_l2_height: u64,
}

impl PqWatcherQuorumAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "checkpoint_id": self.checkpoint_id,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "watcher_set_root": self.watcher_set_root,
            "reorg_evidence_root": self.reorg_evidence_root,
            "alternative_header_root": self.alternative_header_root,
            "affected_private_fence_root": self.affected_private_fence_root,
            "liquidity_snapshot_root": self.liquidity_snapshot_root,
            "rescue_policy_root": self.rescue_policy_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "watcher_count": self.watcher_count,
            "watcher_weight": self.watcher_weight,
            "total_watcher_weight": self.total_watcher_weight,
            "quorum_bps": self.quorum_bps,
            "pq_security_bits": self.pq_security_bits,
            "attested_l2_height": self.attested_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_hash(
            "MONERO-L2-PQ-REORG-RESCUE-WATCHER-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenEmergencyLiquidityRescueWindowRequest {
    pub checkpoint_id: String,
    pub attestation_id: String,
    pub operator_id: String,
    pub rescue_liquidity_root: String,
    pub affected_reserve_root: String,
    pub protected_exit_queue_root: String,
    pub sponsor_budget_root: String,
    pub low_fee_policy_root: String,
    pub window_nonce: String,
    pub opened_l2_height: u64,
}

impl OpenEmergencyLiquidityRescueWindowRequest {
    pub fn validate(&self) -> MoneroL2PqReorgRescueRuntimeResult<()> {
        required("checkpoint_id", &self.checkpoint_id)?;
        required("attestation_id", &self.attestation_id)?;
        required("operator_id", &self.operator_id)?;
        required("rescue_liquidity_root", &self.rescue_liquidity_root)?;
        required("affected_reserve_root", &self.affected_reserve_root)?;
        required("protected_exit_queue_root", &self.protected_exit_queue_root)?;
        required("sponsor_budget_root", &self.sponsor_budget_root)?;
        required("low_fee_policy_root", &self.low_fee_policy_root)?;
        required("window_nonce", &self.window_nonce)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "attestation_id": self.attestation_id,
            "operator_id": self.operator_id,
            "rescue_liquidity_root": self.rescue_liquidity_root,
            "affected_reserve_root": self.affected_reserve_root,
            "protected_exit_queue_root": self.protected_exit_queue_root,
            "sponsor_budget_root": self.sponsor_budget_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "window_nonce": self.window_nonce,
            "opened_l2_height": self.opened_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyLiquidityRescueWindow {
    pub rescue_window_id: String,
    pub sequence: u64,
    pub status: RescueWindowStatus,
    pub checkpoint_id: String,
    pub attestation_id: String,
    pub operator_id: String,
    pub opened_l2_height: u64,
    pub closes_l2_height: u64,
    pub settlement_deadline_l2_height: u64,
    pub rescue_liquidity_root: String,
    pub affected_reserve_root: String,
    pub protected_exit_queue_root: String,
    pub sponsor_budget_root: String,
    pub low_fee_policy_root: String,
    pub low_fee_bps: u64,
    pub rescued_amount: u128,
    pub batch_ids: Vec<String>,
}

impl EmergencyLiquidityRescueWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "rescue_window_id": self.rescue_window_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "checkpoint_id": self.checkpoint_id,
            "attestation_id": self.attestation_id,
            "operator_id": self.operator_id,
            "opened_l2_height": self.opened_l2_height,
            "closes_l2_height": self.closes_l2_height,
            "settlement_deadline_l2_height": self.settlement_deadline_l2_height,
            "rescue_liquidity_root": self.rescue_liquidity_root,
            "affected_reserve_root": self.affected_reserve_root,
            "protected_exit_queue_root": self.protected_exit_queue_root,
            "sponsor_budget_root": self.sponsor_budget_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "low_fee_bps": self.low_fee_bps,
            "rescued_amount": self.rescued_amount,
            "batch_ids": self.batch_ids,
        })
    }

    pub fn root(&self) -> String {
        record_hash(
            "MONERO-L2-PQ-REORG-RESCUE-LIQUIDITY-WINDOW",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleLowFeeRescueBatchRequest {
    pub rescue_window_id: String,
    pub coordinator_id: String,
    pub replay_fence_ids: Vec<String>,
    pub settlement_root: String,
    pub recursive_proof_root: String,
    pub monero_release_tx_root: String,
    pub rescued_output_root: String,
    pub liquidity_delta_root: String,
    pub aggregate_pq_signature_root: String,
    pub batch_replay_fence_root: String,
    pub settled_l2_height: u64,
    pub batch_nonce: String,
}

impl SettleLowFeeRescueBatchRequest {
    pub fn validate(&self) -> MoneroL2PqReorgRescueRuntimeResult<()> {
        required("rescue_window_id", &self.rescue_window_id)?;
        required("coordinator_id", &self.coordinator_id)?;
        required("settlement_root", &self.settlement_root)?;
        required("recursive_proof_root", &self.recursive_proof_root)?;
        required("monero_release_tx_root", &self.monero_release_tx_root)?;
        required("rescued_output_root", &self.rescued_output_root)?;
        required("liquidity_delta_root", &self.liquidity_delta_root)?;
        required(
            "aggregate_pq_signature_root",
            &self.aggregate_pq_signature_root,
        )?;
        required("batch_replay_fence_root", &self.batch_replay_fence_root)?;
        required("batch_nonce", &self.batch_nonce)?;
        require(
            !self.replay_fence_ids.is_empty(),
            "rescue batch requires replay fences",
        )?;
        let unique = self.replay_fence_ids.iter().collect::<BTreeSet<_>>();
        require(
            unique.len() == self.replay_fence_ids.len(),
            "rescue batch replay fences must be unique",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rescue_window_id": self.rescue_window_id,
            "coordinator_id": self.coordinator_id,
            "replay_fence_ids": self.replay_fence_ids,
            "settlement_root": self.settlement_root,
            "recursive_proof_root": self.recursive_proof_root,
            "monero_release_tx_root": self.monero_release_tx_root,
            "rescued_output_root": self.rescued_output_root,
            "liquidity_delta_root": self.liquidity_delta_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "batch_replay_fence_root": self.batch_replay_fence_root,
            "settled_l2_height": self.settled_l2_height,
            "batch_nonce": self.batch_nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRescueBatch {
    pub rescue_batch_id: String,
    pub sequence: u64,
    pub status: RescueBatchStatus,
    pub rescue_window_id: String,
    pub checkpoint_id: String,
    pub attestation_id: String,
    pub coordinator_id: String,
    pub replay_fence_ids: Vec<String>,
    pub settlement_root: String,
    pub recursive_proof_root: String,
    pub monero_release_tx_root: String,
    pub rescued_output_root: String,
    pub liquidity_delta_root: String,
    pub aggregate_pq_signature_root: String,
    pub batch_replay_fence_root: String,
    pub replay_fence_root: String,
    pub total_amount: u128,
    pub low_fee_amount: u128,
    pub settled_l2_height: u64,
    pub receipt_id: String,
}

impl LowFeeRescueBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "rescue_batch_id": self.rescue_batch_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "rescue_window_id": self.rescue_window_id,
            "checkpoint_id": self.checkpoint_id,
            "attestation_id": self.attestation_id,
            "coordinator_id": self.coordinator_id,
            "replay_fence_ids": self.replay_fence_ids,
            "settlement_root": self.settlement_root,
            "recursive_proof_root": self.recursive_proof_root,
            "monero_release_tx_root": self.monero_release_tx_root,
            "rescued_output_root": self.rescued_output_root,
            "liquidity_delta_root": self.liquidity_delta_root,
            "aggregate_pq_signature_root": self.aggregate_pq_signature_root,
            "batch_replay_fence_root": self.batch_replay_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "total_amount": self.total_amount,
            "low_fee_amount": self.low_fee_amount,
            "settled_l2_height": self.settled_l2_height,
            "receipt_id": self.receipt_id,
        })
    }

    pub fn root(&self) -> String {
        record_hash(
            "MONERO-L2-PQ-REORG-RESCUE-LOW-FEE-BATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RescueReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub kind: RescueReceiptKind,
    pub actor_id: String,
    pub checkpoint_id: Option<String>,
    pub replay_fence_id: Option<String>,
    pub attestation_id: Option<String>,
    pub rescue_window_id: Option<String>,
    pub rescue_batch_id: Option<String>,
    pub issued_l2_height: u64,
    pub event_root: String,
    pub receipt_root: String,
}

impl RescueReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "actor_id": self.actor_id,
            "checkpoint_id": self.checkpoint_id,
            "replay_fence_id": self.replay_fence_id,
            "attestation_id": self.attestation_id,
            "rescue_window_id": self.rescue_window_id,
            "rescue_batch_id": self.rescue_batch_id,
            "issued_l2_height": self.issued_l2_height,
            "event_root": self.event_root,
            "receipt_root": self.receipt_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("MONERO-L2-PQ-REORG-RESCUE-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub checkpoint_root: String,
    pub replay_fence_root: String,
    pub deposit_replay_fence_root: String,
    pub withdrawal_replay_fence_root: String,
    pub watcher_attestation_root: String,
    pub rescue_window_root: String,
    pub low_fee_batch_root: String,
    pub receipt_root: String,
    pub consumed_replay_fence_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "checkpoint_root": self.checkpoint_root,
            "replay_fence_root": self.replay_fence_root,
            "deposit_replay_fence_root": self.deposit_replay_fence_root,
            "withdrawal_replay_fence_root": self.withdrawal_replay_fence_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "rescue_window_root": self.rescue_window_root,
            "low_fee_batch_root": self.low_fee_batch_root,
            "receipt_root": self.receipt_root,
            "consumed_replay_fence_root": self.consumed_replay_fence_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn root(&self) -> String {
        record_hash("MONERO-L2-PQ-REORG-RESCUE-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_l2_height: u64,
    pub checkpoints: BTreeMap<String, WatchedMoneroCheckpoint>,
    pub checkpoint_by_height: BTreeMap<u64, BTreeSet<String>>,
    pub replay_fences: BTreeMap<String, PrivateReplayFenceRecord>,
    pub consumed_replay_fences: BTreeSet<String>,
    pub attestations: BTreeMap<String, PqWatcherQuorumAttestation>,
    pub attestations_by_checkpoint: BTreeMap<String, BTreeSet<String>>,
    pub rescue_windows: BTreeMap<String, EmergencyLiquidityRescueWindow>,
    pub rescue_windows_by_checkpoint: BTreeMap<String, BTreeSet<String>>,
    pub batches: BTreeMap<String, LowFeeRescueBatch>,
    pub receipts: BTreeMap<String, RescueReceipt>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            current_l2_height: MONERO_L2_PQ_REORG_RESCUE_RUNTIME_DEVNET_HEIGHT,
            checkpoints: BTreeMap::new(),
            checkpoint_by_height: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            consumed_replay_fences: BTreeSet::new(),
            attestations: BTreeMap::new(),
            attestations_by_checkpoint: BTreeMap::new(),
            rescue_windows: BTreeMap::new(),
            rescue_windows_by_checkpoint: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }

    pub fn with_config(config: Config) -> MoneroL2PqReorgRescueRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::devnet()
        })
    }

    pub fn submit_watched_checkpoint(
        &mut self,
        request: SubmitWatchedCheckpointRequest,
    ) -> MoneroL2PqReorgRescueRuntimeResult<WatchedMoneroCheckpoint> {
        self.config.validate()?;
        request.validate()?;
        require(
            self.checkpoints.len() < MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_CHECKPOINTS,
            "watched checkpoint capacity reached",
        )?;
        self.counters.checkpoint_counter = self.counters.checkpoint_counter.saturating_add(1);
        self.current_l2_height = self.current_l2_height.max(request.observed_l2_height);
        let checkpoint_id =
            watched_monero_checkpoint_id(&request, self.counters.checkpoint_counter);
        require(
            !self.checkpoints.contains_key(&checkpoint_id),
            "watched checkpoint already exists",
        )?;
        let checkpoint = WatchedMoneroCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            sequence: self.counters.checkpoint_counter,
            status: CheckpointStatus::Watched,
            watcher_id: request.watcher_id.clone(),
            monero_height: request.monero_height,
            l2_height: request.l2_height,
            observed_l2_height: request.observed_l2_height,
            block_hash_root: request.block_hash_root,
            previous_block_hash_root: request.previous_block_hash_root,
            header_chain_root: request.header_chain_root,
            txset_root: request.txset_root,
            output_root: request.output_root,
            key_image_root: request.key_image_root,
            anchor_state_root: request.anchor_state_root,
            prior_checkpoint_root: request.prior_checkpoint_root,
            watcher_attestation_root: empty_root(
                "MONERO-L2-PQ-REORG-RESCUE-CHECKPOINT-ATTESTATIONS",
            ),
            rescue_window_id: None,
        };
        self.checkpoint_by_height
            .entry(checkpoint.monero_height)
            .or_default()
            .insert(checkpoint_id.clone());
        self.checkpoints
            .insert(checkpoint_id.clone(), checkpoint.clone());
        self.issue_receipt(
            RescueReceiptKind::CheckpointWatched,
            &request.watcher_id,
            Some(&checkpoint_id),
            None,
            None,
            None,
            None,
            request.observed_l2_height,
            &checkpoint.root(),
        )?;
        Ok(checkpoint)
    }

    pub fn register_private_replay_fence(
        &mut self,
        request: RegisterPrivateReplayFenceRequest,
    ) -> MoneroL2PqReorgRescueRuntimeResult<PrivateReplayFenceRecord> {
        self.config.validate()?;
        request.validate()?;
        require(
            self.replay_fences.len() < MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_REPLAY_FENCES,
            "private replay fence capacity reached",
        )?;
        require(
            self.checkpoints.contains_key(&request.checkpoint_id),
            "checkpoint not found for private replay fence",
        )?;
        require(
            !self
                .consumed_replay_fences
                .contains(&request.replay_fence_root),
            "private replay fence already consumed",
        )?;
        self.counters.replay_fence_counter = self.counters.replay_fence_counter.saturating_add(1);
        self.current_l2_height = self.current_l2_height.max(request.registered_l2_height);
        let replay_fence_id = private_replay_fence_id(&request, self.counters.replay_fence_counter);
        require(
            !self.replay_fences.contains_key(&replay_fence_id),
            "private replay fence already exists",
        )?;
        let record = PrivateReplayFenceRecord {
            replay_fence_id: replay_fence_id.clone(),
            sequence: self.counters.replay_fence_counter,
            checkpoint_id: request.checkpoint_id.clone(),
            fence_kind: request.fence_kind,
            status: FenceStatus::Registered,
            private_note_root: request.private_note_root,
            nullifier_root: request.nullifier_root,
            replay_fence_root: request.replay_fence_root,
            amount_commitment_root: request.amount_commitment_root,
            owner_commitment_root: request.owner_commitment_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            amount: request.amount,
            registered_l2_height: request.registered_l2_height,
            expires_l2_height: request.expires_l2_height,
            rescue_window_id: None,
            rescue_batch_id: None,
        };
        self.replay_fences
            .insert(replay_fence_id.clone(), record.clone());
        self.issue_receipt(
            RescueReceiptKind::ReplayFenceRegistered,
            "private-replay-fence",
            Some(&request.checkpoint_id),
            Some(&replay_fence_id),
            None,
            None,
            None,
            request.registered_l2_height,
            &record.root(),
        )?;
        Ok(record)
    }

    pub fn submit_pq_watcher_attestation(
        &mut self,
        request: SubmitPqWatcherAttestationRequest,
    ) -> MoneroL2PqReorgRescueRuntimeResult<PqWatcherQuorumAttestation> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.attestations.len() < MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_ATTESTATIONS,
            "PQ watcher attestation capacity reached",
        )?;
        require(
            self.checkpoints.contains_key(&request.checkpoint_id),
            "checkpoint not found for PQ watcher attestation",
        )?;
        let quorum_bps = bps(request.watcher_weight, request.total_watcher_weight);
        let status = if quorum_bps >= self.config.watcher_quorum_bps {
            WatcherAttestationStatus::Accepted
        } else {
            WatcherAttestationStatus::WeakQuorum
        };
        require(
            status == WatcherAttestationStatus::Accepted,
            "PQ watcher attestation quorum below threshold",
        )?;
        self.counters.watcher_attestation_counter =
            self.counters.watcher_attestation_counter.saturating_add(1);
        self.current_l2_height = self.current_l2_height.max(request.attested_l2_height);
        let attestation_id =
            pq_watcher_quorum_attestation_id(&request, self.counters.watcher_attestation_counter);
        require(
            !self.attestations.contains_key(&attestation_id),
            "PQ watcher attestation already exists",
        )?;
        let attestation = PqWatcherQuorumAttestation {
            attestation_id: attestation_id.clone(),
            sequence: self.counters.watcher_attestation_counter,
            checkpoint_id: request.checkpoint_id.clone(),
            status,
            severity: request.severity,
            watcher_set_root: request.watcher_set_root,
            reorg_evidence_root: request.reorg_evidence_root,
            alternative_header_root: request.alternative_header_root,
            affected_private_fence_root: request.affected_private_fence_root,
            liquidity_snapshot_root: request.liquidity_snapshot_root,
            rescue_policy_root: request.rescue_policy_root,
            aggregate_pq_signature_root: request.aggregate_pq_signature_root,
            watcher_count: request.watcher_count,
            watcher_weight: request.watcher_weight,
            total_watcher_weight: request.total_watcher_weight,
            quorum_bps,
            pq_security_bits: request.pq_security_bits,
            attested_l2_height: request.attested_l2_height,
        };
        self.attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.attestations_by_checkpoint
            .entry(request.checkpoint_id.clone())
            .or_default()
            .insert(attestation_id.clone());
        self.refresh_checkpoint_attestation_root(&request.checkpoint_id)?;
        if let Some(checkpoint) = self.checkpoints.get_mut(&request.checkpoint_id) {
            checkpoint.status = if request.severity.opens_rescue() {
                self.counters.reorgs_detected = self.counters.reorgs_detected.saturating_add(1);
                CheckpointStatus::ReorgDetected
            } else {
                CheckpointStatus::QuorumAttested
            };
        }
        self.issue_receipt(
            RescueReceiptKind::WatcherQuorumAccepted,
            "pq-watcher-quorum",
            Some(&request.checkpoint_id),
            None,
            Some(&attestation_id),
            None,
            None,
            request.attested_l2_height,
            &attestation.root(),
        )?;
        Ok(attestation)
    }

    pub fn open_emergency_liquidity_rescue_window(
        &mut self,
        request: OpenEmergencyLiquidityRescueWindowRequest,
    ) -> MoneroL2PqReorgRescueRuntimeResult<EmergencyLiquidityRescueWindow> {
        self.config.validate()?;
        request.validate()?;
        require(
            self.rescue_windows.len() < MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_WINDOWS,
            "emergency rescue window capacity reached",
        )?;
        let attestation = self
            .attestations
            .get(&request.attestation_id)
            .ok_or_else(|| "PQ watcher attestation not found for rescue window".to_string())?;
        require(
            attestation.checkpoint_id == request.checkpoint_id,
            "rescue window attestation checkpoint mismatch",
        )?;
        require(
            attestation.status == WatcherAttestationStatus::Accepted,
            "rescue window requires accepted PQ watcher quorum",
        )?;
        require(
            attestation.severity.opens_rescue(),
            "rescue window requires rescue severity",
        )?;
        self.counters.rescue_window_counter = self.counters.rescue_window_counter.saturating_add(1);
        self.current_l2_height = self.current_l2_height.max(request.opened_l2_height);
        let rescue_window_id =
            emergency_liquidity_rescue_window_id(&request, self.counters.rescue_window_counter);
        require(
            !self.rescue_windows.contains_key(&rescue_window_id),
            "emergency rescue window already exists",
        )?;
        let window = EmergencyLiquidityRescueWindow {
            rescue_window_id: rescue_window_id.clone(),
            sequence: self.counters.rescue_window_counter,
            status: RescueWindowStatus::Open,
            checkpoint_id: request.checkpoint_id.clone(),
            attestation_id: request.attestation_id.clone(),
            operator_id: request.operator_id.clone(),
            opened_l2_height: request.opened_l2_height,
            closes_l2_height: request
                .opened_l2_height
                .saturating_add(self.config.rescue_window_blocks),
            settlement_deadline_l2_height: request
                .opened_l2_height
                .saturating_add(self.config.settlement_ttl_blocks),
            rescue_liquidity_root: request.rescue_liquidity_root,
            affected_reserve_root: request.affected_reserve_root,
            protected_exit_queue_root: request.protected_exit_queue_root,
            sponsor_budget_root: request.sponsor_budget_root,
            low_fee_policy_root: request.low_fee_policy_root,
            low_fee_bps: self.config.low_fee_bps,
            rescued_amount: 0,
            batch_ids: Vec::new(),
        };
        self.rescue_windows_by_checkpoint
            .entry(request.checkpoint_id.clone())
            .or_default()
            .insert(rescue_window_id.clone());
        self.rescue_windows
            .insert(rescue_window_id.clone(), window.clone());
        if let Some(checkpoint) = self.checkpoints.get_mut(&request.checkpoint_id) {
            checkpoint.status = CheckpointStatus::RescueOpen;
            checkpoint.rescue_window_id = Some(rescue_window_id.clone());
        }
        for replay_fence in self.replay_fences.values_mut() {
            if replay_fence.checkpoint_id == request.checkpoint_id
                && replay_fence.status.rescue_eligible()
            {
                replay_fence.status = FenceStatus::Quarantined;
                replay_fence.rescue_window_id = Some(rescue_window_id.clone());
            }
        }
        self.issue_receipt(
            RescueReceiptKind::WindowOpened,
            &request.operator_id,
            Some(&request.checkpoint_id),
            None,
            Some(&request.attestation_id),
            Some(&rescue_window_id),
            None,
            request.opened_l2_height,
            &window.root(),
        )?;
        Ok(window)
    }

    pub fn settle_low_fee_rescue_batch(
        &mut self,
        request: SettleLowFeeRescueBatchRequest,
    ) -> MoneroL2PqReorgRescueRuntimeResult<LowFeeRescueBatch> {
        self.config.validate()?;
        request.validate()?;
        require(
            self.batches.len() < MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_BATCHES,
            "low-fee rescue batch capacity reached",
        )?;
        require(
            request.replay_fence_ids.len() <= self.config.max_batch_size,
            "low-fee rescue batch exceeds max batch size",
        )?;
        let window = self
            .rescue_windows
            .get(&request.rescue_window_id)
            .ok_or_else(|| "emergency rescue window not found".to_string())?
            .clone();
        require(window.status.live(), "emergency rescue window is not live")?;
        require(
            request.settled_l2_height <= window.settlement_deadline_l2_height,
            "low-fee rescue batch settled after deadline",
        )?;
        let mut total_amount = 0_u128;
        for replay_fence_id in &request.replay_fence_ids {
            let replay_fence = self
                .replay_fences
                .get(replay_fence_id)
                .ok_or_else(|| format!("private replay fence not found: {replay_fence_id}"))?;
            require(
                replay_fence.checkpoint_id == window.checkpoint_id,
                "low-fee rescue batch mixes checkpoints",
            )?;
            require(
                replay_fence.rescue_window_id.as_deref() == Some(&request.rescue_window_id),
                "private replay fence is not assigned to rescue window",
            )?;
            require(
                replay_fence.status.rescue_eligible(),
                "private replay fence is not rescue eligible",
            )?;
            require(
                request.settled_l2_height < replay_fence.expires_l2_height,
                "private replay fence expired before rescue settlement",
            )?;
            require(
                !self
                    .consumed_replay_fences
                    .contains(&replay_fence.replay_fence_root),
                "private replay fence root already consumed",
            )?;
            total_amount = total_amount.saturating_add(replay_fence.amount);
        }
        self.counters.rescue_batch_counter = self.counters.rescue_batch_counter.saturating_add(1);
        self.current_l2_height = self.current_l2_height.max(request.settled_l2_height);
        let rescue_batch_id = low_fee_rescue_batch_id(&request, self.counters.rescue_batch_counter);
        require(
            !self.batches.contains_key(&rescue_batch_id),
            "low-fee rescue batch already exists",
        )?;
        let replay_fence_root = replay_fence_id_root(&request.replay_fence_ids);
        let low_fee_amount = fee_amount(total_amount, window.low_fee_bps);
        let receipt = self.issue_receipt(
            RescueReceiptKind::BatchSettled,
            &request.coordinator_id,
            Some(&window.checkpoint_id),
            None,
            Some(&window.attestation_id),
            Some(&request.rescue_window_id),
            Some(&rescue_batch_id),
            request.settled_l2_height,
            &request.settlement_root,
        )?;
        let batch = LowFeeRescueBatch {
            rescue_batch_id: rescue_batch_id.clone(),
            sequence: self.counters.rescue_batch_counter,
            status: RescueBatchStatus::Settled,
            rescue_window_id: request.rescue_window_id.clone(),
            checkpoint_id: window.checkpoint_id.clone(),
            attestation_id: window.attestation_id.clone(),
            coordinator_id: request.coordinator_id,
            replay_fence_ids: request.replay_fence_ids.clone(),
            settlement_root: request.settlement_root,
            recursive_proof_root: request.recursive_proof_root,
            monero_release_tx_root: request.monero_release_tx_root,
            rescued_output_root: request.rescued_output_root,
            liquidity_delta_root: request.liquidity_delta_root,
            aggregate_pq_signature_root: request.aggregate_pq_signature_root,
            batch_replay_fence_root: request.batch_replay_fence_root,
            replay_fence_root,
            total_amount,
            low_fee_amount,
            settled_l2_height: request.settled_l2_height,
            receipt_id: receipt.receipt_id,
        };
        for replay_fence_id in &request.replay_fence_ids {
            if let Some(replay_fence) = self.replay_fences.get_mut(replay_fence_id) {
                replay_fence.status = FenceStatus::Rescued;
                replay_fence.rescue_batch_id = Some(rescue_batch_id.clone());
                self.consumed_replay_fences
                    .insert(replay_fence.replay_fence_root.clone());
            }
        }
        if let Some(window) = self.rescue_windows.get_mut(&request.rescue_window_id) {
            window.status = RescueWindowStatus::Settling;
            window.rescued_amount = window.rescued_amount.saturating_add(total_amount);
            window.batch_ids.push(rescue_batch_id.clone());
        }
        if let Some(checkpoint) = self.checkpoints.get_mut(&batch.checkpoint_id) {
            checkpoint.status = CheckpointStatus::Batched;
        }
        self.batches.insert(rescue_batch_id, batch.clone());
        self.counters.low_fee_batches_settled =
            self.counters.low_fee_batches_settled.saturating_add(1);
        self.counters.rescued_private_items = self
            .counters
            .rescued_private_items
            .saturating_add(request.replay_fence_ids.len() as u64);
        self.counters.consumed_replay_fence_counter = self
            .counters
            .consumed_replay_fence_counter
            .saturating_add(request.replay_fence_ids.len() as u64);
        self.counters.total_rescued_amount = self
            .counters
            .total_rescued_amount
            .saturating_add(total_amount);
        self.counters.total_low_fee = self.counters.total_low_fee.saturating_add(low_fee_amount);
        Ok(batch)
    }

    pub fn roots(&self) -> Roots {
        let checkpoint_records = self
            .checkpoints
            .values()
            .map(WatchedMoneroCheckpoint::public_record)
            .collect::<Vec<_>>();
        let replay_fence_records = self
            .replay_fences
            .values()
            .map(PrivateReplayFenceRecord::public_record)
            .collect::<Vec<_>>();
        let deposit_replay_fence_records = self
            .replay_fences
            .values()
            .filter(|record| record.fence_kind == FenceKind::PrivateDeposit)
            .map(PrivateReplayFenceRecord::public_record)
            .collect::<Vec<_>>();
        let withdrawal_replay_fence_records = self
            .replay_fences
            .values()
            .filter(|record| record.fence_kind == FenceKind::PrivateWithdrawal)
            .map(PrivateReplayFenceRecord::public_record)
            .collect::<Vec<_>>();
        let watcher_attestation_records = self
            .attestations
            .values()
            .map(PqWatcherQuorumAttestation::public_record)
            .collect::<Vec<_>>();
        let rescue_window_records = self
            .rescue_windows
            .values()
            .map(EmergencyLiquidityRescueWindow::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(LowFeeRescueBatch::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(RescueReceipt::public_record)
            .collect::<Vec<_>>();
        let consumed_replay_fence_records = self
            .consumed_replay_fences
            .iter()
            .map(|root| json!({ "replay_fence_root": root }))
            .collect::<Vec<_>>();
        let public_record_root = record_hash(
            "MONERO-L2-PQ-REORG-RESCUE-PUBLIC-SUMMARY",
            &json!({
                "protocol_version": self.config.protocol_version,
                "schema_version": self.config.schema_version,
                "chain_id": CHAIN_ID,
                "current_l2_height": self.current_l2_height,
                "checkpoint_count": self.checkpoints.len(),
                "replay_fence_count": self.replay_fences.len(),
                "attestation_count": self.attestations.len(),
                "rescue_window_count": self.rescue_windows.len(),
                "batch_count": self.batches.len(),
                "receipt_count": self.receipts.len(),
            }),
        );
        Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            checkpoint_root: watched_checkpoint_root(&checkpoint_records),
            replay_fence_root: private_replay_fence_root(&replay_fence_records),
            deposit_replay_fence_root: merkle_root(
                "MONERO-L2-PQ-REORG-RESCUE-DEPOSIT-REPLAY-FENCES",
                &deposit_replay_fence_records,
            ),
            withdrawal_replay_fence_root: merkle_root(
                "MONERO-L2-PQ-REORG-RESCUE-WITHDRAWAL-REPLAY-FENCES",
                &withdrawal_replay_fence_records,
            ),
            watcher_attestation_root: pq_watcher_attestation_root(&watcher_attestation_records),
            rescue_window_root: emergency_liquidity_rescue_window_root(&rescue_window_records),
            low_fee_batch_root: low_fee_rescue_batch_root(&batch_records),
            receipt_root: rescue_receipt_root(&receipt_records),
            consumed_replay_fence_root: merkle_root(
                "MONERO-L2-PQ-REORG-RESCUE-CONSUMED-REPLAY-FENCES",
                &consumed_replay_fence_records,
            ),
            public_record_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "privacy_boundary": "roots_only_no_plaintext_monero_addresses_no_view_keys",
            "current_l2_height": self.current_l2_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "checkpoint_count": self.checkpoints.len(),
            "replay_fence_count": self.replay_fences.len(),
            "attestation_count": self.attestations.len(),
            "rescue_window_count": self.rescue_windows.len(),
            "batch_count": self.batches.len(),
            "receipt_count": self.receipts.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        record_hash(
            "MONERO-L2-PQ-REORG-RESCUE-STATE",
            &self.public_record_without_state_root(),
        )
    }

    fn refresh_checkpoint_attestation_root(
        &mut self,
        checkpoint_id: &str,
    ) -> MoneroL2PqReorgRescueRuntimeResult<()> {
        let records = self
            .attestations_by_checkpoint
            .get(checkpoint_id)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|attestation_id| self.attestations.get(attestation_id))
            .map(PqWatcherQuorumAttestation::public_record)
            .collect::<Vec<_>>();
        let root = merkle_root(
            "MONERO-L2-PQ-REORG-RESCUE-CHECKPOINT-ATTESTATIONS",
            &records,
        );
        let checkpoint = self
            .checkpoints
            .get_mut(checkpoint_id)
            .ok_or_else(|| "checkpoint not found while refreshing attestations".to_string())?;
        checkpoint.watcher_attestation_root = root;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_receipt(
        &mut self,
        kind: RescueReceiptKind,
        actor_id: &str,
        checkpoint_id: Option<&str>,
        replay_fence_id: Option<&str>,
        attestation_id: Option<&str>,
        rescue_window_id: Option<&str>,
        rescue_batch_id: Option<&str>,
        issued_l2_height: u64,
        event_root: &str,
    ) -> MoneroL2PqReorgRescueRuntimeResult<RescueReceipt> {
        require(
            self.receipts.len() < MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_RECEIPTS,
            "rescue receipt capacity reached",
        )?;
        required("actor_id", actor_id)?;
        required("event_root", event_root)?;
        self.counters.receipt_counter = self.counters.receipt_counter.saturating_add(1);
        let sequence = self.counters.receipt_counter;
        let receipt_root = rescue_receipt_commitment(
            sequence,
            kind,
            actor_id,
            checkpoint_id,
            replay_fence_id,
            attestation_id,
            rescue_window_id,
            rescue_batch_id,
            issued_l2_height,
            event_root,
        );
        let receipt_id = rescue_receipt_id(sequence, &receipt_root);
        let receipt = RescueReceipt {
            receipt_id: receipt_id.clone(),
            sequence,
            kind,
            actor_id: actor_id.to_string(),
            checkpoint_id: checkpoint_id.map(str::to_string),
            replay_fence_id: replay_fence_id.map(str::to_string),
            attestation_id: attestation_id.map(str::to_string),
            rescue_window_id: rescue_window_id.map(str::to_string),
            rescue_batch_id: rescue_batch_id.map(str::to_string),
            issued_l2_height,
            event_root: event_root.to_string(),
            receipt_root,
        };
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }
}

pub fn monero_l2_pq_reorg_rescue_runtime_devnet() -> State {
    State::devnet()
}

pub fn monero_l2_pq_reorg_rescue_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_pq_reorg_rescue_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn watched_checkpoint_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PQ-REORG-RESCUE-WATCHED-CHECKPOINTS", records)
}

pub fn private_replay_fence_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PQ-REORG-RESCUE-PRIVATE-REPLAY-FENCES", records)
}

pub fn pq_watcher_attestation_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PQ-REORG-RESCUE-PQ-WATCHER-ATTESTATIONS", records)
}

pub fn emergency_liquidity_rescue_window_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-REORG-RESCUE-EMERGENCY-LIQUIDITY-WINDOWS",
        records,
    )
}

pub fn low_fee_rescue_batch_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PQ-REORG-RESCUE-LOW-FEE-BATCHES", records)
}

pub fn rescue_receipt_root(records: &[Value]) -> String {
    merkle_root("MONERO-L2-PQ-REORG-RESCUE-RECEIPTS", records)
}

pub fn watched_monero_checkpoint_id(
    request: &SubmitWatchedCheckpointRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-REORG-RESCUE-WATCHED-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.watcher_id),
            HashPart::Int(request.monero_height as i128),
            HashPart::Int(request.l2_height as i128),
            HashPart::Str(&request.block_hash_root),
            HashPart::Str(&request.header_chain_root),
            HashPart::Str(&request.checkpoint_nonce),
        ],
        32,
    )
}

pub fn private_replay_fence_id(
    request: &RegisterPrivateReplayFenceRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-REORG-RESCUE-PRIVATE-REPLAY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(request.fence_kind.as_str()),
            HashPart::Str(&request.private_note_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.replay_fence_root),
        ],
        32,
    )
}

pub fn pq_watcher_quorum_attestation_id(
    request: &SubmitPqWatcherAttestationRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-REORG-RESCUE-WATCHER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(request.severity.as_str()),
            HashPart::Str(&request.watcher_set_root),
            HashPart::Str(&request.reorg_evidence_root),
            HashPart::Str(&request.aggregate_pq_signature_root),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn emergency_liquidity_rescue_window_id(
    request: &OpenEmergencyLiquidityRescueWindowRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-REORG-RESCUE-LIQUIDITY-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.checkpoint_id),
            HashPart::Str(&request.attestation_id),
            HashPart::Str(&request.operator_id),
            HashPart::Str(&request.rescue_liquidity_root),
            HashPart::Str(&request.window_nonce),
        ],
        32,
    )
}

pub fn low_fee_rescue_batch_id(request: &SettleLowFeeRescueBatchRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-REORG-RESCUE-LOW-FEE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.rescue_window_id),
            HashPart::Str(&request.coordinator_id),
            HashPart::Str(&replay_fence_id_root(&request.replay_fence_ids)),
            HashPart::Str(&request.settlement_root),
            HashPart::Str(&request.batch_replay_fence_root),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn rescue_receipt_id(sequence: u64, receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-REORG-RESCUE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn rescue_receipt_commitment(
    sequence: u64,
    kind: RescueReceiptKind,
    actor_id: &str,
    checkpoint_id: Option<&str>,
    replay_fence_id: Option<&str>,
    attestation_id: Option<&str>,
    rescue_window_id: Option<&str>,
    rescue_batch_id: Option<&str>,
    issued_l2_height: u64,
    event_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-REORG-RESCUE-RECEIPT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(actor_id),
            HashPart::Str(checkpoint_id.unwrap_or("")),
            HashPart::Str(replay_fence_id.unwrap_or("")),
            HashPart::Str(attestation_id.unwrap_or("")),
            HashPart::Str(rescue_window_id.unwrap_or("")),
            HashPart::Str(rescue_batch_id.unwrap_or("")),
            HashPart::Int(issued_l2_height as i128),
            HashPart::Str(event_root),
        ],
        32,
    )
}

fn replay_fence_id_root(ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-REORG-RESCUE-REPLAY-FENCE-IDS", &records)
}

fn record_hash(domain: &str, record: &Value) -> String {
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

fn fee_amount(amount: u128, fee_bps: u64) -> u128 {
    amount.saturating_mul(fee_bps as u128) / MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_BPS as u128
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(MONERO_L2_PQ_REORG_RESCUE_RUNTIME_MAX_BPS) / denominator
}

fn required(field: &str, value: &str) -> MoneroL2PqReorgRescueRuntimeResult<()> {
    require(!value.trim().is_empty(), &format!("{field} is required"))
}

fn require(condition: bool, message: &str) -> MoneroL2PqReorgRescueRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(fields) = record {
        fields.insert(key.to_string(), value);
    }
}
