use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type CheckpointAnchorResult<T> = Result<T, String>;

pub const CHECKPOINT_ANCHOR_PROTOCOL_VERSION: &str = "nebula-checkpoint-anchor-v1";
pub const CHECKPOINT_ANCHOR_DEFAULT_EPOCH_BLOCKS: u64 = 32;
pub const CHECKPOINT_ANCHOR_DEFAULT_FAST_FINALITY_BLOCKS: u64 = 2;
pub const CHECKPOINT_ANCHOR_DEFAULT_MONERO_CONFIRMATIONS: u64 = 20;
pub const CHECKPOINT_ANCHOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const CHECKPOINT_ANCHOR_DEFAULT_MAX_BUNDLE_BLOCKS: usize = 128;
pub const CHECKPOINT_ANCHOR_DEFAULT_MAX_PENDING_ANCHORS: usize = 256;
pub const CHECKPOINT_ANCHOR_DEFAULT_MIN_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const CHECKPOINT_ANCHOR_DEFAULT_LOW_FEE_BUDGET_UNITS: u64 = 100_000;
pub const CHECKPOINT_ANCHOR_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointAnchorLane {
    Fast,
    Economy,
    ProofDense,
    Emergency,
}

impl CheckpointAnchorLane {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Economy => "economy",
            Self::ProofDense => "proof_dense",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_fee_units(&self) -> u64 {
        match self {
            Self::Fast => 8,
            Self::Economy => 2,
            Self::ProofDense => 6,
            Self::Emergency => 12,
        }
    }

    pub fn default_confirmation_target(&self) -> u64 {
        match self {
            Self::Fast => 10,
            Self::Economy => CHECKPOINT_ANCHOR_DEFAULT_MONERO_CONFIRMATIONS,
            Self::ProofDense => 24,
            Self::Emergency => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointBundleStatus {
    Open,
    Sealed,
    Anchoring,
    Anchored,
    Challenged,
    Finalized,
    Rejected,
}

impl CheckpointBundleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Anchoring => "anchoring",
            Self::Anchored => "anchored",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalized | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorManifestStatus {
    Draft,
    Ready,
    Submitted,
    Observed,
    Confirmed,
    Reorged,
    Expired,
}

impl AnchorManifestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Ready => "ready",
            Self::Submitted => "submitted",
            Self::Observed => "observed",
            Self::Confirmed => "confirmed",
            Self::Reorged => "reorged",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Submitted | Self::Observed | Self::Confirmed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorAttestationRole {
    Sequencer,
    Prover,
    Watchtower,
    BridgeGuardian,
    MoneroObserver,
}

impl AnchorAttestationRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Prover => "prover",
            Self::Watchtower => "watchtower",
            Self::BridgeGuardian => "bridge_guardian",
            Self::MoneroObserver => "monero_observer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorChallengeKind {
    InvalidStateRoot,
    InvalidProofRoot,
    MoneroReorg,
    MissingData,
    EquivocatedAnchor,
    FeeAbuse,
}

impl AnchorChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidStateRoot => "invalid_state_root",
            Self::InvalidProofRoot => "invalid_proof_root",
            Self::MoneroReorg => "monero_reorg",
            Self::MissingData => "missing_data",
            Self::EquivocatedAnchor => "equivocated_anchor",
            Self::FeeAbuse => "fee_abuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Escalated,
    Slashed,
    Expired,
}

impl AnchorChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Escalated => "escalated",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open | Self::Escalated)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointAnchorConfig {
    pub epoch_blocks: u64,
    pub fast_finality_blocks: u64,
    pub monero_confirmation_target: u64,
    pub challenge_window_blocks: u64,
    pub max_bundle_blocks: usize,
    pub max_pending_anchors: usize,
    pub min_quorum_weight_bps: u64,
    pub low_fee_budget_units: u64,
    pub anchor_metadata_budget_bytes: u64,
    pub require_proof_manifest: bool,
    pub require_monero_observer_quorum: bool,
}

impl Default for CheckpointAnchorConfig {
    fn default() -> Self {
        Self {
            epoch_blocks: CHECKPOINT_ANCHOR_DEFAULT_EPOCH_BLOCKS,
            fast_finality_blocks: CHECKPOINT_ANCHOR_DEFAULT_FAST_FINALITY_BLOCKS,
            monero_confirmation_target: CHECKPOINT_ANCHOR_DEFAULT_MONERO_CONFIRMATIONS,
            challenge_window_blocks: CHECKPOINT_ANCHOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_bundle_blocks: CHECKPOINT_ANCHOR_DEFAULT_MAX_BUNDLE_BLOCKS,
            max_pending_anchors: CHECKPOINT_ANCHOR_DEFAULT_MAX_PENDING_ANCHORS,
            min_quorum_weight_bps: CHECKPOINT_ANCHOR_DEFAULT_MIN_QUORUM_WEIGHT_BPS,
            low_fee_budget_units: CHECKPOINT_ANCHOR_DEFAULT_LOW_FEE_BUDGET_UNITS,
            anchor_metadata_budget_bytes: 512,
            require_proof_manifest: true,
            require_monero_observer_quorum: true,
        }
    }
}

impl CheckpointAnchorConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: 16,
            fast_finality_blocks: 1,
            monero_confirmation_target: 6,
            challenge_window_blocks: 32,
            max_bundle_blocks: 64,
            max_pending_anchors: 128,
            min_quorum_weight_bps: 6_000,
            low_fee_budget_units: 250_000,
            anchor_metadata_budget_bytes: 768,
            require_proof_manifest: true,
            require_monero_observer_quorum: true,
        }
    }

    pub fn validate(&self) -> CheckpointAnchorResult<()> {
        if self.epoch_blocks == 0 {
            return Err("checkpoint anchor epoch_blocks must be positive".to_string());
        }
        if self.fast_finality_blocks == 0 {
            return Err("checkpoint anchor fast_finality_blocks must be positive".to_string());
        }
        if self.monero_confirmation_target == 0 {
            return Err("checkpoint anchor monero confirmations must be positive".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("checkpoint anchor challenge window must be positive".to_string());
        }
        if self.max_bundle_blocks == 0 || self.max_pending_anchors == 0 {
            return Err("checkpoint anchor capacity limits must be positive".to_string());
        }
        if self.min_quorum_weight_bps > CHECKPOINT_ANCHOR_MAX_BPS {
            return Err("checkpoint anchor quorum exceeds 10000 bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "checkpoint_anchor_config",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "epoch_blocks": self.epoch_blocks,
            "fast_finality_blocks": self.fast_finality_blocks,
            "monero_confirmation_target": self.monero_confirmation_target,
            "challenge_window_blocks": self.challenge_window_blocks,
            "max_bundle_blocks": self.max_bundle_blocks,
            "max_pending_anchors": self.max_pending_anchors,
            "min_quorum_weight_bps": self.min_quorum_weight_bps,
            "low_fee_budget_units": self.low_fee_budget_units,
            "anchor_metadata_budget_bytes": self.anchor_metadata_budget_bytes,
            "require_proof_manifest": self.require_proof_manifest,
            "require_monero_observer_quorum": self.require_monero_observer_quorum,
        })
    }

    pub fn config_root(&self) -> String {
        checkpoint_anchor_payload_root("CHECKPOINT-ANCHOR-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBlockCommitment {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub tx_root: String,
    pub proof_root: String,
    pub da_root: String,
    pub private_order_root: String,
    pub low_fee_root: String,
}

impl CheckpointBlockCommitment {
    pub fn devnet(height: u64, label: &str) -> Self {
        let block_hash = checkpoint_anchor_string_root(
            "CHECKPOINT-ANCHOR-DEVNET-BLOCK",
            &format!("{label}:{height}"),
        );
        Self {
            height,
            block_hash: block_hash.clone(),
            state_root: checkpoint_anchor_string_root(
                "CHECKPOINT-ANCHOR-DEVNET-STATE",
                &block_hash,
            ),
            tx_root: checkpoint_anchor_string_root("CHECKPOINT-ANCHOR-DEVNET-TX", &block_hash),
            proof_root: checkpoint_anchor_string_root(
                "CHECKPOINT-ANCHOR-DEVNET-PROOF",
                &block_hash,
            ),
            da_root: checkpoint_anchor_string_root("CHECKPOINT-ANCHOR-DEVNET-DA", &block_hash),
            private_order_root: checkpoint_anchor_string_root(
                "CHECKPOINT-ANCHOR-DEVNET-PRIVATE-ORDER",
                &block_hash,
            ),
            low_fee_root: checkpoint_anchor_string_root(
                "CHECKPOINT-ANCHOR-DEVNET-LOW-FEE",
                &block_hash,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "checkpoint_block_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "height": self.height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "tx_root": self.tx_root,
            "proof_root": self.proof_root,
            "da_root": self.da_root,
            "private_order_root": self.private_order_root,
            "low_fee_root": self.low_fee_root,
        })
    }

    pub fn commitment_root(&self) -> String {
        checkpoint_anchor_payload_root("CHECKPOINT-BLOCK-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBundle {
    pub bundle_id: String,
    pub epoch: u64,
    pub first_height: u64,
    pub last_height: u64,
    pub lane: CheckpointAnchorLane,
    pub status: CheckpointBundleStatus,
    pub block_commitments: Vec<CheckpointBlockCommitment>,
    pub block_commitment_root: String,
    pub state_root: String,
    pub proof_root: String,
    pub da_root: String,
    pub private_state_root: String,
    pub low_fee_root: String,
    pub created_at_height: u64,
    pub sealed_at_height: Option<u64>,
    pub anchor_manifest_id: Option<String>,
}

impl CheckpointBundle {
    pub fn new(
        epoch: u64,
        lane: CheckpointAnchorLane,
        block_commitments: Vec<CheckpointBlockCommitment>,
        created_at_height: u64,
    ) -> CheckpointAnchorResult<Self> {
        if block_commitments.is_empty() {
            return Err("checkpoint bundle needs at least one block".to_string());
        }
        let first_height = block_commitments
            .iter()
            .map(|block| block.height)
            .min()
            .unwrap_or(created_at_height);
        let last_height = block_commitments
            .iter()
            .map(|block| block.height)
            .max()
            .unwrap_or(created_at_height);
        let records = block_commitments
            .iter()
            .map(CheckpointBlockCommitment::public_record)
            .collect::<Vec<_>>();
        let block_commitment_root = merkle_root("CHECKPOINT-ANCHOR-BLOCKS", &records);
        let state_root = merkle_root(
            "CHECKPOINT-ANCHOR-STATES",
            &block_commitments
                .iter()
                .map(|block| Value::String(block.state_root.clone()))
                .collect::<Vec<_>>(),
        );
        let proof_root = merkle_root(
            "CHECKPOINT-ANCHOR-PROOFS",
            &block_commitments
                .iter()
                .map(|block| Value::String(block.proof_root.clone()))
                .collect::<Vec<_>>(),
        );
        let da_root = merkle_root(
            "CHECKPOINT-ANCHOR-DA",
            &block_commitments
                .iter()
                .map(|block| Value::String(block.da_root.clone()))
                .collect::<Vec<_>>(),
        );
        let private_state_root = merkle_root(
            "CHECKPOINT-ANCHOR-PRIVATE-STATE",
            &block_commitments
                .iter()
                .map(|block| Value::String(block.private_order_root.clone()))
                .collect::<Vec<_>>(),
        );
        let low_fee_root = merkle_root(
            "CHECKPOINT-ANCHOR-LOW-FEE",
            &block_commitments
                .iter()
                .map(|block| Value::String(block.low_fee_root.clone()))
                .collect::<Vec<_>>(),
        );
        let bundle_id = checkpoint_anchor_bundle_id(
            epoch,
            first_height,
            last_height,
            lane,
            &block_commitment_root,
            &state_root,
        );
        Ok(Self {
            bundle_id,
            epoch,
            first_height,
            last_height,
            lane,
            status: CheckpointBundleStatus::Open,
            block_commitments,
            block_commitment_root,
            state_root,
            proof_root,
            da_root,
            private_state_root,
            low_fee_root,
            created_at_height,
            sealed_at_height: None,
            anchor_manifest_id: None,
        })
    }

    pub fn seal(&mut self, height: u64) {
        self.status = CheckpointBundleStatus::Sealed;
        self.sealed_at_height = Some(height);
    }

    pub fn mark_anchoring(&mut self, manifest_id: &str) {
        self.status = CheckpointBundleStatus::Anchoring;
        self.anchor_manifest_id = Some(manifest_id.to_string());
    }

    pub fn mark_anchored(&mut self) {
        self.status = CheckpointBundleStatus::Anchored;
    }

    pub fn finalize(&mut self) {
        self.status = CheckpointBundleStatus::Finalized;
    }

    pub fn challenge(&mut self) {
        self.status = CheckpointBundleStatus::Challenged;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "checkpoint_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "epoch": self.epoch,
            "first_height": self.first_height,
            "last_height": self.last_height,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "block_count": self.block_commitments.len() as u64,
            "block_commitment_root": self.block_commitment_root,
            "state_root": self.state_root,
            "proof_root": self.proof_root,
            "da_root": self.da_root,
            "private_state_root": self.private_state_root,
            "low_fee_root": self.low_fee_root,
            "created_at_height": self.created_at_height,
            "sealed_at_height": self.sealed_at_height,
            "anchor_manifest_id": self.anchor_manifest_id,
        })
    }

    pub fn bundle_root(&self) -> String {
        checkpoint_anchor_payload_root("CHECKPOINT-BUNDLE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointProofManifest {
    pub proof_manifest_id: String,
    pub bundle_id: String,
    pub validity_proof_root: String,
    pub recursive_batch_root: String,
    pub bridge_proof_root: String,
    pub private_state_proof_root: String,
    pub proof_system: String,
    pub pq_verifier_set_root: String,
    pub compression_ratio_bps: u64,
    pub verified: bool,
}

impl CheckpointProofManifest {
    pub fn new(bundle: &CheckpointBundle, proof_system: &str, compression_ratio_bps: u64) -> Self {
        let payload = json!({
            "bundle_id": bundle.bundle_id,
            "state_root": bundle.state_root,
            "proof_root": bundle.proof_root,
            "private_state_root": bundle.private_state_root,
            "proof_system": proof_system,
            "compression_ratio_bps": compression_ratio_bps,
        });
        let proof_manifest_id =
            checkpoint_anchor_payload_root("CHECKPOINT-PROOF-MANIFEST-ID", &payload);
        Self {
            proof_manifest_id,
            bundle_id: bundle.bundle_id.clone(),
            validity_proof_root: checkpoint_anchor_payload_root(
                "CHECKPOINT-VALIDITY-PROOF",
                &payload,
            ),
            recursive_batch_root: checkpoint_anchor_payload_root(
                "CHECKPOINT-RECURSIVE-BATCH",
                &payload,
            ),
            bridge_proof_root: checkpoint_anchor_payload_root("CHECKPOINT-BRIDGE-PROOF", &payload),
            private_state_proof_root: checkpoint_anchor_payload_root(
                "CHECKPOINT-PRIVATE-STATE-PROOF",
                &payload,
            ),
            proof_system: proof_system.to_string(),
            pq_verifier_set_root: checkpoint_anchor_string_root(
                "CHECKPOINT-PQ-VERIFIER-SET",
                &bundle.bundle_id,
            ),
            compression_ratio_bps,
            verified: false,
        }
    }

    pub fn verify(&mut self) {
        self.verified = true;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "checkpoint_proof_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "proof_manifest_id": self.proof_manifest_id,
            "bundle_id": self.bundle_id,
            "validity_proof_root": self.validity_proof_root,
            "recursive_batch_root": self.recursive_batch_root,
            "bridge_proof_root": self.bridge_proof_root,
            "private_state_proof_root": self.private_state_proof_root,
            "proof_system": self.proof_system,
            "pq_verifier_set_root": self.pq_verifier_set_root,
            "compression_ratio_bps": self.compression_ratio_bps,
            "verified": self.verified,
        })
    }

    pub fn manifest_root(&self) -> String {
        checkpoint_anchor_payload_root("CHECKPOINT-PROOF-MANIFEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAnchorManifest {
    pub manifest_id: String,
    pub bundle_id: String,
    pub proof_manifest_id: String,
    pub lane: CheckpointAnchorLane,
    pub status: AnchorManifestStatus,
    pub monero_network: String,
    pub anchor_payload_root: String,
    pub tx_extra_commitment_root: String,
    pub txid_root: String,
    pub output_commitment_root: String,
    pub key_image_watch_root: String,
    pub fee_units: u64,
    pub low_fee_sponsorship_id: Option<String>,
    pub submitted_at_height: Option<u64>,
    pub observed_monero_height: Option<u64>,
    pub confirmations: u64,
    pub finality_target: u64,
    pub expires_at_height: u64,
}

impl MoneroAnchorManifest {
    pub fn new(
        bundle: &CheckpointBundle,
        proof_manifest: &CheckpointProofManifest,
        lane: CheckpointAnchorLane,
        monero_network: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let anchor_payload = json!({
            "bundle_id": bundle.bundle_id,
            "bundle_root": bundle.bundle_root(),
            "proof_manifest_id": proof_manifest.proof_manifest_id,
            "proof_manifest_root": proof_manifest.manifest_root(),
            "lane": lane.as_str(),
            "network": monero_network,
        });
        let anchor_payload_root =
            checkpoint_anchor_payload_root("CHECKPOINT-MONERO-ANCHOR-PAYLOAD", &anchor_payload);
        let manifest_id =
            checkpoint_anchor_payload_root("CHECKPOINT-MONERO-ANCHOR-MANIFEST-ID", &anchor_payload);
        Self {
            manifest_id,
            bundle_id: bundle.bundle_id.clone(),
            proof_manifest_id: proof_manifest.proof_manifest_id.clone(),
            lane,
            status: AnchorManifestStatus::Draft,
            monero_network: monero_network.to_string(),
            anchor_payload_root: anchor_payload_root.clone(),
            tx_extra_commitment_root: checkpoint_anchor_string_root(
                "CHECKPOINT-MONERO-TX-EXTRA",
                &anchor_payload_root,
            ),
            txid_root: checkpoint_anchor_string_root(
                "CHECKPOINT-MONERO-TXID",
                &anchor_payload_root,
            ),
            output_commitment_root: checkpoint_anchor_string_root(
                "CHECKPOINT-MONERO-OUTPUTS",
                &anchor_payload_root,
            ),
            key_image_watch_root: checkpoint_anchor_string_root(
                "CHECKPOINT-MONERO-KEY-IMAGES",
                &anchor_payload_root,
            ),
            fee_units: lane.default_fee_units(),
            low_fee_sponsorship_id: None,
            submitted_at_height: None,
            observed_monero_height: None,
            confirmations: 0,
            finality_target: lane.default_confirmation_target(),
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
        }
    }

    pub fn mark_ready(&mut self) {
        self.status = AnchorManifestStatus::Ready;
    }

    pub fn submit(&mut self, height: u64, sponsorship_id: Option<String>) {
        self.status = AnchorManifestStatus::Submitted;
        self.submitted_at_height = Some(height);
        self.low_fee_sponsorship_id = sponsorship_id;
    }

    pub fn observe(&mut self, monero_height: u64, confirmations: u64) {
        self.status = AnchorManifestStatus::Observed;
        self.observed_monero_height = Some(monero_height);
        self.confirmations = confirmations;
        if confirmations >= self.finality_target {
            self.status = AnchorManifestStatus::Confirmed;
        }
    }

    pub fn expire_if_due(&mut self, height: u64) {
        if height > self.expires_at_height && self.status.is_live() {
            self.status = AnchorManifestStatus::Expired;
        }
    }

    pub fn reorg(&mut self) {
        self.status = AnchorManifestStatus::Reorged;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_anchor_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "bundle_id": self.bundle_id,
            "proof_manifest_id": self.proof_manifest_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "monero_network": self.monero_network,
            "anchor_payload_root": self.anchor_payload_root,
            "tx_extra_commitment_root": self.tx_extra_commitment_root,
            "txid_root": self.txid_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_watch_root": self.key_image_watch_root,
            "fee_units": self.fee_units,
            "low_fee_sponsorship_id": self.low_fee_sponsorship_id,
            "submitted_at_height": self.submitted_at_height,
            "observed_monero_height": self.observed_monero_height,
            "confirmations": self.confirmations,
            "finality_target": self.finality_target,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn manifest_root(&self) -> String {
        checkpoint_anchor_payload_root("MONERO-ANCHOR-MANIFEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointSigner {
    pub signer_id: String,
    pub operator_label: String,
    pub role: AnchorAttestationRole,
    pub pq_key_commitment: String,
    pub stake_weight_bps: u64,
    pub active: bool,
    pub last_seen_height: u64,
}

impl CheckpointSigner {
    pub fn new(
        operator_label: &str,
        role: AnchorAttestationRole,
        stake_weight_bps: u64,
        height: u64,
    ) -> Self {
        let pq_key_commitment =
            checkpoint_anchor_string_root("CHECKPOINT-SIGNER-PQ-KEY", operator_label);
        let signer_id = checkpoint_anchor_signer_id(operator_label, role, &pq_key_commitment);
        Self {
            signer_id,
            operator_label: operator_label.to_string(),
            role,
            pq_key_commitment,
            stake_weight_bps,
            active: true,
            last_seen_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "checkpoint_signer",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "signer_id": self.signer_id,
            "operator_label": self.operator_label,
            "role": self.role.as_str(),
            "pq_key_commitment": self.pq_key_commitment,
            "stake_weight_bps": self.stake_weight_bps,
            "active": self.active,
            "last_seen_height": self.last_seen_height,
        })
    }

    pub fn signer_root(&self) -> String {
        checkpoint_anchor_payload_root("CHECKPOINT-SIGNER", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointAttestation {
    pub attestation_id: String,
    pub signer_id: String,
    pub role: AnchorAttestationRole,
    pub subject_id: String,
    pub subject_root: String,
    pub pq_signature_root: String,
    pub recovery_signature_root: String,
    pub transcript_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub weight_bps: u64,
}

impl CheckpointAttestation {
    pub fn new(
        signer: &CheckpointSigner,
        subject_id: &str,
        subject_root: &str,
        signed_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let transcript = json!({
            "signer_id": signer.signer_id,
            "role": signer.role.as_str(),
            "subject_id": subject_id,
            "subject_root": subject_root,
            "signed_at_height": signed_at_height,
        });
        let transcript_root =
            checkpoint_anchor_payload_root("CHECKPOINT-PQ-TRANSCRIPT", &transcript);
        let attestation_id = checkpoint_anchor_attestation_id(
            &signer.signer_id,
            subject_id,
            subject_root,
            &transcript_root,
        );
        Self {
            attestation_id,
            signer_id: signer.signer_id.clone(),
            role: signer.role,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            pq_signature_root: checkpoint_anchor_string_root(
                "CHECKPOINT-PQ-SIGNATURE",
                &transcript_root,
            ),
            recovery_signature_root: checkpoint_anchor_string_root(
                "CHECKPOINT-RECOVERY-SIGNATURE",
                &transcript_root,
            ),
            transcript_root,
            signed_at_height,
            expires_at_height: signed_at_height.saturating_add(ttl_blocks),
            weight_bps: signer.stake_weight_bps,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "checkpoint_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "signer_id": self.signer_id,
            "role": self.role.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "pq_signature_root": self.pq_signature_root,
            "recovery_signature_root": self.recovery_signature_root,
            "transcript_root": self.transcript_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "weight_bps": self.weight_bps,
        })
    }

    pub fn attestation_root(&self) -> String {
        checkpoint_anchor_payload_root("CHECKPOINT-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub lane: CheckpointAnchorLane,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub expires_at_height: u64,
    pub active: bool,
}

impl AnchorFeeSponsorship {
    pub fn new(
        sponsor_label: &str,
        lane: CheckpointAnchorLane,
        budget_units: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let sponsor_commitment =
            checkpoint_anchor_string_root("CHECKPOINT-ANCHOR-SPONSOR", sponsor_label);
        let sponsorship_id = checkpoint_anchor_sponsorship_id(
            &sponsor_commitment,
            lane,
            budget_units,
            height.saturating_add(ttl_blocks),
        );
        Self {
            sponsorship_id,
            sponsor_commitment,
            lane,
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            expires_at_height: height.saturating_add(ttl_blocks),
            active: true,
        }
    }

    pub fn available_units(&self) -> u64 {
        if !self.active {
            return 0;
        }
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn reserve(&mut self, units: u64) -> CheckpointAnchorResult<()> {
        if self.available_units() < units {
            return Err("checkpoint anchor sponsorship budget exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn spend(&mut self, units: u64) {
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
    }

    pub fn expire_if_due(&mut self, height: u64) {
        if height > self.expires_at_height {
            self.active = false;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "anchor_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "expires_at_height": self.expires_at_height,
            "active": self.active,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        checkpoint_anchor_payload_root("ANCHOR-FEE-SPONSORSHIP", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointChallenge {
    pub challenge_id: String,
    pub kind: AnchorChallengeKind,
    pub status: AnchorChallengeStatus,
    pub bundle_id: String,
    pub manifest_id: Option<String>,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub resolution_root: Option<String>,
}

impl CheckpointChallenge {
    pub fn new(
        kind: AnchorChallengeKind,
        bundle_id: &str,
        manifest_id: Option<String>,
        challenger_label: &str,
        evidence: &Value,
        height: u64,
        challenge_window_blocks: u64,
    ) -> Self {
        let challenger_commitment =
            checkpoint_anchor_string_root("CHECKPOINT-CHALLENGER", challenger_label);
        let evidence_root =
            checkpoint_anchor_payload_root("CHECKPOINT-CHALLENGE-EVIDENCE", evidence);
        let challenge_id = checkpoint_anchor_challenge_id(
            kind,
            bundle_id,
            manifest_id.as_deref().unwrap_or("none"),
            &challenger_commitment,
            &evidence_root,
            height,
        );
        Self {
            challenge_id,
            kind,
            status: AnchorChallengeStatus::Open,
            bundle_id: bundle_id.to_string(),
            manifest_id,
            challenger_commitment,
            evidence_root,
            opened_at_height: height,
            deadline_height: height.saturating_add(challenge_window_blocks),
            resolution_root: None,
        }
    }

    pub fn resolve(&mut self, status: AnchorChallengeStatus, resolution: &Value) {
        self.status = status;
        self.resolution_root = Some(checkpoint_anchor_payload_root(
            "CHECKPOINT-CHALLENGE-RESOLUTION",
            resolution,
        ));
    }

    pub fn expire_if_due(&mut self, height: u64) {
        if height > self.deadline_height && self.status.is_open() {
            self.status = AnchorChallengeStatus::Expired;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "checkpoint_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "bundle_id": self.bundle_id,
            "manifest_id": self.manifest_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "resolution_root": self.resolution_root,
        })
    }

    pub fn challenge_root(&self) -> String {
        checkpoint_anchor_payload_root("CHECKPOINT-CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointAnchorRoots {
    pub config_root: String,
    pub bundle_root: String,
    pub proof_manifest_root: String,
    pub anchor_manifest_root: String,
    pub signer_root: String,
    pub attestation_root: String,
    pub sponsorship_root: String,
    pub challenge_root: String,
    pub replay_registry_root: String,
    pub state_root: String,
}

impl CheckpointAnchorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "checkpoint_anchor_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "bundle_root": self.bundle_root,
            "proof_manifest_root": self.proof_manifest_root,
            "anchor_manifest_root": self.anchor_manifest_root,
            "signer_root": self.signer_root,
            "attestation_root": self.attestation_root,
            "sponsorship_root": self.sponsorship_root,
            "challenge_root": self.challenge_root,
            "replay_registry_root": self.replay_registry_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointAnchorState {
    pub config: CheckpointAnchorConfig,
    pub height: u64,
    pub bundles: BTreeMap<String, CheckpointBundle>,
    pub proof_manifests: BTreeMap<String, CheckpointProofManifest>,
    pub anchor_manifests: BTreeMap<String, MoneroAnchorManifest>,
    pub signers: BTreeMap<String, CheckpointSigner>,
    pub attestations: BTreeMap<String, CheckpointAttestation>,
    pub sponsorships: BTreeMap<String, AnchorFeeSponsorship>,
    pub challenges: BTreeMap<String, CheckpointChallenge>,
    pub replay_registry: BTreeSet<String>,
}

impl CheckpointAnchorState {
    pub fn new(config: CheckpointAnchorConfig) -> CheckpointAnchorResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            bundles: BTreeMap::new(),
            proof_manifests: BTreeMap::new(),
            anchor_manifests: BTreeMap::new(),
            signers: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            challenges: BTreeMap::new(),
            replay_registry: BTreeSet::new(),
        })
    }

    pub fn devnet() -> CheckpointAnchorResult<Self> {
        let mut state = Self::new(CheckpointAnchorConfig::devnet())?;
        state.set_height(64);

        for (label, role, weight) in [
            (
                "devnet-sequencer-anchor-0",
                AnchorAttestationRole::Sequencer,
                2_800,
            ),
            (
                "devnet-prover-anchor-0",
                AnchorAttestationRole::Prover,
                2_400,
            ),
            (
                "devnet-watchtower-anchor-0",
                AnchorAttestationRole::Watchtower,
                1_800,
            ),
            (
                "devnet-bridge-guardian-0",
                AnchorAttestationRole::BridgeGuardian,
                1_600,
            ),
            (
                "devnet-monero-observer-0",
                AnchorAttestationRole::MoneroObserver,
                1_400,
            ),
        ] {
            state.insert_signer(CheckpointSigner::new(label, role, weight, state.height))?;
        }

        let sponsor = AnchorFeeSponsorship::new(
            "devnet-anchor-sponsor",
            CheckpointAnchorLane::Fast,
            state.config.low_fee_budget_units,
            state.height,
            500,
        );
        let sponsor_id = sponsor.sponsorship_id.clone();
        state.insert_sponsorship(sponsor)?;

        let bundle_a = CheckpointBundle::new(
            4,
            CheckpointAnchorLane::Fast,
            (49..=56)
                .map(|height| CheckpointBlockCommitment::devnet(height, "fast"))
                .collect(),
            state.height,
        )?;
        let bundle_a_id = state.insert_bundle(bundle_a)?;
        let proof_a_id =
            state.create_proof_manifest(&bundle_a_id, "nebula-recursive-pq-checkpoint-v1", 880)?;
        let manifest_a_id = state.create_anchor_manifest(
            &bundle_a_id,
            &proof_a_id,
            CheckpointAnchorLane::Fast,
            "monero-devnet",
        )?;
        state.reserve_and_submit_manifest(&manifest_a_id, Some(sponsor_id.clone()))?;
        state.observe_manifest(&manifest_a_id, 132_100, 10)?;
        state.attest_subject_quorum(&bundle_a_id, state.config.challenge_window_blocks)?;
        state.finalize_confirmed_bundle(&bundle_a_id)?;

        let bundle_b = CheckpointBundle::new(
            4,
            CheckpointAnchorLane::ProofDense,
            (57..=64)
                .map(|height| CheckpointBlockCommitment::devnet(height, "proof-dense"))
                .collect(),
            state.height,
        )?;
        let bundle_b_id = state.insert_bundle(bundle_b)?;
        let proof_b_id =
            state.create_proof_manifest(&bundle_b_id, "nebula-proof-dense-checkpoint-v1", 730)?;
        let manifest_b_id = state.create_anchor_manifest(
            &bundle_b_id,
            &proof_b_id,
            CheckpointAnchorLane::ProofDense,
            "monero-devnet",
        )?;
        state.reserve_and_submit_manifest(&manifest_b_id, None)?;
        state.observe_manifest(&manifest_b_id, 132_101, 2)?;
        state.attest_subject_quorum(&bundle_b_id, state.config.challenge_window_blocks)?;

        let challenge = CheckpointChallenge::new(
            AnchorChallengeKind::MissingData,
            &bundle_b_id,
            Some(manifest_b_id),
            "devnet-watchtower-anchor-0",
            &json!({"missing": "sampled-da-shard", "severity": "watch"}),
            state.height,
            state.config.challenge_window_blocks,
        );
        state.insert_challenge(challenge)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for sponsorship in self.sponsorships.values_mut() {
            sponsorship.expire_if_due(height);
        }
        for manifest in self.anchor_manifests.values_mut() {
            manifest.expire_if_due(height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.expire_if_due(height);
        }
    }

    pub fn insert_bundle(
        &mut self,
        mut bundle: CheckpointBundle,
    ) -> CheckpointAnchorResult<String> {
        if bundle.block_commitments.len() > self.config.max_bundle_blocks {
            return Err("checkpoint bundle exceeds max block count".to_string());
        }
        if self.replay_registry.contains(&bundle.block_commitment_root) {
            return Err("checkpoint bundle block root already anchored".to_string());
        }
        bundle.seal(self.height);
        let bundle_id = bundle.bundle_id.clone();
        self.replay_registry
            .insert(bundle.block_commitment_root.clone());
        self.bundles.insert(bundle_id.clone(), bundle);
        Ok(bundle_id)
    }

    pub fn insert_signer(&mut self, signer: CheckpointSigner) -> CheckpointAnchorResult<String> {
        if signer.stake_weight_bps > CHECKPOINT_ANCHOR_MAX_BPS {
            return Err("checkpoint signer weight exceeds max bps".to_string());
        }
        let signer_id = signer.signer_id.clone();
        self.signers.insert(signer_id.clone(), signer);
        Ok(signer_id)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: AnchorFeeSponsorship,
    ) -> CheckpointAnchorResult<String> {
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn insert_challenge(
        &mut self,
        mut challenge: CheckpointChallenge,
    ) -> CheckpointAnchorResult<String> {
        if let Some(bundle) = self.bundles.get_mut(&challenge.bundle_id) {
            bundle.challenge();
        } else {
            return Err("checkpoint challenge references missing bundle".to_string());
        }
        if challenge.deadline_height <= challenge.opened_at_height {
            challenge.deadline_height = challenge
                .opened_at_height
                .saturating_add(self.config.challenge_window_blocks);
        }
        let challenge_id = challenge.challenge_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn create_proof_manifest(
        &mut self,
        bundle_id: &str,
        proof_system: &str,
        compression_ratio_bps: u64,
    ) -> CheckpointAnchorResult<String> {
        let bundle = self
            .bundles
            .get(bundle_id)
            .cloned()
            .ok_or_else(|| format!("checkpoint bundle not found: {bundle_id}"))?;
        let mut proof_manifest =
            CheckpointProofManifest::new(&bundle, proof_system, compression_ratio_bps);
        proof_manifest.verify();
        let proof_manifest_id = proof_manifest.proof_manifest_id.clone();
        self.proof_manifests
            .insert(proof_manifest_id.clone(), proof_manifest);
        Ok(proof_manifest_id)
    }

    pub fn create_anchor_manifest(
        &mut self,
        bundle_id: &str,
        proof_manifest_id: &str,
        lane: CheckpointAnchorLane,
        monero_network: &str,
    ) -> CheckpointAnchorResult<String> {
        let bundle = self
            .bundles
            .get(bundle_id)
            .cloned()
            .ok_or_else(|| format!("checkpoint bundle not found: {bundle_id}"))?;
        let proof_manifest = self
            .proof_manifests
            .get(proof_manifest_id)
            .cloned()
            .ok_or_else(|| format!("checkpoint proof manifest not found: {proof_manifest_id}"))?;
        if self.anchor_manifests.len() >= self.config.max_pending_anchors {
            return Err("checkpoint anchor pending manifest capacity reached".to_string());
        }
        let mut manifest = MoneroAnchorManifest::new(
            &bundle,
            &proof_manifest,
            lane,
            monero_network,
            self.height,
            self.config.challenge_window_blocks.saturating_mul(2),
        );
        manifest.mark_ready();
        let manifest_id = manifest.manifest_id.clone();
        if let Some(bundle) = self.bundles.get_mut(bundle_id) {
            bundle.mark_anchoring(&manifest_id);
        }
        self.anchor_manifests.insert(manifest_id.clone(), manifest);
        Ok(manifest_id)
    }

    pub fn reserve_and_submit_manifest(
        &mut self,
        manifest_id: &str,
        sponsorship_id: Option<String>,
    ) -> CheckpointAnchorResult<()> {
        let fee_units = self
            .anchor_manifests
            .get(manifest_id)
            .ok_or_else(|| format!("checkpoint anchor manifest not found: {manifest_id}"))?
            .fee_units;
        if let Some(sponsorship_id) = &sponsorship_id {
            let sponsorship = self
                .sponsorships
                .get_mut(sponsorship_id)
                .ok_or_else(|| format!("checkpoint sponsorship not found: {sponsorship_id}"))?;
            sponsorship.reserve(fee_units)?;
            sponsorship.spend(fee_units);
        }
        let manifest = self
            .anchor_manifests
            .get_mut(manifest_id)
            .ok_or_else(|| format!("checkpoint anchor manifest not found: {manifest_id}"))?;
        manifest.submit(self.height, sponsorship_id);
        Ok(())
    }

    pub fn observe_manifest(
        &mut self,
        manifest_id: &str,
        monero_height: u64,
        confirmations: u64,
    ) -> CheckpointAnchorResult<()> {
        let manifest = self
            .anchor_manifests
            .get_mut(manifest_id)
            .ok_or_else(|| format!("checkpoint anchor manifest not found: {manifest_id}"))?;
        manifest.observe(monero_height, confirmations);
        if confirmations >= manifest.finality_target {
            if let Some(bundle) = self.bundles.get_mut(&manifest.bundle_id) {
                bundle.mark_anchored();
            }
        }
        Ok(())
    }

    pub fn attest_subject_quorum(
        &mut self,
        subject_id: &str,
        ttl_blocks: u64,
    ) -> CheckpointAnchorResult<u64> {
        let subject_root = if let Some(bundle) = self.bundles.get(subject_id) {
            bundle.bundle_root()
        } else if let Some(manifest) = self.anchor_manifests.get(subject_id) {
            manifest.manifest_root()
        } else {
            return Err(format!(
                "checkpoint attestation subject not found: {subject_id}"
            ));
        };
        let mut total_weight = 0_u64;
        let signers = self
            .signers
            .values()
            .filter(|signer| signer.active)
            .cloned()
            .collect::<Vec<_>>();
        for signer in signers {
            let attestation = CheckpointAttestation::new(
                &signer,
                subject_id,
                &subject_root,
                self.height,
                ttl_blocks,
            );
            total_weight = total_weight.saturating_add(attestation.weight_bps);
            self.attestations
                .insert(attestation.attestation_id.clone(), attestation);
            if total_weight >= self.config.min_quorum_weight_bps {
                break;
            }
        }
        if total_weight < self.config.min_quorum_weight_bps {
            return Err("checkpoint anchor quorum weight not reached".to_string());
        }
        Ok(total_weight)
    }

    pub fn finalize_confirmed_bundle(&mut self, bundle_id: &str) -> CheckpointAnchorResult<()> {
        let manifest_confirmed = self.anchor_manifests.values().any(|manifest| {
            manifest.bundle_id == bundle_id && manifest.status == AnchorManifestStatus::Confirmed
        });
        if !manifest_confirmed {
            return Err("checkpoint bundle has no confirmed Monero anchor".to_string());
        }
        if self
            .challenges
            .values()
            .any(|challenge| challenge.bundle_id == bundle_id && challenge.status.is_open())
        {
            return Err("checkpoint bundle has open challenge".to_string());
        }
        let bundle = self
            .bundles
            .get_mut(bundle_id)
            .ok_or_else(|| format!("checkpoint bundle not found: {bundle_id}"))?;
        bundle.finalize();
        Ok(())
    }

    pub fn active_bundle_count(&self) -> u64 {
        self.bundles
            .values()
            .filter(|bundle| !bundle.status.is_terminal())
            .count() as u64
    }

    pub fn confirmed_manifest_count(&self) -> u64 {
        self.anchor_manifests
            .values()
            .filter(|manifest| manifest.status == AnchorManifestStatus::Confirmed)
            .count() as u64
    }

    pub fn open_challenge_count(&self) -> u64 {
        self.challenges
            .values()
            .filter(|challenge| challenge.status.is_open())
            .count() as u64
    }

    pub fn total_sponsorship_available_units(&self) -> u64 {
        self.sponsorships
            .values()
            .map(AnchorFeeSponsorship::available_units)
            .sum()
    }

    pub fn live_quorum_weight_bps(&self) -> u64 {
        self.signers
            .values()
            .filter(|signer| signer.active)
            .map(|signer| signer.stake_weight_bps)
            .sum::<u64>()
            .min(CHECKPOINT_ANCHOR_MAX_BPS)
    }

    pub fn roots(&self) -> CheckpointAnchorRoots {
        let bundle_records = self
            .bundles
            .values()
            .map(CheckpointBundle::public_record)
            .collect::<Vec<_>>();
        let proof_records = self
            .proof_manifests
            .values()
            .map(CheckpointProofManifest::public_record)
            .collect::<Vec<_>>();
        let manifest_records = self
            .anchor_manifests
            .values()
            .map(MoneroAnchorManifest::public_record)
            .collect::<Vec<_>>();
        let signer_records = self
            .signers
            .values()
            .map(CheckpointSigner::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .attestations
            .values()
            .map(CheckpointAttestation::public_record)
            .collect::<Vec<_>>();
        let sponsorship_records = self
            .sponsorships
            .values()
            .map(AnchorFeeSponsorship::public_record)
            .collect::<Vec<_>>();
        let challenge_records = self
            .challenges
            .values()
            .map(CheckpointChallenge::public_record)
            .collect::<Vec<_>>();
        let replay_records = self
            .replay_registry
            .iter()
            .map(|root| json!({"block_commitment_root": root}))
            .collect::<Vec<_>>();
        let bundle_root = merkle_root("CHECKPOINT-ANCHOR-BUNDLE", &bundle_records);
        let proof_manifest_root = merkle_root("CHECKPOINT-ANCHOR-PROOF-MANIFEST", &proof_records);
        let anchor_manifest_root =
            merkle_root("CHECKPOINT-ANCHOR-MONERO-MANIFEST", &manifest_records);
        let signer_root = merkle_root("CHECKPOINT-ANCHOR-SIGNER", &signer_records);
        let attestation_root = merkle_root("CHECKPOINT-ANCHOR-ATTESTATION", &attestation_records);
        let sponsorship_root = merkle_root("CHECKPOINT-ANCHOR-SPONSORSHIP", &sponsorship_records);
        let challenge_root = merkle_root("CHECKPOINT-ANCHOR-CHALLENGE", &challenge_records);
        let replay_registry_root =
            merkle_root("CHECKPOINT-ANCHOR-REPLAY-REGISTRY", &replay_records);
        let config_root = self.config.config_root();
        let state_record = json!({
            "height": self.height,
            "config_root": config_root,
            "bundle_root": bundle_root,
            "proof_manifest_root": proof_manifest_root,
            "anchor_manifest_root": anchor_manifest_root,
            "signer_root": signer_root,
            "attestation_root": attestation_root,
            "sponsorship_root": sponsorship_root,
            "challenge_root": challenge_root,
            "replay_registry_root": replay_registry_root,
        });
        let state_root = checkpoint_anchor_state_root_from_record(&state_record);
        CheckpointAnchorRoots {
            config_root,
            bundle_root,
            proof_manifest_root,
            anchor_manifest_root,
            signer_root,
            attestation_root,
            sponsorship_root,
            challenge_root,
            replay_registry_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        checkpoint_anchor_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "checkpoint_anchor_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CHECKPOINT_ANCHOR_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "bundle_count": self.bundles.len() as u64,
            "active_bundle_count": self.active_bundle_count(),
            "proof_manifest_count": self.proof_manifests.len() as u64,
            "anchor_manifest_count": self.anchor_manifests.len() as u64,
            "confirmed_manifest_count": self.confirmed_manifest_count(),
            "signer_count": self.signers.len() as u64,
            "attestation_count": self.attestations.len() as u64,
            "sponsorship_count": self.sponsorships.len() as u64,
            "open_challenge_count": self.open_challenge_count(),
            "replay_registry_count": self.replay_registry.len() as u64,
            "live_quorum_weight_bps": self.live_quorum_weight_bps(),
            "total_sponsorship_available_units": self.total_sponsorship_available_units(),
        })
    }

    pub fn validate(&self) -> CheckpointAnchorResult<()> {
        self.config.validate()?;
        if self.live_quorum_weight_bps() < self.config.min_quorum_weight_bps {
            return Err("checkpoint anchor live quorum below threshold".to_string());
        }
        for manifest in self.anchor_manifests.values() {
            if !self.bundles.contains_key(&manifest.bundle_id) {
                return Err(format!(
                    "checkpoint anchor manifest references missing bundle: {}",
                    manifest.manifest_id
                ));
            }
            if !self
                .proof_manifests
                .contains_key(&manifest.proof_manifest_id)
            {
                return Err(format!(
                    "checkpoint anchor manifest references missing proof manifest: {}",
                    manifest.manifest_id
                ));
            }
        }
        for challenge in self.challenges.values() {
            if !self.bundles.contains_key(&challenge.bundle_id) {
                return Err(format!(
                    "checkpoint challenge references missing bundle: {}",
                    challenge.challenge_id
                ));
            }
        }
        Ok(())
    }
}

pub fn checkpoint_anchor_bundle_id(
    epoch: u64,
    first_height: u64,
    last_height: u64,
    lane: CheckpointAnchorLane,
    block_commitment_root: &str,
    state_root: &str,
) -> String {
    domain_hash(
        "CHECKPOINT-ANCHOR-BUNDLE-ID",
        &[
            HashPart::Int(epoch as i128),
            HashPart::Int(first_height as i128),
            HashPart::Int(last_height as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Str(block_commitment_root),
            HashPart::Str(state_root),
        ],
        24,
    )
}

pub fn checkpoint_anchor_signer_id(
    operator_label: &str,
    role: AnchorAttestationRole,
    pq_key_commitment: &str,
) -> String {
    domain_hash(
        "CHECKPOINT-ANCHOR-SIGNER-ID",
        &[
            HashPart::Str(operator_label),
            HashPart::Str(role.as_str()),
            HashPart::Str(pq_key_commitment),
        ],
        24,
    )
}

pub fn checkpoint_anchor_attestation_id(
    signer_id: &str,
    subject_id: &str,
    subject_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "CHECKPOINT-ANCHOR-ATTESTATION-ID",
        &[
            HashPart::Str(signer_id),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(transcript_root),
        ],
        24,
    )
}

pub fn checkpoint_anchor_sponsorship_id(
    sponsor_commitment: &str,
    lane: CheckpointAnchorLane,
    budget_units: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "CHECKPOINT-ANCHOR-SPONSORSHIP-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Int(budget_units as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        24,
    )
}

pub fn checkpoint_anchor_challenge_id(
    kind: AnchorChallengeKind,
    bundle_id: &str,
    manifest_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "CHECKPOINT-ANCHOR-CHALLENGE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(bundle_id),
            HashPart::Str(manifest_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(height as i128),
        ],
        24,
    )
}

pub fn checkpoint_anchor_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CHECKPOINT-ANCHOR-STATE",
        &[
            HashPart::Str(CHECKPOINT_ANCHOR_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn checkpoint_anchor_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHECKPOINT_ANCHOR_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn checkpoint_anchor_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHECKPOINT_ANCHOR_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}
