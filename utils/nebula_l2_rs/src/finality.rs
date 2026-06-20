use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type FinalityResult<T> = Result<T, String>;

pub const FINALITY_PROTOCOL_VERSION: u64 = 1;
pub const FINALITY_DEFAULT_SOFT_QUORUM_BPS: u64 = 6_000;
pub const FINALITY_DEFAULT_FINAL_QUORUM_BPS: u64 = 6_667;
pub const FINALITY_DEFAULT_MONERO_FINALITY_DEPTH: u64 = 10;
pub const FINALITY_DEFAULT_REORG_WINDOW_BLOCKS: u64 = 64;
pub const FINALITY_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 20;
pub const FINALITY_DEFAULT_WITHDRAWAL_CHALLENGE_WINDOW_BLOCKS: u64 = 20;
pub const FINALITY_DEFAULT_ROLLBACK_QUORUM_BPS: u64 = 8_000;
pub const FINALITY_MAX_MANIFEST_ENTRIES: u64 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityCheckpointKind {
    Soft,
    Final,
}

impl FinalityCheckpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Soft => "soft",
            Self::Final => "final",
        }
    }

    pub fn quorum_bps(self, parameters: &FinalitySafetyParameters) -> u64 {
        match self {
            Self::Soft => parameters.soft_quorum_bps,
            Self::Final => parameters.final_quorum_bps,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalitySafetyParameters {
    pub protocol_version: u64,
    pub soft_quorum_bps: u64,
    pub final_quorum_bps: u64,
    pub monero_finality_depth: u64,
    pub reorg_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub withdrawal_challenge_window_blocks: u64,
    pub rollback_quorum_bps: u64,
    pub max_manifest_entries: u64,
}

impl Default for FinalitySafetyParameters {
    fn default() -> Self {
        Self {
            protocol_version: FINALITY_PROTOCOL_VERSION,
            soft_quorum_bps: FINALITY_DEFAULT_SOFT_QUORUM_BPS,
            final_quorum_bps: FINALITY_DEFAULT_FINAL_QUORUM_BPS,
            monero_finality_depth: FINALITY_DEFAULT_MONERO_FINALITY_DEPTH,
            reorg_window_blocks: FINALITY_DEFAULT_REORG_WINDOW_BLOCKS,
            challenge_window_blocks: FINALITY_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            withdrawal_challenge_window_blocks: FINALITY_DEFAULT_WITHDRAWAL_CHALLENGE_WINDOW_BLOCKS,
            rollback_quorum_bps: FINALITY_DEFAULT_ROLLBACK_QUORUM_BPS,
            max_manifest_entries: FINALITY_MAX_MANIFEST_ENTRIES,
        }
    }
}

impl FinalitySafetyParameters {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        soft_quorum_bps: u64,
        final_quorum_bps: u64,
        monero_finality_depth: u64,
        reorg_window_blocks: u64,
        challenge_window_blocks: u64,
        withdrawal_challenge_window_blocks: u64,
        rollback_quorum_bps: u64,
        max_manifest_entries: u64,
    ) -> FinalityResult<Self> {
        let parameters = Self {
            protocol_version: FINALITY_PROTOCOL_VERSION,
            soft_quorum_bps,
            final_quorum_bps,
            monero_finality_depth,
            reorg_window_blocks,
            challenge_window_blocks,
            withdrawal_challenge_window_blocks,
            rollback_quorum_bps,
            max_manifest_entries,
        };
        parameters.validate()?;
        Ok(parameters)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "finality_safety_parameters",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": self.protocol_version,
            "soft_quorum_bps": self.soft_quorum_bps,
            "final_quorum_bps": self.final_quorum_bps,
            "monero_finality_depth": self.monero_finality_depth,
            "reorg_window_blocks": self.reorg_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "withdrawal_challenge_window_blocks": self.withdrawal_challenge_window_blocks,
            "rollback_quorum_bps": self.rollback_quorum_bps,
            "max_manifest_entries": self.max_manifest_entries,
        })
    }

    pub fn parameters_root(&self) -> String {
        finality_parameters_root(&self.public_record())
    }

    pub fn validate(&self) -> FinalityResult<String> {
        if self.protocol_version != FINALITY_PROTOCOL_VERSION {
            return Err("finality parameter protocol version mismatch".to_string());
        }
        ensure_bps(self.soft_quorum_bps, "finality soft quorum bps")?;
        ensure_bps(self.final_quorum_bps, "finality final quorum bps")?;
        ensure_bps(self.rollback_quorum_bps, "finality rollback quorum bps")?;
        if self.soft_quorum_bps > self.final_quorum_bps {
            return Err("finality soft quorum cannot exceed final quorum".to_string());
        }
        if self.final_quorum_bps > self.rollback_quorum_bps {
            return Err("finality final quorum cannot exceed rollback quorum".to_string());
        }
        if self.monero_finality_depth == 0 {
            return Err("finality Monero depth must be positive".to_string());
        }
        if self.reorg_window_blocks == 0 {
            return Err("finality reorg window must be positive".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("finality challenge window must be positive".to_string());
        }
        if self.withdrawal_challenge_window_blocks == 0 {
            return Err("finality withdrawal challenge window must be positive".to_string());
        }
        if self.max_manifest_entries == 0 {
            return Err("finality manifest entry limit must be positive".to_string());
        }
        Ok(self.parameters_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorFinalityAttestation {
    pub attestation_id: String,
    pub checkpoint_kind: FinalityCheckpointKind,
    pub checkpoint_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub validator_id: String,
    pub validator_label: String,
    pub consensus_public_key: String,
    pub stake_weight: u64,
    pub signed_at_height: u64,
    pub signature_root: String,
    pub status: String,
}

impl ValidatorFinalityAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_kind: FinalityCheckpointKind,
        checkpoint_id: impl Into<String>,
        block_height: u64,
        block_hash: impl Into<String>,
        state_root: impl Into<String>,
        validator_id: impl Into<String>,
        validator_label: impl Into<String>,
        consensus_public_key: impl Into<String>,
        stake_weight: u64,
        signed_at_height: u64,
    ) -> FinalityResult<Self> {
        let mut attestation = Self {
            attestation_id: String::new(),
            checkpoint_kind,
            checkpoint_id: checkpoint_id.into(),
            block_height,
            block_hash: block_hash.into(),
            state_root: state_root.into(),
            validator_id: validator_id.into(),
            validator_label: validator_label.into(),
            consensus_public_key: consensus_public_key.into(),
            stake_weight,
            signed_at_height,
            signature_root: String::new(),
            status: "accepted".to_string(),
        };
        let identity = attestation.identity_record();
        attestation.attestation_id = validator_finality_attestation_id(&identity);
        attestation.signature_root = validator_finality_signature_root(
            &identity,
            &attestation.validator_label,
            &attestation.consensus_public_key,
        );
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "validator_finality_attestation",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "checkpoint_kind": self.checkpoint_kind.as_str(),
            "checkpoint_id": self.checkpoint_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "validator_id": self.validator_id,
            "validator_label": self.validator_label,
            "consensus_public_key": self.consensus_public_key,
            "stake_weight": self.stake_weight,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn attestation_root(&self) -> String {
        domain_hash(
            "FINALITY-VALIDATOR-ATTESTATION",
            &[HashPart::Json(&self.public_record_without_root())],
            32,
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("validator finality attestation record object");
        object.insert(
            "attestation_id".to_string(),
            Value::String(self.attestation_id.clone()),
        );
        object.insert(
            "signature_root".to_string(),
            Value::String(self.signature_root.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "attestation_root",
            self.attestation_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.attestation_id == validator_finality_attestation_id(&self.identity_record())
    }

    pub fn validate(&self) -> FinalityResult<String> {
        ensure_non_empty(&self.checkpoint_id, "validator finality checkpoint id")?;
        ensure_non_empty(&self.block_hash, "validator finality block hash")?;
        ensure_non_empty(&self.state_root, "validator finality state root")?;
        ensure_non_empty(&self.validator_id, "validator finality validator id")?;
        ensure_non_empty(&self.validator_label, "validator finality validator label")?;
        ensure_non_empty(
            &self.consensus_public_key,
            "validator finality consensus public key",
        )?;
        if self.stake_weight == 0 {
            return Err("validator finality attestation stake cannot be zero".to_string());
        }
        ensure_status(
            &self.status,
            &["accepted", "superseded", "slashed", "rejected"],
            "validator finality attestation status",
        )?;
        if !self.verify_id() {
            return Err("validator finality attestation id mismatch".to_string());
        }
        let identity = self.identity_record();
        let expected_signature = validator_finality_signature_root(
            &identity,
            &self.validator_label,
            &self.consensus_public_key,
        );
        if self.signature_root != expected_signature {
            return Err("validator finality attestation signature root mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2FinalityCheckpoint {
    pub checkpoint_id: String,
    pub checkpoint_kind: FinalityCheckpointKind,
    pub height: u64,
    pub epoch: u64,
    pub round: u64,
    pub block_hash: String,
    pub parent_block_hash: String,
    pub state_root: String,
    pub tx_root: String,
    pub da_root: String,
    pub bridge_root: String,
    pub validator_set_root: String,
    pub consensus_root: String,
    pub previous_final_checkpoint_id: String,
    pub attestation_root: String,
    pub total_stake: u64,
    pub attested_stake: u64,
    pub quorum_bps: u64,
    pub quorum_stake: u64,
    pub attester_count: u64,
    pub opened_at_height: u64,
    pub finalized_at_height: u64,
    pub challenge_window_end_height: u64,
    pub status: String,
}

impl L2FinalityCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn from_roots(
        checkpoint_kind: FinalityCheckpointKind,
        height: u64,
        epoch: u64,
        round: u64,
        block_hash: impl Into<String>,
        parent_block_hash: impl Into<String>,
        state_root: impl Into<String>,
        tx_root: impl Into<String>,
        da_root: impl Into<String>,
        bridge_root: impl Into<String>,
        validator_set_root: impl Into<String>,
        consensus_root: impl Into<String>,
        previous_final_checkpoint_id: impl Into<String>,
        attestation_root: impl Into<String>,
        total_stake: u64,
        attested_stake: u64,
        quorum_bps: u64,
        attester_count: u64,
        opened_at_height: u64,
        finalized_at_height: u64,
        challenge_window_end_height: u64,
        status: impl Into<String>,
    ) -> FinalityResult<Self> {
        let quorum_stake = finality_quorum_stake(total_stake, quorum_bps);
        let mut checkpoint = Self {
            checkpoint_id: String::new(),
            checkpoint_kind,
            height,
            epoch,
            round,
            block_hash: block_hash.into(),
            parent_block_hash: parent_block_hash.into(),
            state_root: state_root.into(),
            tx_root: tx_root.into(),
            da_root: da_root.into(),
            bridge_root: bridge_root.into(),
            validator_set_root: validator_set_root.into(),
            consensus_root: consensus_root.into(),
            previous_final_checkpoint_id: previous_final_checkpoint_id.into(),
            attestation_root: attestation_root.into(),
            total_stake,
            attested_stake,
            quorum_bps,
            quorum_stake,
            attester_count,
            opened_at_height,
            finalized_at_height,
            challenge_window_end_height,
            status: status.into(),
        };
        checkpoint.checkpoint_id = l2_finality_checkpoint_id(&checkpoint.identity_record());
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_attestations(
        checkpoint_kind: FinalityCheckpointKind,
        height: u64,
        epoch: u64,
        round: u64,
        block_hash: impl Into<String>,
        parent_block_hash: impl Into<String>,
        state_root: impl Into<String>,
        tx_root: impl Into<String>,
        da_root: impl Into<String>,
        bridge_root: impl Into<String>,
        validator_set_root: impl Into<String>,
        consensus_root: impl Into<String>,
        previous_final_checkpoint_id: impl Into<String>,
        total_stake: u64,
        quorum_bps: u64,
        attestations: &[ValidatorFinalityAttestation],
        opened_at_height: u64,
        challenge_window_blocks: u64,
    ) -> FinalityResult<Self> {
        let block_hash = block_hash.into();
        let state_root = state_root.into();
        let attestation_root = validator_finality_attestation_root(attestations);
        let (attested_stake, attester_count) = checkpoint_attested_stake(
            checkpoint_kind,
            height,
            &block_hash,
            &state_root,
            attestations,
        )?;
        let quorum_stake = finality_quorum_stake(total_stake, quorum_bps);
        let status = if attested_stake >= quorum_stake {
            match checkpoint_kind {
                FinalityCheckpointKind::Soft => "soft",
                FinalityCheckpointKind::Final => "final",
            }
        } else {
            "pending"
        };
        let finalized_at_height = if status == "final" {
            opened_at_height.saturating_add(challenge_window_blocks)
        } else {
            0
        };
        Self::from_roots(
            checkpoint_kind,
            height,
            epoch,
            round,
            block_hash,
            parent_block_hash,
            state_root,
            tx_root,
            da_root,
            bridge_root,
            validator_set_root,
            consensus_root,
            previous_final_checkpoint_id,
            attestation_root,
            total_stake,
            attested_stake,
            quorum_bps,
            attester_count,
            opened_at_height,
            finalized_at_height,
            opened_at_height.saturating_add(challenge_window_blocks),
            status,
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "l2_finality_checkpoint_identity",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "checkpoint_kind": self.checkpoint_kind.as_str(),
            "height": self.height,
            "epoch": self.epoch,
            "round": self.round,
            "block_hash": self.block_hash,
            "parent_block_hash": self.parent_block_hash,
            "state_root": self.state_root,
            "tx_root": self.tx_root,
            "da_root": self.da_root,
            "bridge_root": self.bridge_root,
            "validator_set_root": self.validator_set_root,
            "consensus_root": self.consensus_root,
            "previous_final_checkpoint_id": self.previous_final_checkpoint_id,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("L2 finality checkpoint record object");
        object.insert(
            "kind".to_string(),
            Value::String("l2_finality_checkpoint".to_string()),
        );
        object.insert(
            "checkpoint_id".to_string(),
            Value::String(self.checkpoint_id.clone()),
        );
        object.insert(
            "attestation_root".to_string(),
            Value::String(self.attestation_root.clone()),
        );
        object.insert("total_stake".to_string(), json!(self.total_stake));
        object.insert("attested_stake".to_string(), json!(self.attested_stake));
        object.insert("quorum_bps".to_string(), json!(self.quorum_bps));
        object.insert("quorum_stake".to_string(), json!(self.quorum_stake));
        object.insert("attester_count".to_string(), json!(self.attester_count));
        object.insert("opened_at_height".to_string(), json!(self.opened_at_height));
        object.insert(
            "finalized_at_height".to_string(),
            json!(self.finalized_at_height),
        );
        object.insert(
            "challenge_window_end_height".to_string(),
            json!(self.challenge_window_end_height),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn checkpoint_root(&self) -> String {
        l2_finality_checkpoint_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "checkpoint_root",
            self.checkpoint_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.checkpoint_id == l2_finality_checkpoint_id(&self.identity_record())
    }

    pub fn is_finalized(&self) -> bool {
        self.status == "final" && self.finalized_at_height > 0
    }

    pub fn validate(&self) -> FinalityResult<String> {
        ensure_non_empty(&self.block_hash, "L2 finality block hash")?;
        ensure_non_empty(&self.parent_block_hash, "L2 finality parent block hash")?;
        ensure_non_empty(&self.state_root, "L2 finality state root")?;
        ensure_non_empty(&self.tx_root, "L2 finality tx root")?;
        ensure_non_empty(&self.da_root, "L2 finality DA root")?;
        ensure_non_empty(&self.bridge_root, "L2 finality bridge root")?;
        ensure_non_empty(&self.validator_set_root, "L2 finality validator set root")?;
        ensure_non_empty(&self.consensus_root, "L2 finality consensus root")?;
        ensure_non_empty(&self.attestation_root, "L2 finality attestation root")?;
        ensure_bps(self.quorum_bps, "L2 finality quorum bps")?;
        if self.total_stake == 0 {
            return Err("L2 finality total stake must be positive".to_string());
        }
        if self.attested_stake > self.total_stake {
            return Err("L2 finality attested stake exceeds total stake".to_string());
        }
        if self.quorum_stake != finality_quorum_stake(self.total_stake, self.quorum_bps) {
            return Err("L2 finality quorum stake mismatch".to_string());
        }
        if self.challenge_window_end_height < self.opened_at_height {
            return Err("L2 finality challenge window is inverted".to_string());
        }
        ensure_status(
            &self.status,
            &[
                "pending",
                "soft",
                "final",
                "challenged",
                "reverted",
                "expired",
            ],
            "L2 finality checkpoint status",
        )?;
        if matches!(self.status.as_str(), "soft" | "final")
            && self.attested_stake < self.quorum_stake
        {
            return Err("L2 finality checkpoint lacks quorum stake".to_string());
        }
        if self.status == "final" && self.finalized_at_height == 0 {
            return Err("L2 finality final checkpoint requires finalized height".to_string());
        }
        if self.finalized_at_height > 0 && self.finalized_at_height < self.opened_at_height {
            return Err("L2 finality finalized height precedes open height".to_string());
        }
        if !self.verify_id() {
            return Err("L2 finality checkpoint id mismatch".to_string());
        }
        Ok(self.checkpoint_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAnchorFinality {
    pub anchor_finality_id: String,
    pub anchor_id: String,
    pub anchor_commitment: String,
    pub checkpoint_id: String,
    pub checkpoint_root: String,
    pub monero_txid_hash: String,
    pub monero_block_height: u64,
    pub monero_block_hash: String,
    pub confirmations: u64,
    pub finality_depth: u64,
    pub reorg_window_blocks: u64,
    pub observed_at_l2_height: u64,
    pub reorg_window_end_height: u64,
    pub finalized_at_l2_height: u64,
    pub observer_signature_root: String,
    pub status: String,
}

impl MoneroAnchorFinality {
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        anchor_id: impl Into<String>,
        anchor_commitment: impl Into<String>,
        checkpoint_id: impl Into<String>,
        checkpoint_root: impl Into<String>,
        monero_txid_hash: impl Into<String>,
        monero_block_height: u64,
        monero_block_hash: impl Into<String>,
        confirmations: u64,
        finality_depth: u64,
        reorg_window_blocks: u64,
        observed_at_l2_height: u64,
        observer_labels: &[String],
    ) -> FinalityResult<Self> {
        ensure_unique_strings(observer_labels, "Monero anchor observer label")?;
        let anchor_id = anchor_id.into();
        let anchor_commitment = anchor_commitment.into();
        let checkpoint_id = checkpoint_id.into();
        let checkpoint_root = checkpoint_root.into();
        let monero_txid_hash = monero_txid_hash.into();
        let monero_block_hash = monero_block_hash.into();
        let signature_payload = json!({
            "anchor_id": anchor_id,
            "anchor_commitment": anchor_commitment,
            "checkpoint_id": checkpoint_id,
            "checkpoint_root": checkpoint_root,
            "monero_txid_hash": monero_txid_hash,
            "monero_block_height": monero_block_height,
            "monero_block_hash": monero_block_hash,
            "confirmations": confirmations,
            "finality_depth": finality_depth,
        });
        let observer_signature_root = finality_observer_signature_root(
            "monero_anchor_finality",
            &signature_payload,
            observer_labels,
        );
        let status = if confirmations >= finality_depth {
            "final"
        } else {
            "observed"
        };
        let mut finality = Self {
            anchor_finality_id: String::new(),
            anchor_id,
            anchor_commitment,
            checkpoint_id,
            checkpoint_root,
            monero_txid_hash,
            monero_block_height,
            monero_block_hash,
            confirmations,
            finality_depth,
            reorg_window_blocks,
            observed_at_l2_height,
            reorg_window_end_height: observed_at_l2_height.saturating_add(reorg_window_blocks),
            finalized_at_l2_height: if status == "final" {
                observed_at_l2_height
            } else {
                0
            },
            observer_signature_root,
            status: status.to_string(),
        };
        finality.anchor_finality_id = monero_anchor_finality_id(&finality.identity_record());
        finality.validate()?;
        Ok(finality)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_anchor_finality_identity",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "anchor_id": self.anchor_id,
            "anchor_commitment": self.anchor_commitment,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_root": self.checkpoint_root,
            "monero_txid_hash": self.monero_txid_hash,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash": self.monero_block_hash,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("Monero anchor finality record object");
        object.insert(
            "kind".to_string(),
            Value::String("monero_anchor_finality".to_string()),
        );
        object.insert(
            "anchor_finality_id".to_string(),
            Value::String(self.anchor_finality_id.clone()),
        );
        object.insert("confirmations".to_string(), json!(self.confirmations));
        object.insert("finality_depth".to_string(), json!(self.finality_depth));
        object.insert(
            "reorg_window_blocks".to_string(),
            json!(self.reorg_window_blocks),
        );
        object.insert(
            "observed_at_l2_height".to_string(),
            json!(self.observed_at_l2_height),
        );
        object.insert(
            "reorg_window_end_height".to_string(),
            json!(self.reorg_window_end_height),
        );
        object.insert(
            "finalized_at_l2_height".to_string(),
            json!(self.finalized_at_l2_height),
        );
        object.insert(
            "observer_signature_root".to_string(),
            Value::String(self.observer_signature_root.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn finality_root(&self) -> String {
        monero_anchor_finality_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "anchor_finality_root",
            self.finality_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.anchor_finality_id == monero_anchor_finality_id(&self.identity_record())
    }

    pub fn is_final(&self) -> bool {
        self.status == "final" && self.confirmations >= self.finality_depth
    }

    pub fn validate(&self) -> FinalityResult<String> {
        ensure_non_empty(&self.anchor_id, "Monero anchor id")?;
        ensure_non_empty(&self.anchor_commitment, "Monero anchor commitment")?;
        ensure_non_empty(&self.checkpoint_id, "Monero anchor checkpoint id")?;
        ensure_non_empty(&self.checkpoint_root, "Monero anchor checkpoint root")?;
        ensure_non_empty(&self.monero_txid_hash, "Monero anchor txid hash")?;
        ensure_non_empty(&self.monero_block_hash, "Monero anchor block hash")?;
        ensure_non_empty(
            &self.observer_signature_root,
            "Monero anchor observer signature root",
        )?;
        if self.finality_depth == 0 {
            return Err("Monero anchor finality depth must be positive".to_string());
        }
        if self.reorg_window_blocks == 0 {
            return Err("Monero anchor reorg window must be positive".to_string());
        }
        if self.reorg_window_end_height
            != self
                .observed_at_l2_height
                .saturating_add(self.reorg_window_blocks)
        {
            return Err("Monero anchor reorg window end mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &["observed", "final", "challenged", "reorged", "rolled_back"],
            "Monero anchor finality status",
        )?;
        if self.status == "final" && self.confirmations < self.finality_depth {
            return Err("Monero anchor finality depth not met".to_string());
        }
        if self.status == "final" && self.finalized_at_l2_height == 0 {
            return Err("Monero anchor finality requires finalized L2 height".to_string());
        }
        if !self.verify_id() {
            return Err("Monero anchor finality id mismatch".to_string());
        }
        Ok(self.finality_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityReorgWindow {
    pub window_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub monero_txid_hash: String,
    pub canonical_block_height: u64,
    pub canonical_block_hash: String,
    pub observed_tip_height: u64,
    pub observed_tip_hash: String,
    pub confirmations_at_open: u64,
    pub reorg_window_blocks: u64,
    pub opened_at_l2_height: u64,
    pub closes_at_l2_height: u64,
    pub status: String,
}

impl FinalityReorgWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        monero_txid_hash: impl Into<String>,
        canonical_block_height: u64,
        canonical_block_hash: impl Into<String>,
        observed_tip_height: u64,
        observed_tip_hash: impl Into<String>,
        confirmations_at_open: u64,
        reorg_window_blocks: u64,
        opened_at_l2_height: u64,
    ) -> FinalityResult<Self> {
        let mut window = Self {
            window_id: String::new(),
            target_kind: target_kind.into(),
            target_id: target_id.into(),
            monero_txid_hash: monero_txid_hash.into(),
            canonical_block_height,
            canonical_block_hash: canonical_block_hash.into(),
            observed_tip_height,
            observed_tip_hash: observed_tip_hash.into(),
            confirmations_at_open,
            reorg_window_blocks,
            opened_at_l2_height,
            closes_at_l2_height: opened_at_l2_height.saturating_add(reorg_window_blocks),
            status: "open".to_string(),
        };
        window.window_id = finality_reorg_window_id(&window.identity_record());
        window.validate()?;
        Ok(window)
    }

    pub fn for_anchor(
        anchor: &MoneroAnchorFinality,
        observed_tip_height: u64,
        observed_tip_hash: impl Into<String>,
        opened_at_l2_height: u64,
    ) -> FinalityResult<Self> {
        Self::new(
            "monero_anchor",
            anchor.anchor_id.clone(),
            anchor.monero_txid_hash.clone(),
            anchor.monero_block_height,
            anchor.monero_block_hash.clone(),
            observed_tip_height,
            observed_tip_hash,
            anchor.confirmations,
            anchor.reorg_window_blocks,
            opened_at_l2_height,
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "finality_reorg_window_identity",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "monero_txid_hash": self.monero_txid_hash,
            "canonical_block_height": self.canonical_block_height,
            "canonical_block_hash": self.canonical_block_hash,
            "opened_at_l2_height": self.opened_at_l2_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("finality reorg window record object");
        object.insert(
            "kind".to_string(),
            Value::String("finality_reorg_window".to_string()),
        );
        object.insert(
            "window_id".to_string(),
            Value::String(self.window_id.clone()),
        );
        object.insert(
            "observed_tip_height".to_string(),
            json!(self.observed_tip_height),
        );
        object.insert(
            "observed_tip_hash".to_string(),
            Value::String(self.observed_tip_hash.clone()),
        );
        object.insert(
            "confirmations_at_open".to_string(),
            json!(self.confirmations_at_open),
        );
        object.insert(
            "reorg_window_blocks".to_string(),
            json!(self.reorg_window_blocks),
        );
        object.insert(
            "closes_at_l2_height".to_string(),
            json!(self.closes_at_l2_height),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn window_root(&self) -> String {
        finality_reorg_window_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "window_root",
            self.window_root(),
        )
    }

    pub fn contains_l2_height(&self, height: u64) -> bool {
        self.opened_at_l2_height <= height && height <= self.closes_at_l2_height
    }

    pub fn verify_id(&self) -> bool {
        self.window_id == finality_reorg_window_id(&self.identity_record())
    }

    pub fn validate(&self) -> FinalityResult<String> {
        ensure_non_empty(&self.target_kind, "reorg window target kind")?;
        ensure_non_empty(&self.target_id, "reorg window target id")?;
        ensure_non_empty(&self.monero_txid_hash, "reorg window txid hash")?;
        ensure_non_empty(
            &self.canonical_block_hash,
            "reorg window canonical block hash",
        )?;
        ensure_non_empty(&self.observed_tip_hash, "reorg window observed tip hash")?;
        if self.reorg_window_blocks == 0 {
            return Err("reorg window blocks must be positive".to_string());
        }
        if self.closes_at_l2_height
            != self
                .opened_at_l2_height
                .saturating_add(self.reorg_window_blocks)
        {
            return Err("reorg window close height mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &["open", "closed", "challenged", "expired"],
            "reorg window status",
        )?;
        if !self.verify_id() {
            return Err("reorg window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityChallenge {
    pub challenge_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub challenge_kind: String,
    pub challenger_label: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub resolved_at_height: u64,
    pub resolution_root: String,
    pub status: String,
}

impl FinalityChallenge {
    pub fn new(
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        challenge_kind: impl Into<String>,
        challenger_label: impl Into<String>,
        evidence_root: impl Into<String>,
        opened_at_height: u64,
        challenge_window_blocks: u64,
    ) -> FinalityResult<Self> {
        let mut challenge = Self {
            challenge_id: String::new(),
            target_kind: target_kind.into(),
            target_id: target_id.into(),
            challenge_kind: challenge_kind.into(),
            challenger_label: challenger_label.into(),
            evidence_root: evidence_root.into(),
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(challenge_window_blocks),
            resolved_at_height: 0,
            resolution_root: String::new(),
            status: "open".to_string(),
        };
        challenge.challenge_id = finality_challenge_id(&challenge.identity_record());
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn resolve(
        &self,
        status: impl Into<String>,
        resolved_at_height: u64,
        resolution: &Value,
    ) -> FinalityResult<Self> {
        let status = status.into();
        ensure_status(
            &status,
            &["upheld", "rejected", "expired", "resolved"],
            "finality challenge resolution status",
        )?;
        let challenge = Self {
            status,
            resolved_at_height,
            resolution_root: domain_hash(
                "FINALITY-CHALLENGE-RESOLUTION",
                &[HashPart::Json(resolution)],
                32,
            ),
            ..self.clone()
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "finality_challenge_identity",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "challenge_kind": self.challenge_kind,
            "challenger_label": self.challenger_label,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("finality challenge record object");
        object.insert(
            "kind".to_string(),
            Value::String("finality_challenge".to_string()),
        );
        object.insert(
            "challenge_id".to_string(),
            Value::String(self.challenge_id.clone()),
        );
        object.insert(
            "expires_at_height".to_string(),
            json!(self.expires_at_height),
        );
        object.insert(
            "resolved_at_height".to_string(),
            json!(self.resolved_at_height),
        );
        object.insert(
            "resolution_root".to_string(),
            Value::String(self.resolution_root.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn challenge_root(&self) -> String {
        finality_challenge_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "challenge_root",
            self.challenge_root(),
        )
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.status == "open" && self.opened_at_height <= height && height <= self.expires_at_height
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        self.status == "open" && height > self.expires_at_height
    }

    pub fn verify_id(&self) -> bool {
        self.challenge_id == finality_challenge_id(&self.identity_record())
    }

    pub fn validate(&self) -> FinalityResult<String> {
        ensure_non_empty(&self.target_kind, "finality challenge target kind")?;
        ensure_non_empty(&self.target_id, "finality challenge target id")?;
        ensure_non_empty(&self.challenge_kind, "finality challenge kind")?;
        ensure_non_empty(
            &self.challenger_label,
            "finality challenge challenger label",
        )?;
        ensure_non_empty(&self.evidence_root, "finality challenge evidence root")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("finality challenge window must extend beyond open height".to_string());
        }
        ensure_status(
            &self.status,
            &["open", "upheld", "rejected", "expired", "resolved"],
            "finality challenge status",
        )?;
        if self.status != "open" && self.resolved_at_height == 0 {
            return Err("finality challenge resolution height is required".to_string());
        }
        if self.status != "open" && self.resolution_root.is_empty() {
            return Err("finality challenge resolution root is required".to_string());
        }
        if !self.verify_id() {
            return Err("finality challenge id mismatch".to_string());
        }
        Ok(self.challenge_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalFinality {
    pub withdrawal_finality_id: String,
    pub withdrawal_id: String,
    pub release_txid_hash: String,
    pub amount_bucket: u64,
    pub recipient_address_hash: String,
    pub l2_release_height: u64,
    pub monero_block_height: u64,
    pub monero_block_hash: String,
    pub confirmations: u64,
    pub finality_depth: u64,
    pub challenge_opened_height: u64,
    pub challenge_expires_height: u64,
    pub challenge_root: String,
    pub finalized_at_l2_height: u64,
    pub status: String,
}

impl WithdrawalFinality {
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        withdrawal_id: impl Into<String>,
        release_txid_hash: impl Into<String>,
        amount_bucket: u64,
        recipient_address_hash: impl Into<String>,
        l2_release_height: u64,
        monero_block_height: u64,
        monero_block_hash: impl Into<String>,
        confirmations: u64,
        finality_depth: u64,
        challenge_opened_height: u64,
        challenge_window_blocks: u64,
    ) -> FinalityResult<Self> {
        let mut finality = Self {
            withdrawal_finality_id: String::new(),
            withdrawal_id: withdrawal_id.into(),
            release_txid_hash: release_txid_hash.into(),
            amount_bucket,
            recipient_address_hash: recipient_address_hash.into(),
            l2_release_height,
            monero_block_height,
            monero_block_hash: monero_block_hash.into(),
            confirmations,
            finality_depth,
            challenge_opened_height,
            challenge_expires_height: challenge_opened_height
                .saturating_add(challenge_window_blocks),
            challenge_root: merkle_root("FINALITY-WITHDRAWAL-CHALLENGE", &[]),
            finalized_at_l2_height: 0,
            status: if confirmations >= finality_depth {
                "challengeable"
            } else {
                "observed"
            }
            .to_string(),
        };
        finality.withdrawal_finality_id = withdrawal_finality_id(&finality.identity_record());
        finality.validate()?;
        Ok(finality)
    }

    pub fn with_challenge_root(&self, challenge_root: impl Into<String>) -> FinalityResult<Self> {
        let finality = Self {
            challenge_root: challenge_root.into(),
            status: "challenged".to_string(),
            ..self.clone()
        };
        finality.validate()?;
        Ok(finality)
    }

    pub fn finalize(&self, finalized_at_l2_height: u64) -> FinalityResult<Self> {
        if self.confirmations < self.finality_depth {
            return Err("withdrawal finality depth not met".to_string());
        }
        if finalized_at_l2_height < self.challenge_expires_height {
            return Err("withdrawal challenge window is still open".to_string());
        }
        let finality = Self {
            finalized_at_l2_height,
            status: "final".to_string(),
            ..self.clone()
        };
        finality.validate()?;
        Ok(finality)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "withdrawal_finality_identity",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "withdrawal_id": self.withdrawal_id,
            "release_txid_hash": self.release_txid_hash,
            "amount_bucket": self.amount_bucket,
            "recipient_address_hash": self.recipient_address_hash,
            "l2_release_height": self.l2_release_height,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash": self.monero_block_hash,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("withdrawal finality record object");
        object.insert(
            "kind".to_string(),
            Value::String("withdrawal_finality".to_string()),
        );
        object.insert(
            "withdrawal_finality_id".to_string(),
            Value::String(self.withdrawal_finality_id.clone()),
        );
        object.insert("confirmations".to_string(), json!(self.confirmations));
        object.insert("finality_depth".to_string(), json!(self.finality_depth));
        object.insert(
            "challenge_opened_height".to_string(),
            json!(self.challenge_opened_height),
        );
        object.insert(
            "challenge_expires_height".to_string(),
            json!(self.challenge_expires_height),
        );
        object.insert(
            "challenge_root".to_string(),
            Value::String(self.challenge_root.clone()),
        );
        object.insert(
            "finalized_at_l2_height".to_string(),
            json!(self.finalized_at_l2_height),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn finality_root(&self) -> String {
        withdrawal_finality_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "withdrawal_finality_root",
            self.finality_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.withdrawal_finality_id == withdrawal_finality_id(&self.identity_record())
    }

    pub fn is_final(&self) -> bool {
        self.status == "final" && self.finalized_at_l2_height >= self.challenge_expires_height
    }

    pub fn validate(&self) -> FinalityResult<String> {
        ensure_non_empty(&self.withdrawal_id, "withdrawal finality withdrawal id")?;
        ensure_non_empty(&self.release_txid_hash, "withdrawal finality txid hash")?;
        ensure_non_empty(
            &self.recipient_address_hash,
            "withdrawal finality recipient address hash",
        )?;
        ensure_non_empty(
            &self.monero_block_hash,
            "withdrawal finality Monero block hash",
        )?;
        ensure_non_empty(&self.challenge_root, "withdrawal finality challenge root")?;
        if self.amount_bucket == 0 {
            return Err("withdrawal finality amount bucket must be positive".to_string());
        }
        if self.finality_depth == 0 {
            return Err("withdrawal finality depth must be positive".to_string());
        }
        if self.challenge_expires_height <= self.challenge_opened_height {
            return Err("withdrawal challenge window must extend beyond open height".to_string());
        }
        ensure_status(
            &self.status,
            &[
                "observed",
                "challengeable",
                "challenged",
                "final",
                "reverted",
            ],
            "withdrawal finality status",
        )?;
        if self.status == "final" && self.confirmations < self.finality_depth {
            return Err("withdrawal finality confirmations below depth".to_string());
        }
        if self.status == "final" && self.finalized_at_l2_height < self.challenge_expires_height {
            return Err("withdrawal finalized before challenge window closed".to_string());
        }
        if !self.verify_id() {
            return Err("withdrawal finality id mismatch".to_string());
        }
        Ok(self.finality_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyRollbackEvidence {
    pub rollback_id: String,
    pub incident_kind: String,
    pub unsafe_checkpoint_id: String,
    pub unsafe_checkpoint_root: String,
    pub rollback_to_checkpoint_id: String,
    pub rollback_to_checkpoint_root: String,
    pub rollback_from_height: u64,
    pub rollback_to_height: u64,
    pub monero_reorg_evidence_root: String,
    pub challenge_root: String,
    pub manifest_root: String,
    pub reporter_labels: Vec<String>,
    pub reporter_root: String,
    pub total_stake: u64,
    pub attested_stake: u64,
    pub quorum_bps: u64,
    pub quorum_stake: u64,
    pub reported_at_height: u64,
    pub status: String,
}

impl EmergencyRollbackEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        incident_kind: impl Into<String>,
        unsafe_checkpoint_id: impl Into<String>,
        unsafe_checkpoint_root: impl Into<String>,
        rollback_to_checkpoint_id: impl Into<String>,
        rollback_to_checkpoint_root: impl Into<String>,
        rollback_from_height: u64,
        rollback_to_height: u64,
        monero_reorg_evidence_root: impl Into<String>,
        challenge_root: impl Into<String>,
        manifest_root: impl Into<String>,
        reporter_labels: &[String],
        total_stake: u64,
        attested_stake: u64,
        quorum_bps: u64,
        reported_at_height: u64,
    ) -> FinalityResult<Self> {
        ensure_unique_strings(reporter_labels, "rollback reporter label")?;
        let reporter_root = finality_string_root("FINALITY-ROLLBACK-REPORTER", reporter_labels);
        let quorum_stake = finality_quorum_stake(total_stake, quorum_bps);
        let mut evidence = Self {
            rollback_id: String::new(),
            incident_kind: incident_kind.into(),
            unsafe_checkpoint_id: unsafe_checkpoint_id.into(),
            unsafe_checkpoint_root: unsafe_checkpoint_root.into(),
            rollback_to_checkpoint_id: rollback_to_checkpoint_id.into(),
            rollback_to_checkpoint_root: rollback_to_checkpoint_root.into(),
            rollback_from_height,
            rollback_to_height,
            monero_reorg_evidence_root: monero_reorg_evidence_root.into(),
            challenge_root: challenge_root.into(),
            manifest_root: manifest_root.into(),
            reporter_labels: reporter_labels.to_vec(),
            reporter_root,
            total_stake,
            attested_stake,
            quorum_bps,
            quorum_stake,
            reported_at_height,
            status: if attested_stake >= quorum_stake {
                "accepted"
            } else {
                "pending"
            }
            .to_string(),
        };
        evidence.rollback_id = emergency_rollback_id(&evidence.identity_record());
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "emergency_rollback_evidence_identity",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "incident_kind": self.incident_kind,
            "unsafe_checkpoint_id": self.unsafe_checkpoint_id,
            "unsafe_checkpoint_root": self.unsafe_checkpoint_root,
            "rollback_to_checkpoint_id": self.rollback_to_checkpoint_id,
            "rollback_to_checkpoint_root": self.rollback_to_checkpoint_root,
            "rollback_from_height": self.rollback_from_height,
            "rollback_to_height": self.rollback_to_height,
            "monero_reorg_evidence_root": self.monero_reorg_evidence_root,
            "challenge_root": self.challenge_root,
            "manifest_root": self.manifest_root,
            "reporter_root": self.reporter_root,
            "reported_at_height": self.reported_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("emergency rollback evidence record object");
        object.insert(
            "kind".to_string(),
            Value::String("emergency_rollback_evidence".to_string()),
        );
        object.insert(
            "rollback_id".to_string(),
            Value::String(self.rollback_id.clone()),
        );
        object.insert("total_stake".to_string(), json!(self.total_stake));
        object.insert("attested_stake".to_string(), json!(self.attested_stake));
        object.insert("quorum_bps".to_string(), json!(self.quorum_bps));
        object.insert("quorum_stake".to_string(), json!(self.quorum_stake));
        object.insert(
            "reporter_count".to_string(),
            json!(self.reporter_labels.len() as u64),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn evidence_root(&self) -> String {
        emergency_rollback_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "rollback_evidence_root",
            self.evidence_root(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.rollback_id == emergency_rollback_id(&self.identity_record())
    }

    pub fn validate(&self) -> FinalityResult<String> {
        ensure_non_empty(&self.incident_kind, "rollback incident kind")?;
        ensure_non_empty(&self.unsafe_checkpoint_id, "rollback unsafe checkpoint id")?;
        ensure_non_empty(
            &self.unsafe_checkpoint_root,
            "rollback unsafe checkpoint root",
        )?;
        ensure_non_empty(
            &self.rollback_to_checkpoint_id,
            "rollback target checkpoint id",
        )?;
        ensure_non_empty(
            &self.rollback_to_checkpoint_root,
            "rollback target checkpoint root",
        )?;
        ensure_non_empty(
            &self.monero_reorg_evidence_root,
            "rollback Monero reorg evidence root",
        )?;
        ensure_non_empty(&self.challenge_root, "rollback challenge root")?;
        ensure_non_empty(&self.manifest_root, "rollback manifest root")?;
        ensure_unique_strings(&self.reporter_labels, "rollback reporter label")?;
        if self.rollback_to_height > self.rollback_from_height {
            return Err("rollback target height exceeds unsafe height".to_string());
        }
        if self.total_stake == 0 {
            return Err("rollback total stake must be positive".to_string());
        }
        ensure_bps(self.quorum_bps, "rollback quorum bps")?;
        if self.quorum_stake != finality_quorum_stake(self.total_stake, self.quorum_bps) {
            return Err("rollback quorum stake mismatch".to_string());
        }
        if self.attested_stake > self.total_stake {
            return Err("rollback attested stake exceeds total stake".to_string());
        }
        ensure_status(
            &self.status,
            &["pending", "accepted", "executed", "rejected"],
            "rollback evidence status",
        )?;
        if matches!(self.status.as_str(), "accepted" | "executed")
            && self.attested_stake < self.quorum_stake
        {
            return Err("rollback evidence lacks quorum stake".to_string());
        }
        if self.reporter_root
            != finality_string_root("FINALITY-ROLLBACK-REPORTER", &self.reporter_labels)
        {
            return Err("rollback reporter root mismatch".to_string());
        }
        if !self.verify_id() {
            return Err("rollback evidence id mismatch".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedRootManifestEntry {
    pub entry_id: String,
    pub sequence: u64,
    pub root_kind: String,
    pub root: String,
    pub source_id: String,
    pub source_height: u64,
    pub required: bool,
}

impl FinalizedRootManifestEntry {
    pub fn new(
        sequence: u64,
        root_kind: impl Into<String>,
        root: impl Into<String>,
        source_id: impl Into<String>,
        source_height: u64,
        required: bool,
    ) -> FinalityResult<Self> {
        let mut entry = Self {
            entry_id: String::new(),
            sequence,
            root_kind: root_kind.into(),
            root: root.into(),
            source_id: source_id.into(),
            source_height,
            required,
        };
        entry.entry_id = finalized_root_manifest_entry_id(&entry.identity_record());
        entry.validate()?;
        Ok(entry)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "finalized_root_manifest_entry_identity",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "sequence": self.sequence,
            "root_kind": self.root_kind,
            "root": self.root,
            "source_id": self.source_id,
            "source_height": self.source_height,
            "required": self.required,
        })
    }

    pub fn entry_root(&self) -> String {
        domain_hash(
            "FINALIZED-ROOT-MANIFEST-ENTRY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("finalized root manifest entry record object");
        object.insert(
            "kind".to_string(),
            Value::String("finalized_root_manifest_entry".to_string()),
        );
        object.insert("entry_id".to_string(), Value::String(self.entry_id.clone()));
        record
    }

    pub fn verify_id(&self) -> bool {
        self.entry_id == finalized_root_manifest_entry_id(&self.identity_record())
    }

    pub fn validate(&self) -> FinalityResult<String> {
        ensure_non_empty(&self.root_kind, "finalized manifest root kind")?;
        ensure_non_empty(&self.root, "finalized manifest root")?;
        ensure_non_empty(&self.source_id, "finalized manifest source id")?;
        if !self.verify_id() {
            return Err("finalized root manifest entry id mismatch".to_string());
        }
        Ok(self.entry_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedRootManifest {
    pub manifest_id: String,
    pub checkpoint_id: String,
    pub checkpoint_root: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub anchor_finality_root: String,
    pub withdrawal_finality_root: String,
    pub challenge_root: String,
    pub rollback_root: String,
    pub entries: Vec<FinalizedRootManifestEntry>,
    pub generated_at_height: u64,
    pub status: String,
}

impl FinalizedRootManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        checkpoint_id: impl Into<String>,
        checkpoint_root: impl Into<String>,
        block_height: u64,
        block_hash: impl Into<String>,
        state_root: impl Into<String>,
        anchor_finality_root: impl Into<String>,
        withdrawal_finality_root: impl Into<String>,
        challenge_root: impl Into<String>,
        rollback_root: impl Into<String>,
        entries: Vec<FinalizedRootManifestEntry>,
        generated_at_height: u64,
    ) -> FinalityResult<Self> {
        let mut manifest = Self {
            manifest_id: String::new(),
            checkpoint_id: checkpoint_id.into(),
            checkpoint_root: checkpoint_root.into(),
            block_height,
            block_hash: block_hash.into(),
            state_root: state_root.into(),
            anchor_finality_root: anchor_finality_root.into(),
            withdrawal_finality_root: withdrawal_finality_root.into(),
            challenge_root: challenge_root.into(),
            rollback_root: rollback_root.into(),
            entries,
            generated_at_height,
            status: "finalized".to_string(),
        };
        manifest.manifest_id = finalized_root_manifest_id(&manifest.identity_record());
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_checkpoint(
        checkpoint: &L2FinalityCheckpoint,
        state: &FinalityState,
        entries: Vec<FinalizedRootManifestEntry>,
        generated_at_height: u64,
    ) -> FinalityResult<Self> {
        Self::new(
            checkpoint.checkpoint_id.clone(),
            checkpoint.checkpoint_root(),
            checkpoint.height,
            checkpoint.block_hash.clone(),
            checkpoint.state_root.clone(),
            state.monero_anchor_finality_root(),
            state.withdrawal_finality_root(),
            state.challenge_root(),
            state.rollback_evidence_root(),
            entries,
            generated_at_height,
        )
    }

    pub fn entry_records(&self) -> Vec<Value> {
        let mut records = self
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.sequence,
                    entry.entry_id.clone(),
                    entry.public_record(),
                )
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        records.into_iter().map(|(_, _, record)| record).collect()
    }

    pub fn entry_root(&self) -> String {
        merkle_root("FINALIZED-ROOT-MANIFEST-ENTRY", &self.entry_records())
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "finalized_root_manifest_identity",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "checkpoint_root": self.checkpoint_root,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "anchor_finality_root": self.anchor_finality_root,
            "withdrawal_finality_root": self.withdrawal_finality_root,
            "challenge_root": self.challenge_root,
            "rollback_root": self.rollback_root,
            "entry_root": self.entry_root(),
            "entry_count": self.entries.len() as u64,
            "generated_at_height": self.generated_at_height,
            "status": self.status,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("finalized root manifest record object")
            .insert(
                "manifest_id".to_string(),
                Value::String(self.manifest_id.clone()),
            );
        record
    }

    pub fn manifest_root(&self) -> String {
        finalized_root_manifest_root(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = with_root_field(
            self.public_record_without_root(),
            "manifest_root",
            self.manifest_root(),
        );
        record
            .as_object_mut()
            .expect("finalized root manifest public record object")
            .insert("entries".to_string(), Value::Array(self.entry_records()));
        record
    }

    pub fn verify_id(&self) -> bool {
        self.manifest_id == finalized_root_manifest_id(&self.identity_record())
    }

    pub fn validate(&self) -> FinalityResult<String> {
        ensure_non_empty(&self.checkpoint_id, "finalized manifest checkpoint id")?;
        ensure_non_empty(&self.checkpoint_root, "finalized manifest checkpoint root")?;
        ensure_non_empty(&self.block_hash, "finalized manifest block hash")?;
        ensure_non_empty(&self.state_root, "finalized manifest state root")?;
        ensure_non_empty(
            &self.anchor_finality_root,
            "finalized manifest anchor finality root",
        )?;
        ensure_non_empty(
            &self.withdrawal_finality_root,
            "finalized manifest withdrawal finality root",
        )?;
        ensure_non_empty(&self.challenge_root, "finalized manifest challenge root")?;
        ensure_non_empty(&self.rollback_root, "finalized manifest rollback root")?;
        if self.entries.len() as u64 > FINALITY_MAX_MANIFEST_ENTRIES {
            return Err("finalized manifest entry limit exceeded".to_string());
        }
        let mut sequences = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            sequences.push(entry.sequence);
        }
        ensure_unique_u64(&sequences, "finalized manifest entry sequence")?;
        ensure_status(
            &self.status,
            &["finalized", "superseded", "rollback_reference"],
            "finalized manifest status",
        )?;
        if !self.verify_id() {
            return Err("finalized root manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityState {
    pub current_height: u64,
    pub parameters: FinalitySafetyParameters,
    pub validator_attestations: BTreeMap<String, ValidatorFinalityAttestation>,
    pub soft_checkpoints: BTreeMap<String, L2FinalityCheckpoint>,
    pub final_checkpoints: BTreeMap<String, L2FinalityCheckpoint>,
    pub monero_anchor_finalities: BTreeMap<String, MoneroAnchorFinality>,
    pub reorg_windows: BTreeMap<String, FinalityReorgWindow>,
    pub challenges: BTreeMap<String, FinalityChallenge>,
    pub withdrawal_finalities: BTreeMap<String, WithdrawalFinality>,
    pub emergency_rollbacks: BTreeMap<String, EmergencyRollbackEvidence>,
    pub finalized_manifests: BTreeMap<String, FinalizedRootManifest>,
}

impl Default for FinalityState {
    fn default() -> Self {
        Self::new(FinalitySafetyParameters::default())
    }
}

impl FinalityState {
    pub fn new(parameters: FinalitySafetyParameters) -> Self {
        Self {
            current_height: 0,
            parameters,
            validator_attestations: BTreeMap::new(),
            soft_checkpoints: BTreeMap::new(),
            final_checkpoints: BTreeMap::new(),
            monero_anchor_finalities: BTreeMap::new(),
            reorg_windows: BTreeMap::new(),
            challenges: BTreeMap::new(),
            withdrawal_finalities: BTreeMap::new(),
            emergency_rollbacks: BTreeMap::new(),
            finalized_manifests: BTreeMap::new(),
        }
    }

    pub fn set_current_height(&mut self, current_height: u64) -> FinalityResult<String> {
        self.current_height = current_height;
        Ok(self.state_root())
    }

    pub fn apply_parameters(
        &mut self,
        parameters: FinalitySafetyParameters,
    ) -> FinalityResult<String> {
        let root = parameters.validate()?;
        self.parameters = parameters;
        Ok(root)
    }

    pub fn apply_validator_attestation(
        &mut self,
        attestation: ValidatorFinalityAttestation,
    ) -> FinalityResult<String> {
        let root = attestation.validate()?;
        insert_unique_record(
            &mut self.validator_attestations,
            attestation.attestation_id.clone(),
            attestation,
            "validator finality attestation",
        )?;
        Ok(root)
    }

    pub fn apply_l2_checkpoint(
        &mut self,
        checkpoint: L2FinalityCheckpoint,
    ) -> FinalityResult<String> {
        let root = checkpoint.validate()?;
        let expected_quorum = checkpoint.checkpoint_kind.quorum_bps(&self.parameters);
        if checkpoint.quorum_bps != expected_quorum {
            return Err("L2 finality checkpoint quorum does not match parameters".to_string());
        }
        if checkpoint.challenge_window_end_height
            != checkpoint
                .opened_at_height
                .saturating_add(self.parameters.challenge_window_blocks)
        {
            return Err("L2 finality checkpoint challenge window mismatch".to_string());
        }
        if checkpoint.checkpoint_kind == FinalityCheckpointKind::Final {
            if let Some(latest) = self.latest_final_checkpoint() {
                if checkpoint.height < latest.height {
                    return Err(
                        "final checkpoint cannot regress without rollback evidence".to_string()
                    );
                }
            }
            insert_unique_record(
                &mut self.final_checkpoints,
                checkpoint.checkpoint_id.clone(),
                checkpoint,
                "final L2 checkpoint",
            )?;
        } else {
            insert_unique_record(
                &mut self.soft_checkpoints,
                checkpoint.checkpoint_id.clone(),
                checkpoint,
                "soft L2 checkpoint",
            )?;
        }
        Ok(root)
    }

    pub fn apply_monero_anchor_finality(
        &mut self,
        finality: MoneroAnchorFinality,
    ) -> FinalityResult<String> {
        let root = finality.validate()?;
        if finality.finality_depth != self.parameters.monero_finality_depth {
            return Err("Monero anchor finality depth does not match parameters".to_string());
        }
        if finality.reorg_window_blocks != self.parameters.reorg_window_blocks {
            return Err("Monero anchor reorg window does not match parameters".to_string());
        }
        if let Some(checkpoint) = self.checkpoint_by_id(&finality.checkpoint_id) {
            if checkpoint.checkpoint_root() != finality.checkpoint_root {
                return Err("Monero anchor checkpoint root mismatch".to_string());
            }
        }
        insert_unique_record(
            &mut self.monero_anchor_finalities,
            finality.anchor_finality_id.clone(),
            finality,
            "Monero anchor finality",
        )?;
        Ok(root)
    }

    pub fn apply_reorg_window(&mut self, window: FinalityReorgWindow) -> FinalityResult<String> {
        let root = window.validate()?;
        if window.target_kind == "monero_anchor"
            && !self
                .monero_anchor_finalities
                .values()
                .any(|anchor| anchor.anchor_id == window.target_id)
        {
            return Err("reorg window references unknown Monero anchor".to_string());
        }
        insert_unique_record(
            &mut self.reorg_windows,
            window.window_id.clone(),
            window,
            "finality reorg window",
        )?;
        Ok(root)
    }

    pub fn apply_challenge(&mut self, challenge: FinalityChallenge) -> FinalityResult<String> {
        let root = challenge.validate()?;
        if challenge.status == "open" && self.current_height > challenge.expires_at_height {
            return Err("cannot apply expired open finality challenge".to_string());
        }
        insert_unique_record(
            &mut self.challenges,
            challenge.challenge_id.clone(),
            challenge,
            "finality challenge",
        )?;
        Ok(root)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        status: impl Into<String>,
        resolved_at_height: u64,
        resolution: &Value,
    ) -> FinalityResult<String> {
        let challenge = self
            .challenges
            .get(challenge_id)
            .cloned()
            .ok_or_else(|| "finality challenge is missing".to_string())?
            .resolve(status, resolved_at_height, resolution)?;
        let root = challenge.challenge_root();
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(root)
    }

    pub fn apply_withdrawal_finality(
        &mut self,
        finality: WithdrawalFinality,
    ) -> FinalityResult<String> {
        let root = finality.validate()?;
        if finality.finality_depth != self.parameters.monero_finality_depth {
            return Err("withdrawal finality depth does not match parameters".to_string());
        }
        let expected_expires = finality
            .challenge_opened_height
            .saturating_add(self.parameters.withdrawal_challenge_window_blocks);
        if finality.challenge_expires_height != expected_expires {
            return Err("withdrawal finality challenge window mismatch".to_string());
        }
        if finality.status == "final" {
            if self.current_height < finality.challenge_expires_height {
                return Err("withdrawal challenge window is still open".to_string());
            }
            if self.has_open_challenge("withdrawal", &finality.withdrawal_id) {
                return Err("withdrawal has open finality challenge".to_string());
            }
        }
        self.withdrawal_finalities
            .insert(finality.withdrawal_finality_id.clone(), finality);
        Ok(root)
    }

    pub fn apply_emergency_rollback(
        &mut self,
        evidence: EmergencyRollbackEvidence,
    ) -> FinalityResult<String> {
        let root = evidence.validate()?;
        if evidence.quorum_bps != self.parameters.rollback_quorum_bps {
            return Err("rollback quorum does not match parameters".to_string());
        }
        if matches!(evidence.status.as_str(), "accepted" | "executed")
            && evidence.attested_stake < evidence.quorum_stake
        {
            return Err("rollback evidence lacks parameter quorum".to_string());
        }
        insert_unique_record(
            &mut self.emergency_rollbacks,
            evidence.rollback_id.clone(),
            evidence,
            "emergency rollback evidence",
        )?;
        Ok(root)
    }

    pub fn apply_finalized_manifest(
        &mut self,
        manifest: FinalizedRootManifest,
    ) -> FinalityResult<String> {
        let root = manifest.validate()?;
        if manifest.entries.len() as u64 > self.parameters.max_manifest_entries {
            return Err("finalized manifest exceeds state parameter entry limit".to_string());
        }
        if let Some(checkpoint) = self.checkpoint_by_id(&manifest.checkpoint_id) {
            if checkpoint.checkpoint_root() != manifest.checkpoint_root {
                return Err("finalized manifest checkpoint root mismatch".to_string());
            }
        }
        insert_unique_record(
            &mut self.finalized_manifests,
            manifest.manifest_id.clone(),
            manifest,
            "finalized root manifest",
        )?;
        Ok(root)
    }

    pub fn latest_final_checkpoint(&self) -> Option<&L2FinalityCheckpoint> {
        self.final_checkpoints.values().max_by(|left, right| {
            left.height
                .cmp(&right.height)
                .then(left.checkpoint_id.cmp(&right.checkpoint_id))
        })
    }

    pub fn checkpoint_by_id(&self, checkpoint_id: &str) -> Option<&L2FinalityCheckpoint> {
        self.final_checkpoints
            .get(checkpoint_id)
            .or_else(|| self.soft_checkpoints.get(checkpoint_id))
    }

    pub fn has_open_challenge(&self, target_kind: &str, target_id: &str) -> bool {
        self.challenges.values().any(|challenge| {
            challenge.target_kind == target_kind
                && challenge.target_id == target_id
                && challenge.is_open_at(self.current_height)
        })
    }

    pub fn validator_attestation_root(&self) -> String {
        validator_finality_attestation_root(
            &self
                .validator_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn soft_checkpoint_root(&self) -> String {
        l2_finality_checkpoint_set_root(
            "FINALITY-SOFT-CHECKPOINT",
            &self.soft_checkpoints.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn final_checkpoint_root(&self) -> String {
        l2_finality_checkpoint_set_root(
            "FINALITY-FINAL-CHECKPOINT",
            &self.final_checkpoints.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn monero_anchor_finality_root(&self) -> String {
        merkle_root(
            "FINALITY-MONERO-ANCHOR",
            &self
                .monero_anchor_finalities
                .values()
                .map(MoneroAnchorFinality::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn reorg_window_root(&self) -> String {
        merkle_root(
            "FINALITY-REORG-WINDOW",
            &self
                .reorg_windows
                .values()
                .map(FinalityReorgWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn challenge_root(&self) -> String {
        merkle_root(
            "FINALITY-CHALLENGE",
            &self
                .challenges
                .values()
                .map(FinalityChallenge::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn withdrawal_finality_root(&self) -> String {
        merkle_root(
            "FINALITY-WITHDRAWAL",
            &self
                .withdrawal_finalities
                .values()
                .map(WithdrawalFinality::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn rollback_evidence_root(&self) -> String {
        merkle_root(
            "FINALITY-ROLLBACK",
            &self
                .emergency_rollbacks
                .values()
                .map(EmergencyRollbackEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn finalized_manifest_root(&self) -> String {
        merkle_root(
            "FINALITY-ROOT-MANIFEST",
            &self
                .finalized_manifests
                .values()
                .map(FinalizedRootManifest::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "finality_state",
            "chain_id": CHAIN_ID,
            "finality_protocol_version": FINALITY_PROTOCOL_VERSION,
            "current_height": self.current_height,
            "parameters_root": self.parameters.parameters_root(),
            "validator_attestation_root": self.validator_attestation_root(),
            "soft_checkpoint_root": self.soft_checkpoint_root(),
            "final_checkpoint_root": self.final_checkpoint_root(),
            "monero_anchor_finality_root": self.monero_anchor_finality_root(),
            "reorg_window_root": self.reorg_window_root(),
            "challenge_root": self.challenge_root(),
            "withdrawal_finality_root": self.withdrawal_finality_root(),
            "rollback_evidence_root": self.rollback_evidence_root(),
            "finalized_manifest_root": self.finalized_manifest_root(),
            "validator_attestation_count": self.validator_attestations.len() as u64,
            "soft_checkpoint_count": self.soft_checkpoints.len() as u64,
            "final_checkpoint_count": self.final_checkpoints.len() as u64,
            "monero_anchor_finality_count": self.monero_anchor_finalities.len() as u64,
            "reorg_window_count": self.reorg_windows.len() as u64,
            "challenge_count": self.challenges.len() as u64,
            "withdrawal_finality_count": self.withdrawal_finalities.len() as u64,
            "rollback_evidence_count": self.emergency_rollbacks.len() as u64,
            "finalized_manifest_count": self.finalized_manifests.len() as u64,
            "latest_final_checkpoint_id": self.latest_final_checkpoint().map(|checkpoint| checkpoint.checkpoint_id.clone()),
            "latest_final_height": self.latest_final_checkpoint().map(|checkpoint| checkpoint.height).unwrap_or(0),
        })
    }

    pub fn state_root(&self) -> String {
        finality_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "finality_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> FinalityResult<String> {
        self.parameters.validate()?;
        for attestation in self.validator_attestations.values() {
            attestation.validate()?;
        }
        for checkpoint in self.soft_checkpoints.values() {
            checkpoint.validate()?;
            if checkpoint.checkpoint_kind != FinalityCheckpointKind::Soft {
                return Err("soft checkpoint map contains non-soft checkpoint".to_string());
            }
        }
        let mut finalized_blocks_by_height = BTreeMap::new();
        for checkpoint in self.final_checkpoints.values() {
            checkpoint.validate()?;
            if checkpoint.checkpoint_kind != FinalityCheckpointKind::Final {
                return Err("final checkpoint map contains non-final checkpoint".to_string());
            }
            if let Some(existing_hash) =
                finalized_blocks_by_height.insert(checkpoint.height, checkpoint.block_hash.clone())
            {
                if existing_hash != checkpoint.block_hash {
                    return Err(
                        "conflicting final checkpoints exist at the same height".to_string()
                    );
                }
            }
        }
        for finality in self.monero_anchor_finalities.values() {
            finality.validate()?;
        }
        for window in self.reorg_windows.values() {
            window.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        for finality in self.withdrawal_finalities.values() {
            finality.validate()?;
        }
        for rollback in self.emergency_rollbacks.values() {
            rollback.validate()?;
        }
        for manifest in self.finalized_manifests.values() {
            manifest.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn finality_quorum_stake(total_stake: u64, quorum_bps: u64) -> u64 {
    if total_stake == 0 {
        0
    } else {
        total_stake.saturating_mul(quorum_bps).div_ceil(10_000)
    }
}

pub fn finality_parameters_root(record: &Value) -> String {
    domain_hash("FINALITY-PARAMETERS", &[HashPart::Json(record)], 32)
}

pub fn finality_state_root_from_record(record: &Value) -> String {
    domain_hash("FINALITY-STATE", &[HashPart::Json(record)], 32)
}

pub fn l2_finality_checkpoint_id(record: &Value) -> String {
    domain_hash("L2-FINALITY-CHECKPOINT-ID", &[HashPart::Json(record)], 32)
}

pub fn l2_finality_checkpoint_root(record: &Value) -> String {
    domain_hash("L2-FINALITY-CHECKPOINT", &[HashPart::Json(record)], 32)
}

pub fn l2_finality_checkpoint_set_root(
    domain: &str,
    checkpoints: &[L2FinalityCheckpoint],
) -> String {
    merkle_root(
        domain,
        &checkpoints
            .iter()
            .map(L2FinalityCheckpoint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn validator_finality_attestation_id(record: &Value) -> String {
    domain_hash(
        "VALIDATOR-FINALITY-ATTESTATION-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn validator_finality_signature_root(
    payload: &Value,
    validator_label: &str,
    consensus_public_key: &str,
) -> String {
    domain_hash(
        "VALIDATOR-FINALITY-SIGNATURE",
        &[
            HashPart::Json(payload),
            HashPart::Str(validator_label),
            HashPart::Str(consensus_public_key),
        ],
        32,
    )
}

pub fn validator_finality_attestation_root(
    attestations: &[ValidatorFinalityAttestation],
) -> String {
    let mut records = attestations
        .iter()
        .map(|attestation| {
            (
                attestation.block_height,
                attestation.validator_id.clone(),
                attestation.public_record(),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    merkle_root(
        "VALIDATOR-FINALITY-ATTESTATION",
        &records
            .into_iter()
            .map(|(_, _, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn monero_anchor_finality_id(record: &Value) -> String {
    domain_hash("MONERO-ANCHOR-FINALITY-ID", &[HashPart::Json(record)], 32)
}

pub fn monero_anchor_finality_root(record: &Value) -> String {
    domain_hash("MONERO-ANCHOR-FINALITY", &[HashPart::Json(record)], 32)
}

pub fn finality_reorg_window_id(record: &Value) -> String {
    domain_hash("FINALITY-REORG-WINDOW-ID", &[HashPart::Json(record)], 32)
}

pub fn finality_reorg_window_root(record: &Value) -> String {
    domain_hash("FINALITY-REORG-WINDOW", &[HashPart::Json(record)], 32)
}

pub fn finality_challenge_id(record: &Value) -> String {
    domain_hash("FINALITY-CHALLENGE-ID", &[HashPart::Json(record)], 32)
}

pub fn finality_challenge_root(record: &Value) -> String {
    domain_hash("FINALITY-CHALLENGE", &[HashPart::Json(record)], 32)
}

pub fn withdrawal_finality_id(record: &Value) -> String {
    domain_hash("WITHDRAWAL-FINALITY-ID", &[HashPart::Json(record)], 32)
}

pub fn withdrawal_finality_root(record: &Value) -> String {
    domain_hash("WITHDRAWAL-FINALITY", &[HashPart::Json(record)], 32)
}

pub fn emergency_rollback_id(record: &Value) -> String {
    domain_hash("EMERGENCY-ROLLBACK-ID", &[HashPart::Json(record)], 32)
}

pub fn emergency_rollback_root(record: &Value) -> String {
    domain_hash("EMERGENCY-ROLLBACK", &[HashPart::Json(record)], 32)
}

pub fn finalized_root_manifest_entry_id(record: &Value) -> String {
    domain_hash(
        "FINALIZED-ROOT-MANIFEST-ENTRY-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn finalized_root_manifest_id(record: &Value) -> String {
    domain_hash("FINALIZED-ROOT-MANIFEST-ID", &[HashPart::Json(record)], 32)
}

pub fn finalized_root_manifest_root(record: &Value) -> String {
    domain_hash("FINALIZED-ROOT-MANIFEST", &[HashPart::Json(record)], 32)
}

pub fn finality_txid_hash(txid: &str) -> String {
    domain_hash("FINALITY-TXID-HASH", &[HashPart::Str(txid)], 32)
}

pub fn finality_address_hash(address: &str) -> String {
    domain_hash("FINALITY-ADDRESS-HASH", &[HashPart::Str(address)], 32)
}

pub fn finality_string_root(domain: &str, values: &[String]) -> String {
    let mut leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    leaves.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    merkle_root(domain, &leaves)
}

pub fn finality_observer_signature_root(
    event_kind: &str,
    payload: &Value,
    observer_labels: &[String],
) -> String {
    domain_hash(
        "FINALITY-OBSERVER-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Json(payload),
            HashPart::Str(&finality_string_root("FINALITY-OBSERVER", observer_labels)),
        ],
        32,
    )
}

fn checkpoint_attested_stake(
    checkpoint_kind: FinalityCheckpointKind,
    height: u64,
    block_hash: &str,
    state_root: &str,
    attestations: &[ValidatorFinalityAttestation],
) -> FinalityResult<(u64, u64)> {
    let mut seen = BTreeSet::new();
    let mut attested_stake = 0_u64;
    for attestation in attestations {
        attestation.validate()?;
        if attestation.checkpoint_kind != checkpoint_kind
            || attestation.block_height != height
            || attestation.block_hash != block_hash
            || attestation.state_root != state_root
        {
            return Err("checkpoint attestation target mismatch".to_string());
        }
        if seen.insert(attestation.validator_id.clone()) {
            attested_stake = attested_stake.saturating_add(attestation.stake_weight);
        }
    }
    Ok((attested_stake, seen.len() as u64))
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    record
        .as_object_mut()
        .expect("rooted public record object")
        .insert(field.to_string(), Value::String(root));
    record
}

fn ensure_non_empty(value: &str, label: &str) -> FinalityResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_status(status: &str, allowed: &[&str], label: &str) -> FinalityResult<()> {
    if allowed.contains(&status) {
        Ok(())
    } else {
        Err(format!("{label} is invalid"))
    }
}

fn ensure_bps(value: u64, label: &str) -> FinalityResult<()> {
    if value == 0 || value > 10_000 {
        Err(format!("{label} must be between 1 and 10000"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> FinalityResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn ensure_unique_u64(values: &[u64], label: &str) -> FinalityResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn insert_unique_record<T>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> FinalityResult<()> {
    if map.contains_key(&key) {
        return Err(format!("{label} already exists"));
    }
    map.insert(key, value);
    Ok(())
}
