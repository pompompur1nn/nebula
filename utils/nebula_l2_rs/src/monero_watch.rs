use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroWatchResult<T> = Result<T, String>;

pub const MONERO_WATCH_PROTOCOL_VERSION: &str = "nebula-monero-watch-v1";
pub const MONERO_WATCH_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_WATCH_DEFAULT_ENDPOINT_QUORUM: u64 = 2;
pub const MONERO_WATCH_DEFAULT_OBSERVER_QUORUM: u64 = 2;
pub const MONERO_WATCH_DEFAULT_FINALITY_DEPTH: u64 = 10;
pub const MONERO_WATCH_DEFAULT_SOFT_CONFIRMATIONS: u64 = 3;
pub const MONERO_WATCH_DEFAULT_REORG_ALERT_DEPTH: u64 = 2;
pub const MONERO_WATCH_DEFAULT_UNLOCK_MARGIN_BLOCKS: u64 = 1;
pub const MONERO_WATCH_DEFAULT_STUCK_WITHDRAWAL_BLOCKS: u64 = 20;
pub const MONERO_WATCH_DEFAULT_ENDPOINT_LAG_BLOCKS: u64 = 4;
pub const MONERO_WATCH_AMOUNT_BUCKET: u64 = 10_000;
pub const MONERO_WATCH_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MoneroTxKind {
    Deposit,
    Withdrawal,
    Anchor,
    ReserveProof,
    Change,
    Unknown,
}

impl MoneroTxKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
            Self::Anchor => "anchor",
            Self::ReserveProof => "reserve_proof",
            Self::Change => "change",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MoneroBridgeEventKind {
    DepositObserved,
    WithdrawalQueued,
    WithdrawalSubmitted,
    WithdrawalFinalized,
    AnchorSubmitted,
    ReserveReported,
    ReorgRecovery,
}

impl MoneroBridgeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositObserved => "deposit_observed",
            Self::WithdrawalQueued => "withdrawal_queued",
            Self::WithdrawalSubmitted => "withdrawal_submitted",
            Self::WithdrawalFinalized => "withdrawal_finalized",
            Self::AnchorSubmitted => "anchor_submitted",
            Self::ReserveReported => "reserve_reported",
            Self::ReorgRecovery => "reorg_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MoneroReorgAlertKind {
    BlockConflict,
    TxMoved,
    TxDropped,
    FinalizedConflict,
}

impl MoneroReorgAlertKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockConflict => "block_conflict",
            Self::TxMoved => "tx_moved",
            Self::TxDropped => "tx_dropped",
            Self::FinalizedConflict => "finalized_conflict",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MoneroWatchSeverity {
    Info,
    Watch,
    Critical,
}

impl MoneroWatchSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchParameters {
    pub endpoint_quorum: u64,
    pub observer_quorum: u64,
    pub finality_depth: u64,
    pub soft_confirmations: u64,
    pub reorg_alert_depth: u64,
    pub unlock_margin_blocks: u64,
    pub stuck_withdrawal_blocks: u64,
    pub max_endpoint_lag_blocks: u64,
}

impl Default for MoneroWatchParameters {
    fn default() -> Self {
        Self {
            endpoint_quorum: MONERO_WATCH_DEFAULT_ENDPOINT_QUORUM,
            observer_quorum: MONERO_WATCH_DEFAULT_OBSERVER_QUORUM,
            finality_depth: MONERO_WATCH_DEFAULT_FINALITY_DEPTH,
            soft_confirmations: MONERO_WATCH_DEFAULT_SOFT_CONFIRMATIONS,
            reorg_alert_depth: MONERO_WATCH_DEFAULT_REORG_ALERT_DEPTH,
            unlock_margin_blocks: MONERO_WATCH_DEFAULT_UNLOCK_MARGIN_BLOCKS,
            stuck_withdrawal_blocks: MONERO_WATCH_DEFAULT_STUCK_WITHDRAWAL_BLOCKS,
            max_endpoint_lag_blocks: MONERO_WATCH_DEFAULT_ENDPOINT_LAG_BLOCKS,
        }
    }
}

impl MoneroWatchParameters {
    pub fn validate(&self) -> MoneroWatchResult<()> {
        if self.endpoint_quorum == 0 {
            return Err("monero watch endpoint quorum must be positive".to_string());
        }
        if self.observer_quorum == 0 {
            return Err("monero watch observer quorum must be positive".to_string());
        }
        if self.finality_depth == 0 {
            return Err("monero watch finality depth must be positive".to_string());
        }
        if self.soft_confirmations > self.finality_depth {
            return Err("monero watch soft confirmations cannot exceed finality depth".to_string());
        }
        if self.stuck_withdrawal_blocks == 0 {
            return Err("monero watch stuck withdrawal window must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_watch_parameters",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "endpoint_quorum": self.endpoint_quorum,
            "observer_quorum": self.observer_quorum,
            "finality_depth": self.finality_depth,
            "soft_confirmations": self.soft_confirmations,
            "reorg_alert_depth": self.reorg_alert_depth,
            "unlock_margin_blocks": self.unlock_margin_blocks,
            "stuck_withdrawal_blocks": self.stuck_withdrawal_blocks,
            "max_endpoint_lag_blocks": self.max_endpoint_lag_blocks,
        })
    }

    pub fn parameters_root(&self) -> String {
        monero_watch_payload_root("MONERO-WATCH-PARAMETERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroDaemonEndpoint {
    pub endpoint_id: String,
    pub operator_label: String,
    pub network: String,
    pub endpoint_commitment: String,
    pub rpc_route_commitment: String,
    pub zmq_route_commitment: String,
    pub view_key_commitment: String,
    pub advertised_height: u64,
    pub last_observed_height: u64,
    pub lag_blocks: u64,
    pub reliability_bps: u64,
    pub status: String,
}

impl MoneroDaemonEndpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_label: &str,
        network: &str,
        rpc_route: &str,
        zmq_route: &str,
        view_key_label: &str,
        advertised_height: u64,
        reliability_bps: u64,
    ) -> MoneroWatchResult<Self> {
        ensure_non_empty(operator_label, "monero endpoint operator label")?;
        ensure_non_empty(network, "monero endpoint network")?;
        ensure_non_empty(rpc_route, "monero endpoint rpc route")?;
        let rpc_route_commitment = monero_watch_string_root("MONERO-WATCH-RPC-ROUTE", rpc_route);
        let zmq_route_commitment = monero_watch_string_root("MONERO-WATCH-ZMQ-ROUTE", zmq_route);
        let view_key_commitment = monero_watch_string_root("MONERO-WATCH-VIEW-KEY", view_key_label);
        let endpoint_commitment = monero_endpoint_commitment(
            operator_label,
            network,
            &rpc_route_commitment,
            &zmq_route_commitment,
            &view_key_commitment,
        );
        let endpoint_id = monero_daemon_endpoint_id(
            operator_label,
            network,
            &endpoint_commitment,
            advertised_height,
        );
        Ok(Self {
            endpoint_id,
            operator_label: operator_label.to_string(),
            network: network.to_string(),
            endpoint_commitment,
            rpc_route_commitment,
            zmq_route_commitment,
            view_key_commitment,
            advertised_height,
            last_observed_height: advertised_height,
            lag_blocks: 0,
            reliability_bps: reliability_bps.min(MONERO_WATCH_MAX_BPS),
            status: "active".to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_daemon_endpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "endpoint_id": self.endpoint_id,
            "operator_label": self.operator_label,
            "network": self.network,
            "endpoint_commitment": self.endpoint_commitment,
            "rpc_route_commitment": self.rpc_route_commitment,
            "zmq_route_commitment": self.zmq_route_commitment,
            "view_key_commitment": self.view_key_commitment,
            "advertised_height": self.advertised_height,
            "last_observed_height": self.last_observed_height,
            "lag_blocks": self.lag_blocks,
            "reliability_bps": self.reliability_bps,
            "status": self.status,
        })
    }

    pub fn endpoint_root(&self) -> String {
        monero_watch_payload_root("MONERO-WATCH-DAEMON-ENDPOINT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroEndpointQuorum {
    pub quorum_id: String,
    pub network: String,
    pub height: u64,
    pub endpoint_root: String,
    pub advertised_height_root: String,
    pub active_endpoint_count: u64,
    pub quorum_required: u64,
    pub max_lag_blocks: u64,
    pub median_advertised_height: u64,
    pub status: String,
}

impl MoneroEndpointQuorum {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_endpoint_quorum",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "quorum_id": self.quorum_id,
            "network": self.network,
            "height": self.height,
            "endpoint_root": self.endpoint_root,
            "advertised_height_root": self.advertised_height_root,
            "active_endpoint_count": self.active_endpoint_count,
            "quorum_required": self.quorum_required,
            "max_lag_blocks": self.max_lag_blocks,
            "median_advertised_height": self.median_advertised_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroObserverAttestation {
    pub attestation_id: String,
    pub observer_label: String,
    pub observer_public_key: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub endpoint_id: Option<String>,
    pub attested_at_height: u64,
    pub signature_root: String,
    pub status: String,
}

impl MoneroObserverAttestation {
    pub fn new(
        observer_label: &str,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        endpoint_id: Option<String>,
        attested_at_height: u64,
    ) -> MoneroWatchResult<Self> {
        ensure_non_empty(observer_label, "monero observer label")?;
        ensure_non_empty(subject_kind, "monero attestation subject kind")?;
        ensure_non_empty(subject_id, "monero attestation subject id")?;
        ensure_non_empty(subject_root, "monero attestation subject root")?;
        let observer_public_key = monero_watch_observer_public_key(observer_label);
        let attestation_id = monero_observer_attestation_id(
            observer_label,
            subject_kind,
            subject_id,
            subject_root,
            attested_at_height,
        );
        let signature_root = monero_observer_signature_root(
            observer_label,
            &observer_public_key,
            subject_kind,
            subject_id,
            subject_root,
            attested_at_height,
        );
        Ok(Self {
            attestation_id,
            observer_label: observer_label.to_string(),
            observer_public_key,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            endpoint_id,
            attested_at_height,
            signature_root,
            status: "accepted".to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_observer_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "observer_label": self.observer_label,
            "observer_public_key": self.observer_public_key,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "endpoint_id": self.endpoint_id,
            "attested_at_height": self.attested_at_height,
            "signature_root": self.signature_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBlockObservation {
    pub observation_id: String,
    pub endpoint_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub tx_count: u64,
    pub tx_root: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub difficulty_root: String,
    pub observed_tip_height: u64,
    pub confirmations: u64,
    pub observed_at_l2_height: u64,
    pub observer_label: String,
    pub attestation_id: String,
    pub status: String,
}

impl MoneroBlockObservation {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_block_observation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "endpoint_id": self.endpoint_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "previous_block_hash": self.previous_block_hash,
            "tx_count": self.tx_count,
            "tx_root": self.tx_root,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "difficulty_root": self.difficulty_root,
            "observed_tip_height": self.observed_tip_height,
            "confirmations": self.confirmations,
            "observed_at_l2_height": self.observed_at_l2_height,
            "observer_label": self.observer_label,
        })
    }

    pub fn observation_root(&self) -> String {
        monero_watch_payload_root("MONERO-WATCH-BLOCK-OBSERVATION", &self.identity_record())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("monero block observation record object");
        object.insert(
            "kind".to_string(),
            Value::String("monero_block_observation".to_string()),
        );
        object.insert(
            "attestation_id".to_string(),
            Value::String(self.attestation_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "observation_root".to_string(),
            Value::String(self.observation_root()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBlockReconciliation {
    pub reconciliation_id: String,
    pub block_height: u64,
    pub canonical_block_hash: String,
    pub canonical_previous_block_hash: String,
    pub canonical_tx_root: String,
    pub observation_root: String,
    pub endpoint_vote_root: String,
    pub endpoint_vote_count: u64,
    pub dissenting_vote_count: u64,
    pub quorum_required: u64,
    pub confirmations: u64,
    pub reconciled_at_l2_height: u64,
    pub status: String,
}

impl MoneroBlockReconciliation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_block_reconciliation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "reconciliation_id": self.reconciliation_id,
            "block_height": self.block_height,
            "canonical_block_hash": self.canonical_block_hash,
            "canonical_previous_block_hash": self.canonical_previous_block_hash,
            "canonical_tx_root": self.canonical_tx_root,
            "observation_root": self.observation_root,
            "endpoint_vote_root": self.endpoint_vote_root,
            "endpoint_vote_count": self.endpoint_vote_count,
            "dissenting_vote_count": self.dissenting_vote_count,
            "quorum_required": self.quorum_required,
            "confirmations": self.confirmations,
            "reconciled_at_l2_height": self.reconciled_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroTxObservation {
    pub observation_id: String,
    pub txid_hash: String,
    pub tx_kind: MoneroTxKind,
    pub endpoint_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub output_index: u64,
    pub amount_bucket: u64,
    pub recipient_commitment: String,
    pub payment_id_root: String,
    pub ring_member_root: String,
    pub output_commitment: String,
    pub key_image_root: String,
    pub unlock_height: u64,
    pub observed_tip_height: u64,
    pub confirmations: u64,
    pub observed_at_l2_height: u64,
    pub observer_label: String,
    pub attestation_id: String,
    pub status: String,
}

impl MoneroTxObservation {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_tx_observation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "txid_hash": self.txid_hash,
            "tx_kind": self.tx_kind.as_str(),
            "endpoint_id": self.endpoint_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "output_index": self.output_index,
            "amount_bucket": self.amount_bucket,
            "recipient_commitment": self.recipient_commitment,
            "payment_id_root": self.payment_id_root,
            "ring_member_root": self.ring_member_root,
            "output_commitment": self.output_commitment,
            "key_image_root": self.key_image_root,
            "unlock_height": self.unlock_height,
            "observed_tip_height": self.observed_tip_height,
            "confirmations": self.confirmations,
            "observed_at_l2_height": self.observed_at_l2_height,
            "observer_label": self.observer_label,
        })
    }

    pub fn observation_root(&self) -> String {
        monero_watch_payload_root("MONERO-WATCH-TX-OBSERVATION", &self.identity_record())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("monero tx observation record object");
        object.insert(
            "kind".to_string(),
            Value::String("monero_tx_observation".to_string()),
        );
        object.insert(
            "attestation_id".to_string(),
            Value::String(self.attestation_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "observation_root".to_string(),
            Value::String(self.observation_root()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroTxReconciliation {
    pub reconciliation_id: String,
    pub txid_hash: String,
    pub tx_kind: MoneroTxKind,
    pub canonical_block_height: u64,
    pub canonical_block_hash: String,
    pub canonical_output_commitment: String,
    pub observation_root: String,
    pub output_proof_root: String,
    pub watchlist_hit_root: String,
    pub bridge_event_match_root: String,
    pub observer_count: u64,
    pub quorum_required: u64,
    pub confirmations: u64,
    pub reconciled_at_l2_height: u64,
    pub status: String,
}

impl MoneroTxReconciliation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_tx_reconciliation",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "reconciliation_id": self.reconciliation_id,
            "txid_hash": self.txid_hash,
            "tx_kind": self.tx_kind.as_str(),
            "canonical_block_height": self.canonical_block_height,
            "canonical_block_hash": self.canonical_block_hash,
            "canonical_output_commitment": self.canonical_output_commitment,
            "observation_root": self.observation_root,
            "output_proof_root": self.output_proof_root,
            "watchlist_hit_root": self.watchlist_hit_root,
            "bridge_event_match_root": self.bridge_event_match_root,
            "observer_count": self.observer_count,
            "quorum_required": self.quorum_required,
            "confirmations": self.confirmations,
            "reconciled_at_l2_height": self.reconciled_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroOutputProofCommitment {
    pub proof_id: String,
    pub txid_hash: String,
    pub output_index: u64,
    pub output_commitment: String,
    pub one_time_address_hash: String,
    pub amount_commitment: String,
    pub view_tag_commitment: String,
    pub encrypted_mask_root: String,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub proof_payload_root: String,
    pub observer_attestation_root: String,
    pub status: String,
}

impl MoneroOutputProofCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_output_proof_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "txid_hash": self.txid_hash,
            "output_index": self.output_index,
            "output_commitment": self.output_commitment,
            "one_time_address_hash": self.one_time_address_hash,
            "amount_commitment": self.amount_commitment,
            "view_tag_commitment": self.view_tag_commitment,
            "encrypted_mask_root": self.encrypted_mask_root,
            "proof_system": self.proof_system,
            "verifier_key_root": self.verifier_key_root,
            "proof_payload_root": self.proof_payload_root,
            "observer_attestation_root": self.observer_attestation_root,
            "status": self.status,
        })
    }

    pub fn proof_root(&self) -> String {
        monero_watch_payload_root("MONERO-WATCH-OUTPUT-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroKeyImageWatch {
    pub watch_id: String,
    pub key_image_hash: String,
    pub purpose: String,
    pub linked_withdrawal_id: Option<String>,
    pub first_seen_txid_hash: Option<String>,
    pub first_seen_height: u64,
    pub last_seen_height: u64,
    pub observer_attestation_root: String,
    pub status: String,
}

impl MoneroKeyImageWatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_key_image_watch",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "watch_id": self.watch_id,
            "key_image_hash": self.key_image_hash,
            "purpose": self.purpose,
            "linked_withdrawal_id": self.linked_withdrawal_id,
            "first_seen_txid_hash": self.first_seen_txid_hash,
            "first_seen_height": self.first_seen_height,
            "last_seen_height": self.last_seen_height,
            "observer_attestation_root": self.observer_attestation_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroNullifierWatch {
    pub watch_id: String,
    pub nullifier_hash: String,
    pub spend_domain: String,
    pub bridge_event_id: Option<String>,
    pub linked_withdrawal_id: Option<String>,
    pub opened_at_height: u64,
    pub spent_at_height: u64,
    pub matched_key_image_watch_id: Option<String>,
    pub status: String,
}

impl MoneroNullifierWatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_nullifier_watch",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "watch_id": self.watch_id,
            "nullifier_hash": self.nullifier_hash,
            "spend_domain": self.spend_domain,
            "bridge_event_id": self.bridge_event_id,
            "linked_withdrawal_id": self.linked_withdrawal_id,
            "opened_at_height": self.opened_at_height,
            "spent_at_height": self.spent_at_height,
            "matched_key_image_watch_id": self.matched_key_image_watch_id,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroUnlockWindow {
    pub window_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub txid_hash: String,
    pub block_height: u64,
    pub unlock_height: u64,
    pub finality_height: u64,
    pub spendable_at_height: u64,
    pub expires_at_height: u64,
    pub current_height: u64,
    pub confirmations: u64,
    pub required_confirmations: u64,
    pub status: String,
}

impl MoneroUnlockWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_unlock_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "txid_hash": self.txid_hash,
            "block_height": self.block_height,
            "unlock_height": self.unlock_height,
            "finality_height": self.finality_height,
            "spendable_at_height": self.spendable_at_height,
            "expires_at_height": self.expires_at_height,
            "current_height": self.current_height,
            "confirmations": self.confirmations,
            "required_confirmations": self.required_confirmations,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFinalityWindow {
    pub window_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub start_height: u64,
    pub soft_final_height: u64,
    pub hard_final_height: u64,
    pub challenge_deadline_height: u64,
    pub current_height: u64,
    pub status: String,
}

impl MoneroFinalityWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_finality_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "start_height": self.start_height,
            "soft_final_height": self.soft_final_height,
            "hard_final_height": self.hard_final_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "current_height": self.current_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReorgAlert {
    pub alert_id: String,
    pub alert_kind: MoneroReorgAlertKind,
    pub old_block_height: u64,
    pub old_block_hash: String,
    pub new_block_height: u64,
    pub new_block_hash: String,
    pub txid_hash: Option<String>,
    pub depth: u64,
    pub detected_at_height: u64,
    pub affected_subject_root: String,
    pub observer_attestation_root: String,
    pub severity: MoneroWatchSeverity,
    pub status: String,
}

impl MoneroReorgAlert {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_reorg_alert",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "alert_id": self.alert_id,
            "alert_kind": self.alert_kind.as_str(),
            "old_block_height": self.old_block_height,
            "old_block_hash": self.old_block_hash,
            "new_block_height": self.new_block_height,
            "new_block_hash": self.new_block_hash,
            "txid_hash": self.txid_hash,
            "depth": self.depth,
            "detected_at_height": self.detected_at_height,
            "affected_subject_root": self.affected_subject_root,
            "observer_attestation_root": self.observer_attestation_root,
            "severity": self.severity.as_str(),
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroStuckWithdrawal {
    pub stuck_id: String,
    pub withdrawal_id: String,
    pub txid_hash: String,
    pub nullifier_hash: String,
    pub amount_bucket: u64,
    pub recipient_commitment: String,
    pub submitted_at_height: u64,
    pub expected_inclusion_height: u64,
    pub last_observed_height: u64,
    pub last_seen_txid_hash: Option<String>,
    pub attempts: u64,
    pub observer_attestation_root: String,
    pub status: String,
}

impl MoneroStuckWithdrawal {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_stuck_withdrawal",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "stuck_id": self.stuck_id,
            "withdrawal_id": self.withdrawal_id,
            "txid_hash": self.txid_hash,
            "nullifier_hash": self.nullifier_hash,
            "amount_bucket": self.amount_bucket,
            "recipient_commitment": self.recipient_commitment,
            "submitted_at_height": self.submitted_at_height,
            "expected_inclusion_height": self.expected_inclusion_height,
            "last_observed_height": self.last_observed_height,
            "last_seen_txid_hash": self.last_seen_txid_hash,
            "attempts": self.attempts,
            "observer_attestation_root": self.observer_attestation_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeEvent {
    pub event_id: String,
    pub event_kind: MoneroBridgeEventKind,
    pub subject_id: String,
    pub l2_height: u64,
    pub amount_bucket: u64,
    pub txid_hash: Option<String>,
    pub nullifier_hash: Option<String>,
    pub recipient_commitment: Option<String>,
    pub expected_output_commitment: Option<String>,
    pub expected_unlock_height: u64,
    pub status: String,
}

impl MoneroBridgeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_event",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "l2_height": self.l2_height,
            "amount_bucket": self.amount_bucket,
            "txid_hash": self.txid_hash,
            "nullifier_hash": self.nullifier_hash,
            "recipient_commitment": self.recipient_commitment,
            "expected_output_commitment": self.expected_output_commitment,
            "expected_unlock_height": self.expected_unlock_height,
            "status": self.status,
        })
    }

    pub fn event_root(&self) -> String {
        monero_watch_payload_root("MONERO-WATCH-BRIDGE-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeEventMatch {
    pub match_id: String,
    pub event_id: String,
    pub tx_observation_id: String,
    pub output_proof_id: Option<String>,
    pub nullifier_watch_id: Option<String>,
    pub amount_bucket: u64,
    pub event_root: String,
    pub tx_observation_root: String,
    pub proof_root: String,
    pub matched_at_height: u64,
    pub confirmations: u64,
    pub status: String,
}

impl MoneroBridgeEventMatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_event_match",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "match_id": self.match_id,
            "event_id": self.event_id,
            "tx_observation_id": self.tx_observation_id,
            "output_proof_id": self.output_proof_id,
            "nullifier_watch_id": self.nullifier_watch_id,
            "amount_bucket": self.amount_bucket,
            "event_root": self.event_root,
            "tx_observation_root": self.tx_observation_root,
            "proof_root": self.proof_root,
            "matched_at_height": self.matched_at_height,
            "confirmations": self.confirmations,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWatchState {
    pub network: String,
    pub operator_label: String,
    pub height: u64,
    pub parameters: MoneroWatchParameters,
    pub endpoints: BTreeMap<String, MoneroDaemonEndpoint>,
    pub endpoint_quorums: BTreeMap<String, MoneroEndpointQuorum>,
    pub observer_attestations: BTreeMap<String, MoneroObserverAttestation>,
    pub block_observations: BTreeMap<String, MoneroBlockObservation>,
    pub block_reconciliations: BTreeMap<String, MoneroBlockReconciliation>,
    pub tx_observations: BTreeMap<String, MoneroTxObservation>,
    pub tx_reconciliations: BTreeMap<String, MoneroTxReconciliation>,
    pub output_proofs: BTreeMap<String, MoneroOutputProofCommitment>,
    pub key_image_watchlist: BTreeMap<String, MoneroKeyImageWatch>,
    pub nullifier_watchlist: BTreeMap<String, MoneroNullifierWatch>,
    pub unlock_windows: BTreeMap<String, MoneroUnlockWindow>,
    pub finality_windows: BTreeMap<String, MoneroFinalityWindow>,
    pub reorg_alerts: BTreeMap<String, MoneroReorgAlert>,
    pub stuck_withdrawals: BTreeMap<String, MoneroStuckWithdrawal>,
    pub bridge_events: BTreeMap<String, MoneroBridgeEvent>,
    pub bridge_event_matches: BTreeMap<String, MoneroBridgeEventMatch>,
}

impl MoneroWatchState {
    pub fn new(
        operator_label: impl Into<String>,
        network: impl Into<String>,
        parameters: MoneroWatchParameters,
    ) -> MoneroWatchResult<Self> {
        parameters.validate()?;
        let operator_label = operator_label.into();
        let network = network.into();
        ensure_non_empty(&operator_label, "monero watch operator label")?;
        ensure_non_empty(&network, "monero watch network")?;
        Ok(Self {
            network,
            operator_label,
            height: 0,
            parameters,
            endpoints: BTreeMap::new(),
            endpoint_quorums: BTreeMap::new(),
            observer_attestations: BTreeMap::new(),
            block_observations: BTreeMap::new(),
            block_reconciliations: BTreeMap::new(),
            tx_observations: BTreeMap::new(),
            tx_reconciliations: BTreeMap::new(),
            output_proofs: BTreeMap::new(),
            key_image_watchlist: BTreeMap::new(),
            nullifier_watchlist: BTreeMap::new(),
            unlock_windows: BTreeMap::new(),
            finality_windows: BTreeMap::new(),
            reorg_alerts: BTreeMap::new(),
            stuck_withdrawals: BTreeMap::new(),
            bridge_events: BTreeMap::new(),
            bridge_event_matches: BTreeMap::new(),
        })
    }

    pub fn devnet(operator_label: &str) -> MoneroWatchResult<Self> {
        let mut state = Self::new(
            operator_label,
            MONERO_WATCH_DEVNET_NETWORK,
            MoneroWatchParameters::default(),
        )?;
        state.set_height(1);
        for suffix in ["a", "b", "c"] {
            let label = format!("{operator_label}-monero-{suffix}");
            let rpc_route = format!("in-process://{operator_label}/monero/{suffix}/rpc");
            let zmq_route = format!("in-process://{operator_label}/monero/{suffix}/zmq");
            let view_key_label = format!("{operator_label}-view-key-{suffix}");
            state.register_endpoint(&label, &rpc_route, &zmq_route, &view_key_label, 1, 9_800)?;
        }
        state.record_endpoint_quorum()?;
        let deposit_event = state.register_bridge_event(
            MoneroBridgeEventKind::DepositObserved,
            "devnet-deposit-0",
            1,
            MONERO_WATCH_AMOUNT_BUCKET,
            Some("devnet-monero-deposit-tx-0"),
            None,
            Some("devnet-recipient-0"),
            None,
            11,
        )?;
        let withdrawal_event = state.register_bridge_event(
            MoneroBridgeEventKind::WithdrawalQueued,
            "devnet-withdrawal-0",
            1,
            MONERO_WATCH_AMOUNT_BUCKET,
            None,
            Some("devnet-nullifier-0"),
            Some("devnet-withdrawal-recipient-0"),
            None,
            11,
        )?;
        state.watch_nullifier(
            "devnet-nullifier-0",
            "bridge_withdrawal",
            Some("devnet-withdrawal-0"),
            Some(&withdrawal_event.event_id),
        )?;
        state.watch_key_image(
            "devnet-key-image-0",
            "bridge_withdrawal",
            Some("devnet-withdrawal-0"),
        )?;
        state.track_finality_window("bridge_event", &deposit_event.event_id, 1)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for endpoint in self.endpoints.values_mut() {
            endpoint.lag_blocks = height.saturating_sub(endpoint.last_observed_height);
            endpoint.status = if endpoint.lag_blocks > self.parameters.max_endpoint_lag_blocks {
                "lagging"
            } else {
                "active"
            }
            .to_string();
        }
        refresh_unlock_windows(
            &mut self.unlock_windows,
            height,
            self.parameters.finality_depth,
        );
        refresh_finality_windows(&mut self.finality_windows, height);
        refresh_stuck_withdrawals(
            &mut self.stuck_withdrawals,
            height,
            self.parameters.stuck_withdrawal_blocks,
        );
    }

    pub fn register_endpoint(
        &mut self,
        operator_label: &str,
        rpc_route: &str,
        zmq_route: &str,
        view_key_label: &str,
        advertised_height: u64,
        reliability_bps: u64,
    ) -> MoneroWatchResult<MoneroDaemonEndpoint> {
        let endpoint = MoneroDaemonEndpoint::new(
            operator_label,
            &self.network,
            rpc_route,
            zmq_route,
            view_key_label,
            advertised_height,
            reliability_bps,
        )?;
        self.endpoints
            .insert(endpoint.endpoint_id.clone(), endpoint.clone());
        Ok(endpoint)
    }

    pub fn update_endpoint_height(
        &mut self,
        endpoint_id: &str,
        advertised_height: u64,
    ) -> MoneroWatchResult<()> {
        let endpoint = self
            .endpoints
            .get_mut(endpoint_id)
            .ok_or_else(|| "unknown monero daemon endpoint".to_string())?;
        endpoint.advertised_height = advertised_height;
        endpoint.last_observed_height = advertised_height;
        endpoint.lag_blocks = self.height.saturating_sub(advertised_height);
        endpoint.status = if endpoint.lag_blocks > self.parameters.max_endpoint_lag_blocks {
            "lagging"
        } else {
            "active"
        }
        .to_string();
        Ok(())
    }

    pub fn record_endpoint_quorum(&mut self) -> MoneroWatchResult<MoneroEndpointQuorum> {
        let active = self
            .endpoints
            .values()
            .filter(|endpoint| endpoint.status == "active")
            .collect::<Vec<_>>();
        let mut advertised_heights = active
            .iter()
            .map(|endpoint| endpoint.advertised_height)
            .collect::<Vec<_>>();
        advertised_heights.sort_unstable();
        let median_advertised_height = advertised_heights
            .get(advertised_heights.len().saturating_sub(1) / 2)
            .copied()
            .unwrap_or(0);
        let max_lag_blocks = active
            .iter()
            .map(|endpoint| endpoint.lag_blocks)
            .max()
            .unwrap_or(0);
        let endpoint_root = self.endpoint_root();
        let advertised_height_root = merkle_root(
            "MONERO-WATCH-ENDPOINT-HEIGHT",
            &active
                .iter()
                .map(|endpoint| {
                    json!({
                        "endpoint_id": endpoint.endpoint_id,
                        "advertised_height": endpoint.advertised_height,
                        "lag_blocks": endpoint.lag_blocks,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let active_endpoint_count = active.len() as u64;
        let status = if active_endpoint_count >= self.parameters.endpoint_quorum
            && max_lag_blocks <= self.parameters.max_endpoint_lag_blocks
        {
            "quorum"
        } else {
            "insufficient"
        }
        .to_string();
        let quorum_id = monero_endpoint_quorum_id(
            &self.network,
            self.height,
            &endpoint_root,
            &advertised_height_root,
            active_endpoint_count,
        );
        let quorum = MoneroEndpointQuorum {
            quorum_id: quorum_id.clone(),
            network: self.network.clone(),
            height: self.height,
            endpoint_root,
            advertised_height_root,
            active_endpoint_count,
            quorum_required: self.parameters.endpoint_quorum,
            max_lag_blocks,
            median_advertised_height,
            status,
        };
        self.endpoint_quorums.insert(quorum_id, quorum.clone());
        Ok(quorum)
    }

    pub fn attest_subject(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        observer_label: &str,
        endpoint_id: Option<String>,
    ) -> MoneroWatchResult<MoneroObserverAttestation> {
        let attestation = MoneroObserverAttestation::new(
            observer_label,
            subject_kind,
            subject_id,
            subject_root,
            endpoint_id,
            self.height,
        )?;
        self.observer_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_block(
        &mut self,
        endpoint_id: &str,
        block_height: u64,
        block_hash: &str,
        previous_block_hash: &str,
        tx_count: u64,
        tx_ids: &[String],
        output_commitments: &[String],
        key_images: &[String],
        difficulty_root: &str,
        observed_tip_height: u64,
        observer_label: &str,
    ) -> MoneroWatchResult<MoneroBlockObservation> {
        self.require_endpoint(endpoint_id)?;
        ensure_non_empty(block_hash, "monero block hash")?;
        ensure_non_empty(observer_label, "monero block observer label")?;
        let tx_root = monero_watch_string_set_root("MONERO-WATCH-BLOCK-TX", tx_ids);
        let output_commitment_root =
            monero_watch_string_set_root("MONERO-WATCH-BLOCK-OUTPUT", output_commitments);
        let key_image_root =
            monero_watch_string_set_root("MONERO-WATCH-BLOCK-KEY-IMAGE", key_images);
        let confirmations = confirmations(observed_tip_height, block_height);
        let observation_id =
            monero_block_observation_id(endpoint_id, block_height, block_hash, &tx_root);
        let mut observation = MoneroBlockObservation {
            observation_id: observation_id.clone(),
            endpoint_id: endpoint_id.to_string(),
            block_height,
            block_hash: block_hash.to_string(),
            previous_block_hash: previous_block_hash.to_string(),
            tx_count,
            tx_root,
            output_commitment_root,
            key_image_root,
            difficulty_root: difficulty_root.to_string(),
            observed_tip_height,
            confirmations,
            observed_at_l2_height: self.height,
            observer_label: observer_label.to_string(),
            attestation_id: String::new(),
            status: block_status(confirmations, self.parameters.finality_depth),
        };
        let attestation = self.attest_subject(
            "monero_block_observation",
            &observation_id,
            &observation.observation_root(),
            observer_label,
            Some(endpoint_id.to_string()),
        )?;
        observation.attestation_id = attestation.attestation_id;
        if let Some(endpoint) = self.endpoints.get_mut(endpoint_id) {
            endpoint.last_observed_height = endpoint.last_observed_height.max(observed_tip_height);
            endpoint.advertised_height = endpoint.advertised_height.max(observed_tip_height);
            endpoint.lag_blocks = self.height.saturating_sub(endpoint.last_observed_height);
            endpoint.status = if endpoint.lag_blocks > self.parameters.max_endpoint_lag_blocks {
                "lagging"
            } else {
                "active"
            }
            .to_string();
        }
        self.block_observations
            .insert(observation_id, observation.clone());
        Ok(observation)
    }

    pub fn reconcile_block(
        &mut self,
        block_height: u64,
    ) -> MoneroWatchResult<MoneroBlockReconciliation> {
        let mut observations = self
            .block_observations
            .values()
            .filter(|observation| observation.block_height == block_height)
            .cloned()
            .collect::<Vec<_>>();
        if observations.is_empty() {
            return Err("no monero block observations for height".to_string());
        }
        observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
        let observation_root = merkle_root(
            "MONERO-WATCH-BLOCK-OBSERVATION-SET",
            &observations
                .iter()
                .map(MoneroBlockObservation::public_record)
                .collect::<Vec<_>>(),
        );
        let mut votes = BTreeMap::<String, Vec<MoneroBlockObservation>>::new();
        for observation in observations {
            votes
                .entry(observation.block_hash.clone())
                .or_default()
                .push(observation);
        }
        let mut ranked = votes
            .iter()
            .map(|(block_hash, votes)| (votes.len() as u64, block_hash.clone()))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        let (_, canonical_block_hash) = ranked
            .first()
            .cloned()
            .ok_or_else(|| "monero block vote set is empty".to_string())?;
        let canonical_votes = votes
            .get(&canonical_block_hash)
            .ok_or_else(|| "monero canonical block vote missing".to_string())?;
        let canonical = canonical_votes
            .iter()
            .min_by(|left, right| left.observation_id.cmp(&right.observation_id))
            .expect("canonical block observation");
        let endpoint_vote_count = canonical_votes.len() as u64;
        let dissenting_vote_count = votes
            .values()
            .map(|vote_set| vote_set.len() as u64)
            .sum::<u64>()
            .saturating_sub(endpoint_vote_count);
        let endpoint_vote_root = merkle_root(
            "MONERO-WATCH-BLOCK-ENDPOINT-VOTE",
            &votes
                .iter()
                .map(|(block_hash, vote_set)| {
                    json!({
                        "block_hash": block_hash,
                        "vote_count": vote_set.len() as u64,
                        "endpoint_root": merkle_root(
                            "MONERO-WATCH-BLOCK-ENDPOINT-VOTE-SET",
                            &vote_set
                                .iter()
                                .map(|observation| Value::String(observation.endpoint_id.clone()))
                                .collect::<Vec<_>>()
                        ),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let confirmations = canonical_votes
            .iter()
            .map(|observation| observation.confirmations)
            .max()
            .unwrap_or(0);
        let status = reconciliation_status(
            endpoint_vote_count,
            dissenting_vote_count,
            confirmations,
            self.parameters.endpoint_quorum,
            self.parameters.finality_depth,
        );
        let reconciliation_id = monero_block_reconciliation_id(
            block_height,
            &canonical_block_hash,
            &observation_root,
            &endpoint_vote_root,
        );
        let reconciliation = MoneroBlockReconciliation {
            reconciliation_id: reconciliation_id.clone(),
            block_height,
            canonical_block_hash,
            canonical_previous_block_hash: canonical.previous_block_hash.clone(),
            canonical_tx_root: canonical.tx_root.clone(),
            observation_root,
            endpoint_vote_root,
            endpoint_vote_count,
            dissenting_vote_count,
            quorum_required: self.parameters.endpoint_quorum,
            confirmations,
            reconciled_at_l2_height: self.height,
            status,
        };
        self.block_reconciliations
            .insert(reconciliation_id, reconciliation.clone());
        Ok(reconciliation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_tx(
        &mut self,
        endpoint_id: &str,
        txid: &str,
        tx_kind: MoneroTxKind,
        block_height: u64,
        block_hash: &str,
        output_index: u64,
        amount: u64,
        recipient: &str,
        payment_id_payload: &Value,
        ring_members: &[String],
        output_commitment: &str,
        key_images: &[String],
        unlock_height: u64,
        observed_tip_height: u64,
        observer_label: &str,
    ) -> MoneroWatchResult<MoneroTxObservation> {
        self.require_endpoint(endpoint_id)?;
        ensure_non_empty(txid, "monero txid")?;
        ensure_non_empty(block_hash, "monero tx block hash")?;
        ensure_non_empty(observer_label, "monero tx observer label")?;
        let txid_hash = monero_watch_txid_hash(txid);
        let amount_bucket = monero_watch_amount_bucket(amount);
        let recipient_commitment = monero_watch_string_root("MONERO-WATCH-RECIPIENT", recipient);
        let payment_id_root =
            monero_watch_payload_root("MONERO-WATCH-PAYMENT-ID", payment_id_payload);
        let ring_member_root =
            monero_watch_string_set_root("MONERO-WATCH-RING-MEMBER", ring_members);
        let key_image_root = monero_watch_string_set_root("MONERO-WATCH-TX-KEY-IMAGE", key_images);
        let confirmations = confirmations(observed_tip_height, block_height);
        let observation_id =
            monero_tx_observation_id(&txid_hash, tx_kind, block_height, block_hash, output_index);
        let mut observation = MoneroTxObservation {
            observation_id: observation_id.clone(),
            txid_hash,
            tx_kind,
            endpoint_id: endpoint_id.to_string(),
            block_height,
            block_hash: block_hash.to_string(),
            output_index,
            amount_bucket,
            recipient_commitment,
            payment_id_root,
            ring_member_root,
            output_commitment: output_commitment.to_string(),
            key_image_root,
            unlock_height,
            observed_tip_height,
            confirmations,
            observed_at_l2_height: self.height,
            observer_label: observer_label.to_string(),
            attestation_id: String::new(),
            status: block_status(confirmations, self.parameters.finality_depth),
        };
        let attestation = self.attest_subject(
            "monero_tx_observation",
            &observation_id,
            &observation.observation_root(),
            observer_label,
            Some(endpoint_id.to_string()),
        )?;
        observation.attestation_id = attestation.attestation_id;
        self.tx_observations
            .insert(observation_id, observation.clone());
        Ok(observation)
    }

    pub fn reconcile_tx(&mut self, txid_hash: &str) -> MoneroWatchResult<MoneroTxReconciliation> {
        let mut observations = self
            .tx_observations
            .values()
            .filter(|observation| observation.txid_hash == txid_hash)
            .cloned()
            .collect::<Vec<_>>();
        if observations.is_empty() {
            return Err("no monero tx observations for txid hash".to_string());
        }
        observations.sort_by(|left, right| left.observation_id.cmp(&right.observation_id));
        let observation_root = merkle_root(
            "MONERO-WATCH-TX-OBSERVATION-SET",
            &observations
                .iter()
                .map(MoneroTxObservation::public_record)
                .collect::<Vec<_>>(),
        );
        let mut votes = BTreeMap::<String, Vec<MoneroTxObservation>>::new();
        for observation in observations {
            let key = format!(
                "{}:{}:{}",
                observation.block_height, observation.block_hash, observation.output_commitment
            );
            votes.entry(key).or_default().push(observation);
        }
        let mut ranked = votes
            .iter()
            .map(|(vote_key, vote_set)| (vote_set.len() as u64, vote_key.clone()))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        let (_, canonical_key) = ranked
            .first()
            .cloned()
            .ok_or_else(|| "monero tx vote set is empty".to_string())?;
        let canonical_votes = votes
            .get(&canonical_key)
            .ok_or_else(|| "monero canonical tx vote missing".to_string())?;
        let canonical = canonical_votes
            .iter()
            .min_by(|left, right| left.observation_id.cmp(&right.observation_id))
            .expect("canonical tx observation");
        let output_proof_root = keyed_record_root(
            "MONERO-WATCH-TX-OUTPUT-PROOF",
            self.output_proofs
                .values()
                .filter(|proof| proof.txid_hash == txid_hash)
                .map(|proof| (proof.proof_id.clone(), proof.public_record()))
                .collect(),
        );
        let watchlist_hit_root = self.watchlist_hit_root(txid_hash, &canonical.key_image_root);
        let bridge_event_match_root = keyed_record_root(
            "MONERO-WATCH-TX-BRIDGE-EVENT-MATCH",
            self.bridge_event_matches
                .values()
                .filter(|matched| matched.tx_observation_id == canonical.observation_id)
                .map(|matched| (matched.match_id.clone(), matched.public_record()))
                .collect(),
        );
        let observer_count = canonical_votes.len() as u64;
        let dissenting = votes
            .values()
            .map(|vote_set| vote_set.len() as u64)
            .sum::<u64>()
            .saturating_sub(observer_count);
        let confirmations = canonical_votes
            .iter()
            .map(|observation| observation.confirmations)
            .max()
            .unwrap_or(0);
        let status = reconciliation_status(
            observer_count,
            dissenting,
            confirmations,
            self.parameters.observer_quorum,
            self.parameters.finality_depth,
        );
        let reconciliation_id = monero_tx_reconciliation_id(
            txid_hash,
            canonical.tx_kind,
            &observation_root,
            &output_proof_root,
            &bridge_event_match_root,
        );
        let reconciliation = MoneroTxReconciliation {
            reconciliation_id: reconciliation_id.clone(),
            txid_hash: txid_hash.to_string(),
            tx_kind: canonical.tx_kind,
            canonical_block_height: canonical.block_height,
            canonical_block_hash: canonical.block_hash.clone(),
            canonical_output_commitment: canonical.output_commitment.clone(),
            observation_root,
            output_proof_root,
            watchlist_hit_root,
            bridge_event_match_root,
            observer_count,
            quorum_required: self.parameters.observer_quorum,
            confirmations,
            reconciled_at_l2_height: self.height,
            status,
        };
        self.tx_reconciliations
            .insert(reconciliation_id, reconciliation.clone());
        Ok(reconciliation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_output_proof(
        &mut self,
        txid: &str,
        output_index: u64,
        one_time_address: &str,
        amount: u64,
        view_tag: &str,
        encrypted_mask_payload: &Value,
        proof_system: &str,
        verifier_key: &str,
        proof_payload: &Value,
        observer_labels: &[String],
    ) -> MoneroWatchResult<MoneroOutputProofCommitment> {
        ensure_non_empty(txid, "monero output proof txid")?;
        ensure_non_empty(proof_system, "monero output proof system")?;
        validate_observer_labels(observer_labels)?;
        let txid_hash = monero_watch_txid_hash(txid);
        let one_time_address_hash =
            monero_watch_string_root("MONERO-WATCH-ONE-TIME-ADDRESS", one_time_address);
        let amount_commitment = monero_watch_amount_commitment(amount);
        let view_tag_commitment = monero_watch_string_root("MONERO-WATCH-VIEW-TAG", view_tag);
        let encrypted_mask_root =
            monero_watch_payload_root("MONERO-WATCH-ENCRYPTED-MASK", encrypted_mask_payload);
        let verifier_key_root = monero_watch_string_root("MONERO-WATCH-VERIFIER-KEY", verifier_key);
        let proof_payload_root =
            monero_watch_payload_root("MONERO-WATCH-PROOF-PAYLOAD", proof_payload);
        let output_commitment = monero_output_commitment(
            &txid_hash,
            output_index,
            &one_time_address_hash,
            &amount_commitment,
            &view_tag_commitment,
        );
        let proof_id = monero_output_proof_id(&txid_hash, output_index, &output_commitment);
        let subject_root = monero_watch_payload_root(
            "MONERO-WATCH-OUTPUT-PROOF-SUBJECT",
            &json!({
                "txid_hash": txid_hash,
                "output_index": output_index,
                "output_commitment": output_commitment,
                "proof_payload_root": proof_payload_root,
            }),
        );
        let observer_attestation_root = self.attestation_set_root(
            "monero_output_proof_commitment",
            &proof_id,
            &subject_root,
            observer_labels,
            None,
        )?;
        let proof = MoneroOutputProofCommitment {
            proof_id: proof_id.clone(),
            txid_hash,
            output_index,
            output_commitment,
            one_time_address_hash,
            amount_commitment,
            view_tag_commitment,
            encrypted_mask_root,
            proof_system: proof_system.to_string(),
            verifier_key_root,
            proof_payload_root,
            observer_attestation_root,
            status: "committed".to_string(),
        };
        self.output_proofs.insert(proof_id, proof.clone());
        Ok(proof)
    }

    pub fn watch_key_image(
        &mut self,
        key_image: &str,
        purpose: &str,
        linked_withdrawal_id: Option<&str>,
    ) -> MoneroWatchResult<MoneroKeyImageWatch> {
        ensure_non_empty(key_image, "monero key image")?;
        ensure_non_empty(purpose, "monero key image watch purpose")?;
        let key_image_hash = monero_watch_key_image_hash(key_image);
        let watch_id =
            monero_key_image_watch_id(&key_image_hash, purpose, linked_withdrawal_id.unwrap_or(""));
        let watch = MoneroKeyImageWatch {
            watch_id: watch_id.clone(),
            key_image_hash,
            purpose: purpose.to_string(),
            linked_withdrawal_id: linked_withdrawal_id.map(str::to_string),
            first_seen_txid_hash: None,
            first_seen_height: 0,
            last_seen_height: 0,
            observer_attestation_root: merkle_root("MONERO-WATCH-EMPTY-ATTESTATION", &[]),
            status: "watching".to_string(),
        };
        self.key_image_watchlist.insert(watch_id, watch.clone());
        Ok(watch)
    }

    pub fn observe_key_image_spend(
        &mut self,
        watch_id: &str,
        txid: &str,
        block_height: u64,
        observer_labels: &[String],
    ) -> MoneroWatchResult<MoneroKeyImageWatch> {
        let mut watch = self
            .key_image_watchlist
            .get(watch_id)
            .cloned()
            .ok_or_else(|| "unknown monero key image watch".to_string())?;
        validate_observer_labels(observer_labels)?;
        let txid_hash = monero_watch_txid_hash(txid);
        let subject_root = monero_watch_payload_root(
            "MONERO-WATCH-KEY-IMAGE-SPEND",
            &json!({
                "watch_id": watch_id,
                "key_image_hash": watch.key_image_hash,
                "txid_hash": txid_hash,
                "block_height": block_height,
            }),
        );
        let observer_attestation_root = self.attestation_set_root(
            "monero_key_image_spend",
            watch_id,
            &subject_root,
            observer_labels,
            None,
        )?;
        watch.first_seen_txid_hash = watch.first_seen_txid_hash.or(Some(txid_hash));
        watch.first_seen_height = if watch.first_seen_height == 0 {
            block_height
        } else {
            watch.first_seen_height.min(block_height)
        };
        watch.last_seen_height = watch.last_seen_height.max(block_height);
        watch.observer_attestation_root = observer_attestation_root;
        watch.status = "spent".to_string();
        self.key_image_watchlist
            .insert(watch_id.to_string(), watch.clone());
        Ok(watch)
    }

    pub fn watch_nullifier(
        &mut self,
        nullifier: &str,
        spend_domain: &str,
        linked_withdrawal_id: Option<&str>,
        bridge_event_id: Option<&str>,
    ) -> MoneroWatchResult<MoneroNullifierWatch> {
        ensure_non_empty(nullifier, "monero nullifier")?;
        ensure_non_empty(spend_domain, "monero nullifier spend domain")?;
        let nullifier_hash = monero_watch_nullifier_hash(nullifier);
        let watch_id = monero_nullifier_watch_id(&nullifier_hash, spend_domain);
        let watch = MoneroNullifierWatch {
            watch_id: watch_id.clone(),
            nullifier_hash,
            spend_domain: spend_domain.to_string(),
            bridge_event_id: bridge_event_id.map(str::to_string),
            linked_withdrawal_id: linked_withdrawal_id.map(str::to_string),
            opened_at_height: self.height,
            spent_at_height: 0,
            matched_key_image_watch_id: None,
            status: "watching".to_string(),
        };
        self.nullifier_watchlist.insert(watch_id, watch.clone());
        Ok(watch)
    }

    pub fn match_nullifier_to_key_image(
        &mut self,
        nullifier_watch_id: &str,
        key_image_watch_id: &str,
    ) -> MoneroWatchResult<MoneroNullifierWatch> {
        if !self.key_image_watchlist.contains_key(key_image_watch_id) {
            return Err("unknown monero key image watch".to_string());
        }
        let mut watch = self
            .nullifier_watchlist
            .get(nullifier_watch_id)
            .cloned()
            .ok_or_else(|| "unknown monero nullifier watch".to_string())?;
        watch.matched_key_image_watch_id = Some(key_image_watch_id.to_string());
        watch.spent_at_height = self.height;
        watch.status = "matched".to_string();
        self.nullifier_watchlist
            .insert(nullifier_watch_id.to_string(), watch.clone());
        Ok(watch)
    }

    pub fn track_unlock_window(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        txid_hash: &str,
        block_height: u64,
        unlock_height: u64,
        expires_at_height: u64,
    ) -> MoneroWatchResult<MoneroUnlockWindow> {
        ensure_non_empty(subject_kind, "monero unlock subject kind")?;
        ensure_non_empty(subject_id, "monero unlock subject id")?;
        ensure_non_empty(txid_hash, "monero unlock txid hash")?;
        let finality_height = block_height.saturating_add(self.parameters.finality_depth);
        let spendable_at_height = unlock_height
            .max(finality_height)
            .saturating_add(self.parameters.unlock_margin_blocks);
        let window_id = monero_unlock_window_id(subject_kind, subject_id, txid_hash, block_height);
        let confirmations = confirmations(self.height, block_height);
        let status = unlock_status(self.height, spendable_at_height, expires_at_height);
        let window = MoneroUnlockWindow {
            window_id: window_id.clone(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            txid_hash: txid_hash.to_string(),
            block_height,
            unlock_height,
            finality_height,
            spendable_at_height,
            expires_at_height,
            current_height: self.height,
            confirmations,
            required_confirmations: self.parameters.finality_depth,
            status,
        };
        self.unlock_windows.insert(window_id, window.clone());
        Ok(window)
    }

    pub fn track_finality_window(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        start_height: u64,
    ) -> MoneroWatchResult<MoneroFinalityWindow> {
        ensure_non_empty(subject_kind, "monero finality subject kind")?;
        ensure_non_empty(subject_id, "monero finality subject id")?;
        let soft_final_height = start_height.saturating_add(self.parameters.soft_confirmations);
        let hard_final_height = start_height.saturating_add(self.parameters.finality_depth);
        let challenge_deadline_height =
            hard_final_height.saturating_add(self.parameters.reorg_alert_depth);
        let window_id = monero_finality_window_id(subject_kind, subject_id, start_height);
        let window = MoneroFinalityWindow {
            window_id: window_id.clone(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            start_height,
            soft_final_height,
            hard_final_height,
            challenge_deadline_height,
            current_height: self.height,
            status: finality_status(self.height, soft_final_height, hard_final_height),
        };
        self.finality_windows.insert(window_id, window.clone());
        Ok(window)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn raise_reorg_alert(
        &mut self,
        alert_kind: MoneroReorgAlertKind,
        old_block_height: u64,
        old_block_hash: &str,
        new_block_height: u64,
        new_block_hash: &str,
        txid_hash: Option<&str>,
        affected_subject: &Value,
        observer_labels: &[String],
    ) -> MoneroWatchResult<MoneroReorgAlert> {
        if old_block_height == new_block_height && old_block_hash == new_block_hash {
            return Err("monero reorg alert requires conflicting blocks".to_string());
        }
        validate_observer_labels(observer_labels)?;
        let depth = old_block_height.abs_diff(new_block_height);
        let affected_subject_root =
            monero_watch_payload_root("MONERO-WATCH-REORG-AFFECTED-SUBJECT", affected_subject);
        let alert_id = monero_reorg_alert_id(
            alert_kind,
            old_block_height,
            old_block_hash,
            new_block_height,
            new_block_hash,
            txid_hash.unwrap_or(""),
        );
        let subject_root = monero_watch_payload_root(
            "MONERO-WATCH-REORG-ALERT-SUBJECT",
            &json!({
                "alert_id": alert_id,
                "alert_kind": alert_kind.as_str(),
                "old_block_height": old_block_height,
                "old_block_hash": old_block_hash,
                "new_block_height": new_block_height,
                "new_block_hash": new_block_hash,
                "txid_hash": txid_hash,
                "affected_subject_root": affected_subject_root,
            }),
        );
        let observer_attestation_root = self.attestation_set_root(
            "monero_reorg_alert",
            &alert_id,
            &subject_root,
            observer_labels,
            None,
        )?;
        let severity = if depth >= self.parameters.finality_depth {
            MoneroWatchSeverity::Critical
        } else if depth >= self.parameters.reorg_alert_depth {
            MoneroWatchSeverity::Watch
        } else {
            MoneroWatchSeverity::Info
        };
        let alert = MoneroReorgAlert {
            alert_id: alert_id.clone(),
            alert_kind,
            old_block_height,
            old_block_hash: old_block_hash.to_string(),
            new_block_height,
            new_block_hash: new_block_hash.to_string(),
            txid_hash: txid_hash.map(str::to_string),
            depth,
            detected_at_height: self.height,
            affected_subject_root,
            observer_attestation_root,
            severity,
            status: if severity == MoneroWatchSeverity::Critical {
                "critical"
            } else {
                "open"
            }
            .to_string(),
        };
        self.reorg_alerts.insert(alert_id, alert.clone());
        Ok(alert)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn track_stuck_withdrawal(
        &mut self,
        withdrawal_id: &str,
        txid: &str,
        nullifier: &str,
        amount: u64,
        recipient: &str,
        submitted_at_height: u64,
        expected_inclusion_height: u64,
        observer_labels: &[String],
    ) -> MoneroWatchResult<MoneroStuckWithdrawal> {
        ensure_non_empty(withdrawal_id, "monero stuck withdrawal id")?;
        validate_observer_labels(observer_labels)?;
        let txid_hash = monero_watch_txid_hash(txid);
        let nullifier_hash = monero_watch_nullifier_hash(nullifier);
        let amount_bucket = monero_watch_amount_bucket(amount);
        let recipient_commitment =
            monero_watch_string_root("MONERO-WATCH-WITHDRAWAL-RECIPIENT", recipient);
        let stuck_id = monero_stuck_withdrawal_id(withdrawal_id, &txid_hash, submitted_at_height);
        let subject_root = monero_watch_payload_root(
            "MONERO-WATCH-STUCK-WITHDRAWAL-SUBJECT",
            &json!({
                "stuck_id": stuck_id,
                "withdrawal_id": withdrawal_id,
                "txid_hash": txid_hash,
                "nullifier_hash": nullifier_hash,
                "amount_bucket": amount_bucket,
                "submitted_at_height": submitted_at_height,
                "expected_inclusion_height": expected_inclusion_height,
            }),
        );
        let observer_attestation_root = self.attestation_set_root(
            "monero_stuck_withdrawal",
            &stuck_id,
            &subject_root,
            observer_labels,
            None,
        )?;
        let status = stuck_status(
            self.height,
            expected_inclusion_height,
            self.parameters.stuck_withdrawal_blocks,
            None,
        );
        let stuck = MoneroStuckWithdrawal {
            stuck_id: stuck_id.clone(),
            withdrawal_id: withdrawal_id.to_string(),
            txid_hash,
            nullifier_hash,
            amount_bucket,
            recipient_commitment,
            submitted_at_height,
            expected_inclusion_height,
            last_observed_height: 0,
            last_seen_txid_hash: None,
            attempts: 0,
            observer_attestation_root,
            status,
        };
        self.stuck_withdrawals.insert(stuck_id, stuck.clone());
        Ok(stuck)
    }

    pub fn observe_withdrawal_progress(
        &mut self,
        stuck_id: &str,
        txid: &str,
        observed_height: u64,
    ) -> MoneroWatchResult<MoneroStuckWithdrawal> {
        let mut stuck = self
            .stuck_withdrawals
            .get(stuck_id)
            .cloned()
            .ok_or_else(|| "unknown monero stuck withdrawal".to_string())?;
        stuck.last_seen_txid_hash = Some(monero_watch_txid_hash(txid));
        stuck.last_observed_height = observed_height;
        stuck.attempts = stuck.attempts.saturating_add(1);
        stuck.status = if observed_height >= stuck.expected_inclusion_height {
            "observed"
        } else {
            "pending"
        }
        .to_string();
        self.stuck_withdrawals
            .insert(stuck_id.to_string(), stuck.clone());
        Ok(stuck)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_bridge_event(
        &mut self,
        event_kind: MoneroBridgeEventKind,
        subject_id: &str,
        l2_height: u64,
        amount: u64,
        txid: Option<&str>,
        nullifier: Option<&str>,
        recipient: Option<&str>,
        expected_output_commitment: Option<&str>,
        expected_unlock_height: u64,
    ) -> MoneroWatchResult<MoneroBridgeEvent> {
        ensure_non_empty(subject_id, "monero bridge event subject id")?;
        let amount_bucket = monero_watch_amount_bucket(amount);
        let txid_hash = txid.map(monero_watch_txid_hash);
        let nullifier_hash = nullifier.map(monero_watch_nullifier_hash);
        let recipient_commitment =
            recipient.map(|value| monero_watch_string_root("MONERO-WATCH-EVENT-RECIPIENT", value));
        let event_id = monero_bridge_event_id(
            event_kind,
            subject_id,
            l2_height,
            amount_bucket,
            txid_hash.as_deref().unwrap_or(""),
            nullifier_hash.as_deref().unwrap_or(""),
        );
        let event = MoneroBridgeEvent {
            event_id: event_id.clone(),
            event_kind,
            subject_id: subject_id.to_string(),
            l2_height,
            amount_bucket,
            txid_hash,
            nullifier_hash,
            recipient_commitment,
            expected_output_commitment: expected_output_commitment.map(str::to_string),
            expected_unlock_height,
            status: "open".to_string(),
        };
        self.bridge_events.insert(event_id, event.clone());
        Ok(event)
    }

    pub fn match_bridge_event(
        &mut self,
        event_id: &str,
        tx_observation_id: &str,
        output_proof_id: Option<&str>,
        nullifier_watch_id: Option<&str>,
        observer_labels: &[String],
    ) -> MoneroWatchResult<MoneroBridgeEventMatch> {
        validate_observer_labels(observer_labels)?;
        let event = self
            .bridge_events
            .get(event_id)
            .cloned()
            .ok_or_else(|| "unknown monero bridge event".to_string())?;
        let tx_observation = self
            .tx_observations
            .get(tx_observation_id)
            .cloned()
            .ok_or_else(|| "unknown monero tx observation".to_string())?;
        let proof = output_proof_id
            .map(|proof_id| {
                self.output_proofs
                    .get(proof_id)
                    .cloned()
                    .ok_or_else(|| "unknown monero output proof".to_string())
            })
            .transpose()?;
        if let Some(watch_id) = nullifier_watch_id {
            if !self.nullifier_watchlist.contains_key(watch_id) {
                return Err("unknown monero nullifier watch".to_string());
            }
        }
        let event_root = event.event_root();
        let tx_observation_root = tx_observation.observation_root();
        let proof_root = proof
            .as_ref()
            .map(MoneroOutputProofCommitment::proof_root)
            .unwrap_or_else(|| merkle_root("MONERO-WATCH-NO-OUTPUT-PROOF", &[]));
        let amount_matches =
            event.amount_bucket == 0 || event.amount_bucket == tx_observation.amount_bucket;
        let txid_matches = event
            .txid_hash
            .as_ref()
            .map(|expected| expected == &tx_observation.txid_hash)
            .unwrap_or(true);
        let proof_matches = match (&event.expected_output_commitment, proof.as_ref()) {
            (Some(expected), Some(proof)) => expected == &proof.output_commitment,
            (Some(_), None) => false,
            (None, _) => true,
        };
        let status = if amount_matches && txid_matches && proof_matches {
            "matched"
        } else {
            "mismatch"
        }
        .to_string();
        let match_id = monero_bridge_event_match_id(
            event_id,
            tx_observation_id,
            output_proof_id.unwrap_or(""),
            nullifier_watch_id.unwrap_or(""),
            &event_root,
            &tx_observation_root,
        );
        let subject_root = monero_watch_payload_root(
            "MONERO-WATCH-BRIDGE-EVENT-MATCH-SUBJECT",
            &json!({
                "match_id": match_id,
                "event_id": event_id,
                "tx_observation_id": tx_observation_id,
                "output_proof_id": output_proof_id,
                "nullifier_watch_id": nullifier_watch_id,
                "status": status,
            }),
        );
        self.attestation_set_root(
            "monero_bridge_event_match",
            &match_id,
            &subject_root,
            observer_labels,
            None,
        )?;
        let event_match = MoneroBridgeEventMatch {
            match_id: match_id.clone(),
            event_id: event_id.to_string(),
            tx_observation_id: tx_observation_id.to_string(),
            output_proof_id: output_proof_id.map(str::to_string),
            nullifier_watch_id: nullifier_watch_id.map(str::to_string),
            amount_bucket: tx_observation.amount_bucket,
            event_root,
            tx_observation_root,
            proof_root,
            matched_at_height: self.height,
            confirmations: tx_observation.confirmations,
            status: status.clone(),
        };
        self.bridge_event_matches
            .insert(match_id, event_match.clone());
        if let Some(stored_event) = self.bridge_events.get_mut(event_id) {
            stored_event.status = status;
        }
        Ok(event_match)
    }

    pub fn endpoint_root(&self) -> String {
        monero_daemon_endpoint_root(&self.endpoints.values().cloned().collect::<Vec<_>>())
    }

    pub fn endpoint_quorum_root(&self) -> String {
        monero_endpoint_quorum_root(&self.endpoint_quorums.values().cloned().collect::<Vec<_>>())
    }

    pub fn observer_attestation_root(&self) -> String {
        monero_observer_attestation_root(
            &self
                .observer_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn block_observation_root(&self) -> String {
        monero_block_observation_root(
            &self
                .block_observations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn block_reconciliation_root(&self) -> String {
        monero_block_reconciliation_root(
            &self
                .block_reconciliations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn tx_observation_root(&self) -> String {
        monero_tx_observation_root(&self.tx_observations.values().cloned().collect::<Vec<_>>())
    }

    pub fn tx_reconciliation_root(&self) -> String {
        monero_tx_reconciliation_root(
            &self
                .tx_reconciliations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn output_proof_root(&self) -> String {
        monero_output_proof_root(&self.output_proofs.values().cloned().collect::<Vec<_>>())
    }

    pub fn key_image_watch_root(&self) -> String {
        monero_key_image_watch_root(
            &self
                .key_image_watchlist
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn nullifier_watch_root(&self) -> String {
        monero_nullifier_watch_root(
            &self
                .nullifier_watchlist
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn unlock_window_root(&self) -> String {
        monero_unlock_window_root(&self.unlock_windows.values().cloned().collect::<Vec<_>>())
    }

    pub fn finality_window_root(&self) -> String {
        monero_finality_window_root(&self.finality_windows.values().cloned().collect::<Vec<_>>())
    }

    pub fn reorg_alert_root(&self) -> String {
        monero_reorg_alert_root(&self.reorg_alerts.values().cloned().collect::<Vec<_>>())
    }

    pub fn stuck_withdrawal_root(&self) -> String {
        monero_stuck_withdrawal_root(&self.stuck_withdrawals.values().cloned().collect::<Vec<_>>())
    }

    pub fn bridge_event_root(&self) -> String {
        monero_bridge_event_root(&self.bridge_events.values().cloned().collect::<Vec<_>>())
    }

    pub fn bridge_event_match_root(&self) -> String {
        monero_bridge_event_match_root(
            &self
                .bridge_event_matches
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        monero_watch_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("monero watch state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_watch_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_WATCH_PROTOCOL_VERSION,
            "network": self.network,
            "operator_label": self.operator_label,
            "height": self.height,
            "parameters_root": self.parameters.parameters_root(),
            "endpoint_root": self.endpoint_root(),
            "endpoint_quorum_root": self.endpoint_quorum_root(),
            "observer_attestation_root": self.observer_attestation_root(),
            "block_observation_root": self.block_observation_root(),
            "block_reconciliation_root": self.block_reconciliation_root(),
            "tx_observation_root": self.tx_observation_root(),
            "tx_reconciliation_root": self.tx_reconciliation_root(),
            "output_proof_root": self.output_proof_root(),
            "key_image_watch_root": self.key_image_watch_root(),
            "nullifier_watch_root": self.nullifier_watch_root(),
            "unlock_window_root": self.unlock_window_root(),
            "finality_window_root": self.finality_window_root(),
            "reorg_alert_root": self.reorg_alert_root(),
            "stuck_withdrawal_root": self.stuck_withdrawal_root(),
            "bridge_event_root": self.bridge_event_root(),
            "bridge_event_match_root": self.bridge_event_match_root(),
            "endpoint_count": self.endpoints.len() as u64,
            "endpoint_quorum_count": self.endpoint_quorums.len() as u64,
            "observer_attestation_count": self.observer_attestations.len() as u64,
            "block_observation_count": self.block_observations.len() as u64,
            "block_reconciliation_count": self.block_reconciliations.len() as u64,
            "tx_observation_count": self.tx_observations.len() as u64,
            "tx_reconciliation_count": self.tx_reconciliations.len() as u64,
            "output_proof_count": self.output_proofs.len() as u64,
            "key_image_watch_count": self.key_image_watchlist.len() as u64,
            "nullifier_watch_count": self.nullifier_watchlist.len() as u64,
            "unlock_window_count": self.unlock_windows.len() as u64,
            "finality_window_count": self.finality_windows.len() as u64,
            "reorg_alert_count": self.reorg_alerts.len() as u64,
            "stuck_withdrawal_count": self.stuck_withdrawals.len() as u64,
            "bridge_event_count": self.bridge_events.len() as u64,
            "bridge_event_match_count": self.bridge_event_matches.len() as u64,
        })
    }

    fn require_endpoint(&self, endpoint_id: &str) -> MoneroWatchResult<()> {
        if self.endpoints.contains_key(endpoint_id) {
            Ok(())
        } else {
            Err("unknown monero daemon endpoint".to_string())
        }
    }

    fn attestation_set_root(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        observer_labels: &[String],
        endpoint_id: Option<String>,
    ) -> MoneroWatchResult<String> {
        validate_observer_labels(observer_labels)?;
        let mut attestations = Vec::new();
        for label in ordered_labels(observer_labels) {
            let attestation = self.attest_subject(
                subject_kind,
                subject_id,
                subject_root,
                &label,
                endpoint_id.clone(),
            )?;
            attestations.push(attestation.public_record());
        }
        Ok(merkle_root(
            "MONERO-WATCH-OBSERVER-ATTESTATION-SET",
            &attestations,
        ))
    }

    fn watchlist_hit_root(&self, txid_hash: &str, key_image_root: &str) -> String {
        let key_image_hits = self
            .key_image_watchlist
            .values()
            .filter(|watch| {
                watch
                    .first_seen_txid_hash
                    .as_ref()
                    .map(|seen| seen == txid_hash)
                    .unwrap_or(false)
            })
            .map(MoneroKeyImageWatch::public_record)
            .collect::<Vec<_>>();
        let nullifier_hits = self
            .nullifier_watchlist
            .values()
            .filter(|watch| watch.status == "matched")
            .map(MoneroNullifierWatch::public_record)
            .collect::<Vec<_>>();
        monero_watch_payload_root(
            "MONERO-WATCH-WATCHLIST-HITS",
            &json!({
                "txid_hash": txid_hash,
                "key_image_root": key_image_root,
                "key_image_hit_root": merkle_root("MONERO-WATCH-KEY-IMAGE-HIT", &key_image_hits),
                "nullifier_hit_root": merkle_root("MONERO-WATCH-NULLIFIER-HIT", &nullifier_hits),
            }),
        )
    }
}

pub fn monero_endpoint_commitment(
    operator_label: &str,
    network: &str,
    rpc_route_commitment: &str,
    zmq_route_commitment: &str,
    view_key_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-ENDPOINT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(network),
            HashPart::Str(rpc_route_commitment),
            HashPart::Str(zmq_route_commitment),
            HashPart::Str(view_key_commitment),
        ],
        32,
    )
}

pub fn monero_daemon_endpoint_id(
    operator_label: &str,
    network: &str,
    endpoint_commitment: &str,
    advertised_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCH-DAEMON-ENDPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(network),
            HashPart::Str(endpoint_commitment),
            HashPart::Int(advertised_height as i128),
        ],
        32,
    )
}

pub fn monero_endpoint_quorum_id(
    network: &str,
    height: u64,
    endpoint_root: &str,
    advertised_height_root: &str,
    active_endpoint_count: u64,
) -> String {
    domain_hash(
        "MONERO-WATCH-ENDPOINT-QUORUM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(network),
            HashPart::Int(height as i128),
            HashPart::Str(endpoint_root),
            HashPart::Str(advertised_height_root),
            HashPart::Int(active_endpoint_count as i128),
        ],
        32,
    )
}

pub fn monero_observer_attestation_id(
    observer_label: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCH-OBSERVER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(observer_label),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn monero_observer_signature_root(
    observer_label: &str,
    observer_public_key: &str,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCH-OBSERVER-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCH_PROTOCOL_VERSION),
            HashPart::Str(observer_label),
            HashPart::Str(observer_public_key),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn monero_block_observation_id(
    endpoint_id: &str,
    block_height: u64,
    block_hash: &str,
    tx_root: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-BLOCK-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(endpoint_id),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(tx_root),
        ],
        32,
    )
}

pub fn monero_block_reconciliation_id(
    block_height: u64,
    canonical_block_hash: &str,
    observation_root: &str,
    endpoint_vote_root: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-BLOCK-RECONCILIATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(block_height as i128),
            HashPart::Str(canonical_block_hash),
            HashPart::Str(observation_root),
            HashPart::Str(endpoint_vote_root),
        ],
        32,
    )
}

pub fn monero_tx_observation_id(
    txid_hash: &str,
    tx_kind: MoneroTxKind,
    block_height: u64,
    block_hash: &str,
    output_index: u64,
) -> String {
    domain_hash(
        "MONERO-WATCH-TX-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(txid_hash),
            HashPart::Str(tx_kind.as_str()),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Int(output_index as i128),
        ],
        32,
    )
}

pub fn monero_tx_reconciliation_id(
    txid_hash: &str,
    tx_kind: MoneroTxKind,
    observation_root: &str,
    output_proof_root: &str,
    bridge_event_match_root: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-TX-RECONCILIATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(txid_hash),
            HashPart::Str(tx_kind.as_str()),
            HashPart::Str(observation_root),
            HashPart::Str(output_proof_root),
            HashPart::Str(bridge_event_match_root),
        ],
        32,
    )
}

pub fn monero_output_proof_id(
    txid_hash: &str,
    output_index: u64,
    output_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-OUTPUT-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(txid_hash),
            HashPart::Int(output_index as i128),
            HashPart::Str(output_commitment),
        ],
        32,
    )
}

pub fn monero_output_commitment(
    txid_hash: &str,
    output_index: u64,
    one_time_address_hash: &str,
    amount_commitment: &str,
    view_tag_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-OUTPUT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(txid_hash),
            HashPart::Int(output_index as i128),
            HashPart::Str(one_time_address_hash),
            HashPart::Str(amount_commitment),
            HashPart::Str(view_tag_commitment),
        ],
        32,
    )
}

pub fn monero_key_image_watch_id(
    key_image_hash: &str,
    purpose: &str,
    linked_withdrawal_id: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-KEY-IMAGE-WATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(key_image_hash),
            HashPart::Str(purpose),
            HashPart::Str(linked_withdrawal_id),
        ],
        32,
    )
}

pub fn monero_nullifier_watch_id(nullifier_hash: &str, spend_domain: &str) -> String {
    domain_hash(
        "MONERO-WATCH-NULLIFIER-WATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(nullifier_hash),
            HashPart::Str(spend_domain),
        ],
        32,
    )
}

pub fn monero_unlock_window_id(
    subject_kind: &str,
    subject_id: &str,
    txid_hash: &str,
    block_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCH-UNLOCK-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(txid_hash),
            HashPart::Int(block_height as i128),
        ],
        32,
    )
}

pub fn monero_finality_window_id(
    subject_kind: &str,
    subject_id: &str,
    start_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCH-FINALITY-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Int(start_height as i128),
        ],
        32,
    )
}

pub fn monero_reorg_alert_id(
    alert_kind: MoneroReorgAlertKind,
    old_block_height: u64,
    old_block_hash: &str,
    new_block_height: u64,
    new_block_hash: &str,
    txid_hash: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-REORG-ALERT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(alert_kind.as_str()),
            HashPart::Int(old_block_height as i128),
            HashPart::Str(old_block_hash),
            HashPart::Int(new_block_height as i128),
            HashPart::Str(new_block_hash),
            HashPart::Str(txid_hash),
        ],
        32,
    )
}

pub fn monero_stuck_withdrawal_id(
    withdrawal_id: &str,
    txid_hash: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-WATCH-STUCK-WITHDRAWAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(txid_hash),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn monero_bridge_event_id(
    event_kind: MoneroBridgeEventKind,
    subject_id: &str,
    l2_height: u64,
    amount_bucket: u64,
    txid_hash: &str,
    nullifier_hash: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-BRIDGE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Int(l2_height as i128),
            HashPart::Int(amount_bucket as i128),
            HashPart::Str(txid_hash),
            HashPart::Str(nullifier_hash),
        ],
        32,
    )
}

pub fn monero_bridge_event_match_id(
    event_id: &str,
    tx_observation_id: &str,
    output_proof_id: &str,
    nullifier_watch_id: &str,
    event_root: &str,
    tx_observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-WATCH-BRIDGE-EVENT-MATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_id),
            HashPart::Str(tx_observation_id),
            HashPart::Str(output_proof_id),
            HashPart::Str(nullifier_watch_id),
            HashPart::Str(event_root),
            HashPart::Str(tx_observation_root),
        ],
        32,
    )
}

pub fn monero_watch_state_root_from_record(record: &Value) -> String {
    monero_watch_payload_root("MONERO-WATCH-STATE", record)
}

pub fn monero_watch_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCH_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn monero_watch_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_WATCH_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn monero_watch_string_set_root(domain: &str, values: &[String]) -> String {
    let ordered = values.iter().cloned().collect::<BTreeSet<_>>();
    merkle_root(
        domain,
        &ordered
            .iter()
            .map(|value| Value::String(monero_watch_string_root(domain, value)))
            .collect::<Vec<_>>(),
    )
}

pub fn monero_watch_amount_bucket(amount: u64) -> u64 {
    if amount == 0 {
        0
    } else {
        amount.div_ceil(MONERO_WATCH_AMOUNT_BUCKET) * MONERO_WATCH_AMOUNT_BUCKET
    }
}

pub fn monero_watch_amount_commitment(amount: u64) -> String {
    domain_hash(
        "MONERO-WATCH-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(monero_watch_amount_bucket(amount) as i128),
        ],
        32,
    )
}

pub fn monero_watch_txid_hash(txid: &str) -> String {
    monero_watch_string_root("MONERO-WATCH-TXID", txid)
}

pub fn monero_watch_key_image_hash(key_image: &str) -> String {
    monero_watch_string_root("MONERO-WATCH-KEY-IMAGE", key_image)
}

pub fn monero_watch_nullifier_hash(nullifier: &str) -> String {
    monero_watch_string_root("MONERO-WATCH-NULLIFIER", nullifier)
}

pub fn monero_watch_observer_public_key(observer_label: &str) -> String {
    monero_watch_string_root("MONERO-WATCH-OBSERVER-PUBLIC-KEY", observer_label)
}

pub fn monero_daemon_endpoint_root(endpoints: &[MoneroDaemonEndpoint]) -> String {
    keyed_record_root(
        "MONERO-WATCH-DAEMON-ENDPOINT",
        endpoints
            .iter()
            .map(|endpoint| (endpoint.endpoint_id.clone(), endpoint.public_record()))
            .collect(),
    )
}

pub fn monero_endpoint_quorum_root(quorums: &[MoneroEndpointQuorum]) -> String {
    keyed_record_root(
        "MONERO-WATCH-ENDPOINT-QUORUM",
        quorums
            .iter()
            .map(|quorum| (quorum.quorum_id.clone(), quorum.public_record()))
            .collect(),
    )
}

pub fn monero_observer_attestation_root(attestations: &[MoneroObserverAttestation]) -> String {
    keyed_record_root(
        "MONERO-WATCH-OBSERVER-ATTESTATION",
        attestations
            .iter()
            .map(|attestation| {
                (
                    attestation.attestation_id.clone(),
                    attestation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn monero_block_observation_root(observations: &[MoneroBlockObservation]) -> String {
    keyed_record_root(
        "MONERO-WATCH-BLOCK-OBSERVATION",
        observations
            .iter()
            .map(|observation| {
                (
                    observation.observation_id.clone(),
                    observation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn monero_block_reconciliation_root(reconciliations: &[MoneroBlockReconciliation]) -> String {
    keyed_record_root(
        "MONERO-WATCH-BLOCK-RECONCILIATION",
        reconciliations
            .iter()
            .map(|reconciliation| {
                (
                    reconciliation.reconciliation_id.clone(),
                    reconciliation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn monero_tx_observation_root(observations: &[MoneroTxObservation]) -> String {
    keyed_record_root(
        "MONERO-WATCH-TX-OBSERVATION",
        observations
            .iter()
            .map(|observation| {
                (
                    observation.observation_id.clone(),
                    observation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn monero_tx_reconciliation_root(reconciliations: &[MoneroTxReconciliation]) -> String {
    keyed_record_root(
        "MONERO-WATCH-TX-RECONCILIATION",
        reconciliations
            .iter()
            .map(|reconciliation| {
                (
                    reconciliation.reconciliation_id.clone(),
                    reconciliation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn monero_output_proof_root(proofs: &[MoneroOutputProofCommitment]) -> String {
    keyed_record_root(
        "MONERO-WATCH-OUTPUT-PROOF",
        proofs
            .iter()
            .map(|proof| (proof.proof_id.clone(), proof.public_record()))
            .collect(),
    )
}

pub fn monero_key_image_watch_root(watches: &[MoneroKeyImageWatch]) -> String {
    keyed_record_root(
        "MONERO-WATCH-KEY-IMAGE-WATCH",
        watches
            .iter()
            .map(|watch| (watch.watch_id.clone(), watch.public_record()))
            .collect(),
    )
}

pub fn monero_nullifier_watch_root(watches: &[MoneroNullifierWatch]) -> String {
    keyed_record_root(
        "MONERO-WATCH-NULLIFIER-WATCH",
        watches
            .iter()
            .map(|watch| (watch.watch_id.clone(), watch.public_record()))
            .collect(),
    )
}

pub fn monero_unlock_window_root(windows: &[MoneroUnlockWindow]) -> String {
    keyed_record_root(
        "MONERO-WATCH-UNLOCK-WINDOW",
        windows
            .iter()
            .map(|window| (window.window_id.clone(), window.public_record()))
            .collect(),
    )
}

pub fn monero_finality_window_root(windows: &[MoneroFinalityWindow]) -> String {
    keyed_record_root(
        "MONERO-WATCH-FINALITY-WINDOW",
        windows
            .iter()
            .map(|window| (window.window_id.clone(), window.public_record()))
            .collect(),
    )
}

pub fn monero_reorg_alert_root(alerts: &[MoneroReorgAlert]) -> String {
    keyed_record_root(
        "MONERO-WATCH-REORG-ALERT",
        alerts
            .iter()
            .map(|alert| (alert.alert_id.clone(), alert.public_record()))
            .collect(),
    )
}

pub fn monero_stuck_withdrawal_root(withdrawals: &[MoneroStuckWithdrawal]) -> String {
    keyed_record_root(
        "MONERO-WATCH-STUCK-WITHDRAWAL",
        withdrawals
            .iter()
            .map(|withdrawal| (withdrawal.stuck_id.clone(), withdrawal.public_record()))
            .collect(),
    )
}

pub fn monero_bridge_event_root(events: &[MoneroBridgeEvent]) -> String {
    keyed_record_root(
        "MONERO-WATCH-BRIDGE-EVENT",
        events
            .iter()
            .map(|event| (event.event_id.clone(), event.public_record()))
            .collect(),
    )
}

pub fn monero_bridge_event_match_root(matches: &[MoneroBridgeEventMatch]) -> String {
    keyed_record_root(
        "MONERO-WATCH-BRIDGE-EVENT-MATCH",
        matches
            .iter()
            .map(|matched| (matched.match_id.clone(), matched.public_record()))
            .collect(),
    )
}

fn keyed_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroWatchResult<()> {
    if value.is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn validate_observer_labels(observer_labels: &[String]) -> MoneroWatchResult<()> {
    if observer_labels.is_empty() {
        return Err("at least one monero observer is required".to_string());
    }
    let mut seen = BTreeSet::new();
    if observer_labels
        .iter()
        .any(|label| label.is_empty() || !seen.insert(label.clone()))
    {
        return Err("monero observers must be non-empty and unique".to_string());
    }
    Ok(())
}

fn ordered_labels(labels: &[String]) -> Vec<String> {
    labels
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn confirmations(tip_height: u64, block_height: u64) -> u64 {
    tip_height.saturating_sub(block_height).saturating_add(1)
}

fn block_status(confirmations: u64, finality_depth: u64) -> String {
    if confirmations >= finality_depth {
        "final"
    } else {
        "observed"
    }
    .to_string()
}

fn reconciliation_status(
    vote_count: u64,
    dissenting_vote_count: u64,
    confirmations: u64,
    quorum_required: u64,
    finality_depth: u64,
) -> String {
    if vote_count < quorum_required {
        "insufficient_quorum"
    } else if dissenting_vote_count > 0 {
        "quorum_with_dissent"
    } else if confirmations >= finality_depth {
        "final"
    } else {
        "quorum"
    }
    .to_string()
}

fn unlock_status(current_height: u64, spendable_at_height: u64, expires_at_height: u64) -> String {
    if expires_at_height > 0 && current_height > expires_at_height {
        "expired"
    } else if current_height >= spendable_at_height {
        "spendable"
    } else {
        "locked"
    }
    .to_string()
}

fn finality_status(current_height: u64, soft_final_height: u64, hard_final_height: u64) -> String {
    if current_height >= hard_final_height {
        "hard_final"
    } else if current_height >= soft_final_height {
        "soft_final"
    } else {
        "pending"
    }
    .to_string()
}

fn stuck_status(
    current_height: u64,
    expected_inclusion_height: u64,
    stuck_blocks: u64,
    last_seen_txid_hash: Option<&String>,
) -> String {
    if last_seen_txid_hash.is_some() {
        "observed"
    } else if current_height >= expected_inclusion_height.saturating_add(stuck_blocks) {
        "stuck"
    } else {
        "pending"
    }
    .to_string()
}

fn refresh_unlock_windows(
    windows: &mut BTreeMap<String, MoneroUnlockWindow>,
    height: u64,
    finality_depth: u64,
) {
    for window in windows.values_mut() {
        window.current_height = height;
        window.confirmations = confirmations(height, window.block_height);
        window.required_confirmations = finality_depth;
        window.status = unlock_status(height, window.spendable_at_height, window.expires_at_height);
    }
}

fn refresh_finality_windows(windows: &mut BTreeMap<String, MoneroFinalityWindow>, height: u64) {
    for window in windows.values_mut() {
        window.current_height = height;
        window.status = finality_status(height, window.soft_final_height, window.hard_final_height);
    }
}

fn refresh_stuck_withdrawals(
    withdrawals: &mut BTreeMap<String, MoneroStuckWithdrawal>,
    height: u64,
    stuck_blocks: u64,
) {
    for withdrawal in withdrawals.values_mut() {
        withdrawal.status = stuck_status(
            height,
            withdrawal.expected_inclusion_height,
            stuck_blocks,
            withdrawal.last_seen_txid_hash.as_ref(),
        );
    }
}
