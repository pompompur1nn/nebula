use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        crypto_policy_root, public_key_for_label, sign_watchtower_authorization,
        verify_watchtower_authorization, Authorization, CryptoRole,
    },
    hash::{domain_hash, merkle_root, HashPart},
    settlement::{monero_address_hash, monero_txid_hash, AnchorSubmission, BridgeState},
    CHAIN_ID,
};

pub type MoneroResult<T> = Result<T, String>;

pub const MONERO_FINALITY_DEPTH: u64 = 10;
pub const MONERO_RESERVE_BUCKET: u64 = 10_000;
pub const MONERO_REORG_CHALLENGE_DEPTH: u64 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroRpcEndpoint {
    pub endpoint_id: String,
    pub operator_label: String,
    pub endpoint_commitment: String,
    pub network: String,
    pub advertised_height: u64,
    pub pruning_mode: String,
    pub tls_policy: String,
    pub status: String,
}

impl MoneroRpcEndpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_endpoint",
            "chain_id": CHAIN_ID,
            "endpoint_id": self.endpoint_id,
            "operator_label": self.operator_label,
            "endpoint_commitment": self.endpoint_commitment,
            "network": self.network,
            "advertised_height": self.advertised_height,
            "pruning_mode": self.pruning_mode,
            "tls_policy": self.tls_policy,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroRpcObservation {
    pub observation_id: String,
    pub endpoint_id: String,
    pub request_kind: String,
    pub request_root: String,
    pub response_root: String,
    pub advertised_height: u64,
    pub observed_tip_hash: String,
    pub latency_bucket_ms: u64,
    pub observer_label: String,
    pub observer_signature_root: String,
    pub observed_at_l2_height: u64,
    pub status: String,
}

impl MoneroRpcObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_rpc_observation",
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "endpoint_id": self.endpoint_id,
            "request_kind": self.request_kind,
            "request_root": self.request_root,
            "response_root": self.response_root,
            "advertised_height": self.advertised_height,
            "observed_tip_hash": self.observed_tip_hash,
            "latency_bucket_ms": self.latency_bucket_ms,
            "observer_label": self.observer_label,
            "observer_signature_root": self.observer_signature_root,
            "observed_at_l2_height": self.observed_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroZmqObservation {
    pub observation_id: String,
    pub endpoint_id: String,
    pub topic: String,
    pub sequence: u64,
    pub payload_hash: String,
    pub linked_block_height: u64,
    pub linked_block_hash: String,
    pub observer_label: String,
    pub observer_signature_root: String,
    pub observed_at_l2_height: u64,
    pub status: String,
}

impl MoneroZmqObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_zmq_observation",
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "endpoint_id": self.endpoint_id,
            "topic": self.topic,
            "sequence": self.sequence,
            "payload_hash": self.payload_hash,
            "linked_block_height": self.linked_block_height,
            "linked_block_hash": self.linked_block_hash,
            "observer_label": self.observer_label,
            "observer_signature_root": self.observer_signature_root,
            "observed_at_l2_height": self.observed_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBlockObservation {
    pub observation_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub tx_count: u64,
    pub difficulty_bucket: u64,
    pub cumulative_difficulty_hash: String,
    pub observed_tip_hash: String,
    pub confirmations: u64,
    pub endpoint_id: String,
    pub observer_labels: Vec<String>,
    pub observer_signature_root: String,
    pub observed_at_l2_height: u64,
    pub status: String,
}

impl MoneroBlockObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_block_observation",
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "previous_block_hash": self.previous_block_hash,
            "tx_count": self.tx_count,
            "difficulty_bucket": self.difficulty_bucket,
            "cumulative_difficulty_hash": self.cumulative_difficulty_hash,
            "observed_tip_hash": self.observed_tip_hash,
            "confirmations": self.confirmations,
            "endpoint_id": self.endpoint_id,
            "observer_count": self.observer_labels.len() as u64,
            "observer_signature_root": self.observer_signature_root,
            "observed_at_l2_height": self.observed_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroTxObservation {
    pub observation_id: String,
    pub txid_hash: String,
    pub tx_kind: String,
    pub amount_bucket: u64,
    pub address_hash: String,
    pub anchor_commitment: Option<String>,
    pub bridge_event_id: Option<String>,
    pub block_height: u64,
    pub block_hash: String,
    pub unlock_height: u64,
    pub confirmations: u64,
    pub observer_labels: Vec<String>,
    pub observer_signature_root: String,
    pub observed_at_l2_height: u64,
    pub status: String,
}

impl MoneroTxObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_tx_observation",
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "txid_hash": self.txid_hash,
            "tx_kind": self.tx_kind,
            "amount_bucket": self.amount_bucket,
            "address_hash": self.address_hash,
            "anchor_commitment": self.anchor_commitment,
            "bridge_event_id": self.bridge_event_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "unlock_height": self.unlock_height,
            "confirmations": self.confirmations,
            "observer_count": self.observer_labels.len() as u64,
            "observer_signature_root": self.observer_signature_root,
            "observed_at_l2_height": self.observed_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroAnchorObservation {
    pub observation_id: String,
    pub anchor_id: String,
    pub anchor_commitment: String,
    pub checkpoint_root: String,
    pub txid_hash: String,
    pub monero_block_height: u64,
    pub monero_block_hash: String,
    pub confirmations: u64,
    pub finality_depth: u64,
    pub status: String,
    pub observer_signature_root: String,
}

impl MoneroAnchorObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_anchor_observation",
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "anchor_id": self.anchor_id,
            "anchor_commitment": self.anchor_commitment,
            "checkpoint_root": self.checkpoint_root,
            "txid_hash": self.txid_hash,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash": self.monero_block_hash,
            "confirmations": self.confirmations,
            "finality_depth": self.finality_depth,
            "status": self.status,
            "observer_signature_root": self.observer_signature_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroWithdrawalObservation {
    pub observation_id: String,
    pub withdrawal_id: String,
    pub txid_hash: String,
    pub amount_bucket: u64,
    pub recipient_address_hash: String,
    pub monero_block_height: u64,
    pub monero_block_hash: String,
    pub confirmations: u64,
    pub finality_depth: u64,
    pub status: String,
    pub observer_signature_root: String,
}

impl MoneroWithdrawalObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_withdrawal_observation",
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "withdrawal_id": self.withdrawal_id,
            "txid_hash": self.txid_hash,
            "amount_bucket": self.amount_bucket,
            "recipient_address_hash": self.recipient_address_hash,
            "monero_block_height": self.monero_block_height,
            "monero_block_hash": self.monero_block_hash,
            "confirmations": self.confirmations,
            "finality_depth": self.finality_depth,
            "status": self.status,
            "observer_signature_root": self.observer_signature_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReserveReport {
    pub report_id: String,
    pub reserve_asset_id: String,
    pub reserve_address_hash_root: String,
    pub reported_reserve_amount_bucket: u64,
    pub circulating_wrapped_amount: u64,
    pub queued_withdrawal_amount: u64,
    pub submitted_withdrawal_amount: u64,
    pub completed_withdrawal_amount: u64,
    pub liability_amount: u64,
    pub coverage_bps: u64,
    pub status: String,
    pub reporter_labels: Vec<String>,
    pub reporter_signature_root: String,
    pub reported_at_l2_height: u64,
}

impl MoneroReserveReport {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_reserve_report",
            "chain_id": CHAIN_ID,
            "report_id": self.report_id,
            "reserve_asset_id": self.reserve_asset_id,
            "reserve_address_hash_root": self.reserve_address_hash_root,
            "reported_reserve_amount_bucket": self.reported_reserve_amount_bucket,
            "circulating_wrapped_amount": self.circulating_wrapped_amount,
            "queued_withdrawal_amount": self.queued_withdrawal_amount,
            "submitted_withdrawal_amount": self.submitted_withdrawal_amount,
            "completed_withdrawal_amount": self.completed_withdrawal_amount,
            "liability_amount": self.liability_amount,
            "coverage_bps": self.coverage_bps,
            "status": self.status,
            "reporter_count": self.reporter_labels.len() as u64,
            "reporter_signature_root": self.reporter_signature_root,
            "reported_at_l2_height": self.reported_at_l2_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroReorgEvidence {
    pub evidence_id: String,
    pub txid_hash: String,
    pub old_block_height: u64,
    pub old_block_hash: String,
    pub new_block_height: u64,
    pub new_block_hash: String,
    pub affected_anchor_id: Option<String>,
    pub affected_withdrawal_id: Option<String>,
    pub reporter_label: String,
    pub reporter_public_key: String,
    pub reported_at_l2_height: u64,
    pub depth: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl MoneroReorgEvidence {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "monero_reorg_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "txid_hash": self.txid_hash,
            "old_block_height": self.old_block_height,
            "old_block_hash": self.old_block_hash,
            "new_block_height": self.new_block_height,
            "new_block_hash": self.new_block_hash,
            "affected_anchor_id": self.affected_anchor_id,
            "affected_withdrawal_id": self.affected_withdrawal_id,
            "reporter_label": self.reporter_label,
            "reporter_public_key": self.reporter_public_key,
            "reported_at_l2_height": self.reported_at_l2_height,
            "depth": self.depth,
            "status": self.status,
        })
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            "MONERO-REORG-EVIDENCE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("monero reorg evidence record object");
        object.insert(
            "evidence_root".to_string(),
            Value::String(self.evidence_root()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn verify_authorization(&self) -> bool {
        verify_watchtower_authorization(
            &self.reporter_public_key,
            "monero_reorg_evidence",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroMonitorState {
    pub network: String,
    pub height: u64,
    pub endpoints: BTreeMap<String, MoneroRpcEndpoint>,
    pub rpc_observations: BTreeMap<String, MoneroRpcObservation>,
    pub zmq_observations: BTreeMap<String, MoneroZmqObservation>,
    pub block_observations: BTreeMap<String, MoneroBlockObservation>,
    pub tx_observations: BTreeMap<String, MoneroTxObservation>,
    pub anchor_observations: BTreeMap<String, MoneroAnchorObservation>,
    pub withdrawal_observations: BTreeMap<String, MoneroWithdrawalObservation>,
    pub reserve_reports: BTreeMap<String, MoneroReserveReport>,
    pub reorg_evidence: BTreeMap<String, MoneroReorgEvidence>,
}

impl MoneroMonitorState {
    pub fn new(network: impl Into<String>) -> Self {
        Self {
            network: network.into(),
            ..Self::default()
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn register_endpoint(
        &mut self,
        operator_label: &str,
        endpoint_route: &str,
        advertised_height: u64,
        pruning_mode: &str,
        tls_policy: &str,
    ) -> MoneroResult<MoneroRpcEndpoint> {
        if operator_label.is_empty() {
            return Err("monero endpoint operator label is required".to_string());
        }
        let endpoint_commitment = domain_hash(
            "MONERO-ENDPOINT-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(operator_label),
                HashPart::Str(endpoint_route),
                HashPart::Str(&self.network),
            ],
            32,
        );
        let endpoint_id = domain_hash(
            "MONERO-ENDPOINT-ID",
            &[
                HashPart::Str(operator_label),
                HashPart::Str(&endpoint_commitment),
                HashPart::Str(pruning_mode),
                HashPart::Str(tls_policy),
            ],
            32,
        );
        let endpoint = MoneroRpcEndpoint {
            endpoint_id: endpoint_id.clone(),
            operator_label: operator_label.to_string(),
            endpoint_commitment,
            network: self.network.clone(),
            advertised_height,
            pruning_mode: pruning_mode.to_string(),
            tls_policy: tls_policy.to_string(),
            status: "active".to_string(),
        };
        self.endpoints.insert(endpoint_id, endpoint.clone());
        Ok(endpoint)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_rpc_observation(
        &mut self,
        endpoint_id: &str,
        request_kind: &str,
        request: &Value,
        response: &Value,
        advertised_height: u64,
        observed_tip_hash: &str,
        latency_ms: u64,
        observer_label: &str,
    ) -> MoneroResult<MoneroRpcObservation> {
        if !self.endpoints.contains_key(endpoint_id) {
            return Err("unknown monero rpc endpoint".to_string());
        }
        if request_kind.is_empty() || observer_label.is_empty() {
            return Err("rpc observation request kind and observer are required".to_string());
        }
        let request_root = domain_hash("MONERO-RPC-REQUEST", &[HashPart::Json(request)], 32);
        let response_root = domain_hash("MONERO-RPC-RESPONSE", &[HashPart::Json(response)], 32);
        let latency_bucket_ms = monero_latency_bucket(latency_ms);
        let observer_labels = vec![observer_label.to_string()];
        let payload = json!({
            "endpoint_id": endpoint_id,
            "request_kind": request_kind,
            "request_root": request_root,
            "response_root": response_root,
            "advertised_height": advertised_height,
            "observed_tip_hash": observed_tip_hash,
            "latency_bucket_ms": latency_bucket_ms,
        });
        let observer_signature_root =
            monero_observer_signature_root("monero_rpc_observation", &payload, &observer_labels);
        let observation_id = monero_rpc_observation_id(
            endpoint_id,
            request_kind,
            &request_root,
            &response_root,
            advertised_height,
        );
        let observation = MoneroRpcObservation {
            observation_id: observation_id.clone(),
            endpoint_id: endpoint_id.to_string(),
            request_kind: request_kind.to_string(),
            request_root,
            response_root,
            advertised_height,
            observed_tip_hash: observed_tip_hash.to_string(),
            latency_bucket_ms,
            observer_label: observer_label.to_string(),
            observer_signature_root,
            observed_at_l2_height: self.height,
            status: if response.get("error").is_some() {
                "error"
            } else {
                "observed"
            }
            .to_string(),
        };
        self.rpc_observations
            .insert(observation_id, observation.clone());
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_zmq_observation(
        &mut self,
        endpoint_id: &str,
        topic: &str,
        sequence: u64,
        payload: &Value,
        linked_block_height: u64,
        linked_block_hash: &str,
        observer_label: &str,
    ) -> MoneroResult<MoneroZmqObservation> {
        if !self.endpoints.contains_key(endpoint_id) {
            return Err("unknown monero zmq endpoint".to_string());
        }
        if topic.is_empty() || observer_label.is_empty() {
            return Err("zmq observation topic and observer are required".to_string());
        }
        let payload_hash = domain_hash("MONERO-ZMQ-PAYLOAD", &[HashPart::Json(payload)], 32);
        let observer_labels = vec![observer_label.to_string()];
        let signature_payload = json!({
            "endpoint_id": endpoint_id,
            "topic": topic,
            "sequence": sequence,
            "payload_hash": payload_hash,
            "linked_block_height": linked_block_height,
            "linked_block_hash": linked_block_hash,
        });
        let observer_signature_root = monero_observer_signature_root(
            "monero_zmq_observation",
            &signature_payload,
            &observer_labels,
        );
        let observation_id = monero_zmq_observation_id(endpoint_id, topic, sequence, &payload_hash);
        let observation = MoneroZmqObservation {
            observation_id: observation_id.clone(),
            endpoint_id: endpoint_id.to_string(),
            topic: topic.to_string(),
            sequence,
            payload_hash,
            linked_block_height,
            linked_block_hash: linked_block_hash.to_string(),
            observer_label: observer_label.to_string(),
            observer_signature_root,
            observed_at_l2_height: self.height,
            status: "observed".to_string(),
        };
        self.zmq_observations
            .insert(observation_id, observation.clone());
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_block(
        &mut self,
        block_height: u64,
        block_hash: &str,
        previous_block_hash: &str,
        tx_count: u64,
        difficulty: u64,
        cumulative_difficulty: &str,
        observed_tip_hash: &str,
        confirmations: u64,
        endpoint_id: &str,
        observer_labels: &[String],
    ) -> MoneroResult<MoneroBlockObservation> {
        if !self.endpoints.contains_key(endpoint_id) {
            return Err("unknown monero block observation endpoint".to_string());
        }
        if block_hash.is_empty() || observed_tip_hash.is_empty() {
            return Err("monero block hash and tip hash are required".to_string());
        }
        validate_observers(observer_labels)?;
        let difficulty_bucket = monero_difficulty_bucket(difficulty);
        let cumulative_difficulty_hash = domain_hash(
            "MONERO-CUMULATIVE-DIFFICULTY",
            &[HashPart::Str(cumulative_difficulty)],
            32,
        );
        let payload = json!({
            "block_height": block_height,
            "block_hash": block_hash,
            "previous_block_hash": previous_block_hash,
            "tx_count": tx_count,
            "difficulty_bucket": difficulty_bucket,
            "cumulative_difficulty_hash": cumulative_difficulty_hash,
            "observed_tip_hash": observed_tip_hash,
            "confirmations": confirmations,
            "endpoint_id": endpoint_id,
        });
        let observer_signature_root =
            monero_observer_signature_root("monero_block_observation", &payload, observer_labels);
        let observation_id = monero_block_observation_id(block_height, block_hash, endpoint_id);
        let observation = MoneroBlockObservation {
            observation_id: observation_id.clone(),
            block_height,
            block_hash: block_hash.to_string(),
            previous_block_hash: previous_block_hash.to_string(),
            tx_count,
            difficulty_bucket,
            cumulative_difficulty_hash,
            observed_tip_hash: observed_tip_hash.to_string(),
            confirmations,
            endpoint_id: endpoint_id.to_string(),
            observer_labels: observer_labels.to_vec(),
            observer_signature_root,
            observed_at_l2_height: self.height,
            status: if confirmations >= MONERO_FINALITY_DEPTH {
                "final"
            } else {
                "observed"
            }
            .to_string(),
        };
        self.block_observations
            .insert(observation_id, observation.clone());
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_tx(
        &mut self,
        txid: &str,
        tx_kind: &str,
        amount: u64,
        address: &str,
        anchor_commitment: Option<String>,
        bridge_event_id: Option<String>,
        block_height: u64,
        block_hash: &str,
        unlock_height: u64,
        confirmations: u64,
        observer_labels: &[String],
    ) -> MoneroResult<MoneroTxObservation> {
        if txid.is_empty() {
            return Err("monero tx observation txid is required".to_string());
        }
        validate_observers(observer_labels)?;
        let txid_hash = monero_txid_hash(txid);
        let amount_bucket = monero_amount_bucket(amount);
        let address_hash = monero_address_hash(address);
        let observer_signature_root = monero_observer_signature_root(
            "monero_tx_observation",
            &json!({
                "txid_hash": txid_hash,
                "tx_kind": tx_kind,
                "amount_bucket": amount_bucket,
                "address_hash": address_hash,
                "block_height": block_height,
                "block_hash": block_hash,
                "confirmations": confirmations,
            }),
            observer_labels,
        );
        let observation_id =
            monero_tx_observation_id(&txid_hash, tx_kind, block_height, block_hash);
        let observation = MoneroTxObservation {
            observation_id: observation_id.clone(),
            txid_hash,
            tx_kind: tx_kind.to_string(),
            amount_bucket,
            address_hash,
            anchor_commitment,
            bridge_event_id,
            block_height,
            block_hash: block_hash.to_string(),
            unlock_height,
            confirmations,
            observer_labels: observer_labels.to_vec(),
            observer_signature_root,
            observed_at_l2_height: self.height,
            status: if confirmations >= MONERO_FINALITY_DEPTH {
                "final"
            } else {
                "observed"
            }
            .to_string(),
        };
        self.tx_observations
            .insert(observation_id, observation.clone());
        Ok(observation)
    }

    pub fn observe_anchor(
        &mut self,
        submission: &AnchorSubmission,
        monero_block_height: u64,
        monero_block_hash: &str,
        confirmations: u64,
        observer_labels: &[String],
    ) -> MoneroResult<MoneroAnchorObservation> {
        validate_observers(observer_labels)?;
        let txid_hash = submission.monero_txid_hash();
        let observer_signature_root = monero_observer_signature_root(
            "monero_anchor_observation",
            &json!({
                "anchor_id": submission.anchor_id,
                "anchor_commitment": submission.anchor_commitment,
                "checkpoint_root": submission.checkpoint_root,
                "txid_hash": txid_hash,
                "monero_block_height": monero_block_height,
                "monero_block_hash": monero_block_hash,
                "confirmations": confirmations,
            }),
            observer_labels,
        );
        let observation_id = monero_anchor_observation_id(&submission.anchor_id, &txid_hash);
        let observation = MoneroAnchorObservation {
            observation_id: observation_id.clone(),
            anchor_id: submission.anchor_id.clone(),
            anchor_commitment: submission.anchor_commitment.clone(),
            checkpoint_root: submission.checkpoint_root.clone(),
            txid_hash,
            monero_block_height,
            monero_block_hash: monero_block_hash.to_string(),
            confirmations,
            finality_depth: MONERO_FINALITY_DEPTH,
            status: if confirmations >= MONERO_FINALITY_DEPTH {
                "final"
            } else {
                "observed"
            }
            .to_string(),
            observer_signature_root,
        };
        self.anchor_observations
            .insert(observation_id, observation.clone());
        Ok(observation)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_withdrawal(
        &mut self,
        withdrawal_id: &str,
        txid: &str,
        amount: u64,
        recipient_address: &str,
        monero_block_height: u64,
        monero_block_hash: &str,
        confirmations: u64,
        observer_labels: &[String],
    ) -> MoneroResult<MoneroWithdrawalObservation> {
        if withdrawal_id.is_empty() {
            return Err("withdrawal observation id is required".to_string());
        }
        validate_observers(observer_labels)?;
        let txid_hash = monero_txid_hash(txid);
        let amount_bucket = monero_amount_bucket(amount);
        let recipient_address_hash = monero_address_hash(recipient_address);
        let observer_signature_root = monero_observer_signature_root(
            "monero_withdrawal_observation",
            &json!({
                "withdrawal_id": withdrawal_id,
                "txid_hash": txid_hash,
                "amount_bucket": amount_bucket,
                "recipient_address_hash": recipient_address_hash,
                "monero_block_height": monero_block_height,
                "monero_block_hash": monero_block_hash,
                "confirmations": confirmations,
            }),
            observer_labels,
        );
        let observation_id = monero_withdrawal_observation_id(withdrawal_id, &txid_hash);
        let observation = MoneroWithdrawalObservation {
            observation_id: observation_id.clone(),
            withdrawal_id: withdrawal_id.to_string(),
            txid_hash,
            amount_bucket,
            recipient_address_hash,
            monero_block_height,
            monero_block_hash: monero_block_hash.to_string(),
            confirmations,
            finality_depth: MONERO_FINALITY_DEPTH,
            status: if confirmations >= MONERO_FINALITY_DEPTH {
                "final"
            } else {
                "observed"
            }
            .to_string(),
            observer_signature_root,
        };
        self.withdrawal_observations
            .insert(observation_id, observation.clone());
        Ok(observation)
    }

    pub fn publish_reserve_report(
        &mut self,
        bridge: &BridgeState,
        reserve_addresses: &[String],
        reported_reserve_amount: u64,
        reporter_labels: &[String],
    ) -> MoneroResult<MoneroReserveReport> {
        validate_observers(reporter_labels)?;
        let reserve_address_hashes = reserve_addresses
            .iter()
            .map(|address| Value::String(monero_address_hash(address)))
            .collect::<Vec<_>>();
        let reserve_address_hash_root =
            merkle_root("MONERO-RESERVE-ADDRESS", &reserve_address_hashes);
        let reported_reserve_amount_bucket = monero_amount_bucket(reported_reserve_amount);
        let circulating_wrapped_amount = bridge
            .observations
            .values()
            .filter(|observation| observation.status == "observed")
            .map(|observation| observation.amount)
            .sum::<u64>();
        let queued_withdrawal_amount = bridge
            .withdrawals
            .values()
            .filter(|withdrawal| withdrawal.status == "queued")
            .map(|withdrawal| withdrawal.amount)
            .sum::<u64>();
        let submitted_withdrawal_amount = bridge
            .withdrawals
            .values()
            .filter(|withdrawal| withdrawal.status == "released")
            .map(|withdrawal| withdrawal.amount)
            .sum::<u64>();
        let completed_withdrawal_amount = bridge
            .withdrawals
            .values()
            .filter(|withdrawal| withdrawal.status == "completed")
            .map(|withdrawal| withdrawal.amount)
            .sum::<u64>();
        let liability_amount = circulating_wrapped_amount
            .saturating_add(queued_withdrawal_amount)
            .saturating_add(submitted_withdrawal_amount)
            .saturating_sub(completed_withdrawal_amount);
        let coverage_bps = if liability_amount == 0 {
            10_000
        } else {
            reported_reserve_amount_bucket.saturating_mul(10_000) / liability_amount
        };
        let status = if coverage_bps >= 10_000 {
            "healthy"
        } else if coverage_bps >= 9_000 {
            "watch"
        } else {
            "underreserved"
        }
        .to_string();
        let payload = json!({
            "reserve_asset_id": bridge.wrapped_xmr_asset_id,
            "reserve_address_hash_root": reserve_address_hash_root,
            "reported_reserve_amount_bucket": reported_reserve_amount_bucket,
            "liability_amount": liability_amount,
            "coverage_bps": coverage_bps,
            "status": status,
        });
        let reporter_signature_root =
            monero_observer_signature_root("monero_reserve_report", &payload, reporter_labels);
        let report_id = monero_reserve_report_id(
            &bridge.wrapped_xmr_asset_id,
            &reserve_address_hash_root,
            reported_reserve_amount_bucket,
            liability_amount,
        );
        let report = MoneroReserveReport {
            report_id: report_id.clone(),
            reserve_asset_id: bridge.wrapped_xmr_asset_id.clone(),
            reserve_address_hash_root,
            reported_reserve_amount_bucket,
            circulating_wrapped_amount,
            queued_withdrawal_amount,
            submitted_withdrawal_amount,
            completed_withdrawal_amount,
            liability_amount,
            coverage_bps,
            status,
            reporter_labels: reporter_labels.to_vec(),
            reporter_signature_root,
            reported_at_l2_height: self.height,
        };
        self.reserve_reports.insert(report_id, report.clone());
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn report_reorg(
        &mut self,
        txid: &str,
        old_block_height: u64,
        old_block_hash: &str,
        new_block_height: u64,
        new_block_hash: &str,
        affected_anchor_id: Option<String>,
        affected_withdrawal_id: Option<String>,
        reporter_label: &str,
    ) -> MoneroResult<MoneroReorgEvidence> {
        if old_block_hash == new_block_hash && old_block_height == new_block_height {
            return Err("reorg evidence requires conflicting block observations".to_string());
        }
        let txid_hash = monero_txid_hash(txid);
        let reporter_key = public_key_for_label(CryptoRole::WatchtowerSignature, reporter_label);
        let depth = old_block_height.abs_diff(new_block_height);
        let evidence_id = monero_reorg_evidence_id(
            &txid_hash,
            old_block_height,
            old_block_hash,
            new_block_height,
            new_block_hash,
        );
        let mut evidence = MoneroReorgEvidence {
            evidence_id: evidence_id.clone(),
            txid_hash,
            old_block_height,
            old_block_hash: old_block_hash.to_string(),
            new_block_height,
            new_block_hash: new_block_hash.to_string(),
            affected_anchor_id,
            affected_withdrawal_id,
            reporter_label: reporter_label.to_string(),
            reporter_public_key: reporter_key.public_key,
            reported_at_l2_height: self.height,
            depth,
            status: if depth >= MONERO_REORG_CHALLENGE_DEPTH {
                "slashable"
            } else {
                "watch"
            }
            .to_string(),
            authorization: Authorization {
                signer_label: reporter_label.to_string(),
                auth_scheme: CryptoRole::WatchtowerSignature.scheme().to_string(),
                auth_public_key: String::new(),
                auth_transcript_hash: String::new(),
                auth_signature: String::new(),
            },
        };
        evidence.authorization = sign_watchtower_authorization(
            reporter_label,
            "monero_reorg_evidence",
            &evidence.unsigned_record(),
        );
        if !evidence.verify_authorization() {
            return Err("monero reorg evidence authorization failed".to_string());
        }
        self.reorg_evidence.insert(evidence_id, evidence.clone());
        Ok(evidence)
    }

    pub fn endpoint_root(&self) -> String {
        merkle_root(
            "MONERO-ENDPOINT",
            &self
                .endpoints
                .values()
                .map(MoneroRpcEndpoint::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn tx_observation_root(&self) -> String {
        merkle_root(
            "MONERO-TX-OBSERVATION",
            &self
                .tx_observations
                .values()
                .map(MoneroTxObservation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn rpc_observation_root(&self) -> String {
        merkle_root(
            "MONERO-RPC-OBSERVATION",
            &self
                .rpc_observations
                .values()
                .map(MoneroRpcObservation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn zmq_observation_root(&self) -> String {
        merkle_root(
            "MONERO-ZMQ-OBSERVATION",
            &self
                .zmq_observations
                .values()
                .map(MoneroZmqObservation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn block_observation_root(&self) -> String {
        merkle_root(
            "MONERO-BLOCK-OBSERVATION",
            &self
                .block_observations
                .values()
                .map(MoneroBlockObservation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn anchor_observation_root(&self) -> String {
        merkle_root(
            "MONERO-ANCHOR-OBSERVATION",
            &self
                .anchor_observations
                .values()
                .map(MoneroAnchorObservation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn withdrawal_observation_root(&self) -> String {
        merkle_root(
            "MONERO-WITHDRAWAL-OBSERVATION",
            &self
                .withdrawal_observations
                .values()
                .map(MoneroWithdrawalObservation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn reserve_report_root(&self) -> String {
        merkle_root(
            "MONERO-RESERVE-REPORT",
            &self
                .reserve_reports
                .values()
                .map(MoneroReserveReport::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn reorg_evidence_root(&self) -> String {
        merkle_root(
            "MONERO-REORG-EVIDENCE",
            &self
                .reorg_evidence
                .values()
                .map(MoneroReorgEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-MONITOR-STATE",
            &[
                HashPart::Str(&self.endpoint_root()),
                HashPart::Str(&self.rpc_observation_root()),
                HashPart::Str(&self.zmq_observation_root()),
                HashPart::Str(&self.block_observation_root()),
                HashPart::Str(&self.tx_observation_root()),
                HashPart::Str(&self.anchor_observation_root()),
                HashPart::Str(&self.withdrawal_observation_root()),
                HashPart::Str(&self.reserve_report_root()),
                HashPart::Str(&self.reorg_evidence_root()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_monitor_state",
            "chain_id": CHAIN_ID,
            "network": self.network,
            "height": self.height,
            "endpoint_root": self.endpoint_root(),
            "rpc_observation_root": self.rpc_observation_root(),
            "zmq_observation_root": self.zmq_observation_root(),
            "block_observation_root": self.block_observation_root(),
            "tx_observation_root": self.tx_observation_root(),
            "anchor_observation_root": self.anchor_observation_root(),
            "withdrawal_observation_root": self.withdrawal_observation_root(),
            "reserve_report_root": self.reserve_report_root(),
            "reorg_evidence_root": self.reorg_evidence_root(),
            "monero_monitor_state_root": self.state_root(),
            "endpoint_count": self.endpoints.len() as u64,
            "rpc_observation_count": self.rpc_observations.len() as u64,
            "zmq_observation_count": self.zmq_observations.len() as u64,
            "block_observation_count": self.block_observations.len() as u64,
            "tx_observation_count": self.tx_observations.len() as u64,
            "anchor_observation_count": self.anchor_observations.len() as u64,
            "withdrawal_observation_count": self.withdrawal_observations.len() as u64,
            "reserve_report_count": self.reserve_reports.len() as u64,
            "reorg_evidence_count": self.reorg_evidence.len() as u64,
        })
    }
}

pub fn monero_amount_bucket(amount: u64) -> u64 {
    if amount == 0 {
        0
    } else {
        amount.div_ceil(MONERO_RESERVE_BUCKET) * MONERO_RESERVE_BUCKET
    }
}

pub fn monero_latency_bucket(latency_ms: u64) -> u64 {
    if latency_ms == 0 {
        0
    } else if latency_ms <= 25 {
        25
    } else if latency_ms <= 50 {
        50
    } else if latency_ms <= 100 {
        100
    } else if latency_ms <= 250 {
        250
    } else if latency_ms <= 500 {
        500
    } else if latency_ms <= 1_000 {
        1_000
    } else {
        latency_ms.div_ceil(1_000) * 1_000
    }
}

pub fn monero_difficulty_bucket(difficulty: u64) -> u64 {
    if difficulty == 0 {
        0
    } else if difficulty <= 1_000 {
        difficulty.div_ceil(100) * 100
    } else if difficulty <= 1_000_000 {
        difficulty.div_ceil(10_000) * 10_000
    } else {
        difficulty.div_ceil(1_000_000) * 1_000_000
    }
}

pub fn monero_endpoint_id(operator_label: &str, endpoint_commitment: &str) -> String {
    domain_hash(
        "MONERO-ENDPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(endpoint_commitment),
        ],
        32,
    )
}

pub fn monero_rpc_observation_id(
    endpoint_id: &str,
    request_kind: &str,
    request_root: &str,
    response_root: &str,
    advertised_height: u64,
) -> String {
    domain_hash(
        "MONERO-RPC-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(endpoint_id),
            HashPart::Str(request_kind),
            HashPart::Str(request_root),
            HashPart::Str(response_root),
            HashPart::Int(advertised_height as i128),
        ],
        32,
    )
}

pub fn monero_zmq_observation_id(
    endpoint_id: &str,
    topic: &str,
    sequence: u64,
    payload_hash: &str,
) -> String {
    domain_hash(
        "MONERO-ZMQ-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(endpoint_id),
            HashPart::Str(topic),
            HashPart::Int(sequence as i128),
            HashPart::Str(payload_hash),
        ],
        32,
    )
}

pub fn monero_block_observation_id(
    block_height: u64,
    block_hash: &str,
    endpoint_id: &str,
) -> String {
    domain_hash(
        "MONERO-BLOCK-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(endpoint_id),
        ],
        32,
    )
}

pub fn monero_tx_observation_id(
    txid_hash: &str,
    tx_kind: &str,
    block_height: u64,
    block_hash: &str,
) -> String {
    domain_hash(
        "MONERO-TX-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(txid_hash),
            HashPart::Str(tx_kind),
            HashPart::Int(block_height as i128),
            HashPart::Str(block_hash),
        ],
        32,
    )
}

pub fn monero_anchor_observation_id(anchor_id: &str, txid_hash: &str) -> String {
    domain_hash(
        "MONERO-ANCHOR-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(anchor_id),
            HashPart::Str(txid_hash),
        ],
        32,
    )
}

pub fn monero_withdrawal_observation_id(withdrawal_id: &str, txid_hash: &str) -> String {
    domain_hash(
        "MONERO-WITHDRAWAL-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(withdrawal_id),
            HashPart::Str(txid_hash),
        ],
        32,
    )
}

pub fn monero_reserve_report_id(
    reserve_asset_id: &str,
    reserve_address_hash_root: &str,
    reserve_amount_bucket: u64,
    liability_amount: u64,
) -> String {
    domain_hash(
        "MONERO-RESERVE-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reserve_asset_id),
            HashPart::Str(reserve_address_hash_root),
            HashPart::Int(reserve_amount_bucket as i128),
            HashPart::Int(liability_amount as i128),
        ],
        32,
    )
}

pub fn monero_reorg_evidence_id(
    txid_hash: &str,
    old_block_height: u64,
    old_block_hash: &str,
    new_block_height: u64,
    new_block_hash: &str,
) -> String {
    domain_hash(
        "MONERO-REORG-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(txid_hash),
            HashPart::Int(old_block_height as i128),
            HashPart::Str(old_block_hash),
            HashPart::Int(new_block_height as i128),
            HashPart::Str(new_block_hash),
        ],
        32,
    )
}

pub fn monero_observer_signature_root(
    domain: &str,
    payload: &Value,
    observer_labels: &[String],
) -> String {
    merkle_root(
        "MONERO-OBSERVER-SIGNATURE",
        &observer_labels
            .iter()
            .map(|label| {
                let key = public_key_for_label(CryptoRole::WatchtowerSignature, label);
                let auth = sign_watchtower_authorization(label, domain, payload);
                json!({
                    "observer_label": label,
                    "observer_public_key": key.public_key,
                    "auth_transcript_hash": auth.auth_transcript_hash,
                    "auth_signature": auth.auth_signature,
                    "crypto_policy_root": crypto_policy_root(),
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn validate_observers(observer_labels: &[String]) -> MoneroResult<()> {
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
