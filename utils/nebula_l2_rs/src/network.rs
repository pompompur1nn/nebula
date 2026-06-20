use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    blocks::Validator,
    crypto_policy::{
        build_kem_envelope, crypto_policy_root, public_key_for_label, sign_authorization_for_role,
        verify_authorization_for_role, Authorization, CryptoRole, KemEnvelope,
    },
    fees::{execution_profile_from_resources, FeeMarketResource},
    hash::{domain_hash, merkle_root, HashPart},
    mempool::{MempoolAdmission, MempoolPreconfirmation, MempoolState},
    prover::ProverState,
    watchtower::WatchtowerState,
    CHAIN_ID,
};

pub type NetworkResult<T> = Result<T, String>;

pub const NETWORK_ADVERTISEMENT_TTL_BLOCKS: u64 = 20;
pub const NETWORK_MIN_PEER_SCORE: i64 = -100;
pub const NETWORK_MAX_PEER_SCORE: i64 = 1_000;
pub const NETWORK_ROOT_CONFLICT_PENALTY: i64 = 25;
pub const NETWORK_INVENTORY_REWARD: i64 = 3;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NetworkRole {
    Sequencer,
    Validator,
    Prover,
    Watchtower,
    WalletRelay,
    BridgeWatcher,
    DataAvailability,
}

impl NetworkRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Validator => "validator",
            Self::Prover => "prover",
            Self::Watchtower => "watchtower",
            Self::WalletRelay => "wallet_relay",
            Self::BridgeWatcher => "bridge_watcher",
            Self::DataAvailability => "data_availability",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAdvertisement {
    pub node_id: String,
    pub label: String,
    pub roles: Vec<NetworkRole>,
    pub network_public_key: String,
    pub network_key_id: String,
    pub route_commitment: String,
    pub relay_policy: String,
    pub min_supported_height: u64,
    pub max_supported_height: u64,
    pub advertised_at_height: u64,
    pub expires_at_height: u64,
    pub capacity_hint: u64,
    pub observed_fee_floor_units: u64,
    pub node_metadata_root: String,
    pub crypto_policy_root: String,
    pub authorization: Authorization,
}

impl NodeAdvertisement {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "node_advertisement",
            "chain_id": CHAIN_ID,
            "node_id": self.node_id,
            "label": self.label,
            "roles": self.roles.iter().map(NetworkRole::as_str).collect::<Vec<_>>(),
            "network_public_key": self.network_public_key,
            "network_key_id": self.network_key_id,
            "route_commitment": self.route_commitment,
            "relay_policy": self.relay_policy,
            "min_supported_height": self.min_supported_height,
            "max_supported_height": self.max_supported_height,
            "advertised_at_height": self.advertised_at_height,
            "expires_at_height": self.expires_at_height,
            "capacity_hint": self.capacity_hint,
            "observed_fee_floor_units": self.observed_fee_floor_units,
            "node_metadata_root": self.node_metadata_root,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }

    pub fn advertisement_root(&self) -> String {
        domain_hash(
            "NODE-ADVERTISEMENT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn is_live(&self, height: u64) -> bool {
        self.advertised_at_height <= height && height <= self.expires_at_height
    }

    pub fn supports_role(&self, role: NetworkRole) -> bool {
        self.roles.iter().any(|candidate| candidate == &role)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("node advertisement record object");
        object.insert(
            "advertisement_root".to_string(),
            Value::String(self.advertisement_root()),
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
        verify_authorization_for_role(
            CryptoRole::NetworkSignature,
            &self.network_public_key,
            "node_advertisement",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootInventoryAnnouncement {
    pub inventory_id: String,
    pub node_id: String,
    pub node_label: String,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub da_root: String,
    pub mempool_admission_root: String,
    pub mempool_preconfirmation_root: String,
    pub mempool_encrypted_batch_receipt_root: String,
    pub mempool_relay_fairness_ticket_root: String,
    pub mempool_anti_censorship_lane_commitment_root: String,
    pub validity_certificate_root: String,
    pub privacy_proof_aggregate_root: String,
    pub prover_state_root: String,
    pub prover_receipt_root: String,
    pub watchtower_audit_root: String,
    pub watchtower_challenge_root: String,
    pub bridge_root: String,
    pub monero_monitor_root: String,
    pub consensus_state_root: String,
    pub fee_market_root: String,
    pub announced_at_height: u64,
    pub expires_at_height: u64,
    pub authorization: Authorization,
}

impl RootInventoryAnnouncement {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "root_inventory_announcement",
            "chain_id": CHAIN_ID,
            "inventory_id": self.inventory_id,
            "node_id": self.node_id,
            "node_label": self.node_label,
            "height": self.height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "da_root": self.da_root,
            "mempool_admission_root": self.mempool_admission_root,
            "mempool_preconfirmation_root": self.mempool_preconfirmation_root,
            "mempool_encrypted_batch_receipt_root": self.mempool_encrypted_batch_receipt_root,
            "mempool_relay_fairness_ticket_root": self.mempool_relay_fairness_ticket_root,
            "mempool_anti_censorship_lane_commitment_root": self.mempool_anti_censorship_lane_commitment_root,
            "validity_certificate_root": self.validity_certificate_root,
            "privacy_proof_aggregate_root": self.privacy_proof_aggregate_root,
            "prover_state_root": self.prover_state_root,
            "prover_receipt_root": self.prover_receipt_root,
            "watchtower_audit_root": self.watchtower_audit_root,
            "watchtower_challenge_root": self.watchtower_challenge_root,
            "bridge_root": self.bridge_root,
            "monero_monitor_root": self.monero_monitor_root,
            "consensus_state_root": self.consensus_state_root,
            "fee_market_root": self.fee_market_root,
            "announced_at_height": self.announced_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn inventory_root(&self) -> String {
        domain_hash(
            "ROOT-INVENTORY",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn root_vector(&self) -> Value {
        json!({
            "state_root": self.state_root,
            "da_root": self.da_root,
            "mempool_admission_root": self.mempool_admission_root,
            "mempool_preconfirmation_root": self.mempool_preconfirmation_root,
            "mempool_encrypted_batch_receipt_root": self.mempool_encrypted_batch_receipt_root,
            "mempool_relay_fairness_ticket_root": self.mempool_relay_fairness_ticket_root,
            "mempool_anti_censorship_lane_commitment_root": self.mempool_anti_censorship_lane_commitment_root,
            "validity_certificate_root": self.validity_certificate_root,
            "privacy_proof_aggregate_root": self.privacy_proof_aggregate_root,
            "prover_state_root": self.prover_state_root,
            "prover_receipt_root": self.prover_receipt_root,
            "watchtower_audit_root": self.watchtower_audit_root,
            "watchtower_challenge_root": self.watchtower_challenge_root,
            "bridge_root": self.bridge_root,
            "monero_monitor_root": self.monero_monitor_root,
            "consensus_state_root": self.consensus_state_root,
            "fee_market_root": self.fee_market_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("root inventory record object");
        object.insert(
            "inventory_root".to_string(),
            Value::String(self.inventory_root()),
        );
        object.insert(
            "root_vector_hash".to_string(),
            Value::String(root_vector_hash(&self.root_vector())),
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionInventoryAnnouncement {
    pub inventory_id: String,
    pub node_id: String,
    pub node_label: String,
    pub height: u64,
    pub admission_root: String,
    pub preconfirmation_root: String,
    pub admission_count: u64,
    pub preconfirmation_count: u64,
    pub admission_ids_root: String,
    pub target_height_root: String,
    pub encrypted_payload_root: String,
    pub fee_market_root: String,
    pub announced_at_height: u64,
    pub expires_at_height: u64,
    pub authorization: Authorization,
}

impl AdmissionInventoryAnnouncement {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "admission_inventory_announcement",
            "chain_id": CHAIN_ID,
            "inventory_id": self.inventory_id,
            "node_id": self.node_id,
            "node_label": self.node_label,
            "height": self.height,
            "admission_root": self.admission_root,
            "preconfirmation_root": self.preconfirmation_root,
            "admission_count": self.admission_count,
            "preconfirmation_count": self.preconfirmation_count,
            "admission_ids_root": self.admission_ids_root,
            "target_height_root": self.target_height_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "fee_market_root": self.fee_market_root,
            "announced_at_height": self.announced_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn inventory_root(&self) -> String {
        domain_hash(
            "ADMISSION-INVENTORY",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("admission inventory record object");
        object.insert(
            "inventory_root".to_string(),
            Value::String(self.inventory_root()),
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkGossipEnvelope {
    pub envelope_id: String,
    pub sender_node_id: String,
    pub recipient_key_id: String,
    pub payload_kind: String,
    pub payload_root: String,
    pub relay_path_commitment: String,
    pub height: u64,
    pub expires_at_height: u64,
    pub kem_envelope: KemEnvelope,
}

impl NetworkGossipEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "network_gossip_envelope",
            "chain_id": CHAIN_ID,
            "envelope_id": self.envelope_id,
            "sender_node_id": self.sender_node_id,
            "recipient_key_id": self.recipient_key_id,
            "payload_kind": self.payload_kind,
            "payload_root": self.payload_root,
            "relay_path_commitment": self.relay_path_commitment,
            "height": self.height,
            "expires_at_height": self.expires_at_height,
            "kem_envelope": self.kem_envelope.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootConflictEvidence {
    pub evidence_id: String,
    pub left_inventory_id: String,
    pub right_inventory_id: String,
    pub height: u64,
    pub conflict_kind: String,
    pub left_node_id: String,
    pub right_node_id: String,
    pub left_root: String,
    pub right_root: String,
    pub reporter_label: String,
    pub reporter_public_key: String,
    pub reported_at_height: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl RootConflictEvidence {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "root_conflict_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "left_inventory_id": self.left_inventory_id,
            "right_inventory_id": self.right_inventory_id,
            "height": self.height,
            "conflict_kind": self.conflict_kind,
            "left_node_id": self.left_node_id,
            "right_node_id": self.right_node_id,
            "left_root": self.left_root,
            "right_root": self.right_root,
            "reporter_label": self.reporter_label,
            "reporter_public_key": self.reporter_public_key,
            "reported_at_height": self.reported_at_height,
            "status": self.status,
        })
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            "ROOT-CONFLICT-EVIDENCE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("root conflict evidence record object");
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
        verify_authorization_for_role(
            CryptoRole::WatchtowerSignature,
            &self.reporter_public_key,
            "root_conflict_evidence",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerScore {
    pub node_id: String,
    pub score: i64,
    pub successful_inventory_count: u64,
    pub conflict_count: u64,
    pub stale_announcement_count: u64,
    pub last_seen_height: u64,
    pub status: String,
}

impl PeerScore {
    pub fn public_record(&self) -> Value {
        json!({
            "node_id": self.node_id,
            "score": self.score,
            "successful_inventory_count": self.successful_inventory_count,
            "conflict_count": self.conflict_count,
            "stale_announcement_count": self.stale_announcement_count,
            "last_seen_height": self.last_seen_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkState {
    pub height: u64,
    pub advertisements: BTreeMap<String, NodeAdvertisement>,
    pub root_inventories: BTreeMap<String, RootInventoryAnnouncement>,
    pub admission_inventories: BTreeMap<String, AdmissionInventoryAnnouncement>,
    pub gossip_envelopes: BTreeMap<String, NetworkGossipEnvelope>,
    pub root_conflicts: BTreeMap<String, RootConflictEvidence>,
    pub peer_scores: BTreeMap<String, PeerScore>,
}

impl NetworkState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn record_advertisement(&mut self, advertisement: NodeAdvertisement) -> NetworkResult<()> {
        if !advertisement.verify_authorization() {
            return Err("node advertisement authorization failed".to_string());
        }
        self.bump_peer_score(
            &advertisement.node_id,
            NETWORK_INVENTORY_REWARD,
            self.height,
        );
        self.advertisements
            .insert(advertisement.node_id.clone(), advertisement);
        Ok(())
    }

    pub fn record_root_inventory(
        &mut self,
        inventory: RootInventoryAnnouncement,
    ) -> NetworkResult<()> {
        if !verify_network_authorization(
            &inventory.node_label,
            "root_inventory_announcement",
            &inventory.unsigned_record(),
            &inventory.authorization,
        ) {
            return Err("root inventory authorization failed".to_string());
        }
        if inventory.expires_at_height < self.height {
            self.bump_stale(&inventory.node_id, self.height);
        } else {
            self.bump_peer_score(&inventory.node_id, NETWORK_INVENTORY_REWARD, self.height);
        }
        self.root_inventories
            .insert(inventory.inventory_id.clone(), inventory);
        Ok(())
    }

    pub fn record_admission_inventory(
        &mut self,
        inventory: AdmissionInventoryAnnouncement,
    ) -> NetworkResult<()> {
        if !verify_network_authorization(
            &inventory.node_label,
            "admission_inventory_announcement",
            &inventory.unsigned_record(),
            &inventory.authorization,
        ) {
            return Err("admission inventory authorization failed".to_string());
        }
        if inventory.expires_at_height < self.height {
            self.bump_stale(&inventory.node_id, self.height);
        } else {
            self.bump_peer_score(&inventory.node_id, NETWORK_INVENTORY_REWARD, self.height);
        }
        self.admission_inventories
            .insert(inventory.inventory_id.clone(), inventory);
        Ok(())
    }

    pub fn record_gossip_envelope(&mut self, envelope: NetworkGossipEnvelope) {
        self.bump_peer_score(&envelope.sender_node_id, 1, self.height);
        self.gossip_envelopes
            .insert(envelope.envelope_id.clone(), envelope);
    }

    pub fn report_root_conflict(
        &mut self,
        left_inventory_id: &str,
        right_inventory_id: &str,
        reporter_label: &str,
    ) -> NetworkResult<RootConflictEvidence> {
        let left = self
            .root_inventories
            .get(left_inventory_id)
            .cloned()
            .ok_or_else(|| "unknown left root inventory".to_string())?;
        let right = self
            .root_inventories
            .get(right_inventory_id)
            .cloned()
            .ok_or_else(|| "unknown right root inventory".to_string())?;
        let (conflict_kind, left_root, right_root) = first_root_conflict(&left, &right)
            .ok_or_else(|| "root inventories do not conflict".to_string())?;
        let reporter_key = public_key_for_label(CryptoRole::WatchtowerSignature, reporter_label);
        let evidence_id = root_conflict_evidence_id(
            &left.inventory_id,
            &right.inventory_id,
            &conflict_kind,
            &left_root,
            &right_root,
        );
        let mut evidence = RootConflictEvidence {
            evidence_id: evidence_id.clone(),
            left_inventory_id: left.inventory_id.clone(),
            right_inventory_id: right.inventory_id.clone(),
            height: left.height,
            conflict_kind,
            left_node_id: left.node_id.clone(),
            right_node_id: right.node_id.clone(),
            left_root,
            right_root,
            reporter_label: reporter_label.to_string(),
            reporter_public_key: reporter_key.public_key,
            reported_at_height: self.height,
            status: "open".to_string(),
            authorization: empty_network_authorization(
                reporter_label,
                CryptoRole::WatchtowerSignature,
            ),
        };
        evidence.authorization = sign_authorization_for_role(
            CryptoRole::WatchtowerSignature,
            reporter_label,
            "root_conflict_evidence",
            &evidence.unsigned_record(),
        );
        if !evidence.verify_authorization() {
            return Err("root conflict evidence authorization failed".to_string());
        }
        self.bump_peer_score(&left.node_id, -NETWORK_ROOT_CONFLICT_PENALTY, self.height);
        self.bump_peer_score(&right.node_id, -NETWORK_ROOT_CONFLICT_PENALTY, self.height);
        self.root_conflicts.insert(evidence_id, evidence.clone());
        Ok(evidence)
    }

    pub fn advertisement_root(&self) -> String {
        merkle_root(
            "NETWORK-ADVERTISEMENT",
            &self
                .advertisements
                .values()
                .map(NodeAdvertisement::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn root_inventory_root(&self) -> String {
        merkle_root(
            "NETWORK-ROOT-INVENTORY",
            &self
                .root_inventories
                .values()
                .map(RootInventoryAnnouncement::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn admission_inventory_root(&self) -> String {
        merkle_root(
            "NETWORK-ADMISSION-INVENTORY",
            &self
                .admission_inventories
                .values()
                .map(AdmissionInventoryAnnouncement::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn gossip_envelope_root(&self) -> String {
        merkle_root(
            "NETWORK-GOSSIP-ENVELOPE",
            &self
                .gossip_envelopes
                .values()
                .map(NetworkGossipEnvelope::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn root_conflict_root(&self) -> String {
        merkle_root(
            "NETWORK-ROOT-CONFLICT",
            &self
                .root_conflicts
                .values()
                .map(RootConflictEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn peer_score_root(&self) -> String {
        merkle_root(
            "NETWORK-PEER-SCORE",
            &self
                .peer_scores
                .values()
                .map(PeerScore::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "NETWORK-STATE",
            &[
                HashPart::Str(&self.advertisement_root()),
                HashPart::Str(&self.root_inventory_root()),
                HashPart::Str(&self.admission_inventory_root()),
                HashPart::Str(&self.gossip_envelope_root()),
                HashPart::Str(&self.root_conflict_root()),
                HashPart::Str(&self.peer_score_root()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "network_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "advertisement_root": self.advertisement_root(),
            "root_inventory_root": self.root_inventory_root(),
            "admission_inventory_root": self.admission_inventory_root(),
            "gossip_envelope_root": self.gossip_envelope_root(),
            "root_conflict_root": self.root_conflict_root(),
            "peer_score_root": self.peer_score_root(),
            "network_state_root": self.state_root(),
            "advertisement_count": self.advertisements.len() as u64,
            "root_inventory_count": self.root_inventories.len() as u64,
            "admission_inventory_count": self.admission_inventories.len() as u64,
            "gossip_envelope_count": self.gossip_envelopes.len() as u64,
            "root_conflict_count": self.root_conflicts.len() as u64,
            "live_peer_count": self.advertisements.values().filter(|ad| ad.is_live(self.height)).count() as u64,
        })
    }

    fn bump_stale(&mut self, node_id: &str, height: u64) {
        let score = self.peer_score_entry(node_id, height);
        score.stale_announcement_count += 1;
        score.score = clamp_peer_score(score.score - 2);
        score.status = peer_status(score.score).to_string();
    }

    fn bump_peer_score(&mut self, node_id: &str, delta: i64, height: u64) {
        let score = self.peer_score_entry(node_id, height);
        if delta >= 0 {
            score.successful_inventory_count += 1;
        } else {
            score.conflict_count += 1;
        }
        score.score = clamp_peer_score(score.score + delta);
        score.last_seen_height = height;
        score.status = peer_status(score.score).to_string();
    }

    fn peer_score_entry(&mut self, node_id: &str, height: u64) -> &mut PeerScore {
        self.peer_scores
            .entry(node_id.to_string())
            .or_insert_with(|| PeerScore {
                node_id: node_id.to_string(),
                score: 0,
                successful_inventory_count: 0,
                conflict_count: 0,
                stale_announcement_count: 0,
                last_seen_height: height,
                status: "neutral".to_string(),
            })
    }
}

pub fn build_node_advertisement(
    label: &str,
    roles: Vec<NetworkRole>,
    route_hint: &str,
    relay_policy: &str,
    advertised_at_height: u64,
    capacity_hint: u64,
    observed_fee_floor_units: u64,
) -> NetworkResult<NodeAdvertisement> {
    if label.is_empty() {
        return Err("node advertisement label is required".to_string());
    }
    if roles.is_empty() {
        return Err("node advertisement requires at least one role".to_string());
    }
    let mut role_set = BTreeSet::new();
    let roles = roles
        .into_iter()
        .filter(|role| role_set.insert(role.clone()))
        .collect::<Vec<_>>();
    let public_key = public_key_for_label(CryptoRole::NetworkSignature, label);
    let route_commitment = domain_hash(
        "NETWORK-ROUTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(route_hint),
            HashPart::Str(relay_policy),
        ],
        32,
    );
    let role_records = roles
        .iter()
        .map(|role| Value::String(role.as_str().to_string()))
        .collect::<Vec<_>>();
    let node_metadata_root = domain_hash(
        "NODE-METADATA",
        &[
            HashPart::Json(&Value::Array(role_records)),
            HashPart::Str(&route_commitment),
            HashPart::Int(capacity_hint as i128),
            HashPart::Int(observed_fee_floor_units as i128),
        ],
        32,
    );
    let node_id = network_node_id(label, &public_key.key_id, &roles);
    let mut advertisement = NodeAdvertisement {
        node_id,
        label: label.to_string(),
        roles,
        network_public_key: public_key.public_key,
        network_key_id: public_key.key_id,
        route_commitment,
        relay_policy: relay_policy.to_string(),
        min_supported_height: 0,
        max_supported_height: advertised_at_height + NETWORK_ADVERTISEMENT_TTL_BLOCKS,
        advertised_at_height,
        expires_at_height: advertised_at_height + NETWORK_ADVERTISEMENT_TTL_BLOCKS,
        capacity_hint,
        observed_fee_floor_units,
        node_metadata_root,
        crypto_policy_root: crypto_policy_root(),
        authorization: empty_network_authorization(label, CryptoRole::NetworkSignature),
    };
    advertisement.authorization = sign_authorization_for_role(
        CryptoRole::NetworkSignature,
        label,
        "node_advertisement",
        &advertisement.unsigned_record(),
    );
    if !advertisement.verify_authorization() {
        return Err("node advertisement authorization failed".to_string());
    }
    Ok(advertisement)
}

#[allow(clippy::too_many_arguments)]
pub fn build_root_inventory_announcement(
    advertisement: &NodeAdvertisement,
    height: u64,
    block_hash: &str,
    state_root: &str,
    da_root: &str,
    mempool: &MempoolState,
    validity_certificate_root: &str,
    privacy_proof_aggregate_root: &str,
    prover: &ProverState,
    watchtower: &WatchtowerState,
    bridge_root: &str,
    monero_monitor_root: &str,
    consensus_state_root: &str,
    fee_resources: &[FeeMarketResource],
) -> NetworkResult<RootInventoryAnnouncement> {
    if !advertisement.is_live(height) {
        return Err("cannot build root inventory from expired node advertisement".to_string());
    }
    let fee_market_root = execution_profile_from_resources(fee_resources).local_fee_market_root;
    let inventory_id = root_inventory_id(&advertisement.node_id, height, block_hash, state_root);
    let mut announcement = RootInventoryAnnouncement {
        inventory_id,
        node_id: advertisement.node_id.clone(),
        node_label: advertisement.label.clone(),
        height,
        block_hash: block_hash.to_string(),
        state_root: state_root.to_string(),
        da_root: da_root.to_string(),
        mempool_admission_root: mempool.admission_root(),
        mempool_preconfirmation_root: mempool.preconfirmation_root(),
        mempool_encrypted_batch_receipt_root: mempool.encrypted_batch_receipt_root(),
        mempool_relay_fairness_ticket_root: mempool.relay_fairness_ticket_root(),
        mempool_anti_censorship_lane_commitment_root: mempool
            .anti_censorship_lane_commitment_root(),
        validity_certificate_root: validity_certificate_root.to_string(),
        privacy_proof_aggregate_root: privacy_proof_aggregate_root.to_string(),
        prover_state_root: prover.state_root(),
        prover_receipt_root: prover.receipt_root(),
        watchtower_audit_root: watchtower.audit_root(),
        watchtower_challenge_root: watchtower.challenge_root(),
        bridge_root: bridge_root.to_string(),
        monero_monitor_root: monero_monitor_root.to_string(),
        consensus_state_root: consensus_state_root.to_string(),
        fee_market_root,
        announced_at_height: height,
        expires_at_height: height + NETWORK_ADVERTISEMENT_TTL_BLOCKS,
        authorization: empty_network_authorization(
            &advertisement.label,
            CryptoRole::NetworkSignature,
        ),
    };
    announcement.authorization = sign_authorization_for_role(
        CryptoRole::NetworkSignature,
        &advertisement.label,
        "root_inventory_announcement",
        &announcement.unsigned_record(),
    );
    Ok(announcement)
}

pub fn build_admission_inventory_announcement(
    advertisement: &NodeAdvertisement,
    height: u64,
    mempool: &MempoolState,
    fee_resources: &[FeeMarketResource],
) -> NetworkResult<AdmissionInventoryAnnouncement> {
    if !advertisement.is_live(height) {
        return Err("cannot build admission inventory from expired node advertisement".to_string());
    }
    let admissions = mempool.pending_admissions.clone();
    let mut preconfirmations = mempool
        .preconfirmations
        .values()
        .cloned()
        .collect::<Vec<_>>();
    preconfirmations.sort_by(|left, right| left.preconfirmation_id.cmp(&right.preconfirmation_id));
    let admission_ids = admissions
        .iter()
        .map(|admission| {
            json!({
                "admission_id": admission.admission_id,
                "tx_public_hash": admission.tx_public_hash,
                "expires_at_height": admission.expires_at_height,
            })
        })
        .collect::<Vec<_>>();
    let target_heights = preconfirmations
        .iter()
        .map(|preconfirmation| {
            json!({
                "preconfirmation_id": preconfirmation.preconfirmation_id,
                "admission_id": preconfirmation.admission_id,
                "target_height": preconfirmation.target_height,
            })
        })
        .collect::<Vec<_>>();
    let encrypted_payloads = admissions
        .iter()
        .map(|admission| {
            json!({
                "admission_id": admission.admission_id,
                "encrypted_payload_hash": admission.encrypted_payload_hash,
                "kem_ciphertext_hash": admission.kem_ciphertext_hash,
                "committee_key_id": admission.committee_key_id,
            })
        })
        .collect::<Vec<_>>();
    let fee_market_root = execution_profile_from_resources(fee_resources).local_fee_market_root;
    let admission_ids_root = merkle_root("ADMISSION-INVENTORY-ID", &admission_ids);
    let target_height_root = merkle_root("ADMISSION-INVENTORY-TARGET", &target_heights);
    let encrypted_payload_root =
        merkle_root("ADMISSION-INVENTORY-ENCRYPTED-PAYLOAD", &encrypted_payloads);
    let inventory_id = admission_inventory_id(
        &advertisement.node_id,
        height,
        &mempool.admission_root(),
        &mempool.preconfirmation_root(),
    );
    let mut announcement = AdmissionInventoryAnnouncement {
        inventory_id,
        node_id: advertisement.node_id.clone(),
        node_label: advertisement.label.clone(),
        height,
        admission_root: mempool.admission_root(),
        preconfirmation_root: mempool.preconfirmation_root(),
        admission_count: admissions.len() as u64,
        preconfirmation_count: preconfirmations.len() as u64,
        admission_ids_root,
        target_height_root,
        encrypted_payload_root,
        fee_market_root,
        announced_at_height: height,
        expires_at_height: height + NETWORK_ADVERTISEMENT_TTL_BLOCKS,
        authorization: empty_network_authorization(
            &advertisement.label,
            CryptoRole::NetworkSignature,
        ),
    };
    announcement.authorization = sign_authorization_for_role(
        CryptoRole::NetworkSignature,
        &advertisement.label,
        "admission_inventory_announcement",
        &announcement.unsigned_record(),
    );
    Ok(announcement)
}

pub fn build_network_gossip_envelope(
    sender: &NodeAdvertisement,
    recipient_key_id: &str,
    recipient_public_key_root: &str,
    payload_kind: &str,
    payload: &Value,
    relay_path_hint: &str,
    height: u64,
) -> NetworkResult<NetworkGossipEnvelope> {
    if payload_kind.is_empty() {
        return Err("network gossip payload kind is required".to_string());
    }
    let payload_root = domain_hash(
        "NETWORK-GOSSIP-PAYLOAD",
        &[HashPart::Str(payload_kind), HashPart::Json(payload)],
        32,
    );
    let relay_path_commitment = domain_hash(
        "NETWORK-GOSSIP-RELAY-PATH",
        &[
            HashPart::Str(&sender.node_id),
            HashPart::Str(relay_path_hint),
            HashPart::Str(&payload_root),
        ],
        32,
    );
    let transcript = json!({
        "sender_node_id": sender.node_id,
        "payload_kind": payload_kind,
        "payload_root": payload_root,
        "relay_path_commitment": relay_path_commitment,
        "height": height,
    });
    let kem_envelope = build_kem_envelope(
        CryptoRole::KeyEstablishment,
        recipient_key_id,
        recipient_public_key_root,
        &transcript,
    );
    let envelope_id = domain_hash(
        "NETWORK-GOSSIP-ENVELOPE-ID",
        &[
            HashPart::Str(&sender.node_id),
            HashPart::Str(&payload_root),
            HashPart::Str(&kem_envelope.ciphertext_hash),
            HashPart::Int(height as i128),
        ],
        32,
    );
    Ok(NetworkGossipEnvelope {
        envelope_id,
        sender_node_id: sender.node_id.clone(),
        recipient_key_id: recipient_key_id.to_string(),
        payload_kind: payload_kind.to_string(),
        payload_root,
        relay_path_commitment,
        height,
        expires_at_height: height + NETWORK_ADVERTISEMENT_TTL_BLOCKS,
        kem_envelope,
    })
}

pub fn validator_node_network_root(validators: &[Validator]) -> String {
    merkle_root(
        "SEQUENCER-NODE-NETWORK",
        &validators
            .iter()
            .map(|validator| {
                json!({
                    "validator_id": validator.validator_id,
                    "network_public_key": validator.network_public_key,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn network_node_root(validators: &[Validator]) -> String {
    validator_node_network_root(validators)
}

pub fn network_node_id(label: &str, network_key_id: &str, roles: &[NetworkRole]) -> String {
    let role_values = roles
        .iter()
        .map(|role| Value::String(role.as_str().to_string()))
        .collect::<Vec<_>>();
    domain_hash(
        "NETWORK-NODE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(network_key_id),
            HashPart::Json(&Value::Array(role_values)),
        ],
        32,
    )
}

pub fn root_inventory_id(node_id: &str, height: u64, block_hash: &str, state_root: &str) -> String {
    domain_hash(
        "ROOT-INVENTORY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(node_id),
            HashPart::Int(height as i128),
            HashPart::Str(block_hash),
            HashPart::Str(state_root),
        ],
        32,
    )
}

pub fn admission_inventory_id(
    node_id: &str,
    height: u64,
    admission_root: &str,
    preconfirmation_root: &str,
) -> String {
    domain_hash(
        "ADMISSION-INVENTORY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(node_id),
            HashPart::Int(height as i128),
            HashPart::Str(admission_root),
            HashPart::Str(preconfirmation_root),
        ],
        32,
    )
}

pub fn root_vector_hash(root_vector: &Value) -> String {
    domain_hash(
        "ROOT-VECTOR",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(root_vector)],
        32,
    )
}

pub fn root_conflict_evidence_id(
    left_inventory_id: &str,
    right_inventory_id: &str,
    conflict_kind: &str,
    left_root: &str,
    right_root: &str,
) -> String {
    domain_hash(
        "ROOT-CONFLICT-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(left_inventory_id),
            HashPart::Str(right_inventory_id),
            HashPart::Str(conflict_kind),
            HashPart::Str(left_root),
            HashPart::Str(right_root),
        ],
        32,
    )
}

pub fn admission_inventory_root(
    admissions: &[MempoolAdmission],
    preconfirmations: &[MempoolPreconfirmation],
) -> String {
    let records = json!({
        "admissions": admissions.iter().map(MempoolAdmission::public_record).collect::<Vec<_>>(),
        "preconfirmations": preconfirmations.iter().map(MempoolPreconfirmation::public_record).collect::<Vec<_>>(),
    });
    domain_hash("ADMISSION-INVENTORY-ROOT", &[HashPart::Json(&records)], 32)
}

fn first_root_conflict(
    left: &RootInventoryAnnouncement,
    right: &RootInventoryAnnouncement,
) -> Option<(String, String, String)> {
    if left.height != right.height || left.block_hash != right.block_hash {
        return Some((
            "different_block_view".to_string(),
            format!("{}:{}", left.height, left.block_hash),
            format!("{}:{}", right.height, right.block_hash),
        ));
    }
    let fields = [
        ("state_root", &left.state_root, &right.state_root),
        ("da_root", &left.da_root, &right.da_root),
        (
            "mempool_admission_root",
            &left.mempool_admission_root,
            &right.mempool_admission_root,
        ),
        (
            "mempool_preconfirmation_root",
            &left.mempool_preconfirmation_root,
            &right.mempool_preconfirmation_root,
        ),
        (
            "mempool_encrypted_batch_receipt_root",
            &left.mempool_encrypted_batch_receipt_root,
            &right.mempool_encrypted_batch_receipt_root,
        ),
        (
            "mempool_relay_fairness_ticket_root",
            &left.mempool_relay_fairness_ticket_root,
            &right.mempool_relay_fairness_ticket_root,
        ),
        (
            "mempool_anti_censorship_lane_commitment_root",
            &left.mempool_anti_censorship_lane_commitment_root,
            &right.mempool_anti_censorship_lane_commitment_root,
        ),
        (
            "validity_certificate_root",
            &left.validity_certificate_root,
            &right.validity_certificate_root,
        ),
        (
            "privacy_proof_aggregate_root",
            &left.privacy_proof_aggregate_root,
            &right.privacy_proof_aggregate_root,
        ),
        (
            "prover_state_root",
            &left.prover_state_root,
            &right.prover_state_root,
        ),
        (
            "prover_receipt_root",
            &left.prover_receipt_root,
            &right.prover_receipt_root,
        ),
        (
            "watchtower_audit_root",
            &left.watchtower_audit_root,
            &right.watchtower_audit_root,
        ),
        (
            "watchtower_challenge_root",
            &left.watchtower_challenge_root,
            &right.watchtower_challenge_root,
        ),
        ("bridge_root", &left.bridge_root, &right.bridge_root),
        (
            "monero_monitor_root",
            &left.monero_monitor_root,
            &right.monero_monitor_root,
        ),
        (
            "consensus_state_root",
            &left.consensus_state_root,
            &right.consensus_state_root,
        ),
        (
            "fee_market_root",
            &left.fee_market_root,
            &right.fee_market_root,
        ),
    ];
    fields
        .iter()
        .find(|(_, left_root, right_root)| left_root != right_root)
        .map(|(kind, left_root, right_root)| {
            (
                (*kind).to_string(),
                (*left_root).to_string(),
                (*right_root).to_string(),
            )
        })
}

fn verify_network_authorization(
    label: &str,
    domain: &str,
    payload: &Value,
    authorization: &Authorization,
) -> bool {
    let expected_public = public_key_for_label(CryptoRole::NetworkSignature, label);
    verify_authorization_for_role(
        CryptoRole::NetworkSignature,
        &expected_public.public_key,
        domain,
        payload,
        authorization,
    )
}

fn empty_network_authorization(label: &str, role: CryptoRole) -> Authorization {
    Authorization {
        signer_label: label.to_string(),
        auth_scheme: role.scheme().to_string(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

fn clamp_peer_score(score: i64) -> i64 {
    score.clamp(NETWORK_MIN_PEER_SCORE, NETWORK_MAX_PEER_SCORE)
}

fn peer_status(score: i64) -> &'static str {
    if score <= -50 {
        "quarantined"
    } else if score < 0 {
        "degraded"
    } else if score >= 100 {
        "trusted"
    } else {
        "neutral"
    }
}
