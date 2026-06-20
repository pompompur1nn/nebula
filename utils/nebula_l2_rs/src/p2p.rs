use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    crypto_policy::{
        crypto_policy_root, public_key_for_label, sign_network_authorization,
        verify_network_authorization, Authorization, CryptoRole,
    },
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type P2pResult<T> = Result<T, String>;

pub const P2P_PROTOCOL_VERSION: u64 = 1;
pub const P2P_HANDSHAKE_TTL_BLOCKS: u64 = 32;
pub const P2P_SYNC_REQUEST_TTL_BLOCKS: u64 = 8;
pub const P2P_SYNC_RESPONSE_TTL_BLOCKS: u64 = 8;
pub const P2P_GOSSIP_TTL_BLOCKS: u64 = 16;
pub const P2P_BANDWIDTH_WINDOW_BLOCKS: u64 = 16;
pub const P2P_DEFAULT_BANDWIDTH_LIMIT_BYTES: u64 = 4 * 1024 * 1024;
pub const P2P_DEFAULT_MAX_RESPONSE_BYTES: u64 = 512 * 1024;
pub const P2P_DEFAULT_PRIVACY_BUDGET_BYTES: u64 = 64 * 1024;
pub const P2P_MAX_SYNC_SPAN_BLOCKS: u64 = 2_048;
pub const P2P_MIN_PEER_SCORE: i64 = -100;
pub const P2P_MAX_PEER_SCORE: i64 = 1_000;
pub const P2P_QUARANTINE_SCORE: i64 = -50;
pub const P2P_HANDSHAKE_REWARD: i64 = 5;
pub const P2P_SYNC_REWARD: i64 = 4;
pub const P2P_GOSSIP_REWARD: i64 = 2;
pub const P2P_RELAY_REWARD: i64 = 2;
pub const P2P_AUTH_FAILURE_PENALTY: i64 = 30;
pub const P2P_BANDWIDTH_REJECT_PENALTY: i64 = 5;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum P2pPeerRole {
    Sequencer,
    Validator,
    Prover,
    Watchtower,
    WalletRelay,
    BridgeWatcher,
    DataAvailability,
    Archive,
    LightClient,
    PrivacyRelay,
}

impl P2pPeerRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Validator => "validator",
            Self::Prover => "prover",
            Self::Watchtower => "watchtower",
            Self::WalletRelay => "wallet_relay",
            Self::BridgeWatcher => "bridge_watcher",
            Self::DataAvailability => "data_availability",
            Self::Archive => "archive",
            Self::LightClient => "light_client",
            Self::PrivacyRelay => "privacy_relay",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum P2pTransportKind {
    InProcess,
    Tcp,
    Quic,
    TorOnion,
    I2p,
    PrivateRelay,
}

impl P2pTransportKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InProcess => "in_process",
            Self::Tcp => "tcp",
            Self::Quic => "quic",
            Self::TorOnion => "tor_onion",
            Self::I2p => "i2p",
            Self::PrivateRelay => "private_relay",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pCapability {
    pub capability_id: String,
    pub role: P2pPeerRole,
    pub capability: String,
    pub root_kinds: Vec<String>,
    pub min_protocol_version: u64,
    pub max_protocol_version: u64,
    pub supports_low_fee_sync: bool,
    pub supports_private_relay: bool,
    pub priority: u64,
}

impl P2pCapability {
    pub fn new(
        role: P2pPeerRole,
        capability: &str,
        root_kinds: Vec<String>,
        supports_low_fee_sync: bool,
        supports_private_relay: bool,
        priority: u64,
    ) -> Self {
        Self::with_versions(
            role,
            capability,
            root_kinds,
            P2P_PROTOCOL_VERSION,
            P2P_PROTOCOL_VERSION,
            supports_low_fee_sync,
            supports_private_relay,
            priority,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_versions(
        role: P2pPeerRole,
        capability: &str,
        root_kinds: Vec<String>,
        min_protocol_version: u64,
        max_protocol_version: u64,
        supports_low_fee_sync: bool,
        supports_private_relay: bool,
        priority: u64,
    ) -> Self {
        let root_kinds = normalize_strings(root_kinds);
        let capability_id = p2p_capability_id(
            role.as_str(),
            capability,
            &root_kinds,
            min_protocol_version,
            max_protocol_version,
            supports_low_fee_sync,
            supports_private_relay,
        );
        Self {
            capability_id,
            role,
            capability: capability.to_string(),
            root_kinds,
            min_protocol_version,
            max_protocol_version,
            supports_low_fee_sync,
            supports_private_relay,
            priority,
        }
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "p2p_capability",
            "chain_id": CHAIN_ID,
            "capability_id": self.capability_id,
            "role": self.role.as_str(),
            "capability": self.capability,
            "root_kinds": self.root_kinds,
            "min_protocol_version": self.min_protocol_version,
            "max_protocol_version": self.max_protocol_version,
            "supports_low_fee_sync": self.supports_low_fee_sync,
            "supports_private_relay": self.supports_private_relay,
            "priority": self.priority,
        })
    }

    pub fn capability_root(&self) -> String {
        domain_hash(
            "P2P-CAPABILITY",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        insert_string(&mut record, "capability_root", self.capability_root());
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pPeerHandshake {
    pub handshake_id: String,
    pub peer_id: String,
    pub label: String,
    pub roles: Vec<P2pPeerRole>,
    pub transport: P2pTransportKind,
    pub transport_route_commitment: String,
    pub network_public_key: String,
    pub network_key_id: String,
    pub capability_root: String,
    pub root_inventory_root: String,
    pub admission_inventory_root: String,
    pub bridge_evidence_root: String,
    pub monero_evidence_root: String,
    pub min_supported_height: u64,
    pub max_supported_height: u64,
    pub protocol_version: u64,
    pub observed_latency_ms: u64,
    pub fee_floor_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub crypto_policy_root: String,
    pub authorization: Authorization,
}

impl P2pPeerHandshake {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        roles: Vec<P2pPeerRole>,
        transport: P2pTransportKind,
        route_hint: &str,
        capabilities: Vec<P2pCapability>,
        root_inventory_root: &str,
        admission_inventory_root: &str,
        bridge_evidence_root: &str,
        monero_evidence_root: &str,
        min_supported_height: u64,
        max_supported_height: u64,
        opened_at_height: u64,
    ) -> P2pResult<Self> {
        if label.is_empty() {
            return Err("p2p handshake label is required".to_string());
        }
        if max_supported_height < min_supported_height {
            return Err("p2p handshake height range is invalid".to_string());
        }
        let roles = normalize_roles(roles);
        if roles.is_empty() {
            return Err("p2p handshake requires at least one role".to_string());
        }
        let public_key = public_key_for_label(CryptoRole::NetworkSignature, label);
        let transport_route_commitment =
            p2p_transport_route_commitment(label, transport.as_str(), route_hint, opened_at_height);
        let capability_root = p2p_capability_root(&capabilities);
        let root_inventory_root = default_root(root_inventory_root, "P2P-EMPTY-ROOT-INVENTORY");
        let admission_inventory_root =
            default_root(admission_inventory_root, "P2P-EMPTY-ADMISSION-INVENTORY");
        let bridge_evidence_root = default_root(bridge_evidence_root, "P2P-EMPTY-BRIDGE-EVIDENCE");
        let monero_evidence_root = default_root(monero_evidence_root, "P2P-EMPTY-MONERO-EVIDENCE");
        let peer_id = p2p_peer_id(
            label,
            &public_key.key_id,
            &roles,
            transport.as_str(),
            &transport_route_commitment,
        );
        let handshake_id = p2p_handshake_id(
            &peer_id,
            &capability_root,
            &root_inventory_root,
            &admission_inventory_root,
            &bridge_evidence_root,
            &monero_evidence_root,
            opened_at_height,
        );
        let mut handshake = Self {
            handshake_id,
            peer_id,
            label: label.to_string(),
            roles,
            transport,
            transport_route_commitment,
            network_public_key: public_key.public_key,
            network_key_id: public_key.key_id,
            capability_root,
            root_inventory_root,
            admission_inventory_root,
            bridge_evidence_root,
            monero_evidence_root,
            min_supported_height,
            max_supported_height,
            protocol_version: P2P_PROTOCOL_VERSION,
            observed_latency_ms: 0,
            fee_floor_units: 0,
            opened_at_height,
            expires_at_height: opened_at_height + P2P_HANDSHAKE_TTL_BLOCKS,
            crypto_policy_root: crypto_policy_root(),
            authorization: empty_network_authorization(label),
        };
        handshake.authorization =
            sign_network_authorization(label, "p2p_peer_handshake", &handshake.unsigned_record());
        if !handshake.verify() {
            return Err("p2p handshake authorization failed".to_string());
        }
        Ok(handshake)
    }

    pub fn expected_peer_id(&self) -> String {
        p2p_peer_id(
            &self.label,
            &self.network_key_id,
            &self.roles,
            self.transport.as_str(),
            &self.transport_route_commitment,
        )
    }

    pub fn expected_handshake_id(&self) -> String {
        p2p_handshake_id(
            &self.peer_id,
            &self.capability_root,
            &self.root_inventory_root,
            &self.admission_inventory_root,
            &self.bridge_evidence_root,
            &self.monero_evidence_root,
            self.opened_at_height,
        )
    }

    pub fn is_live(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }

    pub fn supports_role(&self, role: P2pPeerRole) -> bool {
        self.roles.iter().any(|candidate| candidate == &role)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "p2p_peer_handshake",
            "chain_id": CHAIN_ID,
            "handshake_id": self.handshake_id,
            "peer_id": self.peer_id,
            "label": self.label,
            "roles": roles_as_strings(&self.roles),
            "transport": self.transport.as_str(),
            "transport_route_commitment": self.transport_route_commitment,
            "network_public_key": self.network_public_key,
            "network_key_id": self.network_key_id,
            "capability_root": self.capability_root,
            "root_inventory_root": self.root_inventory_root,
            "admission_inventory_root": self.admission_inventory_root,
            "bridge_evidence_root": self.bridge_evidence_root,
            "monero_evidence_root": self.monero_evidence_root,
            "min_supported_height": self.min_supported_height,
            "max_supported_height": self.max_supported_height,
            "protocol_version": self.protocol_version,
            "observed_latency_ms": self.observed_latency_ms,
            "fee_floor_units": self.fee_floor_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }

    pub fn handshake_root(&self) -> String {
        domain_hash(
            "P2P-PEER-HANDSHAKE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn authorization_root(&self) -> String {
        p2p_authorization_root(&self.authorization)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        insert_string(&mut record, "handshake_root", self.handshake_root());
        insert_string(&mut record, "authorization_root", self.authorization_root());
        append_authorization(&mut record, &self.authorization);
        record
    }

    pub fn verify_authorization(&self) -> bool {
        verify_network_authorization(
            &self.network_public_key,
            "p2p_peer_handshake",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn verify(&self) -> bool {
        self.peer_id == self.expected_peer_id()
            && self.handshake_id == self.expected_handshake_id()
            && self.roles == normalize_roles(self.roles.clone())
            && self.protocol_version == P2P_PROTOCOL_VERSION
            && self.crypto_policy_root == crypto_policy_root()
            && self.verify_authorization()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pSyncRequest {
    pub request_id: String,
    pub requester_peer_id: String,
    pub target_peer_id: String,
    pub from_height: u64,
    pub to_height: u64,
    pub requested_root_kinds: Vec<String>,
    pub have_root_inventory_root: String,
    pub have_admission_inventory_root: String,
    pub privacy_budget_bytes: u64,
    pub max_response_bytes: u64,
    pub low_fee_only: bool,
    pub include_bridge_evidence: bool,
    pub include_monero_evidence: bool,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub authorization: Authorization,
}

impl P2pSyncRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requester: &P2pPeerHandshake,
        target_peer_id: &str,
        from_height: u64,
        to_height: u64,
        requested_root_kinds: Vec<String>,
        low_fee_only: bool,
        include_bridge_evidence: bool,
        include_monero_evidence: bool,
        opened_at_height: u64,
    ) -> P2pResult<Self> {
        if target_peer_id.is_empty() {
            return Err("p2p sync target peer id is required".to_string());
        }
        if to_height < from_height {
            return Err("p2p sync height range is invalid".to_string());
        }
        if to_height.saturating_sub(from_height) > P2P_MAX_SYNC_SPAN_BLOCKS {
            return Err("p2p sync height range exceeds protocol limit".to_string());
        }
        let requested_root_kinds = normalize_strings(requested_root_kinds);
        if requested_root_kinds.is_empty() {
            return Err("p2p sync request requires at least one root kind".to_string());
        }
        let request_id = p2p_sync_request_id(
            &requester.peer_id,
            target_peer_id,
            from_height,
            to_height,
            &requested_root_kinds,
            &requester.root_inventory_root,
            &requester.admission_inventory_root,
            opened_at_height,
        );
        let mut request = Self {
            request_id,
            requester_peer_id: requester.peer_id.clone(),
            target_peer_id: target_peer_id.to_string(),
            from_height,
            to_height,
            requested_root_kinds,
            have_root_inventory_root: requester.root_inventory_root.clone(),
            have_admission_inventory_root: requester.admission_inventory_root.clone(),
            privacy_budget_bytes: P2P_DEFAULT_PRIVACY_BUDGET_BYTES,
            max_response_bytes: P2P_DEFAULT_MAX_RESPONSE_BYTES,
            low_fee_only,
            include_bridge_evidence,
            include_monero_evidence,
            opened_at_height,
            expires_at_height: opened_at_height + P2P_SYNC_REQUEST_TTL_BLOCKS,
            authorization: empty_network_authorization(&requester.label),
        };
        request.authorization = sign_network_authorization(
            &requester.label,
            "p2p_sync_request",
            &request.unsigned_record(),
        );
        if !request.verify_authorization(&requester.network_public_key) {
            return Err("p2p sync request authorization failed".to_string());
        }
        Ok(request)
    }

    pub fn expected_request_id(&self) -> String {
        p2p_sync_request_id(
            &self.requester_peer_id,
            &self.target_peer_id,
            self.from_height,
            self.to_height,
            &self.requested_root_kinds,
            &self.have_root_inventory_root,
            &self.have_admission_inventory_root,
            self.opened_at_height,
        )
    }

    pub fn is_live(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "p2p_sync_request",
            "chain_id": CHAIN_ID,
            "request_id": self.request_id,
            "requester_peer_id": self.requester_peer_id,
            "target_peer_id": self.target_peer_id,
            "from_height": self.from_height,
            "to_height": self.to_height,
            "requested_root_kinds": self.requested_root_kinds,
            "have_root_inventory_root": self.have_root_inventory_root,
            "have_admission_inventory_root": self.have_admission_inventory_root,
            "privacy_budget_bytes": self.privacy_budget_bytes,
            "max_response_bytes": self.max_response_bytes,
            "low_fee_only": self.low_fee_only,
            "include_bridge_evidence": self.include_bridge_evidence,
            "include_monero_evidence": self.include_monero_evidence,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn request_root(&self) -> String {
        domain_hash(
            "P2P-SYNC-REQUEST",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn authorization_root(&self) -> String {
        p2p_authorization_root(&self.authorization)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        insert_string(&mut record, "request_root", self.request_root());
        insert_string(&mut record, "authorization_root", self.authorization_root());
        append_authorization(&mut record, &self.authorization);
        record
    }

    pub fn verify_authorization(&self, expected_public_key: &str) -> bool {
        verify_network_authorization(
            expected_public_key,
            "p2p_sync_request",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn verify(&self, expected_public_key: &str) -> bool {
        self.request_id == self.expected_request_id()
            && self.requested_root_kinds == normalize_strings(self.requested_root_kinds.clone())
            && self.verify_authorization(expected_public_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pSyncResponse {
    pub response_id: String,
    pub request_id: String,
    pub responder_peer_id: String,
    pub requester_peer_id: String,
    pub from_height: u64,
    pub to_height: u64,
    pub selected_roots: Value,
    pub selected_root_kinds: Vec<String>,
    pub missing_root_kinds: Vec<String>,
    pub root_inventory_root: String,
    pub admission_inventory_root: String,
    pub bridge_evidence_root: String,
    pub monero_evidence_root: String,
    pub response_bytes: u64,
    pub privacy_cost_bytes: u64,
    pub low_fee_path: bool,
    pub answered_at_height: u64,
    pub expires_at_height: u64,
    pub authorization: Authorization,
}

impl P2pSyncResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn from_roots(
        request: &P2pSyncRequest,
        responder: &P2pPeerHandshake,
        root_inventory_root: &str,
        admission_inventory_root: &str,
        selected_roots: Value,
        bridge_evidence_root: &str,
        monero_evidence_root: &str,
        answered_at_height: u64,
    ) -> P2pResult<Self> {
        if request.target_peer_id != responder.peer_id {
            return Err("p2p sync responder does not match request target".to_string());
        }
        let selected_roots = filter_selected_roots(&selected_roots, &request.requested_root_kinds);
        let selected_root_kinds =
            selected_root_kinds(&selected_roots, &request.requested_root_kinds);
        let missing_root_kinds =
            missing_root_kinds(&request.requested_root_kinds, &selected_root_kinds);
        let root_inventory_root = default_root(root_inventory_root, "P2P-EMPTY-ROOT-INVENTORY");
        let admission_inventory_root =
            default_root(admission_inventory_root, "P2P-EMPTY-ADMISSION-INVENTORY");
        let bridge_evidence_root = default_root(bridge_evidence_root, "P2P-EMPTY-BRIDGE-EVIDENCE");
        let monero_evidence_root = default_root(monero_evidence_root, "P2P-EMPTY-MONERO-EVIDENCE");
        let response_bytes = json_byte_len(&selected_roots);
        let privacy_cost_bytes =
            if request.include_bridge_evidence || request.include_monero_evidence {
                response_bytes.min(request.privacy_budget_bytes)
            } else {
                0
            };
        if response_bytes > request.max_response_bytes {
            return Err("p2p sync response exceeds requested byte budget".to_string());
        }
        let response_id = p2p_sync_response_id(
            &request.request_id,
            &responder.peer_id,
            &p2p_root_value_hash(&selected_roots),
            &root_inventory_root,
            &admission_inventory_root,
            answered_at_height,
        );
        let mut response = Self {
            response_id,
            request_id: request.request_id.clone(),
            responder_peer_id: responder.peer_id.clone(),
            requester_peer_id: request.requester_peer_id.clone(),
            from_height: request.from_height,
            to_height: request.to_height,
            selected_roots,
            selected_root_kinds,
            missing_root_kinds,
            root_inventory_root,
            admission_inventory_root,
            bridge_evidence_root,
            monero_evidence_root,
            response_bytes,
            privacy_cost_bytes,
            low_fee_path: request.low_fee_only,
            answered_at_height,
            expires_at_height: answered_at_height + P2P_SYNC_RESPONSE_TTL_BLOCKS,
            authorization: empty_network_authorization(&responder.label),
        };
        response.authorization = sign_network_authorization(
            &responder.label,
            "p2p_sync_response",
            &response.unsigned_record(),
        );
        if !response.verify_authorization(&responder.network_public_key) {
            return Err("p2p sync response authorization failed".to_string());
        }
        Ok(response)
    }

    pub fn expected_response_id(&self) -> String {
        p2p_sync_response_id(
            &self.request_id,
            &self.responder_peer_id,
            &p2p_root_value_hash(&self.selected_roots),
            &self.root_inventory_root,
            &self.admission_inventory_root,
            self.answered_at_height,
        )
    }

    pub fn is_live(&self, height: u64) -> bool {
        self.answered_at_height <= height && height <= self.expires_at_height
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "p2p_sync_response",
            "chain_id": CHAIN_ID,
            "response_id": self.response_id,
            "request_id": self.request_id,
            "responder_peer_id": self.responder_peer_id,
            "requester_peer_id": self.requester_peer_id,
            "from_height": self.from_height,
            "to_height": self.to_height,
            "selected_roots": self.selected_roots,
            "selected_root_kinds": self.selected_root_kinds,
            "missing_root_kinds": self.missing_root_kinds,
            "root_inventory_root": self.root_inventory_root,
            "admission_inventory_root": self.admission_inventory_root,
            "bridge_evidence_root": self.bridge_evidence_root,
            "monero_evidence_root": self.monero_evidence_root,
            "response_bytes": self.response_bytes,
            "privacy_cost_bytes": self.privacy_cost_bytes,
            "low_fee_path": self.low_fee_path,
            "answered_at_height": self.answered_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn response_root(&self) -> String {
        domain_hash(
            "P2P-SYNC-RESPONSE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn authorization_root(&self) -> String {
        p2p_authorization_root(&self.authorization)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        insert_string(&mut record, "response_root", self.response_root());
        insert_string(&mut record, "authorization_root", self.authorization_root());
        append_authorization(&mut record, &self.authorization);
        record
    }

    pub fn verify_authorization(&self, expected_public_key: &str) -> bool {
        verify_network_authorization(
            expected_public_key,
            "p2p_sync_response",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn verify(&self, expected_public_key: &str) -> bool {
        self.response_id == self.expected_response_id()
            && self.selected_root_kinds == normalize_strings(self.selected_root_kinds.clone())
            && self.missing_root_kinds == normalize_strings(self.missing_root_kinds.clone())
            && self.verify_authorization(expected_public_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pGossipMessage {
    pub message_id: String,
    pub origin_peer_id: String,
    pub payload_kind: String,
    pub payload_root: String,
    pub payload: Value,
    pub root_inventory_root: String,
    pub admission_inventory_root: String,
    pub bridge_evidence_root: String,
    pub monero_evidence_root: String,
    pub relay_policy: String,
    pub priority: u64,
    pub fee_class: String,
    pub privacy_level: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub authorization: Authorization,
}

impl P2pGossipMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        origin: &P2pPeerHandshake,
        payload_kind: &str,
        payload: Value,
        relay_policy: &str,
        priority: u64,
        fee_class: &str,
        privacy_level: &str,
        created_at_height: u64,
    ) -> P2pResult<Self> {
        if payload_kind.is_empty() {
            return Err("p2p gossip payload kind is required".to_string());
        }
        let payload_root = p2p_payload_root(payload_kind, &payload);
        let message_id = p2p_gossip_message_id(
            &origin.peer_id,
            payload_kind,
            &payload_root,
            &origin.root_inventory_root,
            &origin.admission_inventory_root,
            &origin.bridge_evidence_root,
            &origin.monero_evidence_root,
            created_at_height,
        );
        let mut message = Self {
            message_id,
            origin_peer_id: origin.peer_id.clone(),
            payload_kind: payload_kind.to_string(),
            payload_root,
            payload,
            root_inventory_root: origin.root_inventory_root.clone(),
            admission_inventory_root: origin.admission_inventory_root.clone(),
            bridge_evidence_root: origin.bridge_evidence_root.clone(),
            monero_evidence_root: origin.monero_evidence_root.clone(),
            relay_policy: relay_policy.to_string(),
            priority,
            fee_class: fee_class.to_string(),
            privacy_level: privacy_level.to_string(),
            created_at_height,
            expires_at_height: created_at_height + P2P_GOSSIP_TTL_BLOCKS,
            authorization: empty_network_authorization(&origin.label),
        };
        message.authorization = sign_network_authorization(
            &origin.label,
            "p2p_gossip_message",
            &message.unsigned_record(),
        );
        if !message.verify_authorization(&origin.network_public_key) {
            return Err("p2p gossip authorization failed".to_string());
        }
        Ok(message)
    }

    pub fn expected_message_id(&self) -> String {
        p2p_gossip_message_id(
            &self.origin_peer_id,
            &self.payload_kind,
            &self.payload_root,
            &self.root_inventory_root,
            &self.admission_inventory_root,
            &self.bridge_evidence_root,
            &self.monero_evidence_root,
            self.created_at_height,
        )
    }

    pub fn is_live(&self, height: u64) -> bool {
        self.created_at_height <= height && height <= self.expires_at_height
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "p2p_gossip_message",
            "chain_id": CHAIN_ID,
            "message_id": self.message_id,
            "origin_peer_id": self.origin_peer_id,
            "payload_kind": self.payload_kind,
            "payload_root": self.payload_root,
            "payload": self.payload,
            "root_inventory_root": self.root_inventory_root,
            "admission_inventory_root": self.admission_inventory_root,
            "bridge_evidence_root": self.bridge_evidence_root,
            "monero_evidence_root": self.monero_evidence_root,
            "relay_policy": self.relay_policy,
            "priority": self.priority,
            "fee_class": self.fee_class,
            "privacy_level": self.privacy_level,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn message_root(&self) -> String {
        domain_hash(
            "P2P-GOSSIP-MESSAGE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn authorization_root(&self) -> String {
        p2p_authorization_root(&self.authorization)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        insert_string(&mut record, "message_root", self.message_root());
        insert_string(&mut record, "authorization_root", self.authorization_root());
        append_authorization(&mut record, &self.authorization);
        record
    }

    pub fn verify_authorization(&self, expected_public_key: &str) -> bool {
        verify_network_authorization(
            expected_public_key,
            "p2p_gossip_message",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn verify(&self, expected_public_key: &str) -> bool {
        self.payload_root == p2p_payload_root(&self.payload_kind, &self.payload)
            && self.message_id == self.expected_message_id()
            && self.verify_authorization(expected_public_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pRelayReceipt {
    pub receipt_id: String,
    pub message_id: String,
    pub relay_peer_id: String,
    pub from_peer_id: String,
    pub to_peer_id: String,
    pub payload_root: String,
    pub accepted: bool,
    pub byte_count: u64,
    pub fee_units: u64,
    pub privacy_budget_bytes: u64,
    pub relay_path_commitment: String,
    pub relayed_at_height: u64,
    pub authorization: Authorization,
}

impl P2pRelayReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        relay: &P2pPeerHandshake,
        message: &P2pGossipMessage,
        from_peer_id: &str,
        to_peer_id: &str,
        accepted: bool,
        byte_count: u64,
        fee_units: u64,
        privacy_budget_bytes: u64,
        route_hint: &str,
        relayed_at_height: u64,
    ) -> P2pResult<Self> {
        if from_peer_id.is_empty() || to_peer_id.is_empty() {
            return Err("p2p relay receipt requires from and to peer ids".to_string());
        }
        let relay_path_commitment = p2p_relay_path_commitment(
            &relay.peer_id,
            from_peer_id,
            to_peer_id,
            &message.message_id,
            route_hint,
        );
        let receipt_id = p2p_relay_receipt_id(
            &message.message_id,
            &relay.peer_id,
            from_peer_id,
            to_peer_id,
            accepted,
            byte_count,
            relayed_at_height,
        );
        let mut receipt = Self {
            receipt_id,
            message_id: message.message_id.clone(),
            relay_peer_id: relay.peer_id.clone(),
            from_peer_id: from_peer_id.to_string(),
            to_peer_id: to_peer_id.to_string(),
            payload_root: message.payload_root.clone(),
            accepted,
            byte_count,
            fee_units,
            privacy_budget_bytes,
            relay_path_commitment,
            relayed_at_height,
            authorization: empty_network_authorization(&relay.label),
        };
        receipt.authorization = sign_network_authorization(
            &relay.label,
            "p2p_relay_receipt",
            &receipt.unsigned_record(),
        );
        if !receipt.verify_authorization(&relay.network_public_key) {
            return Err("p2p relay receipt authorization failed".to_string());
        }
        Ok(receipt)
    }

    pub fn expected_receipt_id(&self) -> String {
        p2p_relay_receipt_id(
            &self.message_id,
            &self.relay_peer_id,
            &self.from_peer_id,
            &self.to_peer_id,
            self.accepted,
            self.byte_count,
            self.relayed_at_height,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "p2p_relay_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "message_id": self.message_id,
            "relay_peer_id": self.relay_peer_id,
            "from_peer_id": self.from_peer_id,
            "to_peer_id": self.to_peer_id,
            "payload_root": self.payload_root,
            "accepted": self.accepted,
            "byte_count": self.byte_count,
            "fee_units": self.fee_units,
            "privacy_budget_bytes": self.privacy_budget_bytes,
            "relay_path_commitment": self.relay_path_commitment,
            "relayed_at_height": self.relayed_at_height,
        })
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "P2P-RELAY-RECEIPT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn authorization_root(&self) -> String {
        p2p_authorization_root(&self.authorization)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        insert_string(&mut record, "receipt_root", self.receipt_root());
        insert_string(&mut record, "authorization_root", self.authorization_root());
        append_authorization(&mut record, &self.authorization);
        record
    }

    pub fn verify_authorization(&self, expected_public_key: &str) -> bool {
        verify_network_authorization(
            expected_public_key,
            "p2p_relay_receipt",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn verify(&self, expected_public_key: &str) -> bool {
        self.receipt_id == self.expected_receipt_id()
            && self.verify_authorization(expected_public_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pPeerScorecard {
    pub peer_id: String,
    pub score: i64,
    pub successful_handshakes: u64,
    pub failed_authorizations: u64,
    pub sync_requests_opened: u64,
    pub sync_responses_served: u64,
    pub gossip_messages_accepted: u64,
    pub relay_receipts_accepted: u64,
    pub bandwidth_charged_bytes: u64,
    pub bandwidth_rejected_bytes: u64,
    pub penalties: u64,
    pub rewards: u64,
    pub last_seen_height: u64,
    pub quarantined: bool,
}

impl P2pPeerScorecard {
    pub fn new(peer_id: &str, height: u64) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            score: 0,
            successful_handshakes: 0,
            failed_authorizations: 0,
            sync_requests_opened: 0,
            sync_responses_served: 0,
            gossip_messages_accepted: 0,
            relay_receipts_accepted: 0,
            bandwidth_charged_bytes: 0,
            bandwidth_rejected_bytes: 0,
            penalties: 0,
            rewards: 0,
            last_seen_height: height,
            quarantined: false,
        }
    }

    pub fn apply_delta(&mut self, delta: i64, height: u64) {
        if delta >= 0 {
            self.rewards = self.rewards.saturating_add(delta as u64);
        } else {
            self.penalties = self.penalties.saturating_add(delta.unsigned_abs());
        }
        self.score = clamp_peer_score(self.score.saturating_add(delta));
        self.last_seen_height = height;
        self.quarantined = self.score <= P2P_QUARANTINE_SCORE;
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "p2p_peer_scorecard",
            "chain_id": CHAIN_ID,
            "peer_id": self.peer_id,
            "score": self.score,
            "successful_handshakes": self.successful_handshakes,
            "failed_authorizations": self.failed_authorizations,
            "sync_requests_opened": self.sync_requests_opened,
            "sync_responses_served": self.sync_responses_served,
            "gossip_messages_accepted": self.gossip_messages_accepted,
            "relay_receipts_accepted": self.relay_receipts_accepted,
            "bandwidth_charged_bytes": self.bandwidth_charged_bytes,
            "bandwidth_rejected_bytes": self.bandwidth_rejected_bytes,
            "penalties": self.penalties,
            "rewards": self.rewards,
            "last_seen_height": self.last_seen_height,
            "quarantined": self.quarantined,
        })
    }

    pub fn scorecard_root(&self) -> String {
        domain_hash(
            "P2P-PEER-SCORECARD",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        insert_string(&mut record, "scorecard_root", self.scorecard_root());
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pBandwidthWindow {
    pub window_id: String,
    pub peer_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub byte_limit: u64,
    pub bytes_used: u64,
    pub low_fee_bytes_used: u64,
    pub privacy_bytes_used: u64,
    pub rejected_bytes: u64,
}

impl P2pBandwidthWindow {
    pub fn new(peer_id: &str, window_start_height: u64, byte_limit: u64) -> Self {
        let window_end_height = window_start_height.saturating_add(P2P_BANDWIDTH_WINDOW_BLOCKS - 1);
        let window_id = p2p_bandwidth_window_id(peer_id, window_start_height, window_end_height);
        Self {
            window_id,
            peer_id: peer_id.to_string(),
            window_start_height,
            window_end_height,
            byte_limit,
            bytes_used: 0,
            low_fee_bytes_used: 0,
            privacy_bytes_used: 0,
            rejected_bytes: 0,
        }
    }

    pub fn contains_height(&self, height: u64) -> bool {
        self.window_start_height <= height && height <= self.window_end_height
    }

    pub fn charge(&mut self, byte_count: u64, low_fee_bytes: u64, privacy_bytes: u64) -> bool {
        let projected = self.bytes_used.saturating_add(byte_count);
        if projected > self.byte_limit {
            self.rejected_bytes = self.rejected_bytes.saturating_add(byte_count);
            return false;
        }
        self.bytes_used = projected;
        self.low_fee_bytes_used = self
            .low_fee_bytes_used
            .saturating_add(low_fee_bytes.min(byte_count));
        self.privacy_bytes_used = self
            .privacy_bytes_used
            .saturating_add(privacy_bytes.min(byte_count));
        true
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "p2p_bandwidth_window",
            "chain_id": CHAIN_ID,
            "window_id": self.window_id,
            "peer_id": self.peer_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "byte_limit": self.byte_limit,
            "bytes_used": self.bytes_used,
            "low_fee_bytes_used": self.low_fee_bytes_used,
            "privacy_bytes_used": self.privacy_bytes_used,
            "rejected_bytes": self.rejected_bytes,
        })
    }

    pub fn window_root(&self) -> String {
        domain_hash(
            "P2P-BANDWIDTH-WINDOW",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        insert_string(&mut record, "window_root", self.window_root());
        record
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pOverlayState {
    pub height: u64,
    pub handshakes: BTreeMap<String, P2pPeerHandshake>,
    pub sync_requests: BTreeMap<String, P2pSyncRequest>,
    pub sync_responses: BTreeMap<String, P2pSyncResponse>,
    pub gossip_messages: BTreeMap<String, P2pGossipMessage>,
    pub relay_receipts: BTreeMap<String, P2pRelayReceipt>,
    pub scorecards: BTreeMap<String, P2pPeerScorecard>,
    pub bandwidth_windows: BTreeMap<String, P2pBandwidthWindow>,
    pub root_inventory_roots: BTreeMap<String, String>,
    pub admission_inventory_roots: BTreeMap<String, String>,
    pub evidence_roots: BTreeMap<String, String>,
}

impl P2pOverlayState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn verify_handshake(&self, handshake: &P2pPeerHandshake) -> P2pResult<()> {
        if !handshake.verify() {
            return Err("p2p handshake verification failed".to_string());
        }
        if !handshake.is_live(self.height) {
            return Err("p2p handshake is not live at overlay height".to_string());
        }
        Ok(())
    }

    pub fn insert_handshake(&mut self, handshake: P2pPeerHandshake) -> P2pResult<()> {
        if let Err(error) = self.verify_handshake(&handshake) {
            self.mark_authorization_failure(&handshake.peer_id);
            return Err(error);
        }
        let peer_id = handshake.peer_id.clone();
        self.root_inventory_roots
            .insert(peer_id.clone(), handshake.root_inventory_root.clone());
        self.admission_inventory_roots
            .insert(peer_id.clone(), handshake.admission_inventory_root.clone());
        self.evidence_roots.insert(
            format!("{peer_id}:bridge"),
            handshake.bridge_evidence_root.clone(),
        );
        self.evidence_roots.insert(
            format!("{peer_id}:monero"),
            handshake.monero_evidence_root.clone(),
        );
        self.handshakes.insert(peer_id.clone(), handshake);
        let scorecard = self.scorecard_entry(&peer_id);
        scorecard.successful_handshakes = scorecard.successful_handshakes.saturating_add(1);
        self.reward_peer(&peer_id, P2P_HANDSHAKE_REWARD);
        Ok(())
    }

    pub fn open_sync_request(
        &mut self,
        requester_peer_id: &str,
        target_peer_id: &str,
        from_height: u64,
        to_height: u64,
        requested_root_kinds: Vec<String>,
        low_fee_only: bool,
        include_bridge_evidence: bool,
        include_monero_evidence: bool,
    ) -> P2pResult<P2pSyncRequest> {
        let requester = self
            .handshakes
            .get(requester_peer_id)
            .cloned()
            .ok_or_else(|| "unknown p2p sync requester".to_string())?;
        if !self.handshakes.contains_key(target_peer_id) {
            return Err("unknown p2p sync target".to_string());
        }
        let request = P2pSyncRequest::new(
            &requester,
            target_peer_id,
            from_height,
            to_height,
            requested_root_kinds,
            low_fee_only,
            include_bridge_evidence,
            include_monero_evidence,
            self.height,
        )?;
        self.sync_requests
            .insert(request.request_id.clone(), request.clone());
        let scorecard = self.scorecard_entry(requester_peer_id);
        scorecard.sync_requests_opened = scorecard.sync_requests_opened.saturating_add(1);
        self.reward_peer(requester_peer_id, 1);
        Ok(request)
    }

    pub fn answer_sync_request_from_roots(
        &mut self,
        request_id: &str,
        responder_peer_id: &str,
        root_inventory_root: &str,
        admission_inventory_root: &str,
        selected_roots: Value,
        bridge_evidence_root: &str,
        monero_evidence_root: &str,
    ) -> P2pResult<P2pSyncResponse> {
        let request = self
            .sync_requests
            .get(request_id)
            .cloned()
            .ok_or_else(|| "unknown p2p sync request".to_string())?;
        if !request.is_live(self.height) {
            return Err("p2p sync request is expired".to_string());
        }
        let requester = self
            .handshakes
            .get(&request.requester_peer_id)
            .ok_or_else(|| "unknown p2p sync request signer".to_string())?;
        if !request.verify(&requester.network_public_key) {
            self.mark_authorization_failure(&request.requester_peer_id);
            return Err("p2p sync request verification failed".to_string());
        }
        let responder = self
            .handshakes
            .get(responder_peer_id)
            .cloned()
            .ok_or_else(|| "unknown p2p sync responder".to_string())?;
        let response = P2pSyncResponse::from_roots(
            &request,
            &responder,
            root_inventory_root,
            admission_inventory_root,
            selected_roots,
            bridge_evidence_root,
            monero_evidence_root,
            self.height,
        )?;
        self.root_inventory_roots.insert(
            responder_peer_id.to_string(),
            response.root_inventory_root.clone(),
        );
        self.admission_inventory_roots.insert(
            responder_peer_id.to_string(),
            response.admission_inventory_root.clone(),
        );
        self.evidence_roots.insert(
            format!("{responder_peer_id}:bridge"),
            response.bridge_evidence_root.clone(),
        );
        self.evidence_roots.insert(
            format!("{responder_peer_id}:monero"),
            response.monero_evidence_root.clone(),
        );
        self.sync_responses
            .insert(response.response_id.clone(), response.clone());
        let scorecard = self.scorecard_entry(responder_peer_id);
        scorecard.sync_responses_served = scorecard.sync_responses_served.saturating_add(1);
        self.reward_peer(responder_peer_id, P2P_SYNC_REWARD);
        Ok(response)
    }

    pub fn build_gossip_message(
        &self,
        origin_peer_id: &str,
        payload_kind: &str,
        payload: Value,
        relay_policy: &str,
        priority: u64,
        fee_class: &str,
        privacy_level: &str,
    ) -> P2pResult<P2pGossipMessage> {
        let origin = self
            .handshakes
            .get(origin_peer_id)
            .ok_or_else(|| "unknown p2p gossip origin".to_string())?;
        P2pGossipMessage::new(
            origin,
            payload_kind,
            payload,
            relay_policy,
            priority,
            fee_class,
            privacy_level,
            self.height,
        )
    }

    pub fn enqueue_gossip(&mut self, message: P2pGossipMessage) -> P2pResult<()> {
        let origin = self
            .handshakes
            .get(&message.origin_peer_id)
            .ok_or_else(|| "unknown p2p gossip origin".to_string())?;
        if !message.verify(&origin.network_public_key) {
            self.mark_authorization_failure(&message.origin_peer_id);
            return Err("p2p gossip verification failed".to_string());
        }
        if !message.is_live(self.height) {
            return Err("p2p gossip message is expired".to_string());
        }
        let origin_peer_id = message.origin_peer_id.clone();
        self.gossip_messages
            .insert(message.message_id.clone(), message);
        let scorecard = self.scorecard_entry(&origin_peer_id);
        scorecard.gossip_messages_accepted = scorecard.gossip_messages_accepted.saturating_add(1);
        self.reward_peer(&origin_peer_id, P2P_GOSSIP_REWARD);
        Ok(())
    }

    pub fn record_relay_receipt(&mut self, receipt: P2pRelayReceipt) -> P2pResult<()> {
        let relay = self
            .handshakes
            .get(&receipt.relay_peer_id)
            .ok_or_else(|| "unknown p2p relay peer".to_string())?;
        if !receipt.verify(&relay.network_public_key) {
            self.mark_authorization_failure(&receipt.relay_peer_id);
            return Err("p2p relay receipt verification failed".to_string());
        }
        let message = self
            .gossip_messages
            .get(&receipt.message_id)
            .ok_or_else(|| "unknown p2p relay message".to_string())?;
        if message.payload_root != receipt.payload_root {
            self.penalize_peer(&receipt.relay_peer_id, P2P_AUTH_FAILURE_PENALTY);
            return Err("p2p relay receipt payload root mismatch".to_string());
        }
        let relay_peer_id = receipt.relay_peer_id.clone();
        self.relay_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        let scorecard = self.scorecard_entry(&relay_peer_id);
        scorecard.relay_receipts_accepted = scorecard.relay_receipts_accepted.saturating_add(1);
        self.reward_peer(&relay_peer_id, P2P_RELAY_REWARD);
        Ok(())
    }

    pub fn reward_peer(&mut self, peer_id: &str, reward: i64) {
        let height = self.height;
        let scorecard = self.scorecard_entry(peer_id);
        scorecard.apply_delta(reward.abs(), height);
    }

    pub fn penalize_peer(&mut self, peer_id: &str, penalty: i64) {
        let height = self.height;
        let scorecard = self.scorecard_entry(peer_id);
        scorecard.apply_delta(-penalty.abs(), height);
    }

    pub fn charge_bandwidth(
        &mut self,
        peer_id: &str,
        byte_count: u64,
        low_fee_bytes: u64,
        privacy_bytes: u64,
    ) -> P2pResult<P2pBandwidthWindow> {
        if peer_id.is_empty() {
            return Err("p2p bandwidth peer id is required".to_string());
        }
        let window_start = current_bandwidth_window_start(self.height);
        let window_end = window_start.saturating_add(P2P_BANDWIDTH_WINDOW_BLOCKS - 1);
        let window_id = p2p_bandwidth_window_id(peer_id, window_start, window_end);
        let accepted = {
            let window = self
                .bandwidth_windows
                .entry(window_id.clone())
                .or_insert_with(|| {
                    P2pBandwidthWindow::new(
                        peer_id,
                        window_start,
                        P2P_DEFAULT_BANDWIDTH_LIMIT_BYTES,
                    )
                });
            window.charge(byte_count, low_fee_bytes, privacy_bytes)
        };
        let height = self.height;
        let scorecard = self.scorecard_entry(peer_id);
        if accepted {
            scorecard.bandwidth_charged_bytes =
                scorecard.bandwidth_charged_bytes.saturating_add(byte_count);
            scorecard.last_seen_height = height;
        } else {
            scorecard.bandwidth_rejected_bytes = scorecard
                .bandwidth_rejected_bytes
                .saturating_add(byte_count);
            self.penalize_peer(peer_id, P2P_BANDWIDTH_REJECT_PENALTY);
        }
        self.bandwidth_windows
            .get(&window_id)
            .cloned()
            .ok_or_else(|| "p2p bandwidth window missing after charge".to_string())
    }

    pub fn peer_root(&self) -> String {
        merkle_root(
            "P2P-PEER",
            &self
                .handshakes
                .values()
                .map(P2pPeerHandshake::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sync_request_root(&self) -> String {
        merkle_root(
            "P2P-SYNC-REQUEST",
            &self
                .sync_requests
                .values()
                .map(P2pSyncRequest::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sync_response_root(&self) -> String {
        merkle_root(
            "P2P-SYNC-RESPONSE",
            &self
                .sync_responses
                .values()
                .map(P2pSyncResponse::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sync_root(&self) -> String {
        domain_hash(
            "P2P-SYNC",
            &[
                HashPart::Str(&self.sync_request_root()),
                HashPart::Str(&self.sync_response_root()),
            ],
            32,
        )
    }

    pub fn gossip_root(&self) -> String {
        merkle_root(
            "P2P-GOSSIP",
            &self
                .gossip_messages
                .values()
                .map(P2pGossipMessage::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn receipt_root(&self) -> String {
        merkle_root(
            "P2P-RELAY-RECEIPT",
            &self
                .relay_receipts
                .values()
                .map(P2pRelayReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn relay_receipt_root(&self) -> String {
        self.receipt_root()
    }

    pub fn scorecard_root(&self) -> String {
        merkle_root(
            "P2P-PEER-SCORECARD",
            &self
                .scorecards
                .values()
                .map(P2pPeerScorecard::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn bandwidth_root(&self) -> String {
        merkle_root(
            "P2P-BANDWIDTH-WINDOW",
            &self
                .bandwidth_windows
                .values()
                .map(P2pBandwidthWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn root_inventory_commitment_root(&self) -> String {
        map_string_root("P2P-ROOT-INVENTORY-COMMITMENT", &self.root_inventory_roots)
    }

    pub fn admission_inventory_commitment_root(&self) -> String {
        map_string_root(
            "P2P-ADMISSION-INVENTORY-COMMITMENT",
            &self.admission_inventory_roots,
        )
    }

    pub fn evidence_root(&self) -> String {
        map_string_root("P2P-EVIDENCE-ROOT", &self.evidence_roots)
    }

    pub fn root_root(&self) -> String {
        domain_hash(
            "P2P-ROOT-COMMITMENT",
            &[
                HashPart::Str(&self.root_inventory_commitment_root()),
                HashPart::Str(&self.admission_inventory_commitment_root()),
                HashPart::Str(&self.evidence_root()),
            ],
            32,
        )
    }

    pub fn overlay_root(&self) -> String {
        domain_hash(
            "P2P-OVERLAY-STATE",
            &[
                HashPart::Str(&self.peer_root()),
                HashPart::Str(&self.sync_root()),
                HashPart::Str(&self.gossip_root()),
                HashPart::Str(&self.receipt_root()),
                HashPart::Str(&self.scorecard_root()),
                HashPart::Str(&self.bandwidth_root()),
                HashPart::Str(&self.root_root()),
            ],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "p2p_overlay_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "protocol_version": P2P_PROTOCOL_VERSION,
            "peer_root": self.peer_root(),
            "sync_request_root": self.sync_request_root(),
            "sync_response_root": self.sync_response_root(),
            "sync_root": self.sync_root(),
            "gossip_root": self.gossip_root(),
            "receipt_root": self.receipt_root(),
            "scorecard_root": self.scorecard_root(),
            "bandwidth_root": self.bandwidth_root(),
            "root_inventory_commitment_root": self.root_inventory_commitment_root(),
            "admission_inventory_commitment_root": self.admission_inventory_commitment_root(),
            "evidence_root": self.evidence_root(),
            "root_root": self.root_root(),
            "peer_count": self.handshakes.len() as u64,
            "live_peer_count": self.handshakes.values().filter(|peer| peer.is_live(self.height)).count() as u64,
            "sync_request_count": self.sync_requests.len() as u64,
            "sync_response_count": self.sync_responses.len() as u64,
            "gossip_message_count": self.gossip_messages.len() as u64,
            "relay_receipt_count": self.relay_receipts.len() as u64,
            "quarantined_peer_count": self.scorecards.values().filter(|score| score.quarantined).count() as u64,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        insert_string(&mut record, "overlay_root", self.overlay_root());
        record
    }

    fn mark_authorization_failure(&mut self, peer_id: &str) {
        let scorecard = self.scorecard_entry(peer_id);
        scorecard.failed_authorizations = scorecard.failed_authorizations.saturating_add(1);
        self.penalize_peer(peer_id, P2P_AUTH_FAILURE_PENALTY);
    }

    fn scorecard_entry(&mut self, peer_id: &str) -> &mut P2pPeerScorecard {
        self.scorecards
            .entry(peer_id.to_string())
            .or_insert_with(|| P2pPeerScorecard::new(peer_id, self.height))
    }
}

pub fn p2p_capability_id(
    role: &str,
    capability: &str,
    root_kinds: &[String],
    min_protocol_version: u64,
    max_protocol_version: u64,
    supports_low_fee_sync: bool,
    supports_private_relay: bool,
) -> String {
    let root_kind_value = Value::Array(
        normalize_strings(root_kinds.to_vec())
            .into_iter()
            .map(Value::String)
            .collect(),
    );
    domain_hash(
        "P2P-CAPABILITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role),
            HashPart::Str(capability),
            HashPart::Json(&root_kind_value),
            HashPart::Int(min_protocol_version as i128),
            HashPart::Int(max_protocol_version as i128),
            HashPart::Int(supports_low_fee_sync as i128),
            HashPart::Int(supports_private_relay as i128),
        ],
        32,
    )
}

pub fn p2p_capability_root(capabilities: &[P2pCapability]) -> String {
    let mut records = capabilities
        .iter()
        .map(P2pCapability::public_record)
        .collect::<Vec<_>>();
    records.sort_by_key(p2p_root_value_hash);
    merkle_root("P2P-CAPABILITY-SET", &records)
}

pub fn p2p_role_root(roles: &[P2pPeerRole]) -> String {
    merkle_root(
        "P2P-PEER-ROLE",
        &roles_as_strings(&normalize_roles(roles.to_vec()))
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>(),
    )
}

pub fn p2p_transport_route_commitment(
    label: &str,
    transport: &str,
    route_hint: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "P2P-TRANSPORT-ROUTE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(transport),
            HashPart::Str(route_hint),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn p2p_peer_id(
    label: &str,
    network_key_id: &str,
    roles: &[P2pPeerRole],
    transport: &str,
    transport_route_commitment: &str,
) -> String {
    domain_hash(
        "P2P-PEER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(network_key_id),
            HashPart::Str(&p2p_role_root(roles)),
            HashPart::Str(transport),
            HashPart::Str(transport_route_commitment),
        ],
        32,
    )
}

pub fn p2p_handshake_id(
    peer_id: &str,
    capability_root: &str,
    root_inventory_root: &str,
    admission_inventory_root: &str,
    bridge_evidence_root: &str,
    monero_evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "P2P-HANDSHAKE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(peer_id),
            HashPart::Str(capability_root),
            HashPart::Str(root_inventory_root),
            HashPart::Str(admission_inventory_root),
            HashPart::Str(bridge_evidence_root),
            HashPart::Str(monero_evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn p2p_sync_request_id(
    requester_peer_id: &str,
    target_peer_id: &str,
    from_height: u64,
    to_height: u64,
    requested_root_kinds: &[String],
    have_root_inventory_root: &str,
    have_admission_inventory_root: &str,
    opened_at_height: u64,
) -> String {
    let requested_roots = Value::Array(
        normalize_strings(requested_root_kinds.to_vec())
            .into_iter()
            .map(Value::String)
            .collect(),
    );
    domain_hash(
        "P2P-SYNC-REQUEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(requester_peer_id),
            HashPart::Str(target_peer_id),
            HashPart::Int(from_height as i128),
            HashPart::Int(to_height as i128),
            HashPart::Json(&requested_roots),
            HashPart::Str(have_root_inventory_root),
            HashPart::Str(have_admission_inventory_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn p2p_sync_response_id(
    request_id: &str,
    responder_peer_id: &str,
    selected_root: &str,
    root_inventory_root: &str,
    admission_inventory_root: &str,
    answered_at_height: u64,
) -> String {
    domain_hash(
        "P2P-SYNC-RESPONSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_id),
            HashPart::Str(responder_peer_id),
            HashPart::Str(selected_root),
            HashPart::Str(root_inventory_root),
            HashPart::Str(admission_inventory_root),
            HashPart::Int(answered_at_height as i128),
        ],
        32,
    )
}

pub fn p2p_payload_root(payload_kind: &str, payload: &Value) -> String {
    domain_hash(
        "P2P-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(payload_kind),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn p2p_gossip_message_id(
    origin_peer_id: &str,
    payload_kind: &str,
    payload_root: &str,
    root_inventory_root: &str,
    admission_inventory_root: &str,
    bridge_evidence_root: &str,
    monero_evidence_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "P2P-GOSSIP-MESSAGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(origin_peer_id),
            HashPart::Str(payload_kind),
            HashPart::Str(payload_root),
            HashPart::Str(root_inventory_root),
            HashPart::Str(admission_inventory_root),
            HashPart::Str(bridge_evidence_root),
            HashPart::Str(monero_evidence_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn p2p_relay_path_commitment(
    relay_peer_id: &str,
    from_peer_id: &str,
    to_peer_id: &str,
    message_id: &str,
    route_hint: &str,
) -> String {
    domain_hash(
        "P2P-RELAY-PATH",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(relay_peer_id),
            HashPart::Str(from_peer_id),
            HashPart::Str(to_peer_id),
            HashPart::Str(message_id),
            HashPart::Str(route_hint),
        ],
        32,
    )
}

pub fn p2p_relay_receipt_id(
    message_id: &str,
    relay_peer_id: &str,
    from_peer_id: &str,
    to_peer_id: &str,
    accepted: bool,
    byte_count: u64,
    relayed_at_height: u64,
) -> String {
    domain_hash(
        "P2P-RELAY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(message_id),
            HashPart::Str(relay_peer_id),
            HashPart::Str(from_peer_id),
            HashPart::Str(to_peer_id),
            HashPart::Int(accepted as i128),
            HashPart::Int(byte_count as i128),
            HashPart::Int(relayed_at_height as i128),
        ],
        32,
    )
}

pub fn p2p_bandwidth_window_id(
    peer_id: &str,
    window_start_height: u64,
    window_end_height: u64,
) -> String {
    domain_hash(
        "P2P-BANDWIDTH-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(peer_id),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
        ],
        32,
    )
}

pub fn p2p_authorization_root(authorization: &Authorization) -> String {
    domain_hash(
        "P2P-AUTHORIZATION",
        &[HashPart::Json(&p2p_authorization_record(authorization))],
        32,
    )
}

pub fn p2p_authorization_record(authorization: &Authorization) -> Value {
    json!({
        "signer_label": authorization.signer_label,
        "auth_scheme": authorization.auth_scheme,
        "auth_public_key": authorization.auth_public_key,
        "auth_transcript_hash": authorization.auth_transcript_hash,
        "auth_signature": authorization.auth_signature,
    })
}

pub fn p2p_root_value_hash(value: &Value) -> String {
    domain_hash(
        "P2P-ROOT-VALUE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

fn append_authorization(record: &mut Value, authorization: &Authorization) {
    if let Some(object) = record.as_object_mut() {
        object.insert(
            "auth_signer_label".to_string(),
            Value::String(authorization.signer_label.clone()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(authorization.auth_signature.clone()),
        );
    }
}

fn insert_string(record: &mut Value, key: &str, value: String) {
    if let Some(object) = record.as_object_mut() {
        object.insert(key.to_string(), Value::String(value));
    }
}

fn empty_network_authorization(label: &str) -> Authorization {
    Authorization {
        signer_label: label.to_string(),
        auth_scheme: CryptoRole::NetworkSignature.scheme().to_string(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

fn normalize_roles(roles: Vec<P2pPeerRole>) -> Vec<P2pPeerRole> {
    let mut roles = roles;
    roles.sort();
    roles.dedup();
    roles
}

fn roles_as_strings(roles: &[P2pPeerRole]) -> Vec<String> {
    roles
        .iter()
        .map(P2pPeerRole::as_str)
        .map(str::to_string)
        .collect()
}

fn normalize_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn default_root(value: &str, empty_domain: &str) -> String {
    if value.is_empty() {
        merkle_root(empty_domain, &[])
    } else {
        value.to_string()
    }
}

fn filter_selected_roots(roots: &Value, requested_root_kinds: &[String]) -> Value {
    let Some(source) = roots.as_object() else {
        return roots.clone();
    };
    let mut filtered = Map::new();
    for kind in normalize_strings(requested_root_kinds.to_vec()) {
        if let Some(value) = source.get(&kind) {
            filtered.insert(kind, value.clone());
        }
    }
    Value::Object(filtered)
}

fn selected_root_kinds(roots: &Value, requested_root_kinds: &[String]) -> Vec<String> {
    let Some(source) = roots.as_object() else {
        return Vec::new();
    };
    normalize_strings(
        requested_root_kinds
            .iter()
            .filter(|kind| {
                source
                    .get(*kind)
                    .map(|value| !value.is_null() && value != "")
                    .unwrap_or(false)
            })
            .cloned()
            .collect(),
    )
}

fn missing_root_kinds(
    requested_root_kinds: &[String],
    selected_root_kinds: &[String],
) -> Vec<String> {
    let selected = selected_root_kinds.iter().cloned().collect::<BTreeSet<_>>();
    normalize_strings(
        requested_root_kinds
            .iter()
            .filter(|kind| !selected.contains(*kind))
            .cloned()
            .collect(),
    )
}

fn json_byte_len(value: &Value) -> u64 {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .unwrap_or(0)
}

fn current_bandwidth_window_start(height: u64) -> u64 {
    (height / P2P_BANDWIDTH_WINDOW_BLOCKS) * P2P_BANDWIDTH_WINDOW_BLOCKS
}

fn map_string_root(domain: &str, values: &BTreeMap<String, String>) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|(key, value)| {
                json!({
                    "key": key,
                    "value": value,
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn clamp_peer_score(score: i64) -> i64 {
    score.clamp(P2P_MIN_PEER_SCORE, P2P_MAX_PEER_SCORE)
}
