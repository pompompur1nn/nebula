use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    api::ApiControlPlaneState,
    crypto_policy::{
        crypto_policy_root, public_key_for_label, sign_network_authorization,
        verify_network_authorization, Authorization, CryptoRole,
    },
    hash::{domain_hash, json_size, merkle_root, HashPart},
    CHAIN_ID,
};

pub type RpcResult<T> = Result<T, RpcError>;

pub const RPC_JSONRPC_VERSION: &str = "2.0";
pub const RPC_CONTROL_PLANE_VERSION: &str = "nebula-l2-jsonrpc-control-plane-v1";
pub const RPC_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 50;
pub const RPC_DEFAULT_MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const RPC_DEFAULT_IDEMPOTENCY_CHARGE_UNITS: u64 = 1;

pub const RPC_ERROR_PARSE: i64 = -32700;
pub const RPC_ERROR_INVALID_REQUEST: i64 = -32600;
pub const RPC_ERROR_METHOD_NOT_FOUND: i64 = -32601;
pub const RPC_ERROR_INVALID_PARAMS: i64 = -32602;
pub const RPC_ERROR_INTERNAL: i64 = -32603;
pub const RPC_ERROR_UNAUTHORIZED: i64 = -32001;
pub const RPC_ERROR_EXPIRED: i64 = -32002;
pub const RPC_ERROR_IDEMPOTENCY_CONFLICT: i64 = -32009;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcMethod {
    Status,
    Health,
    SubmitPrivateTx,
    LowFeeQuote,
    ProduceBlock,
    ApiRoutes,
    StorageManifest,
    P2pStatus,
    MoneroStatus,
    BridgeStatus,
}

impl RpcMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Health => "health",
            Self::SubmitPrivateTx => "submit_private_tx",
            Self::LowFeeQuote => "low_fee_quote",
            Self::ProduceBlock => "produce_block",
            Self::ApiRoutes => "api_routes",
            Self::StorageManifest => "storage_manifest",
            Self::P2pStatus => "p2p_status",
            Self::MoneroStatus => "monero_status",
            Self::BridgeStatus => "bridge_status",
        }
    }

    pub fn from_method_name(method: &str) -> RpcResult<Self> {
        match method {
            "status" | "nebula.status" => Ok(Self::Status),
            "health" | "nebula.health" => Ok(Self::Health),
            "submit_private_tx" | "nebula.submit_private_tx" => Ok(Self::SubmitPrivateTx),
            "low_fee_quote" | "nebula.low_fee_quote" => Ok(Self::LowFeeQuote),
            "produce_block" | "nebula.produce_block" => Ok(Self::ProduceBlock),
            "api_routes" | "nebula.api_routes" => Ok(Self::ApiRoutes),
            "storage_manifest" | "nebula.storage_manifest" => Ok(Self::StorageManifest),
            "p2p_status" | "nebula.p2p_status" => Ok(Self::P2pStatus),
            "monero_status" | "nebula.monero_status" => Ok(Self::MoneroStatus),
            "bridge_status" | "nebula.bridge_status" => Ok(Self::BridgeStatus),
            _ => Err(RpcError::method_not_found(method)),
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::Status,
            Self::Health,
            Self::SubmitPrivateTx,
            Self::LowFeeQuote,
            Self::ProduceBlock,
            Self::ApiRoutes,
            Self::StorageManifest,
            Self::P2pStatus,
            Self::MoneroStatus,
            Self::BridgeStatus,
        ]
    }

    pub fn requires_idempotency(&self) -> bool {
        matches!(
            self,
            Self::SubmitPrivateTx | Self::ProduceBlock | Self::StorageManifest
        )
    }

    pub fn allows_private_payload(&self) -> bool {
        matches!(self, Self::SubmitPrivateTx)
    }

    pub fn requires_auth(&self) -> bool {
        matches!(self, Self::SubmitPrivateTx | Self::ProduceBlock)
    }

    pub fn is_low_fee_command(&self) -> bool {
        matches!(self, Self::LowFeeQuote | Self::SubmitPrivateTx)
    }

    pub fn default_request_payload_kind(&self) -> &'static str {
        match self {
            Self::Status => "status_snapshot_request_hash",
            Self::Health => "health_request_hash",
            Self::SubmitPrivateTx => "private_tx_request_hash",
            Self::LowFeeQuote => "low_fee_quote_request_hash",
            Self::ProduceBlock => "produce_block_request_hash",
            Self::ApiRoutes => "api_routes_request_hash",
            Self::StorageManifest => "storage_manifest_request_hash",
            Self::P2pStatus => "p2p_status_request_hash",
            Self::MoneroStatus => "monero_status_request_hash",
            Self::BridgeStatus => "bridge_status_request_hash",
        }
    }

    pub fn default_response_payload_kind(&self) -> &'static str {
        match self {
            Self::Status => "status_snapshot_response_hash",
            Self::Health => "health_response_hash",
            Self::SubmitPrivateTx => "private_tx_receipt_hash",
            Self::LowFeeQuote => "low_fee_quote_response_hash",
            Self::ProduceBlock => "produce_block_response_hash",
            Self::ApiRoutes => "api_routes_response_hash",
            Self::StorageManifest => "storage_manifest_response_hash",
            Self::P2pStatus => "p2p_status_response_hash",
            Self::MoneroStatus => "monero_status_response_hash",
            Self::BridgeStatus => "bridge_status_response_hash",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcMethodRecord {
    pub method_id: String,
    pub node_id: String,
    pub operator_label: String,
    pub network_public_key: String,
    pub method: RpcMethod,
    pub method_name: String,
    pub request_payload_kind: String,
    pub response_payload_kind: String,
    pub requires_auth: bool,
    pub allows_private_payload: bool,
    pub idempotent: bool,
    pub low_fee_eligible: bool,
    pub public_metadata_root: String,
    pub api_route_root: String,
    pub api_control_plane_state_root: String,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub crypto_policy_root: String,
    pub authorization: Option<Authorization>,
}

impl RpcMethodRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: &str,
        operator_label: &str,
        method: RpcMethod,
        request_payload_kind: &str,
        response_payload_kind: &str,
        public_metadata: &Value,
        api_route_root: &str,
        api_control_plane_state_root: &str,
        registered_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let public_metadata_root = rpc_public_metadata_root(public_metadata);
        let method_name = method.as_str().to_string();
        let method_id = rpc_method_id(
            &method_name,
            request_payload_kind,
            response_payload_kind,
            &public_metadata_root,
        );
        let network_public_key =
            public_key_for_label(CryptoRole::NetworkSignature, operator_label).public_key;
        Self {
            method_id,
            node_id: node_id.to_string(),
            operator_label: operator_label.to_string(),
            network_public_key,
            method_name,
            request_payload_kind: request_payload_kind.to_string(),
            response_payload_kind: response_payload_kind.to_string(),
            requires_auth: method.requires_auth(),
            allows_private_payload: method.allows_private_payload(),
            idempotent: method.requires_idempotency(),
            low_fee_eligible: method.is_low_fee_command(),
            method,
            public_metadata_root,
            api_route_root: api_route_root.to_string(),
            api_control_plane_state_root: api_control_plane_state_root.to_string(),
            registered_at_height,
            expires_at_height,
            crypto_policy_root: crypto_policy_root(),
            authorization: None,
        }
    }

    pub fn signed(mut self) -> Self {
        self.authorization = Some(sign_network_authorization(
            &self.operator_label,
            "rpc_method_record",
            &self.unsigned_record(),
        ));
        self
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "rpc_method_record",
            "chain_id": CHAIN_ID,
            "rpc_version": RPC_CONTROL_PLANE_VERSION,
            "method_id": self.method_id,
            "node_id": self.node_id,
            "operator_label": self.operator_label,
            "network_public_key": self.network_public_key,
            "method": self.method_name,
            "request_payload_kind": self.request_payload_kind,
            "response_payload_kind": self.response_payload_kind,
            "requires_auth": self.requires_auth,
            "allows_private_payload": self.allows_private_payload,
            "idempotent": self.idempotent,
            "low_fee_eligible": self.low_fee_eligible,
            "public_metadata_root": self.public_metadata_root,
            "api_route_root": self.api_route_root,
            "api_control_plane_state_root": self.api_control_plane_state_root,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record.as_object_mut().expect("rpc method record object");
        object.insert("method_root".to_string(), Value::String(self.method_root()));
        if let Some(authorization) = &self.authorization {
            insert_authorization_fields(object, authorization);
        }
        record
    }

    pub fn method_root(&self) -> String {
        domain_hash(
            "RPC-METHOD-RECORD",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn verify_authorization(&self) -> bool {
        match &self.authorization {
            Some(authorization) => verify_network_authorization(
                &self.network_public_key,
                "rpc_method_record",
                &self.unsigned_record(),
                authorization,
            ),
            None => false,
        }
    }

    pub fn is_live(&self, height: u64) -> bool {
        self.registered_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub request_id: String,
    pub client_request_id: Option<Value>,
    pub client_request_id_hash: String,
    pub method: RpcMethod,
    pub method_name: String,
    pub method_id: String,
    pub client_commitment: String,
    pub idempotency_key_hash: String,
    pub payload_hash: String,
    pub payload_kind: String,
    pub payload_bytes: u64,
    pub private_payload: bool,
    pub public_metadata_root: String,
    pub received_at_height: u64,
    pub expires_at_height: u64,
    pub max_response_bytes: u64,
}

impl RpcRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn from_payload(
        method: RpcMethod,
        payload: &Value,
        client_commitment: &str,
        idempotency_key: &str,
        payload_kind: &str,
        public_metadata: &Value,
        received_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let private_payload = method.allows_private_payload();
        Self::from_payload_with_id(
            None,
            method,
            payload,
            client_commitment,
            idempotency_key,
            payload_kind,
            private_payload,
            public_metadata,
            received_at_height,
            expires_at_height,
            RPC_DEFAULT_MAX_RESPONSE_BYTES,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_payload_with_id(
        client_request_id: Option<Value>,
        method: RpcMethod,
        payload: &Value,
        client_commitment: &str,
        idempotency_key: &str,
        payload_kind: &str,
        private_payload: bool,
        public_metadata: &Value,
        received_at_height: u64,
        expires_at_height: u64,
        max_response_bytes: u64,
    ) -> Self {
        let method_name = method.as_str().to_string();
        let public_metadata_root = rpc_public_metadata_root(public_metadata);
        let client_request_id_hash = rpc_client_request_id_hash(&client_request_id);
        let idempotency_key_hash = rpc_idempotency_key_hash(idempotency_key);
        let payload_hash = rpc_payload_hash(&method_name, payload);
        let method_id = rpc_method_id(
            &method_name,
            payload_kind,
            method.default_response_payload_kind(),
            &rpc_public_metadata_root(&json!({})),
        );
        let request_id = rpc_request_id(
            &method_name,
            &client_request_id_hash,
            client_commitment,
            &idempotency_key_hash,
            &payload_hash,
            &public_metadata_root,
            received_at_height,
        );
        Self {
            jsonrpc: RPC_JSONRPC_VERSION.to_string(),
            request_id,
            client_request_id,
            client_request_id_hash,
            method,
            method_name,
            method_id,
            client_commitment: client_commitment.to_string(),
            idempotency_key_hash,
            payload_hash,
            payload_kind: payload_kind.to_string(),
            payload_bytes: json_size(payload) as u64,
            private_payload,
            public_metadata_root,
            received_at_height,
            expires_at_height,
            max_response_bytes,
        }
    }

    pub fn from_jsonrpc_value(
        value: &Value,
        received_at_height: u64,
        ttl_blocks: u64,
    ) -> RpcResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| RpcError::invalid_request("json-rpc request must be an object"))?;
        let jsonrpc = object
            .get("jsonrpc")
            .and_then(Value::as_str)
            .unwrap_or(RPC_JSONRPC_VERSION);
        if jsonrpc != RPC_JSONRPC_VERSION {
            return Err(RpcError::invalid_request("unsupported json-rpc version"));
        }
        let method_name = object
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_request("json-rpc method is required"))?;
        let method = RpcMethod::from_method_name(method_name)?;
        let payload = object.get("params").cloned().unwrap_or(Value::Null);
        let client_request_id = object.get("id").cloned();
        let client_commitment = object
            .get("client_commitment")
            .and_then(Value::as_str)
            .unwrap_or("anonymous");
        let idempotency_key = object
            .get("idempotency_key")
            .and_then(Value::as_str)
            .unwrap_or("");
        let payload_kind = object
            .get("payload_kind")
            .and_then(Value::as_str)
            .unwrap_or_else(|| method.default_request_payload_kind());
        let private_payload = object
            .get("private_payload")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| method.allows_private_payload());
        let public_metadata = object
            .get("public_metadata")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let max_response_bytes = object
            .get("max_response_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(RPC_DEFAULT_MAX_RESPONSE_BYTES);
        let expires_at_height = received_at_height.saturating_add(ttl_blocks);
        Ok(Self::from_payload_with_id(
            client_request_id,
            method,
            &payload,
            client_commitment,
            idempotency_key,
            payload_kind,
            private_payload,
            &public_metadata,
            received_at_height,
            expires_at_height,
            max_response_bytes,
        ))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rpc_request",
            "chain_id": CHAIN_ID,
            "rpc_version": RPC_CONTROL_PLANE_VERSION,
            "jsonrpc": self.jsonrpc,
            "request_id": self.request_id,
            "client_request_id": self.client_request_id,
            "client_request_id_hash": self.client_request_id_hash,
            "method": self.method_name,
            "method_id": self.method_id,
            "client_commitment": self.client_commitment,
            "idempotency_key_hash": self.idempotency_key_hash,
            "payload_hash": self.payload_hash,
            "payload_kind": self.payload_kind,
            "payload_bytes": self.payload_bytes,
            "private_payload": self.private_payload,
            "public_metadata_root": self.public_metadata_root,
            "received_at_height": self.received_at_height,
            "expires_at_height": self.expires_at_height,
            "max_response_bytes": self.max_response_bytes,
        })
    }

    pub fn root(&self) -> String {
        domain_hash("RPC-REQUEST", &[HashPart::Json(&self.public_record())], 32)
    }

    pub fn verify_id(&self) -> bool {
        self.request_id
            == rpc_request_id(
                &self.method_name,
                &self.client_request_id_hash,
                &self.client_commitment,
                &self.idempotency_key_hash,
                &self.payload_hash,
                &self.public_metadata_root,
                self.received_at_height,
            )
    }

    pub fn explicit_idempotency_key(&self) -> bool {
        self.idempotency_key_hash != rpc_idempotency_key_hash("")
    }

    pub fn idempotency_cache_key(&self) -> String {
        let key_material = if self.explicit_idempotency_key() {
            self.idempotency_key_hash.as_str()
        } else {
            self.request_id.as_str()
        };
        domain_hash(
            "RPC-IDEMPOTENCY-CACHE-KEY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.method_id),
                HashPart::Str(&self.client_commitment),
                HashPart::Str(key_material),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub code_name: String,
    pub code_hash: String,
    pub message: String,
    pub data_root: String,
    pub retryable: bool,
    pub retry_after_height: Option<u64>,
    pub public_metadata_root: String,
}

impl RpcError {
    pub fn new(
        code: i64,
        code_name: &str,
        message: &str,
        data: &Value,
        retryable: bool,
        retry_after_height: Option<u64>,
    ) -> Self {
        Self {
            code,
            code_name: code_name.to_string(),
            code_hash: rpc_error_code_hash(code_name),
            message: message.to_string(),
            data_root: rpc_payload_hash("rpc_error_data", data),
            retryable,
            retry_after_height,
            public_metadata_root: rpc_public_metadata_root(&json!({})),
        }
    }

    pub fn parse(message: &str) -> Self {
        Self::new(
            RPC_ERROR_PARSE,
            "parse_error",
            message,
            &json!({}),
            false,
            None,
        )
    }

    pub fn invalid_request(message: &str) -> Self {
        Self::new(
            RPC_ERROR_INVALID_REQUEST,
            "invalid_request",
            message,
            &json!({}),
            false,
            None,
        )
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            RPC_ERROR_METHOD_NOT_FOUND,
            "method_not_found",
            "rpc method not found",
            &json!({ "method": method }),
            false,
            None,
        )
    }

    pub fn invalid_params(message: &str) -> Self {
        Self::new(
            RPC_ERROR_INVALID_PARAMS,
            "invalid_params",
            message,
            &json!({}),
            false,
            None,
        )
    }

    pub fn internal(message: &str) -> Self {
        Self::new(
            RPC_ERROR_INTERNAL,
            "internal_error",
            message,
            &json!({}),
            true,
            None,
        )
    }

    pub fn unauthorized(message: &str) -> Self {
        Self::new(
            RPC_ERROR_UNAUTHORIZED,
            "unauthorized",
            message,
            &json!({}),
            false,
            None,
        )
    }

    pub fn expired_request(height: u64) -> Self {
        Self::new(
            RPC_ERROR_EXPIRED,
            "expired_request",
            "rpc request expired",
            &json!({ "height": height }),
            false,
            None,
        )
    }

    pub fn idempotency_conflict(cache_key: &str) -> Self {
        Self::new(
            RPC_ERROR_IDEMPOTENCY_CONFLICT,
            "idempotency_conflict",
            "idempotency key was already used with different request material",
            &json!({ "cache_key": cache_key }),
            false,
            None,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rpc_error",
            "chain_id": CHAIN_ID,
            "rpc_version": RPC_CONTROL_PLANE_VERSION,
            "code": self.code,
            "code_name": self.code_name,
            "code_hash": self.code_hash,
            "message": self.message,
            "data_root": self.data_root,
            "retryable": self.retryable,
            "retry_after_height": self.retry_after_height,
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash("RPC-ERROR", &[HashPart::Json(&self.public_record())], 32)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} ({}): {}",
            self.code_name, self.code, self.message
        )
    }
}

impl std::error::Error for RpcError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub response_id: String,
    pub request_id: String,
    pub client_request_id: Option<Value>,
    pub method: RpcMethod,
    pub method_name: String,
    pub success: bool,
    pub status_code: u16,
    pub response_payload_hash: String,
    pub response_payload_kind: String,
    pub response_payload_bytes: u64,
    pub error_code_hash: String,
    pub error: Option<RpcError>,
    pub public_metadata_root: String,
    pub produced_at_height: u64,
    pub expires_at_height: u64,
}

impl RpcResponse {
    pub fn from_payload(
        request: &RpcRequest,
        response_payload_kind: &str,
        response_payload: &Value,
        public_metadata: &Value,
        produced_at_height: u64,
    ) -> Self {
        let response_payload_hash =
            rpc_response_payload_hash(&request.request_id, response_payload);
        let error_code_hash = rpc_error_code_hash("");
        let public_metadata_root = rpc_public_metadata_root(public_metadata);
        let response_id = rpc_response_id(
            &request.request_id,
            200,
            &response_payload_hash,
            &error_code_hash,
            &public_metadata_root,
            produced_at_height,
        );
        Self {
            jsonrpc: RPC_JSONRPC_VERSION.to_string(),
            response_id,
            request_id: request.request_id.clone(),
            client_request_id: request.client_request_id.clone(),
            method: request.method.clone(),
            method_name: request.method_name.clone(),
            success: true,
            status_code: 200,
            response_payload_hash,
            response_payload_kind: response_payload_kind.to_string(),
            response_payload_bytes: json_size(response_payload) as u64,
            error_code_hash,
            error: None,
            public_metadata_root,
            produced_at_height,
            expires_at_height: request.expires_at_height,
        }
    }

    pub fn from_error(request: &RpcRequest, error: RpcError, produced_at_height: u64) -> Self {
        let response_payload = error.public_record();
        let response_payload_hash =
            rpc_response_payload_hash(&request.request_id, &response_payload);
        let public_metadata_root = error.public_metadata_root.clone();
        let response_id = rpc_response_id(
            &request.request_id,
            500,
            &response_payload_hash,
            &error.code_hash,
            &public_metadata_root,
            produced_at_height,
        );
        Self {
            jsonrpc: RPC_JSONRPC_VERSION.to_string(),
            response_id,
            request_id: request.request_id.clone(),
            client_request_id: request.client_request_id.clone(),
            method: request.method.clone(),
            method_name: request.method_name.clone(),
            success: false,
            status_code: 500,
            response_payload_hash,
            response_payload_kind: "rpc_error_hash".to_string(),
            response_payload_bytes: json_size(&response_payload) as u64,
            error_code_hash: error.code_hash.clone(),
            error: Some(error),
            public_metadata_root,
            produced_at_height,
            expires_at_height: request.expires_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rpc_response",
            "chain_id": CHAIN_ID,
            "rpc_version": RPC_CONTROL_PLANE_VERSION,
            "jsonrpc": self.jsonrpc,
            "response_id": self.response_id,
            "request_id": self.request_id,
            "client_request_id": self.client_request_id,
            "method": self.method_name,
            "success": self.success,
            "status_code": self.status_code,
            "response_payload_hash": self.response_payload_hash,
            "response_payload_kind": self.response_payload_kind,
            "response_payload_bytes": self.response_payload_bytes,
            "error_code_hash": self.error_code_hash,
            "error_root": self.error.as_ref().map(RpcError::root),
            "public_metadata_root": self.public_metadata_root,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash("RPC-RESPONSE", &[HashPart::Json(&self.public_record())], 32)
    }

    pub fn verify_id(&self) -> bool {
        self.response_id
            == rpc_response_id(
                &self.request_id,
                self.status_code,
                &self.response_payload_hash,
                &self.error_code_hash,
                &self.public_metadata_root,
                self.produced_at_height,
            )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReceipt {
    pub receipt_id: String,
    pub receipt_kind: String,
    pub request_id: String,
    pub response_id: Option<String>,
    pub method: RpcMethod,
    pub method_name: String,
    pub request_root: String,
    pub response_root: Option<String>,
    pub status_code: Option<u16>,
    pub success: Option<bool>,
    pub idempotency_key_hash: String,
    pub public_metadata_root: String,
    pub received_at_height: u64,
    pub produced_at_height: Option<u64>,
    pub expires_at_height: u64,
}

impl RpcReceipt {
    pub fn for_request(request: &RpcRequest, public_metadata: &Value) -> Self {
        let public_metadata_root = rpc_public_metadata_root(public_metadata);
        let request_root = request.root();
        let receipt_id = rpc_receipt_id(
            "request",
            &request.request_id,
            None,
            &request_root,
            None,
            request.received_at_height,
        );
        Self {
            receipt_id,
            receipt_kind: "request".to_string(),
            request_id: request.request_id.clone(),
            response_id: None,
            method: request.method.clone(),
            method_name: request.method_name.clone(),
            request_root,
            response_root: None,
            status_code: None,
            success: None,
            idempotency_key_hash: request.idempotency_key_hash.clone(),
            public_metadata_root,
            received_at_height: request.received_at_height,
            produced_at_height: None,
            expires_at_height: request.expires_at_height,
        }
    }

    pub fn for_response(
        request: &RpcRequest,
        response: &RpcResponse,
        public_metadata: &Value,
    ) -> Self {
        let public_metadata_root = rpc_public_metadata_root(public_metadata);
        let request_root = request.root();
        let response_root = response.root();
        let receipt_id = rpc_receipt_id(
            "response",
            &request.request_id,
            Some(&response.response_id),
            &request_root,
            Some(&response_root),
            response.produced_at_height,
        );
        Self {
            receipt_id,
            receipt_kind: "response".to_string(),
            request_id: request.request_id.clone(),
            response_id: Some(response.response_id.clone()),
            method: request.method.clone(),
            method_name: request.method_name.clone(),
            request_root,
            response_root: Some(response_root),
            status_code: Some(response.status_code),
            success: Some(response.success),
            idempotency_key_hash: request.idempotency_key_hash.clone(),
            public_metadata_root,
            received_at_height: request.received_at_height,
            produced_at_height: Some(response.produced_at_height),
            expires_at_height: request.expires_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rpc_receipt",
            "chain_id": CHAIN_ID,
            "rpc_version": RPC_CONTROL_PLANE_VERSION,
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind,
            "request_id": self.request_id,
            "response_id": self.response_id,
            "method": self.method_name,
            "request_root": self.request_root,
            "response_root": self.response_root,
            "status_code": self.status_code,
            "success": self.success,
            "idempotency_key_hash": self.idempotency_key_hash,
            "public_metadata_root": self.public_metadata_root,
            "received_at_height": self.received_at_height,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash("RPC-RECEIPT", &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcBatch {
    pub batch_id: String,
    pub request_ids: Vec<String>,
    pub response_ids: Vec<String>,
    pub request_root: String,
    pub response_root: String,
    pub public_metadata_root: String,
    pub received_at_height: u64,
    pub produced_at_height: Option<u64>,
}

impl RpcBatch {
    pub fn from_requests(
        requests: &[RpcRequest],
        public_metadata: &Value,
        received_at_height: u64,
    ) -> Self {
        Self::from_requests_and_responses(requests, &[], public_metadata, received_at_height, None)
    }

    pub fn from_requests_and_responses(
        requests: &[RpcRequest],
        responses: &[RpcResponse],
        public_metadata: &Value,
        received_at_height: u64,
        produced_at_height: Option<u64>,
    ) -> Self {
        let request_ids = requests
            .iter()
            .map(|request| request.request_id.clone())
            .collect::<Vec<_>>();
        let response_ids = responses
            .iter()
            .map(|response| response.response_id.clone())
            .collect::<Vec<_>>();
        let request_root = merkle_root(
            "RPC-BATCH-REQUEST",
            &requests
                .iter()
                .map(RpcRequest::public_record)
                .collect::<Vec<_>>(),
        );
        let response_root = merkle_root(
            "RPC-BATCH-RESPONSE",
            &responses
                .iter()
                .map(RpcResponse::public_record)
                .collect::<Vec<_>>(),
        );
        let public_metadata_root = rpc_public_metadata_root(public_metadata);
        let batch_id = rpc_batch_id(
            &request_root,
            &response_root,
            &public_metadata_root,
            received_at_height,
            produced_at_height,
        );
        Self {
            batch_id,
            request_ids,
            response_ids,
            request_root,
            response_root,
            public_metadata_root,
            received_at_height,
            produced_at_height,
        }
    }

    pub fn requests_from_jsonrpc_values(
        values: &[Value],
        received_at_height: u64,
        ttl_blocks: u64,
    ) -> RpcResult<Vec<RpcRequest>> {
        values
            .iter()
            .map(|value| RpcRequest::from_jsonrpc_value(value, received_at_height, ttl_blocks))
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rpc_batch",
            "chain_id": CHAIN_ID,
            "rpc_version": RPC_CONTROL_PLANE_VERSION,
            "batch_id": self.batch_id,
            "request_ids": self.request_ids,
            "response_ids": self.response_ids,
            "request_root": self.request_root,
            "response_root": self.response_root,
            "public_metadata_root": self.public_metadata_root,
            "received_at_height": self.received_at_height,
            "produced_at_height": self.produced_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash("RPC-BATCH", &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcIdempotencyRecord {
    pub cache_key: String,
    pub method: RpcMethod,
    pub method_name: String,
    pub client_commitment: String,
    pub idempotency_key_hash: String,
    pub request_id: String,
    pub response_id: Option<String>,
    pub response_root: Option<String>,
    pub first_seen_height: u64,
    pub last_seen_height: u64,
    pub expires_at_height: u64,
    pub charge_units: u64,
    pub charge_count: u64,
    pub public_metadata_root: String,
}

impl RpcIdempotencyRecord {
    pub fn new(request: &RpcRequest, charge_units: u64) -> Self {
        Self {
            cache_key: request.idempotency_cache_key(),
            method: request.method.clone(),
            method_name: request.method_name.clone(),
            client_commitment: request.client_commitment.clone(),
            idempotency_key_hash: request.idempotency_key_hash.clone(),
            request_id: request.request_id.clone(),
            response_id: None,
            response_root: None,
            first_seen_height: request.received_at_height,
            last_seen_height: request.received_at_height,
            expires_at_height: request.expires_at_height,
            charge_units,
            charge_count: 1,
            public_metadata_root: request.public_metadata_root.clone(),
        }
    }

    pub fn record_replay(&mut self, request: &RpcRequest, charge_units: u64) -> RpcResult<()> {
        if self.request_id != request.request_id {
            return Err(RpcError::idempotency_conflict(&self.cache_key));
        }
        self.last_seen_height = self.last_seen_height.max(request.received_at_height);
        self.expires_at_height = self.expires_at_height.max(request.expires_at_height);
        self.charge_units = self.charge_units.saturating_add(charge_units);
        self.charge_count = self.charge_count.saturating_add(1);
        Ok(())
    }

    pub fn attach_response(&mut self, response: &RpcResponse) {
        self.response_id = Some(response.response_id.clone());
        self.response_root = Some(response.root());
        self.last_seen_height = self.last_seen_height.max(response.produced_at_height);
        self.expires_at_height = self.expires_at_height.max(response.expires_at_height);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rpc_idempotency_record",
            "chain_id": CHAIN_ID,
            "rpc_version": RPC_CONTROL_PLANE_VERSION,
            "cache_key": self.cache_key,
            "method": self.method_name,
            "client_commitment": self.client_commitment,
            "idempotency_key_hash": self.idempotency_key_hash,
            "request_id": self.request_id,
            "response_id": self.response_id,
            "response_root": self.response_root,
            "first_seen_height": self.first_seen_height,
            "last_seen_height": self.last_seen_height,
            "expires_at_height": self.expires_at_height,
            "charge_units": self.charge_units,
            "charge_count": self.charge_count,
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "RPC-IDEMPOTENCY-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcControlPlaneState {
    pub height: u64,
    pub node_id: String,
    pub method_registry: BTreeMap<String, RpcMethodRecord>,
    pub requests: BTreeMap<String, RpcRequest>,
    pub responses: BTreeMap<String, RpcResponse>,
    pub request_receipts: BTreeMap<String, RpcReceipt>,
    pub response_receipts: BTreeMap<String, RpcReceipt>,
    pub idempotency_cache: BTreeMap<String, RpcIdempotencyRecord>,
    pub api_control_plane_state_root: String,
    pub api_route_registry_root: String,
    pub status_snapshot_root: String,
    pub block_production_root: String,
    pub storage_manifest_root: String,
    pub p2p_status_root: String,
    pub monero_status_root: String,
    pub bridge_status_root: String,
    pub crypto_policy_root: String,
}

impl RpcControlPlaneState {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            node_id: "rpc-control-plane".to_string(),
            method_registry: BTreeMap::new(),
            requests: BTreeMap::new(),
            responses: BTreeMap::new(),
            request_receipts: BTreeMap::new(),
            response_receipts: BTreeMap::new(),
            idempotency_cache: BTreeMap::new(),
            api_control_plane_state_root: merkle_root("RPC-API-CONTROL-PLANE", &[]),
            api_route_registry_root: merkle_root("RPC-API-ROUTE-REGISTRY", &[]),
            status_snapshot_root: merkle_root("RPC-STATUS-SNAPSHOT", &[]),
            block_production_root: merkle_root("RPC-BLOCK-PRODUCTION", &[]),
            storage_manifest_root: merkle_root("RPC-STORAGE-MANIFEST", &[]),
            p2p_status_root: merkle_root("RPC-P2P-STATUS", &[]),
            monero_status_root: merkle_root("RPC-MONERO-STATUS", &[]),
            bridge_status_root: merkle_root("RPC-BRIDGE-STATUS", &[]),
            crypto_policy_root: crypto_policy_root(),
        }
    }

    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = node_id.into();
        self
    }

    pub fn from_api_state(height: u64, api_state: &ApiControlPlaneState) -> Self {
        let mut state = Self::new(height);
        state.set_api_state(api_state);
        state
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn set_api_state(&mut self, api_state: &ApiControlPlaneState) {
        self.api_control_plane_state_root = api_state.state_root();
        self.api_route_registry_root = api_state.route_registry_root();
    }

    pub fn set_status_snapshot_root(&mut self, root: impl Into<String>) {
        self.status_snapshot_root = root.into();
    }

    pub fn set_block_production_root(&mut self, root: impl Into<String>) {
        self.block_production_root = root.into();
    }

    pub fn set_storage_manifest_root(&mut self, root: impl Into<String>) {
        self.storage_manifest_root = root.into();
    }

    pub fn set_p2p_status_root(&mut self, root: impl Into<String>) {
        self.p2p_status_root = root.into();
    }

    pub fn set_monero_status_root(&mut self, root: impl Into<String>) {
        self.monero_status_root = root.into();
    }

    pub fn set_bridge_status_root(&mut self, root: impl Into<String>) {
        self.bridge_status_root = root.into();
    }

    pub fn register_method(&mut self, method: RpcMethodRecord) -> RpcResult<String> {
        if method.expires_at_height < method.registered_at_height {
            return Err(RpcError::invalid_request(
                "rpc method expires before it is registered",
            ));
        }
        if method.authorization.is_some() && !method.verify_authorization() {
            return Err(RpcError::unauthorized(
                "rpc method registry authorization failed",
            ));
        }
        let method_id = method.method_id.clone();
        self.method_registry.insert(method_id.clone(), method);
        Ok(method_id)
    }

    pub fn register_default_methods(
        &mut self,
        operator_label: &str,
        registered_at_height: u64,
        expires_at_height: u64,
    ) -> RpcResult<Vec<String>> {
        default_rpc_method_records(
            &self.node_id,
            operator_label,
            registered_at_height,
            expires_at_height,
            &self.api_route_registry_root,
            &self.api_control_plane_state_root,
        )
        .into_iter()
        .map(|record| self.register_method(record))
        .collect()
    }

    pub fn receive_request(&mut self, request: RpcRequest) -> RpcResult<RpcReceipt> {
        if !request.verify_id() {
            return Err(RpcError::invalid_request(
                "rpc request id verification failed",
            ));
        }
        if request.expires_at_height < request.received_at_height {
            return Err(RpcError::invalid_request(
                "rpc request expires before it is received",
            ));
        }
        if request.expires_at_height < self.height {
            return Err(RpcError::expired_request(self.height));
        }
        let method = self
            .method_registry
            .get(&request.method_id)
            .or_else(|| {
                self.method_registry
                    .values()
                    .find(|method| method.method == request.method)
            })
            .ok_or_else(|| RpcError::method_not_found(&request.method_name))?;
        if method.method != request.method || method.method_name != request.method_name {
            return Err(RpcError::invalid_request(
                "rpc request method does not match method registry",
            ));
        }
        if !method.is_live(request.received_at_height) {
            return Err(RpcError::expired_request(request.received_at_height));
        }
        if request.private_payload && !method.allows_private_payload {
            return Err(RpcError::invalid_request(
                "rpc method does not allow private payloads",
            ));
        }
        let idempotent = method.idempotent;
        let receipt = RpcReceipt::for_request(&request, &json!({}));
        self.requests
            .insert(request.request_id.clone(), request.clone());
        self.request_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        if idempotent {
            self.charge_idempotency(&request, RPC_DEFAULT_IDEMPOTENCY_CHARGE_UNITS)?;
        }
        Ok(receipt)
    }

    pub fn produce_response(
        &mut self,
        request: &RpcRequest,
        response_payload_kind: &str,
        response_payload: &Value,
        produced_at_height: u64,
    ) -> RpcResult<RpcResponse> {
        if !self.requests.contains_key(&request.request_id) {
            return Err(RpcError::invalid_request(
                "rpc response references unknown request",
            ));
        }
        let response = RpcResponse::from_payload(
            request,
            response_payload_kind,
            response_payload,
            &json!({}),
            produced_at_height,
        );
        self.insert_response_receipt(request, response)
    }

    pub fn produce_error(
        &mut self,
        request: &RpcRequest,
        error: RpcError,
        produced_at_height: u64,
    ) -> RpcResult<RpcResponse> {
        if !self.requests.contains_key(&request.request_id) {
            return Err(RpcError::invalid_request(
                "rpc error response references unknown request",
            ));
        }
        let response = RpcResponse::from_error(request, error, produced_at_height);
        self.insert_response_receipt(request, response)
    }

    pub fn charge_idempotency(
        &mut self,
        request: &RpcRequest,
        charge_units: u64,
    ) -> RpcResult<RpcIdempotencyRecord> {
        let cache_key = request.idempotency_cache_key();
        if let Some(record) = self.idempotency_cache.get_mut(&cache_key) {
            record.record_replay(request, charge_units)?;
            return Ok(record.clone());
        }
        let record = RpcIdempotencyRecord::new(request, charge_units);
        self.idempotency_cache.insert(cache_key, record.clone());
        Ok(record)
    }

    pub fn cached_response(&self, request: &RpcRequest) -> Option<&RpcResponse> {
        self.idempotency_cache
            .get(&request.idempotency_cache_key())
            .and_then(|record| record.response_id.as_ref())
            .and_then(|response_id| self.responses.get(response_id))
    }

    pub fn prune_expired_receipts(&mut self, current_height: u64) -> usize {
        let before = self.requests.len()
            + self.responses.len()
            + self.request_receipts.len()
            + self.response_receipts.len()
            + self.idempotency_cache.len();
        self.requests
            .retain(|_, request| current_height <= request.expires_at_height);
        self.responses
            .retain(|_, response| current_height <= response.expires_at_height);
        self.request_receipts
            .retain(|_, receipt| current_height <= receipt.expires_at_height);
        self.response_receipts
            .retain(|_, receipt| current_height <= receipt.expires_at_height);
        self.idempotency_cache
            .retain(|_, record| current_height <= record.expires_at_height);
        before
            - (self.requests.len()
                + self.responses.len()
                + self.request_receipts.len()
                + self.response_receipts.len()
                + self.idempotency_cache.len())
    }

    pub fn method_registry_root(&self) -> String {
        rpc_method_registry_root(&self.method_registry.values().cloned().collect::<Vec<_>>())
    }

    pub fn request_receipt_root(&self) -> String {
        rpc_receipt_root(
            "RPC-REQUEST-RECEIPT",
            &self.request_receipts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn response_receipt_root(&self) -> String {
        rpc_receipt_root(
            "RPC-RESPONSE-RECEIPT",
            &self.response_receipts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn idempotency_root(&self) -> String {
        rpc_idempotency_root(&self.idempotency_cache.values().cloned().collect::<Vec<_>>())
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "RPC-CONTROL-PLANE-STATE",
            &[
                HashPart::Str(&self.method_registry_root()),
                HashPart::Str(&self.request_receipt_root()),
                HashPart::Str(&self.response_receipt_root()),
                HashPart::Str(&self.idempotency_root()),
                HashPart::Str(&self.api_control_plane_state_root),
                HashPart::Str(&self.api_route_registry_root),
                HashPart::Str(&self.status_snapshot_root),
                HashPart::Str(&self.block_production_root),
                HashPart::Str(&self.storage_manifest_root),
                HashPart::Str(&self.p2p_status_root),
                HashPart::Str(&self.monero_status_root),
                HashPart::Str(&self.bridge_status_root),
                HashPart::Str(&self.crypto_policy_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rpc_control_plane_state",
            "chain_id": CHAIN_ID,
            "rpc_version": RPC_CONTROL_PLANE_VERSION,
            "height": self.height,
            "node_id": self.node_id,
            "method_registry_root": self.method_registry_root(),
            "request_receipt_root": self.request_receipt_root(),
            "response_receipt_root": self.response_receipt_root(),
            "idempotency_root": self.idempotency_root(),
            "api_control_plane_state_root": self.api_control_plane_state_root,
            "api_route_registry_root": self.api_route_registry_root,
            "status_snapshot_root": self.status_snapshot_root,
            "block_production_root": self.block_production_root,
            "storage_manifest_root": self.storage_manifest_root,
            "p2p_status_root": self.p2p_status_root,
            "monero_status_root": self.monero_status_root,
            "bridge_status_root": self.bridge_status_root,
            "crypto_policy_root": self.crypto_policy_root,
            "rpc_control_plane_state_root": self.state_root(),
            "method_count": self.method_registry.len() as u64,
            "request_count": self.requests.len() as u64,
            "response_count": self.responses.len() as u64,
            "request_receipt_count": self.request_receipts.len() as u64,
            "response_receipt_count": self.response_receipts.len() as u64,
            "idempotency_record_count": self.idempotency_cache.len() as u64,
        })
    }

    fn insert_response_receipt(
        &mut self,
        request: &RpcRequest,
        response: RpcResponse,
    ) -> RpcResult<RpcResponse> {
        if !response.verify_id() {
            return Err(RpcError::internal("rpc response id verification failed"));
        }
        let receipt = RpcReceipt::for_response(request, &response, &json!({}));
        self.responses
            .insert(response.response_id.clone(), response.clone());
        self.response_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        if let Some(record) = self
            .idempotency_cache
            .get_mut(&request.idempotency_cache_key())
        {
            record.attach_response(&response);
        }
        Ok(response)
    }
}

impl Default for RpcControlPlaneState {
    fn default() -> Self {
        Self::new(0)
    }
}

pub fn default_rpc_method_records(
    node_id: &str,
    operator_label: &str,
    registered_at_height: u64,
    expires_at_height: u64,
    api_route_root: &str,
    api_control_plane_state_root: &str,
) -> Vec<RpcMethodRecord> {
    RpcMethod::all()
        .into_iter()
        .map(|method| {
            RpcMethodRecord::new(
                node_id,
                operator_label,
                method.clone(),
                method.default_request_payload_kind(),
                method.default_response_payload_kind(),
                &json!({}),
                api_route_root,
                api_control_plane_state_root,
                registered_at_height,
                expires_at_height,
            )
            .signed()
        })
        .collect()
}

pub fn rpc_method_id(
    method_name: &str,
    request_payload_kind: &str,
    response_payload_kind: &str,
    public_metadata_root: &str,
) -> String {
    domain_hash(
        "RPC-METHOD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(RPC_CONTROL_PLANE_VERSION),
            HashPart::Str(method_name),
            HashPart::Str(request_payload_kind),
            HashPart::Str(response_payload_kind),
            HashPart::Str(public_metadata_root),
        ],
        32,
    )
}

pub fn rpc_request_id(
    method_name: &str,
    client_request_id_hash: &str,
    client_commitment: &str,
    idempotency_key_hash: &str,
    payload_hash: &str,
    public_metadata_root: &str,
    received_at_height: u64,
) -> String {
    domain_hash(
        "RPC-REQUEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(RPC_CONTROL_PLANE_VERSION),
            HashPart::Str(method_name),
            HashPart::Str(client_request_id_hash),
            HashPart::Str(client_commitment),
            HashPart::Str(idempotency_key_hash),
            HashPart::Str(payload_hash),
            HashPart::Str(public_metadata_root),
            HashPart::Int(received_at_height as i128),
        ],
        32,
    )
}

pub fn rpc_response_id(
    request_id: &str,
    status_code: u16,
    response_payload_hash: &str,
    error_code_hash: &str,
    public_metadata_root: &str,
    produced_at_height: u64,
) -> String {
    domain_hash(
        "RPC-RESPONSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(RPC_CONTROL_PLANE_VERSION),
            HashPart::Str(request_id),
            HashPart::Int(status_code as i128),
            HashPart::Str(response_payload_hash),
            HashPart::Str(error_code_hash),
            HashPart::Str(public_metadata_root),
            HashPart::Int(produced_at_height as i128),
        ],
        32,
    )
}

pub fn rpc_receipt_id(
    receipt_kind: &str,
    request_id: &str,
    response_id: Option<&str>,
    request_root: &str,
    response_root: Option<&str>,
    height: u64,
) -> String {
    domain_hash(
        "RPC-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(RPC_CONTROL_PLANE_VERSION),
            HashPart::Str(receipt_kind),
            HashPart::Str(request_id),
            HashPart::Str(response_id.unwrap_or("")),
            HashPart::Str(request_root),
            HashPart::Str(response_root.unwrap_or("")),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn rpc_method_registry_root(records: &[RpcMethodRecord]) -> String {
    let mut records = records.to_vec();
    records.sort_by(|left, right| left.method_id.cmp(&right.method_id));
    merkle_root(
        "RPC-METHOD-REGISTRY",
        &records
            .iter()
            .map(RpcMethodRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rpc_payload_hash(method_name: &str, payload: &Value) -> String {
    domain_hash(
        "RPC-PAYLOAD",
        &[HashPart::Str(method_name), HashPart::Json(payload)],
        32,
    )
}

pub fn rpc_response_payload_hash(request_id: &str, payload: &Value) -> String {
    domain_hash(
        "RPC-RESPONSE-PAYLOAD",
        &[HashPart::Str(request_id), HashPart::Json(payload)],
        32,
    )
}

pub fn rpc_error_code_hash(error_code: &str) -> String {
    domain_hash("RPC-ERROR-CODE", &[HashPart::Str(error_code)], 32)
}

pub fn rpc_idempotency_key_hash(idempotency_key: &str) -> String {
    domain_hash("RPC-IDEMPOTENCY-KEY", &[HashPart::Str(idempotency_key)], 32)
}

pub fn rpc_public_metadata_root(public_metadata: &Value) -> String {
    domain_hash(
        "RPC-PUBLIC-METADATA",
        &[HashPart::Json(public_metadata)],
        32,
    )
}

pub fn rpc_client_request_id_hash(client_request_id: &Option<Value>) -> String {
    match client_request_id {
        Some(value) => domain_hash("RPC-CLIENT-REQUEST-ID", &[HashPart::Json(value)], 32),
        None => domain_hash("RPC-CLIENT-REQUEST-ID", &[HashPart::Str("")], 32),
    }
}

pub fn rpc_receipt_root(domain: &str, receipts: &[RpcReceipt]) -> String {
    let mut receipts = receipts.to_vec();
    receipts.sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
    merkle_root(
        domain,
        &receipts
            .iter()
            .map(RpcReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rpc_idempotency_root(records: &[RpcIdempotencyRecord]) -> String {
    let mut records = records.to_vec();
    records.sort_by(|left, right| left.cache_key.cmp(&right.cache_key));
    merkle_root(
        "RPC-IDEMPOTENCY",
        &records
            .iter()
            .map(RpcIdempotencyRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rpc_batch_id(
    request_root: &str,
    response_root: &str,
    public_metadata_root: &str,
    received_at_height: u64,
    produced_at_height: Option<u64>,
) -> String {
    domain_hash(
        "RPC-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_root),
            HashPart::Str(response_root),
            HashPart::Str(public_metadata_root),
            HashPart::Int(received_at_height as i128),
            HashPart::Int(produced_at_height.unwrap_or(0) as i128),
        ],
        32,
    )
}

fn insert_authorization_fields(
    object: &mut serde_json::Map<String, Value>,
    authorization: &Authorization,
) {
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
