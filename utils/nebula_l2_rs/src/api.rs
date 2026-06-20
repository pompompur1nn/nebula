use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{
        crypto_policy_root, public_key_for_label, sign_network_authorization,
        verify_network_authorization, Authorization, CryptoRole,
    },
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ApiResult<T> = Result<T, String>;

pub const NODE_API_VERSION: &str = "nebula-l2-node-api-v1";
pub const DEFAULT_API_RATE_LIMIT_WINDOW_BLOCKS: u64 = 20;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ApiRouteKind {
    Status,
    SubmitTx,
    WalletScan,
    MoneroMonitor,
    Bridge,
    Defi,
    Consensus,
    FeeQuote,
}

impl ApiRouteKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::SubmitTx => "submit_tx",
            Self::WalletScan => "wallet_scan",
            Self::MoneroMonitor => "monero_monitor",
            Self::Bridge => "bridge",
            Self::Defi => "defi",
            Self::Consensus => "consensus",
            Self::FeeQuote => "fee_quote",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRouteCapability {
    pub capability_id: String,
    pub route_kind: ApiRouteKind,
    pub capability: String,
    pub scope: String,
    pub request_payload_kind: String,
    pub response_payload_kind: String,
    pub requires_auth: bool,
    pub allows_private_payload: bool,
    pub public_metadata_root: String,
}

impl ApiRouteCapability {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_kind: ApiRouteKind,
        capability: &str,
        scope: &str,
        request_payload_kind: &str,
        response_payload_kind: &str,
        requires_auth: bool,
        allows_private_payload: bool,
        public_metadata: &Value,
    ) -> Self {
        let public_metadata_root = api_public_metadata_root(public_metadata);
        let capability_id = api_capability_id(
            route_kind.as_str(),
            capability,
            scope,
            request_payload_kind,
            response_payload_kind,
            requires_auth,
            allows_private_payload,
            &public_metadata_root,
        );
        Self {
            capability_id,
            route_kind,
            capability: capability.to_string(),
            scope: scope.to_string(),
            request_payload_kind: request_payload_kind.to_string(),
            response_payload_kind: response_payload_kind.to_string(),
            requires_auth,
            allows_private_payload,
            public_metadata_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "api_route_capability",
            "chain_id": CHAIN_ID,
            "api_version": NODE_API_VERSION,
            "capability_id": self.capability_id,
            "route_kind": self.route_kind.as_str(),
            "capability": self.capability,
            "scope": self.scope,
            "request_payload_kind": self.request_payload_kind,
            "response_payload_kind": self.response_payload_kind,
            "requires_auth": self.requires_auth,
            "allows_private_payload": self.allows_private_payload,
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn capability_root(&self) -> String {
        domain_hash(
            "API-ROUTE-CAPABILITY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRouteRecord {
    pub route_id: String,
    pub node_id: String,
    pub operator_label: String,
    pub network_public_key: String,
    pub method: String,
    pub path: String,
    pub route_kind: ApiRouteKind,
    pub capabilities: Vec<ApiRouteCapability>,
    pub rate_limit_bucket_id: String,
    pub public_metadata_root: String,
    pub min_supported_height: u64,
    pub max_supported_height: u64,
    pub advertised_at_height: u64,
    pub expires_at_height: u64,
    pub crypto_policy_root: String,
    pub authorization: Option<Authorization>,
}

impl ApiRouteRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: &str,
        operator_label: &str,
        method: &str,
        path: &str,
        route_kind: ApiRouteKind,
        capabilities: Vec<ApiRouteCapability>,
        rate_limit_bucket_id: &str,
        public_metadata: &Value,
        min_supported_height: u64,
        max_supported_height: u64,
        advertised_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let capability_root = api_capability_root(&capabilities);
        let public_metadata_root = api_public_metadata_root(public_metadata);
        let route_id = api_route_id(method, path, route_kind.as_str(), &capability_root);
        let network_public_key =
            public_key_for_label(CryptoRole::NetworkSignature, operator_label).public_key;
        Self {
            route_id,
            node_id: node_id.to_string(),
            operator_label: operator_label.to_string(),
            network_public_key,
            method: method.to_string(),
            path: path.to_string(),
            route_kind,
            capabilities,
            rate_limit_bucket_id: rate_limit_bucket_id.to_string(),
            public_metadata_root,
            min_supported_height,
            max_supported_height,
            advertised_at_height,
            expires_at_height,
            crypto_policy_root: crypto_policy_root(),
            authorization: None,
        }
    }

    pub fn signed(mut self) -> Self {
        self.authorization = Some(sign_network_authorization(
            &self.operator_label,
            "api_route_record",
            &self.unsigned_record(),
        ));
        self
    }

    pub fn capability_root(&self) -> String {
        api_capability_root(&self.capabilities)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "api_route_record",
            "chain_id": CHAIN_ID,
            "api_version": NODE_API_VERSION,
            "route_id": self.route_id,
            "node_id": self.node_id,
            "operator_label": self.operator_label,
            "network_public_key": self.network_public_key,
            "method": self.method,
            "path": self.path,
            "route_kind": self.route_kind.as_str(),
            "capability_root": self.capability_root(),
            "capabilities": self.capabilities.iter().map(ApiRouteCapability::public_record).collect::<Vec<_>>(),
            "rate_limit_bucket_id": self.rate_limit_bucket_id,
            "public_metadata_root": self.public_metadata_root,
            "min_supported_height": self.min_supported_height,
            "max_supported_height": self.max_supported_height,
            "advertised_at_height": self.advertised_at_height,
            "expires_at_height": self.expires_at_height,
            "crypto_policy_root": self.crypto_policy_root,
        })
    }

    pub fn route_root(&self) -> String {
        domain_hash(
            "API-ROUTE-RECORD",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record.as_object_mut().expect("api route record object");
        object.insert("route_root".to_string(), Value::String(self.route_root()));
        if let Some(authorization) = &self.authorization {
            insert_authorization_fields(object, authorization);
        }
        record
    }

    pub fn verify_authorization(&self) -> bool {
        match &self.authorization {
            Some(authorization) => verify_network_authorization(
                &self.network_public_key,
                "api_route_record",
                &self.unsigned_record(),
                authorization,
            ),
            None => false,
        }
    }

    pub fn is_live(&self, height: u64) -> bool {
        self.advertised_at_height <= height && height <= self.expires_at_height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSessionRecord {
    pub session_id: String,
    pub node_id: String,
    pub client_account_commitment: String,
    pub allowed_route_root: String,
    pub authorization_root: String,
    pub authorization_count: u64,
    pub public_metadata_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub last_seen_height: u64,
    pub request_count: u64,
    pub response_count: u64,
    pub rate_limit_subject: String,
}

impl ApiSessionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: &str,
        client_account_commitment: &str,
        allowed_route_ids: &[String],
        authorizations: &[Authorization],
        public_metadata: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
        rate_limit_subject: &str,
    ) -> Self {
        let allowed_route_root = api_string_root("API-SESSION-ROUTE", allowed_route_ids);
        let authorization_root = api_authorization_root(authorizations);
        let authorization_count = authorizations.len() as u64;
        let public_metadata_root = api_public_metadata_root(public_metadata);
        let session_id = api_session_id(
            node_id,
            client_account_commitment,
            &allowed_route_root,
            &authorization_root,
            opened_at_height,
        );
        Self {
            session_id,
            node_id: node_id.to_string(),
            client_account_commitment: client_account_commitment.to_string(),
            allowed_route_root,
            authorization_root,
            authorization_count,
            public_metadata_root,
            opened_at_height,
            expires_at_height,
            last_seen_height: opened_at_height,
            request_count: 0,
            response_count: 0,
            rate_limit_subject: rate_limit_subject.to_string(),
        }
    }

    pub fn record_request_seen(&mut self, height: u64) {
        self.last_seen_height = self.last_seen_height.max(height);
        self.request_count = self.request_count.saturating_add(1);
    }

    pub fn record_response_seen(&mut self, height: u64) {
        self.last_seen_height = self.last_seen_height.max(height);
        self.response_count = self.response_count.saturating_add(1);
    }

    pub fn is_live(&self, height: u64) -> bool {
        self.opened_at_height <= height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "api_session_record",
            "chain_id": CHAIN_ID,
            "api_version": NODE_API_VERSION,
            "session_id": self.session_id,
            "node_id": self.node_id,
            "client_account_commitment": self.client_account_commitment,
            "allowed_route_root": self.allowed_route_root,
            "authorization_root": self.authorization_root,
            "authorization_count": self.authorization_count,
            "public_metadata_root": self.public_metadata_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "last_seen_height": self.last_seen_height,
            "request_count": self.request_count,
            "response_count": self.response_count,
            "rate_limit_subject": self.rate_limit_subject,
        })
    }

    pub fn session_root(&self) -> String {
        domain_hash(
            "API-SESSION-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRequestEnvelope {
    pub request_id: String,
    pub route_id: String,
    pub route_kind: ApiRouteKind,
    pub method: String,
    pub path: String,
    pub session_id: Option<String>,
    pub client_account_commitment: String,
    pub idempotency_key_hash: String,
    pub payload_hash: String,
    pub payload_kind: String,
    pub authorization_root: String,
    pub authorization_count: u64,
    pub public_metadata_root: String,
    pub rate_limit_bucket_id: String,
    pub received_at_height: u64,
    pub expires_at_height: u64,
    pub max_response_bytes: u64,
}

impl ApiRequestEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn from_payload(
        route: &ApiRouteRecord,
        session_id: Option<String>,
        client_account_commitment: &str,
        idempotency_key: &str,
        payload_kind: &str,
        payload: &Value,
        authorizations: &[Authorization],
        public_metadata: &Value,
        received_at_height: u64,
        expires_at_height: u64,
        max_response_bytes: u64,
    ) -> Self {
        let idempotency_key_hash = api_idempotency_key_hash(idempotency_key);
        let payload_hash = api_request_payload_hash(&route.route_id, payload);
        let authorization_root = api_authorization_root(authorizations);
        let authorization_count = authorizations.len() as u64;
        let public_metadata_root = api_public_metadata_root(public_metadata);
        let request_id = api_request_id(
            &route.route_id,
            session_id.as_deref().unwrap_or(""),
            client_account_commitment,
            &idempotency_key_hash,
            &payload_hash,
            &authorization_root,
            received_at_height,
        );
        Self {
            request_id,
            route_id: route.route_id.clone(),
            route_kind: route.route_kind.clone(),
            method: route.method.clone(),
            path: route.path.clone(),
            session_id,
            client_account_commitment: client_account_commitment.to_string(),
            idempotency_key_hash,
            payload_hash,
            payload_kind: payload_kind.to_string(),
            authorization_root,
            authorization_count,
            public_metadata_root,
            rate_limit_bucket_id: route.rate_limit_bucket_id.clone(),
            received_at_height,
            expires_at_height,
            max_response_bytes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "api_request_envelope",
            "chain_id": CHAIN_ID,
            "api_version": NODE_API_VERSION,
            "request_id": self.request_id,
            "route_id": self.route_id,
            "route_kind": self.route_kind.as_str(),
            "method": self.method,
            "path": self.path,
            "session_id": self.session_id,
            "client_account_commitment": self.client_account_commitment,
            "idempotency_key_hash": self.idempotency_key_hash,
            "payload_hash": self.payload_hash,
            "payload_kind": self.payload_kind,
            "authorization_root": self.authorization_root,
            "authorization_count": self.authorization_count,
            "public_metadata_root": self.public_metadata_root,
            "rate_limit_bucket_id": self.rate_limit_bucket_id,
            "received_at_height": self.received_at_height,
            "expires_at_height": self.expires_at_height,
            "max_response_bytes": self.max_response_bytes,
        })
    }

    pub fn envelope_root(&self) -> String {
        domain_hash(
            "API-REQUEST-ENVELOPE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiResponseEnvelope {
    pub response_id: String,
    pub request_id: String,
    pub route_id: String,
    pub route_kind: ApiRouteKind,
    pub status_code: u16,
    pub response_payload_hash: String,
    pub response_payload_kind: String,
    pub error_code_hash: String,
    pub authorization_root: String,
    pub authorization_count: u64,
    pub public_metadata_root: String,
    pub rate_limit_bucket_id: String,
    pub produced_at_height: u64,
    pub retry_after_height: Option<u64>,
}

impl ApiResponseEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn from_payload(
        request: &ApiRequestEnvelope,
        status_code: u16,
        response_payload_kind: &str,
        response_payload: &Value,
        error_code: Option<&str>,
        authorizations: &[Authorization],
        public_metadata: &Value,
        produced_at_height: u64,
        retry_after_height: Option<u64>,
    ) -> Self {
        let response_payload_hash =
            api_response_payload_hash(&request.request_id, response_payload);
        let error_code_hash = error_code
            .map(api_error_code_hash)
            .unwrap_or_else(|| api_error_code_hash(""));
        let authorization_root = api_authorization_root(authorizations);
        let authorization_count = authorizations.len() as u64;
        let public_metadata_root = api_public_metadata_root(public_metadata);
        let response_id = api_response_id(
            &request.request_id,
            status_code,
            &response_payload_hash,
            &error_code_hash,
            &authorization_root,
            produced_at_height,
        );
        Self {
            response_id,
            request_id: request.request_id.clone(),
            route_id: request.route_id.clone(),
            route_kind: request.route_kind.clone(),
            status_code,
            response_payload_hash,
            response_payload_kind: response_payload_kind.to_string(),
            error_code_hash,
            authorization_root,
            authorization_count,
            public_metadata_root,
            rate_limit_bucket_id: request.rate_limit_bucket_id.clone(),
            produced_at_height,
            retry_after_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "api_response_envelope",
            "chain_id": CHAIN_ID,
            "api_version": NODE_API_VERSION,
            "response_id": self.response_id,
            "request_id": self.request_id,
            "route_id": self.route_id,
            "route_kind": self.route_kind.as_str(),
            "status_code": self.status_code,
            "response_payload_hash": self.response_payload_hash,
            "response_payload_kind": self.response_payload_kind,
            "error_code_hash": self.error_code_hash,
            "authorization_root": self.authorization_root,
            "authorization_count": self.authorization_count,
            "public_metadata_root": self.public_metadata_root,
            "rate_limit_bucket_id": self.rate_limit_bucket_id,
            "produced_at_height": self.produced_at_height,
            "retry_after_height": self.retry_after_height,
        })
    }

    pub fn envelope_root(&self) -> String {
        domain_hash(
            "API-RESPONSE-ENVELOPE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRateLimitBucket {
    pub bucket_id: String,
    pub route_id: String,
    pub subject_commitment: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub limit_units: u64,
    pub used_units: u64,
    pub public_metadata_root: String,
}

impl ApiRateLimitBucket {
    pub fn new(
        route_id: &str,
        subject_commitment: &str,
        window_start_height: u64,
        window_blocks: u64,
        limit_units: u64,
        public_metadata: &Value,
    ) -> Self {
        let window_end_height = window_start_height.saturating_add(window_blocks);
        let public_metadata_root = api_public_metadata_root(public_metadata);
        let bucket_id = api_rate_limit_bucket_id(
            route_id,
            subject_commitment,
            window_start_height,
            window_end_height,
        );
        Self {
            bucket_id,
            route_id: route_id.to_string(),
            subject_commitment: subject_commitment.to_string(),
            window_start_height,
            window_end_height,
            limit_units,
            used_units: 0,
            public_metadata_root,
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.limit_units.saturating_sub(self.used_units)
    }

    pub fn try_charge(&mut self, units: u64) -> ApiResult<()> {
        if units > self.remaining_units() {
            return Err("api rate limit bucket exhausted".to_string());
        }
        self.used_units = self.used_units.saturating_add(units);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "api_rate_limit_bucket",
            "chain_id": CHAIN_ID,
            "api_version": NODE_API_VERSION,
            "bucket_id": self.bucket_id,
            "route_id": self.route_id,
            "subject_commitment": self.subject_commitment,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "limit_units": self.limit_units,
            "used_units": self.used_units,
            "remaining_units": self.remaining_units(),
            "public_metadata_root": self.public_metadata_root,
        })
    }

    pub fn bucket_root(&self) -> String {
        domain_hash(
            "API-RATE-LIMIT-BUCKET",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiControlPlaneState {
    pub height: u64,
    pub route_registry: BTreeMap<String, ApiRouteRecord>,
    pub sessions: BTreeMap<String, ApiSessionRecord>,
    pub request_receipts: BTreeMap<String, ApiRequestEnvelope>,
    pub response_receipts: BTreeMap<String, ApiResponseEnvelope>,
    pub rate_limit_buckets: BTreeMap<String, ApiRateLimitBucket>,
}

impl ApiControlPlaneState {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            ..Self::default()
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn with_default_routes(
        node_id: &str,
        operator_label: &str,
        height: u64,
        expires_at_height: u64,
    ) -> Self {
        let mut state = Self::new(height);
        for route in default_api_routes(node_id, operator_label, height, expires_at_height) {
            state
                .insert_route(route)
                .expect("default api route authorization");
        }
        state
    }

    pub fn insert_route(&mut self, route: ApiRouteRecord) -> ApiResult<String> {
        if route.authorization.is_some() && !route.verify_authorization() {
            return Err("api route authorization failed".to_string());
        }
        let route_id = route.route_id.clone();
        self.route_registry.insert(route_id.clone(), route);
        Ok(route_id)
    }

    pub fn insert_session(&mut self, session: ApiSessionRecord) -> ApiResult<String> {
        if session.expires_at_height < session.opened_at_height {
            return Err("api session expires before it opens".to_string());
        }
        let session_id = session.session_id.clone();
        self.sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    pub fn insert_request_receipt(&mut self, request: ApiRequestEnvelope) -> ApiResult<String> {
        if !self.route_registry.contains_key(&request.route_id) {
            return Err("api request references unknown route".to_string());
        }
        if request.expires_at_height < request.received_at_height {
            return Err("api request expires before it is received".to_string());
        }
        if let Some(session_id) = &request.session_id {
            let session = self
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| "api request references unknown session".to_string())?;
            session.record_request_seen(request.received_at_height);
        }
        let request_id = request.request_id.clone();
        self.request_receipts.insert(request_id.clone(), request);
        Ok(request_id)
    }

    pub fn insert_response_receipt(&mut self, response: ApiResponseEnvelope) -> ApiResult<String> {
        let request = self
            .request_receipts
            .get(&response.request_id)
            .ok_or_else(|| "api response references unknown request".to_string())?;
        if response.route_id != request.route_id {
            return Err("api response route does not match request".to_string());
        }
        if let Some(session_id) = &request.session_id {
            let session = self
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| "api response references unknown session".to_string())?;
            session.record_response_seen(response.produced_at_height);
        }
        let response_id = response.response_id.clone();
        self.response_receipts.insert(response_id.clone(), response);
        Ok(response_id)
    }

    pub fn upsert_rate_limit_bucket(&mut self, bucket: ApiRateLimitBucket) -> String {
        let bucket_id = bucket.bucket_id.clone();
        self.rate_limit_buckets.insert(bucket_id.clone(), bucket);
        bucket_id
    }

    pub fn charge_rate_limit(&mut self, bucket_id: &str, units: u64) -> ApiResult<()> {
        self.rate_limit_buckets
            .get_mut(bucket_id)
            .ok_or_else(|| "unknown api rate limit bucket".to_string())?
            .try_charge(units)
    }

    pub fn route_registry_root(&self) -> String {
        merkle_root(
            "API-ROUTE-REGISTRY",
            &self
                .route_registry
                .values()
                .map(ApiRouteRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn session_root(&self) -> String {
        merkle_root(
            "API-SESSION",
            &self
                .sessions
                .values()
                .map(ApiSessionRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn request_receipt_root(&self) -> String {
        merkle_root(
            "API-REQUEST-RECEIPT",
            &self
                .request_receipts
                .values()
                .map(ApiRequestEnvelope::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn response_receipt_root(&self) -> String {
        merkle_root(
            "API-RESPONSE-RECEIPT",
            &self
                .response_receipts
                .values()
                .map(ApiResponseEnvelope::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn rate_limit_root(&self) -> String {
        merkle_root(
            "API-RATE-LIMIT",
            &self
                .rate_limit_buckets
                .values()
                .map(ApiRateLimitBucket::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "API-CONTROL-PLANE-STATE",
            &[
                HashPart::Str(&self.route_registry_root()),
                HashPart::Str(&self.session_root()),
                HashPart::Str(&self.request_receipt_root()),
                HashPart::Str(&self.response_receipt_root()),
                HashPart::Str(&self.rate_limit_root()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "api_control_plane_state",
            "chain_id": CHAIN_ID,
            "api_version": NODE_API_VERSION,
            "height": self.height,
            "route_registry_root": self.route_registry_root(),
            "session_root": self.session_root(),
            "request_receipt_root": self.request_receipt_root(),
            "response_receipt_root": self.response_receipt_root(),
            "rate_limit_root": self.rate_limit_root(),
            "api_control_plane_state_root": self.state_root(),
            "route_count": self.route_registry.len() as u64,
            "session_count": self.sessions.len() as u64,
            "request_receipt_count": self.request_receipts.len() as u64,
            "response_receipt_count": self.response_receipts.len() as u64,
            "rate_limit_bucket_count": self.rate_limit_buckets.len() as u64,
        })
    }
}

pub fn default_api_routes(
    node_id: &str,
    operator_label: &str,
    advertised_at_height: u64,
    expires_at_height: u64,
) -> Vec<ApiRouteRecord> {
    vec![
        default_api_route(
            node_id,
            operator_label,
            "GET",
            "/v1/status",
            ApiRouteKind::Status,
            "node.status.read",
            "public:status",
            "status_request_hash",
            "status_response_hash",
            false,
            false,
            advertised_at_height,
            expires_at_height,
        ),
        default_api_route(
            node_id,
            operator_label,
            "POST",
            "/v1/tx/submit",
            ApiRouteKind::SubmitTx,
            "mempool.transaction.submit",
            "account:submit_tx",
            "submit_tx_request_hash",
            "submit_tx_response_hash",
            true,
            true,
            advertised_at_height,
            expires_at_height,
        ),
        default_api_route(
            node_id,
            operator_label,
            "POST",
            "/v1/wallet/scan",
            ApiRouteKind::WalletScan,
            "wallet.scan",
            "account:wallet_scan",
            "wallet_scan_request_hash",
            "wallet_scan_response_hash",
            true,
            true,
            advertised_at_height,
            expires_at_height,
        ),
        default_api_route(
            node_id,
            operator_label,
            "GET",
            "/v1/monero/monitor",
            ApiRouteKind::MoneroMonitor,
            "monero.monitor.read",
            "public:monero_monitor",
            "monero_monitor_request_hash",
            "monero_monitor_response_hash",
            false,
            false,
            advertised_at_height,
            expires_at_height,
        ),
        default_api_route(
            node_id,
            operator_label,
            "POST",
            "/v1/bridge",
            ApiRouteKind::Bridge,
            "monero.bridge.submit",
            "account:bridge",
            "bridge_request_hash",
            "bridge_response_hash",
            true,
            true,
            advertised_at_height,
            expires_at_height,
        ),
        default_api_route(
            node_id,
            operator_label,
            "POST",
            "/v1/defi",
            ApiRouteKind::Defi,
            "defi.intent.submit",
            "account:defi",
            "defi_request_hash",
            "defi_response_hash",
            true,
            true,
            advertised_at_height,
            expires_at_height,
        ),
        default_api_route(
            node_id,
            operator_label,
            "GET",
            "/v1/consensus",
            ApiRouteKind::Consensus,
            "consensus.read",
            "public:consensus",
            "consensus_request_hash",
            "consensus_response_hash",
            false,
            false,
            advertised_at_height,
            expires_at_height,
        ),
        default_api_route(
            node_id,
            operator_label,
            "POST",
            "/v1/fees/quote",
            ApiRouteKind::FeeQuote,
            "fee.quote",
            "public:fee_quote",
            "fee_quote_request_hash",
            "fee_quote_response_hash",
            false,
            false,
            advertised_at_height,
            expires_at_height,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
pub fn default_api_route(
    node_id: &str,
    operator_label: &str,
    method: &str,
    path: &str,
    route_kind: ApiRouteKind,
    capability: &str,
    scope: &str,
    request_payload_kind: &str,
    response_payload_kind: &str,
    requires_auth: bool,
    allows_private_payload: bool,
    advertised_at_height: u64,
    expires_at_height: u64,
) -> ApiRouteRecord {
    let capability = ApiRouteCapability::new(
        route_kind.clone(),
        capability,
        scope,
        request_payload_kind,
        response_payload_kind,
        requires_auth,
        allows_private_payload,
        &json!({}),
    );
    let capability_root = api_capability_root(&[capability.clone()]);
    let route_id = api_route_id(method, path, route_kind.as_str(), &capability_root);
    ApiRouteRecord::new(
        node_id,
        operator_label,
        method,
        path,
        route_kind,
        vec![capability],
        &route_id,
        &json!({}),
        0,
        u64::MAX,
        advertised_at_height,
        expires_at_height,
    )
    .signed()
}

pub fn api_capability_id(
    route_kind: &str,
    capability: &str,
    scope: &str,
    request_payload_kind: &str,
    response_payload_kind: &str,
    requires_auth: bool,
    allows_private_payload: bool,
    public_metadata_root: &str,
) -> String {
    domain_hash(
        "API-CAPABILITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(NODE_API_VERSION),
            HashPart::Str(route_kind),
            HashPart::Str(capability),
            HashPart::Str(scope),
            HashPart::Str(request_payload_kind),
            HashPart::Str(response_payload_kind),
            HashPart::Str(if requires_auth { "auth" } else { "public" }),
            HashPart::Str(if allows_private_payload {
                "private-payload"
            } else {
                "public-payload"
            }),
            HashPart::Str(public_metadata_root),
        ],
        32,
    )
}

pub fn api_route_id(method: &str, path: &str, route_kind: &str, capability_root: &str) -> String {
    domain_hash(
        "API-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(NODE_API_VERSION),
            HashPart::Str(method),
            HashPart::Str(path),
            HashPart::Str(route_kind),
            HashPart::Str(capability_root),
        ],
        32,
    )
}

pub fn api_session_id(
    node_id: &str,
    client_account_commitment: &str,
    allowed_route_root: &str,
    authorization_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "API-SESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(node_id),
            HashPart::Str(client_account_commitment),
            HashPart::Str(allowed_route_root),
            HashPart::Str(authorization_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn api_request_id(
    route_id: &str,
    session_id: &str,
    client_account_commitment: &str,
    idempotency_key_hash: &str,
    payload_hash: &str,
    authorization_root: &str,
    received_at_height: u64,
) -> String {
    domain_hash(
        "API-REQUEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(session_id),
            HashPart::Str(client_account_commitment),
            HashPart::Str(idempotency_key_hash),
            HashPart::Str(payload_hash),
            HashPart::Str(authorization_root),
            HashPart::Int(received_at_height as i128),
        ],
        32,
    )
}

pub fn api_response_id(
    request_id: &str,
    status_code: u16,
    response_payload_hash: &str,
    error_code_hash: &str,
    authorization_root: &str,
    produced_at_height: u64,
) -> String {
    domain_hash(
        "API-RESPONSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_id),
            HashPart::Int(status_code as i128),
            HashPart::Str(response_payload_hash),
            HashPart::Str(error_code_hash),
            HashPart::Str(authorization_root),
            HashPart::Int(produced_at_height as i128),
        ],
        32,
    )
}

pub fn api_rate_limit_bucket_id(
    route_id: &str,
    subject_commitment: &str,
    window_start_height: u64,
    window_end_height: u64,
) -> String {
    domain_hash(
        "API-RATE-LIMIT-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(subject_commitment),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
        ],
        32,
    )
}

pub fn api_request_payload_hash(route_id: &str, payload: &Value) -> String {
    domain_hash(
        "API-REQUEST-PAYLOAD",
        &[HashPart::Str(route_id), HashPart::Json(payload)],
        32,
    )
}

pub fn api_response_payload_hash(request_id: &str, payload: &Value) -> String {
    domain_hash(
        "API-RESPONSE-PAYLOAD",
        &[HashPart::Str(request_id), HashPart::Json(payload)],
        32,
    )
}

pub fn api_public_metadata_root(public_metadata: &Value) -> String {
    domain_hash(
        "API-PUBLIC-METADATA",
        &[HashPart::Json(public_metadata)],
        32,
    )
}

pub fn api_idempotency_key_hash(idempotency_key: &str) -> String {
    domain_hash("API-IDEMPOTENCY-KEY", &[HashPart::Str(idempotency_key)], 32)
}

pub fn api_error_code_hash(error_code: &str) -> String {
    domain_hash("API-ERROR-CODE", &[HashPart::Str(error_code)], 32)
}

pub fn api_authorization_root(authorizations: &[Authorization]) -> String {
    merkle_root(
        "API-AUTHORIZATION",
        &authorizations
            .iter()
            .map(api_authorization_public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn api_capability_root(capabilities: &[ApiRouteCapability]) -> String {
    merkle_root(
        "API-CAPABILITY",
        &capabilities
            .iter()
            .map(ApiRouteCapability::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn api_string_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn api_authorization_public_record(authorization: &Authorization) -> Value {
    json!({
        "auth_scheme": authorization.auth_scheme,
        "auth_public_key": authorization.auth_public_key,
        "auth_transcript_hash": authorization.auth_transcript_hash,
        "auth_signature": authorization.auth_signature,
    })
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
