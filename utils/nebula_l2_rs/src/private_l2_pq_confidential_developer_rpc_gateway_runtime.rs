use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialDeveloperRpcGatewayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-developer-rpc-gateway-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-rpc-gateway-v1";
pub const VIEW_DISCLOSURE_SUITE: &str = "monero-view-key-selective-disclosure-v1";
pub const ROOTS_ONLY_PROFILE: &str = "roots-only-public-rpc-response-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 512;
pub const DEFAULT_MAX_JSON_BYTES: u32 = 262_144;
pub const DEFAULT_MAX_CALLDATA_BYTES: u32 = 65_536;
pub const DEFAULT_MAX_ROUTES: usize = 128;
pub const DEFAULT_MAX_SESSIONS: usize = 2048;
pub const DEFAULT_MAX_RECEIPTS: usize = 8192;
pub const DEFAULT_MAX_PROGRESS_EVENTS: usize = 4096;
pub const DEFAULT_MAX_DISCLOSURE_LABELS: usize = 64;
pub const DEFAULT_PRECONFIRMATION_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u16 = 12;
pub const DEFAULT_SPONSOR_MAX_FEE_BPS: u16 = 20;
pub const DEFAULT_RATE_LIMIT_WINDOW_BLOCKS: u64 = 20;
pub const DEFAULT_RATE_LIMIT_MAX_REQUESTS: u64 = 240;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_SESSION_WEIGHT: u64 = 2;
pub const MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    WalletPlans,
    ScenarioReceipts,
    ReleaseReadiness,
    ProgressFeed,
    PrivateTokenCall,
    SmartContractCall,
    MoneroBridgeCommand,
    FeeSponsorshipQuote,
    PqSessionAuth,
    ViewKeyDisclosure,
    LowFeeBatching,
    PreconfirmationStatus,
    PublicRoots,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletPlans => "wallet_plans",
            Self::ScenarioReceipts => "scenario_receipts",
            Self::ReleaseReadiness => "release_readiness",
            Self::ProgressFeed => "progress_feed",
            Self::PrivateTokenCall => "private_token_call",
            Self::SmartContractCall => "smart_contract_call",
            Self::MoneroBridgeCommand => "monero_bridge_command",
            Self::FeeSponsorshipQuote => "fee_sponsorship_quote",
            Self::PqSessionAuth => "pq_session_auth",
            Self::ViewKeyDisclosure => "view_key_disclosure",
            Self::LowFeeBatching => "low_fee_batching",
            Self::PreconfirmationStatus => "preconfirmation_status",
            Self::PublicRoots => "public_roots",
        }
    }

    pub fn default_path(self) -> &'static str {
        match self {
            Self::WalletPlans => "/developer/wallet/plans",
            Self::ScenarioReceipts => "/developer/scenarios/receipts",
            Self::ReleaseReadiness => "/developer/release/readiness",
            Self::ProgressFeed => "/developer/progress/feed",
            Self::PrivateTokenCall => "/developer/private-token/call",
            Self::SmartContractCall => "/developer/contracts/call",
            Self::MoneroBridgeCommand => "/developer/monero/bridge/command",
            Self::FeeSponsorshipQuote => "/developer/fees/sponsorship/quote",
            Self::PqSessionAuth => "/developer/pq/session/auth",
            Self::ViewKeyDisclosure => "/developer/view-key/disclosure",
            Self::LowFeeBatching => "/developer/low-fee/batching",
            Self::PreconfirmationStatus => "/developer/preconfirmation/status",
            Self::PublicRoots => "/developer/public/roots",
        }
    }

    pub fn default_method(self) -> &'static str {
        match self {
            Self::ProgressFeed | Self::PreconfirmationStatus | Self::PublicRoots => "GET",
            _ => "POST",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequirement {
    Public,
    Session,
    SessionAndViewPolicy,
    Operator,
    Sponsor,
}

impl AuthRequirement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Session => "session",
            Self::SessionAndViewPolicy => "session_and_view_policy",
            Self::Operator => "operator",
            Self::Sponsor => "sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Drafted,
    Accepted,
    RateLimited,
    Unauthorized,
    Validated,
    Planned,
    Batched,
    Preconfirmed,
    Completed,
    Rejected,
}

impl RequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Accepted => "accepted",
            Self::RateLimited => "rate_limited",
            Self::Unauthorized => "unauthorized",
            Self::Validated => "validated",
            Self::Planned => "planned",
            Self::Batched => "batched",
            Self::Preconfirmed => "preconfirmed",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseProfile {
    PrivateEnvelope,
    PublicSummary,
    RootsOnly,
    ErrorReceipt,
}

impl ResponseProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateEnvelope => "private_envelope",
            Self::PublicSummary => "public_summary",
            Self::RootsOnly => "roots_only",
            Self::ErrorReceipt => "error_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletPlanKind {
    Transfer,
    ContractCall,
    BridgeDeposit,
    BridgeExit,
    SponsoredBundle,
    LowFeeBatch,
    ViewSync,
}

impl WalletPlanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::ContractCall => "contract_call",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeExit => "bridge_exit",
            Self::SponsoredBundle => "sponsored_bundle",
            Self::LowFeeBatch => "low_fee_batch",
            Self::ViewSync => "view_sync",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioStatus {
    Queued,
    Running,
    Passed,
    Failed,
    Waived,
}

impl ScenarioStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Waived => "waived",
        }
    }

    pub fn release_score_bps(self) -> u16 {
        match self {
            Self::Queued => 0,
            Self::Running => 5_000,
            Self::Passed | Self::Waived => MAX_BPS,
            Self::Failed => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateStatus {
    Pending,
    Passing,
    Warning,
    Failing,
    Waived,
}

impl ReleaseGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Passing => "passing",
            Self::Warning => "warning",
            Self::Failing => "failing",
            Self::Waived => "waived",
        }
    }

    pub fn releasable(self) -> bool {
        matches!(self, Self::Passing | Self::Waived)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgressSeverity {
    Trace,
    Info,
    Warning,
    Error,
}

impl ProgressSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeCommandKind {
    PrepareDeposit,
    SubmitDepositProof,
    QuoteExit,
    PrepareExit,
    SubmitExitProof,
    WatchFinality,
    RotateSubaddress,
}

impl BridgeCommandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrepareDeposit => "prepare_deposit",
            Self::SubmitDepositProof => "submit_deposit_proof",
            Self::QuoteExit => "quote_exit",
            Self::PrepareExit => "prepare_exit",
            Self::SubmitExitProof => "submit_exit_proof",
            Self::WatchFinality => "watch_finality",
            Self::RotateSubaddress => "rotate_subaddress",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    None,
    WalletOnly,
    Auditor,
    Counterparty,
    Sponsor,
    Operator,
    Regulator,
    PublicReceipt,
}

impl DisclosureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WalletOnly => "wallet_only",
            Self::Auditor => "auditor",
            Self::Counterparty => "counterparty",
            Self::Sponsor => "sponsor",
            Self::Operator => "operator",
            Self::Regulator => "regulator",
            Self::PublicReceipt => "public_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStrategy {
    None,
    SameAssetNetting,
    ContractCallAggregation,
    BridgeCommandAggregation,
    SponsorBundle,
    PreconfirmationLane,
}

impl BatchStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SameAssetNetting => "same_asset_netting",
            Self::ContractCallAggregation => "contract_call_aggregation",
            Self::BridgeCommandAggregation => "bridge_command_aggregation",
            Self::SponsorBundle => "sponsor_bundle",
            Self::PreconfirmationLane => "preconfirmation_lane",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatusKind {
    Unknown,
    Pending,
    SoftLocked,
    Included,
    Expired,
    Rejected,
}

impl PreconfirmationStatusKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Pending => "pending",
            Self::SoftLocked => "soft_locked",
            Self::Included => "included",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub view_disclosure_suite: String,
    pub roots_only_profile: String,
    pub default_fee_asset_id: String,
    pub max_routes: usize,
    pub max_sessions: usize,
    pub max_receipts: usize,
    pub max_progress_events: usize,
    pub max_batch_items: usize,
    pub max_json_bytes: u32,
    pub max_calldata_bytes: u32,
    pub max_disclosure_labels: usize,
    pub min_pq_security_bits: u16,
    pub min_session_weight: u64,
    pub rate_limit_window_blocks: u64,
    pub rate_limit_max_requests: u64,
    pub low_fee_target_bps: u16,
    pub sponsor_max_fee_bps: u16,
    pub preconfirmation_ttl_blocks: u64,
    pub allow_roots_only_public_responses: bool,
    pub allow_fee_sponsorship: bool,
    pub allow_low_fee_batching: bool,
    pub require_pq_session: bool,
    pub require_view_policy: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            view_disclosure_suite: VIEW_DISCLOSURE_SUITE.to_string(),
            roots_only_profile: ROOTS_ONLY_PROFILE.to_string(),
            default_fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            max_routes: DEFAULT_MAX_ROUTES,
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_progress_events: DEFAULT_MAX_PROGRESS_EVENTS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_json_bytes: DEFAULT_MAX_JSON_BYTES,
            max_calldata_bytes: DEFAULT_MAX_CALLDATA_BYTES,
            max_disclosure_labels: DEFAULT_MAX_DISCLOSURE_LABELS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_session_weight: DEFAULT_MIN_SESSION_WEIGHT,
            rate_limit_window_blocks: DEFAULT_RATE_LIMIT_WINDOW_BLOCKS,
            rate_limit_max_requests: DEFAULT_RATE_LIMIT_MAX_REQUESTS,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            sponsor_max_fee_bps: DEFAULT_SPONSOR_MAX_FEE_BPS,
            preconfirmation_ttl_blocks: DEFAULT_PRECONFIRMATION_TTL_BLOCKS,
            allow_roots_only_public_responses: true,
            allow_fee_sponsorship: true,
            allow_low_fee_batching: true,
            require_pq_session: true,
            require_view_policy: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("l2_network", &self.l2_network)?;
        ensure_nonempty("monero_network", &self.monero_network)?;
        ensure_nonempty("hash_suite", &self.hash_suite)?;
        ensure_nonempty("pq_auth_suite", &self.pq_auth_suite)?;
        ensure_nonempty("view_disclosure_suite", &self.view_disclosure_suite)?;
        ensure_nonempty("roots_only_profile", &self.roots_only_profile)?;
        ensure_nonempty("default_fee_asset_id", &self.default_fee_asset_id)?;
        if self.chain_id != CHAIN_ID {
            return Err("config chain_id does not match crate CHAIN_ID".to_string());
        }
        if self.schema_version == 0 {
            return Err("schema_version must be nonzero".to_string());
        }
        if self.max_routes == 0 || self.max_sessions == 0 || self.max_receipts == 0 {
            return Err("route, session, and receipt capacities must be nonzero".to_string());
        }
        if self.max_batch_items == 0 {
            return Err("max_batch_items must be nonzero".to_string());
        }
        if self.max_json_bytes == 0 || self.max_calldata_bytes == 0 {
            return Err("payload byte limits must be nonzero".to_string());
        }
        if self.rate_limit_window_blocks == 0 || self.rate_limit_max_requests == 0 {
            return Err("rate limit policy must be nonzero".to_string());
        }
        if self.low_fee_target_bps > MAX_BPS || self.sponsor_max_fee_bps > MAX_BPS {
            return Err("fee bps values exceed MAX_BPS".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits below supported floor".to_string());
        }
        Ok(())
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteRecord {
    pub route_id: String,
    pub kind: RouteKind,
    pub method: String,
    pub path: String,
    pub auth_requirement: AuthRequirement,
    pub request_schema_root: String,
    pub response_schema_root: String,
    pub capability_root: String,
    pub rate_policy_id: String,
    pub roots_only_allowed: bool,
    pub private_payload_allowed: bool,
    pub enabled: bool,
}

impl RouteRecord {
    pub fn new(
        kind: RouteKind,
        auth_requirement: AuthRequirement,
        private_payload_allowed: bool,
        roots_only_allowed: bool,
    ) -> Self {
        let method = kind.default_method().to_string();
        let path = kind.default_path().to_string();
        let request_schema_root = label_hash("RPC-GATEWAY-REQUEST-SCHEMA", kind.as_str());
        let response_schema_root = label_hash("RPC-GATEWAY-RESPONSE-SCHEMA", kind.as_str());
        let capability_root = route_capability_root(
            kind,
            auth_requirement,
            &request_schema_root,
            &response_schema_root,
            private_payload_allowed,
            roots_only_allowed,
        );
        let rate_policy_id = label_hash("RPC-GATEWAY-RATE-POLICY-ID", kind.as_str());
        let route_id = route_id(&method, &path, kind, &capability_root);
        Self {
            route_id,
            kind,
            method,
            path,
            auth_requirement,
            request_schema_root,
            response_schema_root,
            capability_root,
            rate_policy_id,
            roots_only_allowed,
            private_payload_allowed,
            enabled: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "route_id": self.route_id,
            "kind": self.kind.as_str(),
            "method": self.method,
            "path": self.path,
            "auth_requirement": self.auth_requirement.as_str(),
            "request_schema_root": self.request_schema_root,
            "response_schema_root": self.response_schema_root,
            "capability_root": self.capability_root,
            "rate_policy_id": self.rate_policy_id,
            "roots_only_allowed": self.roots_only_allowed,
            "private_payload_allowed": self.private_payload_allowed,
            "enabled": self.enabled,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-ROUTE", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("route_id", &self.route_id)?;
        ensure_nonempty("method", &self.method)?;
        ensure_nonempty("path", &self.path)?;
        ensure_nonempty("request_schema_root", &self.request_schema_root)?;
        ensure_nonempty("response_schema_root", &self.response_schema_root)?;
        ensure_nonempty("capability_root", &self.capability_root)?;
        ensure_nonempty("rate_policy_id", &self.rate_policy_id)?;
        if !self.path.starts_with('/') {
            return Err("route path must start with /".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSessionAuthRecord {
    pub session_id: String,
    pub client_account_commitment: String,
    pub wallet_device_commitment: String,
    pub operator_commitment: String,
    pub kem_ciphertext_hash: String,
    pub pq_signature_root: String,
    pub allowed_route_root: String,
    pub view_policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub security_bits: u16,
    pub session_weight: u64,
    pub revoked: bool,
}

impl PqSessionAuthRecord {
    pub fn new(request: &PqSessionAuthRequest) -> Self {
        let allowed_route_root = string_set_root(
            "RPC-GATEWAY-SESSION-ALLOWED-ROUTES",
            &request.allowed_routes,
        );
        let view_policy_root = string_set_root(
            "RPC-GATEWAY-SESSION-VIEW-POLICIES",
            &request.view_policy_labels,
        );
        let session_id = session_id(
            &request.client_account_commitment,
            &request.wallet_device_commitment,
            &request.operator_commitment,
            &request.kem_ciphertext_hash,
            &request.pq_signature_root,
            &allowed_route_root,
            request.opened_at_height,
            request.expires_at_height,
        );
        Self {
            session_id,
            client_account_commitment: request.client_account_commitment.clone(),
            wallet_device_commitment: request.wallet_device_commitment.clone(),
            operator_commitment: request.operator_commitment.clone(),
            kem_ciphertext_hash: request.kem_ciphertext_hash.clone(),
            pq_signature_root: request.pq_signature_root.clone(),
            allowed_route_root,
            view_policy_root,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            security_bits: request.security_bits,
            session_weight: request.session_weight,
            revoked: false,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        !self.revoked && self.opened_at_height <= height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "session_id": self.session_id,
            "client_account_commitment": self.client_account_commitment,
            "wallet_device_commitment": self.wallet_device_commitment,
            "operator_commitment": self.operator_commitment,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "pq_signature_root": self.pq_signature_root,
            "allowed_route_root": self.allowed_route_root,
            "view_policy_root": self.view_policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "security_bits": self.security_bits,
            "session_weight": self.session_weight,
            "revoked": self.revoked,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-PQ-SESSION", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("session_id", &self.session_id)?;
        ensure_nonempty("client_account_commitment", &self.client_account_commitment)?;
        ensure_nonempty("wallet_device_commitment", &self.wallet_device_commitment)?;
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("kem_ciphertext_hash", &self.kem_ciphertext_hash)?;
        ensure_nonempty("pq_signature_root", &self.pq_signature_root)?;
        ensure_ordered_heights(self.opened_at_height, self.expires_at_height, "session")?;
        if self.security_bits < config.min_pq_security_bits {
            return Err("session security_bits below configured minimum".to_string());
        }
        if self.session_weight < config.min_session_weight {
            return Err("session weight below configured minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GatewayRequestEnvelope {
    pub request_id: String,
    pub route_id: String,
    pub route_kind: RouteKind,
    pub session_id: String,
    pub client_account_commitment: String,
    pub idempotency_key_hash: String,
    pub payload_hash: String,
    pub payload_kind: String,
    pub payload_size_bytes: u32,
    pub authorization_root: String,
    pub view_policy_root: String,
    pub received_at_height: u64,
    pub status: RequestStatus,
}

impl GatewayRequestEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "request_id": self.request_id,
            "route_id": self.route_id,
            "route_kind": self.route_kind.as_str(),
            "session_id": self.session_id,
            "client_account_commitment": self.client_account_commitment,
            "idempotency_key_hash": self.idempotency_key_hash,
            "payload_hash": self.payload_hash,
            "payload_kind": self.payload_kind,
            "payload_size_bytes": self.payload_size_bytes,
            "authorization_root": self.authorization_root,
            "view_policy_root": self.view_policy_root,
            "received_at_height": self.received_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-REQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GatewayResponseEnvelope {
    pub response_id: String,
    pub request_id: String,
    pub route_id: String,
    pub profile: ResponseProfile,
    pub status_code: u16,
    pub response_payload_hash: String,
    pub public_root: String,
    pub private_envelope_root: String,
    pub error_code_hash: String,
    pub produced_at_height: u64,
}

impl GatewayResponseEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "response_id": self.response_id,
            "request_id": self.request_id,
            "route_id": self.route_id,
            "profile": self.profile.as_str(),
            "status_code": self.status_code,
            "response_payload_hash": self.response_payload_hash,
            "public_root": self.public_root,
            "private_envelope_root": self.private_envelope_root,
            "error_code_hash": self.error_code_hash,
            "produced_at_height": self.produced_at_height,
        })
    }

    pub fn roots_only_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "response_id": self.response_id,
            "request_id": self.request_id,
            "route_id": self.route_id,
            "profile": ResponseProfile::RootsOnly.as_str(),
            "status_code": self.status_code,
            "response_payload_hash": self.response_payload_hash,
            "public_root": self.public_root,
            "private_envelope_root": self.private_envelope_root,
            "error_code_hash": self.error_code_hash,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-RESPONSE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WalletPlanRequest {
    pub session_id: String,
    pub account_commitment: String,
    pub plan_kind: WalletPlanKind,
    pub target_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub memo_ciphertext_hash: String,
    pub desired_batch_strategy: BatchStrategy,
    pub fee_limit_units: u64,
    pub idempotency_key: String,
    pub height: u64,
}

impl WalletPlanRequest {
    pub fn payload_hash(&self) -> String {
        hash_json("RPC-GATEWAY-WALLET-PLAN-REQUEST-PAYLOAD", &json!(self))
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("session_id", &self.session_id)?;
        ensure_nonempty("account_commitment", &self.account_commitment)?;
        ensure_nonempty("target_commitment", &self.target_commitment)?;
        ensure_nonempty("asset_id", &self.asset_id)?;
        ensure_nonempty("amount_commitment", &self.amount_commitment)?;
        ensure_nonempty("idempotency_key", &self.idempotency_key)?;
        if self.fee_limit_units == 0 {
            return Err("wallet plan fee_limit_units must be nonzero".to_string());
        }
        if self.desired_batch_strategy != BatchStrategy::None && !config.allow_low_fee_batching {
            return Err("low fee batching is disabled".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WalletPlanReceipt {
    pub plan_id: String,
    pub request_id: String,
    pub plan_kind: WalletPlanKind,
    pub account_commitment: String,
    pub action_root: String,
    pub fee_quote_id: String,
    pub disclosure_policy_id: String,
    pub batch_id: String,
    pub preconfirmation_id: String,
    pub created_at_height: u64,
}

impl WalletPlanReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "request_id": self.request_id,
            "plan_kind": self.plan_kind.as_str(),
            "account_commitment": self.account_commitment,
            "action_root": self.action_root,
            "fee_quote_id": self.fee_quote_id,
            "disclosure_policy_id": self.disclosure_policy_id,
            "batch_id": self.batch_id,
            "preconfirmation_id": self.preconfirmation_id,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-WALLET-PLAN-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ScenarioReceipt {
    pub scenario_id: String,
    pub scenario_label: String,
    pub status: ScenarioStatus,
    pub operator_commitment: String,
    pub transcript_root: String,
    pub artifact_root: String,
    pub request_root: String,
    pub response_root: String,
    pub started_at_height: u64,
    pub completed_at_height: u64,
}

impl ScenarioReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "scenario_id": self.scenario_id,
            "scenario_label": self.scenario_label,
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "transcript_root": self.transcript_root,
            "artifact_root": self.artifact_root,
            "request_root": self.request_root,
            "response_root": self.response_root,
            "started_at_height": self.started_at_height,
            "completed_at_height": self.completed_at_height,
            "release_score_bps": self.status.release_score_bps(),
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-SCENARIO-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseReadinessGate {
    pub gate_id: String,
    pub label: String,
    pub status: ReleaseGateStatus,
    pub evidence_root: String,
    pub score_bps: u16,
    pub required: bool,
}

impl ReleaseReadinessGate {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "gate_id": self.gate_id,
            "label": self.label,
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "score_bps": self.score_bps,
            "required": self.required,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-RELEASE-GATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ReleaseReadinessSnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub min_release_score_bps: u16,
    pub aggregate_score_bps: u16,
    pub gate_root: String,
    pub scenario_root: String,
    pub progress_root: String,
    pub releasable: bool,
}

impl ReleaseReadinessSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "min_release_score_bps": self.min_release_score_bps,
            "aggregate_score_bps": self.aggregate_score_bps,
            "gate_root": self.gate_root,
            "scenario_root": self.scenario_root,
            "progress_root": self.progress_root,
            "releasable": self.releasable,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-RELEASE-SNAPSHOT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ProgressFeedEvent {
    pub event_id: String,
    pub lane: String,
    pub severity: ProgressSeverity,
    pub subject_root: String,
    pub message_hash: String,
    pub metadata_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl ProgressFeedEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "event_id": self.event_id,
            "lane": self.lane,
            "severity": self.severity.as_str(),
            "subject_root": self.subject_root,
            "message_hash": self.message_hash,
            "metadata_root": self.metadata_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-PROGRESS-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ProgressFeedSnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub cursor: u64,
    pub event_root: String,
    pub lane_root: String,
    pub severity_root: String,
}

impl ProgressFeedSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "cursor": self.cursor,
            "event_root": self.event_root,
            "lane_root": self.lane_root,
            "severity_root": self.severity_root,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-PROGRESS-SNAPSHOT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PrivateTokenCallRequest {
    pub session_id: String,
    pub account_commitment: String,
    pub token_id: String,
    pub function_selector: String,
    pub encrypted_args_hash: String,
    pub value_commitment: String,
    pub fee_asset_id: String,
    pub fee_limit_units: u64,
    pub idempotency_key: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SmartContractCallRequest {
    pub session_id: String,
    pub account_commitment: String,
    pub contract_id: String,
    pub method_selector: String,
    pub calldata_hash: String,
    pub calldata_size_bytes: u32,
    pub witness_root: String,
    pub fee_asset_id: String,
    pub fee_limit_units: u64,
    pub idempotency_key: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ContractCallReceipt {
    pub call_id: String,
    pub request_id: String,
    pub account_commitment: String,
    pub target_id: String,
    pub call_root: String,
    pub witness_root: String,
    pub fee_quote_id: String,
    pub preconfirmation_id: String,
    pub status: RequestStatus,
    pub produced_at_height: u64,
}

impl ContractCallReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "call_id": self.call_id,
            "request_id": self.request_id,
            "account_commitment": self.account_commitment,
            "target_id": self.target_id,
            "call_root": self.call_root,
            "witness_root": self.witness_root,
            "fee_quote_id": self.fee_quote_id,
            "preconfirmation_id": self.preconfirmation_id,
            "status": self.status.as_str(),
            "produced_at_height": self.produced_at_height,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-CONTRACT-CALL-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MoneroBridgeCommandRequest {
    pub session_id: String,
    pub account_commitment: String,
    pub command_kind: BridgeCommandKind,
    pub bridge_account_commitment: String,
    pub subaddress_commitment: String,
    pub amount_commitment: String,
    pub monero_txid_hash: String,
    pub proof_root: String,
    pub fee_limit_units: u64,
    pub idempotency_key: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MoneroBridgeCommandReceipt {
    pub command_id: String,
    pub request_id: String,
    pub command_kind: BridgeCommandKind,
    pub bridge_account_commitment: String,
    pub command_root: String,
    pub proof_root: String,
    pub watch_root: String,
    pub status: RequestStatus,
    pub produced_at_height: u64,
}

impl MoneroBridgeCommandReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "command_id": self.command_id,
            "request_id": self.request_id,
            "command_kind": self.command_kind.as_str(),
            "bridge_account_commitment": self.bridge_account_commitment,
            "command_root": self.command_root,
            "proof_root": self.proof_root,
            "watch_root": self.watch_root,
            "status": self.status.as_str(),
            "produced_at_height": self.produced_at_height,
        })
    }

    pub fn root(&self) -> String {
        hash_json(
            "RPC-GATEWAY-MONERO-BRIDGE-COMMAND-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FeeSponsorshipQuoteRequest {
    pub session_id: String,
    pub account_commitment: String,
    pub sponsor_commitment: String,
    pub action_root: String,
    pub fee_asset_id: String,
    pub estimated_fee_units: u64,
    pub max_fee_bps: u16,
    pub idempotency_key: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FeeSponsorshipQuote {
    pub quote_id: String,
    pub request_id: String,
    pub sponsor_commitment: String,
    pub action_root: String,
    pub fee_asset_id: String,
    pub estimated_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub sponsor_fee_bps: u16,
    pub expires_at_height: u64,
}

impl FeeSponsorshipQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "request_id": self.request_id,
            "sponsor_commitment": self.sponsor_commitment,
            "action_root": self.action_root,
            "fee_asset_id": self.fee_asset_id,
            "estimated_fee_units": self.estimated_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-FEE-SPONSORSHIP-QUOTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PqSessionAuthRequest {
    pub client_account_commitment: String,
    pub wallet_device_commitment: String,
    pub operator_commitment: String,
    pub kem_ciphertext_hash: String,
    pub pq_signature_root: String,
    pub allowed_routes: BTreeSet<String>,
    pub view_policy_labels: BTreeSet<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub security_bits: u16,
    pub session_weight: u64,
    pub idempotency_key: String,
}

impl PqSessionAuthRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("client_account_commitment", &self.client_account_commitment)?;
        ensure_nonempty("wallet_device_commitment", &self.wallet_device_commitment)?;
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("kem_ciphertext_hash", &self.kem_ciphertext_hash)?;
        ensure_nonempty("pq_signature_root", &self.pq_signature_root)?;
        ensure_nonempty("idempotency_key", &self.idempotency_key)?;
        ensure_ordered_heights(
            self.opened_at_height,
            self.expires_at_height,
            "pq session auth",
        )?;
        if self.security_bits < config.min_pq_security_bits {
            return Err("pq auth security_bits below configured minimum".to_string());
        }
        if self.session_weight < config.min_session_weight {
            return Err("pq auth session_weight below configured minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ViewKeyDisclosureRequest {
    pub session_id: String,
    pub account_commitment: String,
    pub view_key_commitment: String,
    pub disclosure_scope: DisclosureScope,
    pub recipient_commitment: String,
    pub label_set: BTreeSet<String>,
    pub disclosure_window_start_height: u64,
    pub disclosure_window_end_height: u64,
    pub idempotency_key: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ViewKeyDisclosureControl {
    pub disclosure_id: String,
    pub request_id: String,
    pub account_commitment: String,
    pub view_key_commitment: String,
    pub disclosure_scope: DisclosureScope,
    pub recipient_commitment: String,
    pub label_root: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub policy_root: String,
    pub revoked: bool,
}

impl ViewKeyDisclosureControl {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "request_id": self.request_id,
            "account_commitment": self.account_commitment,
            "view_key_commitment": self.view_key_commitment,
            "disclosure_scope": self.disclosure_scope.as_str(),
            "recipient_commitment": self.recipient_commitment,
            "label_root": self.label_root,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "policy_root": self.policy_root,
            "revoked": self.revoked,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-VIEW-KEY-DISCLOSURE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LowFeeBatchRequest {
    pub session_id: String,
    pub account_commitment: String,
    pub strategy: BatchStrategy,
    pub item_roots: Vec<String>,
    pub sponsor_commitment: String,
    pub max_fee_bps: u16,
    pub idempotency_key: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LowFeeBatchReceipt {
    pub batch_id: String,
    pub request_id: String,
    pub strategy: BatchStrategy,
    pub account_commitment: String,
    pub item_root: String,
    pub sponsor_commitment: String,
    pub fee_reduction_bps: u16,
    pub batch_weight: u64,
    pub status: RequestStatus,
    pub produced_at_height: u64,
}

impl LowFeeBatchReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "request_id": self.request_id,
            "strategy": self.strategy.as_str(),
            "account_commitment": self.account_commitment,
            "item_root": self.item_root,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_reduction_bps": self.fee_reduction_bps,
            "batch_weight": self.batch_weight,
            "status": self.status.as_str(),
            "produced_at_height": self.produced_at_height,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-LOW-FEE-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PreconfirmationStatusRequest {
    pub session_id: String,
    pub account_commitment: String,
    pub subject_id: String,
    pub subject_root: String,
    pub idempotency_key: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PreconfirmationRecord {
    pub preconfirmation_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub status: PreconfirmationStatusKind,
    pub quorum_root: String,
    pub expires_at_height: u64,
    pub updated_at_height: u64,
}

impl PreconfirmationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "preconfirmation_id": self.preconfirmation_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "status": self.status.as_str(),
            "quorum_root": self.quorum_root,
            "expires_at_height": self.expires_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-PRECONFIRMATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub requests: u64,
    pub responses: u64,
    pub sessions: u64,
    pub wallet_plans: u64,
    pub contract_calls: u64,
    pub bridge_commands: u64,
    pub fee_quotes: u64,
    pub disclosures: u64,
    pub batches: u64,
    pub preconfirmations: u64,
    pub scenario_receipts: u64,
    pub progress_events: u64,
    pub release_snapshots: u64,
    pub rejected_requests: u64,
    pub rate_limited_requests: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RatePolicy {
    pub policy_id: String,
    pub route_id: String,
    pub window_blocks: u64,
    pub max_requests: u64,
    pub max_payload_bytes: u32,
    pub requires_session: bool,
}

impl RatePolicy {
    pub fn for_route(config: &Config, route: &RouteRecord) -> Self {
        Self {
            policy_id: route.rate_policy_id.clone(),
            route_id: route.route_id.clone(),
            window_blocks: config.rate_limit_window_blocks,
            max_requests: config.rate_limit_max_requests,
            max_payload_bytes: config.max_json_bytes,
            requires_session: route.auth_requirement != AuthRequirement::Public,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-RATE-POLICY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RateWindow {
    pub window_id: String,
    pub policy_id: String,
    pub subject_commitment: String,
    pub route_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub request_count: u64,
}

impl RateWindow {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-RATE-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeePolicy {
    pub fee_asset_id: String,
    pub default_fee_limit_units: u64,
    pub low_fee_target_bps: u16,
    pub sponsor_max_fee_bps: u16,
    pub preconfirmation_fee_units: u64,
    pub bridge_command_fee_units: u64,
    pub contract_call_fee_units: u64,
}

impl FeePolicy {
    pub fn devnet(config: &Config) -> Self {
        Self {
            fee_asset_id: config.default_fee_asset_id.clone(),
            default_fee_limit_units: 25_000,
            low_fee_target_bps: config.low_fee_target_bps,
            sponsor_max_fee_bps: config.sponsor_max_fee_bps,
            preconfirmation_fee_units: 650,
            bridge_command_fee_units: 2_500,
            contract_call_fee_units: 4_000,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        hash_json("RPC-GATEWAY-FEE-POLICY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub route_registry_root: String,
    pub rate_policy_root: String,
    pub rate_window_root: String,
    pub fee_policy_root: String,
    pub session_root: String,
    pub request_root: String,
    pub response_root: String,
    pub wallet_plan_root: String,
    pub scenario_receipt_root: String,
    pub release_readiness_root: String,
    pub progress_feed_root: String,
    pub contract_call_root: String,
    pub monero_bridge_command_root: String,
    pub fee_quote_root: String,
    pub view_disclosure_root: String,
    pub low_fee_batch_root: String,
    pub preconfirmation_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn roots_only_response(&self, height: u64) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "profile": ROOTS_ONLY_PROFILE,
            "height": height,
            "roots": self.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub fee_policy: FeePolicy,
    pub counters: Counters,
    pub routes: BTreeMap<String, RouteRecord>,
    pub routes_by_kind: BTreeMap<RouteKind, String>,
    pub rate_policies: BTreeMap<String, RatePolicy>,
    pub rate_windows: BTreeMap<String, RateWindow>,
    pub sessions: BTreeMap<String, PqSessionAuthRecord>,
    pub requests: BTreeMap<String, GatewayRequestEnvelope>,
    pub responses: BTreeMap<String, GatewayResponseEnvelope>,
    pub wallet_plans: BTreeMap<String, WalletPlanReceipt>,
    pub scenario_receipts: BTreeMap<String, ScenarioReceipt>,
    pub release_gates: BTreeMap<String, ReleaseReadinessGate>,
    pub release_snapshots: BTreeMap<String, ReleaseReadinessSnapshot>,
    pub progress_events: BTreeMap<String, ProgressFeedEvent>,
    pub contract_calls: BTreeMap<String, ContractCallReceipt>,
    pub monero_bridge_commands: BTreeMap<String, MoneroBridgeCommandReceipt>,
    pub fee_quotes: BTreeMap<String, FeeSponsorshipQuote>,
    pub view_disclosures: BTreeMap<String, ViewKeyDisclosureControl>,
    pub low_fee_batches: BTreeMap<String, LowFeeBatchReceipt>,
    pub preconfirmations: BTreeMap<String, PreconfirmationRecord>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            fee_policy: FeePolicy::devnet(&config),
            config,
            counters: Counters::default(),
            routes: BTreeMap::new(),
            routes_by_kind: BTreeMap::new(),
            rate_policies: BTreeMap::new(),
            rate_windows: BTreeMap::new(),
            sessions: BTreeMap::new(),
            requests: BTreeMap::new(),
            responses: BTreeMap::new(),
            wallet_plans: BTreeMap::new(),
            scenario_receipts: BTreeMap::new(),
            release_gates: BTreeMap::new(),
            release_snapshots: BTreeMap::new(),
            progress_events: BTreeMap::new(),
            contract_calls: BTreeMap::new(),
            monero_bridge_commands: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            view_disclosures: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
        };
        state.register_default_routes()?;
        Ok(state)
    }

    pub fn devnet() -> Self {
        match Self::new(Config::devnet()) {
            Ok(state) => state,
            Err(_) => Self {
                config: Config::devnet(),
                fee_policy: FeePolicy::devnet(&Config::devnet()),
                counters: Counters::default(),
                routes: BTreeMap::new(),
                routes_by_kind: BTreeMap::new(),
                rate_policies: BTreeMap::new(),
                rate_windows: BTreeMap::new(),
                sessions: BTreeMap::new(),
                requests: BTreeMap::new(),
                responses: BTreeMap::new(),
                wallet_plans: BTreeMap::new(),
                scenario_receipts: BTreeMap::new(),
                release_gates: BTreeMap::new(),
                release_snapshots: BTreeMap::new(),
                progress_events: BTreeMap::new(),
                contract_calls: BTreeMap::new(),
                monero_bridge_commands: BTreeMap::new(),
                fee_quotes: BTreeMap::new(),
                view_disclosures: BTreeMap::new(),
                low_fee_batches: BTreeMap::new(),
                preconfirmations: BTreeMap::new(),
            },
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let session_request = PqSessionAuthRequest {
            client_account_commitment: label_hash("RPC-GATEWAY-DEMO", "account"),
            wallet_device_commitment: label_hash("RPC-GATEWAY-DEMO", "device"),
            operator_commitment: label_hash("RPC-GATEWAY-DEMO", "operator"),
            kem_ciphertext_hash: label_hash("RPC-GATEWAY-DEMO", "kem"),
            pq_signature_root: label_hash("RPC-GATEWAY-DEMO", "signature"),
            allowed_routes: state.routes.keys().cloned().collect(),
            view_policy_labels: ["wallet", "auditor", "sponsor"]
                .iter()
                .map(|value| value.to_string())
                .collect(),
            opened_at_height: 1,
            expires_at_height: 10_000,
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            session_weight: DEFAULT_MIN_SESSION_WEIGHT,
            idempotency_key: "demo-session".to_string(),
        };
        let session = state.authorize_pq_session(session_request);
        let session_id = session
            .map(|record| record.session_id)
            .unwrap_or_else(|_| String::new());
        let wallet_request = WalletPlanRequest {
            session_id,
            account_commitment: label_hash("RPC-GATEWAY-DEMO", "account"),
            plan_kind: WalletPlanKind::Transfer,
            target_commitment: label_hash("RPC-GATEWAY-DEMO", "recipient"),
            asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            amount_commitment: label_hash("RPC-GATEWAY-DEMO", "amount"),
            memo_ciphertext_hash: label_hash("RPC-GATEWAY-DEMO", "memo"),
            desired_batch_strategy: BatchStrategy::SameAssetNetting,
            fee_limit_units: 25_000,
            idempotency_key: "demo-wallet-plan".to_string(),
            height: 7,
        };
        let _ = state.plan_wallet_action(wallet_request);
        let _ = state.record_progress_event(
            "wallet",
            ProgressSeverity::Info,
            &label_hash("RPC-GATEWAY-DEMO", "subject"),
            "demo wallet plan accepted",
            &json!({"demo": true}),
            8,
        );
        let _ = state.record_scenario_receipt(
            "demo-fast-private-transfer",
            ScenarioStatus::Passed,
            &label_hash("RPC-GATEWAY-DEMO", "operator"),
            &label_hash("RPC-GATEWAY-DEMO", "transcript"),
            &label_hash("RPC-GATEWAY-DEMO", "artifact"),
            9,
            12,
        );
        let _ = state.record_release_gate(
            "pq-session-auth",
            ReleaseGateStatus::Passing,
            &label_hash("RPC-GATEWAY-DEMO", "pq-evidence"),
            MAX_BPS,
            true,
        );
        let _ = state.snapshot_release_readiness(13, 9_000);
        state
    }

    pub fn register_default_routes(&mut self) -> Result<()> {
        let definitions = [
            (
                RouteKind::WalletPlans,
                AuthRequirement::SessionAndViewPolicy,
                true,
                true,
            ),
            (
                RouteKind::ScenarioReceipts,
                AuthRequirement::Operator,
                false,
                true,
            ),
            (
                RouteKind::ReleaseReadiness,
                AuthRequirement::Public,
                false,
                true,
            ),
            (
                RouteKind::ProgressFeed,
                AuthRequirement::Public,
                false,
                true,
            ),
            (
                RouteKind::PrivateTokenCall,
                AuthRequirement::SessionAndViewPolicy,
                true,
                true,
            ),
            (
                RouteKind::SmartContractCall,
                AuthRequirement::SessionAndViewPolicy,
                true,
                true,
            ),
            (
                RouteKind::MoneroBridgeCommand,
                AuthRequirement::SessionAndViewPolicy,
                true,
                true,
            ),
            (
                RouteKind::FeeSponsorshipQuote,
                AuthRequirement::Sponsor,
                true,
                true,
            ),
            (
                RouteKind::PqSessionAuth,
                AuthRequirement::Public,
                true,
                true,
            ),
            (
                RouteKind::ViewKeyDisclosure,
                AuthRequirement::Session,
                true,
                true,
            ),
            (
                RouteKind::LowFeeBatching,
                AuthRequirement::Session,
                true,
                true,
            ),
            (
                RouteKind::PreconfirmationStatus,
                AuthRequirement::Session,
                false,
                true,
            ),
            (RouteKind::PublicRoots, AuthRequirement::Public, false, true),
        ];
        for (kind, auth, private_payload_allowed, roots_only_allowed) in definitions {
            self.register_route(RouteRecord::new(
                kind,
                auth,
                private_payload_allowed,
                roots_only_allowed,
            ))?;
        }
        Ok(())
    }

    pub fn register_route(&mut self, route: RouteRecord) -> Result<()> {
        route.validate()?;
        if self.routes.len() >= self.config.max_routes && !self.routes.contains_key(&route.route_id)
        {
            return Err("route capacity exceeded".to_string());
        }
        let rate_policy = RatePolicy::for_route(&self.config, &route);
        self.routes_by_kind
            .insert(route.kind, route.route_id.clone());
        self.rate_policies
            .insert(rate_policy.policy_id.clone(), rate_policy);
        self.routes.insert(route.route_id.clone(), route);
        Ok(())
    }

    pub fn route_for_kind(&self, kind: RouteKind) -> Result<&RouteRecord> {
        let route_id = self
            .routes_by_kind
            .get(&kind)
            .ok_or_else(|| format!("route kind {} is not registered", kind.as_str()))?;
        self.routes
            .get(route_id)
            .ok_or_else(|| "route index points to missing route".to_string())
    }

    pub fn authorize_pq_session(
        &mut self,
        request: PqSessionAuthRequest,
    ) -> Result<PqSessionAuthRecord> {
        request.validate(&self.config)?;
        self.ensure_capacity(self.sessions.len(), self.config.max_sessions, "sessions")?;
        let record = PqSessionAuthRecord::new(&request);
        record.validate(&self.config)?;
        self.counters.sessions = self.counters.sessions.saturating_add(1);
        self.sessions
            .insert(record.session_id.clone(), record.clone());
        Ok(record)
    }

    pub fn plan_wallet_action(&mut self, request: WalletPlanRequest) -> Result<WalletPlanReceipt> {
        request.validate(&self.config)?;
        let route = self.route_for_kind(RouteKind::WalletPlans)?.clone();
        let envelope = self.accept_request(
            &route,
            &request.session_id,
            &request.account_commitment,
            &request.idempotency_key,
            &request.payload_hash(),
            "wallet_plan",
            request.height,
            RequestStatus::Planned,
        )?;
        let action_root = hash_json(
            "RPC-GATEWAY-WALLET-PLAN-ACTION",
            &json!({
                "plan_kind": request.plan_kind.as_str(),
                "target_commitment": request.target_commitment,
                "asset_id": request.asset_id,
                "amount_commitment": request.amount_commitment,
                "memo_ciphertext_hash": request.memo_ciphertext_hash,
                "batch_strategy": request.desired_batch_strategy.as_str(),
            }),
        );
        let fee_quote_id = deterministic_id(
            "RPC-GATEWAY-WALLET-PLAN-FEE-QUOTE-ID",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&action_root),
            ],
        );
        let disclosure_policy_id = deterministic_id(
            "RPC-GATEWAY-WALLET-PLAN-DISCLOSURE-ID",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&envelope.view_policy_root),
            ],
        );
        let batch_id = if request.desired_batch_strategy == BatchStrategy::None {
            String::new()
        } else {
            deterministic_id(
                "RPC-GATEWAY-WALLET-PLAN-BATCH-ID",
                &[
                    HashPart::Str(&envelope.request_id),
                    HashPart::Str(&action_root),
                ],
            )
        };
        let preconfirmation_id = self.create_preconfirmation(
            &envelope.request_id,
            &action_root,
            request
                .height
                .saturating_add(self.config.preconfirmation_ttl_blocks),
            request.height,
        )?;
        let plan_id = deterministic_id(
            "RPC-GATEWAY-WALLET-PLAN-ID",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&action_root),
            ],
        );
        let receipt = WalletPlanReceipt {
            plan_id: plan_id.clone(),
            request_id: envelope.request_id.clone(),
            plan_kind: request.plan_kind,
            account_commitment: request.account_commitment,
            action_root,
            fee_quote_id,
            disclosure_policy_id,
            batch_id,
            preconfirmation_id,
            created_at_height: request.height,
        };
        self.counters.wallet_plans = self.counters.wallet_plans.saturating_add(1);
        self.wallet_plans.insert(plan_id, receipt.clone());
        let response = self.response_for_record(
            &envelope,
            ResponseProfile::PublicSummary,
            200,
            &receipt.public_record(),
            request.height,
        );
        self.responses
            .insert(response.response_id.clone(), response);
        Ok(receipt)
    }

    pub fn submit_private_token_call(
        &mut self,
        request: PrivateTokenCallRequest,
    ) -> Result<ContractCallReceipt> {
        ensure_nonempty("session_id", &request.session_id)?;
        ensure_nonempty("account_commitment", &request.account_commitment)?;
        ensure_nonempty("token_id", &request.token_id)?;
        ensure_nonempty("function_selector", &request.function_selector)?;
        ensure_nonempty("encrypted_args_hash", &request.encrypted_args_hash)?;
        ensure_nonempty("value_commitment", &request.value_commitment)?;
        ensure_nonempty("fee_asset_id", &request.fee_asset_id)?;
        ensure_nonempty("idempotency_key", &request.idempotency_key)?;
        if request.fee_limit_units == 0 {
            return Err("private token call fee_limit_units must be nonzero".to_string());
        }
        let route = self.route_for_kind(RouteKind::PrivateTokenCall)?.clone();
        let payload_hash = hash_json("RPC-GATEWAY-PRIVATE-TOKEN-CALL-PAYLOAD", &json!(&request));
        let envelope = self.accept_request(
            &route,
            &request.session_id,
            &request.account_commitment,
            &request.idempotency_key,
            &payload_hash,
            "private_token_call",
            request.height,
            RequestStatus::Validated,
        )?;
        let call_root = hash_json(
            "RPC-GATEWAY-PRIVATE-TOKEN-CALL",
            &json!({
                "token_id": request.token_id,
                "function_selector": request.function_selector,
                "encrypted_args_hash": request.encrypted_args_hash,
                "value_commitment": request.value_commitment,
                "fee_asset_id": request.fee_asset_id,
                "fee_limit_units": request.fee_limit_units,
            }),
        );
        self.contract_call_receipt(
            envelope,
            request.account_commitment,
            request.token_id,
            call_root,
            request.encrypted_args_hash,
            request.height,
        )
    }

    pub fn submit_smart_contract_call(
        &mut self,
        request: SmartContractCallRequest,
    ) -> Result<ContractCallReceipt> {
        ensure_nonempty("session_id", &request.session_id)?;
        ensure_nonempty("account_commitment", &request.account_commitment)?;
        ensure_nonempty("contract_id", &request.contract_id)?;
        ensure_nonempty("method_selector", &request.method_selector)?;
        ensure_nonempty("calldata_hash", &request.calldata_hash)?;
        ensure_nonempty("witness_root", &request.witness_root)?;
        ensure_nonempty("fee_asset_id", &request.fee_asset_id)?;
        ensure_nonempty("idempotency_key", &request.idempotency_key)?;
        if request.calldata_size_bytes > self.config.max_calldata_bytes {
            return Err("smart contract calldata exceeds configured limit".to_string());
        }
        let route = self.route_for_kind(RouteKind::SmartContractCall)?.clone();
        let payload_hash = hash_json("RPC-GATEWAY-SMART-CONTRACT-CALL-PAYLOAD", &json!(&request));
        let envelope = self.accept_request(
            &route,
            &request.session_id,
            &request.account_commitment,
            &request.idempotency_key,
            &payload_hash,
            "smart_contract_call",
            request.height,
            RequestStatus::Validated,
        )?;
        let call_root = hash_json(
            "RPC-GATEWAY-SMART-CONTRACT-CALL",
            &json!({
                "contract_id": request.contract_id,
                "method_selector": request.method_selector,
                "calldata_hash": request.calldata_hash,
                "calldata_size_bytes": request.calldata_size_bytes,
                "witness_root": request.witness_root,
                "fee_asset_id": request.fee_asset_id,
                "fee_limit_units": request.fee_limit_units,
            }),
        );
        self.contract_call_receipt(
            envelope,
            request.account_commitment,
            request.contract_id,
            call_root,
            request.witness_root,
            request.height,
        )
    }

    pub fn submit_monero_bridge_command(
        &mut self,
        request: MoneroBridgeCommandRequest,
    ) -> Result<MoneroBridgeCommandReceipt> {
        ensure_nonempty("session_id", &request.session_id)?;
        ensure_nonempty("account_commitment", &request.account_commitment)?;
        ensure_nonempty(
            "bridge_account_commitment",
            &request.bridge_account_commitment,
        )?;
        ensure_nonempty("subaddress_commitment", &request.subaddress_commitment)?;
        ensure_nonempty("amount_commitment", &request.amount_commitment)?;
        ensure_nonempty("proof_root", &request.proof_root)?;
        ensure_nonempty("idempotency_key", &request.idempotency_key)?;
        let route = self.route_for_kind(RouteKind::MoneroBridgeCommand)?.clone();
        let payload_hash = hash_json(
            "RPC-GATEWAY-MONERO-BRIDGE-COMMAND-PAYLOAD",
            &json!(&request),
        );
        let envelope = self.accept_request(
            &route,
            &request.session_id,
            &request.account_commitment,
            &request.idempotency_key,
            &payload_hash,
            "monero_bridge_command",
            request.height,
            RequestStatus::Validated,
        )?;
        let command_root = hash_json(
            "RPC-GATEWAY-MONERO-BRIDGE-COMMAND",
            &json!({
                "command_kind": request.command_kind.as_str(),
                "bridge_account_commitment": request.bridge_account_commitment,
                "subaddress_commitment": request.subaddress_commitment,
                "amount_commitment": request.amount_commitment,
                "monero_txid_hash": request.monero_txid_hash,
                "proof_root": request.proof_root,
            }),
        );
        let watch_root = deterministic_id(
            "RPC-GATEWAY-MONERO-WATCH-ROOT",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&command_root),
            ],
        );
        let command_id = deterministic_id(
            "RPC-GATEWAY-MONERO-COMMAND-ID",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&command_root),
            ],
        );
        let receipt = MoneroBridgeCommandReceipt {
            command_id: command_id.clone(),
            request_id: envelope.request_id.clone(),
            command_kind: request.command_kind,
            bridge_account_commitment: request.bridge_account_commitment,
            command_root,
            proof_root: request.proof_root,
            watch_root,
            status: RequestStatus::Planned,
            produced_at_height: request.height,
        };
        self.counters.bridge_commands = self.counters.bridge_commands.saturating_add(1);
        self.monero_bridge_commands
            .insert(command_id, receipt.clone());
        let response = self.response_for_record(
            &envelope,
            ResponseProfile::PublicSummary,
            200,
            &receipt.public_record(),
            request.height,
        );
        self.responses
            .insert(response.response_id.clone(), response);
        Ok(receipt)
    }

    pub fn quote_fee_sponsorship(
        &mut self,
        request: FeeSponsorshipQuoteRequest,
    ) -> Result<FeeSponsorshipQuote> {
        if !self.config.allow_fee_sponsorship {
            return Err("fee sponsorship is disabled".to_string());
        }
        ensure_nonempty("session_id", &request.session_id)?;
        ensure_nonempty("account_commitment", &request.account_commitment)?;
        ensure_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        ensure_nonempty("action_root", &request.action_root)?;
        ensure_nonempty("fee_asset_id", &request.fee_asset_id)?;
        ensure_nonempty("idempotency_key", &request.idempotency_key)?;
        if request.max_fee_bps > self.config.sponsor_max_fee_bps {
            return Err("requested sponsor fee exceeds configured maximum".to_string());
        }
        let route = self.route_for_kind(RouteKind::FeeSponsorshipQuote)?.clone();
        let payload_hash = hash_json("RPC-GATEWAY-FEE-SPONSORSHIP-PAYLOAD", &json!(&request));
        let envelope = self.accept_request(
            &route,
            &request.session_id,
            &request.account_commitment,
            &request.idempotency_key,
            &payload_hash,
            "fee_sponsorship_quote",
            request.height,
            RequestStatus::Validated,
        )?;
        let sponsored_fee_units = request
            .estimated_fee_units
            .saturating_mul(u64::from(MAX_BPS.saturating_sub(request.max_fee_bps)))
            / u64::from(MAX_BPS);
        let quote_id = deterministic_id(
            "RPC-GATEWAY-FEE-SPONSORSHIP-QUOTE-ID",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&request.action_root),
            ],
        );
        let quote = FeeSponsorshipQuote {
            quote_id: quote_id.clone(),
            request_id: envelope.request_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            action_root: request.action_root,
            fee_asset_id: request.fee_asset_id,
            estimated_fee_units: request.estimated_fee_units,
            sponsored_fee_units,
            sponsor_fee_bps: request.max_fee_bps,
            expires_at_height: request
                .height
                .saturating_add(self.config.preconfirmation_ttl_blocks),
        };
        self.counters.fee_quotes = self.counters.fee_quotes.saturating_add(1);
        self.fee_quotes.insert(quote_id, quote.clone());
        let response = self.response_for_record(
            &envelope,
            ResponseProfile::PublicSummary,
            200,
            &quote.public_record(),
            request.height,
        );
        self.responses
            .insert(response.response_id.clone(), response);
        Ok(quote)
    }

    pub fn disclose_view_key(
        &mut self,
        request: ViewKeyDisclosureRequest,
    ) -> Result<ViewKeyDisclosureControl> {
        ensure_nonempty("session_id", &request.session_id)?;
        ensure_nonempty("account_commitment", &request.account_commitment)?;
        ensure_nonempty("view_key_commitment", &request.view_key_commitment)?;
        ensure_nonempty("recipient_commitment", &request.recipient_commitment)?;
        ensure_nonempty("idempotency_key", &request.idempotency_key)?;
        ensure_ordered_heights(
            request.disclosure_window_start_height,
            request.disclosure_window_end_height,
            "view key disclosure",
        )?;
        if request.label_set.len() > self.config.max_disclosure_labels {
            return Err("view key disclosure label set exceeds configured limit".to_string());
        }
        let route = self.route_for_kind(RouteKind::ViewKeyDisclosure)?.clone();
        let payload_hash = hash_json("RPC-GATEWAY-VIEW-DISCLOSURE-PAYLOAD", &json!(&request));
        let envelope = self.accept_request(
            &route,
            &request.session_id,
            &request.account_commitment,
            &request.idempotency_key,
            &payload_hash,
            "view_key_disclosure",
            request.height,
            RequestStatus::Validated,
        )?;
        let label_root = string_set_root("RPC-GATEWAY-VIEW-DISCLOSURE-LABELS", &request.label_set);
        let policy_root = hash_json(
            "RPC-GATEWAY-VIEW-DISCLOSURE-POLICY",
            &json!({
                "scope": request.disclosure_scope.as_str(),
                "recipient_commitment": request.recipient_commitment,
                "label_root": label_root,
                "start": request.disclosure_window_start_height,
                "end": request.disclosure_window_end_height,
            }),
        );
        let disclosure_id = deterministic_id(
            "RPC-GATEWAY-VIEW-DISCLOSURE-ID",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&policy_root),
            ],
        );
        let control = ViewKeyDisclosureControl {
            disclosure_id: disclosure_id.clone(),
            request_id: envelope.request_id.clone(),
            account_commitment: request.account_commitment,
            view_key_commitment: request.view_key_commitment,
            disclosure_scope: request.disclosure_scope,
            recipient_commitment: request.recipient_commitment,
            label_root,
            window_start_height: request.disclosure_window_start_height,
            window_end_height: request.disclosure_window_end_height,
            policy_root,
            revoked: false,
        };
        self.counters.disclosures = self.counters.disclosures.saturating_add(1);
        self.view_disclosures.insert(disclosure_id, control.clone());
        let response = self.response_for_record(
            &envelope,
            ResponseProfile::PublicSummary,
            200,
            &control.public_record(),
            request.height,
        );
        self.responses
            .insert(response.response_id.clone(), response);
        Ok(control)
    }

    pub fn create_low_fee_batch(
        &mut self,
        request: LowFeeBatchRequest,
    ) -> Result<LowFeeBatchReceipt> {
        if !self.config.allow_low_fee_batching {
            return Err("low fee batching is disabled".to_string());
        }
        ensure_nonempty("session_id", &request.session_id)?;
        ensure_nonempty("account_commitment", &request.account_commitment)?;
        ensure_nonempty("idempotency_key", &request.idempotency_key)?;
        if request.item_roots.is_empty() {
            return Err("low fee batch requires at least one item".to_string());
        }
        if request.item_roots.len() > self.config.max_batch_items {
            return Err("low fee batch exceeds configured max_batch_items".to_string());
        }
        if request.max_fee_bps > self.config.sponsor_max_fee_bps {
            return Err("low fee batch max_fee_bps exceeds sponsorship policy".to_string());
        }
        let route = self.route_for_kind(RouteKind::LowFeeBatching)?.clone();
        let payload_hash = hash_json("RPC-GATEWAY-LOW-FEE-BATCH-PAYLOAD", &json!(&request));
        let envelope = self.accept_request(
            &route,
            &request.session_id,
            &request.account_commitment,
            &request.idempotency_key,
            &payload_hash,
            "low_fee_batch",
            request.height,
            RequestStatus::Batched,
        )?;
        let item_root = string_slice_root("RPC-GATEWAY-LOW-FEE-BATCH-ITEMS", &request.item_roots);
        let batch_id = deterministic_id(
            "RPC-GATEWAY-LOW-FEE-BATCH-ID",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&item_root),
            ],
        );
        let fee_reduction_bps = self
            .config
            .low_fee_target_bps
            .saturating_add((request.item_roots.len() as u16).min(100));
        let receipt = LowFeeBatchReceipt {
            batch_id: batch_id.clone(),
            request_id: envelope.request_id.clone(),
            strategy: request.strategy,
            account_commitment: request.account_commitment,
            item_root,
            sponsor_commitment: request.sponsor_commitment,
            fee_reduction_bps,
            batch_weight: request.item_roots.len() as u64,
            status: RequestStatus::Batched,
            produced_at_height: request.height,
        };
        self.counters.batches = self.counters.batches.saturating_add(1);
        self.low_fee_batches.insert(batch_id, receipt.clone());
        let response = self.response_for_record(
            &envelope,
            ResponseProfile::PublicSummary,
            200,
            &receipt.public_record(),
            request.height,
        );
        self.responses
            .insert(response.response_id.clone(), response);
        Ok(receipt)
    }

    pub fn get_preconfirmation_status(
        &mut self,
        request: PreconfirmationStatusRequest,
    ) -> Result<PreconfirmationRecord> {
        ensure_nonempty("session_id", &request.session_id)?;
        ensure_nonempty("account_commitment", &request.account_commitment)?;
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("subject_root", &request.subject_root)?;
        ensure_nonempty("idempotency_key", &request.idempotency_key)?;
        let route = self
            .route_for_kind(RouteKind::PreconfirmationStatus)?
            .clone();
        let payload_hash = hash_json(
            "RPC-GATEWAY-PRECONFIRMATION-STATUS-PAYLOAD",
            &json!(&request),
        );
        let envelope = self.accept_request(
            &route,
            &request.session_id,
            &request.account_commitment,
            &request.idempotency_key,
            &payload_hash,
            "preconfirmation_status",
            request.height,
            RequestStatus::Accepted,
        )?;
        let existing = self
            .preconfirmations
            .values()
            .find(|record| record.subject_id == request.subject_id)
            .cloned();
        let record = existing.unwrap_or_else(|| PreconfirmationRecord {
            preconfirmation_id: deterministic_id(
                "RPC-GATEWAY-PRECONFIRMATION-LOOKUP-ID",
                &[
                    HashPart::Str(&request.subject_id),
                    HashPart::Str(&request.subject_root),
                ],
            ),
            subject_id: request.subject_id,
            subject_root: request.subject_root,
            status: PreconfirmationStatusKind::Unknown,
            quorum_root: merkle_root("RPC-GATEWAY-PRECONFIRMATION-EMPTY-QUORUM", &[]),
            expires_at_height: request.height,
            updated_at_height: request.height,
        });
        let response = self.response_for_record(
            &envelope,
            ResponseProfile::RootsOnly,
            200,
            &record.public_record(),
            request.height,
        );
        self.responses
            .insert(response.response_id.clone(), response);
        Ok(record)
    }

    pub fn record_scenario_receipt(
        &mut self,
        scenario_label: &str,
        status: ScenarioStatus,
        operator_commitment: &str,
        transcript_root: &str,
        artifact_root: &str,
        started_at_height: u64,
        completed_at_height: u64,
    ) -> Result<ScenarioReceipt> {
        ensure_nonempty("scenario_label", scenario_label)?;
        ensure_nonempty("operator_commitment", operator_commitment)?;
        ensure_nonempty("transcript_root", transcript_root)?;
        ensure_nonempty("artifact_root", artifact_root)?;
        ensure_ordered_heights(started_at_height, completed_at_height, "scenario receipt")?;
        self.ensure_capacity(
            self.scenario_receipts.len(),
            self.config.max_receipts,
            "scenario receipts",
        )?;
        let request_root = self.request_root();
        let response_root = self.response_root();
        let scenario_id = deterministic_id(
            "RPC-GATEWAY-SCENARIO-ID",
            &[
                HashPart::Str(scenario_label),
                HashPart::Str(operator_commitment),
                HashPart::Str(transcript_root),
                HashPart::Int(completed_at_height as i128),
            ],
        );
        let receipt = ScenarioReceipt {
            scenario_id: scenario_id.clone(),
            scenario_label: scenario_label.to_string(),
            status,
            operator_commitment: operator_commitment.to_string(),
            transcript_root: transcript_root.to_string(),
            artifact_root: artifact_root.to_string(),
            request_root,
            response_root,
            started_at_height,
            completed_at_height,
        };
        self.counters.scenario_receipts = self.counters.scenario_receipts.saturating_add(1);
        self.scenario_receipts.insert(scenario_id, receipt.clone());
        Ok(receipt)
    }

    pub fn record_release_gate(
        &mut self,
        label: &str,
        status: ReleaseGateStatus,
        evidence_root: &str,
        score_bps: u16,
        required: bool,
    ) -> Result<ReleaseReadinessGate> {
        ensure_nonempty("release gate label", label)?;
        ensure_nonempty("evidence_root", evidence_root)?;
        if score_bps > MAX_BPS {
            return Err("release gate score_bps exceeds MAX_BPS".to_string());
        }
        let gate_id = deterministic_id(
            "RPC-GATEWAY-RELEASE-GATE-ID",
            &[HashPart::Str(label), HashPart::Str(evidence_root)],
        );
        let gate = ReleaseReadinessGate {
            gate_id: gate_id.clone(),
            label: label.to_string(),
            status,
            evidence_root: evidence_root.to_string(),
            score_bps,
            required,
        };
        self.release_gates.insert(gate_id, gate.clone());
        Ok(gate)
    }

    pub fn snapshot_release_readiness(
        &mut self,
        height: u64,
        min_release_score_bps: u16,
    ) -> Result<ReleaseReadinessSnapshot> {
        if min_release_score_bps > MAX_BPS {
            return Err("min_release_score_bps exceeds MAX_BPS".to_string());
        }
        let gate_records = self
            .release_gates
            .values()
            .map(ReleaseReadinessGate::public_record)
            .collect::<Vec<_>>();
        let gate_root = merkle_root("RPC-GATEWAY-RELEASE-GATES", &gate_records);
        let scenario_root = self.scenario_receipt_root();
        let progress_root = self.progress_feed_root();
        let gate_count = self.release_gates.len() as u64;
        let aggregate_score_bps = if gate_count == 0 {
            0
        } else {
            let total = self.release_gates.values().fold(0_u64, |acc, gate| {
                acc.saturating_add(u64::from(gate.score_bps))
            });
            (total / gate_count).min(u64::from(MAX_BPS)) as u16
        };
        let required_gates_pass = self
            .release_gates
            .values()
            .filter(|gate| gate.required)
            .all(|gate| gate.status.releasable());
        let releasable = required_gates_pass && aggregate_score_bps >= min_release_score_bps;
        let snapshot_id = deterministic_id(
            "RPC-GATEWAY-RELEASE-SNAPSHOT-ID",
            &[
                HashPart::Str(&gate_root),
                HashPart::Str(&scenario_root),
                HashPart::Str(&progress_root),
                HashPart::Int(height as i128),
            ],
        );
        let snapshot = ReleaseReadinessSnapshot {
            snapshot_id: snapshot_id.clone(),
            height,
            min_release_score_bps,
            aggregate_score_bps,
            gate_root,
            scenario_root,
            progress_root,
            releasable,
        };
        self.counters.release_snapshots = self.counters.release_snapshots.saturating_add(1);
        self.release_snapshots.insert(snapshot_id, snapshot.clone());
        Ok(snapshot)
    }

    pub fn record_progress_event(
        &mut self,
        lane: &str,
        severity: ProgressSeverity,
        subject_root: &str,
        message: &str,
        metadata: &Value,
        height: u64,
    ) -> Result<ProgressFeedEvent> {
        ensure_nonempty("progress lane", lane)?;
        ensure_nonempty("subject_root", subject_root)?;
        ensure_nonempty("message", message)?;
        self.ensure_capacity(
            self.progress_events.len(),
            self.config.max_progress_events,
            "progress events",
        )?;
        let sequence = self.counters.progress_events.saturating_add(1);
        let metadata_root = hash_json("RPC-GATEWAY-PROGRESS-METADATA", metadata);
        let message_hash = label_hash("RPC-GATEWAY-PROGRESS-MESSAGE", message);
        let event_id = deterministic_id(
            "RPC-GATEWAY-PROGRESS-EVENT-ID",
            &[
                HashPart::Str(lane),
                HashPart::Str(subject_root),
                HashPart::Str(&message_hash),
                HashPart::Int(height as i128),
                HashPart::Int(sequence as i128),
            ],
        );
        let event = ProgressFeedEvent {
            event_id: event_id.clone(),
            lane: lane.to_string(),
            severity,
            subject_root: subject_root.to_string(),
            message_hash,
            metadata_root,
            emitted_at_height: height,
            sequence,
        };
        self.counters.progress_events = sequence;
        self.progress_events.insert(event_id, event.clone());
        Ok(event)
    }

    pub fn progress_snapshot(&self, height: u64) -> ProgressFeedSnapshot {
        let mut lanes = BTreeSet::new();
        let mut severities = BTreeSet::new();
        for event in self.progress_events.values() {
            lanes.insert(event.lane.clone());
            severities.insert(event.severity.as_str().to_string());
        }
        let event_root = self.progress_feed_root();
        let lane_root = string_set_root("RPC-GATEWAY-PROGRESS-LANES", &lanes);
        let severity_root = string_set_root("RPC-GATEWAY-PROGRESS-SEVERITIES", &severities);
        let cursor = self.counters.progress_events;
        let snapshot_id = deterministic_id(
            "RPC-GATEWAY-PROGRESS-SNAPSHOT-ID",
            &[
                HashPart::Str(&event_root),
                HashPart::Str(&lane_root),
                HashPart::Str(&severity_root),
                HashPart::Int(height as i128),
                HashPart::Int(cursor as i128),
            ],
        );
        ProgressFeedSnapshot {
            snapshot_id,
            height,
            cursor,
            event_root,
            lane_root,
            severity_root,
        }
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.root(),
            route_registry_root: self.route_registry_root(),
            rate_policy_root: self.rate_policy_root(),
            rate_window_root: self.rate_window_root(),
            fee_policy_root: self.fee_policy.root(),
            session_root: self.session_root(),
            request_root: self.request_root(),
            response_root: self.response_root(),
            wallet_plan_root: self.wallet_plan_root(),
            scenario_receipt_root: self.scenario_receipt_root(),
            release_readiness_root: self.release_readiness_root(),
            progress_feed_root: self.progress_feed_root(),
            contract_call_root: self.contract_call_root(),
            monero_bridge_command_root: self.monero_bridge_command_root(),
            fee_quote_root: self.fee_quote_root(),
            view_disclosure_root: self.view_disclosure_root(),
            low_fee_batch_root: self.low_fee_batch_root(),
            preconfirmation_root: self.preconfirmation_root(),
            counter_root: self.counters.root(),
            state_root: String::new(),
        };
        roots.state_root = domain_hash(
            "RPC-GATEWAY-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&roots.config_root),
                HashPart::Str(&roots.route_registry_root),
                HashPart::Str(&roots.rate_policy_root),
                HashPart::Str(&roots.rate_window_root),
                HashPart::Str(&roots.fee_policy_root),
                HashPart::Str(&roots.session_root),
                HashPart::Str(&roots.request_root),
                HashPart::Str(&roots.response_root),
                HashPart::Str(&roots.wallet_plan_root),
                HashPart::Str(&roots.scenario_receipt_root),
                HashPart::Str(&roots.release_readiness_root),
                HashPart::Str(&roots.progress_feed_root),
                HashPart::Str(&roots.contract_call_root),
                HashPart::Str(&roots.monero_bridge_command_root),
                HashPart::Str(&roots.fee_quote_root),
                HashPart::Str(&roots.view_disclosure_root),
                HashPart::Str(&roots.low_fee_batch_root),
                HashPart::Str(&roots.preconfirmation_root),
                HashPart::Str(&roots.counter_root),
            ],
            32,
        );
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "fee_policy": self.fee_policy.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn roots_only_public_response(&self, height: u64) -> Value {
        self.roots().roots_only_response(height)
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        for route in self.routes.values() {
            route.validate()?;
        }
        for session in self.sessions.values() {
            session.validate(&self.config)?;
        }
        if self.routes.len() > self.config.max_routes {
            return Err("route registry exceeds configured capacity".to_string());
        }
        if self.sessions.len() > self.config.max_sessions {
            return Err("session registry exceeds configured capacity".to_string());
        }
        if self.requests.len() > self.config.max_receipts
            || self.responses.len() > self.config.max_receipts
        {
            return Err("request or response receipts exceed configured capacity".to_string());
        }
        Ok(())
    }

    fn accept_request(
        &mut self,
        route: &RouteRecord,
        session_id: &str,
        client_account_commitment: &str,
        idempotency_key: &str,
        payload_hash: &str,
        payload_kind: &str,
        height: u64,
        status: RequestStatus,
    ) -> Result<GatewayRequestEnvelope> {
        self.ensure_capacity(self.requests.len(), self.config.max_receipts, "requests")?;
        ensure_nonempty("route_id", &route.route_id)?;
        ensure_nonempty("client_account_commitment", client_account_commitment)?;
        ensure_nonempty("idempotency_key", idempotency_key)?;
        ensure_nonempty("payload_hash", payload_hash)?;
        if route.auth_requirement != AuthRequirement::Public {
            self.ensure_session_authorized(session_id, height)?;
        }
        self.apply_rate_limit(route, client_account_commitment, height)?;
        let idempotency_key_hash = label_hash("RPC-GATEWAY-IDEMPOTENCY-KEY", idempotency_key);
        let authorization_root =
            self.authorization_root(route, session_id, client_account_commitment);
        let view_policy_root = self
            .sessions
            .get(session_id)
            .map(|session| session.view_policy_root.clone())
            .unwrap_or_else(|| merkle_root("RPC-GATEWAY-EMPTY-VIEW-POLICY", &[]));
        let request_id = request_id(
            &route.route_id,
            session_id,
            client_account_commitment,
            &idempotency_key_hash,
            payload_hash,
            &authorization_root,
            height,
        );
        let envelope = GatewayRequestEnvelope {
            request_id: request_id.clone(),
            route_id: route.route_id.clone(),
            route_kind: route.kind,
            session_id: session_id.to_string(),
            client_account_commitment: client_account_commitment.to_string(),
            idempotency_key_hash,
            payload_hash: payload_hash.to_string(),
            payload_kind: payload_kind.to_string(),
            payload_size_bytes: payload_hash.len() as u32,
            authorization_root,
            view_policy_root,
            received_at_height: height,
            status,
        };
        self.counters.requests = self.counters.requests.saturating_add(1);
        self.requests.insert(request_id, envelope.clone());
        Ok(envelope)
    }

    fn ensure_session_authorized(&self, session_id: &str, height: u64) -> Result<()> {
        ensure_nonempty("session_id", session_id)?;
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| "missing pq session".to_string())?;
        if !session.active_at(height) {
            return Err("pq session is inactive at requested height".to_string());
        }
        Ok(())
    }

    fn apply_rate_limit(
        &mut self,
        route: &RouteRecord,
        subject_commitment: &str,
        height: u64,
    ) -> Result<()> {
        let policy = self
            .rate_policies
            .get(&route.rate_policy_id)
            .ok_or_else(|| "missing rate policy".to_string())?
            .clone();
        let window_start = if policy.window_blocks == 0 {
            height
        } else {
            height.saturating_sub(height % policy.window_blocks)
        };
        let window_end = window_start.saturating_add(policy.window_blocks);
        let window_id = rate_window_id(
            &policy.policy_id,
            subject_commitment,
            &route.route_id,
            window_start,
            window_end,
        );
        let count = self
            .rate_windows
            .get(&window_id)
            .map(|window| window.request_count)
            .unwrap_or(0);
        if count >= policy.max_requests {
            self.counters.rate_limited_requests =
                self.counters.rate_limited_requests.saturating_add(1);
            return Err("rate limit exceeded".to_string());
        }
        let next = RateWindow {
            window_id: window_id.clone(),
            policy_id: policy.policy_id,
            subject_commitment: subject_commitment.to_string(),
            route_id: route.route_id.clone(),
            window_start_height: window_start,
            window_end_height: window_end,
            request_count: count.saturating_add(1),
        };
        self.rate_windows.insert(window_id, next);
        Ok(())
    }

    fn authorization_root(
        &self,
        route: &RouteRecord,
        session_id: &str,
        client_account_commitment: &str,
    ) -> String {
        let session_root = self
            .sessions
            .get(session_id)
            .map(PqSessionAuthRecord::root)
            .unwrap_or_else(|| merkle_root("RPC-GATEWAY-PUBLIC-AUTH", &[]));
        domain_hash(
            "RPC-GATEWAY-AUTHORIZATION-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&route.route_id),
                HashPart::Str(route.auth_requirement.as_str()),
                HashPart::Str(session_id),
                HashPart::Str(client_account_commitment),
                HashPart::Str(&session_root),
            ],
            32,
        )
    }

    fn response_for_record(
        &mut self,
        request: &GatewayRequestEnvelope,
        profile: ResponseProfile,
        status_code: u16,
        payload: &Value,
        height: u64,
    ) -> GatewayResponseEnvelope {
        let public_root = hash_json("RPC-GATEWAY-RESPONSE-PUBLIC-PAYLOAD", payload);
        let private_envelope_root = if profile == ResponseProfile::PrivateEnvelope {
            public_root.clone()
        } else {
            merkle_root("RPC-GATEWAY-EMPTY-PRIVATE-ENVELOPE", &[])
        };
        let response_payload_hash = hash_json("RPC-GATEWAY-RESPONSE-PAYLOAD", payload);
        let error_code_hash = if status_code < 400 {
            String::new()
        } else {
            label_hash("RPC-GATEWAY-ERROR-CODE", "gateway_error")
        };
        let response_id = response_id(
            &request.request_id,
            status_code,
            &response_payload_hash,
            &error_code_hash,
            height,
        );
        self.counters.responses = self.counters.responses.saturating_add(1);
        GatewayResponseEnvelope {
            response_id,
            request_id: request.request_id.clone(),
            route_id: request.route_id.clone(),
            profile,
            status_code,
            response_payload_hash,
            public_root,
            private_envelope_root,
            error_code_hash,
            produced_at_height: height,
        }
    }

    fn contract_call_receipt(
        &mut self,
        envelope: GatewayRequestEnvelope,
        account_commitment: String,
        target_id: String,
        call_root: String,
        witness_root: String,
        height: u64,
    ) -> Result<ContractCallReceipt> {
        let fee_quote_id = deterministic_id(
            "RPC-GATEWAY-CONTRACT-CALL-FEE-QUOTE-ID",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&call_root),
            ],
        );
        let preconfirmation_id = self.create_preconfirmation(
            &envelope.request_id,
            &call_root,
            height.saturating_add(self.config.preconfirmation_ttl_blocks),
            height,
        )?;
        let call_id = deterministic_id(
            "RPC-GATEWAY-CONTRACT-CALL-ID",
            &[
                HashPart::Str(&envelope.request_id),
                HashPart::Str(&call_root),
            ],
        );
        let receipt = ContractCallReceipt {
            call_id: call_id.clone(),
            request_id: envelope.request_id.clone(),
            account_commitment,
            target_id,
            call_root,
            witness_root,
            fee_quote_id,
            preconfirmation_id,
            status: RequestStatus::Preconfirmed,
            produced_at_height: height,
        };
        self.counters.contract_calls = self.counters.contract_calls.saturating_add(1);
        self.contract_calls.insert(call_id, receipt.clone());
        let response = self.response_for_record(
            &envelope,
            ResponseProfile::PublicSummary,
            200,
            &receipt.public_record(),
            height,
        );
        self.responses
            .insert(response.response_id.clone(), response);
        Ok(receipt)
    }

    fn create_preconfirmation(
        &mut self,
        subject_id: &str,
        subject_root: &str,
        expires_at_height: u64,
        updated_at_height: u64,
    ) -> Result<String> {
        ensure_nonempty("preconfirmation subject_id", subject_id)?;
        ensure_nonempty("preconfirmation subject_root", subject_root)?;
        let quorum_root = domain_hash(
            "RPC-GATEWAY-PRECONFIRMATION-QUORUM",
            &[
                HashPart::Str(subject_id),
                HashPart::Str(subject_root),
                HashPart::Int(expires_at_height as i128),
            ],
            32,
        );
        let preconfirmation_id = deterministic_id(
            "RPC-GATEWAY-PRECONFIRMATION-ID",
            &[HashPart::Str(subject_id), HashPart::Str(subject_root)],
        );
        let record = PreconfirmationRecord {
            preconfirmation_id: preconfirmation_id.clone(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            status: PreconfirmationStatusKind::SoftLocked,
            quorum_root,
            expires_at_height,
            updated_at_height,
        };
        self.counters.preconfirmations = self.counters.preconfirmations.saturating_add(1);
        self.preconfirmations
            .insert(preconfirmation_id.clone(), record);
        Ok(preconfirmation_id)
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            Err(format!("{label} capacity exceeded"))
        } else {
            Ok(())
        }
    }

    pub fn route_registry_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-ROUTE-REGISTRY",
            self.routes
                .values()
                .map(RouteRecord::public_record)
                .collect(),
        )
    }

    pub fn rate_policy_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-RATE-POLICIES",
            self.rate_policies
                .values()
                .map(RatePolicy::public_record)
                .collect(),
        )
    }

    pub fn rate_window_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-RATE-WINDOWS",
            self.rate_windows
                .values()
                .map(RateWindow::public_record)
                .collect(),
        )
    }

    pub fn session_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-SESSIONS",
            self.sessions
                .values()
                .map(PqSessionAuthRecord::public_record)
                .collect(),
        )
    }

    pub fn request_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-REQUESTS",
            self.requests
                .values()
                .map(GatewayRequestEnvelope::public_record)
                .collect(),
        )
    }

    pub fn response_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-RESPONSES",
            self.responses
                .values()
                .map(GatewayResponseEnvelope::public_record)
                .collect(),
        )
    }

    pub fn wallet_plan_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-WALLET-PLANS",
            self.wallet_plans
                .values()
                .map(WalletPlanReceipt::public_record)
                .collect(),
        )
    }

    pub fn scenario_receipt_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-SCENARIO-RECEIPTS",
            self.scenario_receipts
                .values()
                .map(ScenarioReceipt::public_record)
                .collect(),
        )
    }

    pub fn release_readiness_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-RELEASE-SNAPSHOTS",
            self.release_snapshots
                .values()
                .map(ReleaseReadinessSnapshot::public_record)
                .collect(),
        )
    }

    pub fn progress_feed_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-PROGRESS-FEED",
            self.progress_events
                .values()
                .map(ProgressFeedEvent::public_record)
                .collect(),
        )
    }

    pub fn contract_call_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-CONTRACT-CALLS",
            self.contract_calls
                .values()
                .map(ContractCallReceipt::public_record)
                .collect(),
        )
    }

    pub fn monero_bridge_command_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-MONERO-BRIDGE-COMMANDS",
            self.monero_bridge_commands
                .values()
                .map(MoneroBridgeCommandReceipt::public_record)
                .collect(),
        )
    }

    pub fn fee_quote_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-FEE-QUOTES",
            self.fee_quotes
                .values()
                .map(FeeSponsorshipQuote::public_record)
                .collect(),
        )
    }

    pub fn view_disclosure_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-VIEW-DISCLOSURES",
            self.view_disclosures
                .values()
                .map(ViewKeyDisclosureControl::public_record)
                .collect(),
        )
    }

    pub fn low_fee_batch_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-LOW-FEE-BATCHES",
            self.low_fee_batches
                .values()
                .map(LowFeeBatchReceipt::public_record)
                .collect(),
        )
    }

    pub fn preconfirmation_root(&self) -> String {
        map_root(
            "RPC-GATEWAY-PRECONFIRMATIONS",
            self.preconfirmations
                .values()
                .map(PreconfirmationRecord::public_record)
                .collect(),
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet_gateway_runtime() -> State {
    State::devnet()
}

pub fn demo_gateway_runtime() -> State {
    State::demo()
}

pub fn route_capability_root(
    kind: RouteKind,
    auth_requirement: AuthRequirement,
    request_schema_root: &str,
    response_schema_root: &str,
    private_payload_allowed: bool,
    roots_only_allowed: bool,
) -> String {
    domain_hash(
        "RPC-GATEWAY-ROUTE-CAPABILITY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(auth_requirement.as_str()),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(if private_payload_allowed {
                "private"
            } else {
                "public"
            }),
            HashPart::Str(if roots_only_allowed { "roots" } else { "full" }),
        ],
        32,
    )
}

pub fn route_id(method: &str, path: &str, kind: RouteKind, capability_root: &str) -> String {
    domain_hash(
        "RPC-GATEWAY-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(method),
            HashPart::Str(path),
            HashPart::Str(kind.as_str()),
            HashPart::Str(capability_root),
        ],
        32,
    )
}

pub fn session_id(
    client_account_commitment: &str,
    wallet_device_commitment: &str,
    operator_commitment: &str,
    kem_ciphertext_hash: &str,
    pq_signature_root: &str,
    allowed_route_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "RPC-GATEWAY-SESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(client_account_commitment),
            HashPart::Str(wallet_device_commitment),
            HashPart::Str(operator_commitment),
            HashPart::Str(kem_ciphertext_hash),
            HashPart::Str(pq_signature_root),
            HashPart::Str(allowed_route_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn request_id(
    route_id: &str,
    session_id: &str,
    client_account_commitment: &str,
    idempotency_key_hash: &str,
    payload_hash: &str,
    authorization_root: &str,
    received_at_height: u64,
) -> String {
    domain_hash(
        "RPC-GATEWAY-REQUEST-ID",
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

pub fn response_id(
    request_id: &str,
    status_code: u16,
    response_payload_hash: &str,
    error_code_hash: &str,
    produced_at_height: u64,
) -> String {
    domain_hash(
        "RPC-GATEWAY-RESPONSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_id),
            HashPart::Int(status_code as i128),
            HashPart::Str(response_payload_hash),
            HashPart::Str(error_code_hash),
            HashPart::Int(produced_at_height as i128),
        ],
        32,
    )
}

pub fn rate_window_id(
    policy_id: &str,
    subject_commitment: &str,
    route_id: &str,
    window_start_height: u64,
    window_end_height: u64,
) -> String {
    domain_hash(
        "RPC-GATEWAY-RATE-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(subject_commitment),
            HashPart::Str(route_id),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
        ],
        32,
    )
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn label_hash(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn hash_json(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

pub fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn string_slice_root(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_heights(start: u64, end: u64, label: &str) -> Result<()> {
    if start > end {
        Err(format!("{label} start height must be <= end height"))
    } else {
        Ok(())
    }
}
