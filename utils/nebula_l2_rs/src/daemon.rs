use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    api::{
        ApiControlPlaneState, ApiRateLimitBucket, ApiRequestEnvelope, ApiResponseEnvelope,
        ApiRouteKind, ApiRouteRecord, ApiSessionRecord, DEFAULT_API_RATE_LIMIT_WINDOW_BLOCKS,
    },
    crypto_policy::{
        crypto_policy_root, sign_network_authorization, verify_network_authorization, Authorization,
    },
    fees::{FeeSmoothingState, LowFeeLane},
    hash::{domain_hash, merkle_root, HashPart},
    node::{
        node_component_root, NebulaNode, NodeCommandReceipt, NodeConfig, NodeHealthReport,
        NodeLifecycleEvent, NodeRole,
    },
    sequencer::{SequencerBlockSummary, SequencerConfig},
    storage::{
        StorageBounds, StorageCheckpointRecord, StorageChunkRecord, StorageComponentRoots,
        StorageRestorePlan, StorageRetentionDecision, StorageServiceRoots, StorageSnapshotRecord,
        StorageState,
    },
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type DaemonResult<T> = Result<T, String>;

pub const DAEMON_PROTOCOL_VERSION: &str = "nebula-l2-daemon-v1";
pub const DAEMON_DEFAULT_SESSION_TTL_BLOCKS: u64 = 1_000;
pub const DAEMON_DEFAULT_REQUEST_TTL_BLOCKS: u64 = 20;
pub const DAEMON_DEFAULT_MAX_RESPONSE_BYTES: u64 = 256 * 1024;
pub const DAEMON_DEFAULT_STORAGE_CHUNK_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DaemonMode {
    Sequencer,
    Validator,
    Archive,
    Watchtower,
    WalletRpc,
    Devnet,
}

impl DaemonMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Validator => "validator",
            Self::Archive => "archive",
            Self::Watchtower => "watchtower",
            Self::WalletRpc => "wallet_rpc",
            Self::Devnet => "devnet",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub daemon_id: String,
    pub operator_label: String,
    pub mode: DaemonMode,
    pub node_config: NodeConfig,
    pub api_bind_commitment: String,
    pub storage_policy_commitment: String,
    pub api_session_ttl_blocks: u64,
    pub api_request_ttl_blocks: u64,
    pub api_rate_limit_window_blocks: u64,
    pub api_rate_limit_units: u64,
    pub max_api_response_bytes: u64,
    pub storage_snapshot_interval_blocks: u64,
    pub storage_chunk_target_bytes: u64,
    pub privacy_payload_policy: String,
}

impl DaemonConfig {
    pub fn devnet(operator_label: impl Into<String>, roles: Vec<NodeRole>) -> DaemonResult<Self> {
        let operator_label = operator_label.into();
        let node_config = NodeConfig::new(operator_label.clone(), roles)?;
        Ok(Self::new(operator_label, DaemonMode::Devnet, node_config))
    }

    pub fn new(
        operator_label: impl Into<String>,
        mode: DaemonMode,
        node_config: NodeConfig,
    ) -> Self {
        let operator_label = operator_label.into();
        let api_bind_commitment = domain_hash(
            "DAEMON-API-BIND-COMMITMENT",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(&operator_label)],
            32,
        );
        let storage_policy_commitment = domain_hash(
            "DAEMON-STORAGE-POLICY-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&operator_label),
                HashPart::Str(mode.as_str()),
            ],
            32,
        );
        let daemon_id = daemon_id(
            &operator_label,
            mode.as_str(),
            &node_config.node_id,
            &api_bind_commitment,
            &storage_policy_commitment,
        );
        Self {
            daemon_id,
            operator_label,
            mode,
            node_config,
            api_bind_commitment,
            storage_policy_commitment,
            api_session_ttl_blocks: DAEMON_DEFAULT_SESSION_TTL_BLOCKS,
            api_request_ttl_blocks: DAEMON_DEFAULT_REQUEST_TTL_BLOCKS,
            api_rate_limit_window_blocks: DEFAULT_API_RATE_LIMIT_WINDOW_BLOCKS,
            api_rate_limit_units: 1_000,
            max_api_response_bytes: DAEMON_DEFAULT_MAX_RESPONSE_BYTES,
            storage_snapshot_interval_blocks: 20,
            storage_chunk_target_bytes: DAEMON_DEFAULT_STORAGE_CHUNK_BYTES,
            privacy_payload_policy: "hash_only".to_string(),
        }
    }

    pub fn with_storage_interval(mut self, interval_blocks: u64) -> Self {
        self.storage_snapshot_interval_blocks = interval_blocks.max(1);
        self
    }

    pub fn with_api_limits(
        mut self,
        session_ttl_blocks: u64,
        request_ttl_blocks: u64,
        rate_limit_units: u64,
        max_response_bytes: u64,
    ) -> Self {
        self.api_session_ttl_blocks = session_ttl_blocks.max(1);
        self.api_request_ttl_blocks = request_ttl_blocks.max(1);
        self.api_rate_limit_units = rate_limit_units.max(1);
        self.max_api_response_bytes = max_response_bytes.max(1);
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "daemon_config",
            "chain_id": CHAIN_ID,
            "daemon_protocol_version": DAEMON_PROTOCOL_VERSION,
            "daemon_id": self.daemon_id,
            "operator_label": self.operator_label,
            "mode": self.mode.as_str(),
            "node_config_root": self.node_config.config_root(),
            "node_id": self.node_config.node_id,
            "api_bind_commitment": self.api_bind_commitment,
            "storage_policy_commitment": self.storage_policy_commitment,
            "api_session_ttl_blocks": self.api_session_ttl_blocks,
            "api_request_ttl_blocks": self.api_request_ttl_blocks,
            "api_rate_limit_window_blocks": self.api_rate_limit_window_blocks,
            "api_rate_limit_units": self.api_rate_limit_units,
            "max_api_response_bytes": self.max_api_response_bytes,
            "storage_snapshot_interval_blocks": self.storage_snapshot_interval_blocks,
            "storage_chunk_target_bytes": self.storage_chunk_target_bytes,
            "privacy_payload_policy": self.privacy_payload_policy,
            "crypto_policy_root": crypto_policy_root(),
        })
    }

    pub fn config_root(&self) -> String {
        daemon_config_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonOperationReceipt {
    pub receipt_id: String,
    pub daemon_id: String,
    pub node_id: String,
    pub operation_kind: String,
    pub height: u64,
    pub timestamp_ms: u64,
    pub request_root: String,
    pub response_root: String,
    pub pre_daemon_root: String,
    pub post_daemon_root: String,
    pub status: String,
    pub authorization: Authorization,
}

impl DaemonOperationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &DaemonConfig,
        operation_kind: &str,
        height: u64,
        timestamp_ms: u64,
        request: &Value,
        response: &Value,
        pre_daemon_root: &str,
        post_daemon_root: &str,
        status: &str,
    ) -> Self {
        let request_root = daemon_payload_root("DAEMON-OPERATION-REQUEST", request);
        let response_root = daemon_payload_root("DAEMON-OPERATION-RESPONSE", response);
        let receipt_id = daemon_operation_receipt_id(
            &config.daemon_id,
            operation_kind,
            height,
            &request_root,
            &response_root,
            pre_daemon_root,
            post_daemon_root,
        );
        let mut receipt = Self {
            receipt_id,
            daemon_id: config.daemon_id.clone(),
            node_id: config.node_config.node_id.clone(),
            operation_kind: operation_kind.to_string(),
            height,
            timestamp_ms,
            request_root,
            response_root,
            pre_daemon_root: pre_daemon_root.to_string(),
            post_daemon_root: post_daemon_root.to_string(),
            status: status.to_string(),
            authorization: empty_daemon_authorization(&config.operator_label),
        };
        receipt.authorization = sign_network_authorization(
            &config.operator_label,
            "daemon_operation_receipt",
            &receipt.unsigned_record(),
        );
        receipt
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "daemon_operation_receipt",
            "chain_id": CHAIN_ID,
            "daemon_protocol_version": DAEMON_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "daemon_id": self.daemon_id,
            "node_id": self.node_id,
            "operation_kind": self.operation_kind,
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "request_root": self.request_root,
            "response_root": self.response_root,
            "pre_daemon_root": self.pre_daemon_root,
            "post_daemon_root": self.post_daemon_root,
            "status": self.status,
        })
    }

    pub fn verify_authorization(&self) -> bool {
        verify_network_authorization(
            &self.authorization.auth_public_key,
            "daemon_operation_receipt",
            &self.unsigned_record(),
            &self.authorization,
        )
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "DAEMON-OPERATION-RECEIPT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("daemon operation receipt public record object");
        object.insert(
            "receipt_root".to_string(),
            Value::String(self.receipt_root()),
        );
        insert_daemon_authorization(object, &self.authorization);
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonApiExchange {
    pub exchange_id: String,
    pub request_id: String,
    pub response_id: Option<String>,
    pub route_id: String,
    pub route_kind: ApiRouteKind,
    pub status_code: Option<u16>,
    pub request_payload_root: String,
    pub response_payload_root: Option<String>,
    pub received_at_height: u64,
    pub completed_at_height: Option<u64>,
}

impl DaemonApiExchange {
    pub fn open(request: &ApiRequestEnvelope, request_payload: &Value) -> Self {
        let request_payload_root =
            daemon_payload_root("DAEMON-API-REQUEST-PAYLOAD", request_payload);
        let exchange_id = daemon_api_exchange_id(
            &request.request_id,
            "",
            &request.route_id,
            &request_payload_root,
        );
        Self {
            exchange_id,
            request_id: request.request_id.clone(),
            response_id: None,
            route_id: request.route_id.clone(),
            route_kind: request.route_kind.clone(),
            status_code: None,
            request_payload_root,
            response_payload_root: None,
            received_at_height: request.received_at_height,
            completed_at_height: None,
        }
    }

    pub fn complete(&mut self, response: &ApiResponseEnvelope, response_payload: &Value) {
        let response_payload_root =
            daemon_payload_root("DAEMON-API-RESPONSE-PAYLOAD", response_payload);
        self.exchange_id = daemon_api_exchange_id(
            &self.request_id,
            &response.response_id,
            &self.route_id,
            &response_payload_root,
        );
        self.response_id = Some(response.response_id.clone());
        self.status_code = Some(response.status_code);
        self.response_payload_root = Some(response_payload_root);
        self.completed_at_height = Some(response.produced_at_height);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "daemon_api_exchange",
            "chain_id": CHAIN_ID,
            "daemon_protocol_version": DAEMON_PROTOCOL_VERSION,
            "exchange_id": self.exchange_id,
            "request_id": self.request_id,
            "response_id": self.response_id,
            "route_id": self.route_id,
            "route_kind": self.route_kind.as_str(),
            "status_code": self.status_code,
            "request_payload_root": self.request_payload_root,
            "response_payload_root": self.response_payload_root,
            "received_at_height": self.received_at_height,
            "completed_at_height": self.completed_at_height,
        })
    }

    pub fn exchange_root(&self) -> String {
        domain_hash(
            "DAEMON-API-EXCHANGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStorageCommit {
    pub commit_id: String,
    pub snapshot_id: String,
    pub checkpoint_id: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub manifest_root: String,
    pub chunk_root: String,
    pub snapshot_root: String,
    pub checkpoint_root: String,
    pub created_at_ms: u64,
}

impl DaemonStorageCommit {
    pub fn from_records(
        snapshot: &StorageSnapshotRecord,
        checkpoint: &StorageCheckpointRecord,
        manifest_root: &str,
    ) -> Self {
        let commit_id = daemon_storage_commit_id(
            &snapshot.snapshot_id,
            &checkpoint.checkpoint_id,
            snapshot.block_height,
            &snapshot.state_root,
            manifest_root,
        );
        Self {
            commit_id,
            snapshot_id: snapshot.snapshot_id.clone(),
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            block_height: snapshot.block_height,
            block_hash: snapshot.block_hash.clone(),
            state_root: snapshot.state_root.clone(),
            manifest_root: manifest_root.to_string(),
            chunk_root: snapshot.chunk_root.clone(),
            snapshot_root: snapshot.snapshot_root(),
            checkpoint_root: checkpoint.checkpoint_root(),
            created_at_ms: checkpoint.created_at_ms,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "daemon_storage_commit",
            "chain_id": CHAIN_ID,
            "daemon_protocol_version": DAEMON_PROTOCOL_VERSION,
            "commit_id": self.commit_id,
            "snapshot_id": self.snapshot_id,
            "checkpoint_id": self.checkpoint_id,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "state_root": self.state_root,
            "manifest_root": self.manifest_root,
            "chunk_root": self.chunk_root,
            "snapshot_root": self.snapshot_root,
            "checkpoint_root": self.checkpoint_root,
            "created_at_ms": self.created_at_ms,
        })
    }

    pub fn commit_root(&self) -> String {
        domain_hash(
            "DAEMON-STORAGE-COMMIT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonHealthSnapshot {
    pub health_id: String,
    pub daemon_id: String,
    pub node_health_report_id: String,
    pub height: u64,
    pub timestamp_ms: u64,
    pub daemon_state_root: String,
    pub node_state_root: String,
    pub api_state_root: String,
    pub storage_manifest_root: String,
    pub operation_receipt_root: String,
    pub api_exchange_root: String,
    pub storage_commit_root: String,
    pub status: String,
}

impl DaemonHealthSnapshot {
    pub fn new(
        config: &DaemonConfig,
        node_health: &NodeHealthReport,
        daemon_state_root: &str,
        node_state_root: &str,
        api_state_root: &str,
        storage_manifest_root: &str,
        operation_receipt_root: &str,
        api_exchange_root: &str,
        storage_commit_root: &str,
        status: &str,
    ) -> Self {
        let health_id = daemon_health_snapshot_id(
            &config.daemon_id,
            node_health.height,
            daemon_state_root,
            node_state_root,
            api_state_root,
            storage_manifest_root,
        );
        Self {
            health_id,
            daemon_id: config.daemon_id.clone(),
            node_health_report_id: node_health.report_id.clone(),
            height: node_health.height,
            timestamp_ms: node_health.timestamp_ms,
            daemon_state_root: daemon_state_root.to_string(),
            node_state_root: node_state_root.to_string(),
            api_state_root: api_state_root.to_string(),
            storage_manifest_root: storage_manifest_root.to_string(),
            operation_receipt_root: operation_receipt_root.to_string(),
            api_exchange_root: api_exchange_root.to_string(),
            storage_commit_root: storage_commit_root.to_string(),
            status: status.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "daemon_health_snapshot",
            "chain_id": CHAIN_ID,
            "daemon_protocol_version": DAEMON_PROTOCOL_VERSION,
            "health_id": self.health_id,
            "daemon_id": self.daemon_id,
            "node_health_report_id": self.node_health_report_id,
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "daemon_state_root": self.daemon_state_root,
            "node_state_root": self.node_state_root,
            "api_state_root": self.api_state_root,
            "storage_manifest_root": self.storage_manifest_root,
            "operation_receipt_root": self.operation_receipt_root,
            "api_exchange_root": self.api_exchange_root,
            "storage_commit_root": self.storage_commit_root,
            "status": self.status,
        })
    }

    pub fn health_root(&self) -> String {
        domain_hash(
            "DAEMON-HEALTH-SNAPSHOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonState {
    pub status: String,
    pub started_at_ms: Option<u64>,
    pub stopped_at_ms: Option<u64>,
    pub last_tick_ms: u64,
    pub last_storage_height: u64,
    pub last_block_hash_seen: String,
    pub operation_receipts: Vec<DaemonOperationReceipt>,
    pub api_exchanges: BTreeMap<String, DaemonApiExchange>,
    pub storage_commits: BTreeMap<String, DaemonStorageCommit>,
    pub health_snapshots: Vec<DaemonHealthSnapshot>,
    pub lifecycle_event_ids: Vec<String>,
    pub node_command_receipt_ids: Vec<String>,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self {
            status: "created".to_string(),
            started_at_ms: None,
            stopped_at_ms: None,
            last_tick_ms: 0,
            last_storage_height: 0,
            last_block_hash_seen: "GENESIS".to_string(),
            operation_receipts: Vec::new(),
            api_exchanges: BTreeMap::new(),
            storage_commits: BTreeMap::new(),
            health_snapshots: Vec::new(),
            lifecycle_event_ids: Vec::new(),
            node_command_receipt_ids: Vec::new(),
        }
    }
}

impl DaemonState {
    pub fn record_lifecycle_event(&mut self, event: &NodeLifecycleEvent) {
        self.lifecycle_event_ids.push(event.event_id.clone());
        self.status = event.status.clone();
    }

    pub fn record_node_command(&mut self, receipt: &NodeCommandReceipt) {
        self.node_command_receipt_ids
            .push(receipt.command_id.clone());
    }

    pub fn record_operation(&mut self, receipt: DaemonOperationReceipt) -> DaemonResult<()> {
        if !receipt.verify_authorization() {
            return Err("daemon operation receipt authorization failed".to_string());
        }
        self.operation_receipts.push(receipt);
        Ok(())
    }

    pub fn operation_receipt_root(&self) -> String {
        merkle_root(
            "DAEMON-OPERATION-RECEIPT",
            &self
                .operation_receipts
                .iter()
                .map(DaemonOperationReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn api_exchange_root(&self) -> String {
        merkle_root(
            "DAEMON-API-EXCHANGE",
            &self
                .api_exchanges
                .values()
                .map(DaemonApiExchange::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn storage_commit_root(&self) -> String {
        merkle_root(
            "DAEMON-STORAGE-COMMIT",
            &self
                .storage_commits
                .values()
                .map(DaemonStorageCommit::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn health_snapshot_root(&self) -> String {
        merkle_root(
            "DAEMON-HEALTH-SNAPSHOT",
            &self
                .health_snapshots
                .iter()
                .map(DaemonHealthSnapshot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn lifecycle_event_root(&self) -> String {
        daemon_string_root("DAEMON-LIFECYCLE-EVENT-ID", &self.lifecycle_event_ids)
    }

    pub fn node_command_receipt_root(&self) -> String {
        daemon_string_root(
            "DAEMON-NODE-COMMAND-RECEIPT-ID",
            &self.node_command_receipt_ids,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "daemon_state",
            "chain_id": CHAIN_ID,
            "daemon_protocol_version": DAEMON_PROTOCOL_VERSION,
            "status": self.status,
            "started_at_ms": self.started_at_ms,
            "stopped_at_ms": self.stopped_at_ms,
            "last_tick_ms": self.last_tick_ms,
            "last_storage_height": self.last_storage_height,
            "last_block_hash_seen": self.last_block_hash_seen,
            "operation_receipt_root": self.operation_receipt_root(),
            "api_exchange_root": self.api_exchange_root(),
            "storage_commit_root": self.storage_commit_root(),
            "health_snapshot_root": self.health_snapshot_root(),
            "lifecycle_event_root": self.lifecycle_event_root(),
            "node_command_receipt_root": self.node_command_receipt_root(),
            "operation_receipt_count": self.operation_receipts.len() as u64,
            "api_exchange_count": self.api_exchanges.len() as u64,
            "storage_commit_count": self.storage_commits.len() as u64,
            "health_snapshot_count": self.health_snapshots.len() as u64,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash("DAEMON-STATE", &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NebulaDaemon {
    pub config: DaemonConfig,
    pub node: NebulaNode,
    pub api: ApiControlPlaneState,
    pub storage: StorageState,
    pub state: DaemonState,
}

impl NebulaDaemon {
    pub fn new(config: DaemonConfig, sequencer_config: SequencerConfig) -> DaemonResult<Self> {
        let node = NebulaNode::new(config.node_config.clone(), sequencer_config)?;
        Self::with_node(config, node, StorageBounds::default())
    }

    pub fn with_node(
        config: DaemonConfig,
        node: NebulaNode,
        storage_bounds: StorageBounds,
    ) -> DaemonResult<Self> {
        if config.node_config.node_id != node.config.node_id {
            return Err("daemon config node id does not match node".to_string());
        }
        let api = ApiControlPlaneState::with_default_routes(
            &node.config.node_id,
            &config.operator_label,
            node.height(),
            node.height()
                .saturating_add(config.api_session_ttl_blocks.saturating_mul(4)),
        );
        Ok(Self {
            config,
            node,
            api,
            storage: StorageState::bounded(storage_bounds),
            state: DaemonState::default(),
        })
    }

    pub fn start(&mut self, timestamp_ms: u64) -> DaemonResult<DaemonOperationReceipt> {
        let pre_root = self.daemon_root();
        let event = self.node.start()?;
        self.state.started_at_ms = Some(timestamp_ms);
        self.state.stopped_at_ms = None;
        self.state.last_tick_ms = timestamp_ms;
        self.state.record_lifecycle_event(&event);
        let response = event.public_record();
        let post_root = self.daemon_root();
        self.record_daemon_operation(
            "start",
            &json!({ "timestamp_ms": timestamp_ms }),
            &response,
            &pre_root,
            &post_root,
            "ok",
            timestamp_ms,
        )
    }

    pub fn stop(&mut self, timestamp_ms: u64) -> DaemonResult<DaemonOperationReceipt> {
        let pre_root = self.daemon_root();
        let event = self.node.stop()?;
        self.state.stopped_at_ms = Some(timestamp_ms);
        self.state.last_tick_ms = timestamp_ms;
        self.state.record_lifecycle_event(&event);
        let response = event.public_record();
        let post_root = self.daemon_root();
        self.record_daemon_operation(
            "stop",
            &json!({ "timestamp_ms": timestamp_ms }),
            &response,
            &pre_root,
            &post_root,
            "ok",
            timestamp_ms,
        )
    }

    pub fn tick(&mut self, timestamp_ms: u64) -> DaemonResult<DaemonHealthSnapshot> {
        self.state.last_tick_ms = timestamp_ms;
        self.api.set_height(self.node.height());
        let node_health = self.node.health_report(timestamp_ms)?;
        let health = self.health_snapshot_from_report(&node_health);
        self.state.health_snapshots.push(health.clone());
        Ok(health)
    }

    pub fn produce_block(
        &mut self,
        timestamp_ms: u64,
    ) -> DaemonResult<(
        SequencerBlockSummary,
        NodeCommandReceipt,
        Option<DaemonStorageCommit>,
    )> {
        let pre_root = self.daemon_root();
        let (summary, command_receipt) = self.node.produce_block()?;
        self.state.record_node_command(&command_receipt);
        self.api.set_height(self.node.height());
        self.state.last_block_hash_seen = summary.block_hash.clone();
        self.state.last_tick_ms = timestamp_ms;
        let storage_commit = if self.should_snapshot(summary.block_height) {
            Some(self.commit_storage_snapshot(timestamp_ms, true)?)
        } else {
            None
        };
        let response = json!({
            "block_summary": summary.public_record(),
            "node_command_receipt": command_receipt.public_record(),
            "storage_commit": storage_commit.as_ref().map(DaemonStorageCommit::public_record),
        });
        let post_root = self.daemon_root();
        let daemon_receipt = self.record_daemon_operation(
            "produce_block",
            &json!({ "timestamp_ms": timestamp_ms }),
            &response,
            &pre_root,
            &post_root,
            "ok",
            timestamp_ms,
        )?;
        self.state.record_operation(daemon_receipt)?;
        Ok((summary, command_receipt, storage_commit))
    }

    pub fn install_fee_smoothing(
        &mut self,
        budget_units_per_lane: u64,
        max_rebate_bps: u64,
        min_settled_fee_units: u64,
        timestamp_ms: u64,
    ) -> DaemonResult<(FeeSmoothingState, NodeCommandReceipt)> {
        let pre_root = self.daemon_root();
        let (smoothing, command_receipt) = self.node.install_fee_smoothing(
            budget_units_per_lane,
            max_rebate_bps,
            min_settled_fee_units,
        )?;
        self.state.record_node_command(&command_receipt);
        let response = json!({
            "fee_smoothing": smoothing.public_record(),
            "node_command_receipt": command_receipt.public_record(),
        });
        let post_root = self.daemon_root();
        let daemon_receipt = self.record_daemon_operation(
            "install_fee_smoothing",
            &json!({
                "budget_units_per_lane": budget_units_per_lane,
                "max_rebate_bps": max_rebate_bps,
                "min_settled_fee_units": min_settled_fee_units,
            }),
            &response,
            &pre_root,
            &post_root,
            "ok",
            timestamp_ms,
        )?;
        self.state.record_operation(daemon_receipt)?;
        Ok((smoothing, command_receipt))
    }

    pub fn open_api_session(
        &mut self,
        client_account_commitment: &str,
        allowed_route_ids: Vec<String>,
        authorizations: &[Authorization],
        public_metadata: &Value,
        rate_limit_subject: &str,
    ) -> DaemonResult<ApiSessionRecord> {
        let height = self.node.height();
        let session = ApiSessionRecord::new(
            &self.node.config.node_id,
            client_account_commitment,
            &allowed_route_ids,
            authorizations,
            public_metadata,
            height,
            height.saturating_add(self.config.api_session_ttl_blocks),
            rate_limit_subject,
        );
        self.api.insert_session(session.clone())?;
        Ok(session)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_api_request(
        &mut self,
        route_id: &str,
        session_id: Option<String>,
        client_account_commitment: &str,
        idempotency_key: &str,
        payload_kind: &str,
        payload: &Value,
        authorizations: &[Authorization],
        public_metadata: &Value,
    ) -> DaemonResult<ApiRequestEnvelope> {
        let route = self
            .api
            .route_registry
            .get(route_id)
            .cloned()
            .ok_or_else(|| "unknown api route".to_string())?;
        if !route.is_live(self.node.height()) {
            return Err("api route is not live".to_string());
        }
        self.ensure_rate_limit_bucket(&route, client_account_commitment);
        self.api.charge_rate_limit(&route.rate_limit_bucket_id, 1)?;
        let height = self.node.height();
        let request = ApiRequestEnvelope::from_payload(
            &route,
            session_id,
            client_account_commitment,
            idempotency_key,
            payload_kind,
            payload,
            authorizations,
            public_metadata,
            height,
            height.saturating_add(self.config.api_request_ttl_blocks),
            self.config.max_api_response_bytes,
        );
        self.api.insert_request_receipt(request.clone())?;
        self.state.api_exchanges.insert(
            request.request_id.clone(),
            DaemonApiExchange::open(&request, payload),
        );
        Ok(request)
    }

    pub fn complete_api_response(
        &mut self,
        request_id: &str,
        status_code: u16,
        response_payload_kind: &str,
        response_payload: &Value,
        error_code: Option<&str>,
        authorizations: &[Authorization],
        public_metadata: &Value,
        retry_after_height: Option<u64>,
    ) -> DaemonResult<ApiResponseEnvelope> {
        let request = self
            .api
            .request_receipts
            .get(request_id)
            .cloned()
            .ok_or_else(|| "unknown api request".to_string())?;
        let response = ApiResponseEnvelope::from_payload(
            &request,
            status_code,
            response_payload_kind,
            response_payload,
            error_code,
            authorizations,
            public_metadata,
            self.node.height(),
            retry_after_height,
        );
        self.api.insert_response_receipt(response.clone())?;
        if let Some(exchange) = self.state.api_exchanges.get_mut(request_id) {
            exchange.complete(&response, response_payload);
        }
        Ok(response)
    }

    pub fn route_by_kind(&self, route_kind: ApiRouteKind) -> Option<&ApiRouteRecord> {
        self.api
            .route_registry
            .values()
            .find(|route| route.route_kind == route_kind)
    }

    pub fn default_route_ids(&self) -> Vec<String> {
        self.api.route_registry.keys().cloned().collect()
    }

    pub fn low_fee_quote_via_api(
        &mut self,
        lane: LowFeeLane,
        gross_fee_units: u64,
        client_account_commitment: &str,
        idempotency_key: &str,
    ) -> DaemonResult<(ApiRequestEnvelope, Value, ApiResponseEnvelope)> {
        let route_id = self
            .route_by_kind(ApiRouteKind::FeeQuote)
            .ok_or_else(|| "fee quote route is not registered".to_string())?
            .route_id
            .clone();
        let request_payload = json!({
            "lane": lane.public_record(),
            "gross_fee_units": gross_fee_units,
        });
        let request = self.receive_api_request(
            &route_id,
            None,
            client_account_commitment,
            idempotency_key,
            "fee_quote_request",
            &request_payload,
            &[],
            &json!({ "privacy": "payload_hash_only" }),
        )?;
        let quote = self.node.low_fee_quote(lane, gross_fee_units)?;
        let response = self.complete_api_response(
            &request.request_id,
            200,
            "fee_quote_response",
            &quote,
            None,
            &[],
            &json!({ "privacy": "payload_hash_only" }),
            None,
        )?;
        Ok((request, quote, response))
    }

    pub fn commit_storage_snapshot(
        &mut self,
        timestamp_ms: u64,
        finalized: bool,
    ) -> DaemonResult<DaemonStorageCommit> {
        let snapshot_value = self.node.sequencer.public_snapshot();
        let state_roots = self.node.sequencer.state_roots();
        let component_roots = StorageComponentRoots {
            note_root: state_roots.note_root,
            nullifier_root: state_roots.nullifier_root,
            contract_root: state_roots.contract_root,
            wasm_runtime_root: state_roots.wasm_runtime_root,
            account_root: state_roots.account_root,
            asset_root: state_roots.asset_root,
            sealed_swap_settlement_receipt_root: state_roots.sealed_swap_settlement_receipt_root,
            bridge_root: state_roots.bridge_root,
            fee_root: state_roots.fee_root,
            crypto_policy_root: state_roots.crypto_policy_root,
            custom_roots: BTreeMap::from([
                (
                    "daemon_state_root".to_string(),
                    self.daemon_state_without_storage_root(),
                ),
                ("api_state_root".to_string(), self.api.state_root()),
            ]),
        };
        let service_roots = StorageServiceRoots {
            da_root: daemon_value_field_root(&snapshot_value, "next_block_packing"),
            proof_root: self.node.sequencer.prover.state_root(),
            consensus_root: self.node.sequencer.consensus.state_root(),
            monero_root: self.node.sequencer.monero.state_root(),
            bridge_root: self.node.sequencer.bridge.bridge_root(),
            mempool_root: self.node.sequencer.mempool.admission_root(),
            network_root: self.node.sequencer.network.state_root(),
            watchtower_root: daemon_value_field_root(&snapshot_value, "watchtower"),
            custom_roots: BTreeMap::from([
                ("node_state_root".to_string(), self.node.node_state_root()),
                (
                    "api_exchange_root".to_string(),
                    self.state.api_exchange_root(),
                ),
            ]),
        };
        let payload_hash = daemon_payload_root("DAEMON-STORAGE-SNAPSHOT-PAYLOAD", &snapshot_value);
        let payload_commitment = domain_hash(
            "DAEMON-STORAGE-SNAPSHOT-COMMITMENT",
            &[
                HashPart::Str(&payload_hash),
                HashPart::Str(&self.config.privacy_payload_policy),
            ],
            32,
        );
        let chunk = StorageChunkRecord::new(
            None,
            "node_snapshot",
            self.storage.chunks.len() as u64,
            json_byte_len(&snapshot_value),
            payload_hash,
            payload_commitment,
            "canonical-json",
            true,
            timestamp_ms,
        );
        let chunk_root = chunk.chunk_root();
        self.storage.insert_chunk(chunk)?;
        let block_height = snapshot_value
            .get("height")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| self.node.height());
        let block_hash = snapshot_value
            .get("last_block_hash")
            .and_then(Value::as_str)
            .unwrap_or("GENESIS")
            .to_string();
        let state_root = snapshot_value
            .get("state_root")
            .and_then(Value::as_str)
            .unwrap_or("GENESIS")
            .to_string();
        let block_root = daemon_payload_root("DAEMON-STORAGE-BLOCK-ROOT", &snapshot_value);
        let snapshot = StorageSnapshotRecord::new(
            block_height,
            block_hash.clone(),
            self.state.last_block_hash_seen.clone(),
            block_root,
            state_root,
            component_roots,
            service_roots,
            chunk_root,
            1,
            timestamp_ms,
            finalized,
        );
        self.storage.insert_snapshot(snapshot.clone())?;
        let mut checkpoint = StorageCheckpointRecord::from_snapshot(
            &snapshot,
            self.storage.manifest_root(),
            timestamp_ms,
        );
        checkpoint.sign(&self.config.operator_label);
        self.storage.insert_checkpoint(checkpoint.clone())?;
        let manifest_root = self.storage.manifest_root();
        let commit = DaemonStorageCommit::from_records(&snapshot, &checkpoint, &manifest_root);
        self.state.last_storage_height = block_height;
        self.state
            .storage_commits
            .insert(commit.commit_id.clone(), commit.clone());
        Ok(commit)
    }

    pub fn plan_restore_latest(&mut self, timestamp_ms: u64) -> DaemonResult<StorageRestorePlan> {
        let snapshot_id = self
            .storage
            .latest_snapshot_id()
            .ok_or_else(|| "no storage snapshot available".to_string())?;
        let snapshot = self
            .storage
            .snapshots
            .get(&snapshot_id)
            .cloned()
            .ok_or_else(|| "latest snapshot missing from storage map".to_string())?;
        let checkpoint_id = self.storage.latest_checkpoint_id();
        let required_checkpoint_ids = checkpoint_id.iter().cloned().collect::<Vec<_>>();
        let required_chunk_ids = self.storage.chunks.keys().cloned().collect::<Vec<_>>();
        let plan = StorageRestorePlan::new(
            snapshot.snapshot_id.clone(),
            checkpoint_id,
            snapshot.block_height,
            snapshot.block_hash.clone(),
            snapshot.state_root.clone(),
            vec![snapshot.snapshot_id.clone()],
            required_checkpoint_ids,
            required_chunk_ids,
            self.storage.manifest_root(),
            timestamp_ms,
            "planned",
        );
        self.storage.record_restore_plan(plan.clone())?;
        Ok(plan)
    }

    pub fn record_retention_decision(
        &mut self,
        timestamp_ms: u64,
    ) -> DaemonResult<StorageRetentionDecision> {
        let retain_from_height = self
            .node
            .height()
            .saturating_sub(self.storage.bounds.retain_recent_heights);
        let prune_before_height = retain_from_height;
        let retained_snapshot_ids = self
            .storage
            .snapshots
            .values()
            .filter(|snapshot| snapshot.block_height >= retain_from_height)
            .map(|snapshot| snapshot.snapshot_id.clone())
            .collect::<Vec<_>>();
        let retained = retained_snapshot_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let pruned_snapshot_ids = self
            .storage
            .snapshots
            .values()
            .filter(|snapshot| !retained.contains(&snapshot.snapshot_id))
            .map(|snapshot| snapshot.snapshot_id.clone())
            .collect::<Vec<_>>();
        let decision = StorageRetentionDecision::new(
            "retain_recent",
            self.node.height(),
            timestamp_ms,
            retain_from_height,
            prune_before_height,
            retained_snapshot_ids,
            pruned_snapshot_ids,
            Vec::new(),
            self.storage.manifest_root(),
            "daemon bounded storage policy",
        );
        self.storage.record_retention_decision(decision.clone())?;
        Ok(decision)
    }

    pub fn health_snapshot_from_report(
        &self,
        node_health: &NodeHealthReport,
    ) -> DaemonHealthSnapshot {
        DaemonHealthSnapshot::new(
            &self.config,
            node_health,
            &self.daemon_root(),
            &self.node.node_state_root(),
            &self.api.state_root(),
            &self.storage.manifest_root(),
            &self.state.operation_receipt_root(),
            &self.state.api_exchange_root(),
            &self.state.storage_commit_root(),
            &self.state.status,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nebula_daemon",
            "chain_id": CHAIN_ID,
            "daemon_protocol_version": DAEMON_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "node": self.node.public_snapshot(),
            "api": self.api.public_record(),
            "storage": self.storage.public_record(),
            "state": self.state.public_record(),
            "daemon_root": self.daemon_root(),
        })
    }

    pub fn daemon_root(&self) -> String {
        domain_hash(
            "NEBULA-DAEMON",
            &[
                HashPart::Str(&self.config.config_root()),
                HashPart::Str(&self.node.node_state_root()),
                HashPart::Str(&self.api.state_root()),
                HashPart::Str(&self.storage.manifest_root()),
                HashPart::Str(&self.state.state_root()),
            ],
            32,
        )
    }

    fn daemon_state_without_storage_root(&self) -> String {
        domain_hash(
            "NEBULA-DAEMON-NON-STORAGE",
            &[
                HashPart::Str(&self.config.config_root()),
                HashPart::Str(&self.node.node_state_root()),
                HashPart::Str(&self.api.state_root()),
                HashPart::Str(&self.state.state_root()),
            ],
            32,
        )
    }

    fn ensure_rate_limit_bucket(&mut self, route: &ApiRouteRecord, subject: &str) {
        if self
            .api
            .rate_limit_buckets
            .contains_key(&route.rate_limit_bucket_id)
        {
            return;
        }
        let mut bucket = ApiRateLimitBucket::new(
            &route.route_id,
            subject,
            self.node.height(),
            self.config.api_rate_limit_window_blocks,
            self.config.api_rate_limit_units,
            &json!({ "daemon_id": self.config.daemon_id }),
        );
        bucket.bucket_id = route.rate_limit_bucket_id.clone();
        self.api.upsert_rate_limit_bucket(bucket);
    }

    fn should_snapshot(&self, produced_height: u64) -> bool {
        produced_height == 0
            || produced_height.saturating_sub(self.state.last_storage_height)
                >= self.config.storage_snapshot_interval_blocks
    }

    fn record_daemon_operation(
        &mut self,
        operation_kind: &str,
        request: &Value,
        response: &Value,
        pre_root: &str,
        post_root: &str,
        status: &str,
        timestamp_ms: u64,
    ) -> DaemonResult<DaemonOperationReceipt> {
        let receipt = DaemonOperationReceipt::new(
            &self.config,
            operation_kind,
            self.node.height(),
            timestamp_ms,
            request,
            response,
            pre_root,
            post_root,
            status,
        );
        if !receipt.verify_authorization() {
            return Err("daemon operation authorization failed".to_string());
        }
        Ok(receipt)
    }
}

pub fn default_daemon(
    operator_label: &str,
    sequencer_config: SequencerConfig,
) -> DaemonResult<NebulaDaemon> {
    let config = DaemonConfig::devnet(
        operator_label,
        vec![
            NodeRole::Sequencer,
            NodeRole::Validator,
            NodeRole::Prover,
            NodeRole::Watchtower,
            NodeRole::MoneroObserver,
            NodeRole::WalletRpc,
            NodeRole::Archive,
        ],
    )?;
    NebulaDaemon::new(config, sequencer_config)
}

pub fn daemon_id(
    operator_label: &str,
    mode: &str,
    node_id: &str,
    api_bind_commitment: &str,
    storage_policy_commitment: &str,
) -> String {
    domain_hash(
        "DAEMON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(DAEMON_PROTOCOL_VERSION),
            HashPart::Str(operator_label),
            HashPart::Str(mode),
            HashPart::Str(node_id),
            HashPart::Str(api_bind_commitment),
            HashPart::Str(storage_policy_commitment),
        ],
        32,
    )
}

pub fn daemon_config_root(config: &Value) -> String {
    domain_hash(
        "DAEMON-CONFIG",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(config)],
        32,
    )
}

pub fn daemon_operation_receipt_id(
    daemon_id: &str,
    operation_kind: &str,
    height: u64,
    request_root: &str,
    response_root: &str,
    pre_daemon_root: &str,
    post_daemon_root: &str,
) -> String {
    domain_hash(
        "DAEMON-OPERATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(daemon_id),
            HashPart::Str(operation_kind),
            HashPart::Int(height as i128),
            HashPart::Str(request_root),
            HashPart::Str(response_root),
            HashPart::Str(pre_daemon_root),
            HashPart::Str(post_daemon_root),
        ],
        32,
    )
}

pub fn daemon_api_exchange_id(
    request_id: &str,
    response_id: &str,
    route_id: &str,
    payload_root: &str,
) -> String {
    domain_hash(
        "DAEMON-API-EXCHANGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request_id),
            HashPart::Str(response_id),
            HashPart::Str(route_id),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn daemon_storage_commit_id(
    snapshot_id: &str,
    checkpoint_id: &str,
    block_height: u64,
    state_root: &str,
    manifest_root: &str,
) -> String {
    domain_hash(
        "DAEMON-STORAGE-COMMIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(snapshot_id),
            HashPart::Str(checkpoint_id),
            HashPart::Int(block_height as i128),
            HashPart::Str(state_root),
            HashPart::Str(manifest_root),
        ],
        32,
    )
}

pub fn daemon_health_snapshot_id(
    daemon_id: &str,
    height: u64,
    daemon_state_root: &str,
    node_state_root: &str,
    api_state_root: &str,
    storage_manifest_root: &str,
) -> String {
    domain_hash(
        "DAEMON-HEALTH-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(daemon_id),
            HashPart::Int(height as i128),
            HashPart::Str(daemon_state_root),
            HashPart::Str(node_state_root),
            HashPart::Str(api_state_root),
            HashPart::Str(storage_manifest_root),
        ],
        32,
    )
}

pub fn daemon_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn daemon_string_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

pub fn daemon_route_root(api: &ApiControlPlaneState) -> String {
    api.route_registry_root()
}

pub fn daemon_value_field_root(value: &Value, field: &str) -> String {
    value
        .get(field)
        .map(node_component_root)
        .unwrap_or_else(|| {
            daemon_payload_root("DAEMON-MISSING-VALUE-FIELD", &json!({ "field": field }))
        })
}

pub fn daemon_runtime_timestamp_ms(height: u64) -> u64 {
    1_700_000_000_000 + height.saturating_mul(TARGET_BLOCK_MS)
}

fn json_byte_len(value: &Value) -> u64 {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .unwrap_or_default()
}

fn empty_daemon_authorization(label: &str) -> Authorization {
    sign_network_authorization(
        label,
        "daemon_empty_authorization",
        &json!({ "label": label }),
    )
}

fn insert_daemon_authorization(
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
