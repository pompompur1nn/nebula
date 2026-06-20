use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    consensus::ConsensusState,
    crypto_policy::{
        crypto_policy_root, public_key_for_label, sign_network_authorization,
        verify_network_authorization, Authorization, CryptoRole,
    },
    fees::{FeeSmoothingState, LowFeeLane},
    hash::{domain_hash, merkle_root, HashPart},
    mempool::MempoolState,
    monero::MoneroMonitorState,
    network::NetworkState,
    prover::ProverState,
    sequencer::{LocalSequencer, SequencerBlockSummary, SequencerConfig},
    watchtower::WatchtowerState,
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type NodeResult<T> = Result<T, String>;

pub const NODE_HEALTH_STALE_AFTER_MS: u64 = TARGET_BLOCK_MS * 8;
pub const NODE_DEFAULT_SNAPSHOT_INTERVAL_BLOCKS: u64 = 20;
pub const NODE_DEFAULT_API_RECEIPT_TTL_BLOCKS: u64 = 50;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeRole {
    Sequencer,
    Validator,
    Prover,
    Watchtower,
    DataAvailability,
    MoneroObserver,
    BridgeSigner,
    WalletRpc,
    Archive,
}

impl NodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Validator => "validator",
            Self::Prover => "prover",
            Self::Watchtower => "watchtower",
            Self::DataAvailability => "data_availability",
            Self::MoneroObserver => "monero_observer",
            Self::BridgeSigner => "bridge_signer",
            Self::WalletRpc => "wallet_rpc",
            Self::Archive => "archive",
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "node_role",
            "chain_id": CHAIN_ID,
            "role": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub node_label: String,
    pub network_id: String,
    pub roles: Vec<NodeRole>,
    pub data_dir_commitment: String,
    pub api_bind_commitment: String,
    pub monero_network: String,
    pub max_pending_transactions: u64,
    pub snapshot_interval_blocks: u64,
    pub api_receipt_ttl_blocks: u64,
    pub privacy_mode: String,
}

impl NodeConfig {
    pub fn new(node_label: impl Into<String>, roles: Vec<NodeRole>) -> NodeResult<Self> {
        let node_label = node_label.into();
        if node_label.is_empty() {
            return Err("node label is required".to_string());
        }
        if roles.is_empty() {
            return Err("node requires at least one role".to_string());
        }
        let data_dir_commitment = domain_hash(
            "NODE-DATA-DIR-COMMITMENT",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(&node_label)],
            32,
        );
        let api_bind_commitment = domain_hash(
            "NODE-API-BIND-COMMITMENT",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(&node_label)],
            32,
        );
        let node_id = node_id(
            &node_label,
            &roles,
            &data_dir_commitment,
            &api_bind_commitment,
        );
        Ok(Self {
            node_id,
            node_label,
            network_id: CHAIN_ID.to_string(),
            roles: canonical_roles(roles),
            data_dir_commitment,
            api_bind_commitment,
            monero_network: "monero-devnet".to_string(),
            max_pending_transactions: 128,
            snapshot_interval_blocks: NODE_DEFAULT_SNAPSHOT_INTERVAL_BLOCKS,
            api_receipt_ttl_blocks: NODE_DEFAULT_API_RECEIPT_TTL_BLOCKS,
            privacy_mode: "hashes_only".to_string(),
        })
    }

    pub fn with_commitments(
        mut self,
        data_dir_commitment: impl Into<String>,
        api_bind_commitment: impl Into<String>,
    ) -> Self {
        self.data_dir_commitment = data_dir_commitment.into();
        self.api_bind_commitment = api_bind_commitment.into();
        self.node_id = node_id(
            &self.node_label,
            &self.roles,
            &self.data_dir_commitment,
            &self.api_bind_commitment,
        );
        self
    }

    pub fn role_root(&self) -> String {
        node_role_root(&self.roles)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "node_config",
            "chain_id": CHAIN_ID,
            "node_id": self.node_id,
            "node_label": self.node_label,
            "network_id": self.network_id,
            "role_root": self.role_root(),
            "roles": self.roles.iter().map(NodeRole::public_record).collect::<Vec<_>>(),
            "data_dir_commitment": self.data_dir_commitment,
            "api_bind_commitment": self.api_bind_commitment,
            "monero_network": self.monero_network,
            "max_pending_transactions": self.max_pending_transactions,
            "snapshot_interval_blocks": self.snapshot_interval_blocks,
            "api_receipt_ttl_blocks": self.api_receipt_ttl_blocks,
            "privacy_mode": self.privacy_mode,
            "crypto_policy_root": crypto_policy_root(),
        })
    }

    pub fn config_root(&self) -> String {
        domain_hash("NODE-CONFIG", &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLifecycleEvent {
    pub event_id: String,
    pub event_kind: String,
    pub node_id: String,
    pub node_label: String,
    pub height: u64,
    pub timestamp_ms: u64,
    pub config_root: String,
    pub previous_event_root: String,
    pub status: String,
    pub authorization: Authorization,
}

impl NodeLifecycleEvent {
    pub fn new(
        event_kind: &str,
        config: &NodeConfig,
        height: u64,
        timestamp_ms: u64,
        previous_event_root: &str,
        status: &str,
    ) -> NodeResult<Self> {
        if event_kind.is_empty() {
            return Err("node lifecycle event kind is required".to_string());
        }
        let config_root = config.config_root();
        let event_id = node_lifecycle_event_id(
            &config.node_id,
            event_kind,
            height,
            timestamp_ms,
            previous_event_root,
        );
        let mut event = Self {
            event_id,
            event_kind: event_kind.to_string(),
            node_id: config.node_id.clone(),
            node_label: config.node_label.clone(),
            height,
            timestamp_ms,
            config_root,
            previous_event_root: previous_event_root.to_string(),
            status: status.to_string(),
            authorization: empty_node_authorization(&config.node_label),
        };
        event.authorization = sign_network_authorization(
            &config.node_label,
            "node_lifecycle_event",
            &event.unsigned_record(),
        );
        if !event.verify_authorization() {
            return Err("node lifecycle authorization failed".to_string());
        }
        Ok(event)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "node_lifecycle_event",
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "node_id": self.node_id,
            "node_label": self.node_label,
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "config_root": self.config_root,
            "previous_event_root": self.previous_event_root,
            "status": self.status,
        })
    }

    pub fn event_root(&self) -> String {
        domain_hash(
            "NODE-LIFECYCLE-EVENT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        with_node_authorization(
            self.unsigned_record(),
            &self.authorization,
            self.event_root(),
        )
    }

    pub fn verify_authorization(&self) -> bool {
        verify_network_authorization(
            &self.authorization.auth_public_key,
            "node_lifecycle_event",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHealthReport {
    pub report_id: String,
    pub node_id: String,
    pub node_label: String,
    pub height: u64,
    pub timestamp_ms: u64,
    pub block_height: u64,
    pub last_block_hash: String,
    pub state_root: String,
    pub mempool_admission_root: String,
    pub mempool_fairness_root: String,
    pub monero_monitor_root: String,
    pub consensus_state_root: String,
    pub prover_state_root: String,
    pub watchtower_state_root: String,
    pub network_state_root: String,
    pub fee_smoothing_root: String,
    pub pending_transaction_count: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl NodeHealthReport {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        config: &NodeConfig,
        height: u64,
        timestamp_ms: u64,
        block_height: u64,
        last_block_hash: &str,
        state_root: &str,
        mempool: &MempoolState,
        monero: &MoneroMonitorState,
        consensus: &ConsensusState,
        prover: &ProverState,
        watchtower: &WatchtowerState,
        network: &NetworkState,
        fee_smoothing: &FeeSmoothingState,
        pending_transaction_count: u64,
        status: &str,
    ) -> NodeResult<Self> {
        let mempool_fairness_root = node_mempool_fairness_root(mempool);
        let report_id = node_health_report_id(
            &config.node_id,
            height,
            last_block_hash,
            state_root,
            &mempool_fairness_root,
        );
        let mut report = Self {
            report_id,
            node_id: config.node_id.clone(),
            node_label: config.node_label.clone(),
            height,
            timestamp_ms,
            block_height,
            last_block_hash: last_block_hash.to_string(),
            state_root: state_root.to_string(),
            mempool_admission_root: mempool.admission_root(),
            mempool_fairness_root,
            monero_monitor_root: monero.state_root(),
            consensus_state_root: consensus.state_root(),
            prover_state_root: prover.state_root(),
            watchtower_state_root: node_watchtower_state_root(watchtower),
            network_state_root: network.state_root(),
            fee_smoothing_root: fee_smoothing.state_root(),
            pending_transaction_count,
            status: status.to_string(),
            authorization: empty_node_authorization(&config.node_label),
        };
        report.authorization = sign_network_authorization(
            &config.node_label,
            "node_health_report",
            &report.unsigned_record(),
        );
        if !report.verify_authorization() {
            return Err("node health authorization failed".to_string());
        }
        Ok(report)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "node_health_report",
            "chain_id": CHAIN_ID,
            "report_id": self.report_id,
            "node_id": self.node_id,
            "node_label": self.node_label,
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "block_height": self.block_height,
            "last_block_hash": self.last_block_hash,
            "state_root": self.state_root,
            "mempool_admission_root": self.mempool_admission_root,
            "mempool_fairness_root": self.mempool_fairness_root,
            "monero_monitor_root": self.monero_monitor_root,
            "consensus_state_root": self.consensus_state_root,
            "prover_state_root": self.prover_state_root,
            "watchtower_state_root": self.watchtower_state_root,
            "network_state_root": self.network_state_root,
            "fee_smoothing_root": self.fee_smoothing_root,
            "pending_transaction_count": self.pending_transaction_count,
            "status": self.status,
        })
    }

    pub fn report_root(&self) -> String {
        domain_hash(
            "NODE-HEALTH-REPORT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        with_node_authorization(
            self.unsigned_record(),
            &self.authorization,
            self.report_root(),
        )
    }

    pub fn verify_authorization(&self) -> bool {
        verify_network_authorization(
            &self.authorization.auth_public_key,
            "node_health_report",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCommandReceipt {
    pub command_id: String,
    pub command_kind: String,
    pub node_id: String,
    pub node_label: String,
    pub height: u64,
    pub timestamp_ms: u64,
    pub request_root: String,
    pub response_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub status: String,
    pub authorization: Authorization,
}

impl NodeCommandReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command_kind: &str,
        config: &NodeConfig,
        height: u64,
        timestamp_ms: u64,
        request: &Value,
        response: &Value,
        pre_state_root: &str,
        post_state_root: &str,
        status: &str,
    ) -> NodeResult<Self> {
        if command_kind.is_empty() {
            return Err("node command kind is required".to_string());
        }
        let request_root = node_payload_root("NODE-COMMAND-REQUEST", request);
        let response_root = node_payload_root("NODE-COMMAND-RESPONSE", response);
        let command_id = node_command_id(
            &config.node_id,
            command_kind,
            height,
            &request_root,
            &response_root,
        );
        let mut receipt = Self {
            command_id,
            command_kind: command_kind.to_string(),
            node_id: config.node_id.clone(),
            node_label: config.node_label.clone(),
            height,
            timestamp_ms,
            request_root,
            response_root,
            pre_state_root: pre_state_root.to_string(),
            post_state_root: post_state_root.to_string(),
            status: status.to_string(),
            authorization: empty_node_authorization(&config.node_label),
        };
        receipt.authorization = sign_network_authorization(
            &config.node_label,
            "node_command_receipt",
            &receipt.unsigned_record(),
        );
        if !receipt.verify_authorization() {
            return Err("node command authorization failed".to_string());
        }
        Ok(receipt)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "node_command_receipt",
            "chain_id": CHAIN_ID,
            "command_id": self.command_id,
            "command_kind": self.command_kind,
            "node_id": self.node_id,
            "node_label": self.node_label,
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "request_root": self.request_root,
            "response_root": self.response_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "NODE-COMMAND-RECEIPT",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        with_node_authorization(
            self.unsigned_record(),
            &self.authorization,
            self.receipt_root(),
        )
    }

    pub fn verify_authorization(&self) -> bool {
        verify_network_authorization(
            &self.authorization.auth_public_key,
            "node_command_receipt",
            &self.unsigned_record(),
            &self.authorization,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRuntimeState {
    pub lifecycle_events: BTreeMap<String, NodeLifecycleEvent>,
    pub health_reports: BTreeMap<String, NodeHealthReport>,
    pub command_receipts: BTreeMap<String, NodeCommandReceipt>,
    pub peers: BTreeMap<String, NodePeerRecord>,
    pub last_event_root: String,
    pub status: String,
}

impl NodeRuntimeState {
    pub fn new() -> Self {
        Self {
            last_event_root: merkle_root("NODE-LIFECYCLE-EVENT", &[]),
            status: "created".to_string(),
            ..Self::default()
        }
    }

    pub fn record_lifecycle_event(&mut self, event: NodeLifecycleEvent) -> NodeResult<()> {
        if self.lifecycle_events.contains_key(&event.event_id) {
            return Err("node lifecycle event already exists".to_string());
        }
        self.last_event_root = event.event_root();
        self.status = event.status.clone();
        self.lifecycle_events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn record_health_report(&mut self, report: NodeHealthReport) -> NodeResult<()> {
        if self.health_reports.contains_key(&report.report_id) {
            return Err("node health report already exists".to_string());
        }
        self.health_reports.insert(report.report_id.clone(), report);
        Ok(())
    }

    pub fn record_command_receipt(&mut self, receipt: NodeCommandReceipt) -> NodeResult<()> {
        if self.command_receipts.contains_key(&receipt.command_id) {
            return Err("node command receipt already exists".to_string());
        }
        self.command_receipts
            .insert(receipt.command_id.clone(), receipt);
        Ok(())
    }

    pub fn record_peer(&mut self, peer: NodePeerRecord) -> NodeResult<()> {
        if peer.peer_id.is_empty() {
            return Err("node peer id is required".to_string());
        }
        self.peers.insert(peer.peer_id.clone(), peer);
        Ok(())
    }

    pub fn lifecycle_root(&self) -> String {
        merkle_root(
            "NODE-LIFECYCLE",
            &self
                .lifecycle_events
                .values()
                .map(NodeLifecycleEvent::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn health_root(&self) -> String {
        merkle_root(
            "NODE-HEALTH",
            &self
                .health_reports
                .values()
                .map(NodeHealthReport::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn command_root(&self) -> String {
        merkle_root(
            "NODE-COMMAND",
            &self
                .command_receipts
                .values()
                .map(NodeCommandReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn peer_root(&self) -> String {
        merkle_root(
            "NODE-PEER",
            &self
                .peers
                .values()
                .map(NodePeerRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "NODE-RUNTIME-STATE",
            &[
                HashPart::Str(&self.lifecycle_root()),
                HashPart::Str(&self.health_root()),
                HashPart::Str(&self.command_root()),
                HashPart::Str(&self.peer_root()),
                HashPart::Str(&self.last_event_root),
                HashPart::Str(&self.status),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "node_runtime_state",
            "chain_id": CHAIN_ID,
            "status": self.status,
            "lifecycle_root": self.lifecycle_root(),
            "health_root": self.health_root(),
            "command_root": self.command_root(),
            "peer_root": self.peer_root(),
            "last_event_root": self.last_event_root,
            "node_runtime_state_root": self.state_root(),
            "lifecycle_event_count": self.lifecycle_events.len() as u64,
            "health_report_count": self.health_reports.len() as u64,
            "command_receipt_count": self.command_receipts.len() as u64,
            "peer_count": self.peers.len() as u64,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePeerRecord {
    pub peer_id: String,
    pub node_id: String,
    pub node_label: String,
    pub role_root: String,
    pub route_commitment: String,
    pub last_seen_height: u64,
    pub last_seen_ms: u64,
    pub health_root: String,
    pub status: String,
}

impl NodePeerRecord {
    pub fn new(
        node_id: &str,
        node_label: &str,
        roles: &[NodeRole],
        route_hint: &str,
        last_seen_height: u64,
        last_seen_ms: u64,
        health_root: &str,
    ) -> Self {
        let role_root = node_role_root(roles);
        let route_commitment = domain_hash(
            "NODE-PEER-ROUTE",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(route_hint)],
            32,
        );
        let peer_id = node_peer_id(node_id, &role_root, &route_commitment);
        Self {
            peer_id,
            node_id: node_id.to_string(),
            node_label: node_label.to_string(),
            role_root,
            route_commitment,
            last_seen_height,
            last_seen_ms,
            health_root: health_root.to_string(),
            status: "live".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "node_peer_record",
            "chain_id": CHAIN_ID,
            "peer_id": self.peer_id,
            "node_id": self.node_id,
            "node_label": self.node_label,
            "role_root": self.role_root,
            "route_commitment": self.route_commitment,
            "last_seen_height": self.last_seen_height,
            "last_seen_ms": self.last_seen_ms,
            "health_root": self.health_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NebulaNode {
    pub config: NodeConfig,
    pub sequencer: LocalSequencer,
    pub runtime: NodeRuntimeState,
}

impl NebulaNode {
    pub fn new(config: NodeConfig, sequencer_config: SequencerConfig) -> NodeResult<Self> {
        let sequencer = LocalSequencer::new(sequencer_config)?;
        Self::with_sequencer(config, sequencer)
    }

    pub fn with_sequencer(config: NodeConfig, sequencer: LocalSequencer) -> NodeResult<Self> {
        let mut node = Self {
            config,
            sequencer,
            runtime: NodeRuntimeState::new(),
        };
        node.record_lifecycle("created", "created")?;
        Ok(node)
    }

    pub fn height(&self) -> u64 {
        self.sequencer.height()
    }

    pub fn start(&mut self) -> NodeResult<NodeLifecycleEvent> {
        self.record_lifecycle("start", "running")
    }

    pub fn stop(&mut self) -> NodeResult<NodeLifecycleEvent> {
        self.record_lifecycle("stop", "stopped")
    }

    pub fn pause(&mut self, reason: &str) -> NodeResult<NodeLifecycleEvent> {
        let reason_root = domain_hash("NODE-PAUSE-REASON", &[HashPart::Str(reason)], 32);
        let event_kind = format!("pause:{reason_root}");
        self.record_lifecycle(&event_kind, "paused")
    }

    pub fn produce_block(&mut self) -> NodeResult<(SequencerBlockSummary, NodeCommandReceipt)> {
        let request = json!({
            "command": "produce_block",
            "height": self.height(),
            "pending_transaction_count": self.sequencer.pending_transaction_count(),
        });
        let pre_state_root = self.node_state_root();
        let summary = self.sequencer.produce_block()?;
        let response = summary.public_record();
        let post_state_root = self.node_state_root();
        let receipt = self.record_command(
            "produce_block",
            &request,
            &response,
            &pre_state_root,
            &post_state_root,
            "ok",
        )?;
        Ok((summary, receipt))
    }

    pub fn install_fee_smoothing(
        &mut self,
        budget_units_per_lane: u64,
        max_rebate_bps: u64,
        min_settled_fee_units: u64,
    ) -> NodeResult<(FeeSmoothingState, NodeCommandReceipt)> {
        let request = json!({
            "command": "install_fee_smoothing",
            "budget_units_per_lane": budget_units_per_lane,
            "max_rebate_bps": max_rebate_bps,
            "min_settled_fee_units": min_settled_fee_units,
        });
        let pre_state_root = self.node_state_root();
        let smoothing = self.sequencer.install_default_fee_smoothing(
            budget_units_per_lane,
            max_rebate_bps,
            min_settled_fee_units,
        )?;
        let response = smoothing.public_record();
        let post_state_root = self.node_state_root();
        let receipt = self.record_command(
            "install_fee_smoothing",
            &request,
            &response,
            &pre_state_root,
            &post_state_root,
            "ok",
        )?;
        Ok((smoothing, receipt))
    }

    pub fn low_fee_quote(&mut self, lane: LowFeeLane, gross_fee_units: u64) -> NodeResult<Value> {
        let request = json!({
            "command": "low_fee_quote",
            "lane": lane.public_record(),
            "gross_fee_units": gross_fee_units,
        });
        let pre_state_root = self.node_state_root();
        let response = self
            .sequencer
            .smoothed_fee_for_low_fee_lane(lane, gross_fee_units);
        let post_state_root = self.node_state_root();
        let _ = self.record_command(
            "low_fee_quote",
            &request,
            &response,
            &pre_state_root,
            &post_state_root,
            "ok",
        )?;
        Ok(response)
    }

    pub fn health_report(&mut self, timestamp_ms: u64) -> NodeResult<NodeHealthReport> {
        let block_height = self.height().saturating_sub(1);
        let snapshot = self.sequencer.public_snapshot();
        let state_root = snapshot
            .get("state_root")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let last_block_hash = snapshot
            .get("last_block_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let pending_transaction_count = snapshot
            .get("pending_transaction_count")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let report = NodeHealthReport::from_parts(
            &self.config,
            self.height(),
            timestamp_ms,
            block_height,
            &last_block_hash,
            &state_root,
            &self.sequencer.mempool,
            &self.sequencer.monero,
            &self.sequencer.consensus,
            &self.sequencer.prover,
            &self.sequencer.watchtower,
            &self.sequencer.network,
            &self.sequencer.fee_smoothing,
            pending_transaction_count,
            &self.runtime.status,
        )?;
        self.runtime.record_health_report(report.clone())?;
        Ok(report)
    }

    pub fn public_snapshot(&self) -> Value {
        json!({
            "kind": "nebula_node_snapshot",
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "runtime": self.runtime.public_record(),
            "sequencer": self.sequencer.public_snapshot(),
            "node_state_root": self.node_state_root(),
        })
    }

    pub fn node_state_root(&self) -> String {
        domain_hash(
            "NEBULA-NODE-STATE",
            &[
                HashPart::Str(&self.config.config_root()),
                HashPart::Str(&self.runtime.state_root()),
                HashPart::Json(&self.sequencer.public_snapshot()),
            ],
            32,
        )
    }

    fn record_lifecycle(
        &mut self,
        event_kind: &str,
        status: &str,
    ) -> NodeResult<NodeLifecycleEvent> {
        let event = NodeLifecycleEvent::new(
            event_kind,
            &self.config,
            self.height(),
            self.sequencer_timestamp_ms(),
            &self.runtime.last_event_root,
            status,
        )?;
        self.runtime.record_lifecycle_event(event.clone())?;
        Ok(event)
    }

    fn record_command(
        &mut self,
        command_kind: &str,
        request: &Value,
        response: &Value,
        pre_state_root: &str,
        post_state_root: &str,
        status: &str,
    ) -> NodeResult<NodeCommandReceipt> {
        let receipt = NodeCommandReceipt::new(
            command_kind,
            &self.config,
            self.height(),
            self.sequencer_timestamp_ms(),
            request,
            response,
            pre_state_root,
            post_state_root,
            status,
        )?;
        self.runtime.record_command_receipt(receipt.clone())?;
        Ok(receipt)
    }

    fn sequencer_timestamp_ms(&self) -> u64 {
        // The sequencer keeps its wall-clock field private; derive a stable devnet
        // timestamp from height for node receipts until a real clock adapter exists.
        1_700_000_000_000 + self.height().saturating_mul(TARGET_BLOCK_MS)
    }
}

pub fn node_id(
    node_label: &str,
    roles: &[NodeRole],
    data_dir_commitment: &str,
    api_bind_commitment: &str,
) -> String {
    domain_hash(
        "NODE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(node_label),
            HashPart::Str(&node_role_root(roles)),
            HashPart::Str(data_dir_commitment),
            HashPart::Str(api_bind_commitment),
        ],
        32,
    )
}

pub fn node_role_root(roles: &[NodeRole]) -> String {
    let roles = canonical_roles(roles.to_vec());
    merkle_root(
        "NODE-ROLE",
        &roles
            .iter()
            .map(NodeRole::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn node_lifecycle_event_id(
    node_id: &str,
    event_kind: &str,
    height: u64,
    timestamp_ms: u64,
    previous_event_root: &str,
) -> String {
    domain_hash(
        "NODE-LIFECYCLE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(node_id),
            HashPart::Str(event_kind),
            HashPart::Int(height as i128),
            HashPart::Int(timestamp_ms as i128),
            HashPart::Str(previous_event_root),
        ],
        32,
    )
}

pub fn node_health_report_id(
    node_id: &str,
    height: u64,
    last_block_hash: &str,
    state_root: &str,
    mempool_fairness_root: &str,
) -> String {
    domain_hash(
        "NODE-HEALTH-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(node_id),
            HashPart::Int(height as i128),
            HashPart::Str(last_block_hash),
            HashPart::Str(state_root),
            HashPart::Str(mempool_fairness_root),
        ],
        32,
    )
}

pub fn node_command_id(
    node_id: &str,
    command_kind: &str,
    height: u64,
    request_root: &str,
    response_root: &str,
) -> String {
    domain_hash(
        "NODE-COMMAND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(node_id),
            HashPart::Str(command_kind),
            HashPart::Int(height as i128),
            HashPart::Str(request_root),
            HashPart::Str(response_root),
        ],
        32,
    )
}

pub fn node_peer_id(node_id: &str, role_root: &str, route_commitment: &str) -> String {
    domain_hash(
        "NODE-PEER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(node_id),
            HashPart::Str(role_root),
            HashPart::Str(route_commitment),
        ],
        32,
    )
}

pub fn node_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn node_mempool_fairness_root(mempool: &MempoolState) -> String {
    domain_hash(
        "NODE-MEMPOOL-FAIRNESS",
        &[
            HashPart::Str(&mempool.encrypted_batch_receipt_root()),
            HashPart::Str(&mempool.relay_fairness_ticket_root()),
            HashPart::Str(&mempool.anti_censorship_lane_commitment_root()),
            HashPart::Str(&mempool.forced_inclusion_root()),
        ],
        32,
    )
}

pub fn node_component_root(snapshot: &Value) -> String {
    domain_hash(
        "NODE-COMPONENT-SNAPSHOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(snapshot)],
        32,
    )
}

fn canonical_roles(roles: Vec<NodeRole>) -> Vec<NodeRole> {
    roles
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn empty_node_authorization(label: &str) -> Authorization {
    let key = public_key_for_label(CryptoRole::NetworkSignature, label);
    Authorization {
        signer_label: label.to_string(),
        auth_scheme: CryptoRole::NetworkSignature.scheme().to_string(),
        auth_public_key: key.public_key,
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

fn with_node_authorization(
    mut record: Value,
    authorization: &Authorization,
    record_root: String,
) -> Value {
    let object = record
        .as_object_mut()
        .expect("node authorized record object");
    object.insert("record_root".to_string(), Value::String(record_root));
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
    record
}

fn node_watchtower_state_root(watchtower: &WatchtowerState) -> String {
    domain_hash(
        "NODE-WATCHTOWER-STATE",
        &[
            HashPart::Str(&watchtower.audit_root()),
            HashPart::Str(&watchtower.challenge_root()),
        ],
        32,
    )
}
