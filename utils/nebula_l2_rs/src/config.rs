use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    daemon::{daemon_id, DaemonConfig, DaemonMode},
    fees::{BlockPackingPolicy, LowFeeLane},
    hash::{domain_hash, merkle_root, HashPart},
    node::{NodeConfig, NodeRole},
    sequencer::SequencerConfig,
    storage::StorageBounds,
    CHAIN_ID, TARGET_BLOCK_MS,
};

pub type ConfigResult<T> = Result<T, String>;

pub const CONFIG_SCHEMA_VERSION: u64 = 1;
pub const CONFIG_KIND_RUNTIME_PROFILE: &str = "nebula_runtime_profile";
pub const CONFIG_KIND_MANIFEST: &str = "nebula_config_manifest";
pub const DEFAULT_OPERATOR_LABEL: &str = "nebula-devnet-operator";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_RPC_BIND: &str = "127.0.0.1:18480";
pub const DEFAULT_P2P_BIND: &str = "127.0.0.1:18481";
pub const LOCAL_FAST_RPC_BIND: &str = "127.0.0.1:28480";
pub const LOCAL_FAST_P2P_BIND: &str = "127.0.0.1:28481";
pub const PRIVATE_BRIDGE_RPC_BIND: &str = "127.0.0.1:38480";
pub const PRIVATE_BRIDGE_P2P_BIND: &str = "127.0.0.1:38481";
pub const ARCHIVE_VALIDATOR_RPC_BIND: &str = "127.0.0.1:48480";
pub const ARCHIVE_VALIDATOR_P2P_BIND: &str = "127.0.0.1:48481";
pub const DEFAULT_PRIVACY_MODE: &str = "hashes_only";
pub const CONFIDENTIAL_PRIVACY_MODE: &str = "confidential_da";
pub const RELAY_PRIVATE_PRIVACY_MODE: &str = "relay_private";
pub const DEFAULT_PRIVACY_PAYLOAD_POLICY: &str = "hash_only";
pub const CONFIDENTIAL_PRIVACY_PAYLOAD_POLICY: &str = "commitments_only";
pub const DEFAULT_QUANTUM_RESISTANCE_POLICY: &str =
    "ml-dsa-65+slh-dsa-shake-128s+shake256-domain-separation";
pub const MIN_PROFILE_BLOCK_TIME_MS: u64 = 50;
pub const MAX_PROFILE_BLOCK_TIME_MS: u64 = 60_000;
pub const DEFAULT_LOW_FEE_BUDGET_UNITS: u64 = 50_000;
pub const DEFAULT_LOW_FEE_MIN_SETTLED_FEE_UNITS: u64 = 1;
pub const DEFAULT_LOW_FEE_MAX_REBATE_BPS: u64 = 9_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NebulaNetworkProfile {
    Devnet,
    LocalFast,
    PrivateBridge,
    ArchiveValidator,
}

impl NebulaNetworkProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::LocalFast => "local_fast",
            Self::PrivateBridge => "private_bridge",
            Self::ArchiveValidator => "archive_validator",
        }
    }

    pub fn from_name(profile_name: &str) -> ConfigResult<Self> {
        let normalized = profile_name
            .trim()
            .to_ascii_lowercase()
            .replace('-', "_")
            .replace(' ', "_");
        match normalized.as_str() {
            "devnet" | "default" | "devnet_default" => Ok(Self::Devnet),
            "local_fast" | "local" | "fast" => Ok(Self::LocalFast),
            "private_bridge" | "bridge" => Ok(Self::PrivateBridge),
            "archive_validator" | "archive" | "validator_archive" => Ok(Self::ArchiveValidator),
            _ => Err(format!("unknown Nebula network profile: {profile_name}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSettings {
    pub enabled: bool,
    pub lanes: Vec<LowFeeLane>,
    pub epoch_budget_units: u64,
    pub min_settled_fee_units: u64,
    pub max_rebate_bps: u64,
}

impl LowFeeSettings {
    pub fn enabled_default() -> Self {
        Self {
            enabled: true,
            lanes: vec![
                LowFeeLane::privacy_transfers(),
                LowFeeLane::monero_bridge_ops(),
                LowFeeLane::small_defi_calls(),
            ],
            epoch_budget_units: DEFAULT_LOW_FEE_BUDGET_UNITS,
            min_settled_fee_units: DEFAULT_LOW_FEE_MIN_SETTLED_FEE_UNITS,
            max_rebate_bps: DEFAULT_LOW_FEE_MAX_REBATE_BPS,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            lanes: Vec::new(),
            epoch_budget_units: 0,
            min_settled_fee_units: 0,
            max_rebate_bps: 0,
        }
    }

    pub fn lane_root(&self) -> String {
        let lane_records = self
            .lanes
            .iter()
            .map(LowFeeLane::public_record)
            .collect::<Vec<_>>();
        merkle_root("NEBULA-CONFIG-LOW-FEE-LANE", &lane_records)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_settings",
            "chain_id": CHAIN_ID,
            "enabled": self.enabled,
            "lane_root": self.lane_root(),
            "lanes": self.lanes.iter().map(LowFeeLane::public_record).collect::<Vec<_>>(),
            "epoch_budget_units": self.epoch_budget_units,
            "min_settled_fee_units": self.min_settled_fee_units,
            "max_rebate_bps": self.max_rebate_bps,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "NEBULA-CONFIG-LOW-FEE-SETTINGS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NebulaRuntimeProfile {
    pub profile_id: String,
    pub profile_root: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub operator_label: String,
    pub profile: NebulaNetworkProfile,
    pub node_roles: Vec<NodeRole>,
    pub daemon_mode: DaemonMode,
    pub sequencer_label: String,
    pub proposer_label: String,
    pub anchor_submitter_label: String,
    pub default_relay_path: String,
    pub epoch_size: u64,
    pub block_time_ms: u64,
    pub admission_ttl_blocks: u64,
    pub finality_depth: u64,
    pub block_packing_policy: BlockPackingPolicy,
    pub api_session_ttl_blocks: u64,
    pub api_request_ttl_blocks: u64,
    pub api_rate_limit_window_blocks: u64,
    pub api_rate_limit_units: u64,
    pub max_api_response_bytes: u64,
    pub max_pending_transactions: u64,
    pub storage_snapshot_interval_blocks: u64,
    pub storage_chunk_target_bytes: u64,
    pub storage_bounds: StorageBounds,
    pub data_dir_commitment: String,
    pub rpc_bind_commitment: String,
    pub p2p_bind_commitment: String,
    pub storage_policy_commitment: String,
    pub monero_network: String,
    pub privacy_mode: String,
    pub privacy_payload_policy: String,
    pub quantum_resistance_policy: String,
    pub defi_enabled: bool,
    pub low_fee: LowFeeSettings,
}

impl NebulaRuntimeProfile {
    pub fn devnet_default() -> Self {
        Self::base(NebulaNetworkProfile::Devnet, DEFAULT_OPERATOR_LABEL)
            .with_bind_commitments(DEFAULT_RPC_BIND, DEFAULT_P2P_BIND)
            .refresh_generated()
    }

    pub fn local_fast() -> Self {
        let mut policy = fast_block_packing_policy();
        policy.max_tx_count = 512;
        policy.max_execution_fuel = 16_000_000;
        policy.max_contract_call_count = 1_024;

        Self {
            profile: NebulaNetworkProfile::LocalFast,
            node_roles: canonical_roles(vec![
                NodeRole::Sequencer,
                NodeRole::Validator,
                NodeRole::Prover,
                NodeRole::DataAvailability,
                NodeRole::WalletRpc,
            ]),
            daemon_mode: DaemonMode::Devnet,
            epoch_size: 4,
            block_time_ms: 100,
            admission_ttl_blocks: 2,
            finality_depth: 3,
            block_packing_policy: policy,
            api_session_ttl_blocks: 250,
            api_request_ttl_blocks: 8,
            api_rate_limit_units: 10_000,
            max_api_response_bytes: 512 * 1024,
            max_pending_transactions: 2_048,
            storage_snapshot_interval_blocks: 5,
            storage_chunk_target_bytes: 512 * 1024,
            storage_bounds: StorageBounds {
                max_snapshots: 256,
                max_checkpoints: 256,
                max_chunks: 2_048,
                max_retention_decisions: 256,
                max_restore_plans: 128,
                retain_recent_heights: 64,
            },
            monero_network: "monero-regtest".to_string(),
            privacy_mode: DEFAULT_PRIVACY_MODE.to_string(),
            privacy_payload_policy: DEFAULT_PRIVACY_PAYLOAD_POLICY.to_string(),
            low_fee: LowFeeSettings {
                epoch_budget_units: DEFAULT_LOW_FEE_BUDGET_UNITS * 2,
                ..LowFeeSettings::enabled_default()
            },
            ..Self::base(NebulaNetworkProfile::LocalFast, DEFAULT_OPERATOR_LABEL)
        }
        .with_bind_commitments(LOCAL_FAST_RPC_BIND, LOCAL_FAST_P2P_BIND)
        .refresh_generated()
    }

    pub fn private_bridge() -> Self {
        let mut policy = fast_block_packing_policy();
        policy.max_batched_da_bytes = 1_024_000;
        policy.max_estimated_proof_bytes = 12 * 1024 * 1024;
        policy.lane_reserve_tx_count = 8;

        Self {
            profile: NebulaNetworkProfile::PrivateBridge,
            node_roles: canonical_roles(vec![
                NodeRole::Sequencer,
                NodeRole::Validator,
                NodeRole::DataAvailability,
                NodeRole::MoneroObserver,
                NodeRole::BridgeSigner,
                NodeRole::Watchtower,
            ]),
            daemon_mode: DaemonMode::Sequencer,
            epoch_size: 20,
            block_time_ms: TARGET_BLOCK_MS,
            admission_ttl_blocks: 8,
            finality_depth: 20,
            block_packing_policy: policy,
            api_session_ttl_blocks: 2_000,
            api_request_ttl_blocks: 20,
            api_rate_limit_units: 5_000,
            max_api_response_bytes: 512 * 1024,
            max_pending_transactions: 1_024,
            storage_snapshot_interval_blocks: 10,
            storage_chunk_target_bytes: 512 * 1024,
            monero_network: "monero-stagenet".to_string(),
            privacy_mode: RELAY_PRIVATE_PRIVACY_MODE.to_string(),
            privacy_payload_policy: CONFIDENTIAL_PRIVACY_PAYLOAD_POLICY.to_string(),
            low_fee: LowFeeSettings {
                epoch_budget_units: DEFAULT_LOW_FEE_BUDGET_UNITS * 4,
                max_rebate_bps: 9_800,
                ..LowFeeSettings::enabled_default()
            },
            ..Self::base(NebulaNetworkProfile::PrivateBridge, DEFAULT_OPERATOR_LABEL)
        }
        .with_bind_commitments(PRIVATE_BRIDGE_RPC_BIND, PRIVATE_BRIDGE_P2P_BIND)
        .refresh_generated()
    }

    pub fn archive_validator() -> Self {
        let mut policy = BlockPackingPolicy::default();
        policy.max_tx_count = 256;
        policy.min_fee_density_microunits = 0;
        policy.lane_reserve_tx_count = 4;

        Self {
            profile: NebulaNetworkProfile::ArchiveValidator,
            node_roles: canonical_roles(vec![
                NodeRole::Validator,
                NodeRole::Archive,
                NodeRole::DataAvailability,
                NodeRole::MoneroObserver,
                NodeRole::Watchtower,
            ]),
            daemon_mode: DaemonMode::Archive,
            epoch_size: 100,
            block_time_ms: TARGET_BLOCK_MS,
            admission_ttl_blocks: 10,
            finality_depth: 40,
            block_packing_policy: policy,
            api_session_ttl_blocks: 5_000,
            api_request_ttl_blocks: 40,
            api_rate_limit_units: 2_500,
            max_api_response_bytes: 2 * 1024 * 1024,
            max_pending_transactions: 4_096,
            storage_snapshot_interval_blocks: 10,
            storage_chunk_target_bytes: 1024 * 1024,
            storage_bounds: StorageBounds {
                max_snapshots: 16_384,
                max_checkpoints: 16_384,
                max_chunks: 262_144,
                max_retention_decisions: 16_384,
                max_restore_plans: 4_096,
                retain_recent_heights: 10_000,
            },
            monero_network: "monero-mainnet".to_string(),
            privacy_mode: CONFIDENTIAL_PRIVACY_MODE.to_string(),
            privacy_payload_policy: CONFIDENTIAL_PRIVACY_PAYLOAD_POLICY.to_string(),
            low_fee: LowFeeSettings {
                epoch_budget_units: DEFAULT_LOW_FEE_BUDGET_UNITS,
                ..LowFeeSettings::enabled_default()
            },
            ..Self::base(
                NebulaNetworkProfile::ArchiveValidator,
                DEFAULT_OPERATOR_LABEL,
            )
        }
        .with_bind_commitments(ARCHIVE_VALIDATOR_RPC_BIND, ARCHIVE_VALIDATOR_P2P_BIND)
        .refresh_generated()
    }

    pub fn from_profile_name(profile_name: &str) -> ConfigResult<Self> {
        match NebulaNetworkProfile::from_name(profile_name)? {
            NebulaNetworkProfile::Devnet => Ok(Self::devnet_default()),
            NebulaNetworkProfile::LocalFast => Ok(Self::local_fast()),
            NebulaNetworkProfile::PrivateBridge => Ok(Self::private_bridge()),
            NebulaNetworkProfile::ArchiveValidator => Ok(Self::archive_validator()),
        }
    }

    pub fn node_config(&self) -> ConfigResult<NodeConfig> {
        let mut config = NodeConfig::new(self.operator_label.clone(), self.node_roles.clone())?
            .with_commitments(
                self.data_dir_commitment.clone(),
                self.rpc_bind_commitment.clone(),
            );
        config.network_id = self.chain_id.clone();
        config.monero_network = self.monero_network.clone();
        config.max_pending_transactions = self.max_pending_transactions.max(1);
        config.snapshot_interval_blocks = self.storage_snapshot_interval_blocks.max(1);
        config.api_receipt_ttl_blocks = self.api_request_ttl_blocks.max(1);
        config.privacy_mode = self.privacy_mode.clone();
        Ok(config)
    }

    pub fn sequencer_config(&self) -> SequencerConfig {
        SequencerConfig {
            epoch_size: self.epoch_size.max(1),
            admission_ttl_blocks: self.admission_ttl_blocks.max(1),
            finality_depth: self.finality_depth.max(1),
            block_packing_policy: self.block_packing_policy.clone(),
            sequencer_label: self.sequencer_label.clone(),
            proposer_label: self.proposer_label.clone(),
            anchor_submitter_label: self.anchor_submitter_label.clone(),
            default_relay_path: self.default_relay_path.clone(),
        }
    }

    pub fn daemon_config(&self) -> ConfigResult<DaemonConfig> {
        let node_config = self.node_config()?;
        let mut config = DaemonConfig::new(
            self.operator_label.clone(),
            self.daemon_mode.clone(),
            node_config,
        );
        config.api_bind_commitment = self.rpc_bind_commitment.clone();
        config.storage_policy_commitment = self.storage_policy_commitment.clone();
        config.api_session_ttl_blocks = self.api_session_ttl_blocks.max(1);
        config.api_request_ttl_blocks = self.api_request_ttl_blocks.max(1);
        config.api_rate_limit_window_blocks = self.api_rate_limit_window_blocks.max(1);
        config.api_rate_limit_units = self.api_rate_limit_units.max(1);
        config.max_api_response_bytes = self.max_api_response_bytes.max(1);
        config.storage_snapshot_interval_blocks = self.storage_snapshot_interval_blocks.max(1);
        config.storage_chunk_target_bytes = self.storage_chunk_target_bytes.max(1);
        config.privacy_payload_policy = self.privacy_payload_policy.clone();
        config.daemon_id = daemon_id(
            &config.operator_label,
            config.mode.as_str(),
            &config.node_config.node_id,
            &config.api_bind_commitment,
            &config.storage_policy_commitment,
        );
        Ok(config)
    }

    pub fn storage_bounds(&self) -> StorageBounds {
        self.storage_bounds.clone()
    }

    pub fn public_record(&self) -> Value {
        let body = self.profile_body_record();
        let profile_id = runtime_profile_id(&body);
        let profile_root = runtime_profile_root(&json!({
            "profile_id": profile_id,
            "profile_body": body,
        }));
        json!({
            "kind": CONFIG_KIND_RUNTIME_PROFILE,
            "chain_id": CHAIN_ID,
            "profile_id": profile_id,
            "profile_root": profile_root,
            "profile_body": body,
        })
    }

    pub fn profile_root(&self) -> String {
        let body = self.profile_body_record();
        runtime_profile_root(&json!({
            "profile_id": runtime_profile_id(&body),
            "profile_body": body,
        }))
    }

    pub fn validation(&self) -> ConfigValidationReport {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if self.schema_version != CONFIG_SCHEMA_VERSION {
            errors.push(format!(
                "unsupported config schema version: {}",
                self.schema_version
            ));
        }
        if self.chain_id != CHAIN_ID {
            errors.push(format!("chain_id must be {CHAIN_ID}"));
        }
        if self.operator_label.trim().is_empty() {
            errors.push("operator_label is required".to_string());
        }
        if self.node_roles.is_empty() {
            errors.push("at least one node role is required".to_string());
        }
        if self.epoch_size == 0 {
            errors.push("epoch_size must be greater than zero".to_string());
        }
        if self.admission_ttl_blocks == 0 {
            errors.push("admission_ttl_blocks must be greater than zero".to_string());
        }
        if self.finality_depth == 0 {
            errors.push("finality_depth must be greater than zero".to_string());
        }
        if !(MIN_PROFILE_BLOCK_TIME_MS..=MAX_PROFILE_BLOCK_TIME_MS).contains(&self.block_time_ms) {
            errors.push(format!(
                "block_time_ms must be between {MIN_PROFILE_BLOCK_TIME_MS} and {MAX_PROFILE_BLOCK_TIME_MS}"
            ));
        }
        if self.block_time_ms != TARGET_BLOCK_MS {
            warnings.push(format!(
                "profile block_time_ms is {}, crate TARGET_BLOCK_MS is {}",
                self.block_time_ms, TARGET_BLOCK_MS
            ));
        }
        if self.monero_network.trim().is_empty() {
            errors.push("monero_network is required".to_string());
        }
        if !is_supported_privacy_mode(&self.privacy_mode) {
            errors.push(format!("unsupported privacy_mode: {}", self.privacy_mode));
        }
        if self.quantum_resistance_policy.trim().is_empty()
            || !self.quantum_resistance_policy.contains("ml-dsa")
            || !self.quantum_resistance_policy.contains("shake")
        {
            errors.push(
                "quantum_resistance_policy must commit to ML-DSA and SHAKE domain separation"
                    .to_string(),
            );
        }
        if self.low_fee.enabled && self.low_fee.lanes.is_empty() {
            errors.push("low_fee is enabled but no low fee lanes are configured".to_string());
        }
        if self.low_fee.max_rebate_bps > 10_000 {
            errors.push("low_fee max_rebate_bps cannot exceed 10000".to_string());
        }
        if self.storage_bounds.max_snapshots == 0
            || self.storage_bounds.max_checkpoints == 0
            || self.storage_bounds.max_chunks == 0
            || self.storage_bounds.retain_recent_heights == 0
        {
            errors.push(
                "storage bounds must retain non-zero snapshots, checkpoints, chunks, and heights"
                    .to_string(),
            );
        }
        if !self.defi_enabled {
            warnings.push("defi_enabled is false for a DeFi-oriented L2 profile".to_string());
        }

        let computed_profile_id = runtime_profile_id(&self.profile_body_record());
        let computed_profile_root = self.profile_root();
        if self.profile_id != computed_profile_id {
            errors.push("profile_id does not match deterministic profile body".to_string());
        }
        if self.profile_root != computed_profile_root {
            errors.push("profile_root does not match deterministic profile body".to_string());
        }

        ConfigValidationReport {
            valid: errors.is_empty(),
            profile_id: computed_profile_id,
            profile_root: computed_profile_root,
            errors,
            warnings,
        }
    }

    pub fn with_operator_label(mut self, operator_label: impl Into<String>) -> Self {
        self.operator_label = operator_label.into();
        self.sequencer_label = format!("{}-sequencer", self.operator_label);
        self.proposer_label = format!("{}-proposer", self.operator_label);
        self.anchor_submitter_label = format!("{}-anchor", self.operator_label);
        self.refresh_generated()
    }

    pub fn with_epoch_size(mut self, epoch_size: u64) -> Self {
        self.epoch_size = epoch_size.max(1);
        self.finality_depth = self
            .finality_depth
            .min(self.epoch_size.saturating_mul(2).max(1));
        self.refresh_generated()
    }

    pub fn with_block_time_ms(mut self, block_time_ms: u64) -> Self {
        self.block_time_ms =
            block_time_ms.clamp(MIN_PROFILE_BLOCK_TIME_MS, MAX_PROFILE_BLOCK_TIME_MS);
        self.refresh_generated()
    }

    pub fn with_storage_bounds(mut self, storage_bounds: StorageBounds) -> Self {
        self.storage_bounds = storage_bounds;
        self.refresh_generated()
    }

    pub fn with_privacy_mode(mut self, privacy_mode: impl Into<String>) -> Self {
        self.privacy_mode = privacy_mode.into();
        if self.privacy_mode == CONFIDENTIAL_PRIVACY_MODE
            || self.privacy_mode == RELAY_PRIVATE_PRIVACY_MODE
        {
            self.privacy_payload_policy = CONFIDENTIAL_PRIVACY_PAYLOAD_POLICY.to_string();
        } else {
            self.privacy_payload_policy = DEFAULT_PRIVACY_PAYLOAD_POLICY.to_string();
        }
        self.refresh_generated()
    }

    pub fn resolved(&self) -> ConfigResult<ConfigResolvedProfile> {
        ConfigResolvedProfile::from_profile(self.clone())
    }

    fn base(profile: NebulaNetworkProfile, operator_label: &str) -> Self {
        let mut packing_policy = BlockPackingPolicy::default();
        packing_policy.min_fee_density_microunits = 0;
        packing_policy.lane_reserve_tx_count = 4;

        let operator_label = if operator_label.trim().is_empty() {
            DEFAULT_OPERATOR_LABEL.to_string()
        } else {
            operator_label.to_string()
        };
        let storage_bounds = StorageBounds::default();
        let mut value = Self {
            profile_id: String::new(),
            profile_root: String::new(),
            schema_version: CONFIG_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            operator_label,
            profile,
            node_roles: canonical_roles(vec![
                NodeRole::Sequencer,
                NodeRole::Validator,
                NodeRole::Prover,
                NodeRole::Watchtower,
                NodeRole::DataAvailability,
                NodeRole::MoneroObserver,
                NodeRole::BridgeSigner,
                NodeRole::WalletRpc,
            ]),
            daemon_mode: DaemonMode::Devnet,
            sequencer_label: String::new(),
            proposer_label: String::new(),
            anchor_submitter_label: String::new(),
            default_relay_path: "direct".to_string(),
            epoch_size: 10,
            block_time_ms: TARGET_BLOCK_MS,
            admission_ttl_blocks: 5,
            finality_depth: 10,
            block_packing_policy: packing_policy,
            api_session_ttl_blocks: 1_000,
            api_request_ttl_blocks: 20,
            api_rate_limit_window_blocks: 10,
            api_rate_limit_units: 2_500,
            max_api_response_bytes: 256 * 1024,
            max_pending_transactions: 512,
            storage_snapshot_interval_blocks: 20,
            storage_chunk_target_bytes: 256 * 1024,
            storage_bounds,
            data_dir_commitment: String::new(),
            rpc_bind_commitment: config_string_root("rpc_bind", DEFAULT_RPC_BIND),
            p2p_bind_commitment: config_string_root("p2p_bind", DEFAULT_P2P_BIND),
            storage_policy_commitment: String::new(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            privacy_mode: DEFAULT_PRIVACY_MODE.to_string(),
            privacy_payload_policy: DEFAULT_PRIVACY_PAYLOAD_POLICY.to_string(),
            quantum_resistance_policy: DEFAULT_QUANTUM_RESISTANCE_POLICY.to_string(),
            defi_enabled: true,
            low_fee: LowFeeSettings::enabled_default(),
        };
        value.sequencer_label = format!("{}-sequencer", value.operator_label);
        value.proposer_label = format!("{}-proposer", value.operator_label);
        value.anchor_submitter_label = format!("{}-anchor", value.operator_label);
        value.refresh_generated()
    }

    fn with_bind_commitments(mut self, rpc_bind: &str, p2p_bind: &str) -> Self {
        self.rpc_bind_commitment = config_string_root("rpc_bind", rpc_bind);
        self.p2p_bind_commitment = config_string_root("p2p_bind", p2p_bind);
        self
    }

    fn refresh_generated(mut self) -> Self {
        self.node_roles = canonical_roles(self.node_roles.clone());
        self.data_dir_commitment = runtime_data_dir_commitment(&self.operator_label, self.profile);
        self.storage_policy_commitment = runtime_storage_policy_commitment(
            &self.operator_label,
            self.profile,
            &self.storage_bounds,
            self.storage_chunk_target_bytes,
            self.storage_snapshot_interval_blocks,
        );
        let body = self.profile_body_record();
        self.profile_id = runtime_profile_id(&body);
        self.profile_root = runtime_profile_root(&json!({
            "profile_id": self.profile_id,
            "profile_body": body,
        }));
        self
    }

    fn profile_body_record(&self) -> Value {
        let role_records = self
            .node_roles
            .iter()
            .map(NodeRole::public_record)
            .collect::<Vec<_>>();
        let role_root = merkle_root("NEBULA-CONFIG-NODE-ROLE", &role_records);

        json!({
            "kind": "nebula_runtime_profile_body",
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "crate_target_block_ms": TARGET_BLOCK_MS,
            "operator_label": self.operator_label,
            "profile": self.profile.as_str(),
            "node": {
                "roles": role_records,
                "role_root": role_root,
                "data_dir_commitment": self.data_dir_commitment,
                "rpc_bind_commitment": self.rpc_bind_commitment,
                "p2p_bind_commitment": self.p2p_bind_commitment,
                "max_pending_transactions": self.max_pending_transactions,
            },
            "sequencer": {
                "sequencer_label": self.sequencer_label,
                "proposer_label": self.proposer_label,
                "anchor_submitter_label": self.anchor_submitter_label,
                "default_relay_path": self.default_relay_path,
                "epoch_size": self.epoch_size,
                "block_time_ms": self.block_time_ms,
                "admission_ttl_blocks": self.admission_ttl_blocks,
                "finality_depth": self.finality_depth,
                "block_packing_policy": self.block_packing_policy.public_record(),
            },
            "daemon": {
                "mode": self.daemon_mode.as_str(),
                "api_session_ttl_blocks": self.api_session_ttl_blocks,
                "api_request_ttl_blocks": self.api_request_ttl_blocks,
                "api_rate_limit_window_blocks": self.api_rate_limit_window_blocks,
                "api_rate_limit_units": self.api_rate_limit_units,
                "max_api_response_bytes": self.max_api_response_bytes,
                "privacy_payload_policy": self.privacy_payload_policy,
            },
            "storage": {
                "bounds": self.storage_bounds.public_record(),
                "snapshot_interval_blocks": self.storage_snapshot_interval_blocks,
                "chunk_target_bytes": self.storage_chunk_target_bytes,
                "policy_commitment": self.storage_policy_commitment,
            },
            "monero_network": self.monero_network,
            "privacy_mode": self.privacy_mode,
            "quantum_resistance_policy": self.quantum_resistance_policy,
            "defi_enabled": self.defi_enabled,
            "low_fee": self.low_fee.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigOverride {
    pub override_id: String,
    pub profile_name: String,
    pub operator_label: Option<String>,
    pub epoch_size: Option<u64>,
    pub block_time_ms: Option<u64>,
    pub storage_bounds: Option<StorageBounds>,
    pub privacy_mode: Option<String>,
    pub monero_network: Option<String>,
    pub rpc_bind_commitment: Option<String>,
    pub p2p_bind_commitment: Option<String>,
    pub low_fee_enabled: Option<bool>,
    pub defi_enabled: Option<bool>,
}

impl ConfigOverride {
    pub fn new(profile_name: impl Into<String>) -> Self {
        Self {
            override_id: String::new(),
            profile_name: profile_name.into(),
            operator_label: None,
            epoch_size: None,
            block_time_ms: None,
            storage_bounds: None,
            privacy_mode: None,
            monero_network: None,
            rpc_bind_commitment: None,
            p2p_bind_commitment: None,
            low_fee_enabled: None,
            defi_enabled: None,
        }
        .refresh_id()
    }

    pub fn apply_to(&self, profile: NebulaRuntimeProfile) -> NebulaRuntimeProfile {
        let mut profile = if let Some(operator_label) = &self.operator_label {
            profile.with_operator_label(operator_label.clone())
        } else {
            profile
        };
        if let Some(epoch_size) = self.epoch_size {
            profile.epoch_size = epoch_size.max(1);
        }
        if let Some(block_time_ms) = self.block_time_ms {
            profile.block_time_ms =
                block_time_ms.clamp(MIN_PROFILE_BLOCK_TIME_MS, MAX_PROFILE_BLOCK_TIME_MS);
        }
        if let Some(storage_bounds) = &self.storage_bounds {
            profile.storage_bounds = storage_bounds.clone();
        }
        if let Some(privacy_mode) = &self.privacy_mode {
            profile.privacy_mode = privacy_mode.clone();
            if privacy_mode == CONFIDENTIAL_PRIVACY_MODE
                || privacy_mode == RELAY_PRIVATE_PRIVACY_MODE
            {
                profile.privacy_payload_policy = CONFIDENTIAL_PRIVACY_PAYLOAD_POLICY.to_string();
            } else {
                profile.privacy_payload_policy = DEFAULT_PRIVACY_PAYLOAD_POLICY.to_string();
            }
        }
        if let Some(monero_network) = &self.monero_network {
            profile.monero_network = monero_network.clone();
        }
        if let Some(rpc_bind_commitment) = &self.rpc_bind_commitment {
            profile.rpc_bind_commitment = rpc_bind_commitment.clone();
        }
        if let Some(p2p_bind_commitment) = &self.p2p_bind_commitment {
            profile.p2p_bind_commitment = p2p_bind_commitment.clone();
        }
        if let Some(low_fee_enabled) = self.low_fee_enabled {
            profile.low_fee.enabled = low_fee_enabled;
            if low_fee_enabled && profile.low_fee.lanes.is_empty() {
                profile.low_fee = LowFeeSettings::enabled_default();
            }
        }
        if let Some(defi_enabled) = self.defi_enabled {
            profile.defi_enabled = defi_enabled;
        }
        profile.refresh_generated()
    }

    pub fn public_record(&self) -> Value {
        let body = self.body_record();
        json!({
            "kind": "nebula_config_override",
            "chain_id": CHAIN_ID,
            "override_id": config_override_id(&body),
            "override_body": body,
        })
    }

    pub fn refresh_id(mut self) -> Self {
        self.override_id = config_override_id(&self.body_record());
        self
    }

    fn body_record(&self) -> Value {
        json!({
            "profile_name": self.profile_name,
            "operator_label": self.operator_label,
            "epoch_size": self.epoch_size,
            "block_time_ms": self.block_time_ms,
            "storage_bounds": self.storage_bounds.as_ref().map(StorageBounds::public_record),
            "privacy_mode": self.privacy_mode,
            "monero_network": self.monero_network,
            "rpc_bind_commitment": self.rpc_bind_commitment,
            "p2p_bind_commitment": self.p2p_bind_commitment,
            "low_fee_enabled": self.low_fee_enabled,
            "defi_enabled": self.defi_enabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigValidationReport {
    pub valid: bool,
    pub profile_id: String,
    pub profile_root: String,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ConfigValidationReport {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nebula_config_validation_report",
            "chain_id": CHAIN_ID,
            "valid": self.valid,
            "profile_id": self.profile_id,
            "profile_root": self.profile_root,
            "errors": self.errors,
            "warnings": self.warnings,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigResolvedProfile {
    pub resolved_root: String,
    pub profile: NebulaRuntimeProfile,
    pub node_config: NodeConfig,
    pub sequencer_config: SequencerConfig,
    pub daemon_config: DaemonConfig,
    pub storage_bounds: StorageBounds,
    pub validation: ConfigValidationReport,
}

impl ConfigResolvedProfile {
    pub fn from_profile(profile: NebulaRuntimeProfile) -> ConfigResult<Self> {
        let validation = profile.validation();
        if !validation.valid {
            return Err(validation.errors.join("; "));
        }
        let node_config = profile.node_config()?;
        let sequencer_config = profile.sequencer_config();
        let daemon_config = profile.daemon_config()?;
        let storage_bounds = profile.storage_bounds();
        let mut resolved = Self {
            resolved_root: String::new(),
            profile,
            node_config,
            sequencer_config,
            daemon_config,
            storage_bounds,
            validation,
        };
        resolved.resolved_root = resolved.root();
        Ok(resolved)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nebula_config_resolved_profile",
            "chain_id": CHAIN_ID,
            "resolved_root": self.resolved_root,
            "profile": self.profile.public_record(),
            "node_config": self.node_config.public_record(),
            "sequencer_config": {
                "epoch_size": self.sequencer_config.epoch_size,
                "admission_ttl_blocks": self.sequencer_config.admission_ttl_blocks,
                "finality_depth": self.sequencer_config.finality_depth,
                "block_packing_policy": self.sequencer_config.block_packing_policy.public_record(),
                "sequencer_label": self.sequencer_config.sequencer_label,
                "proposer_label": self.sequencer_config.proposer_label,
                "anchor_submitter_label": self.sequencer_config.anchor_submitter_label,
                "default_relay_path": self.sequencer_config.default_relay_path,
            },
            "daemon_config": self.daemon_config.public_record(),
            "storage_bounds": self.storage_bounds.public_record(),
            "validation": self.validation.public_record(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "NEBULA-CONFIG-RESOLVED-PROFILE-ROOT",
            &[HashPart::Json(&json!({
                "profile_root": self.profile.profile_root(),
                "node_config_root": self.node_config.config_root(),
                "daemon_config_root": self.daemon_config.config_root(),
                "storage_bounds": self.storage_bounds.public_record(),
                "validation": self.validation.public_record(),
            }))],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigManifest {
    pub manifest_root: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub default_profile: NebulaNetworkProfile,
    pub profiles: Vec<NebulaRuntimeProfile>,
}

impl ConfigManifest {
    pub fn new(
        default_profile: NebulaNetworkProfile,
        profiles: Vec<NebulaRuntimeProfile>,
    ) -> ConfigResult<Self> {
        if profiles.is_empty() {
            return Err("config manifest requires at least one profile".to_string());
        }
        let mut profiles = profiles
            .into_iter()
            .map(NebulaRuntimeProfile::refresh_generated)
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| {
            left.profile
                .cmp(&right.profile)
                .then_with(|| left.operator_label.cmp(&right.operator_label))
        });
        if !profiles
            .iter()
            .any(|profile| profile.profile == default_profile)
        {
            return Err(format!(
                "default profile {} is not present in manifest",
                default_profile.as_str()
            ));
        }
        let mut manifest = Self {
            manifest_root: String::new(),
            schema_version: CONFIG_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            default_profile,
            profiles,
        };
        manifest.manifest_root = manifest.root();
        Ok(manifest)
    }

    pub fn default_suite() -> ConfigResult<Self> {
        Self::new(
            NebulaNetworkProfile::Devnet,
            vec![
                NebulaRuntimeProfile::devnet_default(),
                NebulaRuntimeProfile::local_fast(),
                NebulaRuntimeProfile::private_bridge(),
                NebulaRuntimeProfile::archive_validator(),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": CONFIG_KIND_MANIFEST,
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "manifest_root": self.root(),
            "default_profile": self.default_profile.as_str(),
            "profiles": self.profiles.iter().map(NebulaRuntimeProfile::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn root(&self) -> String {
        config_manifest_root(&json!({
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "default_profile": self.default_profile.as_str(),
            "profile_roots": self.profiles.iter().map(NebulaRuntimeProfile::profile_root).collect::<Vec<_>>(),
        }))
    }

    pub fn profile(&self, profile_name: &str) -> ConfigResult<NebulaRuntimeProfile> {
        let profile_kind = NebulaNetworkProfile::from_name(profile_name)?;
        self.profiles
            .iter()
            .find(|profile| profile.profile == profile_kind)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "profile {} is not present in manifest",
                    profile_kind.as_str()
                )
            })
    }

    pub fn resolve(
        &self,
        profile_name: &str,
        config_override: Option<&ConfigOverride>,
    ) -> ConfigResult<ConfigResolvedProfile> {
        let profile = self.profile(profile_name)?;
        let profile = if let Some(config_override) = config_override {
            let override_profile = NebulaNetworkProfile::from_name(&config_override.profile_name)?;
            if override_profile != profile.profile {
                return Err(format!(
                    "override profile {} does not match requested profile {}",
                    override_profile.as_str(),
                    profile.profile.as_str()
                ));
            }
            config_override.apply_to(profile)
        } else {
            profile
        };
        ConfigResolvedProfile::from_profile(profile)
    }
}

pub fn runtime_profile_id(profile_body: &Value) -> String {
    domain_hash(
        "NEBULA-RUNTIME-PROFILE-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(profile_body)],
        32,
    )
}

pub fn runtime_profile_root(profile_record: &Value) -> String {
    domain_hash(
        "NEBULA-RUNTIME-PROFILE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(profile_record)],
        32,
    )
}

pub fn config_manifest_root(manifest_record: &Value) -> String {
    domain_hash(
        "NEBULA-CONFIG-MANIFEST-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(manifest_record)],
        32,
    )
}

pub fn config_override_id(override_record: &Value) -> String {
    domain_hash(
        "NEBULA-CONFIG-OVERRIDE-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(override_record)],
        32,
    )
}

pub fn config_string_root(label: &str, value: &str) -> String {
    domain_hash(
        "NEBULA-CONFIG-STRING-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
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

fn fast_block_packing_policy() -> BlockPackingPolicy {
    let mut policy = BlockPackingPolicy::default();
    policy.min_fee_density_microunits = 0;
    policy.lane_reserve_tx_count = 6;
    policy
}

fn runtime_data_dir_commitment(operator_label: &str, profile: NebulaNetworkProfile) -> String {
    domain_hash(
        "NEBULA-RUNTIME-DATA-DIR-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(profile.as_str()),
        ],
        32,
    )
}

fn runtime_storage_policy_commitment(
    operator_label: &str,
    profile: NebulaNetworkProfile,
    bounds: &StorageBounds,
    chunk_target_bytes: u64,
    snapshot_interval_blocks: u64,
) -> String {
    domain_hash(
        "NEBULA-RUNTIME-STORAGE-POLICY-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(profile.as_str()),
            HashPart::Json(&bounds.public_record()),
            HashPart::Int(chunk_target_bytes as i128),
            HashPart::Int(snapshot_interval_blocks as i128),
        ],
        32,
    )
}

fn is_supported_privacy_mode(privacy_mode: &str) -> bool {
    matches!(
        privacy_mode,
        DEFAULT_PRIVACY_MODE | CONFIDENTIAL_PRIVACY_MODE | RELAY_PRIVATE_PRIVACY_MODE
    )
}
