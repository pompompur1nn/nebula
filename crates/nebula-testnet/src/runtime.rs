use crate::{
    quote_hybrid_fee, FeeAsset, HybridFeeQuote, CHAIN_ID, NBLA_SYMBOL, NEBULAI_PER_NBLA,
    NXMR_SYMBOL, TARGET_NXMR_BASE_UNITS_PER_NXMR, TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT,
    VERSION,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_RPC_BIND_ADDR: &str = "127.0.0.1:9944";
pub const DEFAULT_SUBSECOND_BLOCK_MS: u64 = 250;
pub const MAX_PUBLIC_TESTNET_BLOCK_MS: u64 = 999;
pub const DEFAULT_GAS_PRICE_NEBULAI: u128 = 1;
pub const DEFAULT_MAX_BLOCK_TRANSACTIONS: usize = 512;
pub const DEFAULT_FAUCET_NBLA: u128 = 10_000 * NEBULAI_PER_NBLA;
pub const DEFAULT_FAUCET_NXMR: u128 = 10_000 * TARGET_NXMR_BASE_UNITS_PER_NXMR;
pub const MIN_BRIDGE_CONFIRMATIONS: u64 = 10;
pub const MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM: usize = 2;
pub const MIN_WITHDRAWAL_OPERATOR_QUORUM: usize = 2;
pub const BRIDGE_CUSTODY_POLICY_ID: &str = "nebula-monero-bridge-custody-testnet-v1";
pub const VALIDATOR_REWARD_ACCOUNT_PREFIX: &str = "validator:";
pub const RUNTIME_SNAPSHOT_FILE: &str = "nebula-runtime-snapshot.json";
pub const RUNTIME_SNAPSHOT_VERSION: u32 = 4;
pub const DEFAULT_PEER_SYNC_MS: u64 = 100;
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 1_048_576;
pub const DEFAULT_MAX_REQUESTS_PER_MINUTE: u32 = 600;
const RPC_RATE_LIMIT_WINDOW_MS: u128 = 60_000;
pub const DEFAULT_DEV_SEQUENCER_SECRET_KEY_HEX: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[derive(Debug, Clone)]
pub struct RuntimeNodeOptions {
    pub data_dir: Option<String>,
    pub bootstrap_rpc_url: Option<String>,
    pub sync_rpc_url: Option<String>,
    pub sync_rpc_urls: Vec<String>,
    pub sequencer_secret_key_hex: Option<String>,
    pub max_request_bytes: usize,
    pub max_requests_per_minute: u32,
}

impl Default for RuntimeNodeOptions {
    fn default() -> Self {
        Self {
            data_dir: None,
            bootstrap_rpc_url: None,
            sync_rpc_url: None,
            sync_rpc_urls: Vec::new(),
            sequencer_secret_key_hex: None,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_requests_per_minute: DEFAULT_MAX_REQUESTS_PER_MINUTE,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub chain_id: String,
    pub runtime_version: String,
    pub validator_id: String,
    pub block_target_ms: u64,
    pub gas_price_nebulai: u128,
    pub max_block_transactions: usize,
    pub faucet_nbla_nebulai: u128,
    pub faucet_nxmr_units: u128,
    pub produce_blocks: bool,
    pub sequencer_public_key_hex: String,
}

impl RuntimeConfig {
    pub fn public_testnet_default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            runtime_version: VERSION.to_string(),
            validator_id: "validator-a".to_string(),
            block_target_ms: DEFAULT_SUBSECOND_BLOCK_MS,
            gas_price_nebulai: DEFAULT_GAS_PRICE_NEBULAI,
            max_block_transactions: DEFAULT_MAX_BLOCK_TRANSACTIONS,
            faucet_nbla_nebulai: DEFAULT_FAUCET_NBLA,
            faucet_nxmr_units: DEFAULT_FAUCET_NXMR,
            produce_blocks: true,
            sequencer_public_key_hex: default_dev_sequencer_public_key_hex(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id.trim().is_empty() {
            return Err("chain_id must not be empty".to_string());
        }
        if self.validator_id.trim().is_empty() {
            return Err("validator_id must not be empty".to_string());
        }
        if self.block_target_ms == 0 {
            return Err("block_target_ms must be greater than zero".to_string());
        }
        if self.block_target_ms > MAX_PUBLIC_TESTNET_BLOCK_MS {
            return Err(format!(
                "block_target_ms must be <= {MAX_PUBLIC_TESTNET_BLOCK_MS} for public testnet"
            ));
        }
        if self.gas_price_nebulai == 0 {
            return Err("gas_price_nebulai must be greater than zero".to_string());
        }
        if self.max_block_transactions == 0 {
            return Err("max_block_transactions must be greater than zero".to_string());
        }
        validate_fixed_hex(
            &self.sequencer_public_key_hex,
            "sequencer_public_key_hex",
            64,
        )?;
        Ok(())
    }

    pub fn validator_reward_account(&self) -> String {
        format!("{VALIDATOR_REWARD_ACCOUNT_PREFIX}{}", self.validator_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAccount {
    pub nbla_nebulai: u128,
    pub nxmr_units: u128,
    pub nonce: u64,
    pub validator_points: u128,
}

impl RuntimeAccount {
    pub fn empty() -> Self {
        Self {
            nbla_nebulai: 0,
            nxmr_units: 0,
            nonce: 0,
            validator_points: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTransaction {
    pub from: String,
    pub to: String,
    pub amount_nebulai: u128,
    pub gas_units: u128,
    pub gas_price_nebulai: u128,
    pub fee_asset: String,
    pub nonce: u64,
    #[serde(default)]
    pub memo: Option<String>,
}

impl RuntimeTransaction {
    pub fn fee_asset_kind(&self) -> Result<FeeAsset, String> {
        parse_fee_asset(&self.fee_asset)
    }

    pub fn id(&self) -> String {
        stable_runtime_root(&json!({
            "tx_domain": "nebula-runtime-transaction-v1",
            "from": self.from,
            "to": self.to,
            "amount_nebulai": self.amount_nebulai,
            "gas_units": self.gas_units,
            "gas_price_nebulai": self.gas_price_nebulai,
            "fee_asset": self.fee_asset,
            "nonce": self.nonce,
            "memo": self.memo,
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Pending,
    Included,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReceipt {
    pub tx_id: String,
    pub status: TransactionStatus,
    pub block_height: Option<u64>,
    pub fee_asset: String,
    pub paid_amount_units: u128,
    pub validator_reward_nebulai: u128,
    pub buyback_nebulai: u128,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBridgeDeposit {
    pub monero_tx_id: String,
    pub account: String,
    pub amount_nxmr_units: u128,
    pub confirmations: u64,
    pub observer_id: String,
    pub proof_root: String,
    pub custody_proof_root: String,
    pub relayer_set_root: String,
    pub observer_signature_roots: Vec<String>,
    pub observed_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWithdrawalRequest {
    pub withdrawal_id: String,
    pub account: String,
    pub monero_address: String,
    pub amount_nxmr_units: u128,
    pub requested_at_unix_ms: u128,
    pub status: String,
    pub bridge_policy_root: String,
    pub operator_approval_roots: Vec<String>,
    pub finalized_monero_tx_id: Option<String>,
    pub finalization_proof_root: Option<String>,
    pub finalized_at_unix_ms: Option<u128>,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSequencerKeyRotation {
    pub activation_height: u64,
    pub old_public_key_hex: String,
    pub new_public_key_hex: String,
    pub operator_id: String,
    pub approval_root: String,
    pub rotated_at_unix_ms: u128,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAccountabilityReport {
    pub report_id: String,
    pub height: u64,
    pub first_block_hash: String,
    pub second_block_hash: String,
    pub reporter_id: String,
    pub evidence_root: String,
    pub reported_at_unix_ms: u128,
    pub root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSnapshot {
    pub snapshot_version: u32,
    pub exported_at_unix_ms: u128,
    pub config: RuntimeConfig,
    pub state_root: String,
    pub accounts: BTreeMap<String, RuntimeAccount>,
    pub mempool: Vec<RuntimeTransaction>,
    pub receipts: BTreeMap<String, RuntimeReceipt>,
    pub bridge_deposits: BTreeMap<String, RuntimeBridgeDeposit>,
    pub withdrawals: BTreeMap<String, RuntimeWithdrawalRequest>,
    pub blocks: Vec<RuntimeBlock>,
    pub total_nxmr_fees_units: u128,
    pub buyback_pool_nebulai: u128,
    pub validator_reward_nebulai: u128,
    pub sequencer_key_rotations: Vec<RuntimeSequencerKeyRotation>,
    pub accountability_reports: Vec<RuntimeAccountabilityReport>,
    pub root: String,
}

impl RuntimeSnapshot {
    pub fn latest_height(&self) -> u64 {
        self.blocks.last().map(|block| block.height).unwrap_or(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBlock {
    pub height: u64,
    pub parent_hash: String,
    pub timestamp_unix_ms: u128,
    pub producer: String,
    pub producer_public_key: String,
    pub transactions: Vec<RuntimeTransaction>,
    pub rejected_tx_ids: Vec<String>,
    pub tx_root: String,
    pub state_root: String,
    pub block_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FaucetReport {
    pub account: String,
    pub credited_nbla_nebulai: u128,
    pub credited_nxmr_units: u128,
    pub account_state: RuntimeAccount,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub chain_id: String,
    pub runtime_version: String,
    pub latest_height: u64,
    pub latest_hash: String,
    pub latest_state_root: String,
    pub current_state_root: String,
    pub block_target_ms: u64,
    pub sub_second_blocks: bool,
    pub block_production_enabled: bool,
    pub node_role: String,
    pub sequencer_public_key_hex: String,
    pub sequencer_key_rotation_count: usize,
    pub sequencer_latest_rotation_activation_height: Option<u64>,
    pub sequencer_key_history_root: String,
    pub accountability_report_count: usize,
    pub accountability_root: String,
    pub sequencer_accountability_clean: bool,
    pub mempool_size: usize,
    pub account_count: usize,
    pub bridge_deposit_count: usize,
    pub withdrawal_request_count: usize,
    pub finalized_withdrawal_count: usize,
    pub total_nxmr_fees_units: u128,
    pub buyback_pool_nebulai: u128,
    pub validator_reward_nebulai: u128,
    pub validator_reward_account: String,
    pub bridge_policy_root: String,
    pub bridge_min_deposit_confirmations: u64,
    pub bridge_deposit_observer_quorum: usize,
    pub bridge_withdrawal_operator_quorum: usize,
    pub bridge_live_value_enabled: bool,
    pub bridge_replay_cache_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeBridgePolicy {
    pub policy_id: &'static str,
    pub custody_model: &'static str,
    pub min_deposit_confirmations: u64,
    pub min_deposit_observer_quorum: usize,
    pub min_withdrawal_operator_quorum: usize,
    pub replay_protection: &'static str,
    pub live_value_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeOpsStatus {
    pub service: String,
    pub generated_at_unix_ms: u128,
    pub chain_id: String,
    pub runtime_version: String,
    pub node_role: String,
    pub latest_height: u64,
    pub latest_hash: String,
    pub latest_block_age_ms: u128,
    pub block_target_ms: u64,
    pub sub_second_blocks: bool,
    pub block_production_enabled: bool,
    pub snapshot_version: u32,
    pub snapshot_root: String,
    pub state_root: String,
    pub current_state_root: String,
    pub storage_snapshot_path: Option<String>,
    pub storage_snapshot_present: bool,
    pub storage_snapshot_root: Option<String>,
    pub storage_snapshot_height: Option<u64>,
    pub storage_snapshot_matches_runtime: bool,
    pub sync_peer_count: usize,
    pub rpc_max_request_bytes: usize,
    pub rpc_max_requests_per_minute: u32,
    pub sequencer_public_key_hex: String,
    pub sequencer_key_rotation_count: usize,
    pub sequencer_latest_rotation_activation_height: Option<u64>,
    pub sequencer_key_history_root: String,
    pub accountability_report_count: usize,
    pub accountability_root: String,
    pub sequencer_accountability_clean: bool,
    pub bridge_policy_root: String,
    pub bridge_live_value_enabled: bool,
    pub public_ops_ready: bool,
    pub blocking_gaps: Vec<String>,
    pub ops_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeBackupManifest {
    pub manifest_version: u32,
    pub generated_at_unix_ms: u128,
    pub chain_id: String,
    pub runtime_version: String,
    pub latest_height: u64,
    pub latest_hash: String,
    pub snapshot_version: u32,
    pub snapshot_root: String,
    pub state_root: String,
    pub current_state_root: String,
    pub snapshot_path: Option<String>,
    pub snapshot_persisted: bool,
    pub storage_snapshot_root: Option<String>,
    pub storage_snapshot_matches_runtime: bool,
    pub sequencer_public_key_hex: String,
    pub sequencer_key_rotation_count: usize,
    pub sequencer_latest_rotation_activation_height: Option<u64>,
    pub sequencer_key_history_root: String,
    pub accountability_report_count: usize,
    pub accountability_root: String,
    pub sequencer_accountability_clean: bool,
    pub bridge_policy_root: String,
    pub sync_peer_count: usize,
    pub rpc_max_request_bytes: usize,
    pub rpc_max_requests_per_minute: u32,
    pub backup_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubmitTransactionReport {
    pub accepted_to_mempool: bool,
    pub tx_id: String,
    pub status: TransactionStatus,
    pub mempool_size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BridgeDepositReport {
    pub credited: bool,
    pub monero_tx_id: String,
    pub account: String,
    pub amount_nxmr_units: u128,
    pub confirmations: u64,
    pub deposit_root: String,
    pub account_state: RuntimeAccount,
}

#[derive(Debug, Clone, Serialize)]
pub struct WithdrawalReport {
    pub accepted: bool,
    pub withdrawal: RuntimeWithdrawalRequest,
    pub account_state: RuntimeAccount,
}

#[derive(Debug, Clone, Serialize)]
pub struct WithdrawalFinalizationReport {
    pub finalized: bool,
    pub withdrawal: RuntimeWithdrawalRequest,
    pub operator_approval_count: usize,
    pub finalization_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SequencerKeyRotationReport {
    pub rotated: bool,
    pub rotation: RuntimeSequencerKeyRotation,
    pub sequencer_public_key_hex: String,
    pub sequencer_key_history_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountabilityReportReceipt {
    pub recorded: bool,
    pub report: RuntimeAccountabilityReport,
    pub accountability_root: String,
    pub sequencer_accountability_clean: bool,
}

#[derive(Debug, Clone)]
pub struct NebulaRuntime {
    config: RuntimeConfig,
    sequencer_secret_key_hex: Option<String>,
    accounts: BTreeMap<String, RuntimeAccount>,
    mempool: VecDeque<RuntimeTransaction>,
    receipts: BTreeMap<String, RuntimeReceipt>,
    bridge_deposits: BTreeMap<String, RuntimeBridgeDeposit>,
    withdrawals: BTreeMap<String, RuntimeWithdrawalRequest>,
    blocks: Vec<RuntimeBlock>,
    total_nxmr_fees_units: u128,
    buyback_pool_nebulai: u128,
    validator_reward_nebulai: u128,
    sequencer_key_rotations: Vec<RuntimeSequencerKeyRotation>,
    accountability_reports: Vec<RuntimeAccountabilityReport>,
}

#[derive(Debug, Clone)]
pub struct RuntimeStorage {
    snapshot_path: PathBuf,
}

#[derive(Clone)]
struct RuntimeRpcState {
    runtime: Arc<Mutex<NebulaRuntime>>,
    storage: Option<RuntimeStorage>,
    rpc_limits: RuntimeRpcLimits,
    sync_peers: RuntimeSyncPeerSet,
    rate_limits: Arc<Mutex<BTreeMap<String, RuntimeRateLimitBucket>>>,
}

#[derive(Debug, Clone, Copy, Serialize)]
struct RuntimeRpcLimits {
    max_request_bytes: usize,
    max_requests_per_minute: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
struct RuntimeSyncPeerSet {
    bootstrap_peer_urls: Vec<String>,
    sync_peer_urls: Vec<String>,
}

#[derive(Debug, Clone)]
struct RuntimeRateLimitBucket {
    window_start_unix_ms: u128,
    request_count: u32,
}

impl RuntimeRpcState {
    fn persist(&self) -> Result<(), String> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "runtime mutex poisoned".to_string())?;
        storage.save_runtime(&runtime)
    }

    fn check_request_allowed(&self, client_id: &str) -> Result<(), String> {
        if self.rpc_limits.max_requests_per_minute == 0 {
            return Err("max_requests_per_minute must be greater than zero".to_string());
        }
        let now = unix_ms();
        let mut buckets = self
            .rate_limits
            .lock()
            .map_err(|_| "rate limit mutex poisoned".to_string())?;
        let bucket =
            buckets
                .entry(client_id.to_string())
                .or_insert_with(|| RuntimeRateLimitBucket {
                    window_start_unix_ms: now,
                    request_count: 0,
                });
        if now.saturating_sub(bucket.window_start_unix_ms) >= RPC_RATE_LIMIT_WINDOW_MS {
            bucket.window_start_unix_ms = now;
            bucket.request_count = 0;
        }
        if bucket.request_count >= self.rpc_limits.max_requests_per_minute {
            return Err(format!(
                "rate limit exceeded for {client_id}: max {} requests per minute",
                self.rpc_limits.max_requests_per_minute
            ));
        }
        bucket.request_count = bucket
            .request_count
            .checked_add(1)
            .ok_or_else(|| "rate limit counter overflowed".to_string())?;
        Ok(())
    }

    fn status_json(&self) -> Result<Value, String> {
        let status = {
            let runtime = self
                .runtime
                .lock()
                .map_err(|_| "runtime mutex poisoned".to_string())?;
            runtime.status()
        };
        let mut status = serde_json::to_value(status)
            .map_err(|error| format!("status serialization failed: {error}"))?;
        let Value::Object(fields) = &mut status else {
            return Err("runtime status did not serialize as an object".to_string());
        };
        fields.insert(
            "rpc_max_request_bytes".to_string(),
            json!(self.rpc_limits.max_request_bytes),
        );
        fields.insert(
            "rpc_max_requests_per_minute".to_string(),
            json!(self.rpc_limits.max_requests_per_minute),
        );
        fields.insert(
            "bootstrap_peer_urls".to_string(),
            json!(self.sync_peers.bootstrap_peer_urls),
        );
        fields.insert(
            "sync_peer_urls".to_string(),
            json!(self.sync_peers.sync_peer_urls),
        );
        fields.insert(
            "sync_peer_count".to_string(),
            json!(self.sync_peers.sync_peer_urls.len()),
        );
        Ok(status)
    }

    fn ops_status(&self) -> Result<RuntimeOpsStatus, String> {
        let generated_at_unix_ms = unix_ms();
        let (status, snapshot) = {
            let runtime = self
                .runtime
                .lock()
                .map_err(|_| "runtime mutex poisoned".to_string())?;
            (runtime.status(), runtime.export_snapshot())
        };
        let storage_snapshot = match &self.storage {
            Some(storage) => storage.load_snapshot()?,
            None => None,
        };
        let storage_snapshot_path = self
            .storage
            .as_ref()
            .map(|storage| storage.snapshot_path().display().to_string());
        let storage_snapshot_root = storage_snapshot
            .as_ref()
            .map(|snapshot| snapshot.root.clone());
        let storage_snapshot_height = storage_snapshot
            .as_ref()
            .map(RuntimeSnapshot::latest_height);
        let storage_snapshot_matches_runtime = storage_snapshot
            .as_ref()
            .map(|persisted| {
                persisted.latest_height() == snapshot.latest_height()
                    && persisted
                        .blocks
                        .last()
                        .map(|block| block.block_hash.as_str())
                        == snapshot
                            .blocks
                            .last()
                            .map(|block| block.block_hash.as_str())
                    && persisted.state_root == snapshot.state_root
            })
            .unwrap_or(false);
        let latest_timestamp_unix_ms = snapshot
            .blocks
            .last()
            .map(|block| block.timestamp_unix_ms)
            .unwrap_or(generated_at_unix_ms);
        let latest_block_age_ms = generated_at_unix_ms.saturating_sub(latest_timestamp_unix_ms);
        let mut blocking_gaps = Vec::new();
        if !status.sub_second_blocks {
            blocking_gaps.push("block-target-not-sub-second".to_string());
        }
        if status.latest_height == 0 {
            blocking_gaps.push("no-produced-blocks-observed".to_string());
        }
        let max_acceptable_age_ms = u128::from(status.block_target_ms)
            .saturating_mul(20)
            .max(5_000);
        if latest_block_age_ms > max_acceptable_age_ms {
            blocking_gaps.push("latest-block-stale".to_string());
        }
        if self.storage.is_none() {
            blocking_gaps.push("missing-persistent-data-dir".to_string());
        }
        if self.storage.is_some() && storage_snapshot.is_none() {
            blocking_gaps.push("missing-persisted-snapshot".to_string());
        }
        if self.storage.is_some() && storage_snapshot.is_some() && !storage_snapshot_matches_runtime
        {
            blocking_gaps.push("persisted-snapshot-mismatch".to_string());
        }
        if status.node_role == "follower" && self.sync_peers.sync_peer_urls.is_empty() {
            blocking_gaps.push("follower-missing-sync-peers".to_string());
        }
        if bridge_policy().live_value_enabled {
            blocking_gaps.push("bridge-live-value-enabled".to_string());
        }
        if !status.sequencer_accountability_clean {
            blocking_gaps.push("sequencer-accountability-evidence-open".to_string());
        }
        let mut report = RuntimeOpsStatus {
            service: "nebula-testnet-rpc".to_string(),
            generated_at_unix_ms,
            chain_id: status.chain_id,
            runtime_version: status.runtime_version,
            node_role: status.node_role,
            latest_height: status.latest_height,
            latest_hash: status.latest_hash,
            latest_block_age_ms,
            block_target_ms: status.block_target_ms,
            sub_second_blocks: status.sub_second_blocks,
            block_production_enabled: status.block_production_enabled,
            snapshot_version: snapshot.snapshot_version,
            snapshot_root: snapshot.root.clone(),
            state_root: snapshot.state_root.clone(),
            current_state_root: status.current_state_root,
            storage_snapshot_path,
            storage_snapshot_present: storage_snapshot.is_some(),
            storage_snapshot_root,
            storage_snapshot_height,
            storage_snapshot_matches_runtime,
            sync_peer_count: self.sync_peers.sync_peer_urls.len(),
            rpc_max_request_bytes: self.rpc_limits.max_request_bytes,
            rpc_max_requests_per_minute: self.rpc_limits.max_requests_per_minute,
            sequencer_public_key_hex: status.sequencer_public_key_hex,
            sequencer_key_rotation_count: status.sequencer_key_rotation_count,
            sequencer_latest_rotation_activation_height: status
                .sequencer_latest_rotation_activation_height,
            sequencer_key_history_root: status.sequencer_key_history_root,
            accountability_report_count: status.accountability_report_count,
            accountability_root: status.accountability_root,
            sequencer_accountability_clean: status.sequencer_accountability_clean,
            bridge_policy_root: bridge_policy_root(),
            bridge_live_value_enabled: bridge_policy().live_value_enabled,
            public_ops_ready: blocking_gaps.is_empty(),
            blocking_gaps,
            ops_root: String::new(),
        };
        report.ops_root = ops_status_root(&report);
        Ok(report)
    }

    fn backup_manifest(&self) -> Result<RuntimeBackupManifest, String> {
        let ops_status = self.ops_status()?;
        let mut manifest = RuntimeBackupManifest {
            manifest_version: 1,
            generated_at_unix_ms: ops_status.generated_at_unix_ms,
            chain_id: ops_status.chain_id,
            runtime_version: ops_status.runtime_version,
            latest_height: ops_status.latest_height,
            latest_hash: ops_status.latest_hash,
            snapshot_version: ops_status.snapshot_version,
            snapshot_root: ops_status.snapshot_root,
            state_root: ops_status.state_root,
            current_state_root: ops_status.current_state_root,
            snapshot_path: ops_status.storage_snapshot_path,
            snapshot_persisted: ops_status.storage_snapshot_present,
            storage_snapshot_root: ops_status.storage_snapshot_root,
            storage_snapshot_matches_runtime: ops_status.storage_snapshot_matches_runtime,
            sequencer_public_key_hex: ops_status.sequencer_public_key_hex,
            sequencer_key_rotation_count: ops_status.sequencer_key_rotation_count,
            sequencer_latest_rotation_activation_height: ops_status
                .sequencer_latest_rotation_activation_height,
            sequencer_key_history_root: ops_status.sequencer_key_history_root,
            accountability_report_count: ops_status.accountability_report_count,
            accountability_root: ops_status.accountability_root,
            sequencer_accountability_clean: ops_status.sequencer_accountability_clean,
            bridge_policy_root: ops_status.bridge_policy_root,
            sync_peer_count: ops_status.sync_peer_count,
            rpc_max_request_bytes: ops_status.rpc_max_request_bytes,
            rpc_max_requests_per_minute: ops_status.rpc_max_requests_per_minute,
            backup_root: String::new(),
        };
        manifest.backup_root = backup_manifest_root(&manifest);
        Ok(manifest)
    }
}

impl RuntimeRpcLimits {
    fn from_options(options: &RuntimeNodeOptions) -> Result<Self, String> {
        if options.max_request_bytes == 0 {
            return Err("max_request_bytes must be greater than zero".to_string());
        }
        if options.max_requests_per_minute == 0 {
            return Err("max_requests_per_minute must be greater than zero".to_string());
        }
        Ok(Self {
            max_request_bytes: options.max_request_bytes,
            max_requests_per_minute: options.max_requests_per_minute,
        })
    }
}

impl RuntimeSyncPeerSet {
    fn from_options(options: &RuntimeNodeOptions) -> Result<Self, String> {
        Ok(Self {
            bootstrap_peer_urls: collect_peer_urls(
                options.bootstrap_rpc_url.as_deref(),
                &[],
                "--bootstrap-rpc",
            )?,
            sync_peer_urls: collect_peer_urls(
                options.sync_rpc_url.as_deref(),
                &options.sync_rpc_urls,
                "--sync-rpc",
            )?,
        })
    }
}

impl RuntimeStorage {
    pub fn from_data_dir(data_dir: impl AsRef<Path>) -> Self {
        Self {
            snapshot_path: data_dir.as_ref().join(RUNTIME_SNAPSHOT_FILE),
        }
    }

    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    pub fn load_snapshot(&self) -> Result<Option<RuntimeSnapshot>, String> {
        if !self.snapshot_path.exists() {
            return Ok(None);
        }
        let input = fs::read_to_string(&self.snapshot_path).map_err(|error| {
            format!(
                "failed to read runtime snapshot {}: {error}",
                self.snapshot_path.display()
            )
        })?;
        let snapshot = serde_json::from_str::<RuntimeSnapshot>(&input).map_err(|error| {
            format!(
                "failed to parse runtime snapshot {}: {error}",
                self.snapshot_path.display()
            )
        })?;
        validate_snapshot(&snapshot)?;
        Ok(Some(snapshot))
    }

    pub fn save_snapshot(&self, snapshot: &RuntimeSnapshot) -> Result<(), String> {
        validate_snapshot(snapshot)?;
        let parent = self
            .snapshot_path
            .parent()
            .ok_or_else(|| "snapshot path must have a parent directory".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create data dir {}: {error}", parent.display()))?;
        let temp_path = self.snapshot_path.with_extension("json.tmp");
        let output = serde_json::to_string_pretty(snapshot)
            .map_err(|error| format!("failed to serialize runtime snapshot: {error}"))?;
        fs::write(&temp_path, output)
            .map_err(|error| format!("failed to write {}: {error}", temp_path.display()))?;
        if self.snapshot_path.exists() {
            fs::remove_file(&self.snapshot_path).map_err(|error| {
                format!(
                    "failed to replace existing snapshot {}: {error}",
                    self.snapshot_path.display()
                )
            })?;
        }
        fs::rename(&temp_path, &self.snapshot_path).map_err(|error| {
            format!(
                "failed to promote snapshot {} to {}: {error}",
                temp_path.display(),
                self.snapshot_path.display()
            )
        })?;
        Ok(())
    }

    pub fn save_runtime(&self, runtime: &NebulaRuntime) -> Result<(), String> {
        self.save_snapshot(&runtime.export_snapshot())
    }
}

impl NebulaRuntime {
    pub fn new(config: RuntimeConfig) -> Result<Self, String> {
        Self::with_sequencer_secret(config, None)
    }

    pub fn with_sequencer_secret(
        config: RuntimeConfig,
        sequencer_secret_key_hex: Option<String>,
    ) -> Result<Self, String> {
        let (config, sequencer_secret_key_hex) =
            prepare_runtime_config(config, sequencer_secret_key_hex)?;

        let mut runtime = Self {
            config,
            sequencer_secret_key_hex,
            accounts: BTreeMap::new(),
            mempool: VecDeque::new(),
            receipts: BTreeMap::new(),
            bridge_deposits: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            blocks: Vec::new(),
            total_nxmr_fees_units: 0,
            buyback_pool_nebulai: 0,
            validator_reward_nebulai: 0,
            sequencer_key_rotations: Vec::new(),
            accountability_reports: Vec::new(),
        };
        runtime.accounts.insert(
            runtime.config.validator_reward_account(),
            RuntimeAccount::empty(),
        );
        runtime.blocks.push(runtime.genesis_block()?);
        Ok(runtime)
    }

    pub fn from_snapshot(config: RuntimeConfig, snapshot: RuntimeSnapshot) -> Result<Self, String> {
        Self::from_snapshot_with_sequencer_secret(config, snapshot, None)
    }

    pub fn from_snapshot_with_sequencer_secret(
        config: RuntimeConfig,
        snapshot: RuntimeSnapshot,
        sequencer_secret_key_hex: Option<String>,
    ) -> Result<Self, String> {
        let (mut config, mut sequencer_secret_key_hex) =
            prepare_runtime_config(config, sequencer_secret_key_hex)?;
        validate_snapshot(&snapshot)?;
        if snapshot.config.chain_id != config.chain_id {
            return Err(format!(
                "snapshot chain_id {} does not match local chain_id {}",
                snapshot.config.chain_id, config.chain_id
            ));
        }
        if snapshot.config.runtime_version != config.runtime_version {
            return Err(format!(
                "snapshot runtime_version {} does not match local runtime_version {}",
                snapshot.config.runtime_version, config.runtime_version
            ));
        }
        let local_sequencer_public_key_hex = config.sequencer_public_key_hex.clone();
        if !snapshot_accepts_local_sequencer_key(&config, &snapshot) {
            return Err(format!(
                "snapshot sequencer_public_key_hex {} does not match local sequencer_public_key_hex {}",
                snapshot.config.sequencer_public_key_hex, local_sequencer_public_key_hex
            ));
        }
        config.sequencer_public_key_hex = snapshot.config.sequencer_public_key_hex.clone();
        if let Some(secret_key_hex) = sequencer_secret_key_hex.as_deref() {
            let derived_public_key = public_key_hex_for_secret(secret_key_hex)?;
            if !derived_public_key.eq_ignore_ascii_case(&config.sequencer_public_key_hex) {
                if config.produce_blocks {
                    return Err(format!(
                        "sequencer_secret_key_hex derives public key {derived_public_key}, expected {}",
                        config.sequencer_public_key_hex
                    ));
                }
                sequencer_secret_key_hex = None;
            }
        }
        config.gas_price_nebulai = snapshot.config.gas_price_nebulai;
        config.max_block_transactions = snapshot.config.max_block_transactions;
        config.faucet_nbla_nebulai = snapshot.config.faucet_nbla_nebulai;
        config.faucet_nxmr_units = snapshot.config.faucet_nxmr_units;

        let mut runtime = Self {
            config,
            sequencer_secret_key_hex,
            accounts: snapshot.accounts,
            mempool: snapshot.mempool.into(),
            receipts: snapshot.receipts,
            bridge_deposits: snapshot.bridge_deposits,
            withdrawals: snapshot.withdrawals,
            blocks: snapshot.blocks,
            total_nxmr_fees_units: snapshot.total_nxmr_fees_units,
            buyback_pool_nebulai: snapshot.buyback_pool_nebulai,
            validator_reward_nebulai: snapshot.validator_reward_nebulai,
            sequencer_key_rotations: snapshot.sequencer_key_rotations,
            accountability_reports: snapshot.accountability_reports,
        };
        runtime
            .accounts
            .entry(runtime.config.validator_reward_account())
            .or_insert_with(RuntimeAccount::empty);
        Ok(runtime)
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    pub fn export_snapshot(&self) -> RuntimeSnapshot {
        let mut snapshot = RuntimeSnapshot {
            snapshot_version: RUNTIME_SNAPSHOT_VERSION,
            exported_at_unix_ms: unix_ms(),
            config: self.config.clone(),
            state_root: self.state_root(),
            accounts: self.accounts.clone(),
            mempool: self.mempool.iter().cloned().collect(),
            receipts: self.receipts.clone(),
            bridge_deposits: self.bridge_deposits.clone(),
            withdrawals: self.withdrawals.clone(),
            blocks: self.blocks.clone(),
            total_nxmr_fees_units: self.total_nxmr_fees_units,
            buyback_pool_nebulai: self.buyback_pool_nebulai,
            validator_reward_nebulai: self.validator_reward_nebulai,
            sequencer_key_rotations: self.sequencer_key_rotations.clone(),
            accountability_reports: self.accountability_reports.clone(),
            root: String::new(),
        };
        snapshot.root = snapshot_root(&snapshot);
        snapshot
    }

    pub fn import_snapshot(&mut self, snapshot: RuntimeSnapshot) -> Result<(), String> {
        let local_config = self.config.clone();
        let replacement = Self::from_snapshot_with_sequencer_secret(
            local_config,
            snapshot,
            self.sequencer_secret_key_hex.clone(),
        )?;
        *self = replacement;
        Ok(())
    }

    pub fn status(&self) -> RuntimeStatus {
        let latest = self
            .blocks
            .last()
            .expect("runtime always has a genesis block");
        let finalized_withdrawal_count = self
            .withdrawals
            .values()
            .filter(|withdrawal| withdrawal.status == "finalized")
            .count();
        RuntimeStatus {
            chain_id: self.config.chain_id.clone(),
            runtime_version: self.config.runtime_version.clone(),
            latest_height: latest.height,
            latest_hash: latest.block_hash.clone(),
            latest_state_root: latest.state_root.clone(),
            current_state_root: self.state_root(),
            block_target_ms: self.config.block_target_ms,
            sub_second_blocks: self.config.block_target_ms <= MAX_PUBLIC_TESTNET_BLOCK_MS,
            block_production_enabled: self.config.produce_blocks,
            node_role: if self.config.produce_blocks {
                "sequencer".to_string()
            } else {
                "follower".to_string()
            },
            sequencer_public_key_hex: self.config.sequencer_public_key_hex.clone(),
            sequencer_key_rotation_count: self.sequencer_key_rotations.len(),
            sequencer_latest_rotation_activation_height: self
                .sequencer_key_rotations
                .last()
                .map(|rotation| rotation.activation_height),
            sequencer_key_history_root: sequencer_key_history_root(&self.sequencer_key_rotations),
            accountability_report_count: self.accountability_reports.len(),
            accountability_root: accountability_root(&self.accountability_reports),
            sequencer_accountability_clean: self.accountability_reports.is_empty(),
            mempool_size: self.mempool.len(),
            account_count: self.accounts.len(),
            bridge_deposit_count: self.bridge_deposits.len(),
            withdrawal_request_count: self.withdrawals.len(),
            finalized_withdrawal_count,
            total_nxmr_fees_units: self.total_nxmr_fees_units,
            buyback_pool_nebulai: self.buyback_pool_nebulai,
            validator_reward_nebulai: self.validator_reward_nebulai,
            validator_reward_account: self.config.validator_reward_account(),
            bridge_policy_root: bridge_policy_root(),
            bridge_min_deposit_confirmations: MIN_BRIDGE_CONFIRMATIONS,
            bridge_deposit_observer_quorum: MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM,
            bridge_withdrawal_operator_quorum: MIN_WITHDRAWAL_OPERATOR_QUORUM,
            bridge_live_value_enabled: bridge_policy().live_value_enabled,
            bridge_replay_cache_count: self.bridge_deposits.len() + finalized_withdrawal_count,
        }
    }

    pub fn faucet(&mut self, account: &str) -> Result<FaucetReport, String> {
        validate_account_id(account)?;
        let state = self
            .accounts
            .entry(account.to_string())
            .or_insert_with(RuntimeAccount::empty);
        state.nbla_nebulai = state
            .nbla_nebulai
            .checked_add(self.config.faucet_nbla_nebulai)
            .ok_or_else(|| "faucet NBLA credit overflowed".to_string())?;
        state.nxmr_units = state
            .nxmr_units
            .checked_add(self.config.faucet_nxmr_units)
            .ok_or_else(|| "faucet nXMR credit overflowed".to_string())?;
        Ok(FaucetReport {
            account: account.to_string(),
            credited_nbla_nebulai: self.config.faucet_nbla_nebulai,
            credited_nxmr_units: self.config.faucet_nxmr_units,
            account_state: state.clone(),
        })
    }

    pub fn account(&self, account: &str) -> Option<RuntimeAccount> {
        self.accounts.get(account).cloned()
    }

    pub fn submit_transaction(
        &mut self,
        tx: RuntimeTransaction,
    ) -> Result<SubmitTransactionReport, String> {
        validate_transaction_shape(&tx)?;
        let tx_id = tx.id();
        if self.receipts.contains_key(&tx_id)
            || self.mempool.iter().any(|pending| pending.id() == tx_id)
        {
            return Err(format!("transaction {tx_id} already exists"));
        }
        self.receipts.insert(
            tx_id.clone(),
            RuntimeReceipt {
                tx_id: tx_id.clone(),
                status: TransactionStatus::Pending,
                block_height: None,
                fee_asset: tx.fee_asset.clone(),
                paid_amount_units: 0,
                validator_reward_nebulai: 0,
                buyback_nebulai: 0,
                error: None,
            },
        );
        self.mempool.push_back(tx);
        Ok(SubmitTransactionReport {
            accepted_to_mempool: true,
            tx_id,
            status: TransactionStatus::Pending,
            mempool_size: self.mempool.len(),
        })
    }

    pub fn receipt(&self, tx_id: &str) -> Option<RuntimeReceipt> {
        self.receipts.get(tx_id).cloned()
    }

    pub fn observe_bridge_deposit(
        &mut self,
        deposit: RuntimeBridgeDeposit,
    ) -> Result<BridgeDepositReport, String> {
        validate_bridge_deposit(&deposit)?;
        if self.bridge_deposits.contains_key(&deposit.monero_tx_id) {
            return Err(format!(
                "bridge deposit {} already observed",
                deposit.monero_tx_id
            ));
        }
        if deposit.confirmations < MIN_BRIDGE_CONFIRMATIONS {
            return Err(format!(
                "bridge deposit requires at least {MIN_BRIDGE_CONFIRMATIONS} confirmations"
            ));
        }
        let account = self
            .accounts
            .entry(deposit.account.clone())
            .or_insert_with(RuntimeAccount::empty);
        account.nxmr_units = account
            .nxmr_units
            .checked_add(deposit.amount_nxmr_units)
            .ok_or_else(|| "bridge deposit nXMR credit overflowed".to_string())?;
        let account_state = account.clone();
        let deposit_root = bridge_deposit_root(&deposit);
        self.bridge_deposits
            .insert(deposit.monero_tx_id.clone(), deposit.clone());
        Ok(BridgeDepositReport {
            credited: true,
            monero_tx_id: deposit.monero_tx_id,
            account: deposit.account,
            amount_nxmr_units: deposit.amount_nxmr_units,
            confirmations: deposit.confirmations,
            deposit_root,
            account_state,
        })
    }

    pub fn request_withdrawal(
        &mut self,
        account: &str,
        monero_address: &str,
        amount_nxmr_units: u128,
    ) -> Result<WithdrawalReport, String> {
        validate_account_id(account)?;
        validate_monero_address(monero_address)?;
        if amount_nxmr_units == 0 {
            return Err("amount_nxmr_units must be greater than zero".to_string());
        }
        let state = self
            .accounts
            .get_mut(account)
            .ok_or_else(|| format!("account {account} does not exist"))?;
        if state.nxmr_units < amount_nxmr_units {
            return Err(format!(
                "insufficient nXMR balance: need {amount_nxmr_units}, have {}",
                state.nxmr_units
            ));
        }
        state.nxmr_units -= amount_nxmr_units;
        let account_state = state.clone();
        let requested_at_unix_ms = unix_ms();
        let withdrawal_id = stable_runtime_root(&json!({
            "withdrawal_id_domain": "nebula-runtime-withdrawal-id-v1",
            "account": account,
            "monero_address": monero_address,
            "amount_nxmr_units": amount_nxmr_units,
            "requested_at_unix_ms": requested_at_unix_ms,
            "withdrawal_index": self.withdrawals.len(),
        }));
        let mut withdrawal = RuntimeWithdrawalRequest {
            withdrawal_id,
            account: account.to_string(),
            monero_address: monero_address.to_string(),
            amount_nxmr_units,
            requested_at_unix_ms,
            status: "operator_pending".to_string(),
            bridge_policy_root: bridge_policy_root(),
            operator_approval_roots: Vec::new(),
            finalized_monero_tx_id: None,
            finalization_proof_root: None,
            finalized_at_unix_ms: None,
            root: String::new(),
        };
        withdrawal.root = withdrawal_root(&withdrawal);
        self.withdrawals
            .insert(withdrawal.withdrawal_id.clone(), withdrawal.clone());
        Ok(WithdrawalReport {
            accepted: true,
            withdrawal,
            account_state,
        })
    }

    pub fn finalize_withdrawal(
        &mut self,
        withdrawal_id: &str,
        finalized_monero_tx_id: &str,
        finalization_proof_root: &str,
        operator_approval_roots: Vec<String>,
    ) -> Result<WithdrawalFinalizationReport, String> {
        validate_fixed_hex(finalized_monero_tx_id, "finalized_monero_tx_id", 64)?;
        validate_fixed_hex(finalization_proof_root, "finalization_proof_root", 64)?;
        validate_quorum_roots(
            &operator_approval_roots,
            "operator_approval_roots",
            MIN_WITHDRAWAL_OPERATOR_QUORUM,
        )?;
        if self.withdrawals.values().any(|withdrawal| {
            withdrawal
                .finalized_monero_tx_id
                .as_deref()
                .map(|tx_id| tx_id.eq_ignore_ascii_case(finalized_monero_tx_id))
                .unwrap_or(false)
        }) {
            return Err(format!(
                "withdrawal Monero tx {finalized_monero_tx_id} already finalized"
            ));
        }
        if self
            .bridge_deposits
            .keys()
            .any(|monero_tx_id| monero_tx_id.eq_ignore_ascii_case(finalized_monero_tx_id))
        {
            return Err(format!(
                "withdrawal Monero tx {finalized_monero_tx_id} reuses a deposit tx id"
            ));
        }
        if self.withdrawals.values().any(|withdrawal| {
            withdrawal
                .finalization_proof_root
                .as_deref()
                .map(|proof_root| proof_root.eq_ignore_ascii_case(finalization_proof_root))
                .unwrap_or(false)
        }) {
            return Err(format!(
                "withdrawal finalization proof {finalization_proof_root} already used"
            ));
        }
        let withdrawal = self
            .withdrawals
            .get_mut(withdrawal_id)
            .ok_or_else(|| format!("withdrawal {withdrawal_id} not found"))?;
        if withdrawal.status != "operator_pending" {
            return Err(format!(
                "withdrawal {withdrawal_id} status {} cannot be finalized",
                withdrawal.status
            ));
        }
        withdrawal.status = "finalized".to_string();
        withdrawal.operator_approval_roots = operator_approval_roots;
        withdrawal.finalized_monero_tx_id = Some(finalized_monero_tx_id.to_ascii_lowercase());
        withdrawal.finalization_proof_root = Some(finalization_proof_root.to_ascii_lowercase());
        withdrawal.finalized_at_unix_ms = Some(unix_ms());
        withdrawal.root = withdrawal_root(withdrawal);
        validate_withdrawal(withdrawal)?;
        Ok(WithdrawalFinalizationReport {
            finalized: true,
            withdrawal: withdrawal.clone(),
            operator_approval_count: withdrawal.operator_approval_roots.len(),
            finalization_root: withdrawal.root.clone(),
        })
    }

    pub fn rotate_sequencer_key(
        &mut self,
        new_sequencer_secret_key_hex: &str,
        operator_id: &str,
        approval_root: &str,
    ) -> Result<SequencerKeyRotationReport, String> {
        if !self.config.produce_blocks {
            return Err("sequencer key rotation requires block production mode".to_string());
        }
        validate_account_id(operator_id)?;
        let approval_root = normalize_fixed_hex(approval_root, "approval_root", 64)?;
        let new_sequencer_secret_key_hex = normalize_fixed_hex(
            new_sequencer_secret_key_hex,
            "new_sequencer_secret_key_hex",
            64,
        )?;
        let new_public_key_hex = public_key_hex_for_secret(&new_sequencer_secret_key_hex)?;
        if new_public_key_hex.eq_ignore_ascii_case(&self.config.sequencer_public_key_hex) {
            return Err("new sequencer key must differ from current key".to_string());
        }
        let latest_height = self.latest_block().height;
        if self
            .sequencer_key_rotations
            .last()
            .map(|rotation| rotation.activation_height > latest_height)
            .unwrap_or(false)
        {
            return Err("a sequencer key rotation is already pending activation".to_string());
        }
        let mut rotation = RuntimeSequencerKeyRotation {
            activation_height: latest_height
                .checked_add(1)
                .ok_or_else(|| "activation_height overflowed".to_string())?,
            old_public_key_hex: self.config.sequencer_public_key_hex.clone(),
            new_public_key_hex,
            operator_id: operator_id.to_string(),
            approval_root,
            rotated_at_unix_ms: unix_ms(),
            root: String::new(),
        };
        rotation.root = sequencer_key_rotation_root(&rotation);
        validate_sequencer_key_rotation(&rotation)?;
        self.config.sequencer_public_key_hex = rotation.new_public_key_hex.clone();
        self.sequencer_secret_key_hex = Some(new_sequencer_secret_key_hex);
        self.sequencer_key_rotations.push(rotation.clone());
        Ok(SequencerKeyRotationReport {
            rotated: true,
            rotation,
            sequencer_public_key_hex: self.config.sequencer_public_key_hex.clone(),
            sequencer_key_history_root: sequencer_key_history_root(&self.sequencer_key_rotations),
        })
    }

    pub fn report_equivocation(
        &mut self,
        height: u64,
        first_block_hash: &str,
        second_block_hash: &str,
        reporter_id: &str,
        evidence_root: &str,
    ) -> Result<AccountabilityReportReceipt, String> {
        if height == 0 {
            return Err("height must be greater than zero".to_string());
        }
        let first_block_hash = normalize_fixed_hex(first_block_hash, "first_block_hash", 64)?;
        let second_block_hash = normalize_fixed_hex(second_block_hash, "second_block_hash", 64)?;
        if first_block_hash.eq_ignore_ascii_case(&second_block_hash) {
            return Err("first_block_hash and second_block_hash must differ".to_string());
        }
        validate_account_id(reporter_id)?;
        let evidence_root = normalize_fixed_hex(evidence_root, "evidence_root", 64)?;
        let report_id = accountability_report_id(
            height,
            &first_block_hash,
            &second_block_hash,
            reporter_id,
            &evidence_root,
        );
        if self
            .accountability_reports
            .iter()
            .any(|report| report.report_id.eq_ignore_ascii_case(&report_id))
        {
            return Err(format!("accountability report {report_id} already exists"));
        }
        let mut report = RuntimeAccountabilityReport {
            report_id,
            height,
            first_block_hash,
            second_block_hash,
            reporter_id: reporter_id.to_string(),
            evidence_root,
            reported_at_unix_ms: unix_ms(),
            root: String::new(),
        };
        report.root = accountability_report_root(&report);
        validate_accountability_report(&report)?;
        self.accountability_reports.push(report.clone());
        Ok(AccountabilityReportReceipt {
            recorded: true,
            report,
            accountability_root: accountability_root(&self.accountability_reports),
            sequencer_accountability_clean: self.accountability_reports.is_empty(),
        })
    }

    pub fn block_by_height(&self, height: u64) -> Option<RuntimeBlock> {
        self.blocks
            .iter()
            .find(|block| block.height == height)
            .cloned()
    }

    pub fn latest_block(&self) -> RuntimeBlock {
        self.blocks
            .last()
            .expect("runtime always has a genesis block")
            .clone()
    }

    pub fn quote_fee(
        &self,
        fee_asset: &str,
        gas_units: u128,
        gas_price_nebulai: Option<u128>,
    ) -> Result<HybridFeeQuote, String> {
        let asset = parse_fee_asset(fee_asset)?;
        quote_hybrid_fee(
            asset,
            gas_units,
            gas_price_nebulai.unwrap_or(self.config.gas_price_nebulai),
            Some(TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT),
        )
        .map_err(|error| format!("{error:?}"))
    }

    pub fn produce_block(&mut self) -> RuntimeBlock {
        self.try_produce_block()
            .expect("sequencer block production must have a valid signing key")
    }

    pub fn try_produce_block(&mut self) -> Result<RuntimeBlock, String> {
        let parent = self.latest_block();
        let height = parent.height + 1;
        let mut included = Vec::new();
        let mut rejected_tx_ids = Vec::new();

        for _ in 0..self.config.max_block_transactions {
            let Some(tx) = self.mempool.pop_front() else {
                break;
            };
            let tx_id = tx.id();
            match self.apply_transaction(&tx, height) {
                Ok(receipt) => {
                    self.receipts.insert(tx_id, receipt);
                    included.push(tx);
                }
                Err(error) => {
                    self.receipts.insert(
                        tx_id.clone(),
                        RuntimeReceipt {
                            tx_id: tx_id.clone(),
                            status: TransactionStatus::Rejected,
                            block_height: Some(height),
                            fee_asset: tx.fee_asset.clone(),
                            paid_amount_units: 0,
                            validator_reward_nebulai: 0,
                            buyback_nebulai: 0,
                            error: Some(error),
                        },
                    );
                    rejected_tx_ids.push(tx_id);
                }
            }
        }

        let tx_root = transaction_root(&included, &rejected_tx_ids);
        let state_root = self.state_root();
        let mut block = RuntimeBlock {
            height,
            parent_hash: parent.block_hash,
            timestamp_unix_ms: unix_ms(),
            producer: self.config.validator_id.clone(),
            producer_public_key: self.config.sequencer_public_key_hex.clone(),
            transactions: included,
            rejected_tx_ids,
            tx_root,
            state_root,
            block_hash: String::new(),
            signature: String::new(),
        };
        self.finalize_block(&mut block)?;
        self.blocks.push(block.clone());
        Ok(block)
    }

    fn genesis_block(&self) -> Result<RuntimeBlock, String> {
        let mut block = RuntimeBlock {
            height: 0,
            parent_hash: "0".repeat(64),
            timestamp_unix_ms: unix_ms(),
            producer: self.config.validator_id.clone(),
            producer_public_key: self.config.sequencer_public_key_hex.clone(),
            transactions: Vec::new(),
            rejected_tx_ids: Vec::new(),
            tx_root: transaction_root(&[], &[]),
            state_root: self.state_root(),
            block_hash: String::new(),
            signature: String::new(),
        };
        self.finalize_block(&mut block)?;
        Ok(block)
    }

    fn finalize_block(&self, block: &mut RuntimeBlock) -> Result<(), String> {
        let Some(secret_key_hex) = self.sequencer_secret_key_hex.as_deref() else {
            return Err(
                "sequencer_secret_key_hex is required to produce signed blocks".to_string(),
            );
        };
        block.producer_public_key = self.config.sequencer_public_key_hex.clone();
        block.block_hash = block_root(block);
        block.signature = sign_block_hash(&block.block_hash, secret_key_hex)?;
        Ok(())
    }

    fn apply_transaction(
        &mut self,
        tx: &RuntimeTransaction,
        block_height: u64,
    ) -> Result<RuntimeReceipt, String> {
        validate_transaction_shape(tx)?;
        let asset = tx.fee_asset_kind()?;
        let quote = quote_hybrid_fee(
            asset,
            tx.gas_units,
            tx.gas_price_nebulai,
            Some(TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT),
        )
        .map_err(|error| format!("{error:?}"))?;
        let sender = self
            .accounts
            .get(&tx.from)
            .cloned()
            .ok_or_else(|| format!("sender {} does not exist", tx.from))?;
        if sender.nonce != tx.nonce {
            return Err(format!(
                "sender nonce expected {} but got {}",
                sender.nonce, tx.nonce
            ));
        }

        let mut next_sender = sender;
        match asset {
            FeeAsset::Nbla => {
                let debit = tx
                    .amount_nebulai
                    .checked_add(quote.paid_amount_units)
                    .ok_or_else(|| "NBLA debit overflowed".to_string())?;
                if next_sender.nbla_nebulai < debit {
                    return Err(format!(
                        "insufficient NBLA balance: need {debit}, have {}",
                        next_sender.nbla_nebulai
                    ));
                }
                next_sender.nbla_nebulai -= debit;
            }
            FeeAsset::NXmr => {
                if next_sender.nbla_nebulai < tx.amount_nebulai {
                    return Err(format!(
                        "insufficient NBLA balance: need {}, have {}",
                        tx.amount_nebulai, next_sender.nbla_nebulai
                    ));
                }
                if next_sender.nxmr_units < quote.paid_amount_units {
                    return Err(format!(
                        "insufficient nXMR balance: need {}, have {}",
                        quote.paid_amount_units, next_sender.nxmr_units
                    ));
                }
                next_sender.nbla_nebulai -= tx.amount_nebulai;
                next_sender.nxmr_units -= quote.paid_amount_units;
                self.total_nxmr_fees_units = self
                    .total_nxmr_fees_units
                    .checked_add(quote.paid_amount_units)
                    .ok_or_else(|| "nXMR fee accounting overflowed".to_string())?;
                self.buyback_pool_nebulai = self
                    .buyback_pool_nebulai
                    .checked_add(quote.reserve_backing_nebulai)
                    .ok_or_else(|| "NBLA buyback accounting overflowed".to_string())?;
            }
        }
        next_sender.nonce = next_sender
            .nonce
            .checked_add(1)
            .ok_or_else(|| "sender nonce overflowed".to_string())?;
        self.accounts.insert(tx.from.clone(), next_sender);

        let recipient = self
            .accounts
            .entry(tx.to.clone())
            .or_insert_with(RuntimeAccount::empty);
        recipient.nbla_nebulai = recipient
            .nbla_nebulai
            .checked_add(tx.amount_nebulai)
            .ok_or_else(|| "recipient NBLA credit overflowed".to_string())?;

        let reward_account_id = self.config.validator_reward_account();
        let reward_account = self
            .accounts
            .entry(reward_account_id)
            .or_insert_with(RuntimeAccount::empty);
        reward_account.nbla_nebulai = reward_account
            .nbla_nebulai
            .checked_add(quote.validator_reward_nebulai)
            .ok_or_else(|| "validator reward credit overflowed".to_string())?;
        reward_account.validator_points = reward_account
            .validator_points
            .checked_add(quote.validator_points)
            .ok_or_else(|| "validator points overflowed".to_string())?;
        self.validator_reward_nebulai = self
            .validator_reward_nebulai
            .checked_add(quote.validator_reward_nebulai)
            .ok_or_else(|| "validator reward accounting overflowed".to_string())?;

        Ok(RuntimeReceipt {
            tx_id: tx.id(),
            status: TransactionStatus::Included,
            block_height: Some(block_height),
            fee_asset: tx.fee_asset.clone(),
            paid_amount_units: quote.paid_amount_units,
            validator_reward_nebulai: quote.validator_reward_nebulai,
            buyback_nebulai: quote.reserve_backing_nebulai,
            error: None,
        })
    }

    fn state_root(&self) -> String {
        stable_runtime_root(&json!({
            "state_domain": "nebula-runtime-state-v1",
            "accounts": self.accounts,
            "bridge_deposits": self.bridge_deposits,
            "withdrawals": self.withdrawals,
            "total_nxmr_fees_units": self.total_nxmr_fees_units,
            "buyback_pool_nebulai": self.buyback_pool_nebulai,
            "validator_reward_nebulai": self.validator_reward_nebulai,
        }))
    }
}

pub fn serve_runtime_rpc(bind_addr: &str, config: RuntimeConfig) -> std::io::Result<()> {
    serve_runtime_rpc_with_options(bind_addr, config, RuntimeNodeOptions::default())
}

pub fn serve_runtime_rpc_with_options(
    bind_addr: &str,
    config: RuntimeConfig,
    options: RuntimeNodeOptions,
) -> std::io::Result<()> {
    let rpc_limits = RuntimeRpcLimits::from_options(&options).map_err(std::io::Error::other)?;
    let sync_peers = RuntimeSyncPeerSet::from_options(&options).map_err(std::io::Error::other)?;
    let storage = options.data_dir.as_ref().map(RuntimeStorage::from_data_dir);
    let startup_bootstrap_peers = if sync_peers.bootstrap_peer_urls.is_empty() {
        sync_peers.sync_peer_urls.clone()
    } else {
        sync_peers.bootstrap_peer_urls.clone()
    };
    let runtime = load_runtime_for_node(
        config,
        storage.as_ref(),
        &startup_bootstrap_peers,
        options.sequencer_secret_key_hex.clone(),
    )
    .map_err(std::io::Error::other)?;
    if let Some(storage) = &storage {
        storage
            .save_runtime(&runtime)
            .map_err(std::io::Error::other)?;
    }

    let block_target = Duration::from_millis(runtime.config.block_target_ms);
    let state = RuntimeRpcState {
        runtime: Arc::new(Mutex::new(runtime)),
        storage,
        rpc_limits,
        sync_peers,
        rate_limits: Arc::new(Mutex::new(BTreeMap::new())),
    };
    let produce_blocks = state
        .runtime
        .lock()
        .map(|runtime| runtime.config.produce_blocks)
        .unwrap_or(false);
    if produce_blocks {
        let producer_state = state.clone();
        thread::spawn(move || loop {
            thread::sleep(block_target);
            if let Ok(mut runtime) = producer_state.runtime.lock() {
                let _ = runtime.try_produce_block();
            }
            let _ = producer_state.persist();
        });
    }
    if !state.sync_peers.sync_peer_urls.is_empty() {
        let sync_state = state.clone();
        let sync_rpc_urls = state.sync_peers.sync_peer_urls.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(DEFAULT_PEER_SYNC_MS));
            let _ = sync_runtime_from_peers(&sync_state, &sync_rpc_urls);
        });
    }

    let listener = TcpListener::bind(bind_addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = state.clone();
                thread::spawn(move || {
                    let _ = handle_http_connection(stream, state);
                });
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn load_runtime_for_node(
    config: RuntimeConfig,
    storage: Option<&RuntimeStorage>,
    bootstrap_rpc_urls: &[String],
    sequencer_secret_key_hex: Option<String>,
) -> Result<NebulaRuntime, String> {
    let local_snapshot = match storage {
        Some(storage) => storage.load_snapshot()?,
        None => None,
    };
    let (bootstrap_snapshots, fetch_errors) = fetch_runtime_snapshots(bootstrap_rpc_urls);
    if local_snapshot.is_none() && bootstrap_snapshots.is_empty() && !bootstrap_rpc_urls.is_empty()
    {
        return Err(format!(
            "no bootstrap peer returned a usable snapshot: {}",
            fetch_errors.join("; ")
        ));
    }
    let selected = select_bootstrap_snapshot(&config, local_snapshot, bootstrap_snapshots)?;

    match selected {
        Some(snapshot) => NebulaRuntime::from_snapshot_with_sequencer_secret(
            config,
            snapshot,
            sequencer_secret_key_hex,
        ),
        None => NebulaRuntime::with_sequencer_secret(config, sequencer_secret_key_hex),
    }
}

fn snapshot_extends(local: &RuntimeSnapshot, peer: &RuntimeSnapshot) -> bool {
    if local.config.chain_id != peer.config.chain_id {
        return false;
    }
    if local.blocks.len() > peer.blocks.len() {
        return false;
    }
    local
        .blocks
        .iter()
        .zip(peer.blocks.iter())
        .all(|(local_block, peer_block)| local_block.block_hash == peer_block.block_hash)
}

fn select_bootstrap_snapshot(
    config: &RuntimeConfig,
    local_snapshot: Option<RuntimeSnapshot>,
    peer_snapshots: Vec<(String, RuntimeSnapshot)>,
) -> Result<Option<RuntimeSnapshot>, String> {
    match local_snapshot {
        Some(local) => {
            let selected = select_best_extending_snapshot(&local, peer_snapshots)?;
            Ok(selected.map(|(_, snapshot)| snapshot).or(Some(local)))
        }
        None => {
            if peer_snapshots.is_empty() {
                return Ok(None);
            }
            let mut selected: Option<(String, RuntimeSnapshot)> = None;
            let mut rejected = Vec::new();
            for (url, snapshot) in peer_snapshots {
                if let Err(error) = snapshot_matches_config(config, &snapshot) {
                    rejected.push(format!("{url}: {error}"));
                    continue;
                }
                if selected
                    .as_ref()
                    .map(|(_, best)| snapshot.latest_height() > best.latest_height())
                    .unwrap_or(true)
                {
                    selected = Some((url, snapshot));
                }
            }
            selected.map(|(_, snapshot)| Some(snapshot)).ok_or_else(|| {
                if rejected.is_empty() {
                    "no bootstrap peer snapshot was available".to_string()
                } else {
                    format!(
                        "no bootstrap peer snapshot matched local config: {}",
                        rejected.join("; ")
                    )
                }
            })
        }
    }
}

fn snapshot_matches_config(
    config: &RuntimeConfig,
    snapshot: &RuntimeSnapshot,
) -> Result<(), String> {
    if snapshot.config.chain_id != config.chain_id {
        return Err(format!(
            "chain_id {} does not match local chain_id {}",
            snapshot.config.chain_id, config.chain_id
        ));
    }
    if snapshot.config.runtime_version != config.runtime_version {
        return Err(format!(
            "runtime_version {} does not match local runtime_version {}",
            snapshot.config.runtime_version, config.runtime_version
        ));
    }
    if !snapshot_accepts_local_sequencer_key(config, snapshot) {
        return Err(format!(
            "sequencer_public_key_hex {} does not match local sequencer_public_key_hex {}",
            snapshot.config.sequencer_public_key_hex, config.sequencer_public_key_hex
        ));
    }
    Ok(())
}

fn snapshot_accepts_local_sequencer_key(
    config: &RuntimeConfig,
    snapshot: &RuntimeSnapshot,
) -> bool {
    if snapshot
        .config
        .sequencer_public_key_hex
        .eq_ignore_ascii_case(&config.sequencer_public_key_hex)
    {
        return true;
    }
    if config.produce_blocks {
        return false;
    }
    snapshot.sequencer_key_rotations.iter().any(|rotation| {
        rotation
            .old_public_key_hex
            .eq_ignore_ascii_case(&config.sequencer_public_key_hex)
            || rotation
                .new_public_key_hex
                .eq_ignore_ascii_case(&config.sequencer_public_key_hex)
    })
}

fn select_best_extending_snapshot(
    local: &RuntimeSnapshot,
    peer_snapshots: Vec<(String, RuntimeSnapshot)>,
) -> Result<Option<(String, RuntimeSnapshot)>, String> {
    let mut selected: Option<(String, RuntimeSnapshot)> = None;
    let mut rejected = Vec::new();
    for (url, snapshot) in peer_snapshots {
        if snapshot.latest_height() <= local.latest_height() {
            continue;
        }
        if !snapshot_extends(local, &snapshot) {
            rejected.push(format!(
                "{url}: height {} does not extend local height {}",
                snapshot.latest_height(),
                local.latest_height()
            ));
            continue;
        }
        if selected
            .as_ref()
            .map(|(_, best)| snapshot.latest_height() > best.latest_height())
            .unwrap_or(true)
        {
            selected = Some((url, snapshot));
        }
    }
    if selected.is_none() && !rejected.is_empty() {
        return Err(format!(
            "no sync peer returned an extending ahead snapshot: {}",
            rejected.join("; ")
        ));
    }
    Ok(selected)
}

fn sync_runtime_from_peers(
    state: &RuntimeRpcState,
    sync_rpc_urls: &[String],
) -> Result<bool, String> {
    let (peer_snapshots, fetch_errors) = fetch_runtime_snapshots(sync_rpc_urls);
    if peer_snapshots.is_empty() && !sync_rpc_urls.is_empty() {
        return Err(format!(
            "no sync peer returned a usable snapshot: {}",
            fetch_errors.join("; ")
        ));
    }
    let imported = {
        let mut runtime = state
            .runtime
            .lock()
            .map_err(|_| "runtime mutex poisoned".to_string())?;
        let local = runtime.export_snapshot();
        let Some((_, peer)) = select_best_extending_snapshot(&local, peer_snapshots)? else {
            return Ok(false);
        };
        runtime.import_snapshot(peer)?;
        true
    };
    if imported {
        state.persist()?;
    }
    Ok(imported)
}

fn collect_peer_urls(
    primary: Option<&str>,
    additional: &[String],
    flag_name: &str,
) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();
    for url in primary
        .into_iter()
        .chain(additional.iter().map(String::as_str))
    {
        let normalized = url.trim();
        if normalized.is_empty() {
            return Err(format!("{flag_name} must not be empty"));
        }
        parse_http_url(normalized).map_err(|error| format!("{flag_name} {normalized}: {error}"))?;
        if !urls.iter().any(|existing| existing == normalized) {
            urls.push(normalized.to_string());
        }
    }
    Ok(urls)
}

fn fetch_runtime_snapshots(urls: &[String]) -> (Vec<(String, RuntimeSnapshot)>, Vec<String>) {
    let mut snapshots = Vec::new();
    let mut errors = Vec::new();
    for url in urls {
        match fetch_runtime_snapshot(url) {
            Ok(snapshot) => snapshots.push((url.clone(), snapshot)),
            Err(error) => errors.push(format!("{url}: {error}")),
        }
    }
    (snapshots, errors)
}

fn fetch_runtime_snapshot(url: &str) -> Result<RuntimeSnapshot, String> {
    let (host, path) = parse_http_url(url)?;
    let mut stream = TcpStream::connect(&host)
        .map_err(|error| format!("failed to connect to bootstrap peer {host}: {error}"))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| format!("failed to request bootstrap snapshot: {error}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("failed to read bootstrap snapshot response: {error}"))?;
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return Err("bootstrap peer returned malformed HTTP response".to_string());
    };
    let status_line = head.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(format!("bootstrap peer returned {status_line}"));
    }
    let snapshot = serde_json::from_str::<RuntimeSnapshot>(body.trim())
        .map_err(|error| format!("failed to parse bootstrap snapshot: {error}"))?;
    validate_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn parse_http_url(url: &str) -> Result<(String, String), String> {
    let Some(rest) = url.strip_prefix("http://") else {
        return Err("bootstrap_rpc_url must use http:// for the local testnet RPC".to_string());
    };
    let (host, path) = match rest.split_once('/') {
        Some((host, path)) => (host, format!("/{path}")),
        None => (rest, "/snapshot".to_string()),
    };
    if host.trim().is_empty() {
        return Err("bootstrap_rpc_url must include a host".to_string());
    }
    Ok((host.to_string(), path))
}

fn handle_http_connection(mut stream: TcpStream, state: RuntimeRpcState) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(750)));
    let client_id = stream
        .peer_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|_| "unknown-peer".to_string());
    if let Err(error) = state.check_request_allowed(&client_id) {
        write_json_response(&mut stream, 429, &json!({"error": error}))?;
        return Ok(());
    }

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                buffer.extend_from_slice(&chunk[..read]);
                if request_size_exceeds_limit(&buffer, state.rpc_limits.max_request_bytes) {
                    write_json_response(
                        &mut stream,
                        413,
                        &json!({
                            "error": "request body too large",
                            "max_request_bytes": state.rpc_limits.max_request_bytes,
                        }),
                    )?;
                    return Ok(());
                }
                if request_complete(&buffer) {
                    break;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => return Err(error),
        }
    }

    let request = String::from_utf8_lossy(&buffer);
    let Some((head, body)) = request.split_once("\r\n\r\n") else {
        write_json_response(
            &mut stream,
            400,
            &json!({"error": "malformed HTTP request"}),
        )?;
        return Ok(());
    };
    let Some(request_line) = head.lines().next() else {
        write_json_response(&mut stream, 400, &json!({"error": "missing request line"}))?;
        return Ok(());
    };
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default();
    let path = request_parts.next().unwrap_or("/");

    match (method, path) {
        ("GET", "/health") => {
            let status = state.status_json().map_err(std::io::Error::other)?;
            write_json_response(
                &mut stream,
                200,
                &json!({
                    "ok": true,
                    "service": "nebula-testnet-rpc",
                    "rpc_limits": state.rpc_limits,
                    "bootstrap_peer_urls": state.sync_peers.bootstrap_peer_urls,
                    "sync_peer_urls": state.sync_peers.sync_peer_urls,
                    "sync_peer_count": state.sync_peers.sync_peer_urls.len(),
                    "sequencer_public_key_hex": status["sequencer_public_key_hex"],
                    "sequencer_key_rotation_count": status["sequencer_key_rotation_count"],
                    "sequencer_latest_rotation_activation_height": status["sequencer_latest_rotation_activation_height"],
                    "sequencer_key_history_root": status["sequencer_key_history_root"],
                    "accountability_report_count": status["accountability_report_count"],
                    "accountability_root": status["accountability_root"],
                    "sequencer_accountability_clean": status["sequencer_accountability_clean"],
                    "bridge_policy": bridge_policy(),
                    "bridge_policy_root": status["bridge_policy_root"],
                    "bridge_min_deposit_confirmations": status["bridge_min_deposit_confirmations"],
                    "bridge_deposit_observer_quorum": status["bridge_deposit_observer_quorum"],
                    "bridge_withdrawal_operator_quorum": status["bridge_withdrawal_operator_quorum"],
                    "bridge_live_value_enabled": status["bridge_live_value_enabled"],
                    "bridge_deposit_count": status["bridge_deposit_count"],
                    "withdrawal_request_count": status["withdrawal_request_count"],
                    "finalized_withdrawal_count": status["finalized_withdrawal_count"],
                    "bridge_replay_cache_count": status["bridge_replay_cache_count"],
                }),
            )?;
        }
        ("GET", "/status") => match state.status_json() {
            Ok(status) => write_json_response(&mut stream, 200, &status)?,
            Err(error) => write_json_response(&mut stream, 500, &json!({"error": error}))?,
        },
        ("GET", "/ops") => match state.ops_status() {
            Ok(status) => write_json_response(&mut stream, 200, &json!(status))?,
            Err(error) => write_json_response(&mut stream, 500, &json!({"error": error}))?,
        },
        ("GET", "/backup") => match state.backup_manifest() {
            Ok(manifest) => write_json_response(&mut stream, 200, &json!(manifest))?,
            Err(error) => write_json_response(&mut stream, 500, &json!({"error": error}))?,
        },
        ("GET", "/snapshot") => {
            let snapshot = state
                .runtime
                .lock()
                .expect("runtime mutex poisoned")
                .export_snapshot();
            write_json_response(&mut stream, 200, &json!(snapshot))?;
        }
        ("POST", "/") | ("POST", "/rpc") => {
            let request = serde_json::from_str::<Value>(body.trim()).unwrap_or_else(|error| {
                json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "method": "__parse_error__",
                    "params": {"message": error.to_string()}
                })
            });
            let response = handle_json_rpc_request(&state, &request);
            write_json_response(&mut stream, 200, &response)?;
        }
        _ => write_json_response(&mut stream, 404, &json!({"error": "not found"}))?,
    }

    Ok(())
}

fn handle_json_rpc_request(state: &RuntimeRpcState, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return rpc_error(id, -32600, "missing method");
    };
    if method == "__parse_error__" {
        let message = request["params"]["message"]
            .as_str()
            .unwrap_or("invalid JSON request");
        return rpc_error(id, -32700, message);
    }
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));

    let result = dispatch_json_rpc_method(state, method, params);
    match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(error) => rpc_error(id, -32000, &error),
    }
}

fn dispatch_json_rpc_method(
    state: &RuntimeRpcState,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    let result = match method {
        "nebula_status" => state.status_json(),
        "nebula_opsStatus" => state.ops_status().map(|status| json!(status)),
        "nebula_backupManifest" => state.backup_manifest().map(|manifest| json!(manifest)),
        "nebula_chainHead" => {
            let runtime = state.runtime.lock().expect("runtime mutex poisoned");
            Ok(json!(runtime.latest_block()))
        }
        "nebula_getBlockByHeight" => {
            let height = required_u64_param(&params, "height")?;
            let runtime = state.runtime.lock().expect("runtime mutex poisoned");
            runtime
                .block_by_height(height)
                .map(|block| json!(block))
                .ok_or_else(|| format!("block height {height} not found"))
        }
        "nebula_getAccount" => {
            let account = required_str_param(&params, "account")?;
            let runtime = state.runtime.lock().expect("runtime mutex poisoned");
            Ok(json!({
                "account": account,
                "state": runtime.account(&account).unwrap_or_else(RuntimeAccount::empty),
            }))
        }
        "nebula_getReceipt" => {
            let tx_id = required_str_param(&params, "tx_id")?;
            let runtime = state.runtime.lock().expect("runtime mutex poisoned");
            runtime
                .receipt(&tx_id)
                .map(|receipt| json!(receipt))
                .ok_or_else(|| format!("receipt {tx_id} not found"))
        }
        "nebula_exportSnapshot" => {
            let runtime = state.runtime.lock().expect("runtime mutex poisoned");
            Ok(json!(runtime.export_snapshot()))
        }
        "nebula_importSnapshot" => {
            let snapshot_value = params.get("snapshot").cloned().unwrap_or(params);
            let snapshot = serde_json::from_value::<RuntimeSnapshot>(snapshot_value)
                .map_err(|error| format!("invalid runtime snapshot: {error}"))?;
            let imported_height = snapshot.latest_height();
            {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                if imported_height < runtime.latest_block().height {
                    return Err(format!(
                        "imported snapshot height {imported_height} is below local height {}",
                        runtime.latest_block().height
                    ));
                }
                runtime.import_snapshot(snapshot)?;
            }
            state.persist()?;
            Ok(json!({
                "imported": true,
                "height": imported_height,
            }))
        }
        "nebula_feeQuote" => {
            let fee_asset = required_str_param(&params, "fee_asset")?;
            let gas_units = required_u128_param(&params, "gas_units")?;
            let gas_price = optional_u128_param(&params, "gas_price_nebulai")?;
            let runtime = state.runtime.lock().expect("runtime mutex poisoned");
            runtime
                .quote_fee(&fee_asset, gas_units, gas_price)
                .map(|quote| json!(quote))
        }
        "nebula_faucet" => {
            ensure_block_producer(state)?;
            let account = required_str_param(&params, "account")?;
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.faucet(&account)?
            };
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_sendTransaction" => {
            ensure_block_producer(state)?;
            let tx_value = params.get("tx").cloned().unwrap_or(params);
            let tx = serde_json::from_value::<RuntimeTransaction>(tx_value)
                .map_err(|error| format!("invalid transaction: {error}"))?;
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.submit_transaction(tx)?
            };
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_observeBridgeDeposit" => {
            ensure_block_producer(state)?;
            let deposit_value = params.get("deposit").cloned().unwrap_or(params);
            let mut deposit = serde_json::from_value::<RuntimeBridgeDeposit>(deposit_value)
                .map_err(|error| format!("invalid bridge deposit: {error}"))?;
            if deposit.observed_at_unix_ms == 0 {
                deposit.observed_at_unix_ms = unix_ms();
            }
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.observe_bridge_deposit(deposit)?
            };
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_requestWithdrawal" => {
            ensure_block_producer(state)?;
            let account = required_str_param(&params, "account")?;
            let monero_address = required_str_param(&params, "monero_address")?;
            let amount_nxmr_units = required_u128_param(&params, "amount_nxmr_units")?;
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.request_withdrawal(&account, &monero_address, amount_nxmr_units)?
            };
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_finalizeWithdrawal" => {
            ensure_block_producer(state)?;
            let withdrawal_id = required_str_param(&params, "withdrawal_id")?;
            let finalized_monero_tx_id = required_str_param(&params, "finalized_monero_tx_id")?;
            let finalization_proof_root = required_str_param(&params, "finalization_proof_root")?;
            let operator_approval_roots =
                required_string_array_param(&params, "operator_approval_roots")?;
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.finalize_withdrawal(
                    &withdrawal_id,
                    &finalized_monero_tx_id,
                    &finalization_proof_root,
                    operator_approval_roots,
                )?
            };
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_rotateSequencerKey" => {
            ensure_block_producer(state)?;
            let new_sequencer_secret_key_hex =
                required_str_param(&params, "new_sequencer_secret_key_hex")?;
            let operator_id = required_str_param(&params, "operator_id")?;
            let approval_root = required_str_param(&params, "approval_root")?;
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.rotate_sequencer_key(
                    &new_sequencer_secret_key_hex,
                    &operator_id,
                    &approval_root,
                )?
            };
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_reportEquivocation" => {
            ensure_block_producer(state)?;
            let height = required_u64_param(&params, "height")?;
            let first_block_hash = required_str_param(&params, "first_block_hash")?;
            let second_block_hash = required_str_param(&params, "second_block_hash")?;
            let reporter_id = required_str_param(&params, "reporter_id")?;
            let evidence_root = required_str_param(&params, "evidence_root")?;
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.report_equivocation(
                    height,
                    &first_block_hash,
                    &second_block_hash,
                    &reporter_id,
                    &evidence_root,
                )?
            };
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_bridgePolicy" => Ok(json!({
            "policy": bridge_policy(),
            "bridge_policy_root": bridge_policy_root(),
        })),
        "nebula_produceBlock" => {
            ensure_block_producer(state)?;
            let block = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.try_produce_block()?
            };
            state.persist()?;
            Ok(json!(block))
        }
        _ => Err(format!("unknown method {method}")),
    };
    result
}

fn ensure_block_producer(state: &RuntimeRpcState) -> Result<(), String> {
    let runtime = state
        .runtime
        .lock()
        .map_err(|_| "runtime mutex poisoned".to_string())?;
    if !runtime.config.produce_blocks {
        return Err(
            "node is running in follower mode; submit mutations to the sequencer".to_string(),
        );
    }
    if runtime.sequencer_secret_key_hex.is_none() {
        return Err("node has no sequencer signing key configured".to_string());
    }
    Ok(())
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

fn write_json_response(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let body = serde_json::to_string_pretty(body).expect("JSON response serializes");
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn request_complete(buffer: &[u8]) -> bool {
    let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let content_length = content_length_from_headers(&headers).unwrap_or(0);
    buffer.len() >= header_end + 4 + content_length
}

fn request_size_exceeds_limit(buffer: &[u8], max_request_bytes: usize) -> bool {
    if buffer.len() > max_request_bytes {
        return true;
    }
    let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    match content_length_from_headers(&headers) {
        Some(content_length) => header_end + 4 + content_length > max_request_bytes,
        None => false,
    }
}

fn content_length_from_headers(headers: &str) -> Option<usize> {
    headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length:"))
        .or_else(|| {
            headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
}

fn validate_transaction_shape(tx: &RuntimeTransaction) -> Result<(), String> {
    validate_account_id(&tx.from)?;
    validate_account_id(&tx.to)?;
    if tx.from == tx.to {
        return Err("from and to accounts must differ".to_string());
    }
    if tx.amount_nebulai == 0 {
        return Err("amount_nebulai must be greater than zero".to_string());
    }
    parse_fee_asset(&tx.fee_asset)?;
    if tx.gas_units == 0 {
        return Err("gas_units must be greater than zero".to_string());
    }
    if tx.gas_price_nebulai == 0 {
        return Err("gas_price_nebulai must be greater than zero".to_string());
    }
    Ok(())
}

fn validate_snapshot(snapshot: &RuntimeSnapshot) -> Result<(), String> {
    if snapshot.snapshot_version != RUNTIME_SNAPSHOT_VERSION {
        return Err(format!(
            "snapshot_version expected {RUNTIME_SNAPSHOT_VERSION} but got {}",
            snapshot.snapshot_version
        ));
    }
    snapshot.config.validate()?;
    if snapshot.blocks.is_empty() {
        return Err("snapshot must contain at least the genesis block".to_string());
    }
    if snapshot.blocks[0].height != 0 {
        return Err("snapshot genesis block must have height 0".to_string());
    }
    if snapshot.root != snapshot_root(snapshot) {
        return Err("snapshot root does not match snapshot contents".to_string());
    }
    validate_sequencer_key_history(snapshot)?;
    validate_accountability_reports(&snapshot.accountability_reports)?;

    let mut previous_hash: Option<String> = None;
    for (index, block) in snapshot.blocks.iter().enumerate() {
        if block.height != index as u64 {
            return Err(format!(
                "block height gap at index {index}: got {}",
                block.height
            ));
        }
        if let Some(parent_hash) = &previous_hash {
            if block.parent_hash != *parent_hash {
                return Err(format!(
                    "block {} parent_hash does not match previous block",
                    block.height
                ));
            }
        } else if block.parent_hash != "0".repeat(64) {
            return Err("genesis parent_hash must be zero root".to_string());
        }
        if block.tx_root != transaction_root(&block.transactions, &block.rejected_tx_ids) {
            return Err(format!("block {} tx_root does not match", block.height));
        }
        if block.block_hash != block_root(block) {
            return Err(format!("block {} block_hash does not match", block.height));
        }
        let expected_public_key_hex = sequencer_public_key_for_height(snapshot, block.height);
        verify_block_signature(block, &expected_public_key_hex)
            .map_err(|error| format!("block {} signature rejected: {error}", block.height))?;
        for tx in &block.transactions {
            validate_transaction_shape(tx)?;
        }
        previous_hash = Some(block.block_hash.clone());
    }

    for account in snapshot.accounts.keys() {
        validate_account_id(account)?;
    }
    for (tx_id, receipt) in &snapshot.receipts {
        if tx_id != &receipt.tx_id {
            return Err(format!(
                "receipt map key {tx_id} does not match receipt tx_id"
            ));
        }
    }
    let mut mempool_ids = BTreeMap::<String, usize>::new();
    for tx in &snapshot.mempool {
        validate_transaction_shape(tx)?;
        let tx_id = tx.id();
        *mempool_ids.entry(tx_id).or_insert(0) += 1;
    }
    for (tx_id, count) in &mempool_ids {
        if *count > 1 {
            return Err(format!("duplicate mempool transaction {tx_id}"));
        }
        match snapshot.receipts.get(tx_id) {
            Some(receipt) if receipt.status == TransactionStatus::Pending => {}
            Some(_) => {
                return Err(format!(
                    "mempool transaction {tx_id} has non-pending receipt"
                ))
            }
            None => {
                return Err(format!(
                    "mempool transaction {tx_id} has no pending receipt"
                ))
            }
        }
    }
    for (tx_id, receipt) in &snapshot.receipts {
        if receipt.status == TransactionStatus::Pending && !mempool_ids.contains_key(tx_id) {
            return Err(format!("pending receipt {tx_id} is not present in mempool"));
        }
    }
    for (tx_id, receipt) in &snapshot.receipts {
        if matches!(
            receipt.status,
            TransactionStatus::Included | TransactionStatus::Rejected
        ) && receipt.block_height.is_none()
        {
            return Err(format!("final receipt {tx_id} must include block_height"));
        }
    }
    for block in &snapshot.blocks {
        for tx in &block.transactions {
            let tx_id = tx.id();
            match snapshot.receipts.get(&tx_id) {
                Some(receipt) if receipt.status == TransactionStatus::Included => {}
                Some(_) => {
                    return Err(format!(
                        "included tx {tx_id} does not have included receipt"
                    ))
                }
                None => return Err(format!("included tx {tx_id} has no receipt")),
            }
        }
    }

    for (monero_tx_id, deposit) in &snapshot.bridge_deposits {
        if monero_tx_id != &deposit.monero_tx_id {
            return Err(format!(
                "bridge deposit map key {monero_tx_id} does not match inner monero_tx_id"
            ));
        }
        validate_bridge_deposit(deposit)?;
        if bridge_deposit_root(deposit).len() != 64 {
            return Err(format!("bridge deposit {monero_tx_id} root failed"));
        }
    }
    let mut finalized_withdrawal_txs = BTreeMap::<String, String>::new();
    let mut finalized_withdrawal_proofs = BTreeMap::<String, String>::new();
    for (withdrawal_id, withdrawal) in &snapshot.withdrawals {
        if withdrawal_id != &withdrawal.withdrawal_id {
            return Err(format!(
                "withdrawal map key {withdrawal_id} does not match inner withdrawal_id"
            ));
        }
        validate_withdrawal(withdrawal)?;
        if let Some(monero_tx_id) = &withdrawal.finalized_monero_tx_id {
            let normalized = monero_tx_id.to_ascii_lowercase();
            if snapshot
                .bridge_deposits
                .keys()
                .any(|deposit_tx_id| deposit_tx_id.eq_ignore_ascii_case(monero_tx_id))
            {
                return Err(format!(
                    "withdrawal {withdrawal_id} finalization reuses bridge deposit tx {monero_tx_id}"
                ));
            }
            if let Some(previous) =
                finalized_withdrawal_txs.insert(normalized, withdrawal_id.clone())
            {
                return Err(format!(
                    "withdrawals {previous} and {withdrawal_id} reuse finalized Monero tx {monero_tx_id}"
                ));
            }
        }
        if let Some(proof_root) = &withdrawal.finalization_proof_root {
            let normalized = proof_root.to_ascii_lowercase();
            if let Some(previous) =
                finalized_withdrawal_proofs.insert(normalized, withdrawal_id.clone())
            {
                return Err(format!(
                    "withdrawals {previous} and {withdrawal_id} reuse finalization proof root {proof_root}"
                ));
            }
        }
    }

    let expected_state_root = stable_runtime_root(&json!({
        "state_domain": "nebula-runtime-state-v1",
        "accounts": snapshot.accounts,
        "bridge_deposits": snapshot.bridge_deposits,
        "withdrawals": snapshot.withdrawals,
        "total_nxmr_fees_units": snapshot.total_nxmr_fees_units,
        "buyback_pool_nebulai": snapshot.buyback_pool_nebulai,
        "validator_reward_nebulai": snapshot.validator_reward_nebulai,
    }));
    if snapshot.state_root != expected_state_root {
        return Err("snapshot state_root does not match snapshot state".to_string());
    }
    Ok(())
}

fn validate_sequencer_key_history(snapshot: &RuntimeSnapshot) -> Result<(), String> {
    let current_public_key = normalize_fixed_hex(
        &snapshot.config.sequencer_public_key_hex,
        "sequencer_public_key_hex",
        64,
    )?;
    verifying_key_from_hex(&current_public_key)?;
    let mut active_public_key = snapshot
        .sequencer_key_rotations
        .first()
        .map(|rotation| rotation.old_public_key_hex.to_ascii_lowercase())
        .unwrap_or_else(|| current_public_key.clone());
    verifying_key_from_hex(&active_public_key)?;
    let mut previous_activation_height: Option<u64> = None;

    for (index, rotation) in snapshot.sequencer_key_rotations.iter().enumerate() {
        validate_sequencer_key_rotation(rotation)
            .map_err(|error| format!("sequencer_key_rotations[{index}]: {error}"))?;
        if let Some(previous) = previous_activation_height {
            if rotation.activation_height <= previous {
                return Err(format!(
                    "sequencer_key_rotations[{index}] activation_height must be greater than {previous}"
                ));
            }
        }
        if !rotation
            .old_public_key_hex
            .eq_ignore_ascii_case(&active_public_key)
        {
            return Err(format!(
                "sequencer_key_rotations[{index}] old_public_key_hex does not match active sequencer key"
            ));
        }
        active_public_key = rotation.new_public_key_hex.to_ascii_lowercase();
        previous_activation_height = Some(rotation.activation_height);
    }

    if !active_public_key.eq_ignore_ascii_case(&current_public_key) {
        return Err(
            "snapshot sequencer_public_key_hex does not match final sequencer key rotation"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_sequencer_key_rotation(rotation: &RuntimeSequencerKeyRotation) -> Result<(), String> {
    if rotation.activation_height == 0 {
        return Err("activation_height must be greater than zero".to_string());
    }
    validate_fixed_hex(&rotation.old_public_key_hex, "old_public_key_hex", 64)?;
    validate_fixed_hex(&rotation.new_public_key_hex, "new_public_key_hex", 64)?;
    verifying_key_from_hex(&rotation.old_public_key_hex)?;
    verifying_key_from_hex(&rotation.new_public_key_hex)?;
    if rotation
        .old_public_key_hex
        .eq_ignore_ascii_case(&rotation.new_public_key_hex)
    {
        return Err("new_public_key_hex must differ from old_public_key_hex".to_string());
    }
    validate_account_id(&rotation.operator_id)?;
    validate_fixed_hex(&rotation.approval_root, "approval_root", 64)?;
    if rotation.root != sequencer_key_rotation_root(rotation) {
        return Err("root does not match sequencer key rotation contents".to_string());
    }
    Ok(())
}

fn sequencer_public_key_for_height(snapshot: &RuntimeSnapshot, height: u64) -> String {
    let mut public_key = snapshot
        .sequencer_key_rotations
        .first()
        .map(|rotation| rotation.old_public_key_hex.clone())
        .unwrap_or_else(|| snapshot.config.sequencer_public_key_hex.clone());
    for rotation in &snapshot.sequencer_key_rotations {
        if height < rotation.activation_height {
            break;
        }
        public_key = rotation.new_public_key_hex.clone();
    }
    public_key
}

fn validate_accountability_reports(reports: &[RuntimeAccountabilityReport]) -> Result<(), String> {
    let mut report_ids = BTreeMap::<String, usize>::new();
    for (index, report) in reports.iter().enumerate() {
        validate_accountability_report(report)
            .map_err(|error| format!("accountability_reports[{index}]: {error}"))?;
        let normalized_report_id = report.report_id.to_ascii_lowercase();
        if let Some(previous_index) = report_ids.insert(normalized_report_id, index) {
            return Err(format!(
                "accountability_reports[{index}] duplicates accountability_reports[{previous_index}]"
            ));
        }
    }
    Ok(())
}

fn validate_accountability_report(report: &RuntimeAccountabilityReport) -> Result<(), String> {
    if report.height == 0 {
        return Err("height must be greater than zero".to_string());
    }
    validate_fixed_hex(&report.report_id, "report_id", 64)?;
    validate_fixed_hex(&report.first_block_hash, "first_block_hash", 64)?;
    validate_fixed_hex(&report.second_block_hash, "second_block_hash", 64)?;
    if report
        .first_block_hash
        .eq_ignore_ascii_case(&report.second_block_hash)
    {
        return Err("first_block_hash and second_block_hash must differ".to_string());
    }
    validate_account_id(&report.reporter_id)?;
    validate_fixed_hex(&report.evidence_root, "evidence_root", 64)?;
    let expected_report_id = accountability_report_id(
        report.height,
        &report.first_block_hash,
        &report.second_block_hash,
        &report.reporter_id,
        &report.evidence_root,
    );
    if !report.report_id.eq_ignore_ascii_case(&expected_report_id) {
        return Err("report_id does not match accountability report contents".to_string());
    }
    if report.root != accountability_report_root(report) {
        return Err("root does not match accountability report contents".to_string());
    }
    Ok(())
}

fn validate_account_id(account: &str) -> Result<(), String> {
    if account.trim().is_empty() {
        return Err("account must not be empty".to_string());
    }
    if account.chars().any(char::is_whitespace) {
        return Err(format!("account {account} must not contain whitespace"));
    }
    Ok(())
}

fn validate_bridge_deposit(deposit: &RuntimeBridgeDeposit) -> Result<(), String> {
    validate_account_id(&deposit.account)?;
    validate_account_id(&deposit.observer_id)?;
    validate_fixed_hex(&deposit.monero_tx_id, "monero_tx_id", 64)?;
    validate_fixed_hex(&deposit.proof_root, "proof_root", 64)?;
    validate_fixed_hex(&deposit.custody_proof_root, "custody_proof_root", 64)?;
    validate_fixed_hex(&deposit.relayer_set_root, "relayer_set_root", 64)?;
    validate_quorum_roots(
        &deposit.observer_signature_roots,
        "observer_signature_roots",
        MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM,
    )?;
    if deposit.amount_nxmr_units == 0 {
        return Err("amount_nxmr_units must be greater than zero".to_string());
    }
    Ok(())
}

fn validate_withdrawal(withdrawal: &RuntimeWithdrawalRequest) -> Result<(), String> {
    validate_account_id(&withdrawal.account)?;
    validate_monero_address(&withdrawal.monero_address)?;
    if withdrawal.amount_nxmr_units == 0 {
        return Err(format!(
            "withdrawal {} amount_nxmr_units must be greater than zero",
            withdrawal.withdrawal_id
        ));
    }
    if withdrawal.bridge_policy_root != bridge_policy_root() {
        return Err(format!(
            "withdrawal {} bridge_policy_root does not match runtime policy",
            withdrawal.withdrawal_id
        ));
    }
    match withdrawal.status.as_str() {
        "operator_pending" => {
            if !withdrawal.operator_approval_roots.is_empty() {
                return Err(format!(
                    "withdrawal {} pending request must not have operator approvals",
                    withdrawal.withdrawal_id
                ));
            }
            if withdrawal.finalized_monero_tx_id.is_some()
                || withdrawal.finalization_proof_root.is_some()
                || withdrawal.finalized_at_unix_ms.is_some()
            {
                return Err(format!(
                    "withdrawal {} pending request must not have finalization evidence",
                    withdrawal.withdrawal_id
                ));
            }
        }
        "finalized" => {
            validate_quorum_roots(
                &withdrawal.operator_approval_roots,
                "operator_approval_roots",
                MIN_WITHDRAWAL_OPERATOR_QUORUM,
            )?;
            let monero_tx_id = withdrawal
                .finalized_monero_tx_id
                .as_deref()
                .ok_or_else(|| {
                    format!(
                        "withdrawal {} finalized request missing finalized_monero_tx_id",
                        withdrawal.withdrawal_id
                    )
                })?;
            validate_fixed_hex(monero_tx_id, "finalized_monero_tx_id", 64)?;
            let proof_root = withdrawal
                .finalization_proof_root
                .as_deref()
                .ok_or_else(|| {
                    format!(
                        "withdrawal {} finalized request missing finalization_proof_root",
                        withdrawal.withdrawal_id
                    )
                })?;
            validate_fixed_hex(proof_root, "finalization_proof_root", 64)?;
            if withdrawal.finalized_at_unix_ms.is_none() {
                return Err(format!(
                    "withdrawal {} finalized request missing finalized_at_unix_ms",
                    withdrawal.withdrawal_id
                ));
            }
        }
        other => {
            return Err(format!(
                "withdrawal {} has unsupported status {other}",
                withdrawal.withdrawal_id
            ))
        }
    }
    if withdrawal.root != withdrawal_root(withdrawal) {
        return Err(format!(
            "withdrawal {} root does not match",
            withdrawal.withdrawal_id
        ));
    }
    Ok(())
}

fn validate_quorum_roots(roots: &[String], name: &str, minimum_count: usize) -> Result<(), String> {
    if roots.len() < minimum_count {
        return Err(format!(
            "{name} must include at least {minimum_count} distinct roots"
        ));
    }
    let mut seen = BTreeMap::<String, usize>::new();
    for (index, root) in roots.iter().enumerate() {
        validate_fixed_hex(root, &format!("{name}[{index}]"), 64)?;
        let normalized = root.to_ascii_lowercase();
        if let Some(previous_index) = seen.insert(normalized, index) {
            return Err(format!(
                "{name}[{index}] duplicates {name}[{previous_index}]"
            ));
        }
    }
    Ok(())
}

fn validate_monero_address(monero_address: &str) -> Result<(), String> {
    if monero_address.trim().is_empty() {
        return Err("monero_address must not be empty".to_string());
    }
    if monero_address.chars().any(char::is_whitespace) {
        return Err("monero_address must not contain whitespace".to_string());
    }
    if monero_address.len() < 20 {
        return Err("monero_address is too short for a public testnet withdrawal".to_string());
    }
    Ok(())
}

fn validate_fixed_hex(value: &str, name: &str, len: usize) -> Result<(), String> {
    if value.len() != len {
        return Err(format!("{name} must be {len} hex characters"));
    }
    if !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(format!("{name} must be hex encoded"));
    }
    Ok(())
}

fn normalize_fixed_hex(value: &str, name: &str, len: usize) -> Result<String, String> {
    validate_fixed_hex(value, name, len)?;
    Ok(value.to_ascii_lowercase())
}

fn decode_fixed_hex(value: &str, name: &str, bytes_len: usize) -> Result<Vec<u8>, String> {
    validate_fixed_hex(value, name, bytes_len * 2)?;
    hex::decode(value).map_err(|error| format!("{name} is not valid hex: {error}"))
}

fn signing_key_from_hex(secret_key_hex: &str) -> Result<SigningKey, String> {
    let bytes = decode_fixed_hex(secret_key_hex, "sequencer_secret_key_hex", 32)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "sequencer_secret_key_hex must decode to 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey, String> {
    let bytes = decode_fixed_hex(public_key_hex, "sequencer_public_key_hex", 32)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "sequencer_public_key_hex must decode to 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| format!("sequencer_public_key_hex is not an Ed25519 key: {error}"))
}

fn public_key_hex_for_secret(secret_key_hex: &str) -> Result<String, String> {
    let signing_key = signing_key_from_hex(secret_key_hex)?;
    Ok(hex::encode(signing_key.verifying_key().to_bytes()))
}

pub fn default_dev_sequencer_public_key_hex() -> String {
    public_key_hex_for_secret(DEFAULT_DEV_SEQUENCER_SECRET_KEY_HEX)
        .expect("default dev sequencer secret key is valid")
}

fn prepare_runtime_config(
    mut config: RuntimeConfig,
    sequencer_secret_key_hex: Option<String>,
) -> Result<(RuntimeConfig, Option<String>), String> {
    config.sequencer_public_key_hex = normalize_fixed_hex(
        &config.sequencer_public_key_hex,
        "sequencer_public_key_hex",
        64,
    )?;
    config.validate()?;
    let sequencer_secret_key_hex = resolve_sequencer_secret(&config, sequencer_secret_key_hex)?;
    Ok((config, sequencer_secret_key_hex))
}

fn resolve_sequencer_secret(
    config: &RuntimeConfig,
    sequencer_secret_key_hex: Option<String>,
) -> Result<Option<String>, String> {
    let selected = match sequencer_secret_key_hex {
        Some(secret_key_hex) => secret_key_hex,
        None if config
            .sequencer_public_key_hex
            .eq_ignore_ascii_case(&default_dev_sequencer_public_key_hex()) =>
        {
            DEFAULT_DEV_SEQUENCER_SECRET_KEY_HEX.to_string()
        }
        None if config.produce_blocks => {
            return Err(
                "sequencer_secret_key_hex is required for custom sequencer_public_key_hex"
                    .to_string(),
            )
        }
        None => return Ok(None),
    };
    let selected = normalize_fixed_hex(&selected, "sequencer_secret_key_hex", 64)?;
    let derived_public_key = public_key_hex_for_secret(&selected)?;
    if !derived_public_key.eq_ignore_ascii_case(&config.sequencer_public_key_hex) {
        return Err(format!(
            "sequencer_secret_key_hex derives public key {derived_public_key}, expected {}",
            config.sequencer_public_key_hex
        ));
    }
    Ok(Some(selected))
}

fn sign_block_hash(block_hash: &str, secret_key_hex: &str) -> Result<String, String> {
    validate_fixed_hex(block_hash, "block_hash", 64)?;
    let signing_key = signing_key_from_hex(secret_key_hex)?;
    let signature: Signature = signing_key.sign(block_hash.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

fn verify_block_signature(
    block: &RuntimeBlock,
    expected_public_key_hex: &str,
) -> Result<(), String> {
    validate_fixed_hex(&block.block_hash, "block_hash", 64)?;
    validate_fixed_hex(&block.signature, "block_signature", 128)?;
    if !block
        .producer_public_key
        .eq_ignore_ascii_case(expected_public_key_hex)
    {
        return Err(format!(
            "producer_public_key {} does not match expected sequencer {}",
            block.producer_public_key, expected_public_key_hex
        ));
    }
    let verifying_key = verifying_key_from_hex(expected_public_key_hex)?;
    let signature_bytes = decode_fixed_hex(&block.signature, "block_signature", 64)?;
    let signature_bytes: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "block_signature must decode to 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(block.block_hash.as_bytes(), &signature)
        .map_err(|error| format!("Ed25519 verification failed: {error}"))
}

fn parse_fee_asset(input: &str) -> Result<FeeAsset, String> {
    match input.trim() {
        NBLA_SYMBOL | "nbla" | "Nbla" => Ok(FeeAsset::Nbla),
        NXMR_SYMBOL | "nxmr" | "NXMR" | "n_xmr" => Ok(FeeAsset::NXmr),
        other => Err(format!(
            "unsupported fee_asset {other}; expected NBLA or nXMR"
        )),
    }
}

fn required_str_param(params: &Value, name: &str) -> Result<String, String> {
    params
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing string param {name}"))
}

fn required_u64_param(params: &Value, name: &str) -> Result<u64, String> {
    params
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing u64 param {name}"))
}

fn required_u128_param(params: &Value, name: &str) -> Result<u128, String> {
    let value = params
        .get(name)
        .ok_or_else(|| format!("missing u128 param {name}"))?;
    value_to_u128(value, name)
}

fn required_string_array_param(params: &Value, name: &str) -> Result<Vec<String>, String> {
    let values = params
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing string array param {name}"))?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{name}[{index}] must be a string"))
        })
        .collect()
}

fn optional_u128_param(params: &Value, name: &str) -> Result<Option<u128>, String> {
    match params.get(name) {
        Some(value) if !value.is_null() => value_to_u128(value, name).map(Some),
        _ => Ok(None),
    }
}

fn value_to_u128(value: &Value, name: &str) -> Result<u128, String> {
    if let Some(number) = value.as_u64() {
        return Ok(u128::from(number));
    }
    if let Some(text) = value.as_str() {
        return text
            .parse::<u128>()
            .map_err(|error| format!("invalid u128 param {name}: {error}"));
    }
    Err(format!("invalid u128 param {name}"))
}

fn transaction_root(transactions: &[RuntimeTransaction], rejected_tx_ids: &[String]) -> String {
    let tx_ids = transactions
        .iter()
        .map(RuntimeTransaction::id)
        .collect::<Vec<_>>();
    stable_runtime_root(&json!({
        "tx_root_domain": "nebula-runtime-block-transactions-v1",
        "included_tx_ids": tx_ids,
        "rejected_tx_ids": rejected_tx_ids,
    }))
}

fn ops_status_root(report: &RuntimeOpsStatus) -> String {
    stable_runtime_root(&json!({
        "ops_status_domain": "nebula-runtime-ops-status-v1",
        "service": report.service,
        "generated_at_unix_ms": report.generated_at_unix_ms,
        "chain_id": report.chain_id,
        "runtime_version": report.runtime_version,
        "node_role": report.node_role,
        "latest_height": report.latest_height,
        "latest_hash": report.latest_hash,
        "latest_block_age_ms": report.latest_block_age_ms,
        "block_target_ms": report.block_target_ms,
        "sub_second_blocks": report.sub_second_blocks,
        "block_production_enabled": report.block_production_enabled,
        "snapshot_version": report.snapshot_version,
        "snapshot_root": report.snapshot_root,
        "state_root": report.state_root,
        "current_state_root": report.current_state_root,
        "storage_snapshot_path": report.storage_snapshot_path,
        "storage_snapshot_present": report.storage_snapshot_present,
        "storage_snapshot_root": report.storage_snapshot_root,
        "storage_snapshot_height": report.storage_snapshot_height,
        "storage_snapshot_matches_runtime": report.storage_snapshot_matches_runtime,
        "sync_peer_count": report.sync_peer_count,
        "rpc_max_request_bytes": report.rpc_max_request_bytes,
        "rpc_max_requests_per_minute": report.rpc_max_requests_per_minute,
        "sequencer_public_key_hex": report.sequencer_public_key_hex,
        "sequencer_key_rotation_count": report.sequencer_key_rotation_count,
        "sequencer_latest_rotation_activation_height": report.sequencer_latest_rotation_activation_height,
        "sequencer_key_history_root": report.sequencer_key_history_root,
        "accountability_report_count": report.accountability_report_count,
        "accountability_root": report.accountability_root,
        "sequencer_accountability_clean": report.sequencer_accountability_clean,
        "bridge_policy_root": report.bridge_policy_root,
        "bridge_live_value_enabled": report.bridge_live_value_enabled,
        "public_ops_ready": report.public_ops_ready,
        "blocking_gaps": report.blocking_gaps,
    }))
}

fn backup_manifest_root(manifest: &RuntimeBackupManifest) -> String {
    stable_runtime_root(&json!({
        "backup_manifest_domain": "nebula-runtime-backup-manifest-v1",
        "manifest_version": manifest.manifest_version,
        "generated_at_unix_ms": manifest.generated_at_unix_ms,
        "chain_id": manifest.chain_id,
        "runtime_version": manifest.runtime_version,
        "latest_height": manifest.latest_height,
        "latest_hash": manifest.latest_hash,
        "snapshot_version": manifest.snapshot_version,
        "snapshot_root": manifest.snapshot_root,
        "state_root": manifest.state_root,
        "current_state_root": manifest.current_state_root,
        "snapshot_path": manifest.snapshot_path,
        "snapshot_persisted": manifest.snapshot_persisted,
        "storage_snapshot_root": manifest.storage_snapshot_root,
        "storage_snapshot_matches_runtime": manifest.storage_snapshot_matches_runtime,
        "sequencer_public_key_hex": manifest.sequencer_public_key_hex,
        "sequencer_key_rotation_count": manifest.sequencer_key_rotation_count,
        "sequencer_latest_rotation_activation_height": manifest.sequencer_latest_rotation_activation_height,
        "sequencer_key_history_root": manifest.sequencer_key_history_root,
        "accountability_report_count": manifest.accountability_report_count,
        "accountability_root": manifest.accountability_root,
        "sequencer_accountability_clean": manifest.sequencer_accountability_clean,
        "bridge_policy_root": manifest.bridge_policy_root,
        "sync_peer_count": manifest.sync_peer_count,
        "rpc_max_request_bytes": manifest.rpc_max_request_bytes,
        "rpc_max_requests_per_minute": manifest.rpc_max_requests_per_minute,
    }))
}

pub fn bridge_policy() -> RuntimeBridgePolicy {
    RuntimeBridgePolicy {
        policy_id: BRIDGE_CUSTODY_POLICY_ID,
        custody_model: "testnet-multisig-evidence-roots",
        min_deposit_confirmations: MIN_BRIDGE_CONFIRMATIONS,
        min_deposit_observer_quorum: MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM,
        min_withdrawal_operator_quorum: MIN_WITHDRAWAL_OPERATOR_QUORUM,
        replay_protection: "monero tx ids must be unique across deposits and finalized withdrawals",
        live_value_enabled: false,
    }
}

pub fn bridge_policy_root() -> String {
    stable_runtime_root(&json!({
        "bridge_policy_domain": "nebula-runtime-monero-bridge-policy-v1",
        "policy": bridge_policy(),
    }))
}

fn bridge_deposit_root(deposit: &RuntimeBridgeDeposit) -> String {
    stable_runtime_root(&json!({
        "bridge_deposit_domain": "nebula-runtime-monero-bridge-deposit-v1",
        "monero_tx_id": deposit.monero_tx_id,
        "account": deposit.account,
        "amount_nxmr_units": deposit.amount_nxmr_units,
        "confirmations": deposit.confirmations,
        "observer_id": deposit.observer_id,
        "proof_root": deposit.proof_root,
        "custody_proof_root": deposit.custody_proof_root,
        "relayer_set_root": deposit.relayer_set_root,
        "observer_signature_roots": deposit.observer_signature_roots,
        "observed_at_unix_ms": deposit.observed_at_unix_ms,
        "bridge_policy_root": bridge_policy_root(),
    }))
}

fn withdrawal_root(withdrawal: &RuntimeWithdrawalRequest) -> String {
    stable_runtime_root(&json!({
        "withdrawal_domain": "nebula-runtime-monero-withdrawal-v1",
        "withdrawal_id": withdrawal.withdrawal_id,
        "account": withdrawal.account,
        "monero_address": withdrawal.monero_address,
        "amount_nxmr_units": withdrawal.amount_nxmr_units,
        "requested_at_unix_ms": withdrawal.requested_at_unix_ms,
        "status": withdrawal.status,
        "bridge_policy_root": withdrawal.bridge_policy_root,
        "operator_approval_roots": withdrawal.operator_approval_roots,
        "finalized_monero_tx_id": withdrawal.finalized_monero_tx_id,
        "finalization_proof_root": withdrawal.finalization_proof_root,
        "finalized_at_unix_ms": withdrawal.finalized_at_unix_ms,
    }))
}

fn sequencer_key_rotation_root(rotation: &RuntimeSequencerKeyRotation) -> String {
    stable_runtime_root(&json!({
        "sequencer_key_rotation_domain": "nebula-runtime-sequencer-key-rotation-v1",
        "activation_height": rotation.activation_height,
        "old_public_key_hex": rotation.old_public_key_hex,
        "new_public_key_hex": rotation.new_public_key_hex,
        "operator_id": rotation.operator_id,
        "approval_root": rotation.approval_root,
        "rotated_at_unix_ms": rotation.rotated_at_unix_ms,
    }))
}

fn sequencer_key_history_root(rotations: &[RuntimeSequencerKeyRotation]) -> String {
    stable_runtime_root(&json!({
        "sequencer_key_history_domain": "nebula-runtime-sequencer-key-history-v1",
        "rotations": rotations,
    }))
}

fn accountability_report_id(
    height: u64,
    first_block_hash: &str,
    second_block_hash: &str,
    reporter_id: &str,
    evidence_root: &str,
) -> String {
    let first_block_hash = first_block_hash.to_ascii_lowercase();
    let second_block_hash = second_block_hash.to_ascii_lowercase();
    let (lower_block_hash, higher_block_hash) = if first_block_hash <= second_block_hash {
        (first_block_hash, second_block_hash)
    } else {
        (second_block_hash, first_block_hash)
    };
    stable_runtime_root(&json!({
        "accountability_report_id_domain": "nebula-runtime-sequencer-accountability-report-id-v1",
        "height": height,
        "block_hashes": [lower_block_hash, higher_block_hash],
        "reporter_id": reporter_id,
        "evidence_root": evidence_root.to_ascii_lowercase(),
    }))
}

fn accountability_report_root(report: &RuntimeAccountabilityReport) -> String {
    stable_runtime_root(&json!({
        "accountability_report_domain": "nebula-runtime-sequencer-accountability-report-v1",
        "report_id": report.report_id,
        "height": report.height,
        "first_block_hash": report.first_block_hash,
        "second_block_hash": report.second_block_hash,
        "reporter_id": report.reporter_id,
        "evidence_root": report.evidence_root,
        "reported_at_unix_ms": report.reported_at_unix_ms,
    }))
}

fn accountability_root(reports: &[RuntimeAccountabilityReport]) -> String {
    stable_runtime_root(&json!({
        "accountability_root_domain": "nebula-runtime-sequencer-accountability-v1",
        "reports": reports,
    }))
}

fn snapshot_root(snapshot: &RuntimeSnapshot) -> String {
    stable_runtime_root(&json!({
        "snapshot_domain": "nebula-runtime-snapshot-v1",
        "snapshot_version": snapshot.snapshot_version,
        "exported_at_unix_ms": snapshot.exported_at_unix_ms,
        "config": snapshot.config,
        "state_root": snapshot.state_root,
        "accounts": snapshot.accounts,
        "mempool": snapshot.mempool,
        "receipts": snapshot.receipts,
        "bridge_deposits": snapshot.bridge_deposits,
        "withdrawals": snapshot.withdrawals,
        "blocks": snapshot.blocks,
        "total_nxmr_fees_units": snapshot.total_nxmr_fees_units,
        "buyback_pool_nebulai": snapshot.buyback_pool_nebulai,
        "validator_reward_nebulai": snapshot.validator_reward_nebulai,
        "sequencer_key_rotations": snapshot.sequencer_key_rotations,
        "accountability_reports": snapshot.accountability_reports,
    }))
}

fn block_root(block: &RuntimeBlock) -> String {
    stable_runtime_root(&json!({
        "block_domain": "nebula-runtime-block-v1",
        "height": block.height,
        "parent_hash": block.parent_hash,
        "timestamp_unix_ms": block.timestamp_unix_ms,
        "producer": block.producer,
        "producer_public_key": block.producer_public_key,
        "tx_root": block.tx_root,
        "state_root": block.state_root,
    }))
}

fn stable_runtime_root(value: &Value) -> String {
    let canonical = serde_json::to_vec(value).expect("runtime root value serializes");
    let digest = Sha3_256::digest(canonical);
    hex::encode(digest)
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX_EPOCH")
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rpc_state_with_limits(
        runtime: NebulaRuntime,
        max_request_bytes: usize,
        max_requests_per_minute: u32,
    ) -> RuntimeRpcState {
        RuntimeRpcState {
            runtime: Arc::new(Mutex::new(runtime)),
            storage: None,
            rpc_limits: RuntimeRpcLimits {
                max_request_bytes,
                max_requests_per_minute,
            },
            sync_peers: RuntimeSyncPeerSet::default(),
            rate_limits: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn test_bridge_deposit(monero_tx_digit: char, proof_digit: char) -> RuntimeBridgeDeposit {
        RuntimeBridgeDeposit {
            monero_tx_id: monero_tx_digit.to_string().repeat(64),
            account: "alice".to_string(),
            amount_nxmr_units: 5_000,
            confirmations: MIN_BRIDGE_CONFIRMATIONS,
            observer_id: "observer-a".to_string(),
            proof_root: proof_digit.to_string().repeat(64),
            custody_proof_root: "7".repeat(64),
            relayer_set_root: "8".repeat(64),
            observer_signature_roots: vec!["9".repeat(64), "a".repeat(64)],
            observed_at_unix_ms: 1,
        }
    }

    #[test]
    fn public_testnet_runtime_uses_sub_second_blocks() {
        let config = RuntimeConfig::public_testnet_default();
        assert!(config.block_target_ms < 1_000);
        let runtime = NebulaRuntime::new(config).unwrap();
        let status = runtime.status();
        assert!(status.sub_second_blocks);
        assert_eq!(status.block_target_ms, DEFAULT_SUBSECOND_BLOCK_MS);
    }

    #[test]
    fn runtime_node_options_default_to_public_rpc_limits() {
        let options = RuntimeNodeOptions::default();
        let limits = RuntimeRpcLimits::from_options(&options).unwrap();

        assert_eq!(limits.max_request_bytes, DEFAULT_MAX_REQUEST_BYTES);
        assert_eq!(
            limits.max_requests_per_minute,
            DEFAULT_MAX_REQUESTS_PER_MINUTE
        );

        let options = RuntimeNodeOptions {
            max_request_bytes: 0,
            ..RuntimeNodeOptions::default()
        };
        assert!(RuntimeRpcLimits::from_options(&options)
            .unwrap_err()
            .contains("max_request_bytes"));

        let options = RuntimeNodeOptions {
            max_requests_per_minute: 0,
            ..RuntimeNodeOptions::default()
        };
        assert!(RuntimeRpcLimits::from_options(&options)
            .unwrap_err()
            .contains("max_requests_per_minute"));
    }

    #[test]
    fn runtime_node_options_collect_distinct_public_sync_peers() {
        let options = RuntimeNodeOptions {
            bootstrap_rpc_url: Some(" http://127.0.0.1:9944/snapshot ".to_string()),
            sync_rpc_url: Some("http://127.0.0.1:9945/snapshot".to_string()),
            sync_rpc_urls: vec![
                "http://127.0.0.1:9945/snapshot".to_string(),
                "http://127.0.0.1:9946/snapshot".to_string(),
            ],
            ..RuntimeNodeOptions::default()
        };
        let peers = RuntimeSyncPeerSet::from_options(&options).unwrap();

        assert_eq!(
            peers.bootstrap_peer_urls,
            vec!["http://127.0.0.1:9944/snapshot"]
        );
        assert_eq!(
            peers.sync_peer_urls,
            vec![
                "http://127.0.0.1:9945/snapshot",
                "http://127.0.0.1:9946/snapshot"
            ]
        );

        let options = RuntimeNodeOptions {
            sync_rpc_url: Some("https://127.0.0.1:9945/snapshot".to_string()),
            ..RuntimeNodeOptions::default()
        };
        assert!(RuntimeSyncPeerSet::from_options(&options)
            .unwrap_err()
            .contains("--sync-rpc"));
    }

    #[test]
    fn runtime_rpc_status_reports_public_rpc_limits() {
        let runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let mut state = test_rpc_state_with_limits(runtime, 2048, 7);
        state.sync_peers = RuntimeSyncPeerSet {
            bootstrap_peer_urls: vec!["http://127.0.0.1:9944/snapshot".to_string()],
            sync_peer_urls: vec![
                "http://127.0.0.1:9945/snapshot".to_string(),
                "http://127.0.0.1:9946/snapshot".to_string(),
            ],
        };
        let status = state.status_json().unwrap();

        assert_eq!(status["rpc_max_request_bytes"], 2048);
        assert_eq!(status["rpc_max_requests_per_minute"], 7);
        assert_eq!(status["sync_peer_count"], 2);
        assert_eq!(
            status["sync_peer_urls"],
            json!([
                "http://127.0.0.1:9945/snapshot",
                "http://127.0.0.1:9946/snapshot"
            ])
        );
        assert_eq!(
            dispatch_json_rpc_method(&state, "nebula_status", json!({})).unwrap()
                ["rpc_max_requests_per_minute"],
            7
        );
    }

    #[test]
    fn runtime_ops_status_reports_missing_public_ops_evidence() {
        let runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        let ops = state.ops_status().unwrap();

        assert!(!ops.public_ops_ready);
        assert!(ops
            .blocking_gaps
            .contains(&"missing-persistent-data-dir".to_string()));
        assert!(ops
            .blocking_gaps
            .contains(&"no-produced-blocks-observed".to_string()));
        assert!(!ops.storage_snapshot_present);
        assert_eq!(ops.ops_root.len(), 64);
    }

    #[test]
    fn runtime_ops_status_and_backup_manifest_bind_persisted_snapshot() {
        let dir = std::env::temp_dir().join(format!("nebula-runtime-ops-test-{}", unix_ms()));
        let storage = RuntimeStorage::from_data_dir(&dir);
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime.faucet("alice").unwrap();
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();
        storage.save_snapshot(&snapshot).unwrap();
        let mut state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.storage = Some(storage.clone());

        let ops = state.ops_status().unwrap();
        assert!(ops.public_ops_ready, "{:?}", ops.blocking_gaps);
        assert_eq!(ops.snapshot_root.len(), 64);
        assert_eq!(
            ops.storage_snapshot_root.as_ref().map(String::len),
            Some(64)
        );
        assert_eq!(ops.storage_snapshot_height, Some(snapshot.latest_height()));
        assert!(ops.storage_snapshot_matches_runtime);
        assert_eq!(
            ops.rpc_max_requests_per_minute,
            DEFAULT_MAX_REQUESTS_PER_MINUTE
        );
        assert_eq!(ops.bridge_policy_root, bridge_policy_root());
        assert_eq!(ops.ops_root.len(), 64);

        let manifest = state.backup_manifest().unwrap();
        assert_eq!(manifest.snapshot_root.len(), 64);
        assert!(manifest.snapshot_persisted);
        assert!(manifest.storage_snapshot_matches_runtime);
        assert_eq!(manifest.backup_root.len(), 64);
        let rpc_ops = dispatch_json_rpc_method(&state, "nebula_opsStatus", json!({})).unwrap();
        assert_eq!(rpc_ops["ops_root"].as_str().unwrap().len(), 64);
        assert_eq!(rpc_ops["public_ops_ready"], true);
        assert_eq!(rpc_ops["storage_snapshot_matches_runtime"], true);
        let rpc_backup =
            dispatch_json_rpc_method(&state, "nebula_backupManifest", json!({})).unwrap();
        assert_eq!(rpc_backup["backup_root"].as_str().unwrap().len(), 64);
        assert_eq!(rpc_backup["snapshot_persisted"], true);
        assert_eq!(rpc_backup["storage_snapshot_matches_runtime"], true);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_rpc_rate_limit_rejects_over_quota_client() {
        let runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let state = test_rpc_state_with_limits(runtime, DEFAULT_MAX_REQUEST_BYTES, 1);

        state.check_request_allowed("127.0.0.1").unwrap();
        assert!(state
            .check_request_allowed("127.0.0.1")
            .unwrap_err()
            .contains("rate limit exceeded"));
        state.check_request_allowed("127.0.0.2").unwrap();
    }

    #[test]
    fn runtime_rpc_request_size_limit_checks_buffer_and_declared_body() {
        let complete_request =
            b"POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}";
        assert!(request_complete(complete_request));
        assert!(!request_size_exceeds_limit(
            complete_request,
            complete_request.len()
        ));
        assert!(request_size_exceeds_limit(
            complete_request,
            complete_request.len() - 1
        ));

        let declared_large =
            b"POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4096\r\n\r\n{}";
        assert!(request_size_exceeds_limit(declared_large, 1024));
    }

    #[test]
    fn runtime_signs_blocks_with_expected_sequencer_key() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();

        assert_eq!(snapshot.snapshot_version, RUNTIME_SNAPSHOT_VERSION);
        for block in &snapshot.blocks {
            assert_eq!(
                block.producer_public_key,
                snapshot.config.sequencer_public_key_hex
            );
            assert_eq!(block.signature.len(), 128);
            verify_block_signature(block, &snapshot.config.sequencer_public_key_hex).unwrap();
        }
        validate_snapshot(&snapshot).unwrap();
    }

    #[test]
    fn runtime_supports_custom_sequencer_signing_key() {
        let secret_key_hex = "1f".repeat(32);
        let public_key_hex = public_key_hex_for_secret(&secret_key_hex).unwrap();
        let mut config = RuntimeConfig::public_testnet_default();
        config.sequencer_public_key_hex = public_key_hex.clone();
        let mut runtime =
            NebulaRuntime::with_sequencer_secret(config.clone(), Some(secret_key_hex)).unwrap();

        let block = runtime.produce_block();
        assert_eq!(block.producer_public_key, public_key_hex);
        assert_eq!(runtime.status().sequencer_public_key_hex, public_key_hex);
        validate_snapshot(&runtime.export_snapshot()).unwrap();

        config.produce_blocks = false;
        let follower = NebulaRuntime::from_snapshot(config, runtime.export_snapshot()).unwrap();
        assert!(!follower.config().produce_blocks);
    }

    #[test]
    fn runtime_rotates_sequencer_key_and_validates_history() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let old_public_key_hex = runtime.config().sequencer_public_key_hex.clone();
        let old_block = runtime.produce_block();
        assert_eq!(old_block.producer_public_key, old_public_key_hex);

        let new_secret_key_hex = "4d".repeat(32);
        let new_public_key_hex = public_key_hex_for_secret(&new_secret_key_hex).unwrap();
        let rotation = runtime
            .rotate_sequencer_key(&new_secret_key_hex, "operator-a", &"b".repeat(64))
            .unwrap();
        assert!(rotation.rotated);
        assert_eq!(rotation.rotation.activation_height, 2);
        assert_eq!(rotation.rotation.old_public_key_hex, old_public_key_hex);
        assert_eq!(rotation.rotation.new_public_key_hex, new_public_key_hex);
        assert_eq!(rotation.sequencer_key_history_root.len(), 64);

        let new_block = runtime.produce_block();
        assert_eq!(new_block.height, 2);
        assert_eq!(new_block.producer_public_key, new_public_key_hex);

        let snapshot = runtime.export_snapshot();
        validate_snapshot(&snapshot).unwrap();
        assert_eq!(snapshot.sequencer_key_rotations.len(), 1);
        assert_eq!(runtime.status().sequencer_key_rotation_count, 1);
        assert_eq!(
            runtime.status().sequencer_latest_rotation_activation_height,
            Some(2)
        );
        assert_eq!(
            runtime.status().sequencer_key_history_root,
            sequencer_key_history_root(&snapshot.sequencer_key_rotations)
        );
        verify_block_signature(&snapshot.blocks[1], &old_public_key_hex).unwrap();
        verify_block_signature(&snapshot.blocks[2], &new_public_key_hex).unwrap();

        let mut follower_config = RuntimeConfig::public_testnet_default();
        follower_config.produce_blocks = false;
        let follower = NebulaRuntime::from_snapshot(follower_config, snapshot.clone()).unwrap();
        assert_eq!(
            follower.config().sequencer_public_key_hex,
            new_public_key_hex
        );
        assert!(follower.sequencer_secret_key_hex.is_none());

        let mut tampered = snapshot;
        tampered.sequencer_key_rotations[0].activation_height = 1;
        tampered.sequencer_key_rotations[0].root =
            sequencer_key_rotation_root(&tampered.sequencer_key_rotations[0]);
        tampered.root = snapshot_root(&tampered);
        assert!(validate_snapshot(&tampered)
            .unwrap_err()
            .contains("block 1 signature rejected"));
    }

    #[test]
    fn runtime_records_equivocation_accountability_report() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime.produce_block();
        let first_block_hash = runtime.latest_block().block_hash;
        let second_block_hash = "e".repeat(64);
        let receipt = runtime
            .report_equivocation(
                1,
                &first_block_hash,
                &second_block_hash,
                "observer-a",
                &"c".repeat(64),
            )
            .unwrap();

        assert!(receipt.recorded);
        assert!(!receipt.sequencer_accountability_clean);
        assert_eq!(receipt.accountability_root.len(), 64);
        assert!(runtime
            .report_equivocation(
                1,
                &second_block_hash,
                &first_block_hash,
                "observer-a",
                &"c".repeat(64),
            )
            .unwrap_err()
            .contains("already exists"));

        let status = runtime.status();
        assert_eq!(status.accountability_report_count, 1);
        assert!(!status.sequencer_accountability_clean);
        validate_snapshot(&runtime.export_snapshot()).unwrap();

        let state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        let ops = state.ops_status().unwrap();
        assert!(!ops.public_ops_ready);
        assert!(ops
            .blocking_gaps
            .contains(&"sequencer-accountability-evidence-open".to_string()));
    }

    #[test]
    fn runtime_rpc_rotates_key_and_reports_equivocation() {
        let runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        let new_secret_key_hex = "5e".repeat(32);
        let new_public_key_hex = public_key_hex_for_secret(&new_secret_key_hex).unwrap();

        let rotation = dispatch_json_rpc_method(
            &state,
            "nebula_rotateSequencerKey",
            json!({
                "new_sequencer_secret_key_hex": new_secret_key_hex,
                "operator_id": "operator-a",
                "approval_root": "d".repeat(64),
            }),
        )
        .unwrap();
        assert_eq!(rotation["rotated"], true);
        assert_eq!(rotation["sequencer_public_key_hex"], new_public_key_hex);

        let block = dispatch_json_rpc_method(&state, "nebula_produceBlock", json!({})).unwrap();
        assert_eq!(block["height"], 1);
        assert_eq!(block["producer_public_key"], new_public_key_hex);

        let receipt = dispatch_json_rpc_method(
            &state,
            "nebula_reportEquivocation",
            json!({
                "height": 1,
                "first_block_hash": block["block_hash"].as_str().unwrap(),
                "second_block_hash": "f".repeat(64),
                "reporter_id": "observer-a",
                "evidence_root": "a".repeat(64),
            }),
        )
        .unwrap();
        assert_eq!(receipt["recorded"], true);
        assert_eq!(receipt["sequencer_accountability_clean"], false);

        let status = dispatch_json_rpc_method(&state, "nebula_status", json!({})).unwrap();
        assert_eq!(status["sequencer_key_rotation_count"], 1);
        assert_eq!(status["sequencer_latest_rotation_activation_height"], 1);
        assert_eq!(status["accountability_report_count"], 1);
        assert_eq!(status["sequencer_accountability_clean"], false);
    }

    #[test]
    fn custom_sequencer_key_requires_matching_secret_for_production() {
        let secret_key_hex = "2a".repeat(32);
        let public_key_hex = public_key_hex_for_secret(&secret_key_hex).unwrap();
        let mut config = RuntimeConfig::public_testnet_default();
        config.sequencer_public_key_hex = public_key_hex;

        assert!(NebulaRuntime::new(config)
            .unwrap_err()
            .contains("sequencer_secret_key_hex is required"));
    }

    #[test]
    fn snapshot_rejects_tampered_block_signature() {
        let runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let mut snapshot = runtime.export_snapshot();
        snapshot.blocks[0].signature = "0".repeat(128);
        snapshot.root = snapshot_root(&snapshot);

        assert!(validate_snapshot(&snapshot)
            .unwrap_err()
            .contains("signature"));
    }

    #[test]
    fn follower_rejects_snapshot_from_unexpected_sequencer_key() {
        let secret_key_hex = "3b".repeat(32);
        let public_key_hex = public_key_hex_for_secret(&secret_key_hex).unwrap();
        let mut sequencer_config = RuntimeConfig::public_testnet_default();
        sequencer_config.sequencer_public_key_hex = public_key_hex;
        let mut sequencer =
            NebulaRuntime::with_sequencer_secret(sequencer_config, Some(secret_key_hex)).unwrap();
        sequencer.produce_block();

        let mut follower_config = RuntimeConfig::public_testnet_default();
        follower_config.produce_blocks = false;
        assert!(
            NebulaRuntime::from_snapshot(follower_config, sequencer.export_snapshot())
                .unwrap_err()
                .contains("sequencer_public_key_hex")
        );
    }

    #[test]
    fn exported_snapshot_does_not_include_sequencer_secret_key() {
        let runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let snapshot_json = serde_json::to_string(&runtime.export_snapshot()).unwrap();

        assert!(snapshot_json.contains(&default_dev_sequencer_public_key_hex()));
        assert!(!snapshot_json.contains(DEFAULT_DEV_SEQUENCER_SECRET_KEY_HEX));
        assert!(!snapshot_json.contains("sequencer_secret_key_hex"));
    }

    #[test]
    fn runtime_includes_nbla_fee_transaction_and_rewards_validator() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime.faucet("alice").unwrap();
        let tx = RuntimeTransaction {
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount_nebulai: 10,
            gas_units: 5,
            gas_price_nebulai: 2,
            fee_asset: NBLA_SYMBOL.to_string(),
            nonce: 0,
            memo: None,
        };
        let tx_id = runtime.submit_transaction(tx).unwrap().tx_id;
        let block = runtime.produce_block();
        assert_eq!(block.height, 1);
        assert_eq!(block.transactions.len(), 1);
        let receipt = runtime.receipt(&tx_id).unwrap();
        assert_eq!(receipt.status, TransactionStatus::Included);
        assert_eq!(receipt.validator_reward_nebulai, 10);
        assert_eq!(runtime.account("bob").unwrap().nbla_nebulai, 10);
        let reward_account = runtime
            .account(&runtime.config().validator_reward_account())
            .unwrap();
        assert_eq!(reward_account.nbla_nebulai, 10);
    }

    #[test]
    fn runtime_accounts_for_nxmr_fee_buyback_pool() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime.faucet("alice").unwrap();
        let tx = RuntimeTransaction {
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount_nebulai: 100,
            gas_units: 100,
            gas_price_nebulai: 10,
            fee_asset: NXMR_SYMBOL.to_string(),
            nonce: 0,
            memo: None,
        };
        let tx_id = runtime.submit_transaction(tx).unwrap().tx_id;
        runtime.produce_block();
        let receipt = runtime.receipt(&tx_id).unwrap();
        assert_eq!(receipt.status, TransactionStatus::Included);
        assert_eq!(receipt.paid_amount_units, 1_000);
        assert_eq!(receipt.buyback_nebulai, 900);
        assert_eq!(receipt.validator_reward_nebulai, 100);
        let status = runtime.status();
        assert_eq!(status.total_nxmr_fees_units, 1_000);
        assert_eq!(status.buyback_pool_nebulai, 900);
        assert_eq!(status.validator_reward_nebulai, 100);
    }

    #[test]
    fn runtime_bridge_deposit_requires_confirmations_and_credits_nxmr() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let mut deposit = test_bridge_deposit('a', 'b');
        deposit.confirmations = MIN_BRIDGE_CONFIRMATIONS - 1;
        assert!(runtime.observe_bridge_deposit(deposit.clone()).is_err());

        deposit.confirmations = MIN_BRIDGE_CONFIRMATIONS;
        let report = runtime.observe_bridge_deposit(deposit).unwrap();
        assert!(report.credited);
        assert_eq!(report.deposit_root.len(), 64);
        assert_eq!(runtime.account("alice").unwrap().nxmr_units, 5_000);
        assert_eq!(runtime.status().bridge_deposit_count, 1);
    }

    #[test]
    fn runtime_withdrawal_burns_nxmr_into_operator_pending_request() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime
            .observe_bridge_deposit(test_bridge_deposit('c', 'd'))
            .unwrap();

        let report = runtime
            .request_withdrawal("alice", "9xTestnetMoneroAddressForNebulaWithdrawals", 2_000)
            .unwrap();
        assert!(report.accepted);
        assert_eq!(report.withdrawal.status, "operator_pending");
        assert_eq!(report.withdrawal.bridge_policy_root, bridge_policy_root());
        assert!(report.withdrawal.operator_approval_roots.is_empty());
        assert_eq!(report.withdrawal.root.len(), 64);
        assert_eq!(report.account_state.nxmr_units, 3_000);
        assert_eq!(runtime.status().withdrawal_request_count, 1);
    }

    #[test]
    fn runtime_bridge_policy_is_reported_in_status() {
        let runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let status = runtime.status();

        assert_eq!(status.bridge_policy_root, bridge_policy_root());
        assert_eq!(
            status.bridge_min_deposit_confirmations,
            MIN_BRIDGE_CONFIRMATIONS
        );
        assert_eq!(
            status.bridge_deposit_observer_quorum,
            MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM
        );
        assert_eq!(
            status.bridge_withdrawal_operator_quorum,
            MIN_WITHDRAWAL_OPERATOR_QUORUM
        );
        assert!(!status.bridge_live_value_enabled);
    }

    #[test]
    fn runtime_bridge_deposit_requires_observer_quorum_and_custody_roots() {
        let mut deposit = test_bridge_deposit('b', 'c');
        deposit.observer_signature_roots = vec!["1".repeat(64)];
        assert!(validate_bridge_deposit(&deposit)
            .unwrap_err()
            .contains("observer_signature_roots"));

        deposit = test_bridge_deposit('b', 'c');
        deposit.observer_signature_roots = vec!["1".repeat(64), "1".repeat(64)];
        assert!(validate_bridge_deposit(&deposit)
            .unwrap_err()
            .contains("duplicates"));

        deposit = test_bridge_deposit('b', 'c');
        deposit.custody_proof_root = "not-hex".to_string();
        assert!(validate_bridge_deposit(&deposit)
            .unwrap_err()
            .contains("custody_proof_root"));
    }

    #[test]
    fn runtime_withdrawal_finalization_requires_operator_quorum_and_prevents_replay() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime
            .observe_bridge_deposit(test_bridge_deposit('d', 'e'))
            .unwrap();
        let withdrawal_id = runtime
            .request_withdrawal("alice", "9xTestnetMoneroAddressForNebulaWithdrawals", 2_000)
            .unwrap()
            .withdrawal
            .withdrawal_id;
        let finalized_tx_id = "f".repeat(64);

        assert!(runtime
            .finalize_withdrawal(
                &withdrawal_id,
                &finalized_tx_id,
                &"1".repeat(64),
                vec!["2".repeat(64)]
            )
            .unwrap_err()
            .contains("operator_approval_roots"));

        let report = runtime
            .finalize_withdrawal(
                &withdrawal_id,
                &finalized_tx_id,
                &"1".repeat(64),
                vec!["2".repeat(64), "3".repeat(64)],
            )
            .unwrap();
        assert!(report.finalized);
        assert_eq!(
            report.operator_approval_count,
            MIN_WITHDRAWAL_OPERATOR_QUORUM
        );
        assert_eq!(report.withdrawal.status, "finalized");
        assert_eq!(
            report.withdrawal.finalized_monero_tx_id.as_deref(),
            Some(finalized_tx_id.as_str())
        );
        assert_eq!(report.finalization_root, report.withdrawal.root);

        runtime
            .observe_bridge_deposit(test_bridge_deposit('4', '5'))
            .unwrap();
        let second_withdrawal_id = runtime
            .request_withdrawal("alice", "9xTestnetMoneroAddressForNebulaWithdrawals", 1_000)
            .unwrap()
            .withdrawal
            .withdrawal_id;
        assert!(runtime
            .finalize_withdrawal(
                &second_withdrawal_id,
                &finalized_tx_id,
                &"6".repeat(64),
                vec!["7".repeat(64), "8".repeat(64)]
            )
            .unwrap_err()
            .contains("already finalized"));
        assert!(runtime
            .finalize_withdrawal(
                &second_withdrawal_id,
                &"a".repeat(64),
                &"1".repeat(64),
                vec!["7".repeat(64), "8".repeat(64)]
            )
            .unwrap_err()
            .contains("already used"));

        let status = runtime.status();
        assert_eq!(status.finalized_withdrawal_count, 1);
        assert_eq!(status.bridge_replay_cache_count, 3);
    }

    #[test]
    fn snapshot_round_trips_pending_mempool_and_preserves_genesis() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let genesis_hash = runtime.latest_block().block_hash;
        runtime.faucet("alice").unwrap();
        let tx = RuntimeTransaction {
            from: "alice".to_string(),
            to: "bob".to_string(),
            amount_nebulai: 100,
            gas_units: 10,
            gas_price_nebulai: 1,
            fee_asset: NBLA_SYMBOL.to_string(),
            nonce: 0,
            memo: Some("pending before restart".to_string()),
        };
        let tx_id = runtime.submit_transaction(tx).unwrap().tx_id;
        let snapshot = runtime.export_snapshot();

        let mut config = RuntimeConfig::public_testnet_default();
        config.validator_id = "validator-after-restart".to_string();
        let mut restored = NebulaRuntime::from_snapshot(config, snapshot).unwrap();
        assert_eq!(restored.latest_block().block_hash, genesis_hash);
        assert_eq!(
            restored.receipt(&tx_id).unwrap().status,
            TransactionStatus::Pending
        );

        let block = restored.produce_block();
        assert_eq!(block.height, 1);
        assert_eq!(block.producer, "validator-after-restart");
        assert_eq!(
            restored.receipt(&tx_id).unwrap().status,
            TransactionStatus::Included
        );
        assert_eq!(restored.account("bob").unwrap().nbla_nebulai, 100);
    }

    #[test]
    fn snapshot_rejects_tampered_state_root_and_block_hash() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime.faucet("alice").unwrap();
        let mut snapshot = runtime.export_snapshot();
        snapshot.accounts.get_mut("alice").unwrap().nbla_nebulai += 1;
        snapshot.root = snapshot_root(&snapshot);
        assert!(validate_snapshot(&snapshot)
            .unwrap_err()
            .contains("state_root"));

        let mut snapshot = runtime.export_snapshot();
        snapshot.blocks[0].block_hash = "f".repeat(64);
        snapshot.root = snapshot_root(&snapshot);
        assert!(validate_snapshot(&snapshot)
            .unwrap_err()
            .contains("block_hash"));
    }

    #[test]
    fn storage_round_trips_snapshot_from_disk() {
        let dir = std::env::temp_dir().join(format!(
            "nebula-runtime-storage-test-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        let storage = RuntimeStorage::from_data_dir(&dir);
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime.faucet("alice").unwrap();
        storage.save_runtime(&runtime).unwrap();

        let snapshot = storage.load_snapshot().unwrap().unwrap();
        let restored =
            NebulaRuntime::from_snapshot(RuntimeConfig::public_testnet_default(), snapshot)
                .unwrap();
        assert_eq!(
            restored.account("alice").unwrap().nbla_nebulai,
            runtime.account("alice").unwrap().nbla_nebulai
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bridge_deposit_and_withdrawal_survive_snapshot_without_double_credit() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let deposit = test_bridge_deposit('e', 'f');
        runtime.observe_bridge_deposit(deposit.clone()).unwrap();
        runtime
            .request_withdrawal("alice", "9xTestnetMoneroAddressForNebulaWithdrawals", 2_000)
            .unwrap();
        let snapshot = runtime.export_snapshot();
        let mut restored =
            NebulaRuntime::from_snapshot(RuntimeConfig::public_testnet_default(), snapshot)
                .unwrap();

        assert_eq!(restored.account("alice").unwrap().nxmr_units, 3_000);
        assert!(restored.observe_bridge_deposit(deposit).is_err());
        assert_eq!(restored.status().bridge_deposit_count, 1);
        assert_eq!(restored.status().withdrawal_request_count, 1);
    }

    #[test]
    fn snapshot_extends_rejects_forked_peer_prefix() {
        let runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let local = runtime.export_snapshot();
        let mut peer = local.clone();
        peer.blocks[0].block_hash = "a".repeat(64);
        assert!(!snapshot_extends(&local, &peer));
    }

    #[test]
    fn sync_peer_selection_uses_highest_extending_snapshot() {
        let mut sequencer = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let local = sequencer.export_snapshot();

        sequencer.faucet("alice").unwrap();
        sequencer.produce_block();
        let height_one = sequencer.export_snapshot();
        sequencer.faucet("bob").unwrap();
        sequencer.produce_block();
        let height_two = sequencer.export_snapshot();

        let selected = select_best_extending_snapshot(
            &local,
            vec![
                ("http://127.0.0.1:9945/snapshot".to_string(), height_one),
                ("http://127.0.0.1:9946/snapshot".to_string(), height_two),
            ],
        )
        .unwrap()
        .unwrap();

        assert_eq!(selected.0, "http://127.0.0.1:9946/snapshot");
        assert_eq!(selected.1.latest_height(), 2);
    }

    #[test]
    fn sync_peer_selection_rejects_only_forked_ahead_snapshots() {
        let mut sequencer = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let local = sequencer.export_snapshot();
        sequencer.faucet("alice").unwrap();
        sequencer.produce_block();
        let mut forked = sequencer.export_snapshot();
        forked.blocks[0].block_hash = "a".repeat(64);

        assert!(select_best_extending_snapshot(
            &local,
            vec![("http://127.0.0.1:9945/snapshot".to_string(), forked)]
        )
        .unwrap_err()
        .contains("does not extend local height"));
    }

    #[test]
    fn follower_mode_does_not_produce_blocks_or_accept_mutations() {
        let mut config = RuntimeConfig::public_testnet_default();
        config.produce_blocks = false;
        let runtime = NebulaRuntime::new(config).unwrap();
        let state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );

        assert!(
            dispatch_json_rpc_method(&state, "nebula_faucet", json!({"account": "alice"}))
                .unwrap_err()
                .contains("follower mode")
        );
        assert!(
            dispatch_json_rpc_method(&state, "nebula_produceBlock", json!({}))
                .unwrap_err()
                .contains("follower mode")
        );
        let status = dispatch_json_rpc_method(&state, "nebula_status", json!({})).unwrap();
        assert_eq!(status["node_role"], "follower");
        assert_eq!(status["block_production_enabled"], false);
    }

    #[test]
    fn follower_sync_imports_ahead_snapshot_and_keeps_follower_role() {
        let mut sequencer = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        sequencer.faucet("alice").unwrap();
        sequencer.produce_block();
        sequencer.produce_block();
        let peer_snapshot = sequencer.export_snapshot();

        let mut follower_config = RuntimeConfig::public_testnet_default();
        follower_config.produce_blocks = false;
        follower_config.validator_id = "follower-a".to_string();
        let follower = NebulaRuntime::from_snapshot(follower_config, peer_snapshot).unwrap();

        assert_eq!(follower.latest_block().height, 2);
        assert!(!follower.config().produce_blocks);
        assert_eq!(
            follower.config().validator_reward_account(),
            "validator:follower-a"
        );
        assert_eq!(
            follower.account("alice").unwrap().nbla_nebulai,
            DEFAULT_FAUCET_NBLA
        );
    }

    #[test]
    fn runtime_rejects_blocks_at_or_above_one_second() {
        let mut config = RuntimeConfig::public_testnet_default();
        config.block_target_ms = 1_000;
        assert!(NebulaRuntime::new(config).is_err());
    }
}
