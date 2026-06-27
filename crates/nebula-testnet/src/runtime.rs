use crate::{
    quote_hybrid_fee, FeeAsset, HybridFeeQuote, CHAIN_ID, NBLA_SYMBOL, NEBULAI_PER_NBLA,
    NXMR_SYMBOL, TARGET_NXMR_TO_NBLA_RATE_NEBULAI_PER_UNIT, VERSION,
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
pub const DEFAULT_MAX_MEMPOOL_TRANSACTIONS: usize = 10_000;
pub const DEFAULT_FAUCET_NBLA: u128 = 10_000 * NEBULAI_PER_NBLA;
pub const DEFAULT_FAUCET_NXMR: u128 = 0;
pub const MIN_BRIDGE_CONFIRMATIONS: u64 = 10;
pub const MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM: usize = 2;
pub const MIN_WITHDRAWAL_OPERATOR_QUORUM: usize = 2;
pub const BRIDGE_CUSTODY_POLICY_ID: &str = "nebula-monero-bridge-custody-testnet-v1";
pub const VALIDATOR_REWARD_ACCOUNT_PREFIX: &str = "validator:";
pub const RUNTIME_SNAPSHOT_FILE: &str = "nebula-runtime-snapshot.json";
pub const RUNTIME_SNAPSHOT_VERSION: u32 = 11;
pub const DEFAULT_PEER_SYNC_MS: u64 = 100;
pub const DEFAULT_SYNC_PEER_QUORUM: usize = 1;
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
    pub sync_peer_quorum: usize,
    pub auto_produce_blocks: bool,
    pub sequencer_secret_key_hex: Option<String>,
    pub admin_rpc_bind_addr: Option<String>,
    pub admin_token: Option<String>,
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
            sync_peer_quorum: DEFAULT_SYNC_PEER_QUORUM,
            auto_produce_blocks: true,
            sequencer_secret_key_hex: None,
            admin_rpc_bind_addr: None,
            admin_token: None,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_binding: Option<RuntimeLaunchBinding>,
    pub validator_id: String,
    pub block_target_ms: u64,
    pub gas_price_nebulai: u128,
    pub max_block_transactions: usize,
    pub max_mempool_transactions: usize,
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
            launch_binding: None,
            validator_id: "validator-a".to_string(),
            block_target_ms: DEFAULT_SUBSECOND_BLOCK_MS,
            gas_price_nebulai: DEFAULT_GAS_PRICE_NEBULAI,
            max_block_transactions: DEFAULT_MAX_BLOCK_TRANSACTIONS,
            max_mempool_transactions: DEFAULT_MAX_MEMPOOL_TRANSACTIONS,
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
        if self.max_mempool_transactions == 0 {
            return Err("max_mempool_transactions must be greater than zero".to_string());
        }
        if self.faucet_nxmr_units != 0 {
            return Err(
                "faucet_nxmr_units must be zero; nXMR is credited only by bridge deposits"
                    .to_string(),
            );
        }
        validate_fixed_hex(
            &self.sequencer_public_key_hex,
            "sequencer_public_key_hex",
            64,
        )?;
        if let Some(launch_binding) = &self.launch_binding {
            launch_binding.validate_against_config(self)?;
        }
        Ok(())
    }

    pub fn validator_reward_account(&self) -> String {
        format!("{VALIDATOR_REWARD_ACCOUNT_PREFIX}{}", self.validator_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBridgeOperatorKey {
    pub operator_id: String,
    pub region: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBridgeObserverKey {
    pub observer_id: String,
    pub region: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLaunchBinding {
    pub chain_id: String,
    pub runtime_version: String,
    pub endpoint_url: String,
    pub deployment_attestation_root: String,
    pub public_status_manifest_root: String,
    pub public_probe_root: String,
    pub validator_set_root: String,
    pub operator_handoff_root: String,
    pub operator_acceptance_root: String,
    pub genesis_root: String,
    pub launch_package_root: String,
    pub launch_package_bundle_root: String,
    pub activation_height: u64,
    pub validator_count: usize,
    pub operator_count: usize,
    pub region_count: usize,
    pub bridge_operator_keys: Vec<RuntimeBridgeOperatorKey>,
    pub bridge_observer_keys: Vec<RuntimeBridgeObserverKey>,
}

impl RuntimeLaunchBinding {
    pub fn validate_against_config(&self, config: &RuntimeConfig) -> Result<(), String> {
        if self.chain_id != config.chain_id {
            return Err(format!(
                "launch binding chain_id {} does not match runtime chain_id {}",
                self.chain_id, config.chain_id
            ));
        }
        if self.runtime_version != config.runtime_version {
            return Err(format!(
                "launch binding runtime_version {} does not match runtime_version {}",
                self.runtime_version, config.runtime_version
            ));
        }
        parse_https_url(&self.endpoint_url)
            .map_err(|error| format!("launch binding endpoint_url: {error}"))?;
        validate_fixed_hex(
            &self.deployment_attestation_root,
            "deployment_attestation_root",
            64,
        )?;
        validate_fixed_hex(
            &self.public_status_manifest_root,
            "public_status_manifest_root",
            64,
        )?;
        validate_fixed_hex(&self.public_probe_root, "public_probe_root", 64)?;
        validate_fixed_hex(&self.validator_set_root, "validator_set_root", 64)?;
        validate_fixed_hex(&self.operator_handoff_root, "operator_handoff_root", 64)?;
        validate_fixed_hex(
            &self.operator_acceptance_root,
            "operator_acceptance_root",
            64,
        )?;
        validate_fixed_hex(&self.genesis_root, "genesis_root", 64)?;
        validate_fixed_hex(&self.launch_package_root, "launch_package_root", 64)?;
        validate_fixed_hex(
            &self.launch_package_bundle_root,
            "launch_package_bundle_root",
            64,
        )?;
        if self.activation_height == 0 {
            return Err("launch binding activation_height must be greater than zero".to_string());
        }
        if self.validator_count == 0 {
            return Err("launch binding validator_count must be greater than zero".to_string());
        }
        if self.operator_count == 0 {
            return Err("launch binding operator_count must be greater than zero".to_string());
        }
        if self.region_count == 0 {
            return Err("launch binding region_count must be greater than zero".to_string());
        }
        validate_launch_bridge_operator_keys(self)?;
        validate_launch_bridge_observer_keys(self)?;
        if self.bridge_operator_keys.len() != self.operator_count {
            return Err(format!(
                "launch binding operator_count {} does not match bridge_operator_keys length {}",
                self.operator_count,
                self.bridge_operator_keys.len()
            ));
        }
        Ok(())
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
    pub signature: String,
    #[serde(default)]
    pub memo: Option<String>,
}

impl RuntimeTransaction {
    pub fn fee_asset_kind(&self) -> Result<FeeAsset, String> {
        parse_fee_asset(&self.fee_asset)
    }

    pub fn signing_root(&self) -> String {
        stable_runtime_root(&json!({
            "tx_domain": "nebula-runtime-transaction-signing-v1",
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

    pub fn id(&self) -> String {
        stable_runtime_root(&json!({
            "tx_domain": "nebula-runtime-transaction-v2",
            "signing_root": self.signing_root(),
            "signature": self.signature,
        }))
    }
}

pub fn withdrawal_authorization_root(
    account: &str,
    monero_address: &str,
    amount_nxmr_units: u128,
    nonce: u64,
) -> String {
    stable_runtime_root(&json!({
        "withdrawal_authorization_domain": "nebula-runtime-withdrawal-authorization-v1",
        "account": account,
        "monero_address": monero_address,
        "amount_nxmr_units": amount_nxmr_units,
        "nonce": nonce,
        "bridge_policy_root": bridge_policy_root(),
    }))
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
pub struct RuntimeBridgeObserverEvidence {
    pub observer_id: String,
    pub observer_public_key_hex: String,
    pub payload_root: String,
    pub signature: String,
    pub signed_at_unix_ms: u128,
    pub evidence_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBridgeDeposit {
    pub monero_tx_id: String,
    pub account: String,
    pub amount_nxmr_units: u128,
    pub confirmations: u64,
    pub observer_id: String,
    pub observer_ids: Vec<String>,
    pub proof_root: String,
    pub custody_proof_root: String,
    pub relayer_set_root: String,
    pub observer_signature_roots: Vec<String>,
    #[serde(default)]
    pub observer_evidence: Vec<RuntimeBridgeObserverEvidence>,
    pub observed_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWithdrawalOperatorApproval {
    pub operator_id: String,
    pub operator_public_key_hex: String,
    pub payload_root: String,
    pub signature: String,
    pub signed_at_unix_ms: u128,
    pub approval_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWithdrawalRequest {
    pub withdrawal_id: String,
    pub account: String,
    pub monero_address: String,
    pub amount_nxmr_units: u128,
    pub nonce: u64,
    pub signature: String,
    pub requested_at_unix_ms: u128,
    pub status: String,
    pub bridge_policy_root: String,
    pub operator_approval_ids: Vec<String>,
    pub operator_approval_roots: Vec<String>,
    #[serde(default)]
    pub operator_approvals: Vec<RuntimeWithdrawalOperatorApproval>,
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
    pub mempool_full_rejection_count: u64,
    pub mempool_admission_rejection_count: u64,
    pub sequencer_key_rotations: Vec<RuntimeSequencerKeyRotation>,
    pub accountability_reports: Vec<RuntimeAccountabilityReport>,
    pub root: String,
}

impl RuntimeSnapshot {
    pub fn latest_height(&self) -> u64 {
        self.blocks.last().map(|block| block.height).unwrap_or(0)
    }

    pub fn latest_block_hash(&self) -> Option<&str> {
        self.blocks.last().map(|block| block.block_hash.as_str())
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub chain_id: String,
    pub runtime_version: String,
    pub launch_binding_present: bool,
    pub launch_endpoint_url: Option<String>,
    pub deployment_attestation_root: Option<String>,
    pub public_status_manifest_root: Option<String>,
    pub public_probe_root: Option<String>,
    pub validator_set_root: Option<String>,
    pub operator_handoff_root: Option<String>,
    pub operator_acceptance_root: Option<String>,
    pub genesis_root: Option<String>,
    pub launch_package_root: Option<String>,
    pub launch_package_bundle_root: Option<String>,
    pub launch_activation_height: Option<u64>,
    pub launch_validator_count: Option<usize>,
    pub launch_operator_count: Option<usize>,
    pub launch_region_count: Option<usize>,
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
    pub max_mempool_transactions: usize,
    pub mempool_capacity_remaining: usize,
    pub mempool_full_rejection_count: u64,
    pub mempool_admission_rejection_count: u64,
    pub account_count: usize,
    pub bridge_deposit_count: usize,
    pub withdrawal_request_count: usize,
    pub finalized_withdrawal_count: usize,
    pub total_nxmr_fees_units: u128,
    pub buyback_pool_nebulai: u128,
    pub validator_reward_nebulai: u128,
    pub validator_reward_account: String,
    pub faucet_nbla_nebulai: u128,
    pub faucet_nxmr_units: u128,
    pub bridge_only_nxmr: bool,
    pub bridge_deposited_nxmr_units: u128,
    pub account_nxmr_units: u128,
    pub withdrawal_reserved_nxmr_units: u128,
    pub nxmr_fee_units: u128,
    pub nxmr_custody_required_units: u128,
    pub nxmr_custody_surplus_units: u128,
    pub nxmr_custody_deficit_units: u128,
    pub bridge_custody_reconciled: bool,
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
    pub deposit_observer_identity_quorum_required: bool,
    pub min_withdrawal_operator_quorum: usize,
    pub withdrawal_operator_identity_quorum_required: bool,
    pub replay_protection: &'static str,
    pub live_value_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeOpsStatus {
    pub service: String,
    pub generated_at_unix_ms: u128,
    pub chain_id: String,
    pub runtime_version: String,
    pub launch_binding_present: bool,
    pub launch_endpoint_url: Option<String>,
    pub deployment_attestation_root: Option<String>,
    pub public_status_manifest_root: Option<String>,
    pub public_probe_root: Option<String>,
    pub validator_set_root: Option<String>,
    pub operator_handoff_root: Option<String>,
    pub operator_acceptance_root: Option<String>,
    pub genesis_root: Option<String>,
    pub launch_package_root: Option<String>,
    pub launch_package_bundle_root: Option<String>,
    pub launch_activation_height: Option<u64>,
    pub launch_validator_count: Option<usize>,
    pub launch_operator_count: Option<usize>,
    pub launch_region_count: Option<usize>,
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
    pub sync_peer_quorum: usize,
    pub sync_quorum_met: bool,
    pub sync_quorum_peer_count: usize,
    pub sync_quorum_height: Option<u64>,
    pub sync_quorum_latest_hash: Option<String>,
    pub sync_quorum_state_root: Option<String>,
    pub sync_successful_peer_count: usize,
    pub sync_failed_peer_count: usize,
    pub sync_attempt_count: u64,
    pub sync_success_count: u64,
    pub sync_failure_count: u64,
    pub sync_stale_snapshot_count: u64,
    pub sync_fork_rejection_count: u64,
    pub sync_quorum_rejection_count: u64,
    pub sync_import_count: u64,
    pub sync_last_success_unix_ms: Option<u128>,
    pub sync_last_import_height: Option<u64>,
    pub sync_peer_telemetry: Vec<RuntimeSyncPeerTelemetry>,
    pub rpc_max_request_bytes: usize,
    pub rpc_max_requests_per_minute: u32,
    pub admin_rpc_enabled: bool,
    pub admin_rpc_private_listener: bool,
    pub public_rpc_admin_methods_enabled: bool,
    pub default_dev_sequencer_key: bool,
    pub max_mempool_transactions: usize,
    pub mempool_size: usize,
    pub mempool_capacity_remaining: usize,
    pub mempool_full_rejection_count: u64,
    pub mempool_admission_rejection_count: u64,
    pub sequencer_public_key_hex: String,
    pub sequencer_key_rotation_count: usize,
    pub sequencer_latest_rotation_activation_height: Option<u64>,
    pub sequencer_key_history_root: String,
    pub accountability_report_count: usize,
    pub accountability_root: String,
    pub sequencer_accountability_clean: bool,
    pub bridge_policy_root: String,
    pub bridge_live_value_enabled: bool,
    pub faucet_nbla_nebulai: u128,
    pub faucet_nxmr_units: u128,
    pub bridge_only_nxmr: bool,
    pub bridge_deposited_nxmr_units: u128,
    pub account_nxmr_units: u128,
    pub withdrawal_reserved_nxmr_units: u128,
    pub nxmr_fee_units: u128,
    pub nxmr_custody_required_units: u128,
    pub nxmr_custody_surplus_units: u128,
    pub nxmr_custody_deficit_units: u128,
    pub bridge_custody_reconciled: bool,
    pub public_ops_ready: bool,
    pub blocking_gaps: Vec<String>,
    pub ops_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeBackupManifest {
    pub manifest_version: u32,
    pub generated_at_unix_ms: u128,
    pub chain_id: String,
    pub runtime_version: String,
    pub launch_binding_present: bool,
    pub launch_endpoint_url: Option<String>,
    pub deployment_attestation_root: Option<String>,
    pub public_status_manifest_root: Option<String>,
    pub public_probe_root: Option<String>,
    pub validator_set_root: Option<String>,
    pub operator_handoff_root: Option<String>,
    pub operator_acceptance_root: Option<String>,
    pub genesis_root: Option<String>,
    pub launch_package_root: Option<String>,
    pub launch_package_bundle_root: Option<String>,
    pub launch_activation_height: Option<u64>,
    pub launch_validator_count: Option<usize>,
    pub launch_operator_count: Option<usize>,
    pub launch_region_count: Option<usize>,
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
    pub sync_peer_quorum: usize,
    pub sync_quorum_met: bool,
    pub sync_quorum_peer_count: usize,
    pub sync_quorum_height: Option<u64>,
    pub sync_quorum_latest_hash: Option<String>,
    pub sync_quorum_state_root: Option<String>,
    pub sync_successful_peer_count: usize,
    pub sync_failed_peer_count: usize,
    pub sync_attempt_count: u64,
    pub sync_success_count: u64,
    pub sync_failure_count: u64,
    pub sync_stale_snapshot_count: u64,
    pub sync_fork_rejection_count: u64,
    pub sync_quorum_rejection_count: u64,
    pub sync_import_count: u64,
    pub sync_last_success_unix_ms: Option<u128>,
    pub sync_last_import_height: Option<u64>,
    pub sync_peer_telemetry: Vec<RuntimeSyncPeerTelemetry>,
    pub rpc_max_request_bytes: usize,
    pub rpc_max_requests_per_minute: u32,
    pub admin_rpc_enabled: bool,
    pub admin_rpc_private_listener: bool,
    pub public_rpc_admin_methods_enabled: bool,
    pub default_dev_sequencer_key: bool,
    pub max_mempool_transactions: usize,
    pub mempool_size: usize,
    pub mempool_capacity_remaining: usize,
    pub mempool_full_rejection_count: u64,
    pub mempool_admission_rejection_count: u64,
    pub faucet_nbla_nebulai: u128,
    pub faucet_nxmr_units: u128,
    pub bridge_only_nxmr: bool,
    pub bridge_deposited_nxmr_units: u128,
    pub account_nxmr_units: u128,
    pub withdrawal_reserved_nxmr_units: u128,
    pub nxmr_fee_units: u128,
    pub nxmr_custody_required_units: u128,
    pub nxmr_custody_surplus_units: u128,
    pub nxmr_custody_deficit_units: u128,
    pub bridge_custody_reconciled: bool,
    pub backup_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubmitTransactionReport {
    pub accepted_to_mempool: bool,
    pub tx_id: String,
    pub status: TransactionStatus,
    pub mempool_size: usize,
    pub max_mempool_transactions: usize,
    pub mempool_capacity_remaining: usize,
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
    mempool_full_rejection_count: u64,
    mempool_admission_rejection_count: u64,
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
    sync_telemetry: Arc<Mutex<BTreeMap<String, RuntimeSyncPeerTelemetry>>>,
    admin_token: Option<String>,
    admin_rpc_private_listener: bool,
    rate_limits: Arc<Mutex<BTreeMap<String, RuntimeRateLimitBucket>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeRpcAccess {
    Public,
    Admin,
}

impl RuntimeRpcAccess {
    fn allows_admin_methods(self) -> bool {
        matches!(self, Self::Admin)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct RuntimeRpcLimits {
    max_request_bytes: usize,
    max_requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeSyncPeerSet {
    bootstrap_peer_urls: Vec<String>,
    sync_peer_urls: Vec<String>,
    sync_peer_quorum: usize,
}

impl Default for RuntimeSyncPeerSet {
    fn default() -> Self {
        Self {
            bootstrap_peer_urls: Vec::new(),
            sync_peer_urls: Vec::new(),
            sync_peer_quorum: DEFAULT_SYNC_PEER_QUORUM,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeSyncPeerTelemetry {
    pub url: String,
    pub last_attempt_unix_ms: Option<u128>,
    pub last_success_unix_ms: Option<u128>,
    pub last_import_unix_ms: Option<u128>,
    pub last_error_unix_ms: Option<u128>,
    pub last_latency_ms: Option<u128>,
    pub last_seen_height: Option<u64>,
    pub last_seen_latest_hash: Option<String>,
    pub last_seen_state_root: Option<String>,
    pub last_seen_snapshot_root: Option<String>,
    pub last_import_height: Option<u64>,
    pub last_import_snapshot_root: Option<String>,
    pub last_error: Option<String>,
    pub attempt_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub stale_snapshot_count: u64,
    pub fork_rejection_count: u64,
    pub quorum_rejection_count: u64,
    pub import_count: u64,
}

#[derive(Debug, Clone, Default)]
struct RuntimeSyncTelemetrySummary {
    peer_telemetry: Vec<RuntimeSyncPeerTelemetry>,
    quorum_met: bool,
    quorum_peer_count: usize,
    quorum_height: Option<u64>,
    quorum_latest_hash: Option<String>,
    quorum_state_root: Option<String>,
    successful_peer_count: usize,
    failed_peer_count: usize,
    attempt_count: u64,
    success_count: u64,
    failure_count: u64,
    stale_snapshot_count: u64,
    fork_rejection_count: u64,
    quorum_rejection_count: u64,
    import_count: u64,
    last_success_unix_ms: Option<u128>,
    last_import_height: Option<u64>,
}

#[derive(Debug, Clone)]
struct RuntimeRateLimitBucket {
    window_start_unix_ms: u128,
    request_count: u32,
}

fn sync_quorum_summary(
    peer_telemetry: &[RuntimeSyncPeerTelemetry],
    required_quorum: usize,
) -> (bool, usize, Option<u64>, Option<String>, Option<String>) {
    let required_quorum = required_quorum.max(1);
    let mut groups: BTreeMap<(u64, String, String), usize> = BTreeMap::new();
    for peer in peer_telemetry {
        let (Some(height), Some(latest_hash), Some(state_root)) = (
            peer.last_seen_height,
            peer.last_seen_latest_hash.as_ref(),
            peer.last_seen_state_root.as_ref(),
        ) else {
            continue;
        };
        if peer.last_success_unix_ms.is_none() {
            continue;
        }
        *groups
            .entry((height, latest_hash.clone(), state_root.clone()))
            .or_default() += 1;
    }

    let mut best_any: Option<(u64, usize, String, String)> = None;
    let mut best_met: Option<(u64, usize, String, String)> = None;
    for ((height, latest_hash, state_root), count) in groups {
        let candidate = (height, count, latest_hash, state_root);
        if best_any
            .as_ref()
            .map(|best| candidate > *best)
            .unwrap_or(true)
        {
            best_any = Some(candidate.clone());
        }
        if count >= required_quorum
            && best_met
                .as_ref()
                .map(|best| candidate > *best)
                .unwrap_or(true)
        {
            best_met = Some(candidate);
        }
    }

    if let Some((height, count, latest_hash, state_root)) = best_met {
        return (
            true,
            count,
            Some(height),
            Some(latest_hash),
            Some(state_root),
        );
    }
    if let Some((height, count, latest_hash, state_root)) = best_any {
        return (
            false,
            count,
            Some(height),
            Some(latest_hash),
            Some(state_root),
        );
    }
    (false, 0, None, None, None)
}

#[derive(Debug, Clone)]
struct RuntimeTransactionExecutionPlan {
    asset: FeeAsset,
    quote: HybridFeeQuote,
    next_sender: RuntimeAccount,
}

#[derive(Debug, Clone)]
struct RuntimeNxmrCustodyReconciliation {
    bridge_deposited_nxmr_units: u128,
    account_nxmr_units: u128,
    withdrawal_reserved_nxmr_units: u128,
    nxmr_fee_units: u128,
    nxmr_custody_required_units: u128,
    nxmr_custody_surplus_units: u128,
    nxmr_custody_deficit_units: u128,
    bridge_custody_reconciled: bool,
}

impl RuntimeRpcState {
    fn admin_rpc_enabled(&self) -> bool {
        self.admin_rpc_private_listener && self.admin_token.is_some()
    }

    fn public_rpc_admin_methods_enabled(&self) -> bool {
        false
    }

    fn default_dev_sequencer_key(&self, sequencer_public_key_hex: &str) -> bool {
        sequencer_public_key_hex.eq_ignore_ascii_case(&default_dev_sequencer_public_key_hex())
    }

    fn commit_direct_state_mutation(&self) -> Result<(), String> {
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| "runtime mutex poisoned".to_string())?;
        runtime.try_produce_block()?;
        Ok(())
    }

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

    fn sync_telemetry_summary(&self) -> Result<RuntimeSyncTelemetrySummary, String> {
        let mut telemetry = self
            .sync_telemetry
            .lock()
            .map_err(|_| "sync telemetry mutex poisoned".to_string())?;
        for url in &self.sync_peers.sync_peer_urls {
            telemetry
                .entry(url.clone())
                .or_insert_with(|| RuntimeSyncPeerTelemetry {
                    url: url.clone(),
                    ..RuntimeSyncPeerTelemetry::default()
                });
        }
        let mut peer_telemetry = Vec::new();
        for url in &self.sync_peers.sync_peer_urls {
            if let Some(peer) = telemetry.get(url) {
                peer_telemetry.push(peer.clone());
            }
        }
        for (url, peer) in telemetry.iter() {
            if !self
                .sync_peers
                .sync_peer_urls
                .iter()
                .any(|configured| configured == url)
            {
                peer_telemetry.push(peer.clone());
            }
        }
        let (quorum_met, quorum_peer_count, quorum_height, quorum_latest_hash, quorum_state_root) =
            sync_quorum_summary(&peer_telemetry, self.sync_peers.sync_peer_quorum);
        Ok(RuntimeSyncTelemetrySummary {
            quorum_met,
            quorum_peer_count,
            quorum_height,
            quorum_latest_hash,
            quorum_state_root,
            successful_peer_count: peer_telemetry
                .iter()
                .filter(|peer| peer.last_success_unix_ms.is_some())
                .count(),
            failed_peer_count: peer_telemetry
                .iter()
                .filter(|peer| peer.last_error.is_some())
                .count(),
            attempt_count: peer_telemetry.iter().map(|peer| peer.attempt_count).sum(),
            success_count: peer_telemetry.iter().map(|peer| peer.success_count).sum(),
            failure_count: peer_telemetry.iter().map(|peer| peer.failure_count).sum(),
            stale_snapshot_count: peer_telemetry
                .iter()
                .map(|peer| peer.stale_snapshot_count)
                .sum(),
            fork_rejection_count: peer_telemetry
                .iter()
                .map(|peer| peer.fork_rejection_count)
                .sum(),
            quorum_rejection_count: peer_telemetry
                .iter()
                .map(|peer| peer.quorum_rejection_count)
                .sum(),
            import_count: peer_telemetry.iter().map(|peer| peer.import_count).sum(),
            last_success_unix_ms: peer_telemetry
                .iter()
                .filter_map(|peer| peer.last_success_unix_ms)
                .max(),
            last_import_height: peer_telemetry
                .iter()
                .filter_map(|peer| peer.last_import_height)
                .max(),
            peer_telemetry,
        })
    }

    fn record_sync_peer_attempt(&self, url: &str, started_at_unix_ms: u128) -> Result<(), String> {
        let mut telemetry = self
            .sync_telemetry
            .lock()
            .map_err(|_| "sync telemetry mutex poisoned".to_string())?;
        let entry = telemetry
            .entry(url.to_string())
            .or_insert_with(|| RuntimeSyncPeerTelemetry {
                url: url.to_string(),
                ..RuntimeSyncPeerTelemetry::default()
            });
        entry.last_attempt_unix_ms = Some(started_at_unix_ms);
        entry.attempt_count = entry.attempt_count.saturating_add(1);
        Ok(())
    }

    fn record_sync_peer_fetch_failure(
        &self,
        url: &str,
        error: String,
        latency_ms: u128,
    ) -> Result<(), String> {
        let mut telemetry = self
            .sync_telemetry
            .lock()
            .map_err(|_| "sync telemetry mutex poisoned".to_string())?;
        let entry = telemetry
            .entry(url.to_string())
            .or_insert_with(|| RuntimeSyncPeerTelemetry {
                url: url.to_string(),
                ..RuntimeSyncPeerTelemetry::default()
            });
        entry.last_latency_ms = Some(latency_ms);
        entry.last_error_unix_ms = Some(unix_ms());
        entry.last_error = Some(error);
        entry.failure_count = entry.failure_count.saturating_add(1);
        Ok(())
    }

    fn record_sync_peer_success(
        &self,
        url: &str,
        snapshot: &RuntimeSnapshot,
        latency_ms: u128,
    ) -> Result<(), String> {
        let now = unix_ms();
        let mut telemetry = self
            .sync_telemetry
            .lock()
            .map_err(|_| "sync telemetry mutex poisoned".to_string())?;
        let entry = telemetry
            .entry(url.to_string())
            .or_insert_with(|| RuntimeSyncPeerTelemetry {
                url: url.to_string(),
                ..RuntimeSyncPeerTelemetry::default()
            });
        entry.last_success_unix_ms = Some(now);
        entry.last_latency_ms = Some(latency_ms);
        entry.last_seen_height = Some(snapshot.latest_height());
        entry.last_seen_latest_hash = snapshot.latest_block_hash().map(str::to_string);
        entry.last_seen_state_root = Some(snapshot.state_root.clone());
        entry.last_seen_snapshot_root = Some(snapshot.root.clone());
        entry.last_error = None;
        entry.last_error_unix_ms = None;
        entry.success_count = entry.success_count.saturating_add(1);
        Ok(())
    }

    fn record_sync_peer_stale(&self, url: &str) -> Result<(), String> {
        let mut telemetry = self
            .sync_telemetry
            .lock()
            .map_err(|_| "sync telemetry mutex poisoned".to_string())?;
        let entry = telemetry
            .entry(url.to_string())
            .or_insert_with(|| RuntimeSyncPeerTelemetry {
                url: url.to_string(),
                ..RuntimeSyncPeerTelemetry::default()
            });
        entry.stale_snapshot_count = entry.stale_snapshot_count.saturating_add(1);
        Ok(())
    }

    fn record_sync_peer_fork(&self, url: &str, error: String) -> Result<(), String> {
        let mut telemetry = self
            .sync_telemetry
            .lock()
            .map_err(|_| "sync telemetry mutex poisoned".to_string())?;
        let entry = telemetry
            .entry(url.to_string())
            .or_insert_with(|| RuntimeSyncPeerTelemetry {
                url: url.to_string(),
                ..RuntimeSyncPeerTelemetry::default()
            });
        entry.last_error = Some(error);
        entry.last_error_unix_ms = Some(unix_ms());
        entry.failure_count = entry.failure_count.saturating_add(1);
        entry.fork_rejection_count = entry.fork_rejection_count.saturating_add(1);
        Ok(())
    }

    fn record_sync_peer_quorum_rejection(&self, url: &str) -> Result<(), String> {
        let mut telemetry = self
            .sync_telemetry
            .lock()
            .map_err(|_| "sync telemetry mutex poisoned".to_string())?;
        let entry = telemetry
            .entry(url.to_string())
            .or_insert_with(|| RuntimeSyncPeerTelemetry {
                url: url.to_string(),
                ..RuntimeSyncPeerTelemetry::default()
            });
        entry.quorum_rejection_count = entry.quorum_rejection_count.saturating_add(1);
        Ok(())
    }

    fn record_sync_peer_import(&self, url: &str, snapshot: &RuntimeSnapshot) -> Result<(), String> {
        let now = unix_ms();
        let mut telemetry = self
            .sync_telemetry
            .lock()
            .map_err(|_| "sync telemetry mutex poisoned".to_string())?;
        let entry = telemetry
            .entry(url.to_string())
            .or_insert_with(|| RuntimeSyncPeerTelemetry {
                url: url.to_string(),
                ..RuntimeSyncPeerTelemetry::default()
            });
        entry.last_import_unix_ms = Some(now);
        entry.last_import_height = Some(snapshot.latest_height());
        entry.last_import_snapshot_root = Some(snapshot.root.clone());
        entry.import_count = entry.import_count.saturating_add(1);
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
        let default_dev_sequencer_key =
            self.default_dev_sequencer_key(&status.sequencer_public_key_hex);
        let mut status = serde_json::to_value(status)
            .map_err(|error| format!("status serialization failed: {error}"))?;
        let Value::Object(fields) = &mut status else {
            return Err("runtime status did not serialize as an object".to_string());
        };
        let sync_telemetry = self.sync_telemetry_summary()?;
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
        fields.insert(
            "sync_peer_quorum".to_string(),
            json!(self.sync_peers.sync_peer_quorum),
        );
        fields.insert(
            "sync_quorum_met".to_string(),
            json!(sync_telemetry.quorum_met),
        );
        fields.insert(
            "sync_quorum_peer_count".to_string(),
            json!(sync_telemetry.quorum_peer_count),
        );
        fields.insert(
            "sync_quorum_height".to_string(),
            json!(sync_telemetry.quorum_height),
        );
        fields.insert(
            "sync_quorum_latest_hash".to_string(),
            json!(sync_telemetry.quorum_latest_hash),
        );
        fields.insert(
            "sync_quorum_state_root".to_string(),
            json!(sync_telemetry.quorum_state_root),
        );
        fields.insert(
            "sync_successful_peer_count".to_string(),
            json!(sync_telemetry.successful_peer_count),
        );
        fields.insert(
            "sync_failed_peer_count".to_string(),
            json!(sync_telemetry.failed_peer_count),
        );
        fields.insert(
            "sync_attempt_count".to_string(),
            json!(sync_telemetry.attempt_count),
        );
        fields.insert(
            "sync_success_count".to_string(),
            json!(sync_telemetry.success_count),
        );
        fields.insert(
            "sync_failure_count".to_string(),
            json!(sync_telemetry.failure_count),
        );
        fields.insert(
            "sync_stale_snapshot_count".to_string(),
            json!(sync_telemetry.stale_snapshot_count),
        );
        fields.insert(
            "sync_fork_rejection_count".to_string(),
            json!(sync_telemetry.fork_rejection_count),
        );
        fields.insert(
            "sync_quorum_rejection_count".to_string(),
            json!(sync_telemetry.quorum_rejection_count),
        );
        fields.insert(
            "sync_import_count".to_string(),
            json!(sync_telemetry.import_count),
        );
        fields.insert(
            "sync_last_success_unix_ms".to_string(),
            json!(sync_telemetry.last_success_unix_ms),
        );
        fields.insert(
            "sync_last_import_height".to_string(),
            json!(sync_telemetry.last_import_height),
        );
        fields.insert(
            "sync_peer_telemetry".to_string(),
            json!(sync_telemetry.peer_telemetry),
        );
        fields.insert(
            "admin_rpc_enabled".to_string(),
            json!(self.admin_rpc_enabled()),
        );
        fields.insert(
            "admin_rpc_private_listener".to_string(),
            json!(self.admin_rpc_private_listener),
        );
        fields.insert(
            "public_rpc_admin_methods_enabled".to_string(),
            json!(self.public_rpc_admin_methods_enabled()),
        );
        fields.insert(
            "default_dev_sequencer_key".to_string(),
            json!(default_dev_sequencer_key),
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
        let sync_telemetry = self.sync_telemetry_summary()?;
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
        if !status.launch_binding_present {
            blocking_gaps.push("missing-launch-package-binding".to_string());
        }
        let default_dev_sequencer_key =
            self.default_dev_sequencer_key(&status.sequencer_public_key_hex);
        if status.launch_binding_present && default_dev_sequencer_key {
            blocking_gaps.push("default-dev-sequencer-key".to_string());
        }
        if status.launch_binding_present && status.faucet_nbla_nebulai > 0 {
            blocking_gaps.push("public-nbla-faucet-enabled".to_string());
        }
        if status.launch_binding_present
            && status.node_role == "sequencer"
            && !self.admin_rpc_enabled()
        {
            blocking_gaps.push("missing-admin-rpc-control".to_string());
        }
        if self.public_rpc_admin_methods_enabled() {
            blocking_gaps.push("public-rpc-admin-methods-enabled".to_string());
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
        if status.node_role == "follower"
            && !self.sync_peers.sync_peer_urls.is_empty()
            && sync_telemetry.successful_peer_count == 0
        {
            blocking_gaps.push("follower-no-successful-sync-peer".to_string());
        }
        if status.node_role == "follower"
            && !self.sync_peers.sync_peer_urls.is_empty()
            && !sync_telemetry.quorum_met
        {
            blocking_gaps.push("follower-sync-quorum-not-met".to_string());
        }
        if bridge_policy().live_value_enabled {
            blocking_gaps.push("bridge-live-value-enabled".to_string());
        }
        if !status.bridge_only_nxmr {
            blocking_gaps.push("nxmr-faucet-enabled".to_string());
        }
        if !status.bridge_custody_reconciled {
            blocking_gaps.push("bridge-custody-not-reconciled".to_string());
        }
        if status.mempool_size >= status.max_mempool_transactions {
            blocking_gaps.push("mempool-at-capacity".to_string());
        }
        if !status.sequencer_accountability_clean {
            blocking_gaps.push("sequencer-accountability-evidence-open".to_string());
        }
        let mut report = RuntimeOpsStatus {
            service: "nebula-testnet-rpc".to_string(),
            generated_at_unix_ms,
            chain_id: status.chain_id,
            runtime_version: status.runtime_version,
            launch_binding_present: status.launch_binding_present,
            launch_endpoint_url: status.launch_endpoint_url,
            deployment_attestation_root: status.deployment_attestation_root,
            public_status_manifest_root: status.public_status_manifest_root,
            public_probe_root: status.public_probe_root,
            validator_set_root: status.validator_set_root,
            operator_handoff_root: status.operator_handoff_root,
            operator_acceptance_root: status.operator_acceptance_root,
            genesis_root: status.genesis_root,
            launch_package_root: status.launch_package_root,
            launch_package_bundle_root: status.launch_package_bundle_root,
            launch_activation_height: status.launch_activation_height,
            launch_validator_count: status.launch_validator_count,
            launch_operator_count: status.launch_operator_count,
            launch_region_count: status.launch_region_count,
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
            sync_peer_quorum: self.sync_peers.sync_peer_quorum,
            sync_quorum_met: sync_telemetry.quorum_met,
            sync_quorum_peer_count: sync_telemetry.quorum_peer_count,
            sync_quorum_height: sync_telemetry.quorum_height,
            sync_quorum_latest_hash: sync_telemetry.quorum_latest_hash,
            sync_quorum_state_root: sync_telemetry.quorum_state_root,
            sync_successful_peer_count: sync_telemetry.successful_peer_count,
            sync_failed_peer_count: sync_telemetry.failed_peer_count,
            sync_attempt_count: sync_telemetry.attempt_count,
            sync_success_count: sync_telemetry.success_count,
            sync_failure_count: sync_telemetry.failure_count,
            sync_stale_snapshot_count: sync_telemetry.stale_snapshot_count,
            sync_fork_rejection_count: sync_telemetry.fork_rejection_count,
            sync_quorum_rejection_count: sync_telemetry.quorum_rejection_count,
            sync_import_count: sync_telemetry.import_count,
            sync_last_success_unix_ms: sync_telemetry.last_success_unix_ms,
            sync_last_import_height: sync_telemetry.last_import_height,
            sync_peer_telemetry: sync_telemetry.peer_telemetry,
            rpc_max_request_bytes: self.rpc_limits.max_request_bytes,
            rpc_max_requests_per_minute: self.rpc_limits.max_requests_per_minute,
            admin_rpc_enabled: self.admin_rpc_enabled(),
            admin_rpc_private_listener: self.admin_rpc_private_listener,
            public_rpc_admin_methods_enabled: self.public_rpc_admin_methods_enabled(),
            default_dev_sequencer_key,
            max_mempool_transactions: status.max_mempool_transactions,
            mempool_size: status.mempool_size,
            mempool_capacity_remaining: status.mempool_capacity_remaining,
            mempool_full_rejection_count: status.mempool_full_rejection_count,
            mempool_admission_rejection_count: status.mempool_admission_rejection_count,
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
            faucet_nbla_nebulai: status.faucet_nbla_nebulai,
            faucet_nxmr_units: status.faucet_nxmr_units,
            bridge_only_nxmr: status.bridge_only_nxmr,
            bridge_deposited_nxmr_units: status.bridge_deposited_nxmr_units,
            account_nxmr_units: status.account_nxmr_units,
            withdrawal_reserved_nxmr_units: status.withdrawal_reserved_nxmr_units,
            nxmr_fee_units: status.nxmr_fee_units,
            nxmr_custody_required_units: status.nxmr_custody_required_units,
            nxmr_custody_surplus_units: status.nxmr_custody_surplus_units,
            nxmr_custody_deficit_units: status.nxmr_custody_deficit_units,
            bridge_custody_reconciled: status.bridge_custody_reconciled,
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
            launch_binding_present: ops_status.launch_binding_present,
            launch_endpoint_url: ops_status.launch_endpoint_url,
            deployment_attestation_root: ops_status.deployment_attestation_root,
            public_status_manifest_root: ops_status.public_status_manifest_root,
            public_probe_root: ops_status.public_probe_root,
            validator_set_root: ops_status.validator_set_root,
            operator_handoff_root: ops_status.operator_handoff_root,
            operator_acceptance_root: ops_status.operator_acceptance_root,
            genesis_root: ops_status.genesis_root,
            launch_package_root: ops_status.launch_package_root,
            launch_package_bundle_root: ops_status.launch_package_bundle_root,
            launch_activation_height: ops_status.launch_activation_height,
            launch_validator_count: ops_status.launch_validator_count,
            launch_operator_count: ops_status.launch_operator_count,
            launch_region_count: ops_status.launch_region_count,
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
            sync_peer_quorum: ops_status.sync_peer_quorum,
            sync_quorum_met: ops_status.sync_quorum_met,
            sync_quorum_peer_count: ops_status.sync_quorum_peer_count,
            sync_quorum_height: ops_status.sync_quorum_height,
            sync_quorum_latest_hash: ops_status.sync_quorum_latest_hash,
            sync_quorum_state_root: ops_status.sync_quorum_state_root,
            sync_successful_peer_count: ops_status.sync_successful_peer_count,
            sync_failed_peer_count: ops_status.sync_failed_peer_count,
            sync_attempt_count: ops_status.sync_attempt_count,
            sync_success_count: ops_status.sync_success_count,
            sync_failure_count: ops_status.sync_failure_count,
            sync_stale_snapshot_count: ops_status.sync_stale_snapshot_count,
            sync_fork_rejection_count: ops_status.sync_fork_rejection_count,
            sync_quorum_rejection_count: ops_status.sync_quorum_rejection_count,
            sync_import_count: ops_status.sync_import_count,
            sync_last_success_unix_ms: ops_status.sync_last_success_unix_ms,
            sync_last_import_height: ops_status.sync_last_import_height,
            sync_peer_telemetry: ops_status.sync_peer_telemetry,
            rpc_max_request_bytes: ops_status.rpc_max_request_bytes,
            rpc_max_requests_per_minute: ops_status.rpc_max_requests_per_minute,
            admin_rpc_enabled: ops_status.admin_rpc_enabled,
            admin_rpc_private_listener: ops_status.admin_rpc_private_listener,
            public_rpc_admin_methods_enabled: ops_status.public_rpc_admin_methods_enabled,
            default_dev_sequencer_key: ops_status.default_dev_sequencer_key,
            max_mempool_transactions: ops_status.max_mempool_transactions,
            mempool_size: ops_status.mempool_size,
            mempool_capacity_remaining: ops_status.mempool_capacity_remaining,
            mempool_full_rejection_count: ops_status.mempool_full_rejection_count,
            mempool_admission_rejection_count: ops_status.mempool_admission_rejection_count,
            faucet_nbla_nebulai: ops_status.faucet_nbla_nebulai,
            faucet_nxmr_units: ops_status.faucet_nxmr_units,
            bridge_only_nxmr: ops_status.bridge_only_nxmr,
            bridge_deposited_nxmr_units: ops_status.bridge_deposited_nxmr_units,
            account_nxmr_units: ops_status.account_nxmr_units,
            withdrawal_reserved_nxmr_units: ops_status.withdrawal_reserved_nxmr_units,
            nxmr_fee_units: ops_status.nxmr_fee_units,
            nxmr_custody_required_units: ops_status.nxmr_custody_required_units,
            nxmr_custody_surplus_units: ops_status.nxmr_custody_surplus_units,
            nxmr_custody_deficit_units: ops_status.nxmr_custody_deficit_units,
            bridge_custody_reconciled: ops_status.bridge_custody_reconciled,
            backup_root: String::new(),
        };
        manifest.backup_root = backup_manifest_root(&manifest);
        Ok(manifest)
    }

    fn health_json(&self) -> Result<Value, String> {
        let status = self.status_json()?;
        let ops_status = self.ops_status()?;
        let backup_manifest = self.backup_manifest()?;
        Ok(json!({
            "ok": true,
            "service": "nebula-testnet-rpc",
            "chain_id": status["chain_id"],
            "runtime_version": status["runtime_version"],
            "launch_binding_present": status["launch_binding_present"],
            "launch_endpoint_url": status["launch_endpoint_url"],
            "deployment_attestation_root": status["deployment_attestation_root"],
            "public_status_manifest_root": status["public_status_manifest_root"],
            "public_probe_root": status["public_probe_root"],
            "validator_set_root": status["validator_set_root"],
            "operator_handoff_root": status["operator_handoff_root"],
            "operator_acceptance_root": status["operator_acceptance_root"],
            "genesis_root": status["genesis_root"],
            "launch_package_root": status["launch_package_root"],
            "launch_package_bundle_root": status["launch_package_bundle_root"],
            "launch_activation_height": status["launch_activation_height"],
            "launch_validator_count": status["launch_validator_count"],
            "launch_operator_count": status["launch_operator_count"],
            "launch_region_count": status["launch_region_count"],
            "node_role": status["node_role"],
            "latest_height": status["latest_height"],
            "latest_hash": status["latest_hash"],
            "latest_state_root": status["latest_state_root"],
            "current_state_root": status["current_state_root"],
            "block_target_ms": status["block_target_ms"],
            "sub_second_blocks": status["sub_second_blocks"],
            "block_production_enabled": status["block_production_enabled"],
            "snapshot_version": ops_status.snapshot_version,
            "snapshot_root": ops_status.snapshot_root,
            "state_root": ops_status.state_root,
            "latest_block_age_ms": ops_status.latest_block_age_ms,
            "public_ops_ready": ops_status.public_ops_ready,
            "public_ops_blocking_gaps": ops_status.blocking_gaps,
            "ops_root": ops_status.ops_root,
            "backup_root": backup_manifest.backup_root,
            "snapshot_persisted": backup_manifest.snapshot_persisted,
            "storage_snapshot_path": backup_manifest.snapshot_path,
            "storage_snapshot_root": backup_manifest.storage_snapshot_root,
            "storage_snapshot_matches_runtime": backup_manifest.storage_snapshot_matches_runtime,
            "rpc_limits": self.rpc_limits,
            "rpc_max_request_bytes": status["rpc_max_request_bytes"],
            "rpc_max_requests_per_minute": status["rpc_max_requests_per_minute"],
            "admin_rpc_enabled": self.admin_rpc_enabled(),
            "admin_rpc_private_listener": self.admin_rpc_private_listener,
            "public_rpc_admin_methods_enabled": self.public_rpc_admin_methods_enabled(),
            "default_dev_sequencer_key": status["default_dev_sequencer_key"],
            "bootstrap_peer_urls": self.sync_peers.bootstrap_peer_urls,
            "sync_peer_urls": self.sync_peers.sync_peer_urls,
            "sync_peer_count": self.sync_peers.sync_peer_urls.len(),
            "sync_peer_quorum": status["sync_peer_quorum"],
            "sync_quorum_met": status["sync_quorum_met"],
            "sync_quorum_peer_count": status["sync_quorum_peer_count"],
            "sync_quorum_height": status["sync_quorum_height"],
            "sync_quorum_latest_hash": status["sync_quorum_latest_hash"],
            "sync_quorum_state_root": status["sync_quorum_state_root"],
            "sync_successful_peer_count": status["sync_successful_peer_count"],
            "sync_failed_peer_count": status["sync_failed_peer_count"],
            "sync_attempt_count": status["sync_attempt_count"],
            "sync_success_count": status["sync_success_count"],
            "sync_failure_count": status["sync_failure_count"],
            "sync_stale_snapshot_count": status["sync_stale_snapshot_count"],
            "sync_fork_rejection_count": status["sync_fork_rejection_count"],
            "sync_quorum_rejection_count": status["sync_quorum_rejection_count"],
            "sync_import_count": status["sync_import_count"],
            "sync_last_success_unix_ms": status["sync_last_success_unix_ms"],
            "sync_last_import_height": status["sync_last_import_height"],
            "sync_peer_telemetry": status["sync_peer_telemetry"],
            "max_mempool_transactions": status["max_mempool_transactions"],
            "mempool_size": status["mempool_size"],
            "mempool_capacity_remaining": status["mempool_capacity_remaining"],
            "mempool_full_rejection_count": status["mempool_full_rejection_count"],
            "mempool_admission_rejection_count": status["mempool_admission_rejection_count"],
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
            "faucet_nbla_nebulai": status["faucet_nbla_nebulai"],
            "faucet_nxmr_units": status["faucet_nxmr_units"],
            "bridge_only_nxmr": status["bridge_only_nxmr"],
            "bridge_deposited_nxmr_units": status["bridge_deposited_nxmr_units"],
            "account_nxmr_units": status["account_nxmr_units"],
            "withdrawal_reserved_nxmr_units": status["withdrawal_reserved_nxmr_units"],
            "nxmr_fee_units": status["nxmr_fee_units"],
            "nxmr_custody_required_units": status["nxmr_custody_required_units"],
            "nxmr_custody_surplus_units": status["nxmr_custody_surplus_units"],
            "nxmr_custody_deficit_units": status["nxmr_custody_deficit_units"],
            "bridge_custody_reconciled": status["bridge_custody_reconciled"],
            "bridge_deposit_count": status["bridge_deposit_count"],
            "withdrawal_request_count": status["withdrawal_request_count"],
            "finalized_withdrawal_count": status["finalized_withdrawal_count"],
            "bridge_replay_cache_count": status["bridge_replay_cache_count"],
        }))
    }

    fn metrics_text(&self) -> Result<String, String> {
        let ops_status = self.ops_status()?;
        let status = {
            let runtime = self
                .runtime
                .lock()
                .map_err(|_| "runtime mutex poisoned".to_string())?;
            runtime.status()
        };
        let mut output = String::new();
        push_metric(
            &mut output,
            "nebula_latest_height",
            "Latest accepted block height.",
            status.latest_height,
        );
        push_metric(
            &mut output,
            "nebula_latest_block_age_ms",
            "Age of the latest block according to the ops surface.",
            ops_status.latest_block_age_ms,
        );
        push_metric(
            &mut output,
            "nebula_block_target_ms",
            "Configured block target in milliseconds.",
            status.block_target_ms,
        );
        push_metric_bool(
            &mut output,
            "nebula_sub_second_blocks",
            "Whether the block target is below one second.",
            status.sub_second_blocks,
        );
        push_metric_bool(
            &mut output,
            "nebula_block_production_enabled",
            "Whether this node is configured to produce blocks.",
            status.block_production_enabled,
        );
        push_metric_bool(
            &mut output,
            "nebula_launch_binding_present",
            "Whether this node is bound to verified public launch artifacts.",
            ops_status.launch_binding_present,
        );
        push_metric(
            &mut output,
            "nebula_launch_validator_count",
            "Validators bound by the verified launch package.",
            ops_status.launch_validator_count.unwrap_or(0),
        );
        push_metric(
            &mut output,
            "nebula_launch_operator_count",
            "Operators bound by the verified launch package.",
            ops_status.launch_operator_count.unwrap_or(0),
        );
        push_metric(
            &mut output,
            "nebula_launch_region_count",
            "Regions bound by the verified launch package.",
            ops_status.launch_region_count.unwrap_or(0),
        );
        push_metric(
            &mut output,
            "nebula_mempool_size",
            "Transactions currently waiting in the mempool.",
            status.mempool_size,
        );
        push_metric(
            &mut output,
            "nebula_mempool_capacity_remaining",
            "Remaining mempool admission capacity.",
            status.mempool_capacity_remaining,
        );
        push_metric(
            &mut output,
            "nebula_mempool_full_rejection_count",
            "Transactions rejected because the mempool was full.",
            status.mempool_full_rejection_count,
        );
        push_metric(
            &mut output,
            "nebula_mempool_admission_rejection_count",
            "Transactions rejected by stateful mempool admission checks.",
            status.mempool_admission_rejection_count,
        );
        push_metric(
            &mut output,
            "nebula_rpc_max_request_bytes",
            "Maximum accepted HTTP request body size.",
            self.rpc_limits.max_request_bytes,
        );
        push_metric(
            &mut output,
            "nebula_rpc_max_requests_per_minute",
            "Per-client RPC request budget per minute.",
            self.rpc_limits.max_requests_per_minute,
        );
        push_metric(
            &mut output,
            "nebula_sync_peer_count",
            "Configured continuous snapshot sync peers.",
            self.sync_peers.sync_peer_urls.len(),
        );
        push_metric(
            &mut output,
            "nebula_sync_peer_quorum",
            "Configured matching snapshot peer quorum required before follower import.",
            self.sync_peers.sync_peer_quorum,
        );
        push_metric_bool(
            &mut output,
            "nebula_sync_quorum_met",
            "Whether recent sync telemetry meets the configured snapshot quorum.",
            ops_status.sync_quorum_met,
        );
        push_metric(
            &mut output,
            "nebula_sync_quorum_peer_count",
            "Peers in the strongest observed matching snapshot quorum group.",
            ops_status.sync_quorum_peer_count,
        );
        push_metric(
            &mut output,
            "nebula_sync_successful_peer_count",
            "Configured sync peers with at least one successful valid snapshot response.",
            ops_status.sync_successful_peer_count,
        );
        push_metric(
            &mut output,
            "nebula_sync_failed_peer_count",
            "Configured sync peers with a recorded current error.",
            ops_status.sync_failed_peer_count,
        );
        push_metric(
            &mut output,
            "nebula_sync_attempt_count",
            "Total sync peer fetch attempts.",
            ops_status.sync_attempt_count,
        );
        push_metric(
            &mut output,
            "nebula_sync_success_count",
            "Total successful valid snapshot responses from sync peers.",
            ops_status.sync_success_count,
        );
        push_metric(
            &mut output,
            "nebula_sync_failure_count",
            "Total failed sync peer fetch or validation attempts.",
            ops_status.sync_failure_count,
        );
        push_metric(
            &mut output,
            "nebula_sync_import_count",
            "Total ahead snapshots imported from sync peers.",
            ops_status.sync_import_count,
        );
        push_metric(
            &mut output,
            "nebula_sync_fork_rejection_count",
            "Total ahead peer snapshots rejected because they did not extend local state.",
            ops_status.sync_fork_rejection_count,
        );
        push_metric(
            &mut output,
            "nebula_sync_quorum_rejection_count",
            "Total valid ahead peer snapshots rejected because no matching quorum was available.",
            ops_status.sync_quorum_rejection_count,
        );
        push_metric_bool(
            &mut output,
            "nebula_admin_rpc_enabled",
            "Whether operator-only JSON-RPC methods are available on a private token-protected listener.",
            ops_status.admin_rpc_enabled,
        );
        push_metric_bool(
            &mut output,
            "nebula_admin_rpc_private_listener",
            "Whether operator-only JSON-RPC methods are isolated from the public RPC listener.",
            ops_status.admin_rpc_private_listener,
        );
        push_metric_bool(
            &mut output,
            "nebula_public_rpc_admin_methods_enabled",
            "Whether the public JSON-RPC listener accepts operator-only methods.",
            ops_status.public_rpc_admin_methods_enabled,
        );
        push_metric_bool(
            &mut output,
            "nebula_default_dev_sequencer_key",
            "Whether the active sequencer key is the public development key.",
            ops_status.default_dev_sequencer_key,
        );
        push_metric(
            &mut output,
            "nebula_bridge_deposit_count",
            "Observed bridge deposits credited into nXMR.",
            status.bridge_deposit_count,
        );
        push_metric(
            &mut output,
            "nebula_withdrawal_request_count",
            "Withdrawal requests accepted by the runtime.",
            status.withdrawal_request_count,
        );
        push_metric(
            &mut output,
            "nebula_finalized_withdrawal_count",
            "Withdrawals finalized by operator evidence.",
            status.finalized_withdrawal_count,
        );
        push_metric(
            &mut output,
            "nebula_total_nxmr_fees_units",
            "Total nXMR fee units collected for NBLA buybacks.",
            status.total_nxmr_fees_units,
        );
        push_metric(
            &mut output,
            "nebula_buyback_pool_nebulai",
            "NBLA-denominated buyback pool accumulated from nXMR gas.",
            status.buyback_pool_nebulai,
        );
        push_metric(
            &mut output,
            "nebula_validator_reward_nebulai",
            "NBLA rewards accrued to the local validator account.",
            status.validator_reward_nebulai,
        );
        push_metric(
            &mut output,
            "nebula_faucet_nbla_nebulai",
            "Configured NBLA nebulai credited by the public faucet. Launch-bound public testnet requires zero.",
            status.faucet_nbla_nebulai,
        );
        push_metric(
            &mut output,
            "nebula_faucet_nxmr_units",
            "Configured nXMR units credited by the faucet. Public testnet requires zero.",
            status.faucet_nxmr_units,
        );
        push_metric_bool(
            &mut output,
            "nebula_bridge_only_nxmr",
            "Whether nXMR is credited only by bridge deposits.",
            status.bridge_only_nxmr,
        );
        push_metric(
            &mut output,
            "nebula_bridge_deposited_nxmr_units",
            "Total nXMR units credited from observed bridge deposits.",
            status.bridge_deposited_nxmr_units,
        );
        push_metric(
            &mut output,
            "nebula_account_nxmr_units",
            "Total nXMR units held in runtime accounts.",
            status.account_nxmr_units,
        );
        push_metric(
            &mut output,
            "nebula_withdrawal_reserved_nxmr_units",
            "Total nXMR units burned into withdrawal requests.",
            status.withdrawal_reserved_nxmr_units,
        );
        push_metric(
            &mut output,
            "nebula_nxmr_custody_required_units",
            "nXMR units required by accounts, withdrawals, and collected fees.",
            status.nxmr_custody_required_units,
        );
        push_metric(
            &mut output,
            "nebula_nxmr_custody_deficit_units",
            "nXMR custody deficit units. Public testnet requires zero.",
            status.nxmr_custody_deficit_units,
        );
        push_metric_bool(
            &mut output,
            "nebula_bridge_custody_reconciled",
            "Whether bridge deposits reconcile with account balances, withdrawals, and fees.",
            status.bridge_custody_reconciled,
        );
        push_metric(
            &mut output,
            "nebula_accountability_report_count",
            "Open sequencer accountability reports.",
            status.accountability_report_count,
        );
        push_metric_bool(
            &mut output,
            "nebula_sequencer_accountability_clean",
            "Whether sequencer accountability evidence is clear.",
            status.sequencer_accountability_clean,
        );
        push_metric_bool(
            &mut output,
            "nebula_storage_snapshot_present",
            "Whether a persisted runtime snapshot is present.",
            ops_status.storage_snapshot_present,
        );
        push_metric_bool(
            &mut output,
            "nebula_storage_snapshot_matches_runtime",
            "Whether persisted snapshot evidence matches runtime state.",
            ops_status.storage_snapshot_matches_runtime,
        );
        push_metric_bool(
            &mut output,
            "nebula_public_ops_ready",
            "Whether public operational evidence is currently ready.",
            ops_status.public_ops_ready,
        );
        push_metric(
            &mut output,
            "nebula_public_ops_blocking_gap_count",
            "Number of public ops readiness blocking gaps.",
            ops_status.blocking_gaps.len(),
        );
        Ok(output)
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

fn normalize_admin_token(admin_token: Option<String>) -> Result<Option<String>, String> {
    match admin_token {
        Some(token) if token.trim().is_empty() => {
            Err("admin_token must not be empty when configured".to_string())
        }
        Some(token) => Ok(Some(token)),
        None => Ok(None),
    }
}

impl RuntimeSyncPeerSet {
    fn from_options(options: &RuntimeNodeOptions) -> Result<Self, String> {
        if options.sync_peer_quorum == 0 {
            return Err("--sync-peer-quorum must be greater than zero".to_string());
        }
        let bootstrap_peer_urls =
            collect_peer_urls(options.bootstrap_rpc_url.as_deref(), &[], "--bootstrap-rpc")?;
        let sync_peer_urls = collect_peer_urls(
            options.sync_rpc_url.as_deref(),
            &options.sync_rpc_urls,
            "--sync-rpc",
        )?;
        if !sync_peer_urls.is_empty() && options.sync_peer_quorum > sync_peer_urls.len() {
            return Err(format!(
                "--sync-peer-quorum {} exceeds configured --sync-rpc peer count {}",
                options.sync_peer_quorum,
                sync_peer_urls.len()
            ));
        }
        Ok(Self {
            bootstrap_peer_urls,
            sync_peer_urls,
            sync_peer_quorum: options.sync_peer_quorum,
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
            mempool_full_rejection_count: 0,
            mempool_admission_rejection_count: 0,
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
        if let Some(local_binding) = &config.launch_binding {
            match &snapshot.config.launch_binding {
                Some(snapshot_binding) if snapshot_binding == local_binding => {}
                Some(_) => {
                    return Err(
                        "snapshot launch binding does not match local launch binding".to_string(),
                    );
                }
                None => {
                    return Err("snapshot is missing the required local launch binding".to_string());
                }
            }
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
        config.max_mempool_transactions = snapshot.config.max_mempool_transactions;
        config.faucet_nbla_nebulai = snapshot.config.faucet_nbla_nebulai;
        config.faucet_nxmr_units = snapshot.config.faucet_nxmr_units;

        Ok(Self {
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
            mempool_full_rejection_count: snapshot.mempool_full_rejection_count,
            mempool_admission_rejection_count: snapshot.mempool_admission_rejection_count,
            sequencer_key_rotations: snapshot.sequencer_key_rotations,
            accountability_reports: snapshot.accountability_reports,
        })
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
            mempool_full_rejection_count: self.mempool_full_rejection_count,
            mempool_admission_rejection_count: self.mempool_admission_rejection_count,
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
        let nxmr_custody = nxmr_custody_reconciliation(
            &self.accounts,
            &self.bridge_deposits,
            &self.withdrawals,
            self.total_nxmr_fees_units,
        )
        .expect("runtime nXMR custody reconciliation remains valid");
        let launch_binding = self.config.launch_binding.as_ref();
        RuntimeStatus {
            chain_id: self.config.chain_id.clone(),
            runtime_version: self.config.runtime_version.clone(),
            launch_binding_present: launch_binding.is_some(),
            launch_endpoint_url: launch_binding.map(|binding| binding.endpoint_url.clone()),
            deployment_attestation_root: launch_binding
                .map(|binding| binding.deployment_attestation_root.clone()),
            public_status_manifest_root: launch_binding
                .map(|binding| binding.public_status_manifest_root.clone()),
            public_probe_root: launch_binding.map(|binding| binding.public_probe_root.clone()),
            validator_set_root: launch_binding.map(|binding| binding.validator_set_root.clone()),
            operator_handoff_root: launch_binding
                .map(|binding| binding.operator_handoff_root.clone()),
            operator_acceptance_root: launch_binding
                .map(|binding| binding.operator_acceptance_root.clone()),
            genesis_root: launch_binding.map(|binding| binding.genesis_root.clone()),
            launch_package_root: launch_binding.map(|binding| binding.launch_package_root.clone()),
            launch_package_bundle_root: launch_binding
                .map(|binding| binding.launch_package_bundle_root.clone()),
            launch_activation_height: launch_binding.map(|binding| binding.activation_height),
            launch_validator_count: launch_binding.map(|binding| binding.validator_count),
            launch_operator_count: launch_binding.map(|binding| binding.operator_count),
            launch_region_count: launch_binding.map(|binding| binding.region_count),
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
            max_mempool_transactions: self.config.max_mempool_transactions,
            mempool_capacity_remaining: self
                .config
                .max_mempool_transactions
                .saturating_sub(self.mempool.len()),
            mempool_full_rejection_count: self.mempool_full_rejection_count,
            mempool_admission_rejection_count: self.mempool_admission_rejection_count,
            account_count: self.accounts.len(),
            bridge_deposit_count: self.bridge_deposits.len(),
            withdrawal_request_count: self.withdrawals.len(),
            finalized_withdrawal_count,
            total_nxmr_fees_units: self.total_nxmr_fees_units,
            buyback_pool_nebulai: self.buyback_pool_nebulai,
            validator_reward_nebulai: self.validator_reward_nebulai,
            validator_reward_account: self.config.validator_reward_account(),
            faucet_nbla_nebulai: self.config.faucet_nbla_nebulai,
            faucet_nxmr_units: self.config.faucet_nxmr_units,
            bridge_only_nxmr: self.config.faucet_nxmr_units == 0
                && nxmr_custody.bridge_custody_reconciled,
            bridge_deposited_nxmr_units: nxmr_custody.bridge_deposited_nxmr_units,
            account_nxmr_units: nxmr_custody.account_nxmr_units,
            withdrawal_reserved_nxmr_units: nxmr_custody.withdrawal_reserved_nxmr_units,
            nxmr_fee_units: nxmr_custody.nxmr_fee_units,
            nxmr_custody_required_units: nxmr_custody.nxmr_custody_required_units,
            nxmr_custody_surplus_units: nxmr_custody.nxmr_custody_surplus_units,
            nxmr_custody_deficit_units: nxmr_custody.nxmr_custody_deficit_units,
            bridge_custody_reconciled: nxmr_custody.bridge_custody_reconciled,
            bridge_policy_root: bridge_policy_root(),
            bridge_min_deposit_confirmations: MIN_BRIDGE_CONFIRMATIONS,
            bridge_deposit_observer_quorum: MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM,
            bridge_withdrawal_operator_quorum: MIN_WITHDRAWAL_OPERATOR_QUORUM,
            bridge_live_value_enabled: bridge_policy().live_value_enabled,
            bridge_replay_cache_count: self.bridge_deposits.len() + finalized_withdrawal_count,
        }
    }

    pub fn faucet(&mut self, account: &str) -> Result<FaucetReport, String> {
        self.ensure_accountability_clean()?;
        if self.config.faucet_nbla_nebulai == 0 {
            return Err("NBLA faucet is disabled".to_string());
        }
        validate_account_id(account)?;
        let state = self
            .accounts
            .entry(account.to_string())
            .or_insert_with(RuntimeAccount::empty);
        state.nbla_nebulai = state
            .nbla_nebulai
            .checked_add(self.config.faucet_nbla_nebulai)
            .ok_or_else(|| "faucet NBLA credit overflowed".to_string())?;
        Ok(FaucetReport {
            account: account.to_string(),
            credited_nbla_nebulai: self.config.faucet_nbla_nebulai,
            credited_nxmr_units: 0,
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
        self.ensure_accountability_clean()?;
        if let Err(error) = validate_transaction_shape(&tx) {
            self.record_mempool_admission_rejection()?;
            return Err(error);
        }
        let tx_id = tx.id();
        if self.receipts.contains_key(&tx_id)
            || self.mempool.iter().any(|pending| pending.id() == tx_id)
        {
            self.record_mempool_admission_rejection()?;
            return Err(format!("transaction {tx_id} already exists"));
        }
        if self
            .mempool
            .iter()
            .any(|pending| pending.from == tx.from && pending.nonce == tx.nonce)
        {
            self.record_mempool_admission_rejection()?;
            return Err(format!(
                "mempool already contains a pending transaction for account {} nonce {}",
                tx.from, tx.nonce
            ));
        }
        if let Err(error) = self.transaction_execution_plan(&tx) {
            self.record_mempool_admission_rejection()?;
            return Err(error);
        }
        if self.mempool.len() >= self.config.max_mempool_transactions {
            self.mempool_full_rejection_count = self
                .mempool_full_rejection_count
                .checked_add(1)
                .ok_or_else(|| "mempool full rejection counter overflowed".to_string())?;
            return Err(format!(
                "mempool is full: {} pending transactions at configured max {}",
                self.mempool.len(),
                self.config.max_mempool_transactions
            ));
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
            max_mempool_transactions: self.config.max_mempool_transactions,
            mempool_capacity_remaining: self
                .config
                .max_mempool_transactions
                .saturating_sub(self.mempool.len()),
        })
    }

    fn record_mempool_admission_rejection(&mut self) -> Result<(), String> {
        self.mempool_admission_rejection_count = self
            .mempool_admission_rejection_count
            .checked_add(1)
            .ok_or_else(|| "mempool admission rejection counter overflowed".to_string())?;
        Ok(())
    }

    pub fn receipt(&self, tx_id: &str) -> Option<RuntimeReceipt> {
        self.receipts.get(tx_id).cloned()
    }

    pub fn observe_bridge_deposit(
        &mut self,
        deposit: RuntimeBridgeDeposit,
    ) -> Result<BridgeDepositReport, String> {
        self.ensure_accountability_clean()?;
        validate_bridge_deposit_for_launch_binding(&deposit, self.config.launch_binding.as_ref())?;
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
        nonce: u64,
        signature: &str,
    ) -> Result<WithdrawalReport, String> {
        self.ensure_accountability_clean()?;
        validate_account_id(account)?;
        validate_monero_address(monero_address)?;
        if amount_nxmr_units == 0 {
            return Err("amount_nxmr_units must be greater than zero".to_string());
        }
        let authorization_root =
            withdrawal_authorization_root(account, monero_address, amount_nxmr_units, nonce);
        verify_account_signature(
            account,
            &authorization_root,
            signature,
            "withdrawal_signature",
        )?;
        let state = self
            .accounts
            .get_mut(account)
            .ok_or_else(|| format!("account {account} does not exist"))?;
        if state.nonce != nonce {
            return Err(format!(
                "account nonce expected {} but got {nonce}",
                state.nonce
            ));
        }
        if state.nxmr_units < amount_nxmr_units {
            return Err(format!(
                "insufficient nXMR balance: need {amount_nxmr_units}, have {}",
                state.nxmr_units
            ));
        }
        state.nxmr_units -= amount_nxmr_units;
        state.nonce = state
            .nonce
            .checked_add(1)
            .ok_or_else(|| "account nonce overflowed".to_string())?;
        let account_state = state.clone();
        let requested_at_unix_ms = unix_ms();
        let withdrawal_id = stable_runtime_root(&json!({
            "withdrawal_id_domain": "nebula-runtime-withdrawal-id-v1",
            "account": account,
            "monero_address": monero_address,
            "amount_nxmr_units": amount_nxmr_units,
            "nonce": nonce,
            "authorization_root": authorization_root,
            "requested_at_unix_ms": requested_at_unix_ms,
            "withdrawal_index": self.withdrawals.len(),
        }));
        let mut withdrawal = RuntimeWithdrawalRequest {
            withdrawal_id,
            account: account.to_string(),
            monero_address: monero_address.to_string(),
            amount_nxmr_units,
            nonce,
            signature: signature.to_ascii_lowercase(),
            requested_at_unix_ms,
            status: "operator_pending".to_string(),
            bridge_policy_root: bridge_policy_root(),
            operator_approval_ids: Vec::new(),
            operator_approval_roots: Vec::new(),
            operator_approvals: Vec::new(),
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
        operator_approval_ids: Vec<String>,
        operator_approval_roots: Vec<String>,
        operator_approvals: Vec<RuntimeWithdrawalOperatorApproval>,
    ) -> Result<WithdrawalFinalizationReport, String> {
        self.ensure_accountability_clean()?;
        validate_fixed_hex(finalized_monero_tx_id, "finalized_monero_tx_id", 64)?;
        validate_fixed_hex(finalization_proof_root, "finalization_proof_root", 64)?;
        validate_identity_root_quorum(
            &operator_approval_ids,
            &operator_approval_roots,
            "operator_approval_ids",
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
        let launch_binding = self.config.launch_binding.clone();
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
        validate_withdrawal_operator_approvals(
            withdrawal,
            finalized_monero_tx_id,
            finalization_proof_root,
            &operator_approval_ids,
            &operator_approval_roots,
            &operator_approvals,
            launch_binding.as_ref(),
        )?;
        withdrawal.status = "finalized".to_string();
        withdrawal.operator_approval_ids = operator_approval_ids;
        withdrawal.operator_approval_roots = operator_approval_roots;
        withdrawal.operator_approvals = operator_approvals;
        withdrawal.finalized_monero_tx_id = Some(finalized_monero_tx_id.to_ascii_lowercase());
        withdrawal.finalization_proof_root = Some(finalization_proof_root.to_ascii_lowercase());
        withdrawal.finalized_at_unix_ms = Some(unix_ms());
        withdrawal.root = withdrawal_root(withdrawal);
        validate_withdrawal_for_launch_binding(withdrawal, launch_binding.as_ref())?;
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
        self.ensure_accountability_clean()?;
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
        self.ensure_accountability_clean()?;
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

    fn ensure_accountability_clean(&self) -> Result<(), String> {
        if self.accountability_reports.is_empty() {
            return Ok(());
        }
        Err(format!(
            "sequencer accountability evidence is open: {} report(s); block production and state mutations are disabled",
            self.accountability_reports.len()
        ))
    }

    fn apply_transaction(
        &mut self,
        tx: &RuntimeTransaction,
        block_height: u64,
    ) -> Result<RuntimeReceipt, String> {
        let plan = self.transaction_execution_plan(tx)?;
        self.accounts.insert(tx.from.clone(), plan.next_sender);

        if matches!(plan.asset, FeeAsset::NXmr) {
            self.total_nxmr_fees_units = self
                .total_nxmr_fees_units
                .checked_add(plan.quote.paid_amount_units)
                .ok_or_else(|| "nXMR fee accounting overflowed".to_string())?;
            self.buyback_pool_nebulai = self
                .buyback_pool_nebulai
                .checked_add(plan.quote.reserve_backing_nebulai)
                .ok_or_else(|| "NBLA buyback accounting overflowed".to_string())?;
        }

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
            .checked_add(plan.quote.validator_reward_nebulai)
            .ok_or_else(|| "validator reward credit overflowed".to_string())?;
        reward_account.validator_points = reward_account
            .validator_points
            .checked_add(plan.quote.validator_points)
            .ok_or_else(|| "validator points overflowed".to_string())?;
        self.validator_reward_nebulai = self
            .validator_reward_nebulai
            .checked_add(plan.quote.validator_reward_nebulai)
            .ok_or_else(|| "validator reward accounting overflowed".to_string())?;

        Ok(RuntimeReceipt {
            tx_id: tx.id(),
            status: TransactionStatus::Included,
            block_height: Some(block_height),
            fee_asset: tx.fee_asset.clone(),
            paid_amount_units: plan.quote.paid_amount_units,
            validator_reward_nebulai: plan.quote.validator_reward_nebulai,
            buyback_nebulai: plan.quote.reserve_backing_nebulai,
            error: None,
        })
    }

    fn transaction_execution_plan(
        &self,
        tx: &RuntimeTransaction,
    ) -> Result<RuntimeTransactionExecutionPlan, String> {
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
            }
        }
        next_sender.nonce = next_sender
            .nonce
            .checked_add(1)
            .ok_or_else(|| "sender nonce overflowed".to_string())?;

        Ok(RuntimeTransactionExecutionPlan {
            asset,
            quote,
            next_sender,
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
    let admin_token =
        normalize_admin_token(options.admin_token.clone()).map_err(std::io::Error::other)?;
    let admin_rpc_bind_addr = options.admin_rpc_bind_addr.clone();
    let sync_peers = RuntimeSyncPeerSet::from_options(&options).map_err(std::io::Error::other)?;
    let auto_produce_blocks = options.auto_produce_blocks;
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
        sync_telemetry: Arc::new(Mutex::new(BTreeMap::new())),
        admin_token,
        admin_rpc_private_listener: admin_rpc_bind_addr.is_some(),
        rate_limits: Arc::new(Mutex::new(BTreeMap::new())),
    };
    let produce_blocks = state
        .runtime
        .lock()
        .map(|runtime| runtime.config.produce_blocks)
        .unwrap_or(false);
    if produce_blocks && auto_produce_blocks {
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

    let admin_listener = match admin_rpc_bind_addr.as_deref() {
        Some(admin_bind_addr) => Some(TcpListener::bind(admin_bind_addr)?),
        None => None,
    };
    let public_listener = TcpListener::bind(bind_addr)?;
    if let Some(admin_listener) = admin_listener {
        let admin_state = state.clone();
        thread::spawn(move || {
            let _ =
                serve_runtime_rpc_listener(admin_listener, admin_state, RuntimeRpcAccess::Admin);
        });
    }
    serve_runtime_rpc_listener(public_listener, state, RuntimeRpcAccess::Public)
}

fn serve_runtime_rpc_listener(
    listener: TcpListener,
    state: RuntimeRpcState,
    access: RuntimeRpcAccess,
) -> std::io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = state.clone();
                thread::spawn(move || {
                    let _ = handle_http_connection(stream, state, access);
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
    if let Some(local_binding) = &config.launch_binding {
        match &snapshot.config.launch_binding {
            Some(snapshot_binding) if snapshot_binding == local_binding => {}
            Some(_) => {
                return Err("launch binding does not match local launch binding".to_string());
            }
            None => return Err("snapshot is missing local launch binding".to_string()),
        }
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
        if let Err(error) = snapshot_matches_config(&local.config, &snapshot) {
            rejected.push(format!("{url}: {error}"));
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

fn select_best_extending_snapshot_with_telemetry(
    state: &RuntimeRpcState,
    local: &RuntimeSnapshot,
    peer_snapshots: Vec<(String, RuntimeSnapshot)>,
) -> Result<Option<(String, RuntimeSnapshot)>, String> {
    let mut candidate_groups: BTreeMap<(u64, String, String), Vec<(String, RuntimeSnapshot)>> =
        BTreeMap::new();
    let mut rejected = Vec::new();
    for (url, snapshot) in peer_snapshots {
        if snapshot.latest_height() <= local.latest_height() {
            state.record_sync_peer_stale(&url)?;
            continue;
        }
        if let Err(error) = snapshot_matches_config(&local.config, &snapshot) {
            state.record_sync_peer_fork(&url, error.clone())?;
            rejected.push(format!("{url}: {error}"));
            continue;
        }
        if !snapshot_extends(local, &snapshot) {
            let error = format!(
                "height {} does not extend local height {}",
                snapshot.latest_height(),
                local.latest_height()
            );
            state.record_sync_peer_fork(&url, error.clone())?;
            rejected.push(format!("{url}: {error}"));
            continue;
        }
        candidate_groups
            .entry((
                snapshot.latest_height(),
                snapshot.latest_block_hash().unwrap_or_default().to_string(),
                snapshot.state_root.clone(),
            ))
            .or_default()
            .push((url, snapshot));
    }
    let selected_key = candidate_groups
        .iter()
        .filter(|(_, candidates)| candidates.len() >= state.sync_peers.sync_peer_quorum)
        .max_by(
            |(left_key, left_candidates), (right_key, right_candidates)| {
                left_key
                    .0
                    .cmp(&right_key.0)
                    .then(left_candidates.len().cmp(&right_candidates.len()))
                    .then(left_key.1.cmp(&right_key.1))
                    .then(left_key.2.cmp(&right_key.2))
            },
        )
        .map(|(key, _)| key.clone());
    if let Some(key) = selected_key {
        return Ok(candidate_groups
            .get(&key)
            .and_then(|candidates| candidates.first())
            .cloned());
    }
    if !candidate_groups.is_empty() {
        for candidates in candidate_groups.values() {
            for (url, _) in candidates {
                state.record_sync_peer_quorum_rejection(url)?;
            }
        }
        return Ok(None);
    }
    if !rejected.is_empty() {
        return Err(format!(
            "no sync peer returned an extending ahead snapshot: {}",
            rejected.join("; ")
        ));
    }
    Ok(None)
}

fn sync_runtime_from_peers(
    state: &RuntimeRpcState,
    sync_rpc_urls: &[String],
) -> Result<bool, String> {
    let mut peer_snapshots = Vec::new();
    let mut fetch_errors = Vec::new();
    for url in sync_rpc_urls {
        let started_at_unix_ms = unix_ms();
        state.record_sync_peer_attempt(url, started_at_unix_ms)?;
        match fetch_runtime_snapshot(url) {
            Ok(snapshot) => {
                let latency_ms = unix_ms().saturating_sub(started_at_unix_ms);
                state.record_sync_peer_success(url, &snapshot, latency_ms)?;
                peer_snapshots.push((url.clone(), snapshot));
            }
            Err(error) => {
                let latency_ms = unix_ms().saturating_sub(started_at_unix_ms);
                state.record_sync_peer_fetch_failure(url, error.clone(), latency_ms)?;
                fetch_errors.push(format!("{url}: {error}"));
            }
        }
    }
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
        let Some((peer_url, peer)) =
            select_best_extending_snapshot_with_telemetry(state, &local, peer_snapshots)?
        else {
            return Ok(false);
        };
        runtime.import_snapshot(peer.clone())?;
        state.record_sync_peer_import(&peer_url, &peer)?;
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

fn parse_https_url(url: &str) -> Result<(), String> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("must use https://".to_string());
    };
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim();
    if host.is_empty() {
        return Err("must include a host".to_string());
    }
    if host.contains('@') {
        return Err("must not include userinfo".to_string());
    }
    if host.contains(char::is_whitespace) {
        return Err("host must not contain whitespace".to_string());
    }
    Ok(())
}

fn handle_http_connection(
    mut stream: TcpStream,
    state: RuntimeRpcState,
    access: RuntimeRpcAccess,
) -> std::io::Result<()> {
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
        ("GET", "/health") => match state.health_json() {
            Ok(health) => write_json_response(&mut stream, 200, &health)?,
            Err(error) => write_json_response(&mut stream, 500, &json!({"error": error}))?,
        },
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
        ("GET", "/metrics") => match state.metrics_text() {
            Ok(metrics) => write_text_response(
                &mut stream,
                200,
                "text/plain; version=0.0.4; charset=utf-8",
                &metrics,
            )?,
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
            let response = handle_json_rpc_request(&state, &request, access);
            write_json_response(&mut stream, 200, &response)?;
        }
        _ => write_json_response(&mut stream, 404, &json!({"error": "not found"}))?,
    }

    Ok(())
}

fn handle_json_rpc_request(
    state: &RuntimeRpcState,
    request: &Value,
    access: RuntimeRpcAccess,
) -> Value {
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
    if is_admin_rpc_method(method) && !access.allows_admin_methods() {
        return rpc_error(
            id,
            -32000,
            &format!(
                "admin method {method} is not available on the public RPC listener; use the private admin RPC listener"
            ),
        );
    }

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
            ensure_admin_rpc(state, &params, method)?;
            let snapshot_value = params
                .get("snapshot")
                .cloned()
                .unwrap_or_else(|| params_without_admin_token(&params));
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
            state.commit_direct_state_mutation()?;
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
            ensure_admin_rpc(state, &params, method)?;
            ensure_block_producer(state)?;
            let deposit_value = params
                .get("deposit")
                .cloned()
                .unwrap_or_else(|| params_without_admin_token(&params));
            let mut deposit = serde_json::from_value::<RuntimeBridgeDeposit>(deposit_value)
                .map_err(|error| format!("invalid bridge deposit: {error}"))?;
            if deposit.observed_at_unix_ms == 0 {
                deposit.observed_at_unix_ms = unix_ms();
            }
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.observe_bridge_deposit(deposit)?
            };
            state.commit_direct_state_mutation()?;
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_requestWithdrawal" => {
            ensure_block_producer(state)?;
            let account = required_str_param(&params, "account")?;
            let monero_address = required_str_param(&params, "monero_address")?;
            let amount_nxmr_units = required_u128_param(&params, "amount_nxmr_units")?;
            let nonce = required_u64_param(&params, "nonce")?;
            let signature = required_str_param(&params, "signature")?;
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.request_withdrawal(
                    &account,
                    &monero_address,
                    amount_nxmr_units,
                    nonce,
                    &signature,
                )?
            };
            state.commit_direct_state_mutation()?;
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_finalizeWithdrawal" => {
            ensure_admin_rpc(state, &params, method)?;
            ensure_block_producer(state)?;
            let withdrawal_id = required_str_param(&params, "withdrawal_id")?;
            let finalized_monero_tx_id = required_str_param(&params, "finalized_monero_tx_id")?;
            let finalization_proof_root = required_str_param(&params, "finalization_proof_root")?;
            let operator_approval_ids =
                required_string_array_param(&params, "operator_approval_ids")?;
            let operator_approval_roots =
                required_string_array_param(&params, "operator_approval_roots")?;
            let operator_approvals = optional_json_array_param::<RuntimeWithdrawalOperatorApproval>(
                &params,
                "operator_approvals",
            )?;
            let report = {
                let mut runtime = state.runtime.lock().expect("runtime mutex poisoned");
                runtime.finalize_withdrawal(
                    &withdrawal_id,
                    &finalized_monero_tx_id,
                    &finalization_proof_root,
                    operator_approval_ids,
                    operator_approval_roots,
                    operator_approvals,
                )?
            };
            state.commit_direct_state_mutation()?;
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_rotateSequencerKey" => {
            ensure_admin_rpc(state, &params, method)?;
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
            state.commit_direct_state_mutation()?;
            state.persist()?;
            Ok(json!(report))
        }
        "nebula_reportEquivocation" => {
            ensure_admin_rpc(state, &params, method)?;
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
            ensure_admin_rpc(state, &params, method)?;
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

fn is_admin_rpc_method(method: &str) -> bool {
    matches!(
        method,
        "nebula_importSnapshot"
            | "nebula_observeBridgeDeposit"
            | "nebula_finalizeWithdrawal"
            | "nebula_rotateSequencerKey"
            | "nebula_reportEquivocation"
            | "nebula_produceBlock"
    )
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
    runtime.ensure_accountability_clean()?;
    Ok(())
}

fn ensure_admin_rpc(state: &RuntimeRpcState, params: &Value, method: &str) -> Result<(), String> {
    let Some(expected_token) = state.admin_token.as_deref() else {
        return Err(format!(
            "admin token required for {method}; no admin token is configured"
        ));
    };
    let provided_token = params
        .get("admin_token")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("admin token required for {method}"))?;
    if provided_token != expected_token {
        return Err(format!("admin token rejected for {method}"));
    }
    Ok(())
}

fn params_without_admin_token(params: &Value) -> Value {
    let Value::Object(fields) = params else {
        return params.clone();
    };
    let mut fields = fields.clone();
    fields.remove("admin_token");
    Value::Object(fields)
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

fn write_text_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        500 => "Internal Server Error",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
    validate_fixed_hex(&tx.from, "from", 64)?;
    verify_account_signature(&tx.from, &tx.signing_root(), &tx.signature, "tx_signature")?;
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

fn verify_account_signature(
    account_public_key_hex: &str,
    signing_root: &str,
    signature_hex: &str,
    signature_name: &str,
) -> Result<(), String> {
    verify_ed25519_signature(
        account_public_key_hex,
        "account_public_key_hex",
        signing_root,
        signature_hex,
        signature_name,
    )
}

fn verify_ed25519_signature(
    public_key_hex: &str,
    public_key_name: &str,
    signing_root: &str,
    signature_hex: &str,
    signature_name: &str,
) -> Result<(), String> {
    validate_fixed_hex(public_key_hex, public_key_name, 64)?;
    validate_fixed_hex(signing_root, "signing_root", 64)?;
    validate_fixed_hex(signature_hex, signature_name, 128)?;
    let verifying_key = verifying_key_from_hex_named(public_key_hex, public_key_name)?;
    let signature_bytes = decode_fixed_hex(signature_hex, signature_name, 64)?;
    let signature_bytes: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{signature_name} must decode to 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(signing_root.as_bytes(), &signature)
        .map_err(|error| format!("{signature_name} Ed25519 verification failed: {error}"))
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
    if snapshot.mempool.len() > snapshot.config.max_mempool_transactions {
        return Err(format!(
            "snapshot mempool size {} exceeds max_mempool_transactions {}",
            snapshot.mempool.len(),
            snapshot.config.max_mempool_transactions
        ));
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
        validate_bridge_deposit_for_launch_binding(
            deposit,
            snapshot.config.launch_binding.as_ref(),
        )?;
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
        validate_withdrawal_for_launch_binding(
            withdrawal,
            snapshot.config.launch_binding.as_ref(),
        )?;
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
    let latest_block = snapshot
        .blocks
        .last()
        .ok_or_else(|| "snapshot must contain at least the genesis block".to_string())?;
    if latest_block.state_root != snapshot.state_root {
        return Err(
            "snapshot state_root must match the latest signed block state_root".to_string(),
        );
    }
    let nxmr_custody = nxmr_custody_reconciliation(
        &snapshot.accounts,
        &snapshot.bridge_deposits,
        &snapshot.withdrawals,
        snapshot.total_nxmr_fees_units,
    )?;
    if !nxmr_custody.bridge_custody_reconciled {
        return Err(format!(
            "nXMR custody mismatch: deposited {}, required {}, surplus {}, deficit {}",
            nxmr_custody.bridge_deposited_nxmr_units,
            nxmr_custody.nxmr_custody_required_units,
            nxmr_custody.nxmr_custody_surplus_units,
            nxmr_custody.nxmr_custody_deficit_units
        ));
    }
    Ok(())
}

fn nxmr_custody_reconciliation(
    accounts: &BTreeMap<String, RuntimeAccount>,
    bridge_deposits: &BTreeMap<String, RuntimeBridgeDeposit>,
    withdrawals: &BTreeMap<String, RuntimeWithdrawalRequest>,
    total_nxmr_fees_units: u128,
) -> Result<RuntimeNxmrCustodyReconciliation, String> {
    let bridge_deposited_nxmr_units =
        bridge_deposits.values().try_fold(0u128, |sum, deposit| {
            sum.checked_add(deposit.amount_nxmr_units)
                .ok_or_else(|| "bridge deposited nXMR accounting overflowed".to_string())
        })?;
    let account_nxmr_units = accounts.values().try_fold(0u128, |sum, account| {
        sum.checked_add(account.nxmr_units)
            .ok_or_else(|| "account nXMR accounting overflowed".to_string())
    })?;
    let withdrawal_reserved_nxmr_units =
        withdrawals.values().try_fold(0u128, |sum, withdrawal| {
            sum.checked_add(withdrawal.amount_nxmr_units)
                .ok_or_else(|| "withdrawal nXMR accounting overflowed".to_string())
        })?;
    let account_and_withdrawal = account_nxmr_units
        .checked_add(withdrawal_reserved_nxmr_units)
        .ok_or_else(|| "nXMR custody required accounting overflowed".to_string())?;
    let nxmr_custody_required_units = account_and_withdrawal
        .checked_add(total_nxmr_fees_units)
        .ok_or_else(|| "nXMR custody required accounting overflowed".to_string())?;
    let (nxmr_custody_surplus_units, nxmr_custody_deficit_units) =
        if bridge_deposited_nxmr_units >= nxmr_custody_required_units {
            (bridge_deposited_nxmr_units - nxmr_custody_required_units, 0)
        } else {
            (0, nxmr_custody_required_units - bridge_deposited_nxmr_units)
        };

    Ok(RuntimeNxmrCustodyReconciliation {
        bridge_deposited_nxmr_units,
        account_nxmr_units,
        withdrawal_reserved_nxmr_units,
        nxmr_fee_units: total_nxmr_fees_units,
        nxmr_custody_required_units,
        nxmr_custody_surplus_units,
        nxmr_custody_deficit_units,
        bridge_custody_reconciled: nxmr_custody_surplus_units == 0
            && nxmr_custody_deficit_units == 0,
    })
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

#[cfg(test)]
fn validate_bridge_deposit(deposit: &RuntimeBridgeDeposit) -> Result<(), String> {
    validate_bridge_deposit_for_launch_binding(deposit, None)
}

fn validate_bridge_deposit_for_launch_binding(
    deposit: &RuntimeBridgeDeposit,
    launch_binding: Option<&RuntimeLaunchBinding>,
) -> Result<(), String> {
    validate_account_id(&deposit.account)?;
    validate_account_id(&deposit.observer_id)?;
    validate_fixed_hex(&deposit.monero_tx_id, "monero_tx_id", 64)?;
    validate_fixed_hex(&deposit.proof_root, "proof_root", 64)?;
    validate_fixed_hex(&deposit.custody_proof_root, "custody_proof_root", 64)?;
    validate_fixed_hex(&deposit.relayer_set_root, "relayer_set_root", 64)?;
    validate_identity_root_quorum(
        &deposit.observer_ids,
        &deposit.observer_signature_roots,
        "observer_ids",
        "observer_signature_roots",
        MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM,
    )?;
    if !deposit
        .observer_ids
        .iter()
        .any(|observer_id| observer_id.eq_ignore_ascii_case(&deposit.observer_id))
    {
        return Err("observer_id must appear in observer_ids quorum".to_string());
    }
    if deposit.amount_nxmr_units == 0 {
        return Err("amount_nxmr_units must be greater than zero".to_string());
    }
    validate_bridge_observer_evidence(deposit, launch_binding)?;
    Ok(())
}

fn validate_withdrawal_for_launch_binding(
    withdrawal: &RuntimeWithdrawalRequest,
    launch_binding: Option<&RuntimeLaunchBinding>,
) -> Result<(), String> {
    validate_account_id(&withdrawal.account)?;
    validate_fixed_hex(&withdrawal.account, "withdrawal account", 64)?;
    validate_monero_address(&withdrawal.monero_address)?;
    if withdrawal.amount_nxmr_units == 0 {
        return Err(format!(
            "withdrawal {} amount_nxmr_units must be greater than zero",
            withdrawal.withdrawal_id
        ));
    }
    verify_account_signature(
        &withdrawal.account,
        &withdrawal_authorization_root(
            &withdrawal.account,
            &withdrawal.monero_address,
            withdrawal.amount_nxmr_units,
            withdrawal.nonce,
        ),
        &withdrawal.signature,
        "withdrawal_signature",
    )?;
    if withdrawal.bridge_policy_root != bridge_policy_root() {
        return Err(format!(
            "withdrawal {} bridge_policy_root does not match runtime policy",
            withdrawal.withdrawal_id
        ));
    }
    match withdrawal.status.as_str() {
        "operator_pending" => {
            if !withdrawal.operator_approval_ids.is_empty() {
                return Err(format!(
                    "withdrawal {} pending request must not have operator approval identities",
                    withdrawal.withdrawal_id
                ));
            }
            if !withdrawal.operator_approval_roots.is_empty() {
                return Err(format!(
                    "withdrawal {} pending request must not have operator approvals",
                    withdrawal.withdrawal_id
                ));
            }
            if !withdrawal.operator_approvals.is_empty() {
                return Err(format!(
                    "withdrawal {} pending request must not have signed operator approvals",
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
            validate_identity_root_quorum(
                &withdrawal.operator_approval_ids,
                &withdrawal.operator_approval_roots,
                "operator_approval_ids",
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
            validate_withdrawal_operator_approvals(
                withdrawal,
                monero_tx_id,
                proof_root,
                &withdrawal.operator_approval_ids,
                &withdrawal.operator_approval_roots,
                &withdrawal.operator_approvals,
                launch_binding,
            )?;
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

fn validate_bridge_observer_evidence(
    deposit: &RuntimeBridgeDeposit,
    launch_binding: Option<&RuntimeLaunchBinding>,
) -> Result<(), String> {
    if deposit.observer_evidence.is_empty() {
        if launch_binding.is_some() {
            return Err(
                "launch-bound bridge deposit requires observer_evidence signed by attested observers"
                    .to_string(),
            );
        }
        return Ok(());
    }
    if deposit.observer_evidence.len() != deposit.observer_ids.len() {
        return Err(format!(
            "observer_evidence length {} must match observer_ids length {}",
            deposit.observer_evidence.len(),
            deposit.observer_ids.len()
        ));
    }
    if deposit.observer_evidence.len() != deposit.observer_signature_roots.len() {
        return Err(format!(
            "observer_evidence length {} must match observer_signature_roots length {}",
            deposit.observer_evidence.len(),
            deposit.observer_signature_roots.len()
        ));
    }

    let observer_roster = launch_binding.map(launch_bridge_observer_key_map);
    let payload_root = bridge_observer_deposit_payload_root(deposit);
    let mut seen_ids = BTreeMap::<String, usize>::new();
    let mut seen_keys = BTreeMap::<String, usize>::new();
    let mut seen_roots = BTreeMap::<String, usize>::new();
    for (index, evidence) in deposit.observer_evidence.iter().enumerate() {
        validate_account_id(&evidence.observer_id)?;
        if !evidence
            .observer_id
            .eq_ignore_ascii_case(&deposit.observer_ids[index])
        {
            return Err(format!(
                "observer_evidence[{index}].observer_id must match observer_ids[{index}]"
            ));
        }
        let observer_key_name = format!("observer_evidence[{index}].observer_public_key_hex");
        validate_fixed_hex(&evidence.observer_public_key_hex, &observer_key_name, 64)?;
        let observer_id = evidence.observer_id.to_ascii_lowercase();
        if let Some(previous_index) = seen_ids.insert(observer_id.clone(), index) {
            return Err(format!(
                "observer_evidence[{index}].observer_id duplicates observer_evidence[{previous_index}]"
            ));
        }
        let public_key = evidence.observer_public_key_hex.to_ascii_lowercase();
        if let Some(previous_index) = seen_keys.insert(public_key.clone(), index) {
            return Err(format!(
                "observer_evidence[{index}].observer_public_key_hex duplicates observer_evidence[{previous_index}]"
            ));
        }
        if let Some(roster) = &observer_roster {
            let expected = roster.get(&observer_id).ok_or_else(|| {
                format!(
                    "observer_evidence[{index}].observer_id {} is not launch-attested",
                    evidence.observer_id
                )
            })?;
            if !evidence
                .observer_public_key_hex
                .eq_ignore_ascii_case(&expected.public_key)
            {
                return Err(format!(
                    "observer_evidence[{index}].observer_public_key_hex does not match launch-attested observer key"
                ));
            }
        }
        validate_fixed_hex(
            &evidence.payload_root,
            &format!("observer_evidence[{index}].payload_root"),
            64,
        )?;
        if !evidence.payload_root.eq_ignore_ascii_case(&payload_root) {
            return Err(format!(
                "observer_evidence[{index}].payload_root does not match bridge deposit payload"
            ));
        }
        verify_ed25519_signature(
            &evidence.observer_public_key_hex,
            &observer_key_name,
            &evidence.payload_root,
            &evidence.signature,
            &format!("observer_evidence[{index}].signature"),
        )?;
        validate_fixed_hex(
            &evidence.evidence_root,
            &format!("observer_evidence[{index}].evidence_root"),
            64,
        )?;
        let expected_root = bridge_observer_evidence_root(evidence);
        if !evidence.evidence_root.eq_ignore_ascii_case(&expected_root) {
            return Err(format!(
                "observer_evidence[{index}].evidence_root does not match observer evidence contents"
            ));
        }
        if !deposit.observer_signature_roots[index].eq_ignore_ascii_case(&expected_root) {
            return Err(format!(
                "observer_signature_roots[{index}] does not match observer_evidence[{index}].evidence_root"
            ));
        }
        let root = evidence.evidence_root.to_ascii_lowercase();
        if let Some(previous_index) = seen_roots.insert(root, index) {
            return Err(format!(
                "observer_evidence[{index}].evidence_root duplicates observer_evidence[{previous_index}]"
            ));
        }
    }
    Ok(())
}

fn validate_withdrawal_operator_approvals(
    withdrawal: &RuntimeWithdrawalRequest,
    finalized_monero_tx_id: &str,
    finalization_proof_root: &str,
    operator_approval_ids: &[String],
    operator_approval_roots: &[String],
    operator_approvals: &[RuntimeWithdrawalOperatorApproval],
    launch_binding: Option<&RuntimeLaunchBinding>,
) -> Result<(), String> {
    if operator_approvals.is_empty() {
        if launch_binding.is_some() {
            return Err(
                "launch-bound withdrawal finalization requires operator_approvals signed by attested operators"
                    .to_string(),
            );
        }
        return Ok(());
    }
    if operator_approvals.len() != operator_approval_ids.len() {
        return Err(format!(
            "operator_approvals length {} must match operator_approval_ids length {}",
            operator_approvals.len(),
            operator_approval_ids.len()
        ));
    }
    if operator_approvals.len() != operator_approval_roots.len() {
        return Err(format!(
            "operator_approvals length {} must match operator_approval_roots length {}",
            operator_approvals.len(),
            operator_approval_roots.len()
        ));
    }

    let operator_roster = launch_binding.map(launch_bridge_operator_key_map);
    let payload_root = withdrawal_operator_finalization_payload_root(
        withdrawal,
        finalized_monero_tx_id,
        finalization_proof_root,
    );
    let mut seen_ids = BTreeMap::<String, usize>::new();
    let mut seen_keys = BTreeMap::<String, usize>::new();
    let mut seen_roots = BTreeMap::<String, usize>::new();
    for (index, approval) in operator_approvals.iter().enumerate() {
        validate_account_id(&approval.operator_id)?;
        if !approval
            .operator_id
            .eq_ignore_ascii_case(&operator_approval_ids[index])
        {
            return Err(format!(
                "operator_approvals[{index}].operator_id must match operator_approval_ids[{index}]"
            ));
        }
        let operator_key_name = format!("operator_approvals[{index}].operator_public_key_hex");
        validate_fixed_hex(&approval.operator_public_key_hex, &operator_key_name, 64)?;
        let operator_id = approval.operator_id.to_ascii_lowercase();
        if let Some(previous_index) = seen_ids.insert(operator_id.clone(), index) {
            return Err(format!(
                "operator_approvals[{index}].operator_id duplicates operator_approvals[{previous_index}]"
            ));
        }
        let public_key = approval.operator_public_key_hex.to_ascii_lowercase();
        if let Some(previous_index) = seen_keys.insert(public_key.clone(), index) {
            return Err(format!(
                "operator_approvals[{index}].operator_public_key_hex duplicates operator_approvals[{previous_index}]"
            ));
        }
        if let Some(roster) = &operator_roster {
            let expected = roster.get(&operator_id).ok_or_else(|| {
                format!(
                    "operator_approvals[{index}].operator_id {} is not launch-attested",
                    approval.operator_id
                )
            })?;
            if !approval
                .operator_public_key_hex
                .eq_ignore_ascii_case(&expected.public_key)
            {
                return Err(format!(
                    "operator_approvals[{index}].operator_public_key_hex does not match launch-attested operator key"
                ));
            }
        }
        validate_fixed_hex(
            &approval.payload_root,
            &format!("operator_approvals[{index}].payload_root"),
            64,
        )?;
        if !approval.payload_root.eq_ignore_ascii_case(&payload_root) {
            return Err(format!(
                "operator_approvals[{index}].payload_root does not match withdrawal finalization payload"
            ));
        }
        verify_ed25519_signature(
            &approval.operator_public_key_hex,
            &operator_key_name,
            &approval.payload_root,
            &approval.signature,
            &format!("operator_approvals[{index}].signature"),
        )?;
        validate_fixed_hex(
            &approval.approval_root,
            &format!("operator_approvals[{index}].approval_root"),
            64,
        )?;
        let expected_root = withdrawal_operator_approval_root(approval);
        if !approval.approval_root.eq_ignore_ascii_case(&expected_root) {
            return Err(format!(
                "operator_approvals[{index}].approval_root does not match operator approval contents"
            ));
        }
        if !operator_approval_roots[index].eq_ignore_ascii_case(&expected_root) {
            return Err(format!(
                "operator_approval_roots[{index}] does not match operator_approvals[{index}].approval_root"
            ));
        }
        let root = approval.approval_root.to_ascii_lowercase();
        if let Some(previous_index) = seen_roots.insert(root, index) {
            return Err(format!(
                "operator_approvals[{index}].approval_root duplicates operator_approvals[{previous_index}]"
            ));
        }
    }
    Ok(())
}

fn validate_identity_root_quorum(
    identities: &[String],
    roots: &[String],
    identity_name: &str,
    root_name: &str,
    minimum_count: usize,
) -> Result<(), String> {
    if identities.len() != roots.len() {
        return Err(format!(
            "{identity_name} length {} must match {root_name} length {}",
            identities.len(),
            roots.len()
        ));
    }
    if identities.len() < minimum_count {
        return Err(format!(
            "{identity_name} must include at least {minimum_count} distinct identities"
        ));
    }
    let mut seen = BTreeMap::<String, usize>::new();
    for (index, identity) in identities.iter().enumerate() {
        validate_account_id(identity)?;
        let normalized = identity.to_ascii_lowercase();
        if let Some(previous_index) = seen.insert(normalized, index) {
            return Err(format!(
                "{identity_name}[{index}] duplicates {identity_name}[{previous_index}]"
            ));
        }
    }
    validate_quorum_roots(roots, root_name, minimum_count)
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

fn validate_launch_bridge_operator_keys(binding: &RuntimeLaunchBinding) -> Result<(), String> {
    if binding.bridge_operator_keys.len() < MIN_WITHDRAWAL_OPERATOR_QUORUM {
        return Err(format!(
            "launch binding bridge_operator_keys must include at least {MIN_WITHDRAWAL_OPERATOR_QUORUM} operators"
        ));
    }
    let mut seen_ids = BTreeMap::<String, usize>::new();
    let mut seen_keys = BTreeMap::<String, usize>::new();
    for (index, operator) in binding.bridge_operator_keys.iter().enumerate() {
        validate_account_id(&operator.operator_id)?;
        validate_label_no_whitespace(
            &operator.region,
            &format!("bridge_operator_keys[{index}].region"),
        )?;
        validate_fixed_hex(
            &operator.public_key,
            &format!("bridge_operator_keys[{index}].public_key"),
            64,
        )?;
        verifying_key_from_hex_named(
            &operator.public_key,
            &format!("bridge_operator_keys[{index}].public_key"),
        )?;
        let operator_id = operator.operator_id.to_ascii_lowercase();
        if let Some(previous_index) = seen_ids.insert(operator_id, index) {
            return Err(format!(
                "bridge_operator_keys[{index}].operator_id duplicates bridge_operator_keys[{previous_index}]"
            ));
        }
        let public_key = operator.public_key.to_ascii_lowercase();
        if let Some(previous_index) = seen_keys.insert(public_key, index) {
            return Err(format!(
                "bridge_operator_keys[{index}].public_key duplicates bridge_operator_keys[{previous_index}]"
            ));
        }
    }
    Ok(())
}

fn validate_launch_bridge_observer_keys(binding: &RuntimeLaunchBinding) -> Result<(), String> {
    if binding.bridge_observer_keys.len() < MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM {
        return Err(format!(
            "launch binding bridge_observer_keys must include at least {MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM} observers"
        ));
    }
    let operator_keys = binding
        .bridge_operator_keys
        .iter()
        .map(|operator| operator.public_key.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut seen_ids = BTreeMap::<String, usize>::new();
    let mut seen_keys = BTreeMap::<String, usize>::new();
    for (index, observer) in binding.bridge_observer_keys.iter().enumerate() {
        validate_account_id(&observer.observer_id)?;
        validate_label_no_whitespace(
            &observer.region,
            &format!("bridge_observer_keys[{index}].region"),
        )?;
        validate_fixed_hex(
            &observer.public_key,
            &format!("bridge_observer_keys[{index}].public_key"),
            64,
        )?;
        verifying_key_from_hex_named(
            &observer.public_key,
            &format!("bridge_observer_keys[{index}].public_key"),
        )?;
        let observer_id = observer.observer_id.to_ascii_lowercase();
        if let Some(previous_index) = seen_ids.insert(observer_id, index) {
            return Err(format!(
                "bridge_observer_keys[{index}].observer_id duplicates bridge_observer_keys[{previous_index}]"
            ));
        }
        let public_key = observer.public_key.to_ascii_lowercase();
        if operator_keys
            .iter()
            .any(|operator_key| operator_key == &public_key)
        {
            return Err(format!(
                "bridge_observer_keys[{index}].public_key must not reuse a bridge operator key"
            ));
        }
        if let Some(previous_index) = seen_keys.insert(public_key, index) {
            return Err(format!(
                "bridge_observer_keys[{index}].public_key duplicates bridge_observer_keys[{previous_index}]"
            ));
        }
    }
    Ok(())
}

fn launch_bridge_operator_key_map(
    binding: &RuntimeLaunchBinding,
) -> BTreeMap<String, &RuntimeBridgeOperatorKey> {
    binding
        .bridge_operator_keys
        .iter()
        .map(|operator| (operator.operator_id.to_ascii_lowercase(), operator))
        .collect()
}

fn launch_bridge_observer_key_map(
    binding: &RuntimeLaunchBinding,
) -> BTreeMap<String, &RuntimeBridgeObserverKey> {
    binding
        .bridge_observer_keys
        .iter()
        .map(|observer| (observer.observer_id.to_ascii_lowercase(), observer))
        .collect()
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

fn validate_label_no_whitespace(value: &str, name: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(format!("{name} must not contain whitespace"));
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
    signing_key_from_hex_named(secret_key_hex, "sequencer_secret_key_hex")
}

fn signing_key_from_hex_named(secret_key_hex: &str, name: &str) -> Result<SigningKey, String> {
    let bytes = decode_fixed_hex(secret_key_hex, name, 32)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{name} must decode to 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key_from_hex(public_key_hex: &str) -> Result<VerifyingKey, String> {
    verifying_key_from_hex_named(public_key_hex, "sequencer_public_key_hex")
}

fn verifying_key_from_hex_named(public_key_hex: &str, name: &str) -> Result<VerifyingKey, String> {
    let bytes = decode_fixed_hex(public_key_hex, name, 32)?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{name} must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| format!("{name} is not an Ed25519 key: {error}"))
}

pub fn public_key_hex_for_secret(secret_key_hex: &str) -> Result<String, String> {
    let signing_key = signing_key_from_hex_named(secret_key_hex, "secret_key_hex")?;
    Ok(hex::encode(signing_key.verifying_key().to_bytes()))
}

pub fn sign_runtime_root(secret_key_hex: &str, root: &str) -> Result<String, String> {
    validate_fixed_hex(root, "signing_root", 64)?;
    let signing_key = signing_key_from_hex_named(secret_key_hex, "secret_key_hex")?;
    let signature: Signature = signing_key.sign(root.as_bytes());
    Ok(hex::encode(signature.to_bytes()))
}

pub fn verify_runtime_root_signature(
    public_key_hex: &str,
    root: &str,
    signature_hex: &str,
) -> Result<(), String> {
    verify_ed25519_signature(
        public_key_hex,
        "public_key_hex",
        root,
        signature_hex,
        "signature",
    )
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

fn optional_json_array_param<T>(params: &Value, name: &str) -> Result<Vec<T>, String>
where
    T: for<'de> Deserialize<'de>,
{
    match params.get(name) {
        Some(value) if !value.is_null() => serde_json::from_value::<Vec<T>>(value.clone())
            .map_err(|error| format!("invalid {name}: {error}")),
        _ => Ok(Vec::new()),
    }
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

fn push_metric<T: std::fmt::Display>(output: &mut String, name: &str, help: &str, value: T) {
    output.push_str("# HELP ");
    output.push_str(name);
    output.push(' ');
    output.push_str(help);
    output.push('\n');
    output.push_str("# TYPE ");
    output.push_str(name);
    output.push_str(" gauge\n");
    output.push_str(name);
    output.push(' ');
    output.push_str(&value.to_string());
    output.push('\n');
}

fn push_metric_bool(output: &mut String, name: &str, help: &str, value: bool) {
    push_metric(output, name, help, u8::from(value));
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

pub fn validate_runtime_snapshot(snapshot: &RuntimeSnapshot) -> Result<(), String> {
    validate_snapshot(snapshot)
}

pub fn runtime_snapshot_root(snapshot: &RuntimeSnapshot) -> String {
    snapshot_root(snapshot)
}

pub fn runtime_ops_status_root(report: &RuntimeOpsStatus) -> String {
    ops_status_root(report)
}

pub fn runtime_backup_manifest_root(manifest: &RuntimeBackupManifest) -> String {
    backup_manifest_root(manifest)
}

fn ops_status_root(report: &RuntimeOpsStatus) -> String {
    stable_runtime_root(&json!({
        "ops_status_domain": "nebula-runtime-ops-status-v1",
        "service": report.service,
        "generated_at_unix_ms": report.generated_at_unix_ms,
        "chain_id": report.chain_id,
        "runtime_version": report.runtime_version,
        "launch_binding_present": report.launch_binding_present,
        "launch_endpoint_url": report.launch_endpoint_url,
        "deployment_attestation_root": report.deployment_attestation_root,
        "public_status_manifest_root": report.public_status_manifest_root,
        "public_probe_root": report.public_probe_root,
        "validator_set_root": report.validator_set_root,
        "operator_handoff_root": report.operator_handoff_root,
        "operator_acceptance_root": report.operator_acceptance_root,
        "genesis_root": report.genesis_root,
        "launch_package_root": report.launch_package_root,
        "launch_package_bundle_root": report.launch_package_bundle_root,
        "launch_activation_height": report.launch_activation_height,
        "launch_validator_count": report.launch_validator_count,
        "launch_operator_count": report.launch_operator_count,
        "launch_region_count": report.launch_region_count,
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
        "sync_peer_quorum": report.sync_peer_quorum,
        "sync_quorum_met": report.sync_quorum_met,
        "sync_quorum_peer_count": report.sync_quorum_peer_count,
        "sync_quorum_height": report.sync_quorum_height,
        "sync_quorum_latest_hash": report.sync_quorum_latest_hash,
        "sync_quorum_state_root": report.sync_quorum_state_root,
        "sync_successful_peer_count": report.sync_successful_peer_count,
        "sync_failed_peer_count": report.sync_failed_peer_count,
        "sync_attempt_count": report.sync_attempt_count,
        "sync_success_count": report.sync_success_count,
        "sync_failure_count": report.sync_failure_count,
        "sync_stale_snapshot_count": report.sync_stale_snapshot_count,
        "sync_fork_rejection_count": report.sync_fork_rejection_count,
        "sync_quorum_rejection_count": report.sync_quorum_rejection_count,
        "sync_import_count": report.sync_import_count,
        "sync_last_success_unix_ms": report.sync_last_success_unix_ms,
        "sync_last_import_height": report.sync_last_import_height,
        "sync_peer_telemetry": report.sync_peer_telemetry,
        "rpc_max_request_bytes": report.rpc_max_request_bytes,
        "rpc_max_requests_per_minute": report.rpc_max_requests_per_minute,
        "admin_rpc_enabled": report.admin_rpc_enabled,
        "admin_rpc_private_listener": report.admin_rpc_private_listener,
        "public_rpc_admin_methods_enabled": report.public_rpc_admin_methods_enabled,
        "default_dev_sequencer_key": report.default_dev_sequencer_key,
        "max_mempool_transactions": report.max_mempool_transactions,
        "mempool_size": report.mempool_size,
        "mempool_capacity_remaining": report.mempool_capacity_remaining,
        "mempool_full_rejection_count": report.mempool_full_rejection_count,
        "mempool_admission_rejection_count": report.mempool_admission_rejection_count,
        "sequencer_public_key_hex": report.sequencer_public_key_hex,
        "sequencer_key_rotation_count": report.sequencer_key_rotation_count,
        "sequencer_latest_rotation_activation_height": report.sequencer_latest_rotation_activation_height,
        "sequencer_key_history_root": report.sequencer_key_history_root,
        "accountability_report_count": report.accountability_report_count,
        "accountability_root": report.accountability_root,
        "sequencer_accountability_clean": report.sequencer_accountability_clean,
        "bridge_policy_root": report.bridge_policy_root,
        "bridge_live_value_enabled": report.bridge_live_value_enabled,
        "faucet_nbla_nebulai": report.faucet_nbla_nebulai,
        "faucet_nxmr_units": report.faucet_nxmr_units,
        "bridge_only_nxmr": report.bridge_only_nxmr,
        "bridge_deposited_nxmr_units": report.bridge_deposited_nxmr_units,
        "account_nxmr_units": report.account_nxmr_units,
        "withdrawal_reserved_nxmr_units": report.withdrawal_reserved_nxmr_units,
        "nxmr_fee_units": report.nxmr_fee_units,
        "nxmr_custody_required_units": report.nxmr_custody_required_units,
        "nxmr_custody_surplus_units": report.nxmr_custody_surplus_units,
        "nxmr_custody_deficit_units": report.nxmr_custody_deficit_units,
        "bridge_custody_reconciled": report.bridge_custody_reconciled,
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
        "launch_binding_present": manifest.launch_binding_present,
        "launch_endpoint_url": manifest.launch_endpoint_url,
        "deployment_attestation_root": manifest.deployment_attestation_root,
        "public_status_manifest_root": manifest.public_status_manifest_root,
        "public_probe_root": manifest.public_probe_root,
        "validator_set_root": manifest.validator_set_root,
        "operator_handoff_root": manifest.operator_handoff_root,
        "operator_acceptance_root": manifest.operator_acceptance_root,
        "genesis_root": manifest.genesis_root,
        "launch_package_root": manifest.launch_package_root,
        "launch_package_bundle_root": manifest.launch_package_bundle_root,
        "launch_activation_height": manifest.launch_activation_height,
        "launch_validator_count": manifest.launch_validator_count,
        "launch_operator_count": manifest.launch_operator_count,
        "launch_region_count": manifest.launch_region_count,
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
        "sync_peer_quorum": manifest.sync_peer_quorum,
        "sync_quorum_met": manifest.sync_quorum_met,
        "sync_quorum_peer_count": manifest.sync_quorum_peer_count,
        "sync_quorum_height": manifest.sync_quorum_height,
        "sync_quorum_latest_hash": manifest.sync_quorum_latest_hash,
        "sync_quorum_state_root": manifest.sync_quorum_state_root,
        "sync_successful_peer_count": manifest.sync_successful_peer_count,
        "sync_failed_peer_count": manifest.sync_failed_peer_count,
        "sync_attempt_count": manifest.sync_attempt_count,
        "sync_success_count": manifest.sync_success_count,
        "sync_failure_count": manifest.sync_failure_count,
        "sync_stale_snapshot_count": manifest.sync_stale_snapshot_count,
        "sync_fork_rejection_count": manifest.sync_fork_rejection_count,
        "sync_quorum_rejection_count": manifest.sync_quorum_rejection_count,
        "sync_import_count": manifest.sync_import_count,
        "sync_last_success_unix_ms": manifest.sync_last_success_unix_ms,
        "sync_last_import_height": manifest.sync_last_import_height,
        "sync_peer_telemetry": manifest.sync_peer_telemetry,
        "rpc_max_request_bytes": manifest.rpc_max_request_bytes,
        "rpc_max_requests_per_minute": manifest.rpc_max_requests_per_minute,
        "admin_rpc_enabled": manifest.admin_rpc_enabled,
        "admin_rpc_private_listener": manifest.admin_rpc_private_listener,
        "public_rpc_admin_methods_enabled": manifest.public_rpc_admin_methods_enabled,
        "default_dev_sequencer_key": manifest.default_dev_sequencer_key,
        "max_mempool_transactions": manifest.max_mempool_transactions,
        "mempool_size": manifest.mempool_size,
        "mempool_capacity_remaining": manifest.mempool_capacity_remaining,
        "mempool_full_rejection_count": manifest.mempool_full_rejection_count,
        "mempool_admission_rejection_count": manifest.mempool_admission_rejection_count,
        "faucet_nbla_nebulai": manifest.faucet_nbla_nebulai,
        "faucet_nxmr_units": manifest.faucet_nxmr_units,
        "bridge_only_nxmr": manifest.bridge_only_nxmr,
        "bridge_deposited_nxmr_units": manifest.bridge_deposited_nxmr_units,
        "account_nxmr_units": manifest.account_nxmr_units,
        "withdrawal_reserved_nxmr_units": manifest.withdrawal_reserved_nxmr_units,
        "nxmr_fee_units": manifest.nxmr_fee_units,
        "nxmr_custody_required_units": manifest.nxmr_custody_required_units,
        "nxmr_custody_surplus_units": manifest.nxmr_custody_surplus_units,
        "nxmr_custody_deficit_units": manifest.nxmr_custody_deficit_units,
        "bridge_custody_reconciled": manifest.bridge_custody_reconciled,
    }))
}

pub fn bridge_policy() -> RuntimeBridgePolicy {
    RuntimeBridgePolicy {
        policy_id: BRIDGE_CUSTODY_POLICY_ID,
        custody_model: "testnet-multisig-evidence-roots",
        min_deposit_confirmations: MIN_BRIDGE_CONFIRMATIONS,
        min_deposit_observer_quorum: MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM,
        deposit_observer_identity_quorum_required: true,
        min_withdrawal_operator_quorum: MIN_WITHDRAWAL_OPERATOR_QUORUM,
        withdrawal_operator_identity_quorum_required: true,
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

pub fn bridge_observer_deposit_payload_root(deposit: &RuntimeBridgeDeposit) -> String {
    stable_runtime_root(&json!({
        "bridge_observer_deposit_payload_domain": "nebula-runtime-monero-bridge-observer-payload-v1",
        "monero_tx_id": deposit.monero_tx_id,
        "account": deposit.account,
        "amount_nxmr_units": deposit.amount_nxmr_units,
        "confirmations": deposit.confirmations,
        "observer_id": deposit.observer_id,
        "observer_ids": deposit.observer_ids,
        "proof_root": deposit.proof_root,
        "custody_proof_root": deposit.custody_proof_root,
        "relayer_set_root": deposit.relayer_set_root,
        "observed_at_unix_ms": deposit.observed_at_unix_ms,
        "bridge_policy_root": bridge_policy_root(),
    }))
}

pub fn bridge_observer_evidence_root(evidence: &RuntimeBridgeObserverEvidence) -> String {
    stable_runtime_root(&json!({
        "bridge_observer_evidence_domain": "nebula-runtime-monero-bridge-observer-evidence-v1",
        "observer_id": evidence.observer_id,
        "observer_public_key_hex": evidence.observer_public_key_hex,
        "payload_root": evidence.payload_root,
        "signature": evidence.signature,
        "signed_at_unix_ms": evidence.signed_at_unix_ms,
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
        "observer_ids": deposit.observer_ids,
        "proof_root": deposit.proof_root,
        "custody_proof_root": deposit.custody_proof_root,
        "relayer_set_root": deposit.relayer_set_root,
        "observer_signature_roots": deposit.observer_signature_roots,
        "observer_evidence": deposit.observer_evidence,
        "observed_at_unix_ms": deposit.observed_at_unix_ms,
        "bridge_policy_root": bridge_policy_root(),
    }))
}

pub fn withdrawal_pending_root(withdrawal: &RuntimeWithdrawalRequest) -> String {
    let mut pending = withdrawal.clone();
    pending.status = "operator_pending".to_string();
    pending.operator_approval_ids.clear();
    pending.operator_approval_roots.clear();
    pending.operator_approvals.clear();
    pending.finalized_monero_tx_id = None;
    pending.finalization_proof_root = None;
    pending.finalized_at_unix_ms = None;
    pending.root = String::new();
    withdrawal_root(&pending)
}

pub fn withdrawal_operator_finalization_payload_root(
    withdrawal: &RuntimeWithdrawalRequest,
    finalized_monero_tx_id: &str,
    finalization_proof_root: &str,
) -> String {
    stable_runtime_root(&json!({
        "bridge_operator_finalization_payload_domain": "nebula-runtime-monero-bridge-operator-finalization-v1",
        "withdrawal_id": withdrawal.withdrawal_id,
        "pending_withdrawal_root": withdrawal_pending_root(withdrawal),
        "account": withdrawal.account,
        "monero_address": withdrawal.monero_address,
        "amount_nxmr_units": withdrawal.amount_nxmr_units,
        "nonce": withdrawal.nonce,
        "withdrawal_authorization_root": withdrawal_authorization_root(
            &withdrawal.account,
            &withdrawal.monero_address,
            withdrawal.amount_nxmr_units,
            withdrawal.nonce,
        ),
        "bridge_policy_root": withdrawal.bridge_policy_root,
        "finalized_monero_tx_id": finalized_monero_tx_id,
        "finalization_proof_root": finalization_proof_root,
    }))
}

pub fn withdrawal_operator_approval_root(approval: &RuntimeWithdrawalOperatorApproval) -> String {
    stable_runtime_root(&json!({
        "bridge_operator_approval_domain": "nebula-runtime-monero-bridge-operator-approval-v1",
        "operator_id": approval.operator_id,
        "operator_public_key_hex": approval.operator_public_key_hex,
        "payload_root": approval.payload_root,
        "signature": approval.signature,
        "signed_at_unix_ms": approval.signed_at_unix_ms,
    }))
}

fn withdrawal_root(withdrawal: &RuntimeWithdrawalRequest) -> String {
    stable_runtime_root(&json!({
        "withdrawal_domain": "nebula-runtime-monero-withdrawal-v1",
        "withdrawal_id": withdrawal.withdrawal_id,
        "account": withdrawal.account,
        "monero_address": withdrawal.monero_address,
        "amount_nxmr_units": withdrawal.amount_nxmr_units,
        "nonce": withdrawal.nonce,
        "signature": withdrawal.signature,
        "requested_at_unix_ms": withdrawal.requested_at_unix_ms,
        "status": withdrawal.status,
        "bridge_policy_root": withdrawal.bridge_policy_root,
        "operator_approval_ids": withdrawal.operator_approval_ids,
        "operator_approval_roots": withdrawal.operator_approval_roots,
        "operator_approvals": withdrawal.operator_approvals,
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
        "mempool_full_rejection_count": snapshot.mempool_full_rejection_count,
        "mempool_admission_rejection_count": snapshot.mempool_admission_rejection_count,
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
            sync_telemetry: Arc::new(Mutex::new(BTreeMap::new())),
            admin_token: None,
            admin_rpc_private_listener: false,
            rate_limits: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn test_launch_binding() -> RuntimeLaunchBinding {
        RuntimeLaunchBinding {
            chain_id: CHAIN_ID.to_string(),
            runtime_version: VERSION.to_string(),
            endpoint_url: "https://public.testnet.nebula.example/status".to_string(),
            deployment_attestation_root: "1".repeat(64),
            public_status_manifest_root: "2".repeat(64),
            public_probe_root: "3".repeat(64),
            validator_set_root: "4".repeat(64),
            operator_handoff_root: "5".repeat(64),
            operator_acceptance_root: "6".repeat(64),
            genesis_root: "7".repeat(64),
            launch_package_root: "8".repeat(64),
            launch_package_bundle_root: "9".repeat(64),
            activation_height: 1,
            validator_count: 3,
            operator_count: 2,
            region_count: 2,
            bridge_operator_keys: vec![
                RuntimeBridgeOperatorKey {
                    operator_id: "operator-a".to_string(),
                    region: "us-east".to_string(),
                    public_key: test_public_key_hex(0xa1),
                },
                RuntimeBridgeOperatorKey {
                    operator_id: "operator-b".to_string(),
                    region: "eu-west".to_string(),
                    public_key: test_public_key_hex(0xa2),
                },
            ],
            bridge_observer_keys: vec![
                RuntimeBridgeObserverKey {
                    observer_id: "observer-a".to_string(),
                    region: "us-east".to_string(),
                    public_key: test_public_key_hex(0xb1),
                },
                RuntimeBridgeObserverKey {
                    observer_id: "observer-b".to_string(),
                    region: "eu-west".to_string(),
                    public_key: test_public_key_hex(0xb2),
                },
            ],
        }
    }

    fn runtime_config_with_launch_binding() -> RuntimeConfig {
        let mut config = RuntimeConfig::public_testnet_default();
        config.launch_binding = Some(test_launch_binding());
        config
    }

    fn runtime_config_with_launch_binding_and_disabled_nbla_faucet() -> RuntimeConfig {
        let mut config = runtime_config_with_launch_binding();
        config.faucet_nbla_nebulai = 0;
        config
    }

    fn disable_public_nbla_faucet(runtime: &mut NebulaRuntime) {
        runtime.config.faucet_nbla_nebulai = 0;
    }

    fn public_ops_test_sequencer_secret_key_hex() -> String {
        "3c".repeat(32)
    }

    fn rotate_runtime_off_default_dev_key(runtime: &mut NebulaRuntime) {
        runtime
            .rotate_sequencer_key(
                &public_ops_test_sequencer_secret_key_hex(),
                "operator-a",
                &"a".repeat(64),
            )
            .unwrap();
    }

    fn enable_private_admin_control(state: &mut RuntimeRpcState) {
        state.admin_token = Some("admin".to_string());
        state.admin_rpc_private_listener = true;
    }

    fn test_account_secret_key_hex() -> String {
        "1f".repeat(32)
    }

    fn test_account_id() -> String {
        public_key_hex_for_secret(&test_account_secret_key_hex()).unwrap()
    }

    fn test_secret_key_hex(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    fn test_public_key_hex(seed: u8) -> String {
        public_key_hex_for_secret(&test_secret_key_hex(seed)).unwrap()
    }

    fn sign_root_with_seed(seed: u8, root: &str) -> String {
        let signing_key = signing_key_from_hex(&test_secret_key_hex(seed)).unwrap();
        hex::encode(signing_key.sign(root.as_bytes()).to_bytes())
    }

    fn sign_test_root(root: &str) -> String {
        let signing_key = signing_key_from_hex(&test_account_secret_key_hex()).unwrap();
        hex::encode(signing_key.sign(root.as_bytes()).to_bytes())
    }

    fn sign_test_transaction(mut tx: RuntimeTransaction) -> RuntimeTransaction {
        tx.signature = sign_test_root(&tx.signing_root());
        tx
    }

    fn test_withdrawal_signature(
        monero_address: &str,
        amount_nxmr_units: u128,
        nonce: u64,
    ) -> String {
        sign_test_root(&withdrawal_authorization_root(
            &test_account_id(),
            monero_address,
            amount_nxmr_units,
            nonce,
        ))
    }

    fn test_bridge_deposit(monero_tx_digit: char, proof_digit: char) -> RuntimeBridgeDeposit {
        RuntimeBridgeDeposit {
            monero_tx_id: monero_tx_digit.to_string().repeat(64),
            account: test_account_id(),
            amount_nxmr_units: 5_000,
            confirmations: MIN_BRIDGE_CONFIRMATIONS,
            observer_id: "observer-a".to_string(),
            observer_ids: vec!["observer-a".to_string(), "observer-b".to_string()],
            proof_root: proof_digit.to_string().repeat(64),
            custody_proof_root: "7".repeat(64),
            relayer_set_root: "8".repeat(64),
            observer_signature_roots: vec!["9".repeat(64), "a".repeat(64)],
            observer_evidence: Vec::new(),
            observed_at_unix_ms: 1,
        }
    }

    fn signed_test_bridge_deposit(
        monero_tx_digit: char,
        proof_digit: char,
    ) -> RuntimeBridgeDeposit {
        let mut deposit = test_bridge_deposit(monero_tx_digit, proof_digit);
        let observer_a = test_bridge_observer_evidence(&deposit, "observer-a", 0xb1, 1);
        let observer_b = test_bridge_observer_evidence(&deposit, "observer-b", 0xb2, 1);
        deposit.observer_signature_roots = vec![
            observer_a.evidence_root.clone(),
            observer_b.evidence_root.clone(),
        ];
        deposit.observer_evidence = vec![observer_a, observer_b];
        deposit
    }

    fn test_bridge_observer_evidence(
        deposit: &RuntimeBridgeDeposit,
        observer_id: &str,
        seed: u8,
        signed_at_unix_ms: u128,
    ) -> RuntimeBridgeObserverEvidence {
        let payload_root = bridge_observer_deposit_payload_root(deposit);
        let mut evidence = RuntimeBridgeObserverEvidence {
            observer_id: observer_id.to_string(),
            observer_public_key_hex: test_public_key_hex(seed),
            payload_root: payload_root.clone(),
            signature: sign_root_with_seed(seed, &payload_root),
            signed_at_unix_ms,
            evidence_root: String::new(),
        };
        evidence.evidence_root = bridge_observer_evidence_root(&evidence);
        evidence
    }

    fn test_operator_approval(
        withdrawal: &RuntimeWithdrawalRequest,
        finalized_monero_tx_id: &str,
        finalization_proof_root: &str,
        operator_id: &str,
        seed: u8,
        signed_at_unix_ms: u128,
    ) -> RuntimeWithdrawalOperatorApproval {
        let payload_root = withdrawal_operator_finalization_payload_root(
            withdrawal,
            finalized_monero_tx_id,
            finalization_proof_root,
        );
        let mut approval = RuntimeWithdrawalOperatorApproval {
            operator_id: operator_id.to_string(),
            operator_public_key_hex: test_public_key_hex(seed),
            payload_root: payload_root.clone(),
            signature: sign_root_with_seed(seed, &payload_root),
            signed_at_unix_ms,
            approval_root: String::new(),
        };
        approval.approval_root = withdrawal_operator_approval_root(&approval);
        approval
    }

    fn test_operator_approval_quorum(
        withdrawal: &RuntimeWithdrawalRequest,
        finalized_monero_tx_id: &str,
        finalization_proof_root: &str,
    ) -> (
        Vec<String>,
        Vec<String>,
        Vec<RuntimeWithdrawalOperatorApproval>,
    ) {
        let approval_a = test_operator_approval(
            withdrawal,
            finalized_monero_tx_id,
            finalization_proof_root,
            "operator-a",
            0xa1,
            1,
        );
        let approval_b = test_operator_approval(
            withdrawal,
            finalized_monero_tx_id,
            finalization_proof_root,
            "operator-b",
            0xa2,
            1,
        );
        (
            vec![
                approval_a.operator_id.clone(),
                approval_b.operator_id.clone(),
            ],
            vec![
                approval_a.approval_root.clone(),
                approval_b.approval_root.clone(),
            ],
            vec![approval_a, approval_b],
        )
    }

    fn one_shot_http_response(body: String, status_line: &str) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let status_line = status_line.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let mut request = Vec::new();
            let mut chunk = [0_u8; 256];
            while !String::from_utf8_lossy(&request).contains("\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || error.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
            let _ = stream.shutdown(std::net::Shutdown::Write);
            thread::sleep(Duration::from_millis(25));
        });
        (format!("http://{address}/snapshot"), handle)
    }

    fn snapshot_test_state_root(snapshot: &RuntimeSnapshot) -> String {
        stable_runtime_root(&json!({
            "state_domain": "nebula-runtime-state-v1",
            "accounts": snapshot.accounts,
            "bridge_deposits": snapshot.bridge_deposits,
            "withdrawals": snapshot.withdrawals,
            "total_nxmr_fees_units": snapshot.total_nxmr_fees_units,
            "buyback_pool_nebulai": snapshot.buyback_pool_nebulai,
            "validator_reward_nebulai": snapshot.validator_reward_nebulai,
        }))
    }

    fn test_nbla_transaction(nonce: u64, to: &str) -> RuntimeTransaction {
        sign_test_transaction(RuntimeTransaction {
            from: test_account_id(),
            to: to.to_string(),
            amount_nebulai: 1,
            gas_units: 1,
            gas_price_nebulai: 1,
            fee_asset: NBLA_SYMBOL.to_string(),
            nonce,
            signature: String::new(),
            memo: Some(format!("test-nbla-{nonce}")),
        })
    }

    #[test]
    fn public_testnet_runtime_uses_sub_second_blocks() {
        let config = RuntimeConfig::public_testnet_default();
        assert!(config.block_target_ms < 1_000);
        assert_eq!(config.faucet_nxmr_units, 0);
        let runtime = NebulaRuntime::new(config).unwrap();
        let status = runtime.status();
        assert!(status.sub_second_blocks);
        assert_eq!(status.block_target_ms, DEFAULT_SUBSECOND_BLOCK_MS);
        assert!(status.bridge_only_nxmr);
    }

    #[test]
    fn runtime_rejects_nxmr_faucet_configuration() {
        let mut config = RuntimeConfig::public_testnet_default();
        config.faucet_nxmr_units = 1;
        assert!(NebulaRuntime::new(config)
            .unwrap_err()
            .contains("faucet_nxmr_units"));
    }

    #[test]
    fn runtime_faucet_credits_only_nbla_and_keeps_nxmr_bridge_only() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let report = runtime.faucet("alice").unwrap();

        assert_eq!(report.credited_nbla_nebulai, DEFAULT_FAUCET_NBLA);
        assert_eq!(report.credited_nxmr_units, 0);
        assert_eq!(report.account_state.nbla_nebulai, DEFAULT_FAUCET_NBLA);
        assert_eq!(report.account_state.nxmr_units, 0);
        let status = runtime.status();
        assert_eq!(status.faucet_nxmr_units, 0);
        assert!(status.bridge_only_nxmr);
    }

    #[test]
    fn disabled_runtime_faucet_rejects_public_account_credit() {
        let mut config = RuntimeConfig::public_testnet_default();
        config.faucet_nbla_nebulai = 0;
        let mut runtime = NebulaRuntime::new(config).unwrap();

        assert!(runtime
            .faucet("alice")
            .unwrap_err()
            .contains("NBLA faucet is disabled"));
        assert!(runtime.account("alice").is_none());
        assert_eq!(runtime.status().faucet_nbla_nebulai, 0);
    }

    #[test]
    fn snapshot_rejects_unbacked_nxmr_balance() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime
            .accounts
            .entry("alice".to_string())
            .or_insert_with(RuntimeAccount::empty)
            .nxmr_units = 1;
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();

        assert!(validate_snapshot(&snapshot)
            .unwrap_err()
            .contains("nXMR custody mismatch"));
    }

    #[test]
    fn snapshot_rejects_bridge_amount_mismatch() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let deposit = test_bridge_deposit('1', '2');
        runtime.observe_bridge_deposit(deposit.clone()).unwrap();
        runtime
            .bridge_deposits
            .get_mut(&deposit.monero_tx_id)
            .unwrap()
            .amount_nxmr_units = 4_999;
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();

        assert!(validate_snapshot(&snapshot)
            .unwrap_err()
            .contains("nXMR custody mismatch"));
    }

    #[test]
    fn snapshot_rejects_state_not_bound_to_latest_signed_block() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime.faucet("alice").unwrap();
        runtime.produce_block();
        let mut snapshot = runtime.export_snapshot();
        snapshot.accounts.get_mut("alice").unwrap().nbla_nebulai += 1;
        snapshot.state_root = snapshot_test_state_root(&snapshot);
        snapshot.root = snapshot_root(&snapshot);

        assert!(validate_snapshot(&snapshot)
            .unwrap_err()
            .contains("latest signed block state_root"));
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

        assert!(normalize_admin_token(Some(String::new()))
            .unwrap_err()
            .contains("admin_token"));
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
        assert_eq!(peers.sync_peer_quorum, DEFAULT_SYNC_PEER_QUORUM);

        let options = RuntimeNodeOptions {
            sync_rpc_url: Some("https://127.0.0.1:9945/snapshot".to_string()),
            ..RuntimeNodeOptions::default()
        };
        assert!(RuntimeSyncPeerSet::from_options(&options)
            .unwrap_err()
            .contains("--sync-rpc"));

        let options = RuntimeNodeOptions {
            sync_rpc_urls: vec!["http://127.0.0.1:9945/snapshot".to_string()],
            sync_peer_quorum: 0,
            ..RuntimeNodeOptions::default()
        };
        assert!(RuntimeSyncPeerSet::from_options(&options)
            .unwrap_err()
            .contains("--sync-peer-quorum"));

        let options = RuntimeNodeOptions {
            sync_rpc_urls: vec!["http://127.0.0.1:9945/snapshot".to_string()],
            sync_peer_quorum: 2,
            ..RuntimeNodeOptions::default()
        };
        assert!(RuntimeSyncPeerSet::from_options(&options)
            .unwrap_err()
            .contains("exceeds configured --sync-rpc peer count"));
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
            sync_peer_quorum: DEFAULT_SYNC_PEER_QUORUM,
        };
        let status = state.status_json().unwrap();

        assert_eq!(status["rpc_max_request_bytes"], 2048);
        assert_eq!(status["rpc_max_requests_per_minute"], 7);
        assert_eq!(status["admin_rpc_enabled"], false);
        assert_eq!(
            status["max_mempool_transactions"],
            DEFAULT_MAX_MEMPOOL_TRANSACTIONS
        );
        assert_eq!(
            status["mempool_capacity_remaining"],
            DEFAULT_MAX_MEMPOOL_TRANSACTIONS
        );
        assert_eq!(status["mempool_full_rejection_count"], 0);
        assert_eq!(status["mempool_admission_rejection_count"], 0);
        assert_eq!(status["faucet_nxmr_units"], 0);
        assert_eq!(status["bridge_only_nxmr"], true);
        assert_eq!(status["bridge_custody_reconciled"], true);
        assert_eq!(status["nxmr_custody_deficit_units"], 0);
        assert_eq!(status["sync_peer_count"], 2);
        assert_eq!(status["sync_peer_quorum"], DEFAULT_SYNC_PEER_QUORUM);
        assert_eq!(status["sync_quorum_met"], false);
        assert_eq!(status["sync_quorum_peer_count"], 0);
        assert_eq!(status["sync_quorum_height"], Value::Null);
        assert_eq!(status["sync_quorum_latest_hash"], Value::Null);
        assert_eq!(status["sync_quorum_state_root"], Value::Null);
        assert_eq!(
            status["sync_peer_urls"],
            json!([
                "http://127.0.0.1:9945/snapshot",
                "http://127.0.0.1:9946/snapshot"
            ])
        );
        assert_eq!(status["sync_successful_peer_count"], 0);
        assert_eq!(status["sync_attempt_count"], 0);
        assert_eq!(status["sync_quorum_rejection_count"], 0);
        assert_eq!(status["sync_peer_telemetry"].as_array().unwrap().len(), 2);
        assert_eq!(
            status["sync_peer_telemetry"][0]["url"],
            "http://127.0.0.1:9945/snapshot"
        );
        assert_eq!(
            status["sync_peer_telemetry"][0]["last_attempt_unix_ms"],
            Value::Null
        );
        assert_eq!(
            status["sync_peer_telemetry"][0]["last_success_unix_ms"],
            Value::Null
        );
        assert_eq!(status["sync_peer_telemetry"][0]["attempt_count"], 0);
        assert_eq!(
            status["sync_peer_telemetry"][0]["quorum_rejection_count"],
            0
        );
        assert_eq!(
            dispatch_json_rpc_method(&state, "nebula_status", json!({})).unwrap()
                ["rpc_max_requests_per_minute"],
            7
        );
        assert_eq!(
            dispatch_json_rpc_method(&state, "nebula_status", json!({})).unwrap()
                ["sync_peer_telemetry"][1]["url"],
            "http://127.0.0.1:9946/snapshot"
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
        assert!(ops
            .blocking_gaps
            .contains(&"missing-launch-package-binding".to_string()));
        assert!(!ops.launch_binding_present);
        assert!(!ops.storage_snapshot_present);
        assert_eq!(ops.ops_root.len(), 64);
    }

    #[test]
    fn runtime_ops_status_requires_launch_package_binding() {
        let dir = std::env::temp_dir().join(format!("nebula-runtime-missing-launch-{}", unix_ms()));
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
        state.storage = Some(storage);

        let ops = state.ops_status().unwrap();
        assert!(!ops.public_ops_ready);
        assert_eq!(
            ops.blocking_gaps,
            vec!["missing-launch-package-binding".to_string()]
        );
        assert!(!ops.launch_binding_present);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_ops_status_fails_closed_when_launch_bound_nbla_faucet_enabled() {
        let dir = std::env::temp_dir().join(format!("nebula-runtime-public-faucet-{}", unix_ms()));
        let storage = RuntimeStorage::from_data_dir(&dir);
        let mut runtime = NebulaRuntime::new(runtime_config_with_launch_binding()).unwrap();
        rotate_runtime_off_default_dev_key(&mut runtime);
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();
        storage.save_snapshot(&snapshot).unwrap();
        let mut state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.storage = Some(storage);
        enable_private_admin_control(&mut state);

        let ops = state.ops_status().unwrap();
        assert!(!ops.public_ops_ready);
        assert_eq!(ops.faucet_nbla_nebulai, DEFAULT_FAUCET_NBLA);
        assert!(ops
            .blocking_gaps
            .contains(&"public-nbla-faucet-enabled".to_string()));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_ops_status_follower_requires_successful_peer_sync_evidence() {
        let sequencer_config = runtime_config_with_launch_binding_and_disabled_nbla_faucet();
        let mut sequencer = NebulaRuntime::new(sequencer_config.clone()).unwrap();
        rotate_runtime_off_default_dev_key(&mut sequencer);
        sequencer.produce_block();
        let snapshot = sequencer.export_snapshot();
        let mut follower_config = sequencer_config;
        follower_config.produce_blocks = false;
        let follower = NebulaRuntime::from_snapshot(follower_config, snapshot.clone()).unwrap();
        let dir =
            std::env::temp_dir().join(format!("nebula-runtime-follower-sync-ready-{}", unix_ms()));
        let storage = RuntimeStorage::from_data_dir(&dir);
        storage.save_snapshot(&snapshot).unwrap();
        let mut state = test_rpc_state_with_limits(
            follower,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.storage = Some(storage);
        state.sync_peers = RuntimeSyncPeerSet {
            bootstrap_peer_urls: Vec::new(),
            sync_peer_urls: vec!["http://127.0.0.1:9945/snapshot".to_string()],
            sync_peer_quorum: DEFAULT_SYNC_PEER_QUORUM,
        };

        let ops = state.ops_status().unwrap();
        assert!(!ops.public_ops_ready);
        assert!(!ops
            .blocking_gaps
            .contains(&"follower-missing-sync-peers".to_string()));
        assert!(ops
            .blocking_gaps
            .contains(&"follower-no-successful-sync-peer".to_string()));
        assert_eq!(ops.sync_successful_peer_count, 0);
        assert_eq!(ops.sync_peer_quorum, DEFAULT_SYNC_PEER_QUORUM);
        assert!(!ops.sync_quorum_met);

        state
            .record_sync_peer_success("http://127.0.0.1:9945/snapshot", &snapshot, 1)
            .unwrap();
        let ops = state.ops_status().unwrap();
        assert!(ops.public_ops_ready, "{:?}", ops.blocking_gaps);
        assert_eq!(ops.sync_successful_peer_count, 1);
        assert!(ops.sync_quorum_met);
        assert_eq!(ops.sync_quorum_peer_count, 1);
        assert_eq!(ops.sync_quorum_height, Some(snapshot.latest_height()));
        assert_eq!(
            ops.sync_quorum_latest_hash.as_deref(),
            snapshot.latest_block_hash()
        );
        assert_eq!(
            ops.sync_quorum_state_root,
            Some(snapshot.state_root.clone())
        );
        assert_eq!(ops.sync_peer_telemetry[0].success_count, 1);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_ops_status_follower_requires_sync_quorum_evidence() {
        let sequencer_config = runtime_config_with_launch_binding_and_disabled_nbla_faucet();
        let mut sequencer = NebulaRuntime::new(sequencer_config.clone()).unwrap();
        rotate_runtime_off_default_dev_key(&mut sequencer);
        sequencer.produce_block();
        let snapshot = sequencer.export_snapshot();
        let mut follower_config = sequencer_config;
        follower_config.produce_blocks = false;
        let follower = NebulaRuntime::from_snapshot(follower_config, snapshot.clone()).unwrap();
        let dir =
            std::env::temp_dir().join(format!("nebula-runtime-follower-quorum-{}", unix_ms()));
        let storage = RuntimeStorage::from_data_dir(&dir);
        storage.save_snapshot(&snapshot).unwrap();
        let mut state = test_rpc_state_with_limits(
            follower,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.storage = Some(storage);
        state.sync_peers = RuntimeSyncPeerSet {
            bootstrap_peer_urls: Vec::new(),
            sync_peer_urls: vec![
                "http://127.0.0.1:9945/snapshot".to_string(),
                "http://127.0.0.1:9946/snapshot".to_string(),
            ],
            sync_peer_quorum: 2,
        };

        state
            .record_sync_peer_success("http://127.0.0.1:9945/snapshot", &snapshot, 1)
            .unwrap();
        let ops = state.ops_status().unwrap();
        assert!(!ops.public_ops_ready);
        assert_eq!(ops.sync_peer_quorum, 2);
        assert!(!ops.sync_quorum_met);
        assert_eq!(ops.sync_quorum_peer_count, 1);
        assert!(ops
            .blocking_gaps
            .contains(&"follower-sync-quorum-not-met".to_string()));

        state
            .record_sync_peer_success("http://127.0.0.1:9946/snapshot", &snapshot, 1)
            .unwrap();
        let ops = state.ops_status().unwrap();
        assert!(ops.public_ops_ready, "{:?}", ops.blocking_gaps);
        assert!(ops.sync_quorum_met);
        assert_eq!(ops.sync_quorum_peer_count, 2);
        assert_eq!(ops.sync_quorum_height, Some(snapshot.latest_height()));
        assert_eq!(
            ops.sync_quorum_latest_hash.as_deref(),
            snapshot.latest_block_hash()
        );
        assert_eq!(ops.sync_quorum_state_root, Some(snapshot.state_root));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_ops_status_and_backup_manifest_bind_persisted_snapshot() {
        let dir = std::env::temp_dir().join(format!("nebula-runtime-ops-test-{}", unix_ms()));
        let storage = RuntimeStorage::from_data_dir(&dir);
        let binding = test_launch_binding();
        let mut runtime = NebulaRuntime::new(runtime_config_with_launch_binding()).unwrap();
        rotate_runtime_off_default_dev_key(&mut runtime);
        runtime.faucet("alice").unwrap();
        disable_public_nbla_faucet(&mut runtime);
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();
        storage.save_snapshot(&snapshot).unwrap();
        let mut state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.storage = Some(storage.clone());
        enable_private_admin_control(&mut state);

        let ops = state.ops_status().unwrap();
        assert!(ops.public_ops_ready, "{:?}", ops.blocking_gaps);
        assert!(ops.launch_binding_present);
        assert_eq!(
            ops.launch_package_bundle_root.as_deref(),
            Some(binding.launch_package_bundle_root.as_str())
        );
        assert_eq!(ops.launch_validator_count, Some(binding.validator_count));
        assert_eq!(ops.launch_operator_count, Some(binding.operator_count));
        assert_eq!(ops.launch_region_count, Some(binding.region_count));
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
        assert!(ops.admin_rpc_enabled);
        assert!(ops.admin_rpc_private_listener);
        assert!(!ops.public_rpc_admin_methods_enabled);
        assert!(!ops.default_dev_sequencer_key);
        assert_eq!(ops.bridge_policy_root, bridge_policy_root());
        assert_eq!(
            ops.max_mempool_transactions,
            DEFAULT_MAX_MEMPOOL_TRANSACTIONS
        );
        assert_eq!(
            ops.mempool_capacity_remaining,
            DEFAULT_MAX_MEMPOOL_TRANSACTIONS
        );
        assert_eq!(ops.mempool_admission_rejection_count, 0);
        assert_eq!(ops.faucet_nxmr_units, 0);
        assert!(ops.bridge_only_nxmr);
        assert!(ops.bridge_custody_reconciled);
        assert_eq!(ops.nxmr_custody_deficit_units, 0);
        assert_eq!(ops.ops_root.len(), 64);

        let manifest = state.backup_manifest().unwrap();
        assert!(manifest.launch_binding_present);
        assert_eq!(
            manifest.launch_package_bundle_root.as_deref(),
            Some(binding.launch_package_bundle_root.as_str())
        );
        assert_eq!(manifest.snapshot_root.len(), 64);
        assert!(manifest.snapshot_persisted);
        assert!(manifest.storage_snapshot_matches_runtime);
        assert!(manifest.admin_rpc_enabled);
        assert!(manifest.admin_rpc_private_listener);
        assert!(!manifest.public_rpc_admin_methods_enabled);
        assert!(!manifest.default_dev_sequencer_key);
        assert_eq!(
            manifest.max_mempool_transactions,
            DEFAULT_MAX_MEMPOOL_TRANSACTIONS
        );
        assert_eq!(manifest.mempool_admission_rejection_count, 0);
        assert_eq!(manifest.faucet_nxmr_units, 0);
        assert!(manifest.bridge_only_nxmr);
        assert!(manifest.bridge_custody_reconciled);
        assert_eq!(manifest.nxmr_custody_deficit_units, 0);
        assert_eq!(manifest.backup_root.len(), 64);
        let rpc_ops = dispatch_json_rpc_method(&state, "nebula_opsStatus", json!({})).unwrap();
        assert_eq!(rpc_ops["ops_root"].as_str().unwrap().len(), 64);
        assert_eq!(rpc_ops["public_ops_ready"], true);
        assert_eq!(rpc_ops["launch_binding_present"], true);
        assert_eq!(
            rpc_ops["launch_package_bundle_root"],
            binding.launch_package_bundle_root
        );
        assert_eq!(rpc_ops["mempool_admission_rejection_count"], 0);
        assert_eq!(rpc_ops["faucet_nxmr_units"], 0);
        assert_eq!(rpc_ops["bridge_only_nxmr"], true);
        assert_eq!(rpc_ops["bridge_custody_reconciled"], true);
        assert_eq!(rpc_ops["nxmr_custody_deficit_units"], 0);
        assert_eq!(rpc_ops["storage_snapshot_matches_runtime"], true);
        let rpc_backup =
            dispatch_json_rpc_method(&state, "nebula_backupManifest", json!({})).unwrap();
        assert_eq!(rpc_backup["backup_root"].as_str().unwrap().len(), 64);
        assert_eq!(rpc_backup["snapshot_persisted"], true);
        assert_eq!(rpc_backup["launch_binding_present"], true);
        assert_eq!(rpc_backup["mempool_admission_rejection_count"], 0);
        assert_eq!(rpc_backup["faucet_nxmr_units"], 0);
        assert_eq!(rpc_backup["bridge_only_nxmr"], true);
        assert_eq!(rpc_backup["bridge_custody_reconciled"], true);
        assert_eq!(rpc_backup["nxmr_custody_deficit_units"], 0);
        assert_eq!(rpc_backup["storage_snapshot_matches_runtime"], true);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_health_surface_binds_chain_roots_and_ops_evidence() {
        let dir = std::env::temp_dir().join(format!("nebula-runtime-health-test-{}", unix_ms()));
        let storage = RuntimeStorage::from_data_dir(&dir);
        let binding = test_launch_binding();
        let mut runtime = NebulaRuntime::new(runtime_config_with_launch_binding()).unwrap();
        rotate_runtime_off_default_dev_key(&mut runtime);
        runtime.faucet("alice").unwrap();
        disable_public_nbla_faucet(&mut runtime);
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();
        storage.save_snapshot(&snapshot).unwrap();
        let mut state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.storage = Some(storage);
        enable_private_admin_control(&mut state);

        let health = state.health_json().unwrap();
        let status = state.status_json().unwrap();
        let ops = state.ops_status().unwrap();
        let backup = state.backup_manifest().unwrap();

        assert_eq!(health["ok"], true);
        assert_eq!(health["chain_id"], status["chain_id"]);
        assert_eq!(health["runtime_version"], status["runtime_version"]);
        assert_eq!(health["launch_binding_present"], true);
        assert_eq!(
            health["launch_package_bundle_root"],
            binding.launch_package_bundle_root
        );
        assert_eq!(health["launch_validator_count"], binding.validator_count);
        assert_eq!(health["launch_operator_count"], binding.operator_count);
        assert_eq!(health["launch_region_count"], binding.region_count);
        assert_eq!(health["node_role"], status["node_role"]);
        assert_eq!(health["latest_height"], status["latest_height"]);
        assert_eq!(health["latest_hash"], status["latest_hash"]);
        assert_eq!(health["latest_state_root"], status["latest_state_root"]);
        assert_eq!(health["current_state_root"], status["current_state_root"]);
        assert_eq!(health["snapshot_version"], ops.snapshot_version);
        assert_eq!(health["snapshot_root"], ops.snapshot_root);
        assert_eq!(health["state_root"], ops.state_root);
        assert_eq!(health["public_ops_ready"], true);
        assert_eq!(health["admin_rpc_enabled"], true);
        assert_eq!(health["admin_rpc_private_listener"], true);
        assert_eq!(health["public_rpc_admin_methods_enabled"], false);
        assert_eq!(health["default_dev_sequencer_key"], false);
        assert_eq!(health["snapshot_persisted"], true);
        assert_eq!(health["storage_snapshot_matches_runtime"], true);
        assert_eq!(health["sync_peer_count"], status["sync_peer_count"]);
        assert_eq!(health["sync_peer_quorum"], status["sync_peer_quorum"]);
        assert_eq!(health["sync_quorum_met"], status["sync_quorum_met"]);
        assert_eq!(
            health["sync_quorum_peer_count"],
            status["sync_quorum_peer_count"]
        );
        assert_eq!(health["sync_quorum_height"], status["sync_quorum_height"]);
        assert_eq!(
            health["sync_quorum_latest_hash"],
            status["sync_quorum_latest_hash"]
        );
        assert_eq!(
            health["sync_quorum_state_root"],
            status["sync_quorum_state_root"]
        );
        assert_eq!(health["bridge_policy_root"], status["bridge_policy_root"]);
        assert_eq!(
            health["sequencer_public_key_hex"],
            status["sequencer_public_key_hex"]
        );
        assert_eq!(health["backup_root"].as_str().unwrap().len(), 64);
        assert_eq!(health["ops_root"].as_str().unwrap().len(), 64);
        assert_eq!(health["snapshot_root"], backup.snapshot_root);
        assert!(health["public_ops_blocking_gaps"]
            .as_array()
            .unwrap()
            .is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_surface_evidence_accepts_matching_captured_surfaces() {
        let dir =
            std::env::temp_dir().join(format!("nebula-runtime-surface-evidence-{}", unix_ms()));
        let storage = RuntimeStorage::from_data_dir(&dir);
        let mut runtime = NebulaRuntime::new(runtime_config_with_launch_binding()).unwrap();
        rotate_runtime_off_default_dev_key(&mut runtime);
        runtime.faucet("alice").unwrap();
        disable_public_nbla_faucet(&mut runtime);
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();
        storage.save_snapshot(&snapshot).unwrap();
        let mut state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.storage = Some(storage);
        enable_private_admin_control(&mut state);

        let health = state.health_json().unwrap();
        let status = state.status_json().unwrap();
        let snapshot = state
            .runtime
            .lock()
            .expect("runtime mutex")
            .export_snapshot();
        let ops = state.ops_status().unwrap();
        let backup = state.backup_manifest().unwrap();
        let metrics_text = state.metrics_text().unwrap();
        let evidence = crate::build_runtime_surface_evidence_json_pretty(
            crate::RuntimeSurfaceEvidenceBuildInput {
                endpoint_url: "https://public.testnet.nebula.example/status".to_string(),
                capture_mode: crate::RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT
                    .to_string(),
                captured_at_unix_ms: unix_ms(),
                health_json: health.to_string(),
                status_json: status.to_string(),
                snapshot_json: serde_json::to_string(&snapshot).unwrap(),
                ops_json: serde_json::to_string(&ops).unwrap(),
                backup_json: serde_json::to_string(&backup).unwrap(),
                rpc_status_json: json!({
                    "jsonrpc": "2.0",
                    "id": "nebula_status",
                    "result": status,
                })
                .to_string(),
                rpc_ops_status_json: json!({
                    "jsonrpc": "2.0",
                    "id": "nebula_opsStatus",
                    "result": state.ops_status().unwrap(),
                })
                .to_string(),
                rpc_backup_manifest_json: json!({
                    "jsonrpc": "2.0",
                    "id": "nebula_backupManifest",
                    "result": state.backup_manifest().unwrap(),
                })
                .to_string(),
                metrics_text,
            },
        )
        .unwrap();

        let report = crate::verify_runtime_surface_evidence_json(&evidence).unwrap();
        assert!(report.runtime_surface_ready);
        assert_eq!(report.level, "runtime-surface-attested");
        assert_eq!(report.latest_height, 1);
        assert_eq!(report.snapshot_root.len(), 64);
        assert_eq!(report.ops_root.len(), 64);
        assert_eq!(report.backup_root.len(), 64);
        assert!(report.blocking_gaps.is_empty());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_surface_evidence_rejects_status_snapshot_mismatch() {
        let dir = std::env::temp_dir().join(format!(
            "nebula-runtime-surface-evidence-mismatch-{}",
            unix_ms()
        ));
        let storage = RuntimeStorage::from_data_dir(&dir);
        let mut runtime = NebulaRuntime::new(runtime_config_with_launch_binding()).unwrap();
        rotate_runtime_off_default_dev_key(&mut runtime);
        runtime.faucet("alice").unwrap();
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();
        storage.save_snapshot(&snapshot).unwrap();
        let mut state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.storage = Some(storage);
        enable_private_admin_control(&mut state);

        let health = state.health_json().unwrap();
        let mut status = state.status_json().unwrap();
        status["latest_height"] = json!(99);
        let snapshot = state
            .runtime
            .lock()
            .expect("runtime mutex")
            .export_snapshot();
        let ops = state.ops_status().unwrap();
        let backup = state.backup_manifest().unwrap();
        let error = crate::build_runtime_surface_evidence_json_pretty(
            crate::RuntimeSurfaceEvidenceBuildInput {
                endpoint_url: "https://public.testnet.nebula.example/status".to_string(),
                capture_mode: crate::RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT
                    .to_string(),
                captured_at_unix_ms: unix_ms(),
                health_json: health.to_string(),
                status_json: status.to_string(),
                snapshot_json: serde_json::to_string(&snapshot).unwrap(),
                ops_json: serde_json::to_string(&ops).unwrap(),
                backup_json: serde_json::to_string(&backup).unwrap(),
                rpc_status_json: json!({
                    "jsonrpc": "2.0",
                    "id": "nebula_status",
                    "result": status,
                })
                .to_string(),
                rpc_ops_status_json: json!({
                    "jsonrpc": "2.0",
                    "id": "nebula_opsStatus",
                    "result": state.ops_status().unwrap(),
                })
                .to_string(),
                rpc_backup_manifest_json: json!({
                    "jsonrpc": "2.0",
                    "id": "nebula_backupManifest",
                    "result": state.backup_manifest().unwrap(),
                })
                .to_string(),
                metrics_text: state.metrics_text().unwrap(),
            },
        )
        .unwrap_err();

        match error {
            crate::AttestationError::Invalid(errors) => assert!(errors
                .iter()
                .any(|error| error.contains("status.latest_height"))),
            crate::AttestationError::MalformedJson(error) => {
                panic!("unexpected malformed JSON: {error}")
            }
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_ops_status_fails_closed_when_mempool_is_full() {
        let mut config = RuntimeConfig::public_testnet_default();
        config.max_mempool_transactions = 1;
        let mut runtime = NebulaRuntime::new(config).unwrap();
        runtime.faucet(&test_account_id()).unwrap();
        runtime
            .submit_transaction(test_nbla_transaction(0, "bob"))
            .unwrap();
        let state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );

        let ops = state.ops_status().unwrap();
        assert!(!ops.public_ops_ready);
        assert_eq!(ops.max_mempool_transactions, 1);
        assert_eq!(ops.mempool_size, 1);
        assert_eq!(ops.mempool_capacity_remaining, 0);
        assert_eq!(ops.mempool_admission_rejection_count, 0);
        assert!(ops
            .blocking_gaps
            .contains(&"mempool-at-capacity".to_string()));
    }

    #[test]
    fn runtime_metrics_text_exposes_public_ops_and_bridge_gauges() {
        let runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let state = test_rpc_state_with_limits(runtime, 2048, 7);

        let metrics = state.metrics_text().unwrap();

        assert!(metrics.contains("# HELP nebula_latest_height"));
        assert!(metrics.contains("nebula_sub_second_blocks 1"));
        assert!(metrics.contains("nebula_rpc_max_request_bytes 2048"));
        assert!(metrics.contains("nebula_rpc_max_requests_per_minute 7"));
        assert!(metrics.contains("nebula_sync_peer_count 0"));
        assert!(metrics.contains("nebula_sync_peer_quorum 1"));
        assert!(metrics.contains("nebula_sync_quorum_met 0"));
        assert!(metrics.contains("nebula_sync_quorum_peer_count 0"));
        assert!(metrics.contains("nebula_sync_successful_peer_count 0"));
        assert!(metrics.contains("nebula_sync_attempt_count 0"));
        assert!(metrics.contains("nebula_sync_success_count 0"));
        assert!(metrics.contains("nebula_sync_failure_count 0"));
        assert!(metrics.contains("nebula_sync_import_count 0"));
        assert!(metrics.contains("nebula_sync_quorum_rejection_count 0"));
        assert!(metrics.contains("nebula_launch_binding_present 0"));
        assert!(metrics.contains("nebula_launch_validator_count 0"));
        assert!(metrics.contains("nebula_launch_operator_count 0"));
        assert!(metrics.contains("nebula_launch_region_count 0"));
        assert!(metrics.contains("nebula_admin_rpc_enabled 0"));
        assert!(metrics.contains("nebula_mempool_admission_rejection_count 0"));
        assert!(metrics.contains("nebula_faucet_nbla_nebulai "));
        assert!(metrics.contains("nebula_faucet_nxmr_units 0"));
        assert!(metrics.contains("nebula_bridge_only_nxmr 1"));
        assert!(metrics.contains("nebula_bridge_custody_reconciled 1"));
        assert!(metrics.contains("nebula_nxmr_custody_deficit_units 0"));
        assert!(metrics.contains("nebula_bridge_deposit_count 0"));
        assert!(metrics.contains("nebula_withdrawal_request_count 0"));
        assert!(metrics.contains("nebula_sequencer_accountability_clean 1"));
        assert!(metrics.contains("nebula_public_ops_ready 0"));
        assert!(metrics.contains("nebula_public_ops_blocking_gap_count "));
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
        let mut state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.admin_token = Some("admin".to_string());
        let new_secret_key_hex = "5e".repeat(32);
        let new_public_key_hex = public_key_hex_for_secret(&new_secret_key_hex).unwrap();

        let rotation = dispatch_json_rpc_method(
            &state,
            "nebula_rotateSequencerKey",
            json!({
                "admin_token": "admin",
                "new_sequencer_secret_key_hex": new_secret_key_hex,
                "operator_id": "operator-a",
                "approval_root": "d".repeat(64),
            }),
        )
        .unwrap();
        assert_eq!(rotation["rotated"], true);
        assert_eq!(rotation["sequencer_public_key_hex"], new_public_key_hex);
        assert_eq!(rotation["rotation"]["activation_height"], 1);

        let activation_block =
            dispatch_json_rpc_method(&state, "nebula_getBlockByHeight", json!({"height": 1}))
                .unwrap();
        assert_eq!(activation_block["producer_public_key"], new_public_key_hex);

        let block = dispatch_json_rpc_method(
            &state,
            "nebula_produceBlock",
            json!({"admin_token": "admin"}),
        )
        .unwrap();
        assert_eq!(block["height"], 2);
        assert_eq!(block["producer_public_key"], new_public_key_hex);

        let receipt = dispatch_json_rpc_method(
            &state,
            "nebula_reportEquivocation",
            json!({
                "admin_token": "admin",
                "height": block["height"],
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
    fn follower_rejects_snapshot_with_mismatched_launch_binding() {
        let local_config = runtime_config_with_launch_binding();
        let mut peer_config = runtime_config_with_launch_binding();
        peer_config
            .launch_binding
            .as_mut()
            .unwrap()
            .launch_package_bundle_root = "a".repeat(64);
        let mut peer = NebulaRuntime::new(peer_config).unwrap();
        peer.produce_block();

        assert!(
            NebulaRuntime::from_snapshot(local_config.clone(), peer.export_snapshot())
                .unwrap_err()
                .contains("launch binding")
        );

        let mut unbound_peer = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        unbound_peer.produce_block();
        let mut local = NebulaRuntime::new(local_config).unwrap();
        assert!(local
            .import_snapshot(unbound_peer.export_snapshot())
            .unwrap_err()
            .contains("launch binding"));
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
        let account = test_account_id();
        runtime.faucet(&account).unwrap();
        let tx = sign_test_transaction(RuntimeTransaction {
            from: account,
            to: "bob".to_string(),
            amount_nebulai: 10,
            gas_units: 5,
            gas_price_nebulai: 2,
            fee_asset: NBLA_SYMBOL.to_string(),
            nonce: 0,
            signature: String::new(),
            memo: None,
        });
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
    fn runtime_rejects_unsigned_user_spends_and_withdrawals() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let account = test_account_id();
        runtime.faucet(&account).unwrap();
        runtime
            .observe_bridge_deposit(test_bridge_deposit('6', '7'))
            .unwrap();

        let unsigned_tx = RuntimeTransaction {
            from: account.clone(),
            to: "bob".to_string(),
            amount_nebulai: 10,
            gas_units: 5,
            gas_price_nebulai: 2,
            fee_asset: NBLA_SYMBOL.to_string(),
            nonce: 0,
            signature: "0".repeat(128),
            memo: None,
        };
        assert!(runtime
            .submit_transaction(unsigned_tx)
            .unwrap_err()
            .contains("tx_signature"));

        assert!(runtime
            .request_withdrawal(
                &account,
                "9xTestnetMoneroAddressForNebulaWithdrawals",
                2_000,
                0,
                &"0".repeat(128),
            )
            .unwrap_err()
            .contains("withdrawal_signature"));
    }

    #[test]
    fn runtime_accounts_for_nxmr_fee_buyback_pool() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let account = test_account_id();
        runtime.faucet(&account).unwrap();
        runtime
            .observe_bridge_deposit(test_bridge_deposit('2', '3'))
            .unwrap();
        let tx = sign_test_transaction(RuntimeTransaction {
            from: account,
            to: "bob".to_string(),
            amount_nebulai: 100,
            gas_units: 100,
            gas_price_nebulai: 10,
            fee_asset: NXMR_SYMBOL.to_string(),
            nonce: 0,
            signature: String::new(),
            memo: None,
        });
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
        assert_eq!(
            runtime.account(&test_account_id()).unwrap().nxmr_units,
            5_000
        );
        assert_eq!(runtime.status().bridge_deposit_count, 1);
    }

    #[test]
    fn runtime_withdrawal_burns_nxmr_into_operator_pending_request() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime
            .observe_bridge_deposit(test_bridge_deposit('c', 'd'))
            .unwrap();

        let report = runtime
            .request_withdrawal(
                &test_account_id(),
                "9xTestnetMoneroAddressForNebulaWithdrawals",
                2_000,
                0,
                &test_withdrawal_signature("9xTestnetMoneroAddressForNebulaWithdrawals", 2_000, 0),
            )
            .unwrap();
        assert!(report.accepted);
        assert_eq!(report.withdrawal.status, "operator_pending");
        assert_eq!(report.withdrawal.bridge_policy_root, bridge_policy_root());
        assert!(report.withdrawal.operator_approval_ids.is_empty());
        assert!(report.withdrawal.operator_approval_roots.is_empty());
        assert!(report.withdrawal.operator_approvals.is_empty());
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
        let policy = bridge_policy();
        assert!(policy.deposit_observer_identity_quorum_required);
        assert!(policy.withdrawal_operator_identity_quorum_required);
        assert_eq!(status.faucet_nxmr_units, 0);
        assert!(status.bridge_only_nxmr);
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
        deposit.observer_ids = vec!["observer-a".to_string()];
        assert!(validate_bridge_deposit(&deposit)
            .unwrap_err()
            .contains("observer_ids length"));

        deposit = test_bridge_deposit('b', 'c');
        deposit.observer_ids = vec!["observer-a".to_string(), "observer-a".to_string()];
        assert!(validate_bridge_deposit(&deposit)
            .unwrap_err()
            .contains("observer_ids[1] duplicates"));

        deposit = test_bridge_deposit('b', 'c');
        deposit.observer_ids = vec!["observer-b".to_string(), "observer-c".to_string()];
        assert!(validate_bridge_deposit(&deposit)
            .unwrap_err()
            .contains("observer_id must appear in observer_ids"));

        deposit = test_bridge_deposit('b', 'c');
        deposit.custody_proof_root = "not-hex".to_string();
        assert!(validate_bridge_deposit(&deposit)
            .unwrap_err()
            .contains("custody_proof_root"));
    }

    #[test]
    fn launch_bound_bridge_deposit_requires_signed_attested_observers() {
        let mut runtime = NebulaRuntime::new(runtime_config_with_launch_binding()).unwrap();

        assert!(runtime
            .observe_bridge_deposit(test_bridge_deposit('1', '2'))
            .unwrap_err()
            .contains("observer_evidence"));

        let report = runtime
            .observe_bridge_deposit(signed_test_bridge_deposit('1', '2'))
            .unwrap();
        assert!(report.credited);
        assert_eq!(
            runtime.account(&test_account_id()).unwrap().nxmr_units,
            5_000
        );

        let mut tampered = signed_test_bridge_deposit('3', '4');
        tampered.amount_nxmr_units = 5_001;
        assert!(runtime
            .observe_bridge_deposit(tampered)
            .unwrap_err()
            .contains("payload_root"));
    }

    #[test]
    fn launch_bound_bridge_deposit_rejects_bad_observer_signature() {
        let mut runtime = NebulaRuntime::new(runtime_config_with_launch_binding()).unwrap();
        let mut deposit = signed_test_bridge_deposit('5', '6');
        deposit.observer_evidence[0].signature = "0".repeat(128);
        deposit.observer_evidence[0].evidence_root =
            bridge_observer_evidence_root(&deposit.observer_evidence[0]);
        deposit.observer_signature_roots[0] = deposit.observer_evidence[0].evidence_root.clone();

        assert!(runtime
            .observe_bridge_deposit(deposit)
            .unwrap_err()
            .contains("Ed25519"));
    }

    #[test]
    fn runtime_withdrawal_finalization_requires_operator_quorum_and_prevents_replay() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        runtime
            .observe_bridge_deposit(test_bridge_deposit('d', 'e'))
            .unwrap();
        let withdrawal_id = runtime
            .request_withdrawal(
                &test_account_id(),
                "9xTestnetMoneroAddressForNebulaWithdrawals",
                2_000,
                0,
                &test_withdrawal_signature("9xTestnetMoneroAddressForNebulaWithdrawals", 2_000, 0),
            )
            .unwrap()
            .withdrawal
            .withdrawal_id;
        let finalized_tx_id = "f".repeat(64);

        assert!(runtime
            .finalize_withdrawal(
                &withdrawal_id,
                &finalized_tx_id,
                &"1".repeat(64),
                vec!["operator-a".to_string()],
                vec!["2".repeat(64)],
                Vec::new(),
            )
            .unwrap_err()
            .contains("operator_approval_ids"));

        assert!(runtime
            .finalize_withdrawal(
                &withdrawal_id,
                &finalized_tx_id,
                &"1".repeat(64),
                vec!["operator-a".to_string(), "operator-a".to_string()],
                vec!["2".repeat(64), "3".repeat(64)],
                Vec::new(),
            )
            .unwrap_err()
            .contains("operator_approval_ids[1] duplicates"));

        assert!(runtime
            .finalize_withdrawal(
                &withdrawal_id,
                &finalized_tx_id,
                &"1".repeat(64),
                vec!["operator-a".to_string(), "operator-b".to_string()],
                vec!["2".repeat(64)],
                Vec::new(),
            )
            .unwrap_err()
            .contains("operator_approval_ids length"));

        let report = runtime
            .finalize_withdrawal(
                &withdrawal_id,
                &finalized_tx_id,
                &"1".repeat(64),
                vec!["operator-a".to_string(), "operator-b".to_string()],
                vec!["2".repeat(64), "3".repeat(64)],
                Vec::new(),
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
            .request_withdrawal(
                &test_account_id(),
                "9xTestnetMoneroAddressForNebulaWithdrawals",
                1_000,
                1,
                &test_withdrawal_signature("9xTestnetMoneroAddressForNebulaWithdrawals", 1_000, 1),
            )
            .unwrap()
            .withdrawal
            .withdrawal_id;
        assert!(runtime
            .finalize_withdrawal(
                &second_withdrawal_id,
                &finalized_tx_id,
                &"6".repeat(64),
                vec!["operator-c".to_string(), "operator-d".to_string()],
                vec!["7".repeat(64), "8".repeat(64)],
                Vec::new(),
            )
            .unwrap_err()
            .contains("already finalized"));
        assert!(runtime
            .finalize_withdrawal(
                &second_withdrawal_id,
                &"a".repeat(64),
                &"1".repeat(64),
                vec!["operator-c".to_string(), "operator-d".to_string()],
                vec!["7".repeat(64), "8".repeat(64)],
                Vec::new(),
            )
            .unwrap_err()
            .contains("already used"));

        let status = runtime.status();
        assert_eq!(status.finalized_withdrawal_count, 1);
        assert_eq!(status.bridge_replay_cache_count, 3);
    }

    #[test]
    fn launch_bound_withdrawal_finalization_requires_signed_attested_operators() {
        let mut runtime = NebulaRuntime::new(runtime_config_with_launch_binding()).unwrap();
        runtime
            .observe_bridge_deposit(signed_test_bridge_deposit('7', '8'))
            .unwrap();
        let withdrawal = runtime
            .request_withdrawal(
                &test_account_id(),
                "9xTestnetMoneroAddressForNebulaWithdrawals",
                2_000,
                0,
                &test_withdrawal_signature("9xTestnetMoneroAddressForNebulaWithdrawals", 2_000, 0),
            )
            .unwrap()
            .withdrawal;
        let finalized_tx_id = "f".repeat(64);
        let proof_root = "1".repeat(64);

        assert!(runtime
            .finalize_withdrawal(
                &withdrawal.withdrawal_id,
                &finalized_tx_id,
                &proof_root,
                vec!["operator-a".to_string(), "operator-b".to_string()],
                vec!["2".repeat(64), "3".repeat(64)],
                Vec::new(),
            )
            .unwrap_err()
            .contains("operator_approvals"));

        let (operator_ids, approval_roots, approvals) =
            test_operator_approval_quorum(&withdrawal, &finalized_tx_id, &proof_root);
        let report = runtime
            .finalize_withdrawal(
                &withdrawal.withdrawal_id,
                &finalized_tx_id,
                &proof_root,
                operator_ids,
                approval_roots,
                approvals,
            )
            .unwrap();
        assert!(report.finalized);
        assert_eq!(report.withdrawal.operator_approvals.len(), 2);
    }

    #[test]
    fn launch_bound_withdrawal_finalization_rejects_bad_operator_signature() {
        let mut runtime = NebulaRuntime::new(runtime_config_with_launch_binding()).unwrap();
        runtime
            .observe_bridge_deposit(signed_test_bridge_deposit('9', 'a'))
            .unwrap();
        let withdrawal = runtime
            .request_withdrawal(
                &test_account_id(),
                "9xTestnetMoneroAddressForNebulaWithdrawals",
                2_000,
                0,
                &test_withdrawal_signature("9xTestnetMoneroAddressForNebulaWithdrawals", 2_000, 0),
            )
            .unwrap()
            .withdrawal;
        let finalized_tx_id = "e".repeat(64);
        let proof_root = "b".repeat(64);
        let (operator_ids, mut approval_roots, mut approvals) =
            test_operator_approval_quorum(&withdrawal, &finalized_tx_id, &proof_root);
        approvals[0].signature = "0".repeat(128);
        approvals[0].approval_root = withdrawal_operator_approval_root(&approvals[0]);
        approval_roots[0] = approvals[0].approval_root.clone();

        assert!(runtime
            .finalize_withdrawal(
                &withdrawal.withdrawal_id,
                &finalized_tx_id,
                &proof_root,
                operator_ids,
                approval_roots,
                approvals,
            )
            .unwrap_err()
            .contains("Ed25519"));
    }

    #[test]
    fn snapshot_round_trips_pending_mempool_and_preserves_genesis() {
        let mut runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let genesis_hash = runtime.latest_block().block_hash;
        let account = test_account_id();
        runtime.faucet(&account).unwrap();
        runtime.produce_block();
        let faucet_commit_hash = runtime.latest_block().block_hash;
        let tx = sign_test_transaction(RuntimeTransaction {
            from: account,
            to: "bob".to_string(),
            amount_nebulai: 100,
            gas_units: 10,
            gas_price_nebulai: 1,
            fee_asset: NBLA_SYMBOL.to_string(),
            nonce: 0,
            signature: String::new(),
            memo: Some("pending before restart".to_string()),
        });
        let tx_id = runtime.submit_transaction(tx).unwrap().tx_id;
        let snapshot = runtime.export_snapshot();

        let mut config = RuntimeConfig::public_testnet_default();
        config.validator_id = "validator-after-restart".to_string();
        let mut restored = NebulaRuntime::from_snapshot(config, snapshot).unwrap();
        assert_ne!(restored.latest_block().block_hash, genesis_hash);
        assert_eq!(restored.latest_block().block_hash, faucet_commit_hash);
        assert_eq!(
            restored.receipt(&tx_id).unwrap().status,
            TransactionStatus::Pending
        );

        let block = restored.produce_block();
        assert_eq!(block.height, 2);
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
        runtime.produce_block();
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
            .request_withdrawal(
                &test_account_id(),
                "9xTestnetMoneroAddressForNebulaWithdrawals",
                2_000,
                0,
                &test_withdrawal_signature("9xTestnetMoneroAddressForNebulaWithdrawals", 2_000, 0),
            )
            .unwrap();
        runtime.produce_block();
        let snapshot = runtime.export_snapshot();
        let mut restored =
            NebulaRuntime::from_snapshot(RuntimeConfig::public_testnet_default(), snapshot)
                .unwrap();

        assert_eq!(
            restored.account(&test_account_id()).unwrap().nxmr_units,
            3_000
        );
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
    fn sync_peer_quorum_imports_matching_chain_state() {
        let local_runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let local_snapshot = local_runtime.export_snapshot();
        let mut peer_runtime =
            NebulaRuntime::from_snapshot(RuntimeConfig::public_testnet_default(), local_snapshot)
                .unwrap();
        peer_runtime.produce_block();
        let peer_snapshot = peer_runtime.export_snapshot();
        let body = serde_json::to_string(&peer_snapshot).unwrap();
        let (first_url, first_handle) = one_shot_http_response(body.clone(), "HTTP/1.1 200 OK");
        let (second_url, second_handle) = one_shot_http_response(body, "HTTP/1.1 200 OK");
        let mut state = test_rpc_state_with_limits(
            local_runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.sync_peers = RuntimeSyncPeerSet {
            bootstrap_peer_urls: Vec::new(),
            sync_peer_urls: vec![first_url.clone(), second_url.clone()],
            sync_peer_quorum: 2,
        };

        let imported =
            sync_runtime_from_peers(&state, &[first_url.clone(), second_url.clone()]).unwrap();
        first_handle.join().unwrap();
        second_handle.join().unwrap();

        assert!(imported);
        let status = state.status_json().unwrap();
        assert_eq!(status["latest_height"], peer_snapshot.latest_height());
        assert_eq!(status["sync_peer_quorum"], 2);
        assert_eq!(status["sync_quorum_met"], true);
        assert_eq!(status["sync_quorum_peer_count"], 2);
        assert_eq!(status["sync_quorum_height"], peer_snapshot.latest_height());
        assert_eq!(
            status["sync_quorum_latest_hash"],
            peer_snapshot.latest_block_hash().unwrap()
        );
        assert_eq!(status["sync_quorum_state_root"], peer_snapshot.state_root);
        assert_eq!(status["sync_quorum_rejection_count"], 0);
        assert_eq!(status["sync_import_count"], 1);
    }

    #[test]
    fn sync_peer_quorum_rejects_divergent_chain_state() {
        let local_runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let local_snapshot = local_runtime.export_snapshot();
        let mut first_peer = NebulaRuntime::from_snapshot(
            RuntimeConfig::public_testnet_default(),
            local_snapshot.clone(),
        )
        .unwrap();
        first_peer.faucet("alice").unwrap();
        first_peer.produce_block();
        let first_snapshot = first_peer.export_snapshot();
        let mut second_peer =
            NebulaRuntime::from_snapshot(RuntimeConfig::public_testnet_default(), local_snapshot)
                .unwrap();
        second_peer.faucet("bob").unwrap();
        second_peer.produce_block();
        let second_snapshot = second_peer.export_snapshot();
        assert_ne!(
            first_snapshot.latest_block_hash(),
            second_snapshot.latest_block_hash()
        );
        let local_height = local_runtime.status().latest_height;
        let (first_url, first_handle) = one_shot_http_response(
            serde_json::to_string(&first_snapshot).unwrap(),
            "HTTP/1.1 200 OK",
        );
        let (second_url, second_handle) = one_shot_http_response(
            serde_json::to_string(&second_snapshot).unwrap(),
            "HTTP/1.1 200 OK",
        );
        let mut state = test_rpc_state_with_limits(
            local_runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.sync_peers = RuntimeSyncPeerSet {
            bootstrap_peer_urls: Vec::new(),
            sync_peer_urls: vec![first_url.clone(), second_url.clone()],
            sync_peer_quorum: 2,
        };

        let imported =
            sync_runtime_from_peers(&state, &[first_url.clone(), second_url.clone()]).unwrap();
        first_handle.join().unwrap();
        second_handle.join().unwrap();

        assert!(!imported);
        let status = state.status_json().unwrap();
        assert_eq!(status["latest_height"], local_height);
        assert_eq!(status["sync_successful_peer_count"], 2);
        assert_eq!(status["sync_quorum_met"], false);
        assert_eq!(status["sync_quorum_peer_count"], 1);
        assert_eq!(status["sync_quorum_rejection_count"], 2);
        assert_eq!(status["sync_import_count"], 0);
        let peers = status["sync_peer_telemetry"].as_array().unwrap();
        assert_eq!(peers[0]["quorum_rejection_count"], 1);
        assert_eq!(peers[1]["quorum_rejection_count"], 1);
    }

    #[test]
    fn runtime_sync_peer_telemetry_records_attempt_success_error_and_import() {
        let local_runtime = NebulaRuntime::new(RuntimeConfig::public_testnet_default()).unwrap();
        let local_snapshot = local_runtime.export_snapshot();
        let mut peer_runtime =
            NebulaRuntime::from_snapshot(RuntimeConfig::public_testnet_default(), local_snapshot)
                .unwrap();
        peer_runtime.produce_block();
        let peer_snapshot = peer_runtime.export_snapshot();
        let (good_url, good_handle) = one_shot_http_response(
            serde_json::to_string(&peer_snapshot).unwrap(),
            "HTTP/1.1 200 OK",
        );
        let (bad_url, bad_handle) = one_shot_http_response(
            "{\"error\":\"not available\"}".to_string(),
            "HTTP/1.1 500 Internal Server Error",
        );
        let mut state = test_rpc_state_with_limits(
            local_runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.sync_peers = RuntimeSyncPeerSet {
            bootstrap_peer_urls: Vec::new(),
            sync_peer_urls: vec![good_url.clone(), bad_url.clone()],
            sync_peer_quorum: DEFAULT_SYNC_PEER_QUORUM,
        };

        let imported =
            sync_runtime_from_peers(&state, &[good_url.clone(), bad_url.clone()]).unwrap();
        good_handle.join().unwrap();
        bad_handle.join().unwrap();

        assert!(imported);
        let status = state.status_json().unwrap();
        assert_eq!(status["latest_height"], 1);
        assert_eq!(status["sync_peer_count"], 2);
        assert_eq!(status["sync_successful_peer_count"], 1);
        assert_eq!(status["sync_failed_peer_count"], 1);
        assert_eq!(status["sync_attempt_count"], 2);
        assert_eq!(status["sync_success_count"], 1);
        assert_eq!(status["sync_failure_count"], 1);
        assert_eq!(status["sync_import_count"], 1);
        assert_eq!(status["sync_last_import_height"], 1);
        let peers = status["sync_peer_telemetry"].as_array().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0]["url"], good_url);
        assert_eq!(peers[0]["attempt_count"], 1);
        assert_eq!(peers[0]["success_count"], 1);
        assert_eq!(peers[0]["failure_count"], 0);
        assert_eq!(peers[0]["import_count"], 1);
        assert_eq!(peers[0]["last_import_height"], 1);
        assert_ne!(peers[0]["last_success_unix_ms"], Value::Null);
        assert_eq!(peers[0]["last_error"], Value::Null);
        assert_eq!(peers[0]["last_error_unix_ms"], Value::Null);
        assert_eq!(peers[1]["url"], bad_url);
        assert_eq!(peers[1]["attempt_count"], 1);
        assert_eq!(peers[1]["success_count"], 0);
        assert_eq!(peers[1]["failure_count"], 1);
        assert_ne!(peers[1]["last_error_unix_ms"], Value::Null);
        assert!(peers[1]["last_error"]
            .as_str()
            .unwrap()
            .contains("500 Internal Server Error"));
    }

    #[test]
    fn follower_mode_does_not_produce_blocks_or_accept_mutations() {
        let mut config = RuntimeConfig::public_testnet_default();
        config.produce_blocks = false;
        let runtime = NebulaRuntime::new(config).unwrap();
        let mut state = test_rpc_state_with_limits(
            runtime,
            DEFAULT_MAX_REQUEST_BYTES,
            DEFAULT_MAX_REQUESTS_PER_MINUTE,
        );
        state.admin_token = Some("admin".to_string());

        assert!(
            dispatch_json_rpc_method(&state, "nebula_faucet", json!({"account": "alice"}))
                .unwrap_err()
                .contains("follower mode")
        );
        assert!(dispatch_json_rpc_method(
            &state,
            "nebula_produceBlock",
            json!({"admin_token": "admin"})
        )
        .unwrap_err()
        .contains("follower mode"));
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
        assert!(follower.account("validator:follower-a").is_none());
        assert_eq!(
            follower.account("alice").unwrap().nbla_nebulai,
            DEFAULT_FAUCET_NBLA
        );
        validate_snapshot(&follower.export_snapshot()).unwrap();
    }

    #[test]
    fn runtime_rejects_blocks_at_or_above_one_second() {
        let mut config = RuntimeConfig::public_testnet_default();
        config.block_target_ms = 1_000;
        assert!(NebulaRuntime::new(config).is_err());
    }
}
