use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ContractRuntimeHostResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_PROTOCOL_VERSION: &str =
    "nebula-private-l2-contract-runtime-host-v1";
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_PROOF_SYSTEM: &str =
    "recursive-private-contract-runtime-v1";
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_STATE_COMMITMENT_SCHEME: &str =
    "shake256-canonical-json-private-state-access-v1";
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_CODE_COMMITMENT_SCHEME: &str =
    "shake256-wasm-code-commitment-v1";
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_ABI_COMMITMENT_SCHEME: &str =
    "shake256-abi-selector-root-v1";
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MAX_CALL_GAS: u64 = 4_000_000;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MAX_BLOCK_GAS: u64 = 24_000_000;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MAX_FEE_BPS: u64 = 35;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MIN_PRIVACY_SET: u64 = 256;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MAX_LATENCY_MS: u64 = 500;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_CHECKPOINT_INTERVAL: u64 = 8;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_CONTRACTS: usize = 16_384;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_SELECTORS_PER_CONTRACT: usize = 512;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_CALLS: usize = 65_536;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_CHECKPOINTS: usize = 16_384;
pub const PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractKind {
    Account,
    Token,
    Paymaster,
    PrivateAmm,
    PrivateDex,
    LendingMarket,
    IntentRouter,
    MoneroBridgeAdapter,
    ProofAggregator,
    Custom,
}

impl ContractKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Token => "token",
            Self::Paymaster => "paymaster",
            Self::PrivateAmm => "private_amm",
            Self::PrivateDex => "private_dex",
            Self::LendingMarket => "lending_market",
            Self::IntentRouter => "intent_router",
            Self::MoneroBridgeAdapter => "monero_bridge_adapter",
            Self::ProofAggregator => "proof_aggregator",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Pending,
    Active,
    Paused,
    Retired,
}

impl ContractStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn callable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorAccess {
    PublicProof,
    PrivateCall,
    PrivateDelegateCall,
    ViewOnly,
    AdminOnly,
}

impl SelectorAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicProof => "public_proof",
            Self::PrivateCall => "private_call",
            Self::PrivateDelegateCall => "private_delegate_call",
            Self::ViewOnly => "view_only",
            Self::AdminOnly => "admin_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLaneKind {
    Standard,
    LowLatency,
    LowFeeBatch,
    ProofPrefetch,
    MoneroExit,
}

impl ExecutionLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::LowLatency => "low_latency",
            Self::LowFeeBatch => "low_fee_batch",
            Self::ProofPrefetch => "proof_prefetch",
            Self::MoneroExit => "monero_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateAccessMode {
    Read,
    Write,
    ReadWrite,
    NullifierConsume,
    ReceiptAppend,
    ProveOnly,
}

impl StateAccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
            Self::NullifierConsume => "nullifier_consume",
            Self::ReceiptAppend => "receipt_append",
            Self::ProveOnly => "prove_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    Accepted,
    Executed,
    Reverted,
    Rejected,
}

impl CallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Executed => "executed",
            Self::Reverted => "reverted",
            Self::Rejected => "rejected",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Executed | Self::Reverted | Self::Rejected)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub proof_system: String,
    pub code_commitment_scheme: String,
    pub abi_commitment_scheme: String,
    pub state_commitment_scheme: String,
    pub max_call_gas: u64,
    pub max_block_gas: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
    pub max_low_latency_ms: u64,
    pub checkpoint_interval_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONTRACT_RUNTIME_HOST_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            pq_signature_scheme: PRIVATE_L2_CONTRACT_RUNTIME_HOST_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_L2_CONTRACT_RUNTIME_HOST_PQ_KEM_SCHEME.to_string(),
            proof_system: PRIVATE_L2_CONTRACT_RUNTIME_HOST_PROOF_SYSTEM.to_string(),
            code_commitment_scheme: PRIVATE_L2_CONTRACT_RUNTIME_HOST_CODE_COMMITMENT_SCHEME
                .to_string(),
            abi_commitment_scheme: PRIVATE_L2_CONTRACT_RUNTIME_HOST_ABI_COMMITMENT_SCHEME
                .to_string(),
            state_commitment_scheme: PRIVATE_L2_CONTRACT_RUNTIME_HOST_STATE_COMMITMENT_SCHEME
                .to_string(),
            max_call_gas: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MAX_CALL_GAS,
            max_block_gas: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MAX_BLOCK_GAS,
            max_fee_bps: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MAX_FEE_BPS,
            min_privacy_set: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_low_latency_ms: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_MAX_LATENCY_MS,
            checkpoint_interval_blocks:
                PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEFAULT_CHECKPOINT_INTERVAL,
        }
    }

    pub fn validate(&self) -> PrivateL2ContractRuntimeHostResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.pq_signature_scheme.is_empty()
            || self.pq_kem_scheme.is_empty()
            || self.proof_system.is_empty()
            || self.code_commitment_scheme.is_empty()
            || self.abi_commitment_scheme.is_empty()
            || self.state_commitment_scheme.is_empty()
        {
            return Err("private l2 contract runtime host labels cannot be empty".to_string());
        }
        if self.max_call_gas == 0
            || self.max_block_gas == 0
            || self.min_privacy_set == 0
            || self.min_pq_security_bits == 0
            || self.max_low_latency_ms == 0
            || self.checkpoint_interval_blocks == 0
        {
            return Err("private l2 contract runtime host thresholds must be positive".to_string());
        }
        if self.max_call_gas > self.max_block_gas {
            return Err("private l2 contract runtime call gas cannot exceed block gas".to_string());
        }
        if self.max_fee_bps > PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_BPS {
            return Err("private l2 contract runtime fee cap cannot exceed 100%".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_contract_runtime_host_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "proof_system": self.proof_system,
            "code_commitment_scheme": self.code_commitment_scheme,
            "abi_commitment_scheme": self.abi_commitment_scheme,
            "state_commitment_scheme": self.state_commitment_scheme,
            "max_call_gas": self.max_call_gas,
            "max_block_gas": self.max_block_gas,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_low_latency_ms": self.max_low_latency_ms,
            "checkpoint_interval_blocks": self.checkpoint_interval_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub contract_count: u64,
    pub selector_count: u64,
    pub call_count: u64,
    pub executed_count: u64,
    pub reverted_count: u64,
    pub rejected_count: u64,
    pub checkpoint_count: u64,
    pub total_gas_committed: u64,
    pub total_fee_cap_units: u64,
    pub low_latency_call_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_contract_runtime_host_counters",
            "contract_count": self.contract_count,
            "selector_count": self.selector_count,
            "call_count": self.call_count,
            "executed_count": self.executed_count,
            "reverted_count": self.reverted_count,
            "rejected_count": self.rejected_count,
            "checkpoint_count": self.checkpoint_count,
            "total_gas_committed": self.total_gas_committed,
            "total_fee_cap_units": self.total_fee_cap_units,
            "low_latency_call_count": self.low_latency_call_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorManifest {
    pub selector: String,
    pub method_root: String,
    pub access: SelectorAccess,
    pub required_state_access_root: String,
    pub max_gas: u64,
    pub payable: bool,
}

impl SelectorManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_contract_selector_manifest",
            "selector": self.selector,
            "method_root": self.method_root,
            "access": self.access.as_str(),
            "required_state_access_root": self.required_state_access_root,
            "max_gas": self.max_gas,
            "payable": self.payable,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRegistration {
    pub contract_id: String,
    pub kind: ContractKind,
    pub status: ContractStatus,
    pub admin_commitment: String,
    pub code_commitment: String,
    pub code_metadata_root: String,
    pub abi_root: String,
    pub selector_root: String,
    pub initial_state_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub registered_at_height: u64,
    pub selector_count: u64,
    pub max_call_gas: u64,
    pub max_fee_bps: u64,
}

impl ContractRegistration {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_contract_registration",
            "contract_id": self.contract_id,
            "contract_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "admin_commitment": self.admin_commitment,
            "code_commitment": self.code_commitment,
            "code_metadata_root": self.code_metadata_root,
            "abi_root": self.abi_root,
            "selector_root": self.selector_root,
            "initial_state_root": self.initial_state_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "registered_at_height": self.registered_at_height,
            "selector_count": self.selector_count,
            "max_call_gas": self.max_call_gas,
            "max_fee_bps": self.max_fee_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateAccessCommitment {
    pub access_id: String,
    pub contract_id: String,
    pub mode: StateAccessMode,
    pub state_path_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
}

impl StateAccessCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_contract_state_access_commitment",
            "access_id": self.access_id,
            "contract_id": self.contract_id,
            "mode": self.mode.as_str(),
            "state_path_root": self.state_path_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "nullifier_root": self.nullifier_root,
            "witness_root": self.witness_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallEnvelope {
    pub call_id: String,
    pub contract_id: String,
    pub selector: String,
    pub lane: ExecutionLaneKind,
    pub caller_commitment: String,
    pub private_calldata_root: String,
    pub private_return_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub state_access_root: String,
    pub fee_asset_id: String,
    pub gas_limit: u64,
    pub fee_cap_units: u64,
    pub fee_cap_bps: u64,
    pub submitted_at_height: u64,
    pub deadline_height: u64,
}

impl CallEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_contract_call_envelope",
            "call_id": self.call_id,
            "contract_id": self.contract_id,
            "selector": self.selector,
            "lane": self.lane.as_str(),
            "caller_commitment": self.caller_commitment,
            "private_calldata_root": self.private_calldata_root,
            "private_return_root": self.private_return_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "state_access_root": self.state_access_root,
            "fee_asset_id": self.fee_asset_id,
            "gas_limit": self.gas_limit,
            "fee_cap_units": self.fee_cap_units,
            "fee_cap_bps": self.fee_cap_bps,
            "submitted_at_height": self.submitted_at_height,
            "deadline_height": self.deadline_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub call_id: String,
    pub contract_id: String,
    pub selector: String,
    pub status: CallStatus,
    pub lane: ExecutionLaneKind,
    pub gas_used: u64,
    pub fee_charged_units: u64,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub event_root: String,
    pub return_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub state_access_root: String,
    pub executed_at_height: u64,
    pub sequencer_commitment: String,
}

impl ExecutionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_contract_execution_receipt",
            "receipt_id": self.receipt_id,
            "call_id": self.call_id,
            "contract_id": self.contract_id,
            "selector": self.selector,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "gas_used": self.gas_used,
            "fee_charged_units": self.fee_charged_units,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "event_root": self.event_root,
            "return_root": self.return_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "state_access_root": self.state_access_root,
            "executed_at_height": self.executed_at_height,
            "sequencer_commitment": self.sequencer_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCheckpoint {
    pub checkpoint_id: String,
    pub height: u64,
    pub sequence: u64,
    pub contract_root: String,
    pub selector_root: String,
    pub call_root: String,
    pub receipt_root: String,
    pub state_access_root: String,
    pub lane_root: String,
    pub previous_checkpoint_root: String,
    pub state_root: String,
    pub operator_commitment: String,
}

impl HostCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_contract_runtime_host_checkpoint",
            "checkpoint_id": self.checkpoint_id,
            "height": self.height,
            "sequence": self.sequence,
            "contract_root": self.contract_root,
            "selector_root": self.selector_root,
            "call_root": self.call_root,
            "receipt_root": self.receipt_root,
            "state_access_root": self.state_access_root,
            "lane_root": self.lane_root,
            "previous_checkpoint_root": self.previous_checkpoint_root,
            "state_root": self.state_root,
            "operator_commitment": self.operator_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterContractInput {
    pub kind: ContractKind,
    pub admin_commitment: String,
    pub code_commitment: String,
    pub code_metadata_root: String,
    pub abi_root: String,
    pub selectors: Vec<SelectorManifest>,
    pub initial_state_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub registered_at_height: u64,
    pub max_call_gas: u64,
    pub max_fee_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchCallInput {
    pub contract_id: String,
    pub selector: String,
    pub lane: ExecutionLaneKind,
    pub caller_commitment: String,
    pub private_calldata_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub state_accesses: Vec<StateAccessCommitment>,
    pub fee_asset_id: String,
    pub gas_limit: u64,
    pub fee_cap_units: u64,
    pub fee_cap_bps: u64,
    pub submitted_at_height: u64,
    pub deadline_height: u64,
    pub sequencer_commitment: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub event_root: String,
    pub return_root: String,
    pub gas_used: u64,
    pub fee_charged_units: u64,
    pub force_status: Option<CallStatus>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitCheckpointInput {
    pub height: u64,
    pub operator_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub contract_root: String,
    pub selector_root: String,
    pub call_root: String,
    pub receipt_root: String,
    pub state_access_root: String,
    pub lane_root: String,
    pub checkpoint_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_contract_runtime_host_roots",
            "contract_root": self.contract_root,
            "selector_root": self.selector_root,
            "call_root": self.call_root,
            "receipt_root": self.receipt_root,
            "state_access_root": self.state_access_root,
            "lane_root": self.lane_root,
            "checkpoint_root": self.checkpoint_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub contracts: BTreeMap<String, ContractRegistration>,
    pub selectors: BTreeMap<String, BTreeMap<String, SelectorManifest>>,
    pub calls: BTreeMap<String, CallEnvelope>,
    pub receipts: BTreeMap<String, ExecutionReceipt>,
    pub state_accesses: BTreeMap<String, StateAccessCommitment>,
    pub lane_calls: BTreeMap<ExecutionLaneKind, BTreeSet<String>>,
    pub checkpoints: BTreeMap<String, HostCheckpoint>,
    pub latest_checkpoint_root: String,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            contracts: BTreeMap::new(),
            selectors: BTreeMap::new(),
            calls: BTreeMap::new(),
            receipts: BTreeMap::new(),
            state_accesses: BTreeMap::new(),
            lane_calls: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            latest_checkpoint_root: merkle_root("PRIVATE-L2-CONTRACT-RUNTIME-HOST-CHECKPOINT", &[]),
        }
    }

    pub fn register_contract(
        &mut self,
        input: RegisterContractInput,
    ) -> PrivateL2ContractRuntimeHostResult<ContractRegistration> {
        self.config.validate()?;
        validate_root("admin commitment", &input.admin_commitment)?;
        validate_root("code commitment", &input.code_commitment)?;
        validate_root("code metadata root", &input.code_metadata_root)?;
        validate_root("abi root", &input.abi_root)?;
        validate_root("initial state root", &input.initial_state_root)?;
        validate_root("pq authority root", &input.pq_authority_root)?;
        validate_root("privacy policy root", &input.privacy_policy_root)?;
        if input.selectors.is_empty() {
            return Err("private l2 contract registration requires selectors".to_string());
        }
        if input.selectors.len() > PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_SELECTORS_PER_CONTRACT {
            return Err("private l2 contract registration has too many selectors".to_string());
        }
        if self.contracts.len() >= PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_CONTRACTS {
            return Err("private l2 contract runtime host contract limit reached".to_string());
        }
        if input.max_call_gas == 0 || input.max_call_gas > self.config.max_call_gas {
            return Err("private l2 contract registration max call gas is invalid".to_string());
        }
        if input.max_fee_bps > self.config.max_fee_bps {
            return Err("private l2 contract registration fee bps exceeds host cap".to_string());
        }

        let mut selector_map = BTreeMap::new();
        for selector in input.selectors {
            validate_selector(&selector)?;
            if selector.max_gas > input.max_call_gas {
                return Err("private l2 contract selector gas exceeds contract cap".to_string());
            }
            if selector_map
                .insert(selector.selector.clone(), selector)
                .is_some()
            {
                return Err("private l2 contract selector duplicated".to_string());
            }
        }

        let selector_records = selector_map
            .values()
            .map(SelectorManifest::public_record)
            .collect::<Vec<_>>();
        let selector_root = merkle_root(
            "PRIVATE-L2-CONTRACT-RUNTIME-HOST-SELECTOR-MANIFEST",
            &selector_records,
        );
        let selector_count = selector_map.len() as u64;
        let contract_id = contract_id(
            input.kind,
            &input.admin_commitment,
            &input.code_commitment,
            &input.abi_root,
            &selector_root,
            input.registered_at_height,
            self.counters.contract_count + 1,
        );
        if self.contracts.contains_key(&contract_id) {
            return Err("private l2 contract registration id already exists".to_string());
        }

        let registration = ContractRegistration {
            contract_id: contract_id.clone(),
            kind: input.kind,
            status: ContractStatus::Active,
            admin_commitment: input.admin_commitment,
            code_commitment: input.code_commitment,
            code_metadata_root: input.code_metadata_root,
            abi_root: input.abi_root,
            selector_root,
            initial_state_root: input.initial_state_root,
            pq_authority_root: input.pq_authority_root,
            privacy_policy_root: input.privacy_policy_root,
            registered_at_height: input.registered_at_height,
            selector_count,
            max_call_gas: input.max_call_gas,
            max_fee_bps: input.max_fee_bps,
        };

        self.counters.contract_count += 1;
        self.counters.selector_count += selector_count;
        self.selectors.insert(contract_id.clone(), selector_map);
        self.contracts.insert(contract_id, registration.clone());
        Ok(registration)
    }

    pub fn dispatch_call(
        &mut self,
        input: DispatchCallInput,
    ) -> PrivateL2ContractRuntimeHostResult<ExecutionReceipt> {
        self.config.validate()?;
        if self.calls.len() >= PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_CALLS {
            return Err("private l2 contract runtime host call limit reached".to_string());
        }
        validate_root("caller commitment", &input.caller_commitment)?;
        validate_root("private calldata root", &input.private_calldata_root)?;
        validate_root("pq authorization root", &input.pq_authorization_root)?;
        validate_root("privacy proof root", &input.privacy_proof_root)?;
        validate_root("sequencer commitment", &input.sequencer_commitment)?;
        validate_root("pre state root", &input.pre_state_root)?;
        validate_root("post state root", &input.post_state_root)?;
        validate_root("event root", &input.event_root)?;
        validate_root("return root", &input.return_root)?;
        if input.fee_asset_id.is_empty() {
            return Err("private l2 contract call fee asset cannot be empty".to_string());
        }
        if input.gas_limit == 0 || input.gas_limit > self.config.max_call_gas {
            return Err("private l2 contract call gas limit is invalid".to_string());
        }
        if input.gas_used > input.gas_limit {
            return Err("private l2 contract call gas used exceeds limit".to_string());
        }
        if input.fee_charged_units > input.fee_cap_units {
            return Err("private l2 contract call fee charged exceeds cap".to_string());
        }
        if input.fee_cap_bps > self.config.max_fee_bps {
            return Err("private l2 contract call fee bps exceeds host cap".to_string());
        }
        if input.deadline_height < input.submitted_at_height {
            return Err("private l2 contract call deadline precedes submission".to_string());
        }

        let contract = self
            .contracts
            .get(&input.contract_id)
            .ok_or_else(|| "private l2 contract call targets unknown contract".to_string())?;
        if !contract.status.callable() {
            return Err("private l2 contract call targets non-callable contract".to_string());
        }
        if input.gas_limit > contract.max_call_gas {
            return Err("private l2 contract call gas exceeds contract cap".to_string());
        }
        if input.fee_cap_bps > contract.max_fee_bps {
            return Err("private l2 contract call fee bps exceeds contract cap".to_string());
        }
        let selector = self
            .selectors
            .get(&input.contract_id)
            .and_then(|selectors| selectors.get(&input.selector))
            .ok_or_else(|| "private l2 contract call selector is not registered".to_string())?;
        if input.gas_limit > selector.max_gas {
            return Err("private l2 contract call gas exceeds selector cap".to_string());
        }

        for access in &input.state_accesses {
            validate_state_access(&input.contract_id, access)?;
        }
        let state_access_records = input
            .state_accesses
            .iter()
            .map(StateAccessCommitment::public_record)
            .collect::<Vec<_>>();
        let state_access_root = merkle_root(
            "PRIVATE-L2-CONTRACT-RUNTIME-HOST-STATE-ACCESS",
            &state_access_records,
        );
        let private_return_root = if input.force_status == Some(CallStatus::Rejected) {
            empty_root("PRIVATE-L2-CONTRACT-RUNTIME-HOST-PRIVATE-RETURN")
        } else {
            input.return_root.clone()
        };
        let call_id = call_id(
            &input.contract_id,
            &input.selector,
            input.lane,
            &input.caller_commitment,
            &input.private_calldata_root,
            &input.pq_authorization_root,
            self.counters.call_count + 1,
        );
        if self.calls.contains_key(&call_id) {
            return Err("private l2 contract call id already exists".to_string());
        }

        let envelope = CallEnvelope {
            call_id: call_id.clone(),
            contract_id: input.contract_id.clone(),
            selector: input.selector.clone(),
            lane: input.lane,
            caller_commitment: input.caller_commitment,
            private_calldata_root: input.private_calldata_root,
            private_return_root: private_return_root.clone(),
            pq_authorization_root: input.pq_authorization_root.clone(),
            privacy_proof_root: input.privacy_proof_root.clone(),
            state_access_root: state_access_root.clone(),
            fee_asset_id: input.fee_asset_id,
            gas_limit: input.gas_limit,
            fee_cap_units: input.fee_cap_units,
            fee_cap_bps: input.fee_cap_bps,
            submitted_at_height: input.submitted_at_height,
            deadline_height: input.deadline_height,
        };

        let status = input.force_status.unwrap_or(CallStatus::Executed);
        let receipt_id = receipt_id(
            &call_id,
            &input.contract_id,
            &input.selector,
            status,
            &input.post_state_root,
            self.counters.call_count + 1,
        );
        let receipt = ExecutionReceipt {
            receipt_id,
            call_id: call_id.clone(),
            contract_id: input.contract_id.clone(),
            selector: input.selector,
            status,
            lane: input.lane,
            gas_used: input.gas_used,
            fee_charged_units: input.fee_charged_units,
            pre_state_root: input.pre_state_root,
            post_state_root: input.post_state_root,
            event_root: input.event_root,
            return_root: private_return_root,
            privacy_proof_root: input.privacy_proof_root,
            pq_authorization_root: input.pq_authorization_root,
            state_access_root: state_access_root.clone(),
            executed_at_height: input.submitted_at_height,
            sequencer_commitment: input.sequencer_commitment,
        };

        for access in input.state_accesses {
            self.state_accesses.insert(access.access_id.clone(), access);
        }
        self.calls.insert(call_id.clone(), envelope);
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.lane_calls
            .entry(input.lane)
            .or_default()
            .insert(call_id);
        self.counters.call_count += 1;
        self.counters.total_gas_committed += input.gas_limit;
        self.counters.total_fee_cap_units += input.fee_cap_units;
        if input.lane == ExecutionLaneKind::LowLatency {
            self.counters.low_latency_call_count += 1;
        }
        match status {
            CallStatus::Executed | CallStatus::Accepted => self.counters.executed_count += 1,
            CallStatus::Reverted => self.counters.reverted_count += 1,
            CallStatus::Rejected => self.counters.rejected_count += 1,
        }
        Ok(receipt)
    }

    pub fn commit_checkpoint(
        &mut self,
        input: CommitCheckpointInput,
    ) -> PrivateL2ContractRuntimeHostResult<HostCheckpoint> {
        self.config.validate()?;
        validate_root("operator commitment", &input.operator_commitment)?;
        if self.checkpoints.len() >= PRIVATE_L2_CONTRACT_RUNTIME_HOST_MAX_CHECKPOINTS {
            return Err("private l2 contract runtime host checkpoint limit reached".to_string());
        }
        let roots = self.roots();
        let sequence = self.counters.checkpoint_count + 1;
        let checkpoint_id = checkpoint_id(
            input.height,
            sequence,
            &roots.contract_root,
            &roots.receipt_root,
            &self.latest_checkpoint_root,
        );
        let state_root = domain_hash(
            "PRIVATE-L2-CONTRACT-RUNTIME-HOST-CHECKPOINT-STATE",
            &[
                HashPart::Str(&self.config.protocol_version),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&roots.contract_root),
                HashPart::Str(&roots.selector_root),
                HashPart::Str(&roots.call_root),
                HashPart::Str(&roots.receipt_root),
                HashPart::Str(&roots.state_access_root),
                HashPart::Str(&roots.lane_root),
                HashPart::Str(&self.latest_checkpoint_root),
                HashPart::Int(input.height as i128),
                HashPart::Int(sequence as i128),
            ],
            32,
        );
        let checkpoint = HostCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            height: input.height,
            sequence,
            contract_root: roots.contract_root,
            selector_root: roots.selector_root,
            call_root: roots.call_root,
            receipt_root: roots.receipt_root,
            state_access_root: roots.state_access_root,
            lane_root: roots.lane_root,
            previous_checkpoint_root: self.latest_checkpoint_root.clone(),
            state_root,
            operator_commitment: input.operator_commitment,
        };
        let checkpoint_root = payload_root(
            "PRIVATE-L2-CONTRACT-RUNTIME-HOST-CHECKPOINT-PAYLOAD",
            &checkpoint.public_record(),
        );
        self.latest_checkpoint_root = checkpoint_root;
        self.counters.checkpoint_count += 1;
        self.checkpoints.insert(checkpoint_id, checkpoint.clone());
        Ok(checkpoint)
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_contract_runtime_host_state",
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "state_root": self.state_root(),
            "latest_checkpoint_root": self.latest_checkpoint_root,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-CONTRACT-RUNTIME-HOST-STATE",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "roots": self.roots().public_record(),
                "latest_checkpoint_root": self.latest_checkpoint_root,
            }),
        )
    }

    fn roots(&self) -> Roots {
        let contract_records = self
            .contracts
            .values()
            .map(ContractRegistration::public_record)
            .collect::<Vec<_>>();
        let selector_records = self
            .selectors
            .iter()
            .flat_map(|(contract_id, selectors)| {
                selectors.values().map(move |selector| {
                    json!({
                        "contract_id": contract_id,
                        "selector": selector.public_record(),
                    })
                })
            })
            .collect::<Vec<_>>();
        let call_records = self
            .calls
            .values()
            .map(CallEnvelope::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(ExecutionReceipt::public_record)
            .collect::<Vec<_>>();
        let state_access_records = self
            .state_accesses
            .values()
            .map(StateAccessCommitment::public_record)
            .collect::<Vec<_>>();
        let lane_records = self
            .lane_calls
            .iter()
            .map(|(lane, calls)| {
                json!({
                    "lane": lane.as_str(),
                    "call_root": merkle_root(
                        "PRIVATE-L2-CONTRACT-RUNTIME-HOST-LANE-CALL",
                        &calls.iter().map(|call_id| json!(call_id)).collect::<Vec<_>>()
                    ),
                    "call_count": calls.len(),
                })
            })
            .collect::<Vec<_>>();
        let checkpoint_records = self
            .checkpoints
            .values()
            .map(HostCheckpoint::public_record)
            .collect::<Vec<_>>();

        Roots {
            contract_root: merkle_root(
                "PRIVATE-L2-CONTRACT-RUNTIME-HOST-CONTRACT",
                &contract_records,
            ),
            selector_root: merkle_root(
                "PRIVATE-L2-CONTRACT-RUNTIME-HOST-SELECTOR",
                &selector_records,
            ),
            call_root: merkle_root("PRIVATE-L2-CONTRACT-RUNTIME-HOST-CALL", &call_records),
            receipt_root: merkle_root("PRIVATE-L2-CONTRACT-RUNTIME-HOST-RECEIPT", &receipt_records),
            state_access_root: merkle_root(
                "PRIVATE-L2-CONTRACT-RUNTIME-HOST-STATE-ACCESS-BOOK",
                &state_access_records,
            ),
            lane_root: merkle_root("PRIVATE-L2-CONTRACT-RUNTIME-HOST-LANE", &lane_records),
            checkpoint_root: merkle_root(
                "PRIVATE-L2-CONTRACT-RUNTIME-HOST-CHECKPOINT",
                &checkpoint_records,
            ),
        }
    }
}

fn validate_selector(selector: &SelectorManifest) -> PrivateL2ContractRuntimeHostResult<()> {
    if selector.selector.is_empty() || selector.selector.len() > 16 {
        return Err("private l2 contract selector must be compact and non-empty".to_string());
    }
    validate_root("selector method root", &selector.method_root)?;
    validate_root(
        "selector required state access root",
        &selector.required_state_access_root,
    )?;
    if selector.max_gas == 0 {
        return Err("private l2 contract selector gas must be positive".to_string());
    }
    Ok(())
}

fn validate_state_access(
    contract_id: &str,
    access: &StateAccessCommitment,
) -> PrivateL2ContractRuntimeHostResult<()> {
    if access.access_id.is_empty() {
        return Err("private l2 contract state access id cannot be empty".to_string());
    }
    if access.contract_id != contract_id {
        return Err("private l2 contract state access contract mismatch".to_string());
    }
    validate_root("state path root", &access.state_path_root)?;
    validate_root("pre state root", &access.pre_state_root)?;
    validate_root("post state root", &access.post_state_root)?;
    validate_root("nullifier root", &access.nullifier_root)?;
    validate_root("witness root", &access.witness_root)?;
    Ok(())
}

fn validate_root(label: &str, value: &str) -> PrivateL2ContractRuntimeHostResult<()> {
    if value.is_empty() {
        return Err(format!(
            "private l2 contract runtime {label} cannot be empty"
        ));
    }
    Ok(())
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONTRACT_RUNTIME_HOST_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn contract_id(
    kind: ContractKind,
    admin_commitment: &str,
    code_commitment: &str,
    abi_root: &str,
    selector_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RUNTIME-HOST-CONTRACT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(admin_commitment),
            HashPart::Str(code_commitment),
            HashPart::Str(abi_root),
            HashPart::Str(selector_root),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn call_id(
    contract_id: &str,
    selector: &str,
    lane: ExecutionLaneKind,
    caller_commitment: &str,
    calldata_root: &str,
    pq_authorization_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RUNTIME-HOST-CALL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(selector),
            HashPart::Str(lane.as_str()),
            HashPart::Str(caller_commitment),
            HashPart::Str(calldata_root),
            HashPart::Str(pq_authorization_root),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn receipt_id(
    call_id: &str,
    contract_id: &str,
    selector: &str,
    status: CallStatus,
    post_state_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RUNTIME-HOST-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_id),
            HashPart::Str(contract_id),
            HashPart::Str(selector),
            HashPart::Str(status.as_str()),
            HashPart::Str(post_state_root),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn checkpoint_id(
    height: u64,
    sequence: u64,
    contract_root: &str,
    receipt_root: &str,
    previous_checkpoint_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONTRACT-RUNTIME-HOST-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
            HashPart::Str(contract_root),
            HashPart::Str(receipt_root),
            HashPart::Str(previous_checkpoint_root),
        ],
        32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(label: &str) -> String {
        domain_hash(
            "PRIVATE-L2-CONTRACT-RUNTIME-HOST-TEST",
            &[HashPart::Str(label)],
            32,
        )
    }

    fn selector() -> SelectorManifest {
        SelectorManifest {
            selector: "a9059cbb".to_string(),
            method_root: root("method"),
            access: SelectorAccess::PrivateCall,
            required_state_access_root: root("required-state"),
            max_gas: 500_000,
            payable: true,
        }
    }

    #[test]
    fn devnet_register_dispatch_and_checkpoint_are_roots_only() {
        let mut state = State::devnet();
        let contract = state
            .register_contract(RegisterContractInput {
                kind: ContractKind::Token,
                admin_commitment: root("admin"),
                code_commitment: root("code"),
                code_metadata_root: root("code-metadata"),
                abi_root: root("abi"),
                selectors: vec![selector()],
                initial_state_root: root("initial-state"),
                pq_authority_root: root("pq-authority"),
                privacy_policy_root: root("privacy-policy"),
                registered_at_height: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEVNET_HEIGHT,
                max_call_gas: 1_000_000,
                max_fee_bps: 20,
            })
            .expect("contract registration");

        let receipt = state
            .dispatch_call(DispatchCallInput {
                contract_id: contract.contract_id.clone(),
                selector: "a9059cbb".to_string(),
                lane: ExecutionLaneKind::LowLatency,
                caller_commitment: root("caller"),
                private_calldata_root: root("calldata"),
                pq_authorization_root: root("pq-auth"),
                privacy_proof_root: root("privacy-proof"),
                state_accesses: vec![StateAccessCommitment {
                    access_id: "access-1".to_string(),
                    contract_id: contract.contract_id,
                    mode: StateAccessMode::ReadWrite,
                    state_path_root: root("path"),
                    pre_state_root: root("pre"),
                    post_state_root: root("post"),
                    nullifier_root: root("nullifier"),
                    witness_root: root("witness"),
                }],
                fee_asset_id: "dnr-devnet-fee".to_string(),
                gas_limit: 500_000,
                fee_cap_units: 50,
                fee_cap_bps: 20,
                submitted_at_height: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEVNET_HEIGHT + 1,
                deadline_height: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEVNET_HEIGHT + 4,
                sequencer_commitment: root("sequencer"),
                pre_state_root: root("pre"),
                post_state_root: root("post"),
                event_root: root("event"),
                return_root: root("return"),
                gas_used: 400_000,
                fee_charged_units: 40,
                force_status: None,
            })
            .expect("dispatch call");

        assert_eq!(receipt.status, CallStatus::Executed);
        let checkpoint = state
            .commit_checkpoint(CommitCheckpointInput {
                height: PRIVATE_L2_CONTRACT_RUNTIME_HOST_DEVNET_HEIGHT + 8,
                operator_commitment: root("operator"),
            })
            .expect("checkpoint");
        assert_eq!(checkpoint.sequence, 1);
        assert!(state.public_record().get("contracts").is_none());
        assert_ne!(state.state_root(), merkle_root("empty", &[]));
    }
}
