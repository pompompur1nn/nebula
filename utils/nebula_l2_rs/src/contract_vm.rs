use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ContractVmResult<T> = Result<T, String>;

pub const CONTRACT_VM_PROTOCOL_VERSION: &str = "nebula-contract-vm-v1";
pub const CONTRACT_VM_HOST_PROFILE: &str = "deterministic-pq-private-host";
pub const CONTRACT_VM_DEFAULT_MAX_FUEL: u64 = 8_000_000;
pub const CONTRACT_VM_DEFAULT_MAX_MEMORY_PAGES: u64 = 64;
pub const CONTRACT_VM_DEFAULT_MAX_STORAGE_WRITES: u64 = 512;
pub const CONTRACT_VM_DEFAULT_MAX_EVENT_BYTES: u64 = 32 * 1024;
pub const CONTRACT_VM_DEFAULT_TRACE_TTL_BLOCKS: u64 = 64;
pub const CONTRACT_VM_LOW_FEE_FUEL_CREDIT: u64 = 50_000;
pub const CONTRACT_VM_MAX_ABI_METHODS: usize = 256;
pub const CONTRACT_VM_MAX_SYSCALLS: usize = 128;
pub const CONTRACT_VM_MAX_REPLAY_INPUTS: usize = 1024;
pub const CONTRACT_VM_STATUS_ACTIVE: &str = "active";
pub const CONTRACT_VM_STATUS_PAUSED: &str = "paused";
pub const CONTRACT_VM_STATUS_RETIRED: &str = "retired";
pub const CONTRACT_VM_STATUS_ACCEPTED: &str = "accepted";
pub const CONTRACT_VM_STATUS_REJECTED: &str = "rejected";
pub const CONTRACT_VM_STATUS_EXECUTED: &str = "executed";
pub const CONTRACT_VM_STATUS_FAILED: &str = "failed";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VmHostFunction {
    StorageRead,
    StorageWrite,
    EmitEvent,
    TransferAsset,
    MintAsset,
    BurnAsset,
    VerifyQuantumSignature,
    VerifyPrivacyProof,
    ReadOracle,
    BridgeQuote,
    PaymasterCharge,
    ScheduleProof,
    Custom(String),
}

impl VmHostFunction {
    pub fn as_str(&self) -> String {
        match self {
            Self::StorageRead => "storage_read".to_string(),
            Self::StorageWrite => "storage_write".to_string(),
            Self::EmitEvent => "emit_event".to_string(),
            Self::TransferAsset => "transfer_asset".to_string(),
            Self::MintAsset => "mint_asset".to_string(),
            Self::BurnAsset => "burn_asset".to_string(),
            Self::VerifyQuantumSignature => "verify_quantum_signature".to_string(),
            Self::VerifyPrivacyProof => "verify_privacy_proof".to_string(),
            Self::ReadOracle => "read_oracle".to_string(),
            Self::BridgeQuote => "bridge_quote".to_string(),
            Self::PaymasterCharge => "paymaster_charge".to_string(),
            Self::ScheduleProof => "schedule_proof".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn default_fuel_cost(&self) -> u64 {
        match self {
            Self::StorageRead => 200,
            Self::StorageWrite => 1_200,
            Self::EmitEvent => 150,
            Self::TransferAsset => 2_500,
            Self::MintAsset | Self::BurnAsset => 3_000,
            Self::VerifyQuantumSignature => 7_500,
            Self::VerifyPrivacyProof => 25_000,
            Self::ReadOracle => 1_000,
            Self::BridgeQuote => 1_500,
            Self::PaymasterCharge => 800,
            Self::ScheduleProof => 4_000,
            Self::Custom(_) => 1_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VmPermission {
    ReadState,
    WriteState,
    EmitPublicEvent,
    EmitPrivateEvent,
    AssetTransfer,
    AssetMint,
    AssetBurn,
    OracleRead,
    BridgeRead,
    BridgeWithdraw,
    PaymasterUse,
    ProverSchedule,
    GovernanceCall,
    Custom(String),
}

impl VmPermission {
    pub fn as_str(&self) -> String {
        match self {
            Self::ReadState => "read_state".to_string(),
            Self::WriteState => "write_state".to_string(),
            Self::EmitPublicEvent => "emit_public_event".to_string(),
            Self::EmitPrivateEvent => "emit_private_event".to_string(),
            Self::AssetTransfer => "asset_transfer".to_string(),
            Self::AssetMint => "asset_mint".to_string(),
            Self::AssetBurn => "asset_burn".to_string(),
            Self::OracleRead => "oracle_read".to_string(),
            Self::BridgeRead => "bridge_read".to_string(),
            Self::BridgeWithdraw => "bridge_withdraw".to_string(),
            Self::PaymasterUse => "paymaster_use".to_string(),
            Self::ProverSchedule => "prover_schedule".to_string(),
            Self::GovernanceCall => "governance_call".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmStorageMode {
    Read,
    Write,
    Delete,
}

impl VmStorageMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmCallPhase {
    Admission,
    PreExecute,
    Execute,
    PostExecute,
    Prove,
    Finalize,
}

impl VmCallPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::PreExecute => "pre_execute",
            Self::Execute => "execute",
            Self::PostExecute => "post_execute",
            Self::Prove => "prove",
            Self::Finalize => "finalize",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VmTrapKind {
    None,
    OutOfFuel,
    MemoryLimit,
    PermissionDenied,
    InvalidSyscall,
    StorageConflict,
    PrivacyProofRejected,
    QuantumAuthRejected,
    DeterminismViolation,
    Custom(String),
}

impl VmTrapKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::None => "none".to_string(),
            Self::OutOfFuel => "out_of_fuel".to_string(),
            Self::MemoryLimit => "memory_limit".to_string(),
            Self::PermissionDenied => "permission_denied".to_string(),
            Self::InvalidSyscall => "invalid_syscall".to_string(),
            Self::StorageConflict => "storage_conflict".to_string(),
            Self::PrivacyProofRejected => "privacy_proof_rejected".to_string(),
            Self::QuantumAuthRejected => "quantum_auth_rejected".to_string(),
            Self::DeterminismViolation => "determinism_violation".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmAbiMethod {
    pub method_id: String,
    pub contract_id: String,
    pub selector: String,
    pub entrypoint: String,
    pub arg_schema_root: String,
    pub return_schema_root: String,
    pub required_permission_root: String,
    pub max_fuel: u64,
    pub private_args_allowed: bool,
    pub status: String,
}

impl VmAbiMethod {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        selector: impl Into<String>,
        entrypoint: impl Into<String>,
        arg_schema_root: impl Into<String>,
        return_schema_root: impl Into<String>,
        required_permissions: Vec<VmPermission>,
        max_fuel: u64,
        private_args_allowed: bool,
    ) -> ContractVmResult<Self> {
        let contract_id = contract_id.into();
        let selector = selector.into();
        let entrypoint = entrypoint.into();
        let arg_schema_root = arg_schema_root.into();
        let return_schema_root = return_schema_root.into();
        ensure_non_empty(&contract_id, "vm abi contract id")?;
        ensure_non_empty(&selector, "vm abi selector")?;
        ensure_non_empty(&entrypoint, "vm abi entrypoint")?;
        ensure_non_empty(&arg_schema_root, "vm abi arg schema root")?;
        ensure_non_empty(&return_schema_root, "vm abi return schema root")?;
        ensure_positive(max_fuel, "vm abi max fuel")?;
        let required_permission_root = vm_permission_root(&required_permissions);
        let method_id = vm_abi_method_id(
            &contract_id,
            &selector,
            &entrypoint,
            &arg_schema_root,
            &return_schema_root,
            &required_permission_root,
            max_fuel,
            private_args_allowed,
        );
        Ok(Self {
            method_id,
            contract_id,
            selector,
            entrypoint,
            arg_schema_root,
            return_schema_root,
            required_permission_root,
            max_fuel,
            private_args_allowed,
            status: CONTRACT_VM_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_abi_method",
            "chain_id": CHAIN_ID,
            "method_id": self.method_id,
            "contract_id": self.contract_id,
            "selector": self.selector,
            "entrypoint": self.entrypoint,
            "arg_schema_root": self.arg_schema_root,
            "return_schema_root": self.return_schema_root,
            "required_permission_root": self.required_permission_root,
            "max_fuel": self.max_fuel,
            "private_args_allowed": self.private_args_allowed,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmModulePolicy {
    pub policy_id: String,
    pub module_id: String,
    pub code_hash: String,
    pub abi_root: String,
    pub permission_root: String,
    pub syscall_allowlist_root: String,
    pub max_fuel: u64,
    pub max_memory_pages: u64,
    pub max_storage_writes: u64,
    pub max_event_bytes: u64,
    pub quantum_auth_root: String,
    pub privacy_policy_root: String,
    pub status: String,
}

impl VmModulePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        module_id: impl Into<String>,
        code_hash: impl Into<String>,
        abi_methods: &[VmAbiMethod],
        permissions: Vec<VmPermission>,
        syscalls: Vec<VmHostFunction>,
        max_fuel: u64,
        max_memory_pages: u64,
        max_storage_writes: u64,
        max_event_bytes: u64,
        quantum_auth_root: impl Into<String>,
        privacy_policy_root: impl Into<String>,
    ) -> ContractVmResult<Self> {
        let module_id = module_id.into();
        let code_hash = code_hash.into();
        let quantum_auth_root = quantum_auth_root.into();
        let privacy_policy_root = privacy_policy_root.into();
        ensure_non_empty(&module_id, "vm module policy module id")?;
        ensure_non_empty(&code_hash, "vm module policy code hash")?;
        ensure_non_empty(&quantum_auth_root, "vm module quantum auth root")?;
        ensure_non_empty(&privacy_policy_root, "vm module privacy root")?;
        ensure_positive(max_fuel, "vm module max fuel")?;
        ensure_positive(max_memory_pages, "vm module max memory")?;
        if abi_methods.len() > CONTRACT_VM_MAX_ABI_METHODS {
            return Err("vm module has too many abi methods".to_string());
        }
        if syscalls.len() > CONTRACT_VM_MAX_SYSCALLS {
            return Err("vm module has too many syscalls".to_string());
        }
        let abi_root = vm_abi_method_root(abi_methods);
        let permission_root = vm_permission_root(&permissions);
        let syscall_allowlist_root = vm_host_function_root(&syscalls);
        let policy_id = vm_module_policy_id(
            &module_id,
            &code_hash,
            &abi_root,
            &permission_root,
            &syscall_allowlist_root,
            max_fuel,
            max_memory_pages,
            max_storage_writes,
            max_event_bytes,
            &quantum_auth_root,
            &privacy_policy_root,
        );
        Ok(Self {
            policy_id,
            module_id,
            code_hash,
            abi_root,
            permission_root,
            syscall_allowlist_root,
            max_fuel,
            max_memory_pages,
            max_storage_writes,
            max_event_bytes,
            quantum_auth_root,
            privacy_policy_root,
            status: CONTRACT_VM_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_module_policy",
            "chain_id": CHAIN_ID,
            "policy_id": self.policy_id,
            "module_id": self.module_id,
            "code_hash": self.code_hash,
            "abi_root": self.abi_root,
            "permission_root": self.permission_root,
            "syscall_allowlist_root": self.syscall_allowlist_root,
            "max_fuel": self.max_fuel,
            "max_memory_pages": self.max_memory_pages,
            "max_storage_writes": self.max_storage_writes,
            "max_event_bytes": self.max_event_bytes,
            "quantum_auth_root": self.quantum_auth_root,
            "privacy_policy_root": self.privacy_policy_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmStorageAccess {
    pub access_id: String,
    pub contract_id: String,
    pub storage_key_commitment: String,
    pub before_root: String,
    pub after_root: String,
    pub mode: VmStorageMode,
    pub ordinal: u64,
}

impl VmStorageAccess {
    pub fn new(
        contract_id: impl Into<String>,
        storage_key_commitment: impl Into<String>,
        before_root: impl Into<String>,
        after_root: impl Into<String>,
        mode: VmStorageMode,
        ordinal: u64,
    ) -> ContractVmResult<Self> {
        let contract_id = contract_id.into();
        let storage_key_commitment = storage_key_commitment.into();
        let before_root = before_root.into();
        let after_root = after_root.into();
        ensure_non_empty(&contract_id, "vm storage contract id")?;
        ensure_non_empty(&storage_key_commitment, "vm storage key commitment")?;
        ensure_non_empty(&before_root, "vm storage before root")?;
        ensure_non_empty(&after_root, "vm storage after root")?;
        let access_id = vm_storage_access_id(
            &contract_id,
            &storage_key_commitment,
            &before_root,
            &after_root,
            mode,
            ordinal,
        );
        Ok(Self {
            access_id,
            contract_id,
            storage_key_commitment,
            before_root,
            after_root,
            mode,
            ordinal,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_storage_access",
            "chain_id": CHAIN_ID,
            "access_id": self.access_id,
            "contract_id": self.contract_id,
            "storage_key_commitment": self.storage_key_commitment,
            "before_root": self.before_root,
            "after_root": self.after_root,
            "mode": self.mode.as_str(),
            "ordinal": self.ordinal,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmStorageOverlay {
    pub overlay_id: String,
    pub call_id: String,
    pub base_storage_root: String,
    pub access_root: String,
    pub write_root: String,
    pub delete_root: String,
    pub final_storage_root: String,
    pub status: String,
}

impl VmStorageOverlay {
    pub fn new(
        call_id: impl Into<String>,
        base_storage_root: impl Into<String>,
        accesses: &[VmStorageAccess],
        final_storage_root: impl Into<String>,
    ) -> ContractVmResult<Self> {
        let call_id = call_id.into();
        let base_storage_root = base_storage_root.into();
        let final_storage_root = final_storage_root.into();
        ensure_non_empty(&call_id, "vm overlay call id")?;
        ensure_non_empty(&base_storage_root, "vm overlay base root")?;
        ensure_non_empty(&final_storage_root, "vm overlay final root")?;
        let access_root = vm_storage_access_root(accesses);
        let writes = accesses
            .iter()
            .filter(|access| access.mode == VmStorageMode::Write)
            .cloned()
            .collect::<Vec<_>>();
        let deletes = accesses
            .iter()
            .filter(|access| access.mode == VmStorageMode::Delete)
            .cloned()
            .collect::<Vec<_>>();
        let write_root = vm_storage_access_root(&writes);
        let delete_root = vm_storage_access_root(&deletes);
        let overlay_id = vm_storage_overlay_id(
            &call_id,
            &base_storage_root,
            &access_root,
            &write_root,
            &delete_root,
            &final_storage_root,
        );
        Ok(Self {
            overlay_id,
            call_id,
            base_storage_root,
            access_root,
            write_root,
            delete_root,
            final_storage_root,
            status: CONTRACT_VM_STATUS_ACCEPTED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_storage_overlay",
            "chain_id": CHAIN_ID,
            "overlay_id": self.overlay_id,
            "call_id": self.call_id,
            "base_storage_root": self.base_storage_root,
            "access_root": self.access_root,
            "write_root": self.write_root,
            "delete_root": self.delete_root,
            "final_storage_root": self.final_storage_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmSyscallTrace {
    pub trace_id: String,
    pub call_id: String,
    pub host_function: VmHostFunction,
    pub phase: VmCallPhase,
    pub input_root: String,
    pub output_root: String,
    pub fuel_charged: u64,
    pub permission_root: String,
    pub ordinal: u64,
    pub status: String,
}

impl VmSyscallTrace {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call_id: impl Into<String>,
        host_function: VmHostFunction,
        phase: VmCallPhase,
        input_root: impl Into<String>,
        output_root: impl Into<String>,
        fuel_charged: u64,
        permissions: Vec<VmPermission>,
        ordinal: u64,
        status: impl Into<String>,
    ) -> ContractVmResult<Self> {
        let call_id = call_id.into();
        let input_root = input_root.into();
        let output_root = output_root.into();
        let status = status.into();
        ensure_non_empty(&call_id, "vm syscall call id")?;
        ensure_non_empty(&input_root, "vm syscall input root")?;
        ensure_non_empty(&output_root, "vm syscall output root")?;
        ensure_non_empty(&status, "vm syscall status")?;
        let permission_root = vm_permission_root(&permissions);
        let trace_id = vm_syscall_trace_id(
            &call_id,
            &host_function,
            phase,
            &input_root,
            &output_root,
            fuel_charged,
            &permission_root,
            ordinal,
            &status,
        );
        Ok(Self {
            trace_id,
            call_id,
            host_function,
            phase,
            input_root,
            output_root,
            fuel_charged,
            permission_root,
            ordinal,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_syscall_trace",
            "chain_id": CHAIN_ID,
            "trace_id": self.trace_id,
            "call_id": self.call_id,
            "host_function": self.host_function.as_str(),
            "phase": self.phase.as_str(),
            "input_root": self.input_root,
            "output_root": self.output_root,
            "fuel_charged": self.fuel_charged,
            "permission_root": self.permission_root,
            "ordinal": self.ordinal,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmMeterSnapshot {
    pub meter_id: String,
    pub call_id: String,
    pub fuel_limit: u64,
    pub fuel_used: u64,
    pub memory_pages: u64,
    pub storage_reads: u64,
    pub storage_writes: u64,
    pub event_bytes: u64,
    pub low_fee_credit_used: u64,
    pub fee_units_charged: u64,
}

impl VmMeterSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call_id: impl Into<String>,
        fuel_limit: u64,
        fuel_used: u64,
        memory_pages: u64,
        storage_reads: u64,
        storage_writes: u64,
        event_bytes: u64,
        low_fee_credit_used: u64,
        fee_units_charged: u64,
    ) -> ContractVmResult<Self> {
        let call_id = call_id.into();
        ensure_non_empty(&call_id, "vm meter call id")?;
        ensure_positive(fuel_limit, "vm meter fuel limit")?;
        if fuel_used > fuel_limit {
            return Err("vm meter fuel used exceeds fuel limit".to_string());
        }
        if memory_pages > CONTRACT_VM_DEFAULT_MAX_MEMORY_PAGES {
            return Err("vm meter memory exceeds default maximum".to_string());
        }
        let meter_id = vm_meter_snapshot_id(
            &call_id,
            fuel_limit,
            fuel_used,
            memory_pages,
            storage_reads,
            storage_writes,
            event_bytes,
            low_fee_credit_used,
            fee_units_charged,
        );
        Ok(Self {
            meter_id,
            call_id,
            fuel_limit,
            fuel_used,
            memory_pages,
            storage_reads,
            storage_writes,
            event_bytes,
            low_fee_credit_used,
            fee_units_charged,
        })
    }

    pub fn remaining_fuel(&self) -> u64 {
        self.fuel_limit.saturating_sub(self.fuel_used)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_meter_snapshot",
            "chain_id": CHAIN_ID,
            "meter_id": self.meter_id,
            "call_id": self.call_id,
            "fuel_limit": self.fuel_limit,
            "fuel_used": self.fuel_used,
            "remaining_fuel": self.remaining_fuel(),
            "memory_pages": self.memory_pages,
            "storage_reads": self.storage_reads,
            "storage_writes": self.storage_writes,
            "event_bytes": self.event_bytes,
            "low_fee_credit_used": self.low_fee_credit_used,
            "fee_units_charged": self.fee_units_charged,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmExecutionFrame {
    pub frame_id: String,
    pub call_id: String,
    pub contract_id: String,
    pub module_id: String,
    pub method_id: String,
    pub caller_commitment: String,
    pub args_root: String,
    pub private_args: bool,
    pub phase: VmCallPhase,
    pub parent_frame_id: Option<String>,
    pub depth: u64,
    pub status: String,
}

impl VmExecutionFrame {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call_id: impl Into<String>,
        contract_id: impl Into<String>,
        module_id: impl Into<String>,
        method_id: impl Into<String>,
        caller_commitment: impl Into<String>,
        args_root: impl Into<String>,
        private_args: bool,
        phase: VmCallPhase,
        parent_frame_id: Option<String>,
        depth: u64,
    ) -> ContractVmResult<Self> {
        let call_id = call_id.into();
        let contract_id = contract_id.into();
        let module_id = module_id.into();
        let method_id = method_id.into();
        let caller_commitment = caller_commitment.into();
        let args_root = args_root.into();
        ensure_non_empty(&call_id, "vm frame call id")?;
        ensure_non_empty(&contract_id, "vm frame contract id")?;
        ensure_non_empty(&module_id, "vm frame module id")?;
        ensure_non_empty(&method_id, "vm frame method id")?;
        ensure_non_empty(&caller_commitment, "vm frame caller commitment")?;
        ensure_non_empty(&args_root, "vm frame args root")?;
        let frame_id = vm_execution_frame_id(
            &call_id,
            &contract_id,
            &module_id,
            &method_id,
            &caller_commitment,
            &args_root,
            private_args,
            phase,
            parent_frame_id.as_deref(),
            depth,
        );
        Ok(Self {
            frame_id,
            call_id,
            contract_id,
            module_id,
            method_id,
            caller_commitment,
            args_root,
            private_args,
            phase,
            parent_frame_id,
            depth,
            status: CONTRACT_VM_STATUS_ACCEPTED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_execution_frame",
            "chain_id": CHAIN_ID,
            "frame_id": self.frame_id,
            "call_id": self.call_id,
            "contract_id": self.contract_id,
            "module_id": self.module_id,
            "method_id": self.method_id,
            "caller_commitment": self.caller_commitment,
            "args_root": self.args_root,
            "private_args": self.private_args,
            "phase": self.phase.as_str(),
            "parent_frame_id": self.parent_frame_id,
            "depth": self.depth,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmHostReceipt {
    pub receipt_id: String,
    pub call_id: String,
    pub frame_root: String,
    pub syscall_root: String,
    pub storage_overlay_root: String,
    pub meter_root: String,
    pub event_root: String,
    pub return_root: String,
    pub trap: VmTrapKind,
    pub proof_input_root: String,
    pub status: String,
}

impl VmHostReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call_id: impl Into<String>,
        frames: &[VmExecutionFrame],
        syscalls: &[VmSyscallTrace],
        overlays: &[VmStorageOverlay],
        meters: &[VmMeterSnapshot],
        event_root: impl Into<String>,
        return_root: impl Into<String>,
        trap: VmTrapKind,
        proof_input_root: impl Into<String>,
        status: impl Into<String>,
    ) -> ContractVmResult<Self> {
        let call_id = call_id.into();
        let event_root = event_root.into();
        let return_root = return_root.into();
        let proof_input_root = proof_input_root.into();
        let status = status.into();
        ensure_non_empty(&call_id, "vm host receipt call id")?;
        ensure_non_empty(&event_root, "vm host receipt event root")?;
        ensure_non_empty(&return_root, "vm host receipt return root")?;
        ensure_non_empty(&proof_input_root, "vm host receipt proof input root")?;
        ensure_non_empty(&status, "vm host receipt status")?;
        let frame_root = vm_execution_frame_root(frames);
        let syscall_root = vm_syscall_trace_root(syscalls);
        let storage_overlay_root = vm_storage_overlay_root(overlays);
        let meter_root = vm_meter_snapshot_root(meters);
        let receipt_id = vm_host_receipt_id(
            &call_id,
            &frame_root,
            &syscall_root,
            &storage_overlay_root,
            &meter_root,
            &event_root,
            &return_root,
            &trap,
            &proof_input_root,
            &status,
        );
        Ok(Self {
            receipt_id,
            call_id,
            frame_root,
            syscall_root,
            storage_overlay_root,
            meter_root,
            event_root,
            return_root,
            trap,
            proof_input_root,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_host_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "call_id": self.call_id,
            "frame_root": self.frame_root,
            "syscall_root": self.syscall_root,
            "storage_overlay_root": self.storage_overlay_root,
            "meter_root": self.meter_root,
            "event_root": self.event_root,
            "return_root": self.return_root,
            "trap": self.trap.as_str(),
            "proof_input_root": self.proof_input_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmReplayWitness {
    pub witness_id: String,
    pub call_id: String,
    pub input_root: String,
    pub host_receipt_id: String,
    pub storage_proof_root: String,
    pub oracle_input_root: String,
    pub privacy_input_root: String,
    pub quantum_auth_root: String,
    pub determinism_root: String,
    pub expires_at_height: u64,
    pub status: String,
}

impl VmReplayWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call_id: impl Into<String>,
        input_root: impl Into<String>,
        host_receipt_id: impl Into<String>,
        storage_proof_root: impl Into<String>,
        oracle_input_root: impl Into<String>,
        privacy_input_root: impl Into<String>,
        quantum_auth_root: impl Into<String>,
        determinism_root: impl Into<String>,
        expires_at_height: u64,
    ) -> ContractVmResult<Self> {
        let call_id = call_id.into();
        let input_root = input_root.into();
        let host_receipt_id = host_receipt_id.into();
        let storage_proof_root = storage_proof_root.into();
        let oracle_input_root = oracle_input_root.into();
        let privacy_input_root = privacy_input_root.into();
        let quantum_auth_root = quantum_auth_root.into();
        let determinism_root = determinism_root.into();
        ensure_non_empty(&call_id, "vm replay call id")?;
        ensure_non_empty(&input_root, "vm replay input root")?;
        ensure_non_empty(&host_receipt_id, "vm replay receipt id")?;
        ensure_non_empty(&storage_proof_root, "vm replay storage proof root")?;
        ensure_non_empty(&oracle_input_root, "vm replay oracle root")?;
        ensure_non_empty(&privacy_input_root, "vm replay privacy root")?;
        ensure_non_empty(&quantum_auth_root, "vm replay quantum auth root")?;
        ensure_non_empty(&determinism_root, "vm replay determinism root")?;
        let witness_id = vm_replay_witness_id(
            &call_id,
            &input_root,
            &host_receipt_id,
            &storage_proof_root,
            &oracle_input_root,
            &privacy_input_root,
            &quantum_auth_root,
            &determinism_root,
            expires_at_height,
        );
        Ok(Self {
            witness_id,
            call_id,
            input_root,
            host_receipt_id,
            storage_proof_root,
            oracle_input_root,
            privacy_input_root,
            quantum_auth_root,
            determinism_root,
            expires_at_height,
            status: CONTRACT_VM_STATUS_ACCEPTED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_replay_witness",
            "chain_id": CHAIN_ID,
            "witness_id": self.witness_id,
            "call_id": self.call_id,
            "input_root": self.input_root,
            "host_receipt_id": self.host_receipt_id,
            "storage_proof_root": self.storage_proof_root,
            "oracle_input_root": self.oracle_input_root,
            "privacy_input_root": self.privacy_input_root,
            "quantum_auth_root": self.quantum_auth_root,
            "determinism_root": self.determinism_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmUpgradeEnvelope {
    pub upgrade_id: String,
    pub contract_id: String,
    pub old_policy_id: String,
    pub new_policy_id: String,
    pub migration_root: String,
    pub authority_root: String,
    pub proposed_at_height: u64,
    pub executable_at_height: u64,
    pub status: String,
}

impl VmUpgradeEnvelope {
    pub fn new(
        contract_id: impl Into<String>,
        old_policy_id: impl Into<String>,
        new_policy_id: impl Into<String>,
        migration_root: impl Into<String>,
        authority_root: impl Into<String>,
        proposed_at_height: u64,
        executable_at_height: u64,
    ) -> ContractVmResult<Self> {
        let contract_id = contract_id.into();
        let old_policy_id = old_policy_id.into();
        let new_policy_id = new_policy_id.into();
        let migration_root = migration_root.into();
        let authority_root = authority_root.into();
        ensure_non_empty(&contract_id, "vm upgrade contract id")?;
        ensure_non_empty(&old_policy_id, "vm upgrade old policy id")?;
        ensure_non_empty(&new_policy_id, "vm upgrade new policy id")?;
        ensure_non_empty(&migration_root, "vm upgrade migration root")?;
        ensure_non_empty(&authority_root, "vm upgrade authority root")?;
        if old_policy_id == new_policy_id {
            return Err("vm upgrade requires a new policy".to_string());
        }
        if executable_at_height <= proposed_at_height {
            return Err("vm upgrade executable height must be after proposal".to_string());
        }
        let upgrade_id = vm_upgrade_envelope_id(
            &contract_id,
            &old_policy_id,
            &new_policy_id,
            &migration_root,
            &authority_root,
            proposed_at_height,
            executable_at_height,
        );
        Ok(Self {
            upgrade_id,
            contract_id,
            old_policy_id,
            new_policy_id,
            migration_root,
            authority_root,
            proposed_at_height,
            executable_at_height,
            status: CONTRACT_VM_STATUS_ACCEPTED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "vm_upgrade_envelope",
            "chain_id": CHAIN_ID,
            "upgrade_id": self.upgrade_id,
            "contract_id": self.contract_id,
            "old_policy_id": self.old_policy_id,
            "new_policy_id": self.new_policy_id,
            "migration_root": self.migration_root,
            "authority_root": self.authority_root,
            "proposed_at_height": self.proposed_at_height,
            "executable_at_height": self.executable_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVmState {
    pub height: u64,
    pub abi_methods: BTreeMap<String, VmAbiMethod>,
    pub module_policies: BTreeMap<String, VmModulePolicy>,
    pub storage_accesses: BTreeMap<String, VmStorageAccess>,
    pub storage_overlays: BTreeMap<String, VmStorageOverlay>,
    pub syscall_traces: BTreeMap<String, VmSyscallTrace>,
    pub meter_snapshots: BTreeMap<String, VmMeterSnapshot>,
    pub execution_frames: BTreeMap<String, VmExecutionFrame>,
    pub host_receipts: BTreeMap<String, VmHostReceipt>,
    pub replay_witnesses: BTreeMap<String, VmReplayWitness>,
    pub upgrades: BTreeMap<String, VmUpgradeEnvelope>,
}

impl ContractVmState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet(operator_label: &str) -> ContractVmResult<Self> {
        ensure_non_empty(operator_label, "vm devnet operator label")?;
        let mut state = Self::new();
        let contract_id = vm_label_root(operator_label, "devnet-contract");
        let abi = VmAbiMethod::new(
            contract_id.clone(),
            "0x00000001",
            "execute",
            vm_payload_root("VM-DEVNET-ARGS", &json!({"type": "json"})),
            vm_payload_root("VM-DEVNET-RETURNS", &json!({"type": "receipt"})),
            vec![
                VmPermission::ReadState,
                VmPermission::WriteState,
                VmPermission::OracleRead,
                VmPermission::PaymasterUse,
                VmPermission::ProverSchedule,
            ],
            CONTRACT_VM_DEFAULT_MAX_FUEL,
            true,
        )?;
        let policy = VmModulePolicy::new(
            vm_label_root(operator_label, "devnet-module"),
            vm_label_root(operator_label, "devnet-code-hash"),
            std::slice::from_ref(&abi),
            vec![
                VmPermission::ReadState,
                VmPermission::WriteState,
                VmPermission::EmitPublicEvent,
                VmPermission::EmitPrivateEvent,
                VmPermission::OracleRead,
                VmPermission::PaymasterUse,
                VmPermission::ProverSchedule,
            ],
            vec![
                VmHostFunction::StorageRead,
                VmHostFunction::StorageWrite,
                VmHostFunction::EmitEvent,
                VmHostFunction::VerifyQuantumSignature,
                VmHostFunction::VerifyPrivacyProof,
                VmHostFunction::ReadOracle,
                VmHostFunction::PaymasterCharge,
                VmHostFunction::ScheduleProof,
            ],
            CONTRACT_VM_DEFAULT_MAX_FUEL,
            CONTRACT_VM_DEFAULT_MAX_MEMORY_PAGES,
            CONTRACT_VM_DEFAULT_MAX_STORAGE_WRITES,
            CONTRACT_VM_DEFAULT_MAX_EVENT_BYTES,
            vm_label_root(operator_label, "devnet-quantum-auth"),
            vm_label_root(operator_label, "devnet-privacy-policy"),
        )?;
        state.register_abi_method(abi)?;
        state.register_module_policy(policy)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn register_abi_method(&mut self, method: VmAbiMethod) -> ContractVmResult<String> {
        if self.abi_methods.len() >= CONTRACT_VM_MAX_ABI_METHODS
            && !self.abi_methods.contains_key(&method.method_id)
        {
            return Err("vm abi method limit exceeded".to_string());
        }
        let method_id = method.method_id.clone();
        self.abi_methods.insert(method_id.clone(), method);
        Ok(method_id)
    }

    pub fn register_module_policy(&mut self, policy: VmModulePolicy) -> ContractVmResult<String> {
        let policy_id = policy.policy_id.clone();
        self.module_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn record_storage_overlay(
        &mut self,
        overlay: VmStorageOverlay,
        accesses: Vec<VmStorageAccess>,
    ) -> ContractVmResult<String> {
        if overlay.access_root != vm_storage_access_root(&accesses) {
            return Err("vm storage overlay access root mismatch".to_string());
        }
        for access in accesses {
            self.storage_accesses
                .insert(access.access_id.clone(), access);
        }
        let overlay_id = overlay.overlay_id.clone();
        self.storage_overlays.insert(overlay_id.clone(), overlay);
        Ok(overlay_id)
    }

    pub fn record_syscall(&mut self, trace: VmSyscallTrace) -> ContractVmResult<String> {
        let trace_id = trace.trace_id.clone();
        self.syscall_traces.insert(trace_id.clone(), trace);
        Ok(trace_id)
    }

    pub fn record_meter(&mut self, meter: VmMeterSnapshot) -> ContractVmResult<String> {
        let meter_id = meter.meter_id.clone();
        self.meter_snapshots.insert(meter_id.clone(), meter);
        Ok(meter_id)
    }

    pub fn record_frame(&mut self, frame: VmExecutionFrame) -> ContractVmResult<String> {
        let frame_id = frame.frame_id.clone();
        self.execution_frames.insert(frame_id.clone(), frame);
        Ok(frame_id)
    }

    pub fn record_host_receipt(&mut self, receipt: VmHostReceipt) -> ContractVmResult<String> {
        let receipt_id = receipt.receipt_id.clone();
        self.host_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn record_replay_witness(&mut self, witness: VmReplayWitness) -> ContractVmResult<String> {
        if !self.host_receipts.contains_key(&witness.host_receipt_id) {
            return Err("vm replay witness references unknown host receipt".to_string());
        }
        let witness_id = witness.witness_id.clone();
        self.replay_witnesses.insert(witness_id.clone(), witness);
        Ok(witness_id)
    }

    pub fn record_upgrade(&mut self, upgrade: VmUpgradeEnvelope) -> ContractVmResult<String> {
        let upgrade_id = upgrade.upgrade_id.clone();
        self.upgrades.insert(upgrade_id.clone(), upgrade);
        Ok(upgrade_id)
    }

    pub fn host_policy_root(&self) -> String {
        vm_module_policy_root_from_map(&self.module_policies)
    }

    pub fn state_root(&self) -> String {
        contract_vm_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_vm_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VM_PROTOCOL_VERSION,
            "host_profile": CONTRACT_VM_HOST_PROFILE,
            "height": self.height,
            "abi_method_root": vm_abi_method_root_from_map(&self.abi_methods),
            "module_policy_root": vm_module_policy_root_from_map(&self.module_policies),
            "storage_access_root": vm_storage_access_root_from_map(&self.storage_accesses),
            "storage_overlay_root": vm_storage_overlay_root_from_map(&self.storage_overlays),
            "syscall_trace_root": vm_syscall_trace_root_from_map(&self.syscall_traces),
            "meter_snapshot_root": vm_meter_snapshot_root_from_map(&self.meter_snapshots),
            "execution_frame_root": vm_execution_frame_root_from_map(&self.execution_frames),
            "host_receipt_root": vm_host_receipt_root_from_map(&self.host_receipts),
            "replay_witness_root": vm_replay_witness_root_from_map(&self.replay_witnesses),
            "upgrade_root": vm_upgrade_envelope_root_from_map(&self.upgrades),
            "module_policy_count": self.module_policies.len() as u64,
            "host_receipt_count": self.host_receipts.len() as u64,
            "replay_witness_count": self.replay_witnesses.len() as u64,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn vm_abi_method_id(
    contract_id: &str,
    selector: &str,
    entrypoint: &str,
    arg_schema_root: &str,
    return_schema_root: &str,
    required_permission_root: &str,
    max_fuel: u64,
    private_args_allowed: bool,
) -> String {
    domain_hash(
        "VM-ABI-METHOD-ID",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(selector),
            HashPart::Str(entrypoint),
            HashPart::Str(arg_schema_root),
            HashPart::Str(return_schema_root),
            HashPart::Str(required_permission_root),
            HashPart::Int(max_fuel as i128),
            HashPart::Int(private_args_allowed as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn vm_module_policy_id(
    module_id: &str,
    code_hash: &str,
    abi_root: &str,
    permission_root: &str,
    syscall_allowlist_root: &str,
    max_fuel: u64,
    max_memory_pages: u64,
    max_storage_writes: u64,
    max_event_bytes: u64,
    quantum_auth_root: &str,
    privacy_policy_root: &str,
) -> String {
    domain_hash(
        "VM-MODULE-POLICY-ID",
        &[
            HashPart::Str(module_id),
            HashPart::Str(code_hash),
            HashPart::Str(abi_root),
            HashPart::Str(permission_root),
            HashPart::Str(syscall_allowlist_root),
            HashPart::Int(max_fuel as i128),
            HashPart::Int(max_memory_pages as i128),
            HashPart::Int(max_storage_writes as i128),
            HashPart::Int(max_event_bytes as i128),
            HashPart::Str(quantum_auth_root),
            HashPart::Str(privacy_policy_root),
        ],
        32,
    )
}

pub fn vm_storage_access_id(
    contract_id: &str,
    storage_key_commitment: &str,
    before_root: &str,
    after_root: &str,
    mode: VmStorageMode,
    ordinal: u64,
) -> String {
    domain_hash(
        "VM-STORAGE-ACCESS-ID",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(storage_key_commitment),
            HashPart::Str(before_root),
            HashPart::Str(after_root),
            HashPart::Str(mode.as_str()),
            HashPart::Int(ordinal as i128),
        ],
        32,
    )
}

pub fn vm_storage_overlay_id(
    call_id: &str,
    base_storage_root: &str,
    access_root: &str,
    write_root: &str,
    delete_root: &str,
    final_storage_root: &str,
) -> String {
    domain_hash(
        "VM-STORAGE-OVERLAY-ID",
        &[
            HashPart::Str(call_id),
            HashPart::Str(base_storage_root),
            HashPart::Str(access_root),
            HashPart::Str(write_root),
            HashPart::Str(delete_root),
            HashPart::Str(final_storage_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn vm_syscall_trace_id(
    call_id: &str,
    host_function: &VmHostFunction,
    phase: VmCallPhase,
    input_root: &str,
    output_root: &str,
    fuel_charged: u64,
    permission_root: &str,
    ordinal: u64,
    status: &str,
) -> String {
    domain_hash(
        "VM-SYSCALL-TRACE-ID",
        &[
            HashPart::Str(call_id),
            HashPart::Str(&host_function.as_str()),
            HashPart::Str(phase.as_str()),
            HashPart::Str(input_root),
            HashPart::Str(output_root),
            HashPart::Int(fuel_charged as i128),
            HashPart::Str(permission_root),
            HashPart::Int(ordinal as i128),
            HashPart::Str(status),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn vm_meter_snapshot_id(
    call_id: &str,
    fuel_limit: u64,
    fuel_used: u64,
    memory_pages: u64,
    storage_reads: u64,
    storage_writes: u64,
    event_bytes: u64,
    low_fee_credit_used: u64,
    fee_units_charged: u64,
) -> String {
    domain_hash(
        "VM-METER-SNAPSHOT-ID",
        &[
            HashPart::Str(call_id),
            HashPart::Int(fuel_limit as i128),
            HashPart::Int(fuel_used as i128),
            HashPart::Int(memory_pages as i128),
            HashPart::Int(storage_reads as i128),
            HashPart::Int(storage_writes as i128),
            HashPart::Int(event_bytes as i128),
            HashPart::Int(low_fee_credit_used as i128),
            HashPart::Int(fee_units_charged as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn vm_execution_frame_id(
    call_id: &str,
    contract_id: &str,
    module_id: &str,
    method_id: &str,
    caller_commitment: &str,
    args_root: &str,
    private_args: bool,
    phase: VmCallPhase,
    parent_frame_id: Option<&str>,
    depth: u64,
) -> String {
    domain_hash(
        "VM-EXECUTION-FRAME-ID",
        &[
            HashPart::Str(call_id),
            HashPart::Str(contract_id),
            HashPart::Str(module_id),
            HashPart::Str(method_id),
            HashPart::Str(caller_commitment),
            HashPart::Str(args_root),
            HashPart::Int(private_args as i128),
            HashPart::Str(phase.as_str()),
            HashPart::Str(parent_frame_id.unwrap_or("none")),
            HashPart::Int(depth as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn vm_host_receipt_id(
    call_id: &str,
    frame_root: &str,
    syscall_root: &str,
    storage_overlay_root: &str,
    meter_root: &str,
    event_root: &str,
    return_root: &str,
    trap: &VmTrapKind,
    proof_input_root: &str,
    status: &str,
) -> String {
    domain_hash(
        "VM-HOST-RECEIPT-ID",
        &[
            HashPart::Str(call_id),
            HashPart::Str(frame_root),
            HashPart::Str(syscall_root),
            HashPart::Str(storage_overlay_root),
            HashPart::Str(meter_root),
            HashPart::Str(event_root),
            HashPart::Str(return_root),
            HashPart::Str(&trap.as_str()),
            HashPart::Str(proof_input_root),
            HashPart::Str(status),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn vm_replay_witness_id(
    call_id: &str,
    input_root: &str,
    host_receipt_id: &str,
    storage_proof_root: &str,
    oracle_input_root: &str,
    privacy_input_root: &str,
    quantum_auth_root: &str,
    determinism_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "VM-REPLAY-WITNESS-ID",
        &[
            HashPart::Str(call_id),
            HashPart::Str(input_root),
            HashPart::Str(host_receipt_id),
            HashPart::Str(storage_proof_root),
            HashPart::Str(oracle_input_root),
            HashPart::Str(privacy_input_root),
            HashPart::Str(quantum_auth_root),
            HashPart::Str(determinism_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn vm_upgrade_envelope_id(
    contract_id: &str,
    old_policy_id: &str,
    new_policy_id: &str,
    migration_root: &str,
    authority_root: &str,
    proposed_at_height: u64,
    executable_at_height: u64,
) -> String {
    domain_hash(
        "VM-UPGRADE-ENVELOPE-ID",
        &[
            HashPart::Str(contract_id),
            HashPart::Str(old_policy_id),
            HashPart::Str(new_policy_id),
            HashPart::Str(migration_root),
            HashPart::Str(authority_root),
            HashPart::Int(proposed_at_height as i128),
            HashPart::Int(executable_at_height as i128),
        ],
        32,
    )
}

pub fn vm_label_root(operator_label: &str, label: &str) -> String {
    domain_hash(
        "VM-LABEL-ROOT",
        &[HashPart::Str(operator_label), HashPart::Str(label)],
        32,
    )
}

pub fn vm_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn vm_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn vm_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn vm_permission_root(values: &[VmPermission]) -> String {
    let mut records = values
        .iter()
        .map(|permission| permission.as_str())
        .collect::<Vec<_>>();
    records.sort();
    records.dedup();
    let leaves = records
        .iter()
        .map(|permission| json!({ "permission": permission }))
        .collect::<Vec<_>>();
    merkle_root("VM-PERMISSION-ROOT", &leaves)
}

pub fn vm_host_function_root(values: &[VmHostFunction]) -> String {
    let mut records = values
        .iter()
        .map(|function| function.as_str())
        .collect::<Vec<_>>();
    records.sort();
    records.dedup();
    let leaves = records
        .iter()
        .map(|function| json!({ "host_function": function }))
        .collect::<Vec<_>>();
    merkle_root("VM-HOST-FUNCTION-ROOT", &leaves)
}

pub fn vm_abi_method_root(values: &[VmAbiMethod]) -> String {
    let leaves = values
        .iter()
        .map(VmAbiMethod::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-ABI-METHOD-ROOT", &leaves)
}

pub fn vm_module_policy_root(values: &[VmModulePolicy]) -> String {
    let leaves = values
        .iter()
        .map(VmModulePolicy::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-MODULE-POLICY-ROOT", &leaves)
}

pub fn vm_storage_access_root(values: &[VmStorageAccess]) -> String {
    let leaves = values
        .iter()
        .map(VmStorageAccess::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-STORAGE-ACCESS-ROOT", &leaves)
}

pub fn vm_storage_overlay_root(values: &[VmStorageOverlay]) -> String {
    let leaves = values
        .iter()
        .map(VmStorageOverlay::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-STORAGE-OVERLAY-ROOT", &leaves)
}

pub fn vm_syscall_trace_root(values: &[VmSyscallTrace]) -> String {
    let leaves = values
        .iter()
        .map(VmSyscallTrace::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-SYSCALL-TRACE-ROOT", &leaves)
}

pub fn vm_meter_snapshot_root(values: &[VmMeterSnapshot]) -> String {
    let leaves = values
        .iter()
        .map(VmMeterSnapshot::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-METER-SNAPSHOT-ROOT", &leaves)
}

pub fn vm_execution_frame_root(values: &[VmExecutionFrame]) -> String {
    let leaves = values
        .iter()
        .map(VmExecutionFrame::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-EXECUTION-FRAME-ROOT", &leaves)
}

pub fn vm_host_receipt_root(values: &[VmHostReceipt]) -> String {
    let leaves = values
        .iter()
        .map(VmHostReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-HOST-RECEIPT-ROOT", &leaves)
}

pub fn vm_replay_witness_root(values: &[VmReplayWitness]) -> String {
    let leaves = values
        .iter()
        .map(VmReplayWitness::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-REPLAY-WITNESS-ROOT", &leaves)
}

pub fn vm_upgrade_envelope_root(values: &[VmUpgradeEnvelope]) -> String {
    let leaves = values
        .iter()
        .map(VmUpgradeEnvelope::public_record)
        .collect::<Vec<_>>();
    merkle_root("VM-UPGRADE-ENVELOPE-ROOT", &leaves)
}

pub fn vm_abi_method_root_from_map(values: &BTreeMap<String, VmAbiMethod>) -> String {
    vm_abi_method_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn vm_module_policy_root_from_map(values: &BTreeMap<String, VmModulePolicy>) -> String {
    vm_module_policy_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn vm_storage_access_root_from_map(values: &BTreeMap<String, VmStorageAccess>) -> String {
    vm_storage_access_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn vm_storage_overlay_root_from_map(values: &BTreeMap<String, VmStorageOverlay>) -> String {
    vm_storage_overlay_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn vm_syscall_trace_root_from_map(values: &BTreeMap<String, VmSyscallTrace>) -> String {
    vm_syscall_trace_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn vm_meter_snapshot_root_from_map(values: &BTreeMap<String, VmMeterSnapshot>) -> String {
    vm_meter_snapshot_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn vm_execution_frame_root_from_map(values: &BTreeMap<String, VmExecutionFrame>) -> String {
    vm_execution_frame_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn vm_host_receipt_root_from_map(values: &BTreeMap<String, VmHostReceipt>) -> String {
    vm_host_receipt_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn vm_replay_witness_root_from_map(values: &BTreeMap<String, VmReplayWitness>) -> String {
    vm_replay_witness_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn vm_upgrade_envelope_root_from_map(values: &BTreeMap<String, VmUpgradeEnvelope>) -> String {
    vm_upgrade_envelope_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn contract_vm_state_root_from_record(record: &Value) -> String {
    vm_payload_root("CONTRACT-VM-STATE-ROOT", record)
}

fn ensure_non_empty(value: &str, field: &str) -> ContractVmResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> ContractVmResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}
