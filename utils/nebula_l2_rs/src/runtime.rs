use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    contracts::contract_call_fee,
    crypto_policy::{sign_authorization, verify_authorization, Authorization},
    defi::{build_privacy_proof, PrivacyProof},
    fees::FeeMarketResource,
    hash::{domain_hash, json_size, merkle_root, HashPart},
    CHAIN_ID, DEVNET_PRIVACY_PROOF_BYTES,
};

pub const WASM_RUNTIME_VERSION: &str = "nebula-wasm-deterministic-v0";
pub const WASM_MAX_MEMORY_PAGES: u64 = 64;
pub const WASM_MIN_FUEL_LIMIT: u64 = 1;
pub const WASM_REQUIRED_EXPORT: &str = "execute";

pub type RuntimeResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmModuleManifest {
    pub module_id: String,
    pub wasm_hash: String,
    pub abi_hash: String,
    pub runtime_version: String,
    pub owner_label: String,
    pub max_fuel_per_call: u64,
    pub max_memory_pages: u64,
    pub host_permissions: Vec<String>,
    pub imported_host_function_root: String,
    pub exported_function_root: String,
    pub validation_hash: String,
    pub deterministic_profile_hash: String,
    pub upgrade_policy_hash: String,
    pub authorization: Authorization,
}

impl WasmModuleManifest {
    pub fn host_permission_root(&self) -> String {
        merkle_root(
            "WASM-HOST-PERMISSION",
            &self
                .normalized_host_permissions()
                .iter()
                .map(|permission| Value::String(permission.clone()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn normalized_host_permissions(&self) -> Vec<String> {
        let mut permissions = self.host_permissions.clone();
        permissions.sort();
        permissions.dedup();
        permissions
    }

    pub fn id_payload(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "wasm_hash": self.wasm_hash,
            "abi_hash": self.abi_hash,
            "runtime_version": self.runtime_version,
            "owner_commitment": wasm_owner_commitment(&self.owner_label),
            "max_fuel_per_call": self.max_fuel_per_call,
            "max_memory_pages": self.max_memory_pages,
            "host_permission_root": self.host_permission_root(),
            "imported_host_function_root": self.imported_host_function_root,
            "exported_function_root": self.exported_function_root,
            "validation_hash": self.validation_hash,
            "deterministic_profile_hash": self.deterministic_profile_hash,
            "upgrade_policy_hash": self.upgrade_policy_hash,
        })
    }

    pub fn expected_module_id(&self) -> String {
        domain_hash("WASM-MODULE-ID", &[HashPart::Json(&self.id_payload())], 32)
    }

    pub fn unsigned_record(&self) -> Value {
        let mut record = self.id_payload();
        let object = record.as_object_mut().expect("wasm module manifest object");
        object.insert(
            "kind".to_string(),
            Value::String("wasm_module_manifest".to_string()),
        );
        object.insert(
            "module_id".to_string(),
            Value::String(self.module_id.clone()),
        );
        object.insert(
            "host_permissions".to_string(),
            json!(self.normalized_host_permissions()),
        );
        object.insert(
            "required_export".to_string(),
            Value::String(WASM_REQUIRED_EXPORT.to_string()),
        );
        record
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("wasm module public record object");
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("wasm module state record object")
            .insert(
                "owner_label".to_string(),
                Value::String(self.owner_label.clone()),
            );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmContractInstance {
    pub contract_id: String,
    pub module_id: String,
    pub deployer_label: String,
    pub storage: Value,
    pub storage_root: String,
    pub version: u64,
    pub active: bool,
}

impl WasmContractInstance {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wasm_contract_instance",
            "contract_id": self.contract_id,
            "module_id": self.module_id,
            "deployer_commitment": wasm_owner_commitment(&self.deployer_label),
            "storage_root": self.storage_root,
            "version": self.version,
            "active": self.active,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("wasm instance state record object");
        object.insert(
            "deployer_label".to_string(),
            Value::String(self.deployer_label.clone()),
        );
        object.insert("storage".to_string(), self.storage.clone());
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmRuntimeCallRequest {
    pub contract_id: String,
    pub entrypoint: String,
    pub args: Value,
    pub signer_label: String,
    pub fuel_limit: u64,
    pub private_args: bool,
    pub fee_asset_id: String,
    pub paymaster_id: String,
    pub max_fee: Option<u64>,
}

impl WasmRuntimeCallRequest {
    pub fn new(
        contract_id: impl Into<String>,
        entrypoint: impl Into<String>,
        args: Value,
        signer_label: impl Into<String>,
        fuel_limit: u64,
    ) -> Self {
        Self {
            contract_id: contract_id.into(),
            entrypoint: entrypoint.into(),
            args,
            signer_label: signer_label.into(),
            fuel_limit,
            private_args: false,
            fee_asset_id: String::new(),
            paymaster_id: String::new(),
            max_fee: None,
        }
    }

    pub fn private_args(mut self, private_args: bool) -> Self {
        self.private_args = private_args;
        self
    }

    pub fn fee_asset(mut self, fee_asset_id: impl Into<String>, max_fee: Option<u64>) -> Self {
        self.fee_asset_id = fee_asset_id.into();
        self.max_fee = max_fee;
        self
    }

    pub fn paymaster(mut self, paymaster_id: impl Into<String>) -> Self {
        self.paymaster_id = paymaster_id.into();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmRuntimeCall {
    pub contract_id: String,
    pub module_id: String,
    pub entrypoint: String,
    pub args: Value,
    pub private_args: bool,
    pub args_commitment: String,
    pub fuel_limit: u64,
    pub fuel_used: u64,
    pub memory_pages: u64,
    pub fee_asset_id: String,
    pub fee: u64,
    pub paymaster_id: String,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: Option<PrivacyProof>,
}

impl WasmRuntimeCall {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "wasm_contract_call",
            "runtime_version": WASM_RUNTIME_VERSION,
            "contract_id": self.contract_id,
            "module_id": self.module_id,
            "entrypoint": self.entrypoint,
            "args": self.args,
            "private_args": self.private_args,
            "args_commitment": self.args_commitment,
            "fuel_limit": self.fuel_limit,
            "fuel_used": self.fuel_used,
            "memory_pages": self.memory_pages,
            "fee_asset_id": self.fee_asset_id,
            "fee": self.fee,
            "paymaster_id": self.paymaster_id,
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.as_ref().map(PrivacyProof::public_record),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record.as_object_mut().expect("wasm call record object");
        if self.private_args {
            object.remove("args");
        }
        object.insert(
            "caller_commitment".to_string(),
            Value::String(wasm_caller_commitment(&self.signer_label)),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("wasm call state record object");
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert(
            "auth_public_key".to_string(),
            Value::String(self.authorization.auth_public_key.clone()),
        );
        object.insert(
            "auth_transcript_hash".to_string(),
            Value::String(self.authorization.auth_transcript_hash.clone()),
        );
        object.insert(
            "auth_signature".to_string(),
            Value::String(self.authorization.auth_signature.clone()),
        );
        if let Some(proof) = &self.privacy_proof {
            object.insert("proof_bundle".to_string(), proof.state_record());
        }
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmHostCall {
    pub call_index: u64,
    pub host_function: String,
    pub input_commitment: String,
    pub output_commitment: String,
    pub fuel_used: u64,
    pub privacy_boundary: String,
}

impl WasmHostCall {
    pub fn public_record(&self) -> Value {
        json!({
            "call_index": self.call_index,
            "host_function": self.host_function,
            "input_commitment": self.input_commitment,
            "output_commitment": self.output_commitment,
            "fuel_used": self.fuel_used,
            "privacy_boundary": self.privacy_boundary,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmStorageDelta {
    pub delta_index: u64,
    pub key_commitment: String,
    pub value_commitment: String,
    pub storage_root_before: String,
    pub storage_root_after: String,
    pub private_value: bool,
}

impl WasmStorageDelta {
    pub fn public_record(&self) -> Value {
        json!({
            "delta_index": self.delta_index,
            "key_commitment": self.key_commitment,
            "value_commitment": self.value_commitment,
            "storage_root_before": self.storage_root_before,
            "storage_root_after": self.storage_root_after,
            "private_value": self.private_value,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmRuntimeEvent {
    pub event_index: u64,
    pub event_name: String,
    pub data_commitment: String,
    pub public_data: Value,
}

impl WasmRuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_index": self.event_index,
            "event_name": self.event_name,
            "data_commitment": self.data_commitment,
            "public_data": self.public_data,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmRuntimeExecutionReceipt {
    pub receipt_id: String,
    pub tx_hash: String,
    pub contract_id: String,
    pub module_id: String,
    pub runtime_version: String,
    pub entrypoint: String,
    pub args_commitment: String,
    pub private_args: bool,
    pub caller_commitment: String,
    pub fuel_limit: u64,
    pub fuel_used: u64,
    pub memory_pages: u64,
    pub storage_root_before: String,
    pub storage_root_after: String,
    pub host_call_root: String,
    pub storage_delta_root: String,
    pub event_root: String,
    pub fee_asset_id: String,
    pub fee: u64,
    pub paymaster_id: String,
}

impl WasmRuntimeExecutionReceipt {
    pub fn id_payload(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "tx_hash": self.tx_hash,
            "contract_id": self.contract_id,
            "module_id": self.module_id,
            "runtime_version": self.runtime_version,
            "entrypoint": self.entrypoint,
            "args_commitment": self.args_commitment,
            "private_args": self.private_args,
            "caller_commitment": self.caller_commitment,
            "fuel_limit": self.fuel_limit,
            "fuel_used": self.fuel_used,
            "memory_pages": self.memory_pages,
            "storage_root_before": self.storage_root_before,
            "storage_root_after": self.storage_root_after,
            "host_call_root": self.host_call_root,
            "storage_delta_root": self.storage_delta_root,
            "event_root": self.event_root,
            "fee_asset_id": self.fee_asset_id,
            "fee": self.fee,
            "paymaster_id": self.paymaster_id,
        })
    }

    pub fn expected_receipt_id(&self) -> String {
        domain_hash(
            "WASM-RUNTIME-EXECUTION-RECEIPT-ID",
            &[HashPart::Json(&self.id_payload())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.id_payload();
        let object = record
            .as_object_mut()
            .expect("wasm runtime receipt record object");
        object.insert(
            "kind".to_string(),
            Value::String("wasm_runtime_execution_receipt".to_string()),
        );
        object.insert(
            "receipt_id".to_string(),
            Value::String(self.receipt_id.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedWasmRuntimeCall {
    pub call: WasmRuntimeCall,
    pub receipt: WasmRuntimeExecutionReceipt,
    pub host_calls: Vec<WasmHostCall>,
    pub storage_deltas: Vec<WasmStorageDelta>,
    pub events: Vec<WasmRuntimeEvent>,
    pub instance_before: WasmContractInstance,
    pub instance_after: WasmContractInstance,
    pub fee_resource: FeeMarketResource,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmRuntimeState {
    pub modules: BTreeMap<String, WasmModuleManifest>,
    pub instances: BTreeMap<String, WasmContractInstance>,
    pub receipts: BTreeMap<String, WasmRuntimeExecutionReceipt>,
    pub height: u64,
}

impl WasmRuntimeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn deploy_module(
        &mut self,
        owner_label: &str,
        wasm_bytes: &[u8],
        abi: &Value,
        max_fuel_per_call: u64,
        max_memory_pages: u64,
        host_permissions: Vec<String>,
    ) -> RuntimeResult<WasmModuleManifest> {
        if wasm_bytes.is_empty() {
            return Err("wasm module bytes are required".to_string());
        }
        if max_fuel_per_call < WASM_MIN_FUEL_LIMIT {
            return Err("wasm max_fuel_per_call must be positive".to_string());
        }
        if max_memory_pages == 0 || max_memory_pages > WASM_MAX_MEMORY_PAGES {
            return Err("wasm max_memory_pages exceeds runtime policy".to_string());
        }
        let host_permissions = normalize_and_validate_host_permissions(host_permissions)?;
        let validation = validate_wasm_module(wasm_bytes, &host_permissions, max_memory_pages)?;
        let wasm_hash = domain_hash("WASM-BYTES", &[HashPart::Bytes(wasm_bytes)], 32);
        let abi_hash = domain_hash("WASM-ABI", &[HashPart::Json(abi)], 32);
        let deterministic_profile_hash = domain_hash(
            "WASM-DETERMINISTIC-PROFILE",
            &[
                HashPart::Str(WASM_RUNTIME_VERSION),
                HashPart::Int(max_fuel_per_call as i128),
                HashPart::Int(max_memory_pages as i128),
                HashPart::Json(&json!(host_permissions)),
            ],
            32,
        );
        let upgrade_policy_hash = domain_hash(
            "WASM-UPGRADE-POLICY",
            &[
                HashPart::Str(owner_label),
                HashPart::Str(&wasm_hash),
                HashPart::Str(&abi_hash),
            ],
            32,
        );
        let mut module = WasmModuleManifest {
            module_id: String::new(),
            wasm_hash,
            abi_hash,
            runtime_version: WASM_RUNTIME_VERSION.to_string(),
            owner_label: owner_label.to_string(),
            max_fuel_per_call,
            max_memory_pages,
            host_permissions,
            imported_host_function_root: validation.imported_host_function_root,
            exported_function_root: validation.exported_function_root,
            validation_hash: validation.validation_hash,
            deterministic_profile_hash,
            upgrade_policy_hash,
            authorization: empty_authorization(),
        };
        module.module_id = module.expected_module_id();
        module.authorization = sign_authorization(
            owner_label,
            "wasm_module_manifest",
            &module.unsigned_record(),
        );
        if !verify_authorization(
            owner_label,
            "wasm_module_manifest",
            &module.unsigned_record(),
            &module.authorization,
        ) {
            return Err("invalid wasm module authorization".to_string());
        }
        self.modules
            .insert(module.module_id.clone(), module.clone());
        Ok(module)
    }

    pub fn instantiate_contract(
        &mut self,
        module_id: &str,
        deployer_label: &str,
        initial_storage: Value,
    ) -> RuntimeResult<WasmContractInstance> {
        if !initial_storage.is_object() {
            return Err("wasm initial storage must be an object".to_string());
        }
        let module = self.require_module(module_id)?;
        let storage_root = wasm_storage_root(module_id, &initial_storage);
        let contract_id = domain_hash(
            "WASM-CONTRACT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(module_id),
                HashPart::Str(&wasm_owner_commitment(deployer_label)),
                HashPart::Str(&storage_root),
                HashPart::Int(self.instances.len() as i128),
            ],
            32,
        );
        let instance = WasmContractInstance {
            contract_id: contract_id.clone(),
            module_id: module.module_id.clone(),
            deployer_label: deployer_label.to_string(),
            storage: initial_storage,
            storage_root,
            version: 1,
            active: true,
        };
        self.instances.insert(contract_id, instance.clone());
        Ok(instance)
    }

    pub fn execute_call(
        &mut self,
        request: WasmRuntimeCallRequest,
    ) -> RuntimeResult<AppliedWasmRuntimeCall> {
        let instance_before = self.require_instance(&request.contract_id)?.clone();
        if !instance_before.active {
            return Err("wasm contract instance is inactive".to_string());
        }
        let module = self.require_module(&instance_before.module_id)?.clone();
        if request.fuel_limit == 0 || request.fuel_limit > module.max_fuel_per_call {
            return Err("wasm call fuel_limit exceeds module policy".to_string());
        }
        if !request.paymaster_id.is_empty() && request.fee_asset_id.is_empty() {
            return Err("wasm paymaster call requires fee_asset_id".to_string());
        }

        let args_commitment = wasm_args_commitment(
            &request.contract_id,
            &module.module_id,
            &request.entrypoint,
            &request.args,
        );
        let simulation =
            simulate_wasm_execution(&module, &instance_before, &request, &args_commitment)?;
        if simulation.fuel_used > request.fuel_limit {
            return Err("wasm call exceeds fuel limit".to_string());
        }
        let fee = if request.fee_asset_id.is_empty() && request.paymaster_id.is_empty() {
            0
        } else {
            contract_call_fee(simulation.fuel_used)?
        };
        if let Some(max_fee) = request.max_fee {
            if fee > max_fee {
                return Err("wasm call fee exceeds max_fee".to_string());
            }
        }

        let proof_system = "devnet-mock-wasm-runtime-proof".to_string();
        let mut call = WasmRuntimeCall {
            contract_id: request.contract_id.clone(),
            module_id: module.module_id.clone(),
            entrypoint: request.entrypoint.clone(),
            args: request.args.clone(),
            private_args: request.private_args,
            args_commitment,
            fuel_limit: request.fuel_limit,
            fuel_used: simulation.fuel_used,
            memory_pages: simulation.memory_pages,
            fee_asset_id: request.fee_asset_id.clone(),
            fee,
            paymaster_id: request.paymaster_id.clone(),
            signer_label: request.signer_label.clone(),
            authorization: empty_authorization(),
            proof_system,
            privacy_proof: None,
        };
        if call.private_args {
            let public_inputs = json!({
                "kind": "wasm_runtime_private_call",
                "contract_id": call.contract_id,
                "module_id": call.module_id,
                "entrypoint": call.entrypoint,
                "args_commitment": call.args_commitment,
                "storage_root_before": instance_before.storage_root,
                "storage_root_after": simulation.storage_root_after,
                "host_call_root": simulation.host_call_root,
                "storage_delta_root": simulation.storage_delta_root,
                "event_root": simulation.event_root,
                "fee_asset_id": call.fee_asset_id,
                "fee": call.fee,
                "paymaster_id": call.paymaster_id,
            });
            let private_witnesses = json!({
                "args": call.args,
                "signer_label": call.signer_label,
            });
            call.privacy_proof = Some(build_privacy_proof(
                &call.proof_system,
                &public_inputs,
                &private_witnesses,
            ));
        }
        call.authorization = sign_authorization(
            &call.signer_label,
            "wasm_contract_call",
            &call.unsigned_record(),
        );
        if !verify_authorization(
            &call.signer_label,
            "wasm_contract_call",
            &call.unsigned_record(),
            &call.authorization,
        ) {
            return Err("invalid wasm call authorization".to_string());
        }

        let tx_hash = domain_hash(
            "WASM-CONTRACT-CALL-TX",
            &[HashPart::Json(&call.public_record())],
            32,
        );
        let mut receipt = WasmRuntimeExecutionReceipt {
            receipt_id: String::new(),
            tx_hash,
            contract_id: call.contract_id.clone(),
            module_id: call.module_id.clone(),
            runtime_version: WASM_RUNTIME_VERSION.to_string(),
            entrypoint: call.entrypoint.clone(),
            args_commitment: call.args_commitment.clone(),
            private_args: call.private_args,
            caller_commitment: wasm_caller_commitment(&call.signer_label),
            fuel_limit: call.fuel_limit,
            fuel_used: call.fuel_used,
            memory_pages: call.memory_pages,
            storage_root_before: instance_before.storage_root.clone(),
            storage_root_after: simulation.storage_root_after.clone(),
            host_call_root: simulation.host_call_root.clone(),
            storage_delta_root: simulation.storage_delta_root.clone(),
            event_root: simulation.event_root.clone(),
            fee_asset_id: call.fee_asset_id.clone(),
            fee: call.fee,
            paymaster_id: call.paymaster_id.clone(),
        };
        receipt.receipt_id = receipt.expected_receipt_id();
        verify_wasm_execution_receipt(&receipt, &call)?;

        let instance_after = WasmContractInstance {
            storage: simulation.storage_after,
            storage_root: simulation.storage_root_after,
            ..instance_before.clone()
        };
        self.instances
            .insert(instance_after.contract_id.clone(), instance_after.clone());
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        let fee_resource = fee_market_resource_for_wasm_call(&call, &receipt);
        Ok(AppliedWasmRuntimeCall {
            call,
            receipt,
            host_calls: simulation.host_calls,
            storage_deltas: simulation.storage_deltas,
            events: simulation.events,
            instance_before,
            instance_after,
            fee_resource,
        })
    }

    pub fn module_root(&self) -> String {
        let leaves = self
            .modules
            .values()
            .map(WasmModuleManifest::public_record)
            .collect::<Vec<_>>();
        merkle_root("WASM-MODULE", &leaves)
    }

    pub fn instance_root(&self) -> String {
        let leaves = self
            .instances
            .values()
            .map(WasmContractInstance::public_record)
            .collect::<Vec<_>>();
        merkle_root("WASM-CONTRACT-INSTANCE", &leaves)
    }

    pub fn receipt_root(&self) -> String {
        let leaves = self
            .receipts
            .values()
            .map(WasmRuntimeExecutionReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("WASM-RUNTIME-RECEIPT", &leaves)
    }

    pub fn runtime_root(&self) -> String {
        merkle_root(
            "WASM-RUNTIME",
            &[json!({
                "module_count": self.modules.len(),
                "module_root": self.module_root(),
                "instance_count": self.instances.len(),
                "instance_root": self.instance_root(),
                "receipt_count": self.receipts.len(),
                "receipt_root": self.receipt_root(),
            })],
        )
    }

    fn require_module(&self, module_id: &str) -> RuntimeResult<&WasmModuleManifest> {
        self.modules
            .get(module_id)
            .ok_or_else(|| "unknown wasm module".to_string())
    }

    fn require_instance(&self, contract_id: &str) -> RuntimeResult<&WasmContractInstance> {
        self.instances
            .get(contract_id)
            .ok_or_else(|| "unknown wasm contract instance".to_string())
    }
}

#[derive(Clone, Debug)]
struct WasmExecutionSimulation {
    storage_after: Value,
    storage_root_after: String,
    host_calls: Vec<WasmHostCall>,
    storage_deltas: Vec<WasmStorageDelta>,
    events: Vec<WasmRuntimeEvent>,
    host_call_root: String,
    storage_delta_root: String,
    event_root: String,
    fuel_used: u64,
    memory_pages: u64,
}

fn simulate_wasm_execution(
    module: &WasmModuleManifest,
    instance: &WasmContractInstance,
    request: &WasmRuntimeCallRequest,
    args_commitment: &str,
) -> RuntimeResult<WasmExecutionSimulation> {
    let mut storage_after = instance.storage.clone();
    let mut host_calls = Vec::new();
    let mut storage_deltas = Vec::new();
    let mut events = Vec::new();

    if module
        .host_permissions
        .contains(&"storage_read".to_string())
    {
        host_calls.push(WasmHostCall {
            call_index: host_calls.len() as u64,
            host_function: "storage_read".to_string(),
            input_commitment: domain_hash(
                "WASM-HOST-INPUT",
                &[
                    HashPart::Str(&instance.contract_id),
                    HashPart::Str(&request.entrypoint),
                    HashPart::Str(args_commitment),
                ],
                32,
            ),
            output_commitment: instance.storage_root.clone(),
            fuel_used: 5,
            privacy_boundary: if request.private_args {
                "committed".to_string()
            } else {
                "public".to_string()
            },
        });
    }

    if request.args.get("write_key").is_some()
        || module
            .host_permissions
            .contains(&"storage_write".to_string())
    {
        if !module
            .host_permissions
            .contains(&"storage_write".to_string())
        {
            return Err("wasm module lacks storage_write permission".to_string());
        }
        let key = request
            .args
            .get("write_key")
            .and_then(Value::as_str)
            .unwrap_or(&request.entrypoint)
            .to_string();
        let value = request
            .args
            .get("write_value")
            .cloned()
            .unwrap_or_else(|| json!({"args_commitment": args_commitment}));
        let object = storage_after
            .as_object_mut()
            .ok_or_else(|| "wasm storage must be an object".to_string())?;
        let before_root = instance.storage_root.clone();
        object.insert(key.clone(), value.clone());
        let after_root = wasm_storage_root(&instance.module_id, &storage_after);
        let private_value = request.private_args
            || request
                .args
                .get("private_write")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        storage_deltas.push(WasmStorageDelta {
            delta_index: 0,
            key_commitment: domain_hash(
                "WASM-STORAGE-KEY",
                &[HashPart::Str(&instance.contract_id), HashPart::Str(&key)],
                32,
            ),
            value_commitment: domain_hash("WASM-STORAGE-VALUE", &[HashPart::Json(&value)], 32),
            storage_root_before: before_root,
            storage_root_after: after_root,
            private_value,
        });
    }

    if module
        .host_permissions
        .contains(&"asset_transfer".to_string())
        && request.args.get("asset_id").is_some()
    {
        host_calls.push(WasmHostCall {
            call_index: host_calls.len() as u64,
            host_function: "asset_transfer".to_string(),
            input_commitment: domain_hash(
                "WASM-ASSET-HOST-INPUT",
                &[
                    HashPart::Str(&instance.contract_id),
                    HashPart::Json(&json!({
                        "asset_id": request.args.get("asset_id"),
                        "amount": request.args.get("amount"),
                    })),
                ],
                32,
            ),
            output_commitment: domain_hash(
                "WASM-ASSET-HOST-OUTPUT",
                &[HashPart::Str(args_commitment)],
                32,
            ),
            fuel_used: 9,
            privacy_boundary: "committed".to_string(),
        });
    }

    if module.host_permissions.contains(&"emit_event".to_string()) {
        let public_data = if request.private_args {
            json!({
                "private_args": true,
                "args_commitment": args_commitment,
                "caller_commitment": wasm_caller_commitment(&request.signer_label),
            })
        } else {
            json!({
                "args": request.args,
                "caller_commitment": wasm_caller_commitment(&request.signer_label),
            })
        };
        events.push(WasmRuntimeEvent {
            event_index: 0,
            event_name: format!("{}.executed", request.entrypoint),
            data_commitment: domain_hash("WASM-EVENT-DATA", &[HashPart::Json(&public_data)], 32),
            public_data,
        });
    }

    let storage_root_after = if let Some(delta) = storage_deltas.last() {
        delta.storage_root_after.clone()
    } else {
        instance.storage_root.clone()
    };
    let host_call_root = merkle_root(
        "WASM-HOST-CALL",
        &host_calls
            .iter()
            .map(WasmHostCall::public_record)
            .collect::<Vec<_>>(),
    );
    let storage_delta_root = merkle_root(
        "WASM-STORAGE-DELTA",
        &storage_deltas
            .iter()
            .map(WasmStorageDelta::public_record)
            .collect::<Vec<_>>(),
    );
    let event_root = merkle_root(
        "WASM-RUNTIME-EVENT",
        &events
            .iter()
            .map(WasmRuntimeEvent::public_record)
            .collect::<Vec<_>>(),
    );
    let host_fuel = host_calls.iter().map(|call| call.fuel_used).sum::<u64>();
    let fuel_used = 25
        + json_size(&request.args) as u64
        + host_fuel
        + storage_deltas.len() as u64 * 11
        + events.len() as u64 * 5;
    let memory_pages = std::cmp::max(1, json_size(&storage_after) as u64 / 65_536 + 1);
    if memory_pages > module.max_memory_pages {
        return Err("wasm execution exceeds memory-page policy".to_string());
    }
    Ok(WasmExecutionSimulation {
        storage_after,
        storage_root_after,
        host_calls,
        storage_deltas,
        events,
        host_call_root,
        storage_delta_root,
        event_root,
        fuel_used,
        memory_pages,
    })
}

pub fn wasm_storage_root(module_id: &str, storage: &Value) -> String {
    domain_hash(
        "WASM-STORAGE-ROOT",
        &[HashPart::Str(module_id), HashPart::Json(storage)],
        32,
    )
}

pub fn wasm_args_commitment(
    contract_id: &str,
    module_id: &str,
    entrypoint: &str,
    args: &Value,
) -> String {
    domain_hash(
        "WASM-CALL-ARGS",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(module_id),
            HashPart::Str(entrypoint),
            HashPart::Json(args),
        ],
        32,
    )
}

pub fn wasm_owner_commitment(label: &str) -> String {
    domain_hash("WASM-OWNER", &[HashPart::Str(label)], 32)
}

pub fn wasm_caller_commitment(label: &str) -> String {
    domain_hash("WASM-CALLER", &[HashPart::Str(label)], 32)
}

pub fn verify_wasm_execution_receipt(
    receipt: &WasmRuntimeExecutionReceipt,
    call: &WasmRuntimeCall,
) -> RuntimeResult<()> {
    if receipt.receipt_id != receipt.expected_receipt_id() {
        return Err("wasm runtime receipt id mismatch".to_string());
    }
    if receipt.runtime_version != WASM_RUNTIME_VERSION {
        return Err("wasm runtime version mismatch".to_string());
    }
    if receipt.contract_id != call.contract_id || receipt.module_id != call.module_id {
        return Err("wasm runtime receipt call target mismatch".to_string());
    }
    if receipt.args_commitment != call.args_commitment {
        return Err("wasm runtime receipt args commitment mismatch".to_string());
    }
    if receipt.fuel_limit != call.fuel_limit
        || receipt.fuel_used != call.fuel_used
        || receipt.fuel_used == 0
        || receipt.fuel_used > receipt.fuel_limit
    {
        return Err("wasm runtime receipt fuel mismatch".to_string());
    }
    if receipt.caller_commitment != wasm_caller_commitment(&call.signer_label) {
        return Err("wasm runtime receipt caller mismatch".to_string());
    }
    Ok(())
}

pub fn fee_market_resource_for_wasm_call(
    call: &WasmRuntimeCall,
    receipt: &WasmRuntimeExecutionReceipt,
) -> FeeMarketResource {
    let mut fee_asset_ids = Vec::new();
    if !call.fee_asset_id.is_empty() {
        fee_asset_ids.push(call.fee_asset_id.clone());
    }
    let mut fee_lanes = vec![
        ("operation".to_string(), "wasm_contract_call".to_string()),
        ("runtime".to_string(), WASM_RUNTIME_VERSION.to_string()),
        ("contract".to_string(), call.contract_id.clone()),
        ("wasm_module".to_string(), call.module_id.clone()),
    ];
    if !call.paymaster_id.is_empty() {
        fee_lanes.push(("paymaster".to_string(), call.paymaster_id.clone()));
    }
    if !call.fee_asset_id.is_empty() {
        fee_lanes.push(("asset".to_string(), call.fee_asset_id.clone()));
    }
    FeeMarketResource {
        public_record: json!({
            "kind": "wasm_contract_call",
            "call": call.public_record(),
            "receipt": receipt.public_record(),
        }),
        execution_fuel: call.fuel_used,
        privacy_proof_count: u64::from(call.privacy_proof.is_some()),
        contract_call_count: 1,
        observed_fee_units: call.fee,
        estimated_proof_bytes: if call.privacy_proof.is_some() {
            DEVNET_PRIVACY_PROOF_BYTES
        } else {
            0
        },
        authorization_count: 1,
        fee_asset_ids,
        fee_lanes,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmModuleValidation {
    pub imported_host_functions: Vec<String>,
    pub exported_functions: Vec<String>,
    pub declared_memory_max_pages: u64,
    pub local_function_count: u64,
    pub code_body_count: u64,
    pub imported_host_function_root: String,
    pub exported_function_root: String,
    pub validation_hash: String,
}

pub fn validate_wasm_module(
    wasm_bytes: &[u8],
    requested_host_permissions: &[String],
    manifest_max_memory_pages: u64,
) -> RuntimeResult<WasmModuleValidation> {
    if wasm_bytes.len() < 8 || &wasm_bytes[0..4] != b"\0asm" {
        return Err("invalid wasm module magic".to_string());
    }
    if wasm_bytes[4..8] != [1, 0, 0, 0] {
        return Err("unsupported wasm binary version".to_string());
    }

    let mut cursor = WasmCursor::new(&wasm_bytes[8..]);
    let mut last_section_id = 0_u8;
    let mut imported_host_functions = Vec::new();
    let mut exported_functions = Vec::new();
    let mut declared_memory_max_pages = 0_u64;
    let mut local_function_count = 0_u64;
    let mut code_body_count = 0_u64;

    while !cursor.is_empty() {
        let section_id = cursor.read_u8()?;
        let section_size = cursor.read_var_u32()? as usize;
        let section = cursor.read_slice(section_size)?;
        if section_id != 0 {
            if section_id <= last_section_id {
                return Err("wasm sections must use canonical order".to_string());
            }
            last_section_id = section_id;
        }
        let mut section_cursor = WasmCursor::new(section);
        match section_id {
            0 => {}
            2 => {
                imported_host_functions = parse_import_section(&mut section_cursor)?;
            }
            3 => {
                local_function_count = section_cursor.read_var_u32()? as u64;
                for _ in 0..local_function_count {
                    section_cursor.read_var_u32()?;
                }
            }
            5 => {
                declared_memory_max_pages = parse_memory_section(&mut section_cursor)?;
            }
            7 => {
                exported_functions = parse_export_section(&mut section_cursor)?;
            }
            10 => {
                code_body_count = section_cursor.read_var_u32()? as u64;
                for _ in 0..code_body_count {
                    let body_size = section_cursor.read_var_u32()? as usize;
                    section_cursor.read_slice(body_size)?;
                }
            }
            1 | 4 | 6 | 8 | 9 | 11 | 12 => {}
            _ => return Err(format!("unsupported wasm section id: {section_id}")),
        }
        if !section_cursor.is_empty() && !matches!(section_id, 1 | 4 | 6 | 8 | 9 | 11 | 12) {
            return Err(format!("trailing bytes in wasm section {section_id}"));
        }
    }

    imported_host_functions.sort();
    imported_host_functions.dedup();
    exported_functions.sort();
    exported_functions.dedup();

    if !exported_functions.contains(&WASM_REQUIRED_EXPORT.to_string()) {
        return Err(format!(
            "wasm module must export required function: {WASM_REQUIRED_EXPORT}"
        ));
    }
    if local_function_count == 0 {
        return Err("wasm module must define at least one local function".to_string());
    }
    if code_body_count != local_function_count {
        return Err("wasm function/code section count mismatch".to_string());
    }
    if declared_memory_max_pages > manifest_max_memory_pages {
        return Err("wasm declared memory exceeds manifest policy".to_string());
    }
    if declared_memory_max_pages > WASM_MAX_MEMORY_PAGES {
        return Err("wasm declared memory exceeds runtime policy".to_string());
    }

    let mut requested = requested_host_permissions.to_vec();
    requested.sort();
    requested.dedup();
    if imported_host_functions != requested {
        return Err("wasm host imports must match requested host permissions".to_string());
    }

    let imported_host_function_root = merkle_root(
        "WASM-IMPORTED-HOST-FUNCTION",
        &imported_host_functions
            .iter()
            .map(|function| Value::String(function.clone()))
            .collect::<Vec<_>>(),
    );
    let exported_function_root = merkle_root(
        "WASM-EXPORTED-FUNCTION",
        &exported_functions
            .iter()
            .map(|function| Value::String(function.clone()))
            .collect::<Vec<_>>(),
    );
    let validation_hash = domain_hash(
        "WASM-MODULE-VALIDATION",
        &[
            HashPart::Str(WASM_RUNTIME_VERSION),
            HashPart::Str(&imported_host_function_root),
            HashPart::Str(&exported_function_root),
            HashPart::Int(declared_memory_max_pages as i128),
            HashPart::Int(local_function_count as i128),
            HashPart::Int(code_body_count as i128),
        ],
        32,
    );

    Ok(WasmModuleValidation {
        imported_host_functions,
        exported_functions,
        declared_memory_max_pages,
        local_function_count,
        code_body_count,
        imported_host_function_root,
        exported_function_root,
        validation_hash,
    })
}

fn parse_import_section(cursor: &mut WasmCursor<'_>) -> RuntimeResult<Vec<String>> {
    let count = cursor.read_var_u32()?;
    let mut imports = Vec::new();
    for _ in 0..count {
        let module = cursor.read_name()?;
        let name = cursor.read_name()?;
        let kind = cursor.read_u8()?;
        match kind {
            0 => {
                cursor.read_var_u32()?;
                if module != "nebula" {
                    return Err("wasm imports must use the nebula host module".to_string());
                }
                if !is_supported_host_permission(&name) {
                    return Err(format!("unsupported wasm host import: {name}"));
                }
                imports.push(name);
            }
            1 => skip_table_type(cursor)?,
            2 => {
                return Err("wasm memory imports are not allowed".to_string());
            }
            3 => skip_global_type(cursor)?,
            _ => return Err("unsupported wasm import kind".to_string()),
        }
    }
    Ok(imports)
}

fn parse_memory_section(cursor: &mut WasmCursor<'_>) -> RuntimeResult<u64> {
    let count = cursor.read_var_u32()?;
    if count > 1 {
        return Err("wasm modules may declare at most one memory".to_string());
    }
    if count == 0 {
        return Ok(0);
    }
    let (min, max) = parse_limits(cursor)?;
    Ok(max.unwrap_or(min) as u64)
}

fn parse_export_section(cursor: &mut WasmCursor<'_>) -> RuntimeResult<Vec<String>> {
    let count = cursor.read_var_u32()?;
    let mut exports = Vec::new();
    for _ in 0..count {
        let name = cursor.read_name()?;
        let kind = cursor.read_u8()?;
        cursor.read_var_u32()?;
        if kind == 0 {
            exports.push(name);
        }
    }
    Ok(exports)
}

fn skip_table_type(cursor: &mut WasmCursor<'_>) -> RuntimeResult<()> {
    cursor.read_u8()?;
    parse_limits(cursor)?;
    Ok(())
}

fn skip_global_type(cursor: &mut WasmCursor<'_>) -> RuntimeResult<()> {
    cursor.read_u8()?;
    cursor.read_u8()?;
    Ok(())
}

fn parse_limits(cursor: &mut WasmCursor<'_>) -> RuntimeResult<(u32, Option<u32>)> {
    let flags = cursor.read_var_u32()?;
    match flags {
        0 => Ok((cursor.read_var_u32()?, None)),
        1 => Ok((cursor.read_var_u32()?, Some(cursor.read_var_u32()?))),
        _ => Err("unsupported wasm limits flags".to_string()),
    }
}

fn is_supported_host_permission(permission: &str) -> bool {
    matches!(
        permission,
        "storage_read"
            | "storage_write"
            | "emit_event"
            | "asset_transfer"
            | "privacy_verify"
            | "paymaster_debit"
    )
}

struct WasmCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WasmCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset >= self.bytes.len()
    }

    fn read_u8(&mut self) -> RuntimeResult<u8> {
        if self.offset >= self.bytes.len() {
            return Err("unexpected end of wasm bytes".to_string());
        }
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn read_slice(&mut self, len: usize) -> RuntimeResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "wasm section length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("wasm section exceeds module length".to_string());
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn read_var_u32(&mut self) -> RuntimeResult<u32> {
        let mut result = 0_u32;
        let mut shift = 0_u32;
        loop {
            let byte = self.read_u8()?;
            if shift >= 32 {
                if (byte & 0x7f) != 0 {
                    return Err("wasm varuint32 overflow".to_string());
                }
                if byte & 0x80 == 0 {
                    return Ok(result);
                }
                return Err("wasm varuint32 is too long".to_string());
            }
            result |= ((byte & 0x7f) as u32) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 35 {
                return Err("wasm varuint32 is too long".to_string());
            }
        }
    }

    fn read_name(&mut self) -> RuntimeResult<String> {
        let len = self.read_var_u32()? as usize;
        let bytes = self.read_slice(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|_| "wasm name is not valid utf-8".to_string())
    }
}

fn normalize_and_validate_host_permissions(permissions: Vec<String>) -> RuntimeResult<Vec<String>> {
    let mut normalized = permissions;
    normalized.sort();
    normalized.dedup();
    for permission in &normalized {
        if !is_supported_host_permission(permission) {
            return Err(format!("unsupported wasm host permission: {permission}"));
        }
    }
    Ok(normalized)
}

fn empty_authorization() -> Authorization {
    Authorization {
        signer_label: String::new(),
        auth_scheme: String::new(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blocks::{build_l2_block, BlockBuildInput, BlockStateRoots, Validator},
        crypto_policy::crypto_policy_root,
        fees::execution_profile_from_resources,
    };
    use serde_json::json;

    fn push_leb_u32(bytes: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn push_name(bytes: &mut Vec<u8>, name: &str) {
        push_leb_u32(bytes, name.len() as u32);
        bytes.extend_from_slice(name.as_bytes());
    }

    fn push_section(module: &mut Vec<u8>, section_id: u8, payload: &[u8]) {
        module.push(section_id);
        push_leb_u32(module, payload.len() as u32);
        module.extend_from_slice(payload);
    }

    fn test_wasm_module(imports: &[&str]) -> Vec<u8> {
        let mut module = b"\0asm\x01\0\0\0".to_vec();

        let type_section = vec![1, 0x60, 0, 0];
        push_section(&mut module, 1, &type_section);

        let mut import_section = Vec::new();
        push_leb_u32(&mut import_section, imports.len() as u32);
        for import in imports {
            push_name(&mut import_section, "nebula");
            push_name(&mut import_section, import);
            import_section.push(0);
            push_leb_u32(&mut import_section, 0);
        }
        push_section(&mut module, 2, &import_section);

        let function_section = vec![1, 0];
        push_section(&mut module, 3, &function_section);

        let mut export_section = Vec::new();
        push_leb_u32(&mut export_section, 1);
        push_name(&mut export_section, WASM_REQUIRED_EXPORT);
        export_section.push(0);
        push_leb_u32(&mut export_section, imports.len() as u32);
        push_section(&mut module, 7, &export_section);

        let code_section = vec![1, 2, 0, 0x0b];
        push_section(&mut module, 10, &code_section);
        module
    }

    fn test_runtime() -> (WasmRuntimeState, WasmModuleManifest, WasmContractInstance) {
        let mut runtime = WasmRuntimeState::new();
        let wasm = test_wasm_module(&[
            "storage_read",
            "storage_write",
            "emit_event",
            "asset_transfer",
        ]);
        let module = runtime
            .deploy_module(
                "alice-view-key",
                &wasm,
                &json!({"exports": ["execute"], "schema": "counter-v1"}),
                200,
                2,
                vec![
                    "storage_read".to_string(),
                    "storage_write".to_string(),
                    "emit_event".to_string(),
                    "asset_transfer".to_string(),
                ],
            )
            .unwrap();
        let instance = runtime
            .instantiate_contract(&module.module_id, "alice-view-key", json!({"count": 0}))
            .unwrap();
        (runtime, module, instance)
    }

    #[test]
    fn wasm_runtime_private_call_commits_args_storage_and_fee_lanes() {
        let (mut runtime, module, instance) = test_runtime();
        assert_eq!(
            module.imported_host_function_root,
            validate_wasm_module(
                &test_wasm_module(&[
                    "storage_read",
                    "storage_write",
                    "emit_event",
                    "asset_transfer",
                ]),
                &module.normalized_host_permissions(),
                module.max_memory_pages,
            )
            .unwrap()
            .imported_host_function_root
        );
        assert_eq!(module.exported_function_root.len(), 64);
        assert_eq!(module.validation_hash.len(), 64);
        let applied = runtime
            .execute_call(
                WasmRuntimeCallRequest::new(
                    &instance.contract_id,
                    "increment",
                    json!({
                        "write_key": "count",
                        "write_value": 7,
                        "asset_id": "wxmr-rust",
                        "amount": 1,
                        "secret_route": "hidden"
                    }),
                    "bob-view-key",
                    160,
                )
                .private_args(true)
                .fee_asset("wxmr-rust", Some(10))
                .paymaster("paymaster-runtime"),
            )
            .unwrap();

        assert_eq!(applied.call.module_id, module.module_id);
        assert!(applied.call.public_record().get("args").is_none());
        assert!(applied
            .call
            .state_record()
            .to_string()
            .contains("secret_route"));
        assert!(!applied
            .receipt
            .public_record()
            .to_string()
            .contains("bob-view-key"));
        assert_eq!(applied.storage_deltas.len(), 1);
        assert_eq!(applied.host_calls.len(), 2);
        assert_eq!(applied.events.len(), 1);
        assert_eq!(
            applied.instance_after.storage_root,
            applied.receipt.storage_root_after
        );
        assert_eq!(
            runtime.instances[&instance.contract_id].storage["count"],
            json!(7)
        );
        assert!(verify_wasm_execution_receipt(&applied.receipt, &applied.call).is_ok());

        let profile = execution_profile_from_resources(&[applied.fee_resource]);
        assert_eq!(profile.contract_call_count, 1);
        assert_eq!(profile.privacy_proof_count, 1);
        assert_eq!(profile.local_fee_lane_count, 6);
    }

    #[test]
    fn wasm_runtime_rejects_unsupported_host_permissions_and_overfuel() {
        let mut runtime = WasmRuntimeState::new();
        assert_eq!(
            runtime
                .deploy_module(
                    "alice-view-key",
                    &test_wasm_module(&[]),
                    &json!({}),
                    100,
                    1,
                    vec!["wall_clock".to_string()]
                )
                .unwrap_err(),
            "unsupported wasm host permission: wall_clock"
        );

        assert_eq!(
            runtime
                .deploy_module(
                    "alice-view-key",
                    b"not wasm",
                    &json!({}),
                    100,
                    1,
                    Vec::new()
                )
                .unwrap_err(),
            "invalid wasm module magic"
        );

        assert_eq!(
            runtime
                .deploy_module(
                    "alice-view-key",
                    &test_wasm_module(&["storage_read"]),
                    &json!({}),
                    100,
                    1,
                    Vec::new()
                )
                .unwrap_err(),
            "wasm host imports must match requested host permissions"
        );

        let (mut runtime, _module, instance) = test_runtime();
        assert_eq!(
            runtime
                .execute_call(WasmRuntimeCallRequest::new(
                    &instance.contract_id,
                    "increment",
                    json!({"write_key": "count", "write_value": 1}),
                    "bob-view-key",
                    1,
                ))
                .unwrap_err(),
            "wasm call exceeds fuel limit"
        );
    }

    #[test]
    fn wasm_runtime_root_can_be_committed_by_l2_block_header() {
        let (mut runtime, _module, instance) = test_runtime();
        let applied = runtime
            .execute_call(
                WasmRuntimeCallRequest::new(
                    &instance.contract_id,
                    "increment",
                    json!({"write_key": "count", "write_value": 3}),
                    "bob-view-key",
                    120,
                )
                .fee_asset("wxmr-rust", Some(10)),
            )
            .unwrap();
        let runtime_root = runtime.runtime_root();
        let input = BlockBuildInput {
            height: 11,
            epoch: 1,
            timestamp_ms: 1_700_000_100_000,
            prev_block_hash: "previous".to_string(),
            previous_state_root: "previous-state".to_string(),
            transactions: vec![
                applied.call.public_record(),
                applied.receipt.public_record(),
            ],
            mempool_admissions: Vec::new(),
            state_roots: BlockStateRoots {
                wasm_runtime_root: runtime_root.clone(),
                crypto_policy_root: crypto_policy_root(),
                ..BlockStateRoots::empty()
            },
            fee_resources: vec![applied.fee_resource],
            validators: vec![Validator::new("devnet-proposer", 1_000).unwrap()],
            proposer_label: "devnet-proposer".to_string(),
        };
        let produced = build_l2_block(input).unwrap();
        assert_eq!(produced.block.header.wasm_runtime_root, runtime_root);
        assert_eq!(
            produced.block.header.execution_profile.contract_call_count,
            1
        );
        assert!(produced.certificate.verify_authorization());
    }
}
