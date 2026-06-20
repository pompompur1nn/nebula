use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{sign_authorization, verify_authorization, Authorization},
    defi::{build_privacy_proof, PrivacyProof},
    fees::FeeMarketResource,
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, DEVNET_PRIVACY_PROOF_BYTES,
};

pub const CONTRACT_CALL_FEE_MICROUNITS_PER_FUEL: u64 = 25_000;
pub const CONTRACT_UPGRADE_TIMELOCK_BLOCKS: u64 = 2;
pub const CONTRACT_CALL_BATCH_MAX_ACTIONS: usize = 16;

pub type ContractResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    pub contract_id: String,
    pub template: String,
    pub code_hash: String,
    pub owner_label: String,
    pub storage: Value,
    pub fuel_limit: u64,
    pub version: u64,
    pub asset_balances: BTreeMap<String, u64>,
    pub private_storage: bool,
}

impl Contract {
    pub fn storage_root(&self) -> String {
        domain_hash("CONTRACT-STORAGE", &[HashPart::Json(&self.storage)], 32)
    }

    pub fn asset_balance_root(&self) -> String {
        domain_hash(
            "CONTRACT-ASSET-BALANCES",
            &[HashPart::Json(&json!(self.asset_balances))],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let storage_root = self.storage_root();
        let mut record = json!({
            "contract_id": self.contract_id,
            "template": self.template,
            "code_hash": self.code_hash,
            "owner_label": self.owner_label,
            "private_storage": self.private_storage,
            "storage_root": storage_root,
            "storage_commitment": storage_root,
            "asset_balances": self.asset_balances,
            "asset_balance_root": self.asset_balance_root(),
            "fuel_limit": self.fuel_limit,
            "version": self.version,
        });
        if !self.private_storage {
            record
                .as_object_mut()
                .expect("contract record object")
                .insert("storage".to_string(), self.storage.clone());
        }
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("contract state object")
            .insert("storage".to_string(), self.storage.clone());
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractUpgradeProposal {
    pub proposal_id: String,
    pub contract_id: String,
    pub template: String,
    pub current_version: u64,
    pub proposed_version: u64,
    pub current_code_hash: String,
    pub proposed_code_hash: String,
    pub current_fuel_limit: u64,
    pub proposed_fuel_limit: u64,
    pub proposer_label: String,
    pub proposed_at_height: u64,
    pub executable_at_height: u64,
    pub status: String,
    pub executed_at_height: u64,
    pub authorization: Authorization,
}

impl ContractUpgradeProposal {
    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "contract_upgrade_proposal",
            "chain_id": CHAIN_ID,
            "proposal_id": self.proposal_id,
            "contract_id": self.contract_id,
            "template": self.template,
            "current_version": self.current_version,
            "proposed_version": self.proposed_version,
            "current_code_hash": self.current_code_hash,
            "proposed_code_hash": self.proposed_code_hash,
            "current_fuel_limit": self.current_fuel_limit,
            "proposed_fuel_limit": self.proposed_fuel_limit,
            "proposer_label": self.proposer_label,
            "proposed_at_height": self.proposed_at_height,
            "executable_at_height": self.executable_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("contract upgrade proposal record object");
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "executed_at_height".to_string(),
            Value::from(self.executed_at_height),
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCall {
    pub contract_id: String,
    pub entrypoint: String,
    pub args: Value,
    pub fuel_limit: u64,
    pub private_args: bool,
    pub fuel_used: u64,
    pub fee_asset_id: String,
    pub fee: u64,
    pub fee_note_id: String,
    pub fee_nullifier: String,
    pub fee_change_commitment: String,
    pub paymaster_id: String,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub fee_proof_system: String,
    pub privacy_proof: Option<PrivacyProof>,
}

impl ContractCall {
    pub fn args_commitment(&self) -> String {
        domain_hash(
            "CONTRACT-CALL-ARGS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.contract_id),
                HashPart::Str(&self.entrypoint),
                HashPart::Json(&self.args),
            ],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "contract_call",
            "contract_id": self.contract_id,
            "entrypoint": self.entrypoint,
            "args": self.args,
            "private_args": self.private_args,
            "args_commitment": self.args_commitment(),
            "fuel_limit": self.fuel_limit,
            "fuel_used": self.fuel_used,
            "fee_asset_id": self.fee_asset_id,
            "fee": self.fee,
            "fee_note_id": self.fee_note_id,
            "fee_nullifier": self.fee_nullifier,
            "fee_change_commitment": self.fee_change_commitment,
            "paymaster_id": self.paymaster_id,
            "proof_system": self.proof_system,
            "fee_proof_system": self.fee_proof_system,
            "proof_bundle": self.privacy_proof.as_ref().map(PrivacyProof::public_record),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record.as_object_mut().expect("contract call record object");
        object.remove("fee_note_id");
        if self.private_args {
            object.remove("args");
        }
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
        let object = record.as_object_mut().expect("contract call state object");
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
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
        object.insert(
            "auth_scheme".to_string(),
            Value::String(self.authorization.auth_scheme.clone()),
        );
        object.insert("fee_change_note".to_string(), Value::Null);
        if let Some(proof) = &self.privacy_proof {
            object.insert("proof_bundle".to_string(), proof.state_record());
        }
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallRequest {
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

impl ContractCallRequest {
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
pub struct ContractCallAction {
    pub contract_id: String,
    pub entrypoint: String,
    pub args: Value,
    pub fuel_limit: u64,
    pub private_args: bool,
    pub fuel_used: u64,
}

impl ContractCallAction {
    pub fn new(
        contract_id: impl Into<String>,
        entrypoint: impl Into<String>,
        args: Value,
        fuel_limit: u64,
    ) -> Self {
        Self {
            contract_id: contract_id.into(),
            entrypoint: entrypoint.into(),
            args,
            fuel_limit,
            private_args: false,
            fuel_used: 0,
        }
    }

    pub fn private_args(mut self, private_args: bool) -> Self {
        self.private_args = private_args;
        self
    }

    pub fn args_commitment(&self) -> String {
        domain_hash(
            "CONTRACT-CALL-ARGS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.contract_id),
                HashPart::Str(&self.entrypoint),
                HashPart::Json(&self.args),
            ],
            32,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "entrypoint": self.entrypoint,
            "args": self.args,
            "private_args": self.private_args,
            "args_commitment": self.args_commitment(),
            "fuel_limit": self.fuel_limit,
            "fuel_used": self.fuel_used,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        if self.private_args {
            record
                .as_object_mut()
                .expect("contract call action record object")
                .remove("args");
        }
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallBatch {
    pub calls: Vec<ContractCallAction>,
    pub fee_asset_id: String,
    pub fee: u64,
    pub fee_note_id: String,
    pub fee_nullifier: String,
    pub fee_change_commitment: String,
    pub paymaster_id: String,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub fee_proof_system: String,
    pub privacy_proof: Option<PrivacyProof>,
}

impl ContractCallBatch {
    pub fn call_root(&self) -> String {
        let leaves = self
            .calls
            .iter()
            .map(ContractCallAction::public_record)
            .collect::<Vec<_>>();
        merkle_root("CONTRACT-CALL-BATCH-ACTION", &leaves)
    }

    pub fn total_fuel_used(&self) -> u64 {
        self.calls.iter().map(|call| call.fuel_used).sum()
    }

    pub fn has_private_args(&self) -> bool {
        self.calls.iter().any(|call| call.private_args)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "contract_call_batch",
            "call_count": self.calls.len(),
            "call_root": self.call_root(),
            "calls": self.calls.iter().map(ContractCallAction::unsigned_record).collect::<Vec<_>>(),
            "total_fuel_used": self.total_fuel_used(),
            "fee_asset_id": self.fee_asset_id,
            "fee": self.fee,
            "fee_note_id": self.fee_note_id,
            "fee_nullifier": self.fee_nullifier,
            "fee_change_commitment": self.fee_change_commitment,
            "paymaster_id": self.paymaster_id,
            "proof_system": self.proof_system,
            "fee_proof_system": self.fee_proof_system,
            "proof_bundle": self.privacy_proof.as_ref().map(PrivacyProof::public_record),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        let object = record
            .as_object_mut()
            .expect("contract call batch record object");
        object.insert(
            "calls".to_string(),
            Value::Array(
                self.calls
                    .iter()
                    .map(ContractCallAction::public_record)
                    .collect(),
            ),
        );
        object.insert("call_root".to_string(), Value::String(self.call_root()));
        object.remove("fee_note_id");
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
            .expect("contract call batch state object");
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        object.insert("fee_change_note".to_string(), Value::Null);
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
pub struct ContractCallBatchRequest {
    pub calls: Vec<ContractCallAction>,
    pub signer_label: String,
    pub fee_asset_id: String,
    pub paymaster_id: String,
    pub max_fee: Option<u64>,
}

impl ContractCallBatchRequest {
    pub fn new(calls: Vec<ContractCallAction>, signer_label: impl Into<String>) -> Self {
        Self {
            calls,
            signer_label: signer_label.into(),
            fee_asset_id: String::new(),
            paymaster_id: String::new(),
            max_fee: None,
        }
    }

    pub fn fee_asset(mut self, fee_asset_id: impl Into<String>, max_fee: Option<u64>) -> Self {
        self.fee_asset_id = fee_asset_id.into();
        self.max_fee = max_fee;
        self
    }

    pub fn paymaster(
        mut self,
        paymaster_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
    ) -> Self {
        self.paymaster_id = paymaster_id.into();
        self.fee_asset_id = fee_asset_id.into();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEvent {
    pub event_id: String,
    pub contract_id: String,
    pub event_name: String,
    pub event_index: u64,
    pub tx_hash: String,
    pub emitted_at_height: u64,
    pub contract_storage_root: String,
    pub data_hash: String,
    pub public_data: Value,
    pub previous_event_root: String,
    pub event_chain_root: String,
}

impl ContractEvent {
    pub fn id_payload(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "contract_id": self.contract_id,
            "event_name": self.event_name,
            "event_index": self.event_index,
            "tx_hash": self.tx_hash,
            "emitted_at_height": self.emitted_at_height,
            "contract_storage_root": self.contract_storage_root,
            "data_hash": self.data_hash,
            "previous_event_root": self.previous_event_root,
        })
    }

    pub fn expected_event_id(&self) -> String {
        domain_hash(
            "CONTRACT-EVENT-ID",
            &[HashPart::Json(&self.id_payload())],
            32,
        )
    }

    pub fn expected_event_chain_root(&self) -> String {
        let mut payload = self.id_payload();
        payload
            .as_object_mut()
            .expect("event payload object")
            .insert("event_id".to_string(), Value::String(self.event_id.clone()));
        domain_hash("CONTRACT-EVENT-CHAIN", &[HashPart::Json(&payload)], 32)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "contract_id": self.contract_id,
            "event_name": self.event_name,
            "event_index": self.event_index,
            "tx_hash": self.tx_hash,
            "emitted_at_height": self.emitted_at_height,
            "contract_storage_root": self.contract_storage_root,
            "data_hash": self.data_hash,
            "previous_event_root": self.previous_event_root,
            "event_chain_root": self.event_chain_root,
            "public_data": self.public_data,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractExecutionReceipt {
    pub receipt_id: String,
    pub tx_hash: String,
    pub contract_id: String,
    pub template: String,
    pub code_hash: String,
    pub contract_version: u64,
    pub entrypoint: String,
    pub call_index: u64,
    pub block_height: u64,
    pub tx_index: u64,
    pub args_commitment: String,
    pub private_args: bool,
    pub caller_commitment: String,
    pub fuel_limit: u64,
    pub fuel_used: u64,
    pub storage_root_before: String,
    pub storage_root_after: String,
    pub event_id: String,
    pub event_chain_root: String,
    pub runtime: String,
}

impl ContractExecutionReceipt {
    pub fn id_payload(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "runtime": self.runtime,
            "tx_hash": self.tx_hash,
            "contract_id": self.contract_id,
            "template": self.template,
            "code_hash": self.code_hash,
            "contract_version": self.contract_version,
            "entrypoint": self.entrypoint,
            "call_index": self.call_index,
            "block_height": self.block_height,
            "tx_index": self.tx_index,
            "args_commitment": self.args_commitment,
            "private_args": self.private_args,
            "caller_commitment": self.caller_commitment,
            "fuel_limit": self.fuel_limit,
            "fuel_used": self.fuel_used,
            "storage_root_before": self.storage_root_before,
            "storage_root_after": self.storage_root_after,
            "event_id": self.event_id,
            "event_chain_root": self.event_chain_root,
        })
    }

    pub fn expected_receipt_id(&self) -> String {
        domain_hash(
            "CONTRACT-EXECUTION-RECEIPT-ID",
            &[HashPart::Json(&self.id_payload())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_execution_receipt",
            "receipt_id": self.receipt_id,
            "runtime": self.runtime,
            "tx_hash": self.tx_hash,
            "contract_id": self.contract_id,
            "template": self.template,
            "code_hash": self.code_hash,
            "contract_version": self.contract_version,
            "entrypoint": self.entrypoint,
            "call_index": self.call_index,
            "block_height": self.block_height,
            "tx_index": self.tx_index,
            "args_commitment": self.args_commitment,
            "private_args": self.private_args,
            "caller_commitment": self.caller_commitment,
            "fuel_limit": self.fuel_limit,
            "fuel_used": self.fuel_used,
            "storage_root_before": self.storage_root_before,
            "storage_root_after": self.storage_root_after,
            "event_id": self.event_id,
            "event_chain_root": self.event_chain_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedContractCall {
    pub call: ContractCall,
    pub contract_before: Contract,
    pub contract_after: Contract,
    pub event: ContractEvent,
    pub receipt: ContractExecutionReceipt,
    pub fee_resource: FeeMarketResource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedContractCallBatch {
    pub batch: ContractCallBatch,
    pub calls: Vec<ContractCall>,
    pub contract_befores: Vec<Contract>,
    pub contract_afters: Vec<Contract>,
    pub events: Vec<ContractEvent>,
    pub receipts: Vec<ContractExecutionReceipt>,
    pub fee_resource: FeeMarketResource,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractState {
    pub contracts: BTreeMap<String, Contract>,
    pub contract_events: BTreeMap<String, ContractEvent>,
    pub contract_execution_receipts: BTreeMap<String, ContractExecutionReceipt>,
    pub contract_upgrade_proposals: BTreeMap<String, ContractUpgradeProposal>,
    pub height: u64,
}

impl ContractState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn deploy_counter_contract(
        &mut self,
        owner_label: &str,
        fuel_limit: u64,
        private_storage: bool,
    ) -> ContractResult<Contract> {
        self.deploy_contract("counter", owner_label, fuel_limit, private_storage)
    }

    pub fn deploy_vault_contract(
        &mut self,
        owner_label: &str,
        fuel_limit: u64,
        private_storage: bool,
    ) -> ContractResult<Contract> {
        self.deploy_contract("vault", owner_label, fuel_limit, private_storage)
    }

    pub fn deploy_governor_contract(
        &mut self,
        owner_label: &str,
        fuel_limit: u64,
        private_storage: bool,
    ) -> ContractResult<Contract> {
        self.deploy_contract("governor", owner_label, fuel_limit, private_storage)
    }

    pub fn deploy_contract(
        &mut self,
        template: &str,
        owner_label: &str,
        fuel_limit: u64,
        private_storage: bool,
    ) -> ContractResult<Contract> {
        if template != "counter" && template != "vault" && template != "governor" {
            return Err("unsupported contract template".to_string());
        }
        if fuel_limit == 0 {
            return Err("contract fuel_limit must be positive".to_string());
        }
        let storage = match template {
            "counter" => json!({"count": 0, "last_caller": ""}),
            "vault" => vault_initial_storage(),
            "governor" => governor_initial_storage(),
            _ => unreachable!("template checked above"),
        };
        let code_hash = domain_hash(
            "CONTRACT-CODE",
            &[HashPart::Str(template), HashPart::Int(1)],
            32,
        );
        let contract_id = domain_hash(
            "CONTRACT-ID",
            &[
                HashPart::Str(template),
                HashPart::Str(owner_label),
                HashPart::Str(&code_hash),
                HashPart::Int(self.contracts.len() as i128),
            ],
            32,
        );
        let contract = Contract {
            contract_id: contract_id.clone(),
            template: template.to_string(),
            code_hash,
            owner_label: owner_label.to_string(),
            storage,
            fuel_limit,
            version: 1,
            asset_balances: BTreeMap::new(),
            private_storage,
        };
        self.contracts.insert(contract_id, contract.clone());
        Ok(contract)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) {
        self.height = self.height.saturating_add(blocks);
    }

    pub fn propose_contract_upgrade(
        &mut self,
        contract_id: &str,
        proposed_version: Option<u64>,
        proposed_fuel_limit: Option<u64>,
        proposer_label: Option<&str>,
        timelock_blocks: Option<u64>,
    ) -> ContractResult<ContractUpgradeProposal> {
        let contract = self.require_contract(contract_id)?.clone();
        let proposer = proposer_label.unwrap_or(&contract.owner_label);
        if proposer != contract.owner_label {
            return Err("only the contract owner can propose upgrades".to_string());
        }
        let timelock = timelock_blocks.unwrap_or(CONTRACT_UPGRADE_TIMELOCK_BLOCKS);
        if timelock == 0 {
            return Err("contract upgrade timelock must be positive".to_string());
        }
        if self
            .contract_upgrade_proposals
            .values()
            .any(|proposal| proposal.contract_id == contract_id && proposal.status == "pending")
        {
            return Err("contract already has a pending upgrade".to_string());
        }
        let version = proposed_version.unwrap_or(contract.version + 1);
        if version <= contract.version {
            return Err("contract upgrade version must increase".to_string());
        }
        let fuel_limit = proposed_fuel_limit.unwrap_or(contract.fuel_limit);
        if fuel_limit == 0 {
            return Err("contract upgrade fuel_limit must be positive".to_string());
        }
        let proposed_code_hash = contract_code_hash(&contract.template, version);
        let proposed_at_height = self.height;
        let executable_at_height = proposed_at_height + timelock;
        let proposal_id = contract_upgrade_proposal_id(
            &contract.contract_id,
            contract.version,
            version,
            &contract.code_hash,
            &proposed_code_hash,
            contract.fuel_limit,
            fuel_limit,
            proposed_at_height,
            executable_at_height,
        );
        let mut proposal = ContractUpgradeProposal {
            proposal_id,
            contract_id: contract.contract_id,
            template: contract.template,
            current_version: contract.version,
            proposed_version: version,
            current_code_hash: contract.code_hash,
            proposed_code_hash,
            current_fuel_limit: contract.fuel_limit,
            proposed_fuel_limit: fuel_limit,
            proposer_label: proposer.to_string(),
            proposed_at_height,
            executable_at_height,
            status: "pending".to_string(),
            executed_at_height: 0,
            authorization: empty_authorization(),
        };
        proposal.authorization = sign_authorization(
            &proposal.proposer_label,
            "contract_upgrade_proposal",
            &proposal.unsigned_record(),
        );
        self.verify_contract_upgrade_proposal(&proposal)?;
        self.contract_upgrade_proposals
            .insert(proposal.proposal_id.clone(), proposal.clone());
        Ok(proposal)
    }

    pub fn execute_contract_upgrade(
        &mut self,
        proposal_id: &str,
        executor_label: &str,
    ) -> ContractResult<ContractUpgradeProposal> {
        let proposal = self
            .contract_upgrade_proposals
            .get(proposal_id)
            .ok_or_else(|| "unknown contract upgrade proposal".to_string())?
            .clone();
        self.verify_contract_upgrade_proposal(&proposal)?;
        if proposal.status != "pending" {
            return Err("contract upgrade proposal is not pending".to_string());
        }
        if self.height < proposal.executable_at_height {
            return Err("contract upgrade timelock has not elapsed".to_string());
        }
        let contract = self.require_contract(&proposal.contract_id)?.clone();
        if contract.template != proposal.template {
            return Err("contract upgrade template mismatch".to_string());
        }
        if contract.version != proposal.current_version {
            return Err("contract upgrade current version mismatch".to_string());
        }
        if contract.code_hash != proposal.current_code_hash {
            return Err("contract upgrade current code hash mismatch".to_string());
        }
        if contract.fuel_limit != proposal.current_fuel_limit {
            return Err("contract upgrade current fuel limit mismatch".to_string());
        }
        let updated_contract = Contract {
            version: proposal.proposed_version,
            code_hash: proposal.proposed_code_hash.clone(),
            fuel_limit: proposal.proposed_fuel_limit,
            ..contract.clone()
        };
        self.contracts.insert(
            updated_contract.contract_id.clone(),
            updated_contract.clone(),
        );

        let mut executed = proposal;
        executed.status = "executed".to_string();
        executed.executed_at_height = self.height;
        self.contract_upgrade_proposals
            .insert(executed.proposal_id.clone(), executed.clone());
        let executor_commitment = contract_upgrade_executor_commitment(executor_label);

        let public_data = json!({
            "proposal_id": executed.proposal_id,
            "previous_version": executed.current_version,
            "new_version": executed.proposed_version,
            "previous_code_hash": executed.current_code_hash,
            "new_code_hash": executed.proposed_code_hash,
            "previous_fuel_limit": executed.current_fuel_limit,
            "new_fuel_limit": executed.proposed_fuel_limit,
            "executor_commitment": executor_commitment,
        });
        let tx_hash = domain_hash(
            "CONTRACT-UPGRADE-EXECUTION",
            &[HashPart::Json(&executed.public_record())],
            32,
        );
        self.append_contract_event(
            &updated_contract.contract_id,
            "contract.upgraded",
            &tx_hash,
            &updated_contract.storage_root(),
            public_data,
        )?;
        self.verify_contract_upgrade_proposal(&executed)?;
        Ok(executed)
    }

    pub fn execute_contract_call(
        &mut self,
        request: ContractCallRequest,
    ) -> ContractResult<AppliedContractCall> {
        let contract_before = self.require_contract(&request.contract_id)?.clone();
        if request.fuel_limit == 0 || request.fuel_limit > contract_before.fuel_limit {
            return Err("contract call fuel_limit exceeds contract policy".to_string());
        }
        if !request.paymaster_id.is_empty() && request.fee_asset_id.is_empty() {
            return Err("paymaster contract call requires fee_asset_id".to_string());
        }
        let (contract_after, fuel_used) =
            execute_template_contract_call(&contract_before, &request, self.height)?;
        let fee = if request.fee_asset_id.is_empty() && request.paymaster_id.is_empty() {
            0
        } else {
            contract_call_fee(fuel_used)?
        };
        if let Some(max_fee) = request.max_fee {
            if fee > max_fee {
                return Err("contract call fee exceeds max_fee".to_string());
            }
        }
        let mut call = ContractCall {
            contract_id: request.contract_id.clone(),
            entrypoint: request.entrypoint.clone(),
            args: request.args.clone(),
            fuel_limit: request.fuel_limit,
            private_args: request.private_args,
            fuel_used,
            fee_asset_id: request.fee_asset_id.clone(),
            fee,
            fee_note_id: String::new(),
            fee_nullifier: String::new(),
            fee_change_commitment: String::new(),
            paymaster_id: request.paymaster_id.clone(),
            signer_label: request.signer_label.clone(),
            authorization: empty_authorization(),
            proof_system: "devnet-deterministic-contract-call".to_string(),
            fee_proof_system: "devnet-mock-contract-fee-proof".to_string(),
            privacy_proof: None,
        };
        if call.private_args {
            let (public_inputs, private_witnesses) = contract_fee_proof_context(&call);
            call.privacy_proof = Some(build_privacy_proof(
                &call.fee_proof_system,
                &public_inputs,
                &private_witnesses,
            ));
        }
        call.authorization =
            sign_authorization(&call.signer_label, "contract_call", &call.unsigned_record());
        if !verify_authorization(
            &call.signer_label,
            "contract_call",
            &call.unsigned_record(),
            &call.authorization,
        ) {
            return Err("invalid transaction authorization".to_string());
        }
        let tx_hash = domain_hash(
            "CONTRACT-CALL-TX",
            &[HashPart::Json(&call.public_record())],
            32,
        );
        let event =
            self.record_contract_event(&contract_before, &call, &contract_after, &tx_hash)?;
        let receipt = self.append_contract_execution_receipt(
            &contract_before,
            &call,
            &contract_after,
            &event,
            &tx_hash,
            0,
            0,
        )?;
        self.contracts
            .insert(contract_after.contract_id.clone(), contract_after.clone());
        let fee_resource = fee_market_resource_for_contract_call(&call);
        Ok(AppliedContractCall {
            call,
            contract_before,
            contract_after,
            event,
            receipt,
            fee_resource,
        })
    }

    pub fn execute_contract_call_batch(
        &mut self,
        request: ContractCallBatchRequest,
    ) -> ContractResult<AppliedContractCallBatch> {
        if request.calls.is_empty() {
            return Err("contract call batch requires at least one call".to_string());
        }
        if request.calls.len() > CONTRACT_CALL_BATCH_MAX_ACTIONS {
            return Err("contract call batch has too many calls".to_string());
        }
        if !request.paymaster_id.is_empty() && request.fee_asset_id.is_empty() {
            return Err("paymaster contract call batch requires fee_asset_id".to_string());
        }

        let mut working_contracts = self.contracts.clone();
        let mut metered_actions = Vec::with_capacity(request.calls.len());
        let mut contract_befores = Vec::with_capacity(request.calls.len());
        let mut contract_afters = Vec::with_capacity(request.calls.len());
        let mut calls = Vec::with_capacity(request.calls.len());
        let mut total_fuel_used = 0_u64;

        for action in request.calls {
            let contract_before = working_contracts
                .get(&action.contract_id)
                .cloned()
                .ok_or_else(|| "unknown contract".to_string())?;
            if action.fuel_limit == 0 || action.fuel_limit > contract_before.fuel_limit {
                return Err("contract call fuel_limit exceeds contract policy".to_string());
            }
            let probe = ContractCallRequest {
                contract_id: action.contract_id.clone(),
                entrypoint: action.entrypoint.clone(),
                args: action.args.clone(),
                signer_label: request.signer_label.clone(),
                fuel_limit: action.fuel_limit,
                private_args: action.private_args,
                fee_asset_id: String::new(),
                paymaster_id: String::new(),
                max_fee: None,
            };
            let (contract_after, fuel_used) =
                execute_template_contract_call(&contract_before, &probe, self.height)?;
            total_fuel_used = total_fuel_used
                .checked_add(fuel_used)
                .ok_or_else(|| "contract call batch fuel overflow".to_string())?;
            let metered_action = ContractCallAction {
                fuel_used,
                ..action
            };
            let call = contract_call_from_action(&metered_action, &request.signer_label);
            working_contracts.insert(contract_after.contract_id.clone(), contract_after.clone());
            contract_befores.push(contract_before);
            contract_afters.push(contract_after);
            calls.push(call);
            metered_actions.push(metered_action);
        }

        let fee = if request.fee_asset_id.is_empty() && request.paymaster_id.is_empty() {
            0
        } else {
            contract_call_fee(total_fuel_used)?
        };
        if let Some(max_fee) = request.max_fee {
            if fee > max_fee {
                return Err("contract call batch fee exceeds max_fee".to_string());
            }
        }

        let mut batch = ContractCallBatch {
            calls: metered_actions,
            fee_asset_id: request.fee_asset_id,
            fee,
            fee_note_id: String::new(),
            fee_nullifier: String::new(),
            fee_change_commitment: String::new(),
            paymaster_id: request.paymaster_id,
            signer_label: request.signer_label,
            authorization: empty_authorization(),
            proof_system: "devnet-deterministic-contract-call-batch".to_string(),
            fee_proof_system: "devnet-mock-contract-call-batch-proof".to_string(),
            privacy_proof: None,
        };
        if batch.has_private_args() {
            let (public_inputs, private_witnesses) = contract_batch_proof_context(&batch);
            batch.privacy_proof = Some(build_privacy_proof(
                &batch.fee_proof_system,
                &public_inputs,
                &private_witnesses,
            ));
        }
        batch.authorization = sign_authorization(
            &batch.signer_label,
            "contract_call_batch",
            &batch.unsigned_record(),
        );
        if !verify_authorization(
            &batch.signer_label,
            "contract_call_batch",
            &batch.unsigned_record(),
            &batch.authorization,
        ) {
            return Err("invalid contract call batch authorization".to_string());
        }

        let batch_public_record = batch.public_record();
        let mut events = Vec::with_capacity(calls.len());
        let mut receipts = Vec::with_capacity(calls.len());
        for (index, ((contract_before, contract_after), call)) in contract_befores
            .iter()
            .zip(contract_afters.iter())
            .zip(calls.iter())
            .enumerate()
        {
            let tx_hash = domain_hash(
                "CONTRACT-CALL-BATCH-TX",
                &[
                    HashPart::Json(&batch_public_record),
                    HashPart::Int(index as i128),
                ],
                32,
            );
            let event =
                self.record_contract_event(contract_before, call, contract_after, &tx_hash)?;
            let receipt = self.append_contract_execution_receipt(
                contract_before,
                call,
                contract_after,
                &event,
                &tx_hash,
                0,
                index as u64,
            )?;
            self.contracts
                .insert(contract_after.contract_id.clone(), contract_after.clone());
            events.push(event);
            receipts.push(receipt);
        }

        let fee_resource = fee_market_resource_for_contract_call_batch(&batch);
        Ok(AppliedContractCallBatch {
            batch,
            calls,
            contract_befores,
            contract_afters,
            events,
            receipts,
            fee_resource,
        })
    }

    pub fn contract_event_root(&self) -> String {
        event_root_for_events(&self.contract_events.values().cloned().collect::<Vec<_>>())
    }

    pub fn contract_execution_receipt_root(&self) -> String {
        let leaves = self
            .contract_execution_receipts
            .values()
            .map(ContractExecutionReceipt::public_record)
            .collect::<Vec<_>>();
        merkle_root("CONTRACT-EXECUTION-RECEIPT", &leaves)
    }

    pub fn contract_upgrade_root(&self) -> String {
        let leaves = self
            .contract_upgrade_proposals
            .values()
            .map(ContractUpgradeProposal::public_record)
            .collect::<Vec<_>>();
        merkle_root("CONTRACT-UPGRADE-PROPOSAL", &leaves)
    }

    pub fn contract_state_root(&self) -> String {
        let contracts = self
            .contracts
            .values()
            .map(Contract::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "CONTRACT-STATE",
            &[json!({
                "contracts": contracts,
                "contract_event_count": self.contract_events.len(),
                "contract_event_root": self.contract_event_root(),
                "contract_execution_receipt_count": self.contract_execution_receipts.len(),
                "contract_execution_receipt_root": self.contract_execution_receipt_root(),
                "contract_upgrade_count": self.contract_upgrade_proposals.len(),
                "contract_upgrade_root": self.contract_upgrade_root(),
            })],
        )
    }

    pub fn record_contract_asset_event(
        &mut self,
        contract_id: &str,
        event_name: &str,
        tx_hash: &str,
        contract_storage_root: &str,
        public_data: Value,
    ) -> ContractResult<ContractEvent> {
        self.append_contract_event(
            contract_id,
            event_name,
            tx_hash,
            contract_storage_root,
            public_data,
        )
    }

    fn require_contract(&self, contract_id: &str) -> ContractResult<&Contract> {
        self.contracts
            .get(contract_id)
            .ok_or_else(|| "unknown contract".to_string())
    }

    fn record_contract_event(
        &mut self,
        contract_before: &Contract,
        call: &ContractCall,
        contract_after: &Contract,
        tx_hash: &str,
    ) -> ContractResult<ContractEvent> {
        let (event_name, public_data) =
            contract_event_payload(contract_before, call, contract_after)?;
        self.append_contract_event(
            &contract_after.contract_id,
            &event_name,
            tx_hash,
            &contract_after.storage_root(),
            public_data,
        )
    }

    fn append_contract_event(
        &mut self,
        contract_id: &str,
        event_name: &str,
        tx_hash: &str,
        contract_storage_root: &str,
        public_data: Value,
    ) -> ContractResult<ContractEvent> {
        let data_hash = domain_hash("CONTRACT-EVENT-DATA", &[HashPart::Json(&public_data)], 32);
        let previous_events = self.contract_events.values().cloned().collect::<Vec<_>>();
        let mut event = ContractEvent {
            event_id: String::new(),
            contract_id: contract_id.to_string(),
            event_name: event_name.to_string(),
            event_index: self.contract_events.len() as u64,
            tx_hash: tx_hash.to_string(),
            emitted_at_height: self.height,
            contract_storage_root: contract_storage_root.to_string(),
            data_hash,
            public_data,
            previous_event_root: event_root_for_events(&previous_events),
            event_chain_root: String::new(),
        };
        event.event_id = event.expected_event_id();
        event.event_chain_root = event.expected_event_chain_root();
        self.contract_events
            .insert(event.event_id.clone(), event.clone());
        Ok(event)
    }

    #[allow(clippy::too_many_arguments)]
    fn append_contract_execution_receipt(
        &mut self,
        contract_before: &Contract,
        call: &ContractCall,
        contract_after: &Contract,
        event: &ContractEvent,
        tx_hash: &str,
        tx_index: u64,
        call_index: u64,
    ) -> ContractResult<ContractExecutionReceipt> {
        let mut receipt = ContractExecutionReceipt {
            receipt_id: String::new(),
            tx_hash: tx_hash.to_string(),
            contract_id: contract_before.contract_id.clone(),
            template: contract_before.template.clone(),
            code_hash: contract_before.code_hash.clone(),
            contract_version: contract_before.version,
            entrypoint: call.entrypoint.clone(),
            call_index,
            block_height: self.height,
            tx_index,
            args_commitment: call.args_commitment(),
            private_args: call.private_args,
            caller_commitment: caller_commitment(&call.signer_label),
            fuel_limit: call.fuel_limit,
            fuel_used: call.fuel_used,
            storage_root_before: contract_before.storage_root(),
            storage_root_after: contract_after.storage_root(),
            event_id: event.event_id.clone(),
            event_chain_root: event.event_chain_root.clone(),
            runtime: "devnet-template-v1".to_string(),
        };
        receipt.receipt_id = receipt.expected_receipt_id();
        verify_contract_execution_receipt(&receipt, event)?;
        self.contract_execution_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    fn verify_contract_upgrade_proposal(
        &self,
        proposal: &ContractUpgradeProposal,
    ) -> ContractResult<()> {
        let contract = self
            .contracts
            .get(&proposal.contract_id)
            .ok_or_else(|| "contract upgrade references unknown contract".to_string())?;
        if proposal.status != "pending" && proposal.status != "executed" {
            return Err("contract upgrade status is invalid".to_string());
        }
        if proposal.proposed_version <= proposal.current_version {
            return Err("contract upgrade version must increase".to_string());
        }
        if proposal.current_fuel_limit == 0 || proposal.proposed_fuel_limit == 0 {
            return Err("contract upgrade fuel_limit must be positive".to_string());
        }
        if proposal.executable_at_height <= proposal.proposed_at_height {
            return Err("contract upgrade timelock must be positive".to_string());
        }
        if proposal.current_code_hash
            != contract_code_hash(&proposal.template, proposal.current_version)
        {
            return Err("contract upgrade current code hash mismatch".to_string());
        }
        if proposal.proposed_code_hash
            != contract_code_hash(&proposal.template, proposal.proposed_version)
        {
            return Err("contract upgrade proposed code hash mismatch".to_string());
        }
        let expected_proposal_id = contract_upgrade_proposal_id(
            &proposal.contract_id,
            proposal.current_version,
            proposal.proposed_version,
            &proposal.current_code_hash,
            &proposal.proposed_code_hash,
            proposal.current_fuel_limit,
            proposal.proposed_fuel_limit,
            proposal.proposed_at_height,
            proposal.executable_at_height,
        );
        if proposal.proposal_id != expected_proposal_id {
            return Err("contract upgrade proposal id mismatch".to_string());
        }
        if proposal.proposer_label != contract.owner_label {
            return Err("contract upgrade proposer must be owner".to_string());
        }
        if proposal.status == "pending" {
            if proposal.executed_at_height != 0 {
                return Err("pending contract upgrade cannot be executed".to_string());
            }
            if contract.template != proposal.template {
                return Err("contract upgrade template mismatch".to_string());
            }
            if contract.version != proposal.current_version {
                return Err("contract upgrade current version mismatch".to_string());
            }
            if contract.code_hash != proposal.current_code_hash {
                return Err("contract upgrade current code hash mismatch".to_string());
            }
            if contract.fuel_limit != proposal.current_fuel_limit {
                return Err("contract upgrade current fuel limit mismatch".to_string());
            }
        } else if proposal.executed_at_height == 0 {
            return Err("executed contract upgrade missing execution height".to_string());
        }
        if proposal.status == "executed" && proposal.executed_at_height > self.height {
            return Err("contract upgrade execution height is in the future".to_string());
        }
        if !verify_authorization(
            &proposal.proposer_label,
            "contract_upgrade_proposal",
            &proposal.unsigned_record(),
            &proposal.authorization,
        ) {
            return Err("invalid contract upgrade authorization".to_string());
        }
        Ok(())
    }
}

pub fn contract_code_hash(template: &str, version: u64) -> String {
    domain_hash(
        "CONTRACT-CODE",
        &[HashPart::Str(template), HashPart::Int(version as i128)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn contract_upgrade_proposal_id(
    contract_id: &str,
    current_version: u64,
    proposed_version: u64,
    current_code_hash: &str,
    proposed_code_hash: &str,
    current_fuel_limit: u64,
    proposed_fuel_limit: u64,
    proposed_at_height: u64,
    executable_at_height: u64,
) -> String {
    domain_hash(
        "CONTRACT-UPGRADE-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Int(current_version as i128),
            HashPart::Int(proposed_version as i128),
            HashPart::Str(current_code_hash),
            HashPart::Str(proposed_code_hash),
            HashPart::Int(current_fuel_limit as i128),
            HashPart::Int(proposed_fuel_limit as i128),
            HashPart::Int(proposed_at_height as i128),
            HashPart::Int(executable_at_height as i128),
        ],
        32,
    )
}

pub fn contract_upgrade_executor_commitment(executor_label: &str) -> String {
    if executor_label.is_empty() {
        String::new()
    } else {
        domain_hash(
            "CONTRACT-UPGRADE-EXECUTOR",
            &[HashPart::Str(executor_label)],
            32,
        )
    }
}

pub fn vault_allowance_key(asset_id: &str, beneficiary_commitment: &str) -> String {
    domain_hash(
        "VAULT-ALLOWANCE",
        &[
            HashPart::Str(asset_id),
            HashPart::Str(beneficiary_commitment),
        ],
        32,
    )
}

pub fn vault_allowance_commitment(
    asset_id: &str,
    beneficiary_commitment: &str,
    amount: u64,
) -> String {
    domain_hash(
        "VAULT-ALLOWANCE-COMMITMENT",
        &[HashPart::Json(&json!({
            "asset_id": asset_id,
            "beneficiary_commitment": beneficiary_commitment,
            "amount": amount,
        }))],
        32,
    )
}

pub fn vault_allowance_record(asset_id: &str, beneficiary_commitment: &str, amount: u64) -> Value {
    json!({
        "asset_id": asset_id,
        "beneficiary_commitment": beneficiary_commitment,
        "amount": amount,
        "allowance_commitment": vault_allowance_commitment(
            asset_id,
            beneficiary_commitment,
            amount,
        ),
    })
}

pub fn vault_allowance_root_from_records(
    allowances: &BTreeMap<String, Value>,
) -> ContractResult<String> {
    let mut leaves = Vec::with_capacity(allowances.len());
    for (allowance_key, raw_record) in allowances {
        let asset_id = raw_record
            .get("asset_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "vault allowance asset_id is required".to_string())?;
        let beneficiary_commitment = raw_record
            .get("beneficiary_commitment")
            .and_then(Value::as_str)
            .ok_or_else(|| "vault allowance beneficiary is required".to_string())?;
        let amount = raw_record
            .get("amount")
            .and_then(Value::as_u64)
            .ok_or_else(|| "vault allowance amount is required".to_string())?;
        if amount == 0 {
            return Err("vault allowance amount must be positive".to_string());
        }
        let expected_key = vault_allowance_key(asset_id, beneficiary_commitment);
        if allowance_key != &expected_key {
            return Err("vault allowance key mismatch".to_string());
        }
        let allowance_commitment = raw_record
            .get("allowance_commitment")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                vault_allowance_commitment(asset_id, beneficiary_commitment, amount)
            });
        if allowance_commitment
            != vault_allowance_commitment(asset_id, beneficiary_commitment, amount)
        {
            return Err("vault allowance commitment mismatch".to_string());
        }
        leaves.push(json!({
            "allowance_key": allowance_key,
            "asset_id": asset_id,
            "beneficiary_commitment": beneficiary_commitment,
            "amount": amount,
            "allowance_commitment": allowance_commitment,
        }));
    }
    Ok(merkle_root("VAULT-ALLOWANCE", &leaves))
}

pub fn vault_available_allowance(
    contract: &Contract,
    asset_id: &str,
    beneficiary_commitment: &str,
) -> ContractResult<u64> {
    let storage = normalize_vault_contract_storage(&contract.storage)?;
    let allowances = vault_allowances_from_storage(&storage)?;
    let allowance_key = vault_allowance_key(asset_id, beneficiary_commitment);
    Ok(allowances
        .get(&allowance_key)
        .and_then(|record| record.get("amount"))
        .and_then(Value::as_u64)
        .unwrap_or(0))
}

pub fn vault_spend_allowance(
    contract: &Contract,
    asset_id: &str,
    beneficiary_commitment: &str,
    amount: u64,
) -> ContractResult<Contract> {
    let mut storage = normalize_vault_contract_storage(&contract.storage)?;
    let mut allowances = vault_allowances_from_storage(&storage)?;
    let allowance_key = vault_allowance_key(asset_id, beneficiary_commitment);
    let current = allowances
        .get(&allowance_key)
        .and_then(|record| record.get("amount"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if current < amount {
        return Err("vault allowance cannot cover withdrawal plus fee".to_string());
    }
    let remaining = current - amount;
    if remaining == 0 {
        allowances.remove(&allowance_key);
    } else {
        allowances.insert(
            allowance_key,
            vault_allowance_record(asset_id, beneficiary_commitment, remaining),
        );
    }
    write_vault_allowances(&mut storage, allowances)?;
    Ok(Contract {
        storage,
        ..contract.clone()
    })
}

pub fn vault_initial_storage() -> Value {
    let allowances = BTreeMap::<String, Value>::new();
    json!({
        "allowances": {},
        "allowance_root": vault_allowance_root_from_records(&allowances)
            .expect("empty vault allowance root"),
        "last_caller_commitment": "",
    })
}

pub fn governor_initial_storage() -> Value {
    json!({
        "proposal_nonce": 0,
        "proposals": {},
        "quorum": 1,
        "last_caller_commitment": "",
    })
}

pub fn governor_proposal_id(
    contract_id: &str,
    proposal_index: u64,
    description_hash: &str,
    action_hash: &str,
    start_height: u64,
    end_height: u64,
    proposer_commitment: &str,
) -> String {
    domain_hash(
        "GOVERNOR-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Int(proposal_index as i128),
            HashPart::Str(description_hash),
            HashPart::Str(action_hash),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(proposer_commitment),
        ],
        32,
    )
}

fn governor_proposals_from_storage(
    storage: &Value,
) -> ContractResult<serde_json::Map<String, Value>> {
    Ok(storage
        .get("proposals")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default())
}

fn parse_governor_support(value: &Value) -> ContractResult<bool> {
    if let Some(support) = value.as_bool() {
        return Ok(support);
    }
    if let Some(raw) = value.as_i64() {
        return match raw {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("governor vote support must be boolean".to_string()),
        };
    }
    if let Some(raw) = value.as_str() {
        return match raw.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "for" | "1" => Ok(true),
            "false" | "no" | "against" | "0" => Ok(false),
            _ => Err("governor vote support must be boolean".to_string()),
        };
    }
    Err("governor vote support must be boolean".to_string())
}

fn value_u64(value: &Value, message: &str) -> ContractResult<u64> {
    value.as_u64().ok_or_else(|| message.to_string())
}

fn normalize_vault_contract_storage(storage: &Value) -> ContractResult<Value> {
    let mut normalized = storage
        .as_object()
        .cloned()
        .ok_or_else(|| "vault storage must be an object".to_string())?;
    let mut allowances = BTreeMap::<String, Value>::new();
    if let Some(raw_allowances) = normalized.get("allowances") {
        let object = raw_allowances
            .as_object()
            .ok_or_else(|| "vault allowances must be an object".to_string())?;
        for (allowance_key, raw_record) in object {
            let asset_id = raw_record
                .get("asset_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "vault allowance asset_id is required".to_string())?;
            let beneficiary_commitment = raw_record
                .get("beneficiary_commitment")
                .and_then(Value::as_str)
                .ok_or_else(|| "vault allowance beneficiary is required".to_string())?;
            let amount = raw_record
                .get("amount")
                .and_then(Value::as_u64)
                .ok_or_else(|| "vault allowance amount is required".to_string())?;
            if allowance_key != &vault_allowance_key(asset_id, beneficiary_commitment) {
                return Err("vault allowance key mismatch".to_string());
            }
            allowances.insert(
                allowance_key.clone(),
                vault_allowance_record(asset_id, beneficiary_commitment, amount),
            );
        }
    }
    let allowance_root = vault_allowance_root_from_records(&allowances)?;
    normalized.insert("allowances".to_string(), json!(allowances));
    normalized.insert("allowance_root".to_string(), json!(allowance_root));
    Ok(Value::Object(normalized))
}

fn vault_allowances_from_storage(storage: &Value) -> ContractResult<BTreeMap<String, Value>> {
    let mut allowances = BTreeMap::new();
    if let Some(object) = storage.get("allowances").and_then(Value::as_object) {
        for (key, value) in object {
            allowances.insert(key.clone(), value.clone());
        }
    }
    Ok(allowances)
}

fn write_vault_allowances(
    storage: &mut Value,
    allowances: BTreeMap<String, Value>,
) -> ContractResult<()> {
    let allowance_root = vault_allowance_root_from_records(&allowances)?;
    let object = storage
        .as_object_mut()
        .ok_or_else(|| "vault storage must be an object".to_string())?;
    object.insert("allowances".to_string(), json!(allowances));
    object.insert("allowance_root".to_string(), json!(allowance_root));
    Ok(())
}

fn execute_template_contract_call(
    contract: &Contract,
    request: &ContractCallRequest,
    current_height: u64,
) -> ContractResult<(Contract, u64)> {
    if contract.template != "counter"
        && contract.template != "vault"
        && contract.template != "governor"
    {
        return Err("unsupported contract template".to_string());
    }
    let mut storage = if contract.template == "vault" {
        normalize_vault_contract_storage(&contract.storage)?
    } else {
        contract.storage.clone()
    };
    match (contract.template.as_str(), request.entrypoint.as_str()) {
        ("counter", "increment") => {
            let amount = request
                .args
                .get("amount")
                .and_then(Value::as_i64)
                .unwrap_or(1);
            if amount <= 0 {
                return Err("counter increment amount must be positive".to_string());
            }
            let fuel_used = 10 + amount.to_string().len() as u64;
            if fuel_used > request.fuel_limit {
                return Err("contract call exceeds fuel limit".to_string());
            }
            let count = storage.get("count").and_then(Value::as_i64).unwrap_or(0) + amount;
            storage["count"] = json!(count);
            storage["last_caller"] = json!(request.signer_label);
            Ok((
                Contract {
                    storage,
                    ..contract.clone()
                },
                fuel_used,
            ))
        }
        ("counter", "set") => {
            if request.signer_label != contract.owner_label {
                return Err("only the contract owner can set the counter".to_string());
            }
            let value = request
                .args
                .get("value")
                .and_then(Value::as_i64)
                .ok_or_else(|| "counter set value is required".to_string())?;
            let fuel_used = 20 + value.to_string().len() as u64;
            if fuel_used > request.fuel_limit {
                return Err("contract call exceeds fuel limit".to_string());
            }
            storage["count"] = json!(value);
            storage["last_caller"] = json!(request.signer_label);
            Ok((
                Contract {
                    storage,
                    ..contract.clone()
                },
                fuel_used,
            ))
        }
        ("vault", "grant") => {
            if request.signer_label != contract.owner_label {
                return Err("only the contract owner can grant vault allowance".to_string());
            }
            let asset_id = request
                .args
                .get("asset_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "vault allowance asset_id is required".to_string())?;
            let beneficiary_commitment = request
                .args
                .get("beneficiary_commitment")
                .and_then(Value::as_str)
                .ok_or_else(|| "vault beneficiary commitment is required".to_string())?;
            let amount = request
                .args
                .get("amount")
                .and_then(Value::as_u64)
                .ok_or_else(|| "vault allowance amount is required".to_string())?;
            if asset_id.is_empty() {
                return Err("vault allowance asset_id is required".to_string());
            }
            if beneficiary_commitment.is_empty() {
                return Err("vault beneficiary commitment is required".to_string());
            }
            if amount == 0 {
                return Err("vault allowance amount must be positive".to_string());
            }
            let fuel_used = 30
                + asset_id.len() as u64
                + beneficiary_commitment.len() as u64 / 8
                + amount.to_string().len() as u64;
            if fuel_used > request.fuel_limit {
                return Err("contract call exceeds fuel limit".to_string());
            }
            let mut allowances = vault_allowances_from_storage(&storage)?;
            let allowance_key = vault_allowance_key(asset_id, beneficiary_commitment);
            allowances.insert(
                allowance_key,
                vault_allowance_record(asset_id, beneficiary_commitment, amount),
            );
            write_vault_allowances(&mut storage, allowances)?;
            storage["last_caller_commitment"] = json!(caller_commitment(&request.signer_label));
            Ok((
                Contract {
                    storage,
                    ..contract.clone()
                },
                fuel_used,
            ))
        }
        ("vault", "revoke") => {
            if request.signer_label != contract.owner_label {
                return Err("only the contract owner can revoke vault allowance".to_string());
            }
            let asset_id = request
                .args
                .get("asset_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "vault allowance asset_id is required".to_string())?;
            let beneficiary_commitment = request
                .args
                .get("beneficiary_commitment")
                .and_then(Value::as_str)
                .ok_or_else(|| "vault beneficiary commitment is required".to_string())?;
            if asset_id.is_empty() {
                return Err("vault allowance asset_id is required".to_string());
            }
            if beneficiary_commitment.is_empty() {
                return Err("vault beneficiary commitment is required".to_string());
            }
            let fuel_used = 24 + asset_id.len() as u64 + beneficiary_commitment.len() as u64 / 8;
            if fuel_used > request.fuel_limit {
                return Err("contract call exceeds fuel limit".to_string());
            }
            let mut allowances = vault_allowances_from_storage(&storage)?;
            allowances.remove(&vault_allowance_key(asset_id, beneficiary_commitment));
            write_vault_allowances(&mut storage, allowances)?;
            storage["last_caller_commitment"] = json!(caller_commitment(&request.signer_label));
            Ok((
                Contract {
                    storage,
                    ..contract.clone()
                },
                fuel_used,
            ))
        }
        ("governor", "propose") => {
            let description_hash = request
                .args
                .get("description_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "governor proposal description hash is required".to_string())?;
            if description_hash.is_empty() {
                return Err("governor proposal description hash is required".to_string());
            }
            let action_hash = request
                .args
                .get("action_hash")
                .and_then(Value::as_str)
                .unwrap_or("");
            let voting_period_blocks = request
                .args
                .get("voting_period_blocks")
                .and_then(Value::as_u64)
                .unwrap_or(2);
            if voting_period_blocks == 0 {
                return Err("governor voting period must be positive".to_string());
            }
            let quorum = request
                .args
                .get("quorum")
                .and_then(Value::as_u64)
                .or_else(|| storage.get("quorum").and_then(Value::as_u64))
                .unwrap_or(1);
            if quorum == 0 {
                return Err("governor quorum must be positive".to_string());
            }
            let mut proposals = governor_proposals_from_storage(&storage)?;
            let proposal_index = storage
                .get("proposal_nonce")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| "governor proposal nonce overflow".to_string())?;
            let start_height = current_height;
            let end_height = start_height
                .checked_add(voting_period_blocks)
                .ok_or_else(|| "governor voting period overflow".to_string())?;
            let proposer_commitment = caller_commitment(&request.signer_label);
            let proposal_id = governor_proposal_id(
                &contract.contract_id,
                proposal_index,
                description_hash,
                action_hash,
                start_height,
                end_height,
                &proposer_commitment,
            );
            let fuel_used = 40
                + description_hash.len() as u64 / 8
                + action_hash.len() as u64 / 8
                + voting_period_blocks.to_string().len() as u64
                + quorum.to_string().len() as u64;
            if fuel_used > request.fuel_limit {
                return Err("contract call exceeds fuel limit".to_string());
            }
            proposals.insert(
                proposal_id.clone(),
                json!({
                    "proposal_id": proposal_id,
                    "proposal_index": proposal_index,
                    "description_hash": description_hash,
                    "action_hash": action_hash,
                    "proposer_commitment": proposer_commitment,
                    "start_height": start_height,
                    "end_height": end_height,
                    "yes_weight": 0,
                    "no_weight": 0,
                    "quorum": quorum,
                    "status": "active",
                    "outcome": "",
                    "executed_at_height": 0,
                    "voter_commitments": {},
                }),
            );
            storage["proposal_nonce"] = json!(proposal_index);
            storage["proposals"] = Value::Object(proposals);
            storage["last_caller_commitment"] = json!(caller_commitment(&request.signer_label));
            Ok((
                Contract {
                    storage,
                    ..contract.clone()
                },
                fuel_used,
            ))
        }
        ("governor", "vote") => {
            let proposal_id = request
                .args
                .get("proposal_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "governor proposal_id is required".to_string())?;
            let support = parse_governor_support(
                request
                    .args
                    .get("support")
                    .ok_or_else(|| "governor vote support is required".to_string())?,
            )?;
            let weight = request
                .args
                .get("weight")
                .and_then(Value::as_u64)
                .unwrap_or(1);
            if weight == 0 {
                return Err("governor vote weight must be positive".to_string());
            }
            let mut proposals = governor_proposals_from_storage(&storage)?;
            let proposal = proposals
                .get_mut(proposal_id)
                .ok_or_else(|| "unknown governor proposal".to_string())?;
            if proposal.get("status").and_then(Value::as_str) != Some("active") {
                return Err("governor proposal is not active".to_string());
            }
            let end_height = proposal
                .get("end_height")
                .map(|value| value_u64(value, "governor proposal end height is required"))
                .transpose()?
                .ok_or_else(|| "governor proposal end height is required".to_string())?;
            if current_height > end_height {
                return Err("governor proposal voting period has ended".to_string());
            }
            let voter_commitment = caller_commitment(&request.signer_label);
            let mut voters = proposal
                .get("voter_commitments")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if voters.contains_key(&voter_commitment) {
                return Err("governor voter already voted".to_string());
            }
            voters.insert(
                voter_commitment.clone(),
                json!({
                    "support": support,
                    "weight": weight,
                }),
            );
            let object = proposal
                .as_object_mut()
                .ok_or_else(|| "governor proposal must be an object".to_string())?;
            object.insert("voter_commitments".to_string(), Value::Object(voters));
            let yes_weight = object
                .get("yes_weight")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let no_weight = object.get("no_weight").and_then(Value::as_u64).unwrap_or(0);
            if support {
                object.insert(
                    "yes_weight".to_string(),
                    json!(yes_weight
                        .checked_add(weight)
                        .ok_or_else(|| "governor yes weight overflow".to_string())?),
                );
            } else {
                object.insert(
                    "no_weight".to_string(),
                    json!(no_weight
                        .checked_add(weight)
                        .ok_or_else(|| "governor no weight overflow".to_string())?),
                );
            }
            let fuel_used = 34 + proposal_id.len() as u64 / 8 + weight.to_string().len() as u64;
            if fuel_used > request.fuel_limit {
                return Err("contract call exceeds fuel limit".to_string());
            }
            storage["proposals"] = Value::Object(proposals);
            storage["last_caller_commitment"] = json!(voter_commitment);
            Ok((
                Contract {
                    storage,
                    ..contract.clone()
                },
                fuel_used,
            ))
        }
        ("governor", "execute") => {
            let proposal_id = request
                .args
                .get("proposal_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "governor proposal_id is required".to_string())?;
            let mut proposals = governor_proposals_from_storage(&storage)?;
            let proposal = proposals
                .get_mut(proposal_id)
                .ok_or_else(|| "unknown governor proposal".to_string())?;
            if proposal.get("status").and_then(Value::as_str) != Some("active") {
                return Err("governor proposal is not active".to_string());
            }
            let end_height = proposal
                .get("end_height")
                .map(|value| value_u64(value, "governor proposal end height is required"))
                .transpose()?
                .ok_or_else(|| "governor proposal end height is required".to_string())?;
            if current_height <= end_height {
                return Err("governor proposal voting period has not ended".to_string());
            }
            let object = proposal
                .as_object_mut()
                .ok_or_else(|| "governor proposal must be an object".to_string())?;
            let yes_weight = object
                .get("yes_weight")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let no_weight = object.get("no_weight").and_then(Value::as_u64).unwrap_or(0);
            let quorum = object.get("quorum").and_then(Value::as_u64).unwrap_or(1);
            let passed = yes_weight >= quorum && yes_weight > no_weight;
            object.insert(
                "status".to_string(),
                json!(if passed { "executed" } else { "rejected" }),
            );
            object.insert(
                "outcome".to_string(),
                json!(if passed { "passed" } else { "rejected" }),
            );
            object.insert("executed_at_height".to_string(), json!(current_height));
            let fuel_used = 28 + proposal_id.len() as u64 / 8;
            if fuel_used > request.fuel_limit {
                return Err("contract call exceeds fuel limit".to_string());
            }
            storage["proposals"] = Value::Object(proposals);
            storage["last_caller_commitment"] = json!(caller_commitment(&request.signer_label));
            Ok((
                Contract {
                    storage,
                    ..contract.clone()
                },
                fuel_used,
            ))
        }
        _ => Err(format!("unsupported {} entrypoint", contract.template)),
    }
}

fn contract_event_payload(
    contract_before: &Contract,
    call: &ContractCall,
    contract_after: &Contract,
) -> ContractResult<(String, Value)> {
    let caller_commitment = caller_commitment(&call.signer_label);
    if call.private_args {
        return Ok((
            match (contract_before.template.as_str(), call.entrypoint.as_str()) {
                ("counter", "increment") => "counter.incremented".to_string(),
                ("counter", "set") => "counter.set".to_string(),
                ("vault", "grant") => "vault.allowance_granted".to_string(),
                ("vault", "revoke") => "vault.allowance_revoked".to_string(),
                ("governor", "propose") => "governor.proposed".to_string(),
                ("governor", "vote") => "governor.voted".to_string(),
                ("governor", "execute") => "governor.executed".to_string(),
                _ => format!("{}.{}", contract_before.template, call.entrypoint),
            },
            json!({
                "private_args": true,
                "args_commitment": call.args_commitment(),
                "caller_commitment": caller_commitment,
            }),
        ));
    }
    if contract_before.template == "counter" && call.entrypoint == "increment" {
        let amount = call.args.get("amount").and_then(Value::as_i64).unwrap_or(1);
        return Ok((
            "counter.incremented".to_string(),
            json!({
                "amount": amount,
                "new_count": contract_after.storage.get("count").and_then(Value::as_i64).unwrap_or(0),
                "caller_commitment": caller_commitment,
            }),
        ));
    }
    if contract_before.template == "counter" && call.entrypoint == "set" {
        let value = call
            .args
            .get("value")
            .and_then(Value::as_i64)
            .ok_or_else(|| "counter set value is required".to_string())?;
        return Ok((
            "counter.set".to_string(),
            json!({
                "value": value,
                "new_count": contract_after.storage.get("count").and_then(Value::as_i64).unwrap_or(0),
                "caller_commitment": caller_commitment,
            }),
        ));
    }
    if contract_before.template == "vault" && call.entrypoint == "grant" {
        let asset_id = call
            .args
            .get("asset_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "vault allowance asset_id is required".to_string())?;
        let beneficiary_commitment = call
            .args
            .get("beneficiary_commitment")
            .and_then(Value::as_str)
            .ok_or_else(|| "vault beneficiary commitment is required".to_string())?;
        let allowance_key = vault_allowance_key(asset_id, beneficiary_commitment);
        let allowance = contract_after
            .storage
            .get("allowances")
            .and_then(Value::as_object)
            .and_then(|allowances| allowances.get(&allowance_key))
            .cloned()
            .unwrap_or(Value::Null);
        return Ok((
            "vault.allowance_granted".to_string(),
            json!({
                "asset_id": asset_id,
                "beneficiary_commitment": beneficiary_commitment,
                "allowance_key": allowance_key,
                "amount": allowance.get("amount").and_then(Value::as_u64).unwrap_or(0),
                "allowance_commitment": allowance
                    .get("allowance_commitment")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                "allowance_root": contract_after
                    .storage
                    .get("allowance_root")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                "caller_commitment": caller_commitment,
            }),
        ));
    }
    if contract_before.template == "vault" && call.entrypoint == "revoke" {
        let asset_id = call
            .args
            .get("asset_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "vault allowance asset_id is required".to_string())?;
        let beneficiary_commitment = call
            .args
            .get("beneficiary_commitment")
            .and_then(Value::as_str)
            .ok_or_else(|| "vault beneficiary commitment is required".to_string())?;
        return Ok((
            "vault.allowance_revoked".to_string(),
            json!({
                "asset_id": asset_id,
                "beneficiary_commitment": beneficiary_commitment,
                "allowance_key": vault_allowance_key(asset_id, beneficiary_commitment),
                "allowance_root": contract_after
                    .storage
                    .get("allowance_root")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                "caller_commitment": caller_commitment,
            }),
        ));
    }
    if contract_before.template == "governor" && call.entrypoint == "propose" {
        let before = contract_before
            .storage
            .get("proposals")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let after = contract_after
            .storage
            .get("proposals")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut added = after
            .keys()
            .filter(|proposal_id| !before.contains_key(*proposal_id))
            .cloned()
            .collect::<Vec<_>>();
        added.sort();
        let proposal_id = added
            .first()
            .ok_or_else(|| "governor proposal event missing proposal".to_string())?;
        let proposal = after
            .get(proposal_id)
            .ok_or_else(|| "governor proposal event missing proposal".to_string())?;
        return Ok((
            "governor.proposed".to_string(),
            json!({
                "proposal_id": proposal.get("proposal_id").and_then(Value::as_str).unwrap_or(""),
                "proposal_index": proposal.get("proposal_index").and_then(Value::as_u64).unwrap_or(0),
                "description_hash": proposal.get("description_hash").and_then(Value::as_str).unwrap_or(""),
                "action_hash": proposal.get("action_hash").and_then(Value::as_str).unwrap_or(""),
                "start_height": proposal.get("start_height").and_then(Value::as_u64).unwrap_or(0),
                "end_height": proposal.get("end_height").and_then(Value::as_u64).unwrap_or(0),
                "quorum": proposal.get("quorum").and_then(Value::as_u64).unwrap_or(0),
                "proposer_commitment": proposal.get("proposer_commitment").and_then(Value::as_str).unwrap_or(""),
                "caller_commitment": caller_commitment,
            }),
        ));
    }
    if contract_before.template == "governor" && call.entrypoint == "vote" {
        let proposal_id = call
            .args
            .get("proposal_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "governor proposal_id is required".to_string())?;
        let support = parse_governor_support(
            call.args
                .get("support")
                .ok_or_else(|| "governor vote support is required".to_string())?,
        )?;
        let weight = call.args.get("weight").and_then(Value::as_u64).unwrap_or(1);
        let proposal = contract_after
            .storage
            .get("proposals")
            .and_then(Value::as_object)
            .and_then(|proposals| proposals.get(proposal_id))
            .cloned()
            .unwrap_or(Value::Null);
        return Ok((
            "governor.voted".to_string(),
            json!({
                "proposal_id": proposal_id,
                "support": support,
                "weight": weight,
                "yes_weight": proposal.get("yes_weight").and_then(Value::as_u64).unwrap_or(0),
                "no_weight": proposal.get("no_weight").and_then(Value::as_u64).unwrap_or(0),
                "voter_commitment": caller_commitment,
            }),
        ));
    }
    if contract_before.template == "governor" && call.entrypoint == "execute" {
        let proposal_id = call
            .args
            .get("proposal_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "governor proposal_id is required".to_string())?;
        let proposal = contract_after
            .storage
            .get("proposals")
            .and_then(Value::as_object)
            .and_then(|proposals| proposals.get(proposal_id))
            .cloned()
            .unwrap_or(Value::Null);
        return Ok((
            "governor.executed".to_string(),
            json!({
                "proposal_id": proposal_id,
                "status": proposal.get("status").and_then(Value::as_str).unwrap_or(""),
                "outcome": proposal.get("outcome").and_then(Value::as_str).unwrap_or(""),
                "yes_weight": proposal.get("yes_weight").and_then(Value::as_u64).unwrap_or(0),
                "no_weight": proposal.get("no_weight").and_then(Value::as_u64).unwrap_or(0),
                "quorum": proposal.get("quorum").and_then(Value::as_u64).unwrap_or(0),
                "executed_at_height": proposal.get("executed_at_height").and_then(Value::as_u64).unwrap_or(0),
                "executor_commitment": caller_commitment,
            }),
        ));
    }
    Err(format!(
        "unsupported {} entrypoint",
        contract_before.template
    ))
}

fn contract_fee_proof_context(call: &ContractCall) -> (Value, Value) {
    let mut public_inputs = json!({
        "kind": "contract_call_privacy",
        "contract_id": call.contract_id,
        "entrypoint": call.entrypoint,
        "private_args": call.private_args,
        "args_commitment": call.args_commitment(),
        "fuel_limit": call.fuel_limit,
        "fuel_used": call.fuel_used,
        "fee_asset_id": call.fee_asset_id,
        "fee": call.fee,
        "paymaster_id": call.paymaster_id,
        "fee_input_commitment": "",
        "fee_nullifier": call.fee_nullifier,
        "fee_change_commitment": call.fee_change_commitment,
    });
    if !call.private_args {
        public_inputs
            .as_object_mut()
            .expect("contract proof inputs object")
            .insert("args".to_string(), call.args.clone());
    }
    let private_witnesses = json!({
        "args": if call.private_args { call.args.clone() } else { Value::Null },
        "fee_note": Value::Null,
        "fee_change_note": Value::Null,
        "balance": {
            "input_amount": 0,
            "fee": call.fee,
            "change": 0,
        },
    });
    (public_inputs, private_witnesses)
}

fn verify_contract_execution_receipt(
    receipt: &ContractExecutionReceipt,
    event: &ContractEvent,
) -> ContractResult<()> {
    if receipt.receipt_id != receipt.expected_receipt_id() {
        return Err("contract execution receipt id mismatch".to_string());
    }
    if receipt.runtime != "devnet-template-v1" {
        return Err("contract execution receipt runtime mismatch".to_string());
    }
    if receipt.fuel_limit == 0 || receipt.fuel_used == 0 || receipt.fuel_used > receipt.fuel_limit {
        return Err("contract execution receipt fuel must be positive".to_string());
    }
    if event.contract_id != receipt.contract_id {
        return Err("contract execution receipt event contract mismatch".to_string());
    }
    if event.tx_hash != receipt.tx_hash {
        return Err("contract execution receipt tx hash mismatch".to_string());
    }
    if event.contract_storage_root != receipt.storage_root_after {
        return Err("contract execution receipt storage root mismatch".to_string());
    }
    if event.event_chain_root != receipt.event_chain_root {
        return Err("contract execution receipt event chain mismatch".to_string());
    }
    Ok(())
}

fn event_root_for_events(events: &[ContractEvent]) -> String {
    let mut ordered = events.to_vec();
    ordered.sort_by(|left, right| {
        (left.event_index, left.event_id.as_str())
            .cmp(&(right.event_index, right.event_id.as_str()))
    });
    let leaves = ordered
        .iter()
        .map(ContractEvent::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EVENT", &leaves)
}

pub fn caller_commitment(signer_label: &str) -> String {
    domain_hash("CONTRACT-CALLER", &[HashPart::Str(signer_label)], 32)
}

pub fn contract_call_fee(fuel_used: u64) -> ContractResult<u64> {
    if fuel_used == 0 {
        return Err("contract call fuel_used must be positive".to_string());
    }
    Ok(std::cmp::max(
        1,
        (fuel_used * CONTRACT_CALL_FEE_MICROUNITS_PER_FUEL).div_ceil(1_000_000),
    ))
}

fn contract_call_from_action(action: &ContractCallAction, signer_label: &str) -> ContractCall {
    ContractCall {
        contract_id: action.contract_id.clone(),
        entrypoint: action.entrypoint.clone(),
        args: action.args.clone(),
        fuel_limit: action.fuel_limit,
        private_args: action.private_args,
        fuel_used: action.fuel_used,
        fee_asset_id: String::new(),
        fee: 0,
        fee_note_id: String::new(),
        fee_nullifier: String::new(),
        fee_change_commitment: String::new(),
        paymaster_id: String::new(),
        signer_label: signer_label.to_string(),
        authorization: empty_authorization(),
        proof_system: "devnet-deterministic-contract-call".to_string(),
        fee_proof_system: "devnet-mock-contract-fee-proof".to_string(),
        privacy_proof: None,
    }
}

fn contract_batch_proof_context(batch: &ContractCallBatch) -> (Value, Value) {
    let public_inputs = json!({
        "kind": "contract_call_batch_privacy",
        "call_count": batch.calls.len(),
        "call_root": batch.call_root(),
        "calls": batch.calls.iter().map(ContractCallAction::public_record).collect::<Vec<_>>(),
        "total_fuel_used": batch.total_fuel_used(),
        "has_private_args": batch.has_private_args(),
        "fee_asset_id": batch.fee_asset_id,
        "fee": batch.fee,
        "paymaster_id": batch.paymaster_id,
        "fee_input_commitment": "",
        "fee_nullifier": batch.fee_nullifier,
        "fee_change_commitment": batch.fee_change_commitment,
    });
    let private_args = batch
        .calls
        .iter()
        .enumerate()
        .filter(|(_, call)| call.private_args)
        .map(|(index, call)| {
            json!({
                "call_index": index,
                "contract_id": call.contract_id,
                "entrypoint": call.entrypoint,
                "args": call.args,
                "args_commitment": call.args_commitment(),
            })
        })
        .collect::<Vec<_>>();
    let private_witnesses = json!({
        "private_args": private_args,
        "fee_note": Value::Null,
        "fee_change_note": Value::Null,
        "balance": {
            "input_amount": 0,
            "fee": batch.fee,
            "change": 0,
        },
    });
    (public_inputs, private_witnesses)
}

pub fn fee_market_resource_for_contract_call(call: &ContractCall) -> FeeMarketResource {
    let mut fee_asset_ids = Vec::new();
    if !call.fee_asset_id.is_empty() {
        fee_asset_ids.push(call.fee_asset_id.clone());
    }
    let mut fee_lanes = vec![
        ("operation".to_string(), "contract_call".to_string()),
        ("contract".to_string(), call.contract_id.clone()),
    ];
    if !call.fee_asset_id.is_empty() {
        fee_lanes.push(("asset".to_string(), call.fee_asset_id.clone()));
    }
    if !call.paymaster_id.is_empty() {
        fee_lanes.push(("paymaster".to_string(), call.paymaster_id.clone()));
    }
    FeeMarketResource {
        public_record: call.public_record(),
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

pub fn fee_market_resource_for_contract_call_batch(batch: &ContractCallBatch) -> FeeMarketResource {
    let mut fee_asset_ids = Vec::new();
    if !batch.fee_asset_id.is_empty() {
        fee_asset_ids.push(batch.fee_asset_id.clone());
    }
    let mut fee_lanes = vec![("operation".to_string(), "contract_call_batch".to_string())];
    for call in &batch.calls {
        if !fee_lanes
            .iter()
            .any(|(lane_type, lane_key)| lane_type == "contract" && lane_key == &call.contract_id)
        {
            fee_lanes.push(("contract".to_string(), call.contract_id.clone()));
        }
    }
    if !batch.fee_asset_id.is_empty() {
        fee_lanes.push(("asset".to_string(), batch.fee_asset_id.clone()));
    }
    if !batch.paymaster_id.is_empty() {
        fee_lanes.push(("paymaster".to_string(), batch.paymaster_id.clone()));
    }
    FeeMarketResource {
        public_record: batch.public_record(),
        execution_fuel: batch.total_fuel_used(),
        privacy_proof_count: u64::from(batch.privacy_proof.is_some()),
        contract_call_count: batch.calls.len() as u64,
        observed_fee_units: batch.fee,
        estimated_proof_bytes: if batch.privacy_proof.is_some() {
            DEVNET_PRIVACY_PROOF_BYTES
        } else {
            0
        },
        authorization_count: 1,
        fee_asset_ids,
        fee_lanes,
    }
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
    use crate::fees::execution_profile_from_resources;

    #[test]
    fn counter_contract_deployment_matches_python_reference() {
        let mut state = ContractState::new();
        let contract = state
            .deploy_counter_contract("alice-view-key", 100, false)
            .unwrap();
        assert_eq!(
            contract.code_hash,
            "61bdb62b6e15c456085f1703fef1761aecd6bc012790d9728631b13ea8039a14"
        );
        assert_eq!(
            contract.contract_id,
            "5f0b5ef6445ad0534d7964489619ea9bf67a3840ff667083b610b15e9d21b8ba"
        );
        assert_eq!(
            contract.storage_root(),
            "570bf162ed6c770d60f9614f9655986b87e9b3671f9985650cd6074e69cbeb86"
        );
        assert_eq!(contract.public_record()["storage"]["count"], 0);
    }

    #[test]
    fn public_counter_call_emits_python_compatible_receipt_and_fee_resource() {
        let mut state = ContractState::new();
        let contract = state
            .deploy_counter_contract("alice-view-key", 100, false)
            .unwrap();
        let applied = state
            .execute_contract_call(ContractCallRequest::new(
                &contract.contract_id,
                "increment",
                json!({"amount": 7}),
                "bob-view-key",
                20,
            ))
            .unwrap();

        assert_eq!(applied.call.fuel_used, 11);
        assert_eq!(
            applied.call.args_commitment(),
            "84886ef51f439deaf83543f5ea781391d3b0da0a1173b0626733b6d67671e9f2"
        );
        assert_eq!(
            applied.contract_after.storage_root(),
            "f64033bf20acc5c267176497f1446c40ca692a8e7a370e54f8a7a7b4d59c4019"
        );
        assert_eq!(
            domain_hash(
                "CONTRACT-CALL-TX",
                &[HashPart::Json(&applied.call.public_record())],
                32
            ),
            "7a959ab37db5aebe5adca85c47710d59e83c5f2b2244c1666867f40849662fdb"
        );
        assert_eq!(
            applied.event.event_id,
            "ef81e12b6e752eacca8eb265520562ab626f7605da4b099c730c4b569c644f73"
        );
        assert_eq!(
            applied.event.event_chain_root,
            "df0a8992bb85613b1c04abf426ee68ba9519e0b0919cebd4daa931f1e5d3872a"
        );
        assert_eq!(
            state.contract_event_root(),
            "5631fea1ee156841faacda890e41d64e0ab05ad57621fb7bd9296c464f5a357f"
        );
        assert_eq!(
            applied.receipt.receipt_id,
            "c680bf09adbb88ab88756c7f4534f60a71e3c0df6610cdb6212080086c0abe46"
        );
        assert_eq!(
            state.contract_execution_receipt_root(),
            "4d60288d7b8a8821a47c0ed6dd4d037444098bed813e312a7ca5f2b234874873"
        );
        assert_eq!(applied.event.public_data["amount"], 7);
        assert!(!applied
            .event
            .public_record()
            .to_string()
            .contains("bob-view-key"));

        let fee_resource = fee_market_resource_for_contract_call(&applied.call);
        assert_eq!(fee_resource.execution_fuel, 11);
        assert_eq!(fee_resource.contract_call_count, 1);
        assert_eq!(fee_resource.authorization_count, 1);
        let profile = execution_profile_from_resources(&[fee_resource]);
        assert_eq!(profile.contract_call_count, 1);
        assert_eq!(profile.execution_fuel, 11);
    }

    #[test]
    fn private_counter_args_are_committed_not_published() {
        let mut state = ContractState::new();
        let contract = state
            .deploy_counter_contract("alice-view-key", 100, false)
            .unwrap();
        let applied = state
            .execute_contract_call(
                ContractCallRequest::new(
                    &contract.contract_id,
                    "increment",
                    json!({"amount": 17}),
                    "bob-view-key",
                    20,
                )
                .private_args(true),
            )
            .unwrap();

        let public_call = applied.call.public_record();
        assert_eq!(
            applied.call.args_commitment(),
            "0578bd583acc8996b8a4c735d3a431e9bee6d187a57c2cbbd475de4c202463c5"
        );
        assert!(public_call["private_args"].as_bool().unwrap());
        assert!(public_call.get("args").is_none());
        assert_eq!(
            public_call["proof_bundle"]["proof_root"],
            "6437a6b546cc56f673e1c481889e4b86fe4877c852f622612a74a64090445047"
        );
        assert_eq!(
            domain_hash("CONTRACT-CALL-TX", &[HashPart::Json(&public_call)], 32),
            "236446c6d4b3e4573ba2f3e81f20e90d3271011407d4379365d5b3253cd3b692"
        );
        assert_eq!(
            applied.event.event_id,
            "7e7b7d2b63822059d4a3d4e661667260fbce4a678a65c465ee63668b1f0b0720"
        );
        assert_eq!(
            state.contract_event_root(),
            "221d4945539111dafa9a8d0571e9f2b95b68d22e51b9cef38eb35eae472cc680"
        );
        assert_eq!(
            applied.receipt.receipt_id,
            "3f1607fe275f7212de3e2b39dc087a73967bc884ba1a1d350f96af205e944839"
        );
        assert_eq!(
            state.contract_execution_receipt_root(),
            "dcfd4b8642b84de4a83a5b802281022a374c446c91fc930d67d04fe8a7d36f82"
        );
        assert_eq!(applied.event.public_data["private_args"], true);
        assert!(applied.event.public_data.get("amount").is_none());
        assert!(applied
            .event
            .public_record()
            .to_string()
            .contains("0578bd583acc8996b8a4c735d3a431e9bee6d187a57c2cbbd475de4c202463c5"));
        assert!(!applied
            .event
            .public_record()
            .to_string()
            .contains("bob-view-key"));
        assert_eq!(applied.fee_resource.privacy_proof_count, 1);
        assert_eq!(
            applied.fee_resource.estimated_proof_bytes,
            DEVNET_PRIVACY_PROOF_BYTES
        );
    }
}
