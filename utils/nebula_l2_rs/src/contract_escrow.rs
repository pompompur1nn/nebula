use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    contracts::{
        caller_commitment, vault_available_allowance, vault_spend_allowance, Contract,
        ContractEvent, ContractState,
    },
    crypto_policy::{sign_authorization, verify_authorization, Authorization},
    defi::{build_privacy_proof, note_nullifier, DefiState, Note, PrivacyProof},
    fees::FeeMarketResource,
    hash::{domain_hash, HashPart},
    DEVNET_PRIVACY_PROOF_BYTES,
};

pub type ContractEscrowResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractDeposit {
    pub contract_id: String,
    pub spent_note_id: String,
    pub nullifier: String,
    pub asset_id: String,
    pub amount: u64,
    pub output_notes: Vec<Note>,
    pub network_fee: u64,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
    pub privacy_proof: Option<PrivacyProof>,
}

impl ContractDeposit {
    pub fn terms_hash(&self) -> String {
        domain_hash(
            "CONTRACT-DEPOSIT-TERMS",
            &[
                HashPart::Str(&self.contract_id),
                HashPart::Str(&self.asset_id),
                HashPart::Int(self.amount as i128),
                HashPart::Int(self.network_fee as i128),
                HashPart::Json(&output_commitments(&self.output_notes)),
            ],
            32,
        )
    }

    pub fn unsigned_record(&self, include_spent_note: bool) -> Value {
        let mut record = json!({
            "kind": "contract_deposit",
            "contract_id": self.contract_id,
            "nullifier": self.nullifier,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "network_fee": self.network_fee,
            "terms_hash": self.terms_hash(),
            "output_commitments": output_commitments(&self.output_notes),
            "proof_system": self.proof_system,
            "proof_bundle": self.privacy_proof.as_ref().map(PrivacyProof::public_record),
        });
        if include_spent_note {
            record
                .as_object_mut()
                .expect("contract deposit record object")
                .insert(
                    "spent_note_id".to_string(),
                    Value::String(self.spent_note_id.clone()),
                );
        }
        record
    }

    pub fn public_record(&self) -> Value {
        signed_public_record(self.unsigned_record(false), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.unsigned_record(true);
        let object = record
            .as_object_mut()
            .expect("contract deposit state object");
        object.insert(
            "output_notes".to_string(),
            Value::Array(self.output_notes.iter().map(Note::state_record).collect()),
        );
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
        object.insert(
            "proof_bundle".to_string(),
            self.privacy_proof
                .as_ref()
                .map(PrivacyProof::state_record)
                .unwrap_or(Value::Null),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractWithdraw {
    pub contract_id: String,
    pub asset_id: String,
    pub amount: u64,
    pub output_note: Note,
    pub network_fee: u64,
    pub signer_label: String,
    pub authorization: Authorization,
    pub proof_system: String,
}

impl ContractWithdraw {
    pub fn recipient_commitment(&self) -> String {
        contract_withdraw_recipient_commitment(&self.output_note.owner_view_key)
    }

    pub fn unsigned_record(&self) -> Value {
        json!({
            "kind": "contract_withdraw",
            "contract_id": self.contract_id,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "network_fee": self.network_fee,
            "output_commitment": self.output_note.commitment,
            "recipient_commitment": self.recipient_commitment(),
            "proof_system": self.proof_system,
        })
    }

    pub fn public_record(&self) -> Value {
        signed_public_record(self.unsigned_record(), &self.authorization)
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("contract withdraw state object");
        object.insert("output_note".to_string(), self.output_note.state_record());
        object.insert(
            "signer_label".to_string(),
            Value::String(self.signer_label.clone()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedContractDeposit {
    pub deposit: ContractDeposit,
    pub contract_before: Contract,
    pub contract_after: Contract,
    pub event: ContractEvent,
    pub fee_resource: FeeMarketResource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedContractWithdraw {
    pub withdraw: ContractWithdraw,
    pub contract_before: Contract,
    pub contract_after: Contract,
    pub event: ContractEvent,
    pub fee_resource: FeeMarketResource,
}

pub fn submit_contract_deposit(
    defi_state: &mut DefiState,
    contract_state: &mut ContractState,
    contract_id: &str,
    spent_note_id: &str,
    amount: u64,
    network_fee: u64,
    signer_label: Option<&str>,
) -> ContractEscrowResult<AppliedContractDeposit> {
    if amount == 0 {
        return Err("contract deposit amount must be positive".to_string());
    }
    let contract_before = contract_state
        .contracts
        .get(contract_id)
        .cloned()
        .ok_or_else(|| "unknown contract".to_string())?;
    let spent = defi_state
        .notes
        .get(spent_note_id)
        .cloned()
        .ok_or_else(|| "unknown or already spent contract deposit note".to_string())?;
    if !defi_state.assets.contains_key(&spent.asset_id) {
        return Err("unknown asset".to_string());
    }
    let signer = signer_label.unwrap_or(&spent.owner_view_key).to_string();
    if signer != spent.owner_view_key {
        return Err("signer does not own the contract deposit note".to_string());
    }
    let debit = amount
        .checked_add(network_fee)
        .ok_or_else(|| "contract deposit amount plus fee overflow".to_string())?;
    if spent.amount < debit {
        return Err("contract deposit amount plus fee exceeds note value".to_string());
    }
    let nullifier = note_nullifier(&spent);
    ensure_nullifier_available(defi_state, &nullifier)?;
    let change = spent.amount - debit;
    let mut output_notes = Vec::new();
    if change != 0 {
        output_notes.push(create_note(
            defi_state,
            &spent.owner_view_key,
            &spent.asset_id,
            change,
        )?);
    }
    let proof_system = "devnet-mock-private-contract-deposit-proof".to_string();
    let mut deposit = ContractDeposit {
        contract_id: contract_id.to_string(),
        spent_note_id: spent_note_id.to_string(),
        nullifier,
        asset_id: spent.asset_id.clone(),
        amount,
        output_notes,
        network_fee,
        signer_label: signer,
        authorization: empty_authorization(),
        proof_system,
        privacy_proof: None,
    };
    deposit.privacy_proof = Some(contract_deposit_privacy_proof(
        &contract_before,
        &spent,
        &deposit,
    ));
    deposit.authorization = sign_authorization(
        &deposit.signer_label,
        "contract_deposit",
        &deposit.unsigned_record(true),
    );
    if !verify_authorization(
        &deposit.signer_label,
        "contract_deposit",
        &deposit.unsigned_record(true),
        &deposit.authorization,
    ) {
        return Err("invalid contract deposit authorization".to_string());
    }

    defi_state.notes.remove(spent_note_id);
    defi_state.spent_nullifiers.push(deposit.nullifier.clone());
    for output in &deposit.output_notes {
        defi_state
            .notes
            .insert(output.note_id.clone(), output.clone());
    }
    add_fee(defi_state, &deposit.asset_id, deposit.network_fee)?;
    let contract_after =
        update_contract_asset_balance(&contract_before, &deposit.asset_id, amount as i128)?;
    contract_state
        .contracts
        .insert(contract_after.contract_id.clone(), contract_after.clone());
    let tx_hash = domain_hash(
        "CONTRACT-DEPOSIT-TX",
        &[HashPart::Json(&deposit.public_record())],
        32,
    );
    let event = contract_state.record_contract_asset_event(
        &contract_after.contract_id,
        "contract.deposited",
        &tx_hash,
        &contract_after.storage_root(),
        json!({
            "asset_id": deposit.asset_id,
            "amount": deposit.amount,
            "network_fee": deposit.network_fee,
            "new_asset_balance": contract_after.asset_balances.get(&deposit.asset_id).copied().unwrap_or(0),
            "asset_balance_root": contract_after.asset_balance_root(),
            "caller_commitment": caller_commitment(&deposit.signer_label),
        }),
    )?;
    let fee_resource = fee_market_resource_for_contract_deposit(&deposit);
    Ok(AppliedContractDeposit {
        deposit,
        contract_before,
        contract_after,
        event,
        fee_resource,
    })
}

pub fn submit_contract_withdraw(
    defi_state: &mut DefiState,
    contract_state: &mut ContractState,
    contract_id: &str,
    asset_id: &str,
    amount: u64,
    recipient_view_key: &str,
    network_fee: u64,
    signer_label: Option<&str>,
) -> ContractEscrowResult<AppliedContractWithdraw> {
    if amount == 0 {
        return Err("contract withdrawal amount must be positive".to_string());
    }
    if recipient_view_key.is_empty() {
        return Err("contract withdrawal recipient is required".to_string());
    }
    if !defi_state.assets.contains_key(asset_id) {
        return Err("unknown asset".to_string());
    }
    let contract_before = contract_state
        .contracts
        .get(contract_id)
        .cloned()
        .ok_or_else(|| "unknown contract".to_string())?;
    let signer = signer_label
        .unwrap_or(&contract_before.owner_label)
        .to_string();
    let debit = amount
        .checked_add(network_fee)
        .ok_or_else(|| "contract withdrawal amount plus fee overflow".to_string())?;
    let mut allowance_spender_commitment = String::new();
    let mut remaining_allowance_commitment = String::new();
    let mut allowance_root = String::new();
    let authorized_contract = if signer == contract_before.owner_label {
        contract_before.clone()
    } else {
        if contract_before.template != "vault" {
            return Err("only the contract owner can withdraw native balances".to_string());
        }
        if recipient_view_key != signer {
            return Err("vault allowance withdrawals must pay the signer".to_string());
        }
        allowance_spender_commitment = caller_commitment(&signer);
        let allowance =
            vault_available_allowance(&contract_before, asset_id, &allowance_spender_commitment)?;
        if allowance < debit {
            return Err("vault allowance cannot cover withdrawal plus fee".to_string());
        }
        let updated = vault_spend_allowance(
            &contract_before,
            asset_id,
            &allowance_spender_commitment,
            debit,
        )?;
        let allowance_key =
            crate::contracts::vault_allowance_key(asset_id, &allowance_spender_commitment);
        remaining_allowance_commitment = updated
            .storage
            .get("allowances")
            .and_then(Value::as_object)
            .and_then(|allowances| allowances.get(&allowance_key))
            .and_then(|record| record.get("allowance_commitment"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        allowance_root = updated
            .storage
            .get("allowance_root")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        updated
    };
    let available = contract_before
        .asset_balances
        .get(asset_id)
        .copied()
        .unwrap_or(0);
    if available < debit {
        return Err("contract balance cannot cover withdrawal plus fee".to_string());
    }
    let output_note = create_note(defi_state, recipient_view_key, asset_id, amount)?;
    let mut withdraw = ContractWithdraw {
        contract_id: contract_id.to_string(),
        asset_id: asset_id.to_string(),
        amount,
        output_note,
        network_fee,
        signer_label: signer,
        authorization: empty_authorization(),
        proof_system: "devnet-contract-native-asset-withdraw".to_string(),
    };
    withdraw.authorization = sign_authorization(
        &withdraw.signer_label,
        "contract_withdraw",
        &withdraw.unsigned_record(),
    );
    if !verify_authorization(
        &withdraw.signer_label,
        "contract_withdraw",
        &withdraw.unsigned_record(),
        &withdraw.authorization,
    ) {
        return Err("invalid contract withdrawal authorization".to_string());
    }

    let contract_after =
        update_contract_asset_balance(&authorized_contract, asset_id, -(debit as i128))?;
    contract_state
        .contracts
        .insert(contract_after.contract_id.clone(), contract_after.clone());
    defi_state.notes.insert(
        withdraw.output_note.note_id.clone(),
        withdraw.output_note.clone(),
    );
    add_fee(defi_state, asset_id, network_fee)?;
    let tx_hash = domain_hash(
        "CONTRACT-WITHDRAW-TX",
        &[HashPart::Json(&withdraw.public_record())],
        32,
    );
    let allowance_root_for_event = if allowance_root.is_empty() {
        contract_after
            .storage
            .get("allowance_root")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    } else {
        allowance_root
    };
    let event = contract_state.record_contract_asset_event(
        &contract_after.contract_id,
        "contract.withdrawn",
        &tx_hash,
        &contract_after.storage_root(),
        json!({
            "asset_id": withdraw.asset_id,
            "amount": withdraw.amount,
            "network_fee": withdraw.network_fee,
            "remaining_asset_balance": contract_after.asset_balances.get(&withdraw.asset_id).copied().unwrap_or(0),
            "asset_balance_root": contract_after.asset_balance_root(),
            "caller_commitment": caller_commitment(&withdraw.signer_label),
            "allowance_spender_commitment": allowance_spender_commitment,
            "remaining_allowance_commitment": remaining_allowance_commitment,
            "allowance_root": allowance_root_for_event,
            "recipient_commitment": withdraw.recipient_commitment(),
        }),
    )?;
    let fee_resource = fee_market_resource_for_contract_withdraw(&withdraw);
    Ok(AppliedContractWithdraw {
        withdraw,
        contract_before,
        contract_after,
        event,
        fee_resource,
    })
}

pub fn contract_withdraw_recipient_commitment(recipient_view_key: &str) -> String {
    domain_hash(
        "CONTRACT-WITHDRAW-RECIPIENT",
        &[HashPart::Str(recipient_view_key)],
        32,
    )
}

pub fn fee_market_resource_for_contract_deposit(deposit: &ContractDeposit) -> FeeMarketResource {
    FeeMarketResource {
        public_record: deposit.public_record(),
        execution_fuel: 210 + deposit.output_notes.len() as u64 * 16,
        privacy_proof_count: u64::from(deposit.privacy_proof.is_some()),
        contract_call_count: 0,
        observed_fee_units: deposit.network_fee,
        estimated_proof_bytes: if deposit.privacy_proof.is_some() {
            DEVNET_PRIVACY_PROOF_BYTES
        } else {
            0
        },
        authorization_count: 1,
        fee_asset_ids: vec![deposit.asset_id.clone()],
        fee_lanes: vec![
            ("operation".to_string(), "contract_deposit".to_string()),
            ("contract".to_string(), deposit.contract_id.clone()),
            ("asset".to_string(), deposit.asset_id.clone()),
        ],
    }
}

pub fn fee_market_resource_for_contract_withdraw(withdraw: &ContractWithdraw) -> FeeMarketResource {
    FeeMarketResource {
        public_record: withdraw.public_record(),
        execution_fuel: 120,
        privacy_proof_count: 0,
        contract_call_count: 0,
        observed_fee_units: withdraw.network_fee,
        estimated_proof_bytes: 0,
        authorization_count: 1,
        fee_asset_ids: vec![withdraw.asset_id.clone()],
        fee_lanes: vec![
            ("operation".to_string(), "contract_withdraw".to_string()),
            ("contract".to_string(), withdraw.contract_id.clone()),
            ("asset".to_string(), withdraw.asset_id.clone()),
        ],
    }
}

fn contract_deposit_privacy_proof(
    contract: &Contract,
    spent: &Note,
    deposit: &ContractDeposit,
) -> PrivacyProof {
    let public_inputs = json!({
        "kind": "contract_deposit",
        "contract": contract.public_record(),
        "input_commitment": spent.commitment,
        "nullifier": deposit.nullifier,
        "asset_id": deposit.asset_id,
        "amount": deposit.amount,
        "network_fee": deposit.network_fee,
        "terms_hash": deposit.terms_hash(),
        "output_commitments": output_commitments(&deposit.output_notes),
    });
    let private_witnesses = json!({
        "spent_note": spent.state_record(),
        "output_notes": deposit.output_notes.iter().map(Note::state_record).collect::<Vec<_>>(),
        "expected_change": spent.amount - deposit.amount - deposit.network_fee,
    });
    build_privacy_proof(&deposit.proof_system, &public_inputs, &private_witnesses)
}

fn update_contract_asset_balance(
    contract: &Contract,
    asset_id: &str,
    delta: i128,
) -> ContractEscrowResult<Contract> {
    let current = contract.asset_balances.get(asset_id).copied().unwrap_or(0) as i128;
    let updated_amount = current
        .checked_add(delta)
        .ok_or_else(|| "contract asset balance overflow".to_string())?;
    if updated_amount < 0 {
        return Err("contract asset balance cannot go negative".to_string());
    }
    let mut asset_balances = contract.asset_balances.clone();
    if updated_amount == 0 {
        asset_balances.remove(asset_id);
    } else {
        asset_balances.insert(asset_id.to_string(), updated_amount as u64);
    }
    Ok(Contract {
        asset_balances,
        ..contract.clone()
    })
}

fn create_note(
    defi_state: &mut DefiState,
    owner_view_key: &str,
    asset_id: &str,
    amount: u64,
) -> ContractEscrowResult<Note> {
    defi_state.nonce = defi_state
        .nonce
        .checked_add(1)
        .ok_or_else(|| "note nonce overflow".to_string())?;
    Ok(Note::create(
        owner_view_key,
        asset_id,
        amount,
        defi_state.nonce,
    ))
}

fn ensure_nullifier_available(defi_state: &DefiState, nullifier: &str) -> ContractEscrowResult<()> {
    if defi_state
        .spent_nullifiers
        .iter()
        .any(|spent| spent == nullifier)
    {
        return Err("duplicate nullifier".to_string());
    }
    Ok(())
}

fn add_fee(defi_state: &mut DefiState, asset_id: &str, amount: u64) -> ContractEscrowResult<()> {
    let entry = defi_state
        .fees_collected
        .entry(asset_id.to_string())
        .or_insert(0);
    *entry = entry
        .checked_add(amount)
        .ok_or_else(|| "fee total overflow".to_string())?;
    Ok(())
}

fn output_commitments(output_notes: &[Note]) -> Value {
    Value::Array(
        output_notes
            .iter()
            .map(|note| Value::String(note.commitment.clone()))
            .collect(),
    )
}

fn signed_public_record(mut record: Value, authorization: &Authorization) -> Value {
    let object = record.as_object_mut().expect("signed record object");
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

fn empty_authorization() -> Authorization {
    Authorization {
        signer_label: String::new(),
        auth_scheme: String::new(),
        auth_public_key: String::new(),
        auth_transcript_hash: String::new(),
        auth_signature: String::new(),
    }
}
