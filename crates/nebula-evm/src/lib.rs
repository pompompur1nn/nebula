use std::collections::BTreeMap;

use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{
    AccountInfo, Address, Bytecode, Bytes, ExecutionResult, Output, TxKind, B256, U256,
};
use revm::Evm;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const EVM_ADDRESS_DOMAIN: &[u8] = b"nebula-evm-address-v1";
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;
pub const MAX_CODE_HEX_LEN: usize = 2 * 24_576 * 2;
pub const MAX_CALLDATA_HEX_LEN: usize = 2 * 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvmLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvmOutcome {
    pub success: bool,
    pub gas_used: u64,
    pub output: String,
    pub contract_address: Option<String>,
    pub logs: Vec<EvmLog>,
    pub revert_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvmAccountState {
    pub balance: String,
    pub nonce: u64,
    pub code: String,
    pub storage: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvmStateExport {
    pub accounts: BTreeMap<String, EvmAccountState>,
}

impl EvmStateExport {
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}

pub fn evm_address_for_account(account_id: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(EVM_ADDRESS_DOMAIN);
    hasher.update(account_id.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[12..32])
}

fn parse_address(value: &str, name: &str) -> Result<Address, String> {
    let cleaned = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(cleaned).map_err(|error| format!("{name} is not valid hex: {error}"))?;
    if bytes.len() != 20 {
        return Err(format!("{name} must be a 20-byte hex address"));
    }
    Ok(Address::from_slice(&bytes))
}

fn parse_bytes(value: &str, name: &str, max_hex_len: usize) -> Result<Bytes, String> {
    let cleaned = value.strip_prefix("0x").unwrap_or(value);
    if cleaned.len() > max_hex_len {
        return Err(format!("{name} exceeds the maximum length"));
    }
    let bytes =
        hex::decode(cleaned).map_err(|error| format!("{name} is not valid hex: {error}"))?;
    Ok(Bytes::from(bytes))
}

fn parse_u256(value: &str, name: &str) -> Result<U256, String> {
    let cleaned = value.strip_prefix("0x").unwrap_or(value);
    if cleaned.is_empty() || cleaned.len() > 64 {
        return Err(format!("{name} must be a 1..=64 character hex value"));
    }
    U256::from_str_radix(cleaned, 16).map_err(|error| format!("{name} is not valid hex: {error}"))
}

pub fn validate_address_hex(value: &str, name: &str) -> Result<(), String> {
    parse_address(value, name).map(|_| ())
}

pub fn validate_code_hex(value: &str, name: &str) -> Result<(), String> {
    parse_bytes(value, name, MAX_CODE_HEX_LEN).map(|_| ())
}

pub fn validate_calldata_hex(value: &str, name: &str) -> Result<(), String> {
    parse_bytes(value, name, MAX_CALLDATA_HEX_LEN).map(|_| ())
}

#[derive(Debug, Clone)]
pub struct EvmExecutor {
    db: CacheDB<EmptyDB>,
}

impl Default for EvmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl EvmExecutor {
    pub fn new() -> Self {
        EvmExecutor {
            db: CacheDB::new(EmptyDB::default()),
        }
    }

    pub fn balance_of(&self, address_hex: &str) -> Result<u128, String> {
        let address = parse_address(address_hex, "address")?;
        let balance = self
            .db
            .accounts
            .get(&address)
            .map(|account| account.info.balance)
            .unwrap_or(U256::ZERO);
        u128::try_from(balance).map_err(|_| "EVM balance exceeds u128".to_string())
    }

    pub fn credit_balance(&mut self, address_hex: &str, amount: u128) -> Result<(), String> {
        let address = parse_address(address_hex, "address")?;
        let account = self.db.accounts.entry(address).or_default();
        account.info.balance = account
            .info
            .balance
            .checked_add(U256::from(amount))
            .ok_or_else(|| "EVM balance credit overflowed".to_string())?;
        Ok(())
    }

    pub fn debit_balance(&mut self, address_hex: &str, amount: u128) -> Result<(), String> {
        let address = parse_address(address_hex, "address")?;
        let account = self
            .db
            .accounts
            .get_mut(&address)
            .ok_or_else(|| "EVM account does not exist".to_string())?;
        let debit = U256::from(amount);
        if account.info.balance < debit {
            return Err(format!(
                "insufficient EVM balance: need {amount}, have {}",
                account.info.balance
            ));
        }
        account.info.balance -= debit;
        Ok(())
    }

    pub fn code_of(&self, address_hex: &str) -> Result<String, String> {
        let address = parse_address(address_hex, "address")?;
        let code = self
            .db
            .accounts
            .get(&address)
            .and_then(|account| account.info.code.as_ref())
            .map(|code| hex::encode(code.original_bytes()))
            .unwrap_or_default();
        Ok(code)
    }

    pub fn storage_at(&self, address_hex: &str, slot_hex: &str) -> Result<String, String> {
        let address = parse_address(address_hex, "address")?;
        let slot = parse_u256(slot_hex, "slot")?;
        let value = self
            .db
            .accounts
            .get(&address)
            .and_then(|account| account.storage.get(&slot).copied())
            .unwrap_or(U256::ZERO);
        Ok(hex::encode(value.to_be_bytes::<32>()))
    }

    pub fn deploy(
        &mut self,
        caller_hex: &str,
        init_code_hex: &str,
        value: u128,
        gas_limit: u64,
    ) -> Result<EvmOutcome, String> {
        let init_code = parse_bytes(init_code_hex, "init_code", MAX_CODE_HEX_LEN)?;
        self.execute(
            caller_hex,
            TxKind::Create,
            init_code,
            value,
            gas_limit,
            true,
        )
    }

    pub fn call(
        &mut self,
        caller_hex: &str,
        contract_hex: &str,
        calldata_hex: &str,
        value: u128,
        gas_limit: u64,
    ) -> Result<EvmOutcome, String> {
        let contract = parse_address(contract_hex, "contract")?;
        let calldata = parse_bytes(calldata_hex, "calldata", MAX_CALLDATA_HEX_LEN)?;
        self.execute(
            caller_hex,
            TxKind::Call(contract),
            calldata,
            value,
            gas_limit,
            true,
        )
    }

    pub fn view(
        &mut self,
        caller_hex: &str,
        contract_hex: &str,
        calldata_hex: &str,
        gas_limit: u64,
    ) -> Result<EvmOutcome, String> {
        let contract = parse_address(contract_hex, "contract")?;
        let calldata = parse_bytes(calldata_hex, "calldata", MAX_CALLDATA_HEX_LEN)?;
        self.execute(
            caller_hex,
            TxKind::Call(contract),
            calldata,
            0,
            gas_limit,
            false,
        )
    }

    /// Read-only call that executes against a shared reference to the state database, so it
    /// neither commits nor requires `&mut self` and — crucially — does not clone the whole
    /// state. Callers can run it while holding only a shared borrow, avoiding an
    /// O(total-state) copy per (potentially unauthenticated) view request.
    pub fn view_ref(
        &self,
        caller_hex: &str,
        contract_hex: &str,
        calldata_hex: &str,
        gas_limit: u64,
    ) -> Result<EvmOutcome, String> {
        let caller = parse_address(caller_hex, "caller")?;
        let contract = parse_address(contract_hex, "contract")?;
        let calldata = parse_bytes(calldata_hex, "calldata", MAX_CALLDATA_HEX_LEN)?;
        let nonce = self
            .db
            .accounts
            .get(&caller)
            .map(|account| account.info.nonce)
            .unwrap_or(0);
        let mut evm = Evm::builder()
            .with_ref_db(&self.db)
            .modify_cfg_env(|cfg| {
                cfg.chain_id = 6_874_269;
            })
            .modify_block_env(|block| {
                block.basefee = U256::ZERO;
                block.gas_limit = U256::from(gas_limit).max(U256::from(30_000_000u64));
            })
            .modify_tx_env(|tx| {
                tx.caller = caller;
                tx.transact_to = TxKind::Call(contract);
                tx.data = calldata;
                tx.value = U256::ZERO;
                tx.gas_limit = gas_limit;
                tx.gas_price = U256::ZERO;
                tx.nonce = Some(nonce);
            })
            .build();
        let result = evm
            .transact()
            .map_err(|error| format!("EVM execution failed: {error:?}"))?
            .result;
        drop(evm);
        Ok(outcome_from_result(result))
    }

    fn execute(
        &mut self,
        caller_hex: &str,
        kind: TxKind,
        data: Bytes,
        value: u128,
        gas_limit: u64,
        commit: bool,
    ) -> Result<EvmOutcome, String> {
        let caller = parse_address(caller_hex, "caller")?;
        let nonce = self
            .db
            .accounts
            .get(&caller)
            .map(|account| account.info.nonce)
            .unwrap_or(0);
        let mut evm = Evm::builder()
            .with_db(&mut self.db)
            .modify_cfg_env(|cfg| {
                cfg.chain_id = 6_874_269;
            })
            .modify_block_env(|block| {
                block.basefee = U256::ZERO;
                block.gas_limit = U256::from(gas_limit).max(U256::from(30_000_000u64));
            })
            .modify_tx_env(|tx| {
                tx.caller = caller;
                tx.transact_to = kind;
                tx.data = data;
                tx.value = U256::from(value);
                tx.gas_limit = gas_limit;
                tx.gas_price = U256::ZERO;
                tx.nonce = Some(nonce);
            })
            .build();
        let result = if commit {
            evm.transact_commit()
                .map_err(|error| format!("EVM execution failed: {error:?}"))?
        } else {
            evm.transact()
                .map_err(|error| format!("EVM execution failed: {error:?}"))?
                .result
        };
        drop(evm);
        Ok(outcome_from_result(result))
    }

    pub fn export_state(&self) -> EvmStateExport {
        let mut accounts = BTreeMap::new();
        for (address, account) in &self.db.accounts {
            let code = account
                .info
                .code
                .as_ref()
                .map(|code| hex::encode(code.original_bytes()))
                .unwrap_or_default();
            let mut storage = BTreeMap::new();
            for (slot, value) in &account.storage {
                if *value != U256::ZERO {
                    storage.insert(
                        hex::encode(slot.to_be_bytes::<32>()),
                        hex::encode(value.to_be_bytes::<32>()),
                    );
                }
            }
            if account.info.balance == U256::ZERO
                && account.info.nonce == 0
                && code.is_empty()
                && storage.is_empty()
            {
                continue;
            }
            accounts.insert(
                hex::encode(address.as_slice()),
                EvmAccountState {
                    balance: hex::encode(account.info.balance.to_be_bytes::<32>()),
                    nonce: account.info.nonce,
                    code,
                    storage,
                },
            );
        }
        EvmStateExport { accounts }
    }

    pub fn import_state(export: &EvmStateExport) -> Result<Self, String> {
        let mut executor = EvmExecutor::new();
        for (address_hex, state) in &export.accounts {
            let address = parse_address(address_hex, "evm account address")?;
            let balance = parse_u256(&state.balance, "evm account balance")?;
            let code_bytes =
                hex::decode(&state.code).map_err(|error| format!("evm code hex: {error}"))?;
            let code = if code_bytes.is_empty() {
                None
            } else {
                Some(Bytecode::new_raw(Bytes::from(code_bytes)))
            };
            let code_hash = code
                .as_ref()
                .map(|code| code.hash_slow())
                .unwrap_or(B256::from(revm::primitives::KECCAK_EMPTY));
            let info = AccountInfo {
                balance,
                nonce: state.nonce,
                code_hash,
                code,
            };
            executor.db.insert_account_info(address, info);
            for (slot_hex, value_hex) in &state.storage {
                let slot = parse_u256(slot_hex, "evm storage slot")?;
                let value = parse_u256(value_hex, "evm storage value")?;
                executor
                    .db
                    .insert_account_storage(address, slot, value)
                    .map_err(|error| format!("evm storage import failed: {error:?}"))?;
            }
        }
        Ok(executor)
    }
}

fn outcome_from_result(result: ExecutionResult) -> EvmOutcome {
    match result {
        ExecutionResult::Success {
            gas_used,
            logs,
            output,
            ..
        } => {
            let (output_bytes, contract_address) = match output {
                Output::Create(bytes, address) => {
                    (bytes, address.map(|a| hex::encode(a.as_slice())))
                }
                Output::Call(bytes) => (bytes, None),
            };
            EvmOutcome {
                success: true,
                gas_used,
                output: hex::encode(&output_bytes),
                contract_address,
                logs: logs
                    .into_iter()
                    .map(|log| EvmLog {
                        address: hex::encode(log.address.as_slice()),
                        topics: log
                            .topics()
                            .iter()
                            .map(|topic| hex::encode(topic.as_slice()))
                            .collect(),
                        data: hex::encode(&log.data.data),
                    })
                    .collect(),
                revert_reason: None,
            }
        }
        ExecutionResult::Revert { gas_used, output } => EvmOutcome {
            success: false,
            gas_used,
            output: hex::encode(&output),
            contract_address: None,
            logs: Vec::new(),
            revert_reason: Some("execution reverted".to_string()),
        },
        ExecutionResult::Halt { reason, gas_used } => EvmOutcome {
            success: false,
            gas_used,
            output: String::new(),
            contract_address: None,
            logs: Vec::new(),
            revert_reason: Some(format!("execution halted: {reason:?}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTER_RUNTIME: &str = "6000546001018060005560005260206000f3";

    fn counter_init_code() -> String {
        format!("6012600c60003960126000f3{COUNTER_RUNTIME}")
    }

    fn caller() -> String {
        evm_address_for_account("nbla1testcaller")
    }

    #[test]
    fn evm_address_derivation_is_deterministic_and_distinct() {
        let a = evm_address_for_account("nbla1alice");
        let b = evm_address_for_account("nbla1bob");
        assert_eq!(a.len(), 40);
        assert_eq!(a, evm_address_for_account("nbla1alice"));
        assert_ne!(a, b);
    }

    #[test]
    fn deploys_and_calls_a_counter_contract() {
        let mut executor = EvmExecutor::new();
        let deployed = executor
            .deploy(&caller(), &counter_init_code(), 0, DEFAULT_GAS_LIMIT)
            .unwrap();
        assert!(deployed.success, "{deployed:?}");
        let contract = deployed.contract_address.clone().unwrap();
        assert_eq!(executor.code_of(&contract).unwrap(), COUNTER_RUNTIME);

        let first = executor
            .call(&caller(), &contract, "", 0, DEFAULT_GAS_LIMIT)
            .unwrap();
        assert!(first.success);
        assert!(first.output.ends_with("01"));
        let second = executor
            .call(&caller(), &contract, "", 0, DEFAULT_GAS_LIMIT)
            .unwrap();
        assert!(second.success);
        assert!(second.output.ends_with("02"));
        let slot = executor.storage_at(&contract, "00").unwrap();
        assert!(slot.ends_with("02"));
    }

    #[test]
    fn view_does_not_mutate_state() {
        let mut executor = EvmExecutor::new();
        let deployed = executor
            .deploy(&caller(), &counter_init_code(), 0, DEFAULT_GAS_LIMIT)
            .unwrap();
        let contract = deployed.contract_address.unwrap();
        let viewed = executor
            .view(&caller(), &contract, "", DEFAULT_GAS_LIMIT)
            .unwrap();
        assert!(viewed.success);
        assert!(viewed.output.ends_with("01"));
        let slot = executor.storage_at(&contract, "00").unwrap();
        assert!(slot.ends_with("00"), "view must not persist storage writes");
    }

    #[test]
    fn balances_credit_debit_and_transfer_via_call() {
        let mut executor = EvmExecutor::new();
        let from = caller();
        let to = evm_address_for_account("nbla1recipient");
        executor.credit_balance(&from, 1_000).unwrap();
        assert_eq!(executor.balance_of(&from).unwrap(), 1_000);
        assert!(executor.debit_balance(&from, 2_000).is_err());

        let sent = executor
            .call(&from, &to, "", 250, DEFAULT_GAS_LIMIT)
            .unwrap();
        assert!(sent.success, "{sent:?}");
        assert_eq!(executor.balance_of(&from).unwrap(), 750);
        assert_eq!(executor.balance_of(&to).unwrap(), 250);

        executor.debit_balance(&to, 250).unwrap();
        assert_eq!(executor.balance_of(&to).unwrap(), 0);
    }

    #[test]
    fn reverted_deploys_report_failure() {
        let mut executor = EvmExecutor::new();
        let outcome = executor
            .deploy(&caller(), "6000600060006000fd", 0, DEFAULT_GAS_LIMIT)
            .unwrap();
        assert!(!outcome.success);
        assert!(outcome.revert_reason.is_some());
        assert!(outcome.contract_address.is_none());
    }

    #[test]
    fn state_export_import_round_trips() {
        let mut executor = EvmExecutor::new();
        executor.credit_balance(&caller(), 12_345).unwrap();
        let deployed = executor
            .deploy(&caller(), &counter_init_code(), 0, DEFAULT_GAS_LIMIT)
            .unwrap();
        let contract = deployed.contract_address.unwrap();
        executor
            .call(&caller(), &contract, "", 0, DEFAULT_GAS_LIMIT)
            .unwrap();

        let export = executor.export_state();
        assert!(!export.is_empty());
        let mut imported = EvmExecutor::import_state(&export).unwrap();
        assert_eq!(imported.balance_of(&caller()).unwrap(), 12_345);
        assert_eq!(imported.code_of(&contract).unwrap(), COUNTER_RUNTIME);
        assert!(imported
            .storage_at(&contract, "00")
            .unwrap()
            .ends_with("01"));
        let next = imported
            .call(&caller(), &contract, "", 0, DEFAULT_GAS_LIMIT)
            .unwrap();
        assert!(next.output.ends_with("02"));
        assert_eq!(imported.export_state(), {
            let mut expected = executor.export_state();
            let account = expected.accounts.get_mut(&contract).unwrap();
            account.storage.insert(
                hex::encode([0u8; 32]),
                hex::encode(U256::from(2u64).to_be_bytes::<32>()),
            );
            expected.accounts.get_mut(&caller()).unwrap().nonce += 1;
            expected
        });
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let mut executor = EvmExecutor::new();
        assert!(executor.deploy("zz", "60", 0, DEFAULT_GAS_LIMIT).is_err());
        assert!(executor
            .deploy(&caller(), "not-hex", 0, DEFAULT_GAS_LIMIT)
            .is_err());
        assert!(executor.balance_of("1234").is_err());
        assert!(executor.storage_at(&caller(), "zz").is_err());
    }
}
