use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub const ROLLUP_PROTOCOL_VERSION: u64 = 1;
pub const ROLLUP_DEFAULT_FORCED_INCLUSION_WINDOW_BLOCKS: u64 = 20;
pub const ROLLUP_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 40;
pub const ROLLUP_DEFAULT_SETTLEMENT_INTERVAL_BLOCKS: u64 = 100;
pub const ROLLUP_MAX_BATCH_TRANSACTIONS: usize = 512;
pub const ROLLUP_GENESIS_BATCH_ID: &str = "GENESIS";
pub const ROLLUP_VALIDITY_PROOF_SYSTEM: &str = "devnet-transparent-rollup-validity-proof";
pub const ROLLUP_FRAUD_PROOF_SYSTEM: &str = "devnet-transparent-rollup-fraud-proof";
pub const ROLLUP_STATUS_PENDING: &str = "pending";
pub const ROLLUP_STATUS_INCLUDED: &str = "included";
pub const ROLLUP_STATUS_SUBMITTED: &str = "submitted";
pub const ROLLUP_STATUS_FINAL: &str = "final";
pub const ROLLUP_STATUS_REJECTED: &str = "rejected";
pub const ROLLUP_RECEIPT_SUCCESS: &str = "success";
pub const ROLLUP_RECEIPT_REVERTED: &str = "reverted";
pub const ROLLUP_RECEIPT_FAILED: &str = "failed";
pub const ROLLUP_STATE_WRITE_UPSERT: &str = "upsert";
pub const ROLLUP_STATE_WRITE_DELETE: &str = "delete";

pub type RollupResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupTransactionEnvelope {
    pub tx_id: String,
    pub tx_kind: String,
    pub sender_commitment: String,
    pub nonce: u64,
    pub public_input: Value,
    pub calldata_root: String,
    pub authorization_root: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub priority_fee_units: u64,
    pub submitted_at_height: u64,
}

impl RollupTransactionEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_kind: impl Into<String>,
        sender_commitment: impl Into<String>,
        nonce: u64,
        public_input: Value,
        calldata_root: impl Into<String>,
        authorization_root: impl Into<String>,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        priority_fee_units: u64,
        submitted_at_height: u64,
    ) -> RollupResult<Self> {
        let tx_kind = tx_kind.into();
        let sender_commitment = sender_commitment.into();
        let calldata_root = calldata_root.into();
        let authorization_root = authorization_root.into();
        let fee_asset_id = fee_asset_id.into();
        if tx_kind.is_empty() {
            return Err("rollup transaction kind is required".to_string());
        }
        if sender_commitment.is_empty() {
            return Err("rollup transaction sender commitment is required".to_string());
        }
        if authorization_root.is_empty() {
            return Err("rollup transaction authorization root is required".to_string());
        }
        if priority_fee_units > max_fee_units {
            return Err("rollup transaction priority fee exceeds max fee".to_string());
        }
        let tx_id = rollup_tx_id(
            &tx_kind,
            &sender_commitment,
            nonce,
            &public_input,
            &calldata_root,
            &authorization_root,
        );
        Ok(Self {
            tx_id,
            tx_kind,
            sender_commitment,
            nonce,
            public_input,
            calldata_root,
            authorization_root,
            fee_asset_id,
            max_fee_units,
            priority_fee_units,
            submitted_at_height,
        })
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.tx_kind.is_empty() {
            return Err("rollup transaction kind is required".to_string());
        }
        if self.sender_commitment.is_empty() {
            return Err("rollup transaction sender commitment is required".to_string());
        }
        if self.authorization_root.is_empty() {
            return Err("rollup transaction authorization root is required".to_string());
        }
        if self.priority_fee_units > self.max_fee_units {
            return Err("rollup transaction priority fee exceeds max fee".to_string());
        }
        let expected = rollup_tx_id(
            &self.tx_kind,
            &self.sender_commitment,
            self.nonce,
            &self.public_input,
            &self.calldata_root,
            &self.authorization_root,
        );
        if self.tx_id != expected {
            return Err("rollup transaction id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_transaction",
            "chain_id": CHAIN_ID,
            "tx_id": self.tx_id,
            "tx_kind": self.tx_kind,
            "sender_commitment": self.sender_commitment,
            "nonce": self.nonce,
            "public_input": self.public_input,
            "calldata_root": self.calldata_root,
            "authorization_root": self.authorization_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "priority_fee_units": self.priority_fee_units,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupStateWrite {
    pub key: String,
    pub key_hash: String,
    pub previous_value_hash: String,
    pub new_value_hash: String,
    pub operation: String,
}

impl RollupStateWrite {
    pub fn upsert(
        key: impl Into<String>,
        previous_value_hash: impl Into<String>,
        new_value_hash: impl Into<String>,
    ) -> RollupResult<Self> {
        let key = key.into();
        let previous_value_hash = previous_value_hash.into();
        let new_value_hash = new_value_hash.into();
        let write = Self {
            key_hash: rollup_state_key_hash(&key),
            key,
            previous_value_hash,
            new_value_hash,
            operation: ROLLUP_STATE_WRITE_UPSERT.to_string(),
        };
        write.validate()?;
        Ok(write)
    }

    pub fn delete(
        key: impl Into<String>,
        previous_value_hash: impl Into<String>,
    ) -> RollupResult<Self> {
        let key = key.into();
        let previous_value_hash = previous_value_hash.into();
        let write = Self {
            key_hash: rollup_state_key_hash(&key),
            key,
            previous_value_hash,
            new_value_hash: rollup_empty_state_value_hash(),
            operation: ROLLUP_STATE_WRITE_DELETE.to_string(),
        };
        write.validate()?;
        Ok(write)
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.key.is_empty() {
            return Err("rollup state write key is required".to_string());
        }
        if self.key_hash != rollup_state_key_hash(&self.key) {
            return Err("rollup state write key hash mismatch".to_string());
        }
        if self.previous_value_hash.is_empty() {
            return Err("rollup state write previous value hash is required".to_string());
        }
        if self.new_value_hash.is_empty() {
            return Err("rollup state write new value hash is required".to_string());
        }
        match self.operation.as_str() {
            ROLLUP_STATE_WRITE_UPSERT => {
                if self.new_value_hash == rollup_empty_state_value_hash() {
                    return Err("rollup upsert write requires a non-empty value hash".to_string());
                }
            }
            ROLLUP_STATE_WRITE_DELETE => {
                if self.new_value_hash != rollup_empty_state_value_hash() {
                    return Err("rollup delete write must commit the empty value hash".to_string());
                }
            }
            _ => return Err("rollup state write operation is invalid".to_string()),
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "key_hash": self.key_hash,
            "previous_value_hash": self.previous_value_hash,
            "new_value_hash": self.new_value_hash,
            "operation": self.operation,
        })
    }

    pub fn state_record(&self) -> Value {
        json!({
            "key": self.key,
            "key_hash": self.key_hash,
            "previous_value_hash": self.previous_value_hash,
            "new_value_hash": self.new_value_hash,
            "operation": self.operation,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupWithdrawalRequest {
    pub withdrawal_id: String,
    pub tx_id: String,
    pub withdrawal_index: u64,
    pub asset_id: String,
    pub amount: u64,
    pub fee_units: u64,
    pub recipient_commitment: String,
    pub destination_chain: String,
    pub destination_address_hash: String,
    pub requested_at_height: u64,
    pub status: String,
}

impl RollupWithdrawalRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_id: impl Into<String>,
        withdrawal_index: u64,
        asset_id: impl Into<String>,
        amount: u64,
        fee_units: u64,
        recipient_commitment: impl Into<String>,
        destination_chain: impl Into<String>,
        destination_address_hash: impl Into<String>,
        requested_at_height: u64,
    ) -> RollupResult<Self> {
        let tx_id = tx_id.into();
        let asset_id = asset_id.into();
        let recipient_commitment = recipient_commitment.into();
        let destination_chain = destination_chain.into();
        let destination_address_hash = destination_address_hash.into();
        let withdrawal_id = rollup_withdrawal_id(
            &tx_id,
            withdrawal_index,
            &asset_id,
            amount,
            fee_units,
            &recipient_commitment,
            &destination_chain,
            &destination_address_hash,
        );
        let withdrawal = Self {
            withdrawal_id,
            tx_id,
            withdrawal_index,
            asset_id,
            amount,
            fee_units,
            recipient_commitment,
            destination_chain,
            destination_address_hash,
            requested_at_height,
            status: ROLLUP_STATUS_PENDING.to_string(),
        };
        withdrawal.validate()?;
        Ok(withdrawal)
    }

    pub fn mark_included(&self) -> Self {
        let mut withdrawal = self.clone();
        withdrawal.status = ROLLUP_STATUS_INCLUDED.to_string();
        withdrawal
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.tx_id.is_empty() {
            return Err("rollup withdrawal tx id is required".to_string());
        }
        if self.asset_id.is_empty() {
            return Err("rollup withdrawal asset id is required".to_string());
        }
        if self.amount == 0 {
            return Err("rollup withdrawal amount must be positive".to_string());
        }
        if self.fee_units > self.amount {
            return Err("rollup withdrawal fee exceeds amount".to_string());
        }
        if self.recipient_commitment.is_empty() {
            return Err("rollup withdrawal recipient commitment is required".to_string());
        }
        if self.destination_chain.is_empty() {
            return Err("rollup withdrawal destination chain is required".to_string());
        }
        if self.destination_address_hash.is_empty() {
            return Err("rollup withdrawal destination address hash is required".to_string());
        }
        let expected = rollup_withdrawal_id(
            &self.tx_id,
            self.withdrawal_index,
            &self.asset_id,
            self.amount,
            self.fee_units,
            &self.recipient_commitment,
            &self.destination_chain,
            &self.destination_address_hash,
        );
        if self.withdrawal_id != expected {
            return Err("rollup withdrawal id mismatch".to_string());
        }
        if !matches!(
            self.status.as_str(),
            ROLLUP_STATUS_PENDING
                | ROLLUP_STATUS_INCLUDED
                | ROLLUP_STATUS_SUBMITTED
                | ROLLUP_STATUS_FINAL
                | ROLLUP_STATUS_REJECTED
        ) {
            return Err("rollup withdrawal status is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_withdrawal_request",
            "chain_id": CHAIN_ID,
            "withdrawal_id": self.withdrawal_id,
            "tx_id": self.tx_id,
            "withdrawal_index": self.withdrawal_index,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "fee_units": self.fee_units,
            "recipient_commitment": self.recipient_commitment,
            "destination_chain": self.destination_chain,
            "destination_address_hash": self.destination_address_hash,
            "requested_at_height": self.requested_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupExecutionReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub tx_id: String,
    pub tx_index: u64,
    pub status: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub state_write_root: String,
    pub withdrawal_root: String,
    pub emitted_event_root: String,
    pub gas_used: u64,
    pub fee_charged_units: u64,
    pub sequencer_label: String,
    pub error_code_hash: String,
    pub state_writes: Vec<RollupStateWrite>,
    pub withdrawals: Vec<RollupWithdrawalRequest>,
    pub emitted_events: Vec<Value>,
}

impl RollupExecutionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn from_state_transition(
        tx_id: impl Into<String>,
        tx_index: u64,
        status: impl Into<String>,
        pre_state_root: impl Into<String>,
        post_state_root: impl Into<String>,
        state_writes: Vec<RollupStateWrite>,
        withdrawals: Vec<RollupWithdrawalRequest>,
        emitted_events: Vec<Value>,
        gas_used: u64,
        fee_charged_units: u64,
        sequencer_label: impl Into<String>,
        error_code_hash: impl Into<String>,
    ) -> RollupResult<Self> {
        let receipt = Self {
            receipt_id: String::new(),
            batch_id: String::new(),
            tx_id: tx_id.into(),
            tx_index,
            status: status.into(),
            pre_state_root: pre_state_root.into(),
            post_state_root: post_state_root.into(),
            state_write_root: rollup_state_write_root(&state_writes),
            withdrawal_root: rollup_withdrawal_root(&withdrawals),
            emitted_event_root: rollup_value_root("ROLLUP-EMITTED-EVENT", &emitted_events),
            gas_used,
            fee_charged_units,
            sequencer_label: sequencer_label.into(),
            error_code_hash: error_code_hash.into(),
            state_writes,
            withdrawals,
            emitted_events,
        };
        receipt.validate_transition()?;
        Ok(receipt)
    }

    pub fn with_batch(mut self, batch_id: &str) -> Self {
        self.batch_id = batch_id.to_string();
        self.receipt_id = rollup_receipt_id(
            batch_id,
            &self.tx_id,
            self.tx_index,
            &self.transition_root(),
        );
        self
    }

    pub fn transition_record(&self) -> Value {
        json!({
            "kind": "rollup_execution_transition",
            "chain_id": CHAIN_ID,
            "tx_id": self.tx_id,
            "tx_index": self.tx_index,
            "status": self.status,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "state_write_root": self.state_write_root,
            "withdrawal_root": self.withdrawal_root,
            "emitted_event_root": self.emitted_event_root,
            "gas_used": self.gas_used,
            "fee_charged_units": self.fee_charged_units,
            "sequencer_label": self.sequencer_label,
            "error_code_hash": self.error_code_hash,
            "state_writes": self.state_writes.iter().map(RollupStateWrite::public_record).collect::<Vec<_>>(),
            "withdrawals": self.withdrawals.iter().map(RollupWithdrawalRequest::public_record).collect::<Vec<_>>(),
            "emitted_events": self.emitted_events,
        })
    }

    pub fn transition_root(&self) -> String {
        domain_hash(
            "ROLLUP-EXECUTION-TRANSITION",
            &[HashPart::Json(&self.transition_record())],
            32,
        )
    }

    pub fn validate_transition(&self) -> RollupResult<()> {
        if self.tx_id.is_empty() {
            return Err("rollup receipt tx id is required".to_string());
        }
        if !matches!(
            self.status.as_str(),
            ROLLUP_RECEIPT_SUCCESS | ROLLUP_RECEIPT_REVERTED | ROLLUP_RECEIPT_FAILED
        ) {
            return Err("rollup receipt status is invalid".to_string());
        }
        if self.pre_state_root.is_empty() || self.post_state_root.is_empty() {
            return Err("rollup receipt state roots are required".to_string());
        }
        let mut keys = BTreeSet::new();
        for write in &self.state_writes {
            write.validate()?;
            if !keys.insert(write.key_hash.clone()) {
                return Err("rollup receipt contains duplicate state writes".to_string());
            }
        }
        for withdrawal in &self.withdrawals {
            withdrawal.validate()?;
            if withdrawal.tx_id != self.tx_id {
                return Err("rollup receipt withdrawal tx id mismatch".to_string());
            }
        }
        if self.status != ROLLUP_RECEIPT_SUCCESS && !self.withdrawals.is_empty() {
            return Err("rollup non-success receipt cannot emit withdrawals".to_string());
        }
        if self.state_write_root != rollup_state_write_root(&self.state_writes) {
            return Err("rollup receipt state write root mismatch".to_string());
        }
        if self.withdrawal_root != rollup_withdrawal_root(&self.withdrawals) {
            return Err("rollup receipt withdrawal root mismatch".to_string());
        }
        if self.emitted_event_root
            != rollup_value_root("ROLLUP-EMITTED-EVENT", &self.emitted_events)
        {
            return Err("rollup receipt emitted event root mismatch".to_string());
        }
        Ok(())
    }

    pub fn validate_for_batch(&self, batch_id: &str) -> RollupResult<()> {
        self.validate_transition()?;
        if self.batch_id != batch_id {
            return Err("rollup receipt batch id mismatch".to_string());
        }
        let expected = rollup_receipt_id(
            batch_id,
            &self.tx_id,
            self.tx_index,
            &self.transition_root(),
        );
        if self.receipt_id != expected {
            return Err("rollup receipt id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.transition_record();
        let object = record
            .as_object_mut()
            .expect("rollup receipt transition record object");
        object.insert(
            "kind".to_string(),
            Value::String("rollup_execution_receipt".to_string()),
        );
        object.insert(
            "receipt_id".to_string(),
            Value::String(self.receipt_id.clone()),
        );
        object.insert("batch_id".to_string(), Value::String(self.batch_id.clone()));
        object.insert(
            "transition_root".to_string(),
            Value::String(self.transition_root()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupForcedInclusionRequest {
    pub request_id: String,
    pub tx_id: String,
    pub tx_public_hash: String,
    pub requester_commitment: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub inclusion_fee_units: u64,
    pub status: String,
    pub included_in_batch_id: String,
    pub included_at_height: u64,
}

impl RollupForcedInclusionRequest {
    pub fn open(
        tx_id: impl Into<String>,
        tx_public_hash: impl Into<String>,
        requester_commitment: impl Into<String>,
        opened_at_height: u64,
        window_blocks: u64,
        inclusion_fee_units: u64,
    ) -> RollupResult<Self> {
        if window_blocks == 0 {
            return Err("rollup forced inclusion window must be positive".to_string());
        }
        let tx_id = tx_id.into();
        let tx_public_hash = tx_public_hash.into();
        let requester_commitment = requester_commitment.into();
        let deadline_height = opened_at_height.saturating_add(window_blocks);
        let request_id = rollup_forced_inclusion_id(
            &tx_id,
            &tx_public_hash,
            &requester_commitment,
            opened_at_height,
            deadline_height,
        );
        let request = Self {
            request_id,
            tx_id,
            tx_public_hash,
            requester_commitment,
            opened_at_height,
            deadline_height,
            inclusion_fee_units,
            status: ROLLUP_STATUS_PENDING.to_string(),
            included_in_batch_id: String::new(),
            included_at_height: 0,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn include_in_batch(&self, batch_id: &str, included_at_height: u64) -> Self {
        let mut request = self.clone();
        request.status = ROLLUP_STATUS_INCLUDED.to_string();
        request.included_in_batch_id = batch_id.to_string();
        request.included_at_height = included_at_height;
        request
    }

    pub fn is_due(&self, current_height: u64) -> bool {
        self.status == ROLLUP_STATUS_PENDING && self.deadline_height <= current_height
    }

    pub fn request_record(&self) -> Value {
        json!({
            "kind": "rollup_forced_inclusion_request",
            "chain_id": CHAIN_ID,
            "request_id": self.request_id,
            "tx_id": self.tx_id,
            "tx_public_hash": self.tx_public_hash,
            "requester_commitment": self.requester_commitment,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "inclusion_fee_units": self.inclusion_fee_units,
        })
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.tx_id.is_empty() {
            return Err("rollup forced inclusion tx id is required".to_string());
        }
        if self.tx_public_hash.is_empty() {
            return Err("rollup forced inclusion tx public hash is required".to_string());
        }
        if self.requester_commitment.is_empty() {
            return Err("rollup forced inclusion requester commitment is required".to_string());
        }
        if self.deadline_height <= self.opened_at_height {
            return Err(
                "rollup forced inclusion deadline must be after opening height".to_string(),
            );
        }
        let expected = rollup_forced_inclusion_id(
            &self.tx_id,
            &self.tx_public_hash,
            &self.requester_commitment,
            self.opened_at_height,
            self.deadline_height,
        );
        if self.request_id != expected {
            return Err("rollup forced inclusion request id mismatch".to_string());
        }
        match self.status.as_str() {
            ROLLUP_STATUS_PENDING => {
                if !self.included_in_batch_id.is_empty() || self.included_at_height != 0 {
                    return Err(
                        "pending rollup forced inclusion cannot have inclusion fields".to_string(),
                    );
                }
            }
            ROLLUP_STATUS_INCLUDED => {
                if self.included_in_batch_id.is_empty() {
                    return Err("included rollup forced inclusion requires batch id".to_string());
                }
                if self.included_at_height < self.opened_at_height {
                    return Err(
                        "rollup forced inclusion included before opening height".to_string()
                    );
                }
            }
            _ => return Err("rollup forced inclusion status is invalid".to_string()),
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.request_record();
        let object = record
            .as_object_mut()
            .expect("rollup forced inclusion request record object");
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "included_in_batch_id".to_string(),
            Value::String(self.included_in_batch_id.clone()),
        );
        object.insert(
            "included_at_height".to_string(),
            Value::Number(self.included_at_height.into()),
        );
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupDaReference {
    pub reference_id: String,
    pub provider: String,
    pub namespace: String,
    pub payload_hash: String,
    pub payload_byte_size: u64,
    pub shard_root: String,
    pub shard_count: u64,
    pub erasure_root: String,
    pub published_at_height: u64,
    pub expires_at_height: u64,
}

impl RollupDaReference {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: impl Into<String>,
        namespace: impl Into<String>,
        payload_hash: impl Into<String>,
        payload_byte_size: u64,
        shard_hashes: &[String],
        erasure_root: impl Into<String>,
        published_at_height: u64,
        ttl_blocks: u64,
    ) -> RollupResult<Self> {
        let provider = provider.into();
        let namespace = namespace.into();
        let payload_hash = payload_hash.into();
        let shard_root = rollup_string_root("ROLLUP-DA-SHARD", shard_hashes);
        let shard_count = shard_hashes.len() as u64;
        let erasure_root = erasure_root.into();
        let expires_at_height = published_at_height.saturating_add(ttl_blocks);
        let reference_id = rollup_da_reference_id(
            &provider,
            &namespace,
            &payload_hash,
            &shard_root,
            published_at_height,
        );
        let reference = Self {
            reference_id,
            provider,
            namespace,
            payload_hash,
            payload_byte_size,
            shard_root,
            shard_count,
            erasure_root,
            published_at_height,
            expires_at_height,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.provider.is_empty() {
            return Err("rollup DA provider is required".to_string());
        }
        if self.namespace.is_empty() {
            return Err("rollup DA namespace is required".to_string());
        }
        if self.payload_hash.is_empty() {
            return Err("rollup DA payload hash is required".to_string());
        }
        if self.payload_byte_size == 0 {
            return Err("rollup DA payload byte size must be positive".to_string());
        }
        if self.shard_root.is_empty() {
            return Err("rollup DA shard root is required".to_string());
        }
        if self.shard_count == 0 {
            return Err("rollup DA shard count must be positive".to_string());
        }
        if self.expires_at_height <= self.published_at_height {
            return Err("rollup DA expiry must be after publish height".to_string());
        }
        let expected = rollup_da_reference_id(
            &self.provider,
            &self.namespace,
            &self.payload_hash,
            &self.shard_root,
            self.published_at_height,
        );
        if self.reference_id != expected {
            return Err("rollup DA reference id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_da_reference",
            "chain_id": CHAIN_ID,
            "reference_id": self.reference_id,
            "provider": self.provider,
            "namespace": self.namespace,
            "payload_hash": self.payload_hash,
            "payload_byte_size": self.payload_byte_size,
            "shard_root": self.shard_root,
            "shard_count": self.shard_count,
            "erasure_root": self.erasure_root,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupBatchHeader {
    pub version: u64,
    pub chain_id: String,
    pub batch_number: u64,
    pub epoch: u64,
    pub sequencer_id: String,
    pub sequencer_label: String,
    pub parent_batch_id: String,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub timestamp_ms: u64,
    pub previous_state_root: String,
    pub post_state_root: String,
    pub tx_root: String,
    pub tx_count: u64,
    pub receipt_root: String,
    pub receipt_count: u64,
    pub forced_inclusion_root: String,
    pub forced_inclusion_count: u64,
    pub withdrawal_root: String,
    pub withdrawal_count: u64,
    pub da_root: String,
    pub da_reference_count: u64,
    pub state_transition_root: String,
    pub fee_root: String,
    pub gas_used: u64,
    pub validity_public_input_hash: String,
    pub expected_validity_proof_system: String,
}

impl RollupBatchHeader {
    pub fn state_record(&self) -> Value {
        json!({
            "version": self.version,
            "chain_id": self.chain_id,
            "batch_number": self.batch_number,
            "epoch": self.epoch,
            "sequencer_id": self.sequencer_id,
            "sequencer_label": self.sequencer_label,
            "parent_batch_id": self.parent_batch_id,
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "timestamp_ms": self.timestamp_ms,
            "previous_state_root": self.previous_state_root,
            "post_state_root": self.post_state_root,
            "tx_root": self.tx_root,
            "tx_count": self.tx_count,
            "receipt_root": self.receipt_root,
            "receipt_count": self.receipt_count,
            "forced_inclusion_root": self.forced_inclusion_root,
            "forced_inclusion_count": self.forced_inclusion_count,
            "withdrawal_root": self.withdrawal_root,
            "withdrawal_count": self.withdrawal_count,
            "da_root": self.da_root,
            "da_reference_count": self.da_reference_count,
            "state_transition_root": self.state_transition_root,
            "fee_root": self.fee_root,
            "gas_used": self.gas_used,
            "validity_public_input_hash": self.validity_public_input_hash,
            "expected_validity_proof_system": self.expected_validity_proof_system,
        })
    }

    pub fn batch_id(&self) -> String {
        rollup_batch_id(self)
    }

    pub fn validate_static(&self) -> RollupResult<()> {
        if self.version != ROLLUP_PROTOCOL_VERSION {
            return Err("rollup batch header version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("rollup batch header chain id mismatch".to_string());
        }
        if self.sequencer_id.is_empty() {
            return Err("rollup batch header sequencer id is required".to_string());
        }
        if self.sequencer_label.is_empty() {
            return Err("rollup batch header sequencer label is required".to_string());
        }
        if self.l2_end_height < self.l2_start_height {
            return Err("rollup batch header height range is invalid".to_string());
        }
        if self.previous_state_root.is_empty() || self.post_state_root.is_empty() {
            return Err("rollup batch header state roots are required".to_string());
        }
        if self.tx_count as usize > ROLLUP_MAX_BATCH_TRANSACTIONS {
            return Err("rollup batch exceeds max transaction count".to_string());
        }
        if self.expected_validity_proof_system.is_empty() {
            return Err("rollup batch expected validity proof system is required".to_string());
        }
        if self.validity_public_input_hash.is_empty() {
            return Err("rollup batch validity public input hash is required".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.state_record();
        record
            .as_object_mut()
            .expect("rollup batch header state record object")
            .insert("batch_id".to_string(), Value::String(self.batch_id()));
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupBatchBuildInput {
    pub batch_number: u64,
    pub epoch: u64,
    pub sequencer_id: String,
    pub sequencer_label: String,
    pub parent_batch_id: String,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub timestamp_ms: u64,
    pub previous_state_root: String,
    pub post_state_root: String,
    pub transactions: Vec<RollupTransactionEnvelope>,
    pub receipts: Vec<RollupExecutionReceipt>,
    pub forced_inclusions: Vec<RollupForcedInclusionRequest>,
    pub da_references: Vec<RollupDaReference>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupSequencerBatch {
    pub header: RollupBatchHeader,
    pub transactions: Vec<RollupTransactionEnvelope>,
    pub receipts: Vec<RollupExecutionReceipt>,
    pub forced_inclusions: Vec<RollupForcedInclusionRequest>,
    pub withdrawals: Vec<RollupWithdrawalRequest>,
    pub da_references: Vec<RollupDaReference>,
    pub validity_envelope: Option<RollupValidityEnvelope>,
}

impl RollupSequencerBatch {
    pub fn build(input: RollupBatchBuildInput) -> RollupResult<Self> {
        if input.transactions.len() > ROLLUP_MAX_BATCH_TRANSACTIONS {
            return Err("rollup batch exceeds max transaction count".to_string());
        }
        let withdrawals = rollup_withdrawals_from_receipts(&input.receipts);
        let tx_root = rollup_tx_root(&input.transactions);
        let receipt_root = rollup_receipt_root(&input.receipts);
        let forced_inclusion_root = rollup_forced_inclusion_root(&input.forced_inclusions);
        let withdrawal_root = rollup_withdrawal_root(&withdrawals);
        let da_root = rollup_da_reference_root(&input.da_references);
        let state_transition_root = rollup_state_transition_root(
            &input.previous_state_root,
            &input.post_state_root,
            &receipt_root,
        );
        let fee_root = rollup_fee_root(&input.receipts);
        let gas_used = input.receipts.iter().fold(0_u64, |total, receipt| {
            total.saturating_add(receipt.gas_used)
        });
        let validity_public_input_hash = rollup_validity_public_input_hash(
            &input.previous_state_root,
            &input.post_state_root,
            &tx_root,
            &receipt_root,
            &withdrawal_root,
            &da_root,
        );
        let parent_batch_id = if input.parent_batch_id.is_empty() && input.batch_number == 0 {
            ROLLUP_GENESIS_BATCH_ID.to_string()
        } else {
            input.parent_batch_id
        };
        let header = RollupBatchHeader {
            version: ROLLUP_PROTOCOL_VERSION,
            chain_id: CHAIN_ID.to_string(),
            batch_number: input.batch_number,
            epoch: input.epoch,
            sequencer_id: input.sequencer_id,
            sequencer_label: input.sequencer_label,
            parent_batch_id,
            l2_start_height: input.l2_start_height,
            l2_end_height: input.l2_end_height,
            timestamp_ms: input.timestamp_ms,
            previous_state_root: input.previous_state_root,
            post_state_root: input.post_state_root,
            tx_root,
            tx_count: input.transactions.len() as u64,
            receipt_root,
            receipt_count: input.receipts.len() as u64,
            forced_inclusion_root,
            forced_inclusion_count: input.forced_inclusions.len() as u64,
            withdrawal_root,
            withdrawal_count: withdrawals.len() as u64,
            da_root,
            da_reference_count: input.da_references.len() as u64,
            state_transition_root,
            fee_root,
            gas_used,
            validity_public_input_hash,
            expected_validity_proof_system: ROLLUP_VALIDITY_PROOF_SYSTEM.to_string(),
        };
        header.validate_static()?;
        let batch_id = header.batch_id();
        let receipts = input
            .receipts
            .into_iter()
            .map(|receipt| receipt.with_batch(&batch_id))
            .collect::<Vec<_>>();
        let withdrawals = rollup_withdrawals_from_receipts(&receipts);
        let batch = Self {
            header,
            transactions: input.transactions,
            receipts,
            forced_inclusions: input.forced_inclusions,
            withdrawals,
            da_references: input.da_references,
            validity_envelope: None,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn batch_id(&self) -> String {
        self.header.batch_id()
    }

    pub fn with_validity_envelope(
        mut self,
        validity_envelope: RollupValidityEnvelope,
    ) -> RollupResult<Self> {
        validity_envelope.validate_for_batch_header(&self.header)?;
        self.validity_envelope = Some(validity_envelope);
        Ok(self)
    }

    pub fn validate(&self) -> RollupResult<()> {
        self.header.validate_static()?;
        let batch_id = self.batch_id();
        if self.header.tx_root != rollup_tx_root(&self.transactions) {
            return Err("rollup batch tx root mismatch".to_string());
        }
        if self.header.tx_count != self.transactions.len() as u64 {
            return Err("rollup batch tx count mismatch".to_string());
        }
        if self.header.receipt_root != rollup_receipt_root(&self.receipts) {
            return Err("rollup batch receipt root mismatch".to_string());
        }
        if self.header.receipt_count != self.receipts.len() as u64 {
            return Err("rollup batch receipt count mismatch".to_string());
        }
        if self.header.forced_inclusion_root
            != rollup_forced_inclusion_root(&self.forced_inclusions)
        {
            return Err("rollup batch forced inclusion root mismatch".to_string());
        }
        if self.header.forced_inclusion_count != self.forced_inclusions.len() as u64 {
            return Err("rollup batch forced inclusion count mismatch".to_string());
        }
        if self.header.da_root != rollup_da_reference_root(&self.da_references) {
            return Err("rollup batch DA root mismatch".to_string());
        }
        if self.header.da_reference_count != self.da_references.len() as u64 {
            return Err("rollup batch DA reference count mismatch".to_string());
        }
        let aggregate_withdrawals = rollup_withdrawals_from_receipts(&self.receipts);
        if self.withdrawals != aggregate_withdrawals {
            return Err("rollup batch withdrawal aggregate mismatch".to_string());
        }
        if self.header.withdrawal_root != rollup_withdrawal_root(&self.withdrawals) {
            return Err("rollup batch withdrawal root mismatch".to_string());
        }
        if self.header.withdrawal_count != self.withdrawals.len() as u64 {
            return Err("rollup batch withdrawal count mismatch".to_string());
        }
        let expected_transition_root = rollup_state_transition_root(
            &self.header.previous_state_root,
            &self.header.post_state_root,
            &self.header.receipt_root,
        );
        if self.header.state_transition_root != expected_transition_root {
            return Err("rollup batch state transition root mismatch".to_string());
        }
        if self.header.fee_root != rollup_fee_root(&self.receipts) {
            return Err("rollup batch fee root mismatch".to_string());
        }
        let gas_used = self.receipts.iter().fold(0_u64, |total, receipt| {
            total.saturating_add(receipt.gas_used)
        });
        if self.header.gas_used != gas_used {
            return Err("rollup batch gas used mismatch".to_string());
        }
        let expected_validity_hash = rollup_validity_public_input_hash(
            &self.header.previous_state_root,
            &self.header.post_state_root,
            &self.header.tx_root,
            &self.header.receipt_root,
            &self.header.withdrawal_root,
            &self.header.da_root,
        );
        if self.header.validity_public_input_hash != expected_validity_hash {
            return Err("rollup batch validity public input hash mismatch".to_string());
        }

        let mut tx_ids = BTreeSet::new();
        for transaction in &self.transactions {
            transaction.validate()?;
            if !tx_ids.insert(transaction.tx_id.clone()) {
                return Err("rollup batch contains duplicate transactions".to_string());
            }
        }
        for (expected_index, receipt) in self.receipts.iter().enumerate() {
            receipt.validate_for_batch(&batch_id)?;
            if receipt.tx_index != expected_index as u64 {
                return Err("rollup batch receipt index mismatch".to_string());
            }
            let transaction = self
                .transactions
                .get(expected_index)
                .ok_or_else(|| "rollup receipt has no matching transaction".to_string())?;
            if receipt.tx_id != transaction.tx_id {
                return Err("rollup receipt tx id does not match transaction order".to_string());
            }
        }
        let mut receipt_ids = BTreeSet::new();
        for receipt in &self.receipts {
            if !receipt_ids.insert(receipt.receipt_id.clone()) {
                return Err("rollup batch contains duplicate receipts".to_string());
            }
        }
        let mut withdrawal_ids = BTreeSet::new();
        for withdrawal in &self.withdrawals {
            if !withdrawal_ids.insert(withdrawal.withdrawal_id.clone()) {
                return Err("rollup batch contains duplicate withdrawals".to_string());
            }
        }
        let mut forced_ids = BTreeSet::new();
        for request in &self.forced_inclusions {
            request.validate()?;
            if request.status != ROLLUP_STATUS_PENDING {
                return Err(
                    "rollup batch forced inclusion must carry the pending request".to_string(),
                );
            }
            if !forced_ids.insert(request.request_id.clone()) {
                return Err("rollup batch contains duplicate forced inclusions".to_string());
            }
            if !tx_ids.contains(&request.tx_id) {
                return Err("rollup forced inclusion tx is missing from batch".to_string());
            }
        }
        let mut da_ids = BTreeSet::new();
        for reference in &self.da_references {
            reference.validate()?;
            if !da_ids.insert(reference.reference_id.clone()) {
                return Err("rollup batch contains duplicate DA references".to_string());
            }
        }
        if let Some(envelope) = &self.validity_envelope {
            envelope.validate_for_batch_header(&self.header)?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_sequencer_batch",
            "chain_id": CHAIN_ID,
            "batch_id": self.batch_id(),
            "header": self.header.public_record(),
            "transactions": self.transactions.iter().map(RollupTransactionEnvelope::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.iter().map(RollupExecutionReceipt::public_record).collect::<Vec<_>>(),
            "forced_inclusions": self.forced_inclusions.iter().map(RollupForcedInclusionRequest::public_record).collect::<Vec<_>>(),
            "withdrawals": self.withdrawals.iter().map(RollupWithdrawalRequest::public_record).collect::<Vec<_>>(),
            "da_references": self.da_references.iter().map(RollupDaReference::public_record).collect::<Vec<_>>(),
            "validity_envelope": self.validity_envelope.as_ref().map(RollupValidityEnvelope::public_record),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupValidityEnvelope {
    pub envelope_id: String,
    pub batch_id: String,
    pub batch_number: u64,
    pub state_transition_root: String,
    pub public_input_hash: String,
    pub proof_system: String,
    pub proof_root: String,
    pub prover_label: String,
    pub submitted_at_height: u64,
    pub challenge_window_end_height: u64,
    pub status: String,
}

impl RollupValidityEnvelope {
    pub fn new(
        header: &RollupBatchHeader,
        prover_label: impl Into<String>,
        proof_system: impl Into<String>,
        proof_root: impl Into<String>,
        submitted_at_height: u64,
        challenge_window_blocks: u64,
    ) -> RollupResult<Self> {
        if challenge_window_blocks == 0 {
            return Err("rollup validity challenge window must be positive".to_string());
        }
        let batch_id = header.batch_id();
        let prover_label = prover_label.into();
        let proof_system = proof_system.into();
        let proof_root = proof_root.into();
        let envelope_id = rollup_validity_envelope_id(
            &batch_id,
            &header.state_transition_root,
            &header.validity_public_input_hash,
            &proof_system,
            &proof_root,
        );
        let envelope = Self {
            envelope_id,
            batch_id,
            batch_number: header.batch_number,
            state_transition_root: header.state_transition_root.clone(),
            public_input_hash: header.validity_public_input_hash.clone(),
            proof_system,
            proof_root,
            prover_label,
            submitted_at_height,
            challenge_window_end_height: submitted_at_height
                .saturating_add(challenge_window_blocks),
            status: ROLLUP_STATUS_SUBMITTED.to_string(),
        };
        envelope.validate_for_batch_header(header)?;
        Ok(envelope)
    }

    pub fn envelope_root(&self) -> String {
        domain_hash(
            "ROLLUP-VALIDITY-ENVELOPE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate_for_batch_header(&self, header: &RollupBatchHeader) -> RollupResult<()> {
        if self.batch_id != header.batch_id() {
            return Err("rollup validity envelope batch id mismatch".to_string());
        }
        if self.batch_number != header.batch_number {
            return Err("rollup validity envelope batch number mismatch".to_string());
        }
        if self.state_transition_root != header.state_transition_root {
            return Err("rollup validity envelope state transition root mismatch".to_string());
        }
        if self.public_input_hash != header.validity_public_input_hash {
            return Err("rollup validity envelope public input hash mismatch".to_string());
        }
        if self.proof_system != header.expected_validity_proof_system {
            return Err("rollup validity envelope proof system mismatch".to_string());
        }
        self.validate()
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.batch_id.is_empty() {
            return Err("rollup validity envelope batch id is required".to_string());
        }
        if self.state_transition_root.is_empty() {
            return Err("rollup validity envelope state transition root is required".to_string());
        }
        if self.public_input_hash.is_empty() {
            return Err("rollup validity envelope public input hash is required".to_string());
        }
        if self.proof_system.is_empty() {
            return Err("rollup validity envelope proof system is required".to_string());
        }
        if self.proof_root.is_empty() {
            return Err("rollup validity envelope proof root is required".to_string());
        }
        if self.prover_label.is_empty() {
            return Err("rollup validity envelope prover label is required".to_string());
        }
        if self.challenge_window_end_height <= self.submitted_at_height {
            return Err("rollup validity envelope challenge window is invalid".to_string());
        }
        let expected = rollup_validity_envelope_id(
            &self.batch_id,
            &self.state_transition_root,
            &self.public_input_hash,
            &self.proof_system,
            &self.proof_root,
        );
        if self.envelope_id != expected {
            return Err("rollup validity envelope id mismatch".to_string());
        }
        if !matches!(
            self.status.as_str(),
            ROLLUP_STATUS_SUBMITTED | ROLLUP_STATUS_FINAL | ROLLUP_STATUS_REJECTED
        ) {
            return Err("rollup validity envelope status is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_validity_envelope",
            "chain_id": CHAIN_ID,
            "envelope_id": self.envelope_id,
            "batch_id": self.batch_id,
            "batch_number": self.batch_number,
            "state_transition_root": self.state_transition_root,
            "public_input_hash": self.public_input_hash,
            "proof_system": self.proof_system,
            "proof_root": self.proof_root,
            "prover_label": self.prover_label,
            "submitted_at_height": self.submitted_at_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupChallengeResolution {
    pub resolution_id: String,
    pub challenge_id: String,
    pub outcome: String,
    pub resolver_label: String,
    pub evidence_root: String,
    pub resolved_at_height: u64,
    pub slashed_sequencer_units: u64,
    pub reward_units: u64,
}

impl RollupChallengeResolution {
    pub fn new(
        challenge_id: impl Into<String>,
        outcome: impl Into<String>,
        resolver_label: impl Into<String>,
        evidence_root: impl Into<String>,
        resolved_at_height: u64,
        slashed_sequencer_units: u64,
        reward_units: u64,
    ) -> RollupResult<Self> {
        let challenge_id = challenge_id.into();
        let outcome = outcome.into();
        let resolver_label = resolver_label.into();
        let evidence_root = evidence_root.into();
        let resolution_id = rollup_challenge_resolution_id(
            &challenge_id,
            &outcome,
            &resolver_label,
            &evidence_root,
            resolved_at_height,
        );
        let resolution = Self {
            resolution_id,
            challenge_id,
            outcome,
            resolver_label,
            evidence_root,
            resolved_at_height,
            slashed_sequencer_units,
            reward_units,
        };
        resolution.validate()?;
        Ok(resolution)
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.challenge_id.is_empty() {
            return Err("rollup challenge resolution challenge id is required".to_string());
        }
        if self.outcome.is_empty() {
            return Err("rollup challenge resolution outcome is required".to_string());
        }
        if self.resolver_label.is_empty() {
            return Err("rollup challenge resolution resolver label is required".to_string());
        }
        if self.evidence_root.is_empty() {
            return Err("rollup challenge resolution evidence root is required".to_string());
        }
        let expected = rollup_challenge_resolution_id(
            &self.challenge_id,
            &self.outcome,
            &self.resolver_label,
            &self.evidence_root,
            self.resolved_at_height,
        );
        if self.resolution_id != expected {
            return Err("rollup challenge resolution id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "resolution_id": self.resolution_id,
            "challenge_id": self.challenge_id,
            "outcome": self.outcome,
            "resolver_label": self.resolver_label,
            "evidence_root": self.evidence_root,
            "resolved_at_height": self.resolved_at_height,
            "slashed_sequencer_units": self.slashed_sequencer_units,
            "reward_units": self.reward_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupFraudChallengeEnvelope {
    pub challenge_id: String,
    pub batch_id: String,
    pub challenged_receipt_id: String,
    pub challenger_label: String,
    pub challenge_kind: String,
    pub claim_hash: String,
    pub evidence_root: String,
    pub proof_system: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub bond_units: u64,
    pub status: String,
    pub resolution: Option<RollupChallengeResolution>,
}

impl RollupFraudChallengeEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        batch_id: impl Into<String>,
        challenged_receipt_id: impl Into<String>,
        challenger_label: impl Into<String>,
        challenge_kind: impl Into<String>,
        claim: &Value,
        evidence: &[Value],
        opened_at_height: u64,
        window_blocks: u64,
        bond_units: u64,
    ) -> RollupResult<Self> {
        if window_blocks == 0 {
            return Err("rollup fraud challenge window must be positive".to_string());
        }
        let batch_id = batch_id.into();
        let challenged_receipt_id = challenged_receipt_id.into();
        let challenger_label = challenger_label.into();
        let challenge_kind = challenge_kind.into();
        let claim_hash = rollup_value_hash("ROLLUP-FRAUD-CLAIM", claim);
        let evidence_root = rollup_value_root("ROLLUP-FRAUD-EVIDENCE", evidence);
        let deadline_height = opened_at_height.saturating_add(window_blocks);
        let proof_system = ROLLUP_FRAUD_PROOF_SYSTEM.to_string();
        let challenge_id = rollup_fraud_challenge_id(
            &batch_id,
            &challenged_receipt_id,
            &challenge_kind,
            &claim_hash,
            &evidence_root,
            opened_at_height,
        );
        let challenge = Self {
            challenge_id,
            batch_id,
            challenged_receipt_id,
            challenger_label,
            challenge_kind,
            claim_hash,
            evidence_root,
            proof_system,
            opened_at_height,
            deadline_height,
            bond_units,
            status: ROLLUP_STATUS_PENDING.to_string(),
            resolution: None,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn resolve(&self, resolution: RollupChallengeResolution) -> RollupResult<Self> {
        if resolution.challenge_id != self.challenge_id {
            return Err("rollup challenge resolution target mismatch".to_string());
        }
        resolution.validate()?;
        let mut challenge = self.clone();
        challenge.status = match resolution.outcome.as_str() {
            "valid" | "accepted" | "fraud_proven" => ROLLUP_STATUS_FINAL.to_string(),
            "invalid" | "rejected" => ROLLUP_STATUS_REJECTED.to_string(),
            _ => ROLLUP_STATUS_FINAL.to_string(),
        };
        challenge.resolution = Some(resolution);
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn is_open(&self, current_height: u64) -> bool {
        self.status == ROLLUP_STATUS_PENDING && current_height <= self.deadline_height
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.batch_id.is_empty() {
            return Err("rollup fraud challenge batch id is required".to_string());
        }
        if self.challenged_receipt_id.is_empty() {
            return Err("rollup fraud challenge receipt id is required".to_string());
        }
        if self.challenger_label.is_empty() {
            return Err("rollup fraud challenge challenger label is required".to_string());
        }
        if self.challenge_kind.is_empty() {
            return Err("rollup fraud challenge kind is required".to_string());
        }
        if self.claim_hash.is_empty() {
            return Err("rollup fraud challenge claim hash is required".to_string());
        }
        if self.evidence_root.is_empty() {
            return Err("rollup fraud challenge evidence root is required".to_string());
        }
        if self.proof_system != ROLLUP_FRAUD_PROOF_SYSTEM {
            return Err("rollup fraud challenge proof system mismatch".to_string());
        }
        if self.deadline_height <= self.opened_at_height {
            return Err("rollup fraud challenge deadline is invalid".to_string());
        }
        let expected = rollup_fraud_challenge_id(
            &self.batch_id,
            &self.challenged_receipt_id,
            &self.challenge_kind,
            &self.claim_hash,
            &self.evidence_root,
            self.opened_at_height,
        );
        if self.challenge_id != expected {
            return Err("rollup fraud challenge id mismatch".to_string());
        }
        match self.status.as_str() {
            ROLLUP_STATUS_PENDING => {
                if self.resolution.is_some() {
                    return Err("pending rollup fraud challenge cannot have resolution".to_string());
                }
            }
            ROLLUP_STATUS_FINAL | ROLLUP_STATUS_REJECTED => {
                let resolution = self.resolution.as_ref().ok_or_else(|| {
                    "resolved rollup fraud challenge requires resolution".to_string()
                })?;
                resolution.validate()?;
                if resolution.challenge_id != self.challenge_id {
                    return Err("rollup fraud challenge resolution id mismatch".to_string());
                }
            }
            _ => return Err("rollup fraud challenge status is invalid".to_string()),
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_fraud_challenge_envelope",
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "batch_id": self.batch_id,
            "challenged_receipt_id": self.challenged_receipt_id,
            "challenger_label": self.challenger_label,
            "challenge_kind": self.challenge_kind,
            "claim_hash": self.claim_hash,
            "evidence_root": self.evidence_root,
            "proof_system": self.proof_system,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "bond_units": self.bond_units,
            "status": self.status,
            "resolution": self.resolution.as_ref().map(RollupChallengeResolution::public_record),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupSettlementCheckpoint {
    pub checkpoint_id: String,
    pub epoch: u64,
    pub start_batch_number: u64,
    pub end_batch_number: u64,
    pub batch_count: u64,
    pub start_state_root: String,
    pub end_state_root: String,
    pub batch_header_root: String,
    pub batch_id_root: String,
    pub withdrawal_root: String,
    pub da_root: String,
    pub validity_input_root: String,
    pub challenge_root: String,
    pub total_tx_count: u64,
    pub total_withdrawal_count: u64,
    pub finalized_at_height: u64,
    pub monero_anchor_txid_hash: String,
    pub status: String,
}

impl RollupSettlementCheckpoint {
    pub fn from_batch_headers(
        headers: &[RollupBatchHeader],
        epoch: u64,
        finalized_at_height: u64,
        monero_anchor_txid: &str,
        status: impl Into<String>,
    ) -> RollupResult<Self> {
        Self::from_batch_headers_with_anchor_hash(
            headers,
            epoch,
            finalized_at_height,
            &rollup_monero_anchor_txid_hash(monero_anchor_txid),
            status,
        )
    }

    pub fn from_batch_headers_with_anchor_hash(
        headers: &[RollupBatchHeader],
        epoch: u64,
        finalized_at_height: u64,
        monero_anchor_txid_hash: &str,
        status: impl Into<String>,
    ) -> RollupResult<Self> {
        if headers.is_empty() {
            return Err("rollup settlement checkpoint requires batch headers".to_string());
        }
        for header in headers {
            header.validate_static()?;
            if header.epoch != epoch {
                return Err("rollup settlement checkpoint epoch mismatch".to_string());
            }
        }
        for pair in headers.windows(2) {
            let left = &pair[0];
            let right = &pair[1];
            if right.batch_number != left.batch_number.saturating_add(1) {
                return Err(
                    "rollup settlement checkpoint batch numbers must be contiguous".to_string(),
                );
            }
            if right.parent_batch_id != left.batch_id() {
                return Err("rollup settlement checkpoint parent chain mismatch".to_string());
            }
            if right.previous_state_root != left.post_state_root {
                return Err("rollup settlement checkpoint state chain mismatch".to_string());
            }
        }
        let first = headers.first().expect("non-empty headers");
        let last = headers.last().expect("non-empty headers");
        let batch_header_root = rollup_batch_header_root(headers);
        let batch_ids = headers
            .iter()
            .map(RollupBatchHeader::batch_id)
            .collect::<Vec<_>>();
        let batch_id_root = rollup_string_root("ROLLUP-CHECKPOINT-BATCH-ID", &batch_ids);
        let withdrawal_root = merkle_root(
            "ROLLUP-CHECKPOINT-WITHDRAWAL",
            &headers
                .iter()
                .map(|header| {
                    json!({
                        "batch_id": header.batch_id(),
                        "batch_number": header.batch_number,
                        "withdrawal_root": header.withdrawal_root,
                        "withdrawal_count": header.withdrawal_count,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let da_root = merkle_root(
            "ROLLUP-CHECKPOINT-DA",
            &headers
                .iter()
                .map(|header| {
                    json!({
                        "batch_id": header.batch_id(),
                        "batch_number": header.batch_number,
                        "da_root": header.da_root,
                        "da_reference_count": header.da_reference_count,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let validity_input_root = merkle_root(
            "ROLLUP-CHECKPOINT-VALIDITY-INPUT",
            &headers
                .iter()
                .map(|header| {
                    json!({
                        "batch_id": header.batch_id(),
                        "batch_number": header.batch_number,
                        "validity_public_input_hash": header.validity_public_input_hash,
                        "state_transition_root": header.state_transition_root,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let challenge_root = merkle_root("ROLLUP-CHECKPOINT-CHALLENGE", &[]);
        let total_tx_count = headers
            .iter()
            .fold(0_u64, |total, header| total.saturating_add(header.tx_count));
        let total_withdrawal_count = headers.iter().fold(0_u64, |total, header| {
            total.saturating_add(header.withdrawal_count)
        });
        let checkpoint_id = rollup_checkpoint_id(
            epoch,
            first.batch_number,
            last.batch_number,
            &batch_header_root,
            &last.post_state_root,
            monero_anchor_txid_hash,
        );
        let checkpoint = Self {
            checkpoint_id,
            epoch,
            start_batch_number: first.batch_number,
            end_batch_number: last.batch_number,
            batch_count: headers.len() as u64,
            start_state_root: first.previous_state_root.clone(),
            end_state_root: last.post_state_root.clone(),
            batch_header_root,
            batch_id_root,
            withdrawal_root,
            da_root,
            validity_input_root,
            challenge_root,
            total_tx_count,
            total_withdrawal_count,
            finalized_at_height,
            monero_anchor_txid_hash: monero_anchor_txid_hash.to_string(),
            status: status.into(),
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn validate(&self) -> RollupResult<()> {
        if self.batch_count == 0 {
            return Err("rollup settlement checkpoint batch count must be positive".to_string());
        }
        if self.end_batch_number < self.start_batch_number {
            return Err("rollup settlement checkpoint range is invalid".to_string());
        }
        if self.batch_count != self.end_batch_number - self.start_batch_number + 1 {
            return Err("rollup settlement checkpoint batch count mismatch".to_string());
        }
        if self.start_state_root.is_empty() || self.end_state_root.is_empty() {
            return Err("rollup settlement checkpoint state roots are required".to_string());
        }
        if self.batch_header_root.is_empty()
            || self.batch_id_root.is_empty()
            || self.withdrawal_root.is_empty()
            || self.da_root.is_empty()
            || self.validity_input_root.is_empty()
            || self.challenge_root.is_empty()
        {
            return Err("rollup settlement checkpoint roots are required".to_string());
        }
        if self.monero_anchor_txid_hash.is_empty() {
            return Err("rollup settlement checkpoint Monero anchor hash is required".to_string());
        }
        let expected = rollup_checkpoint_id(
            self.epoch,
            self.start_batch_number,
            self.end_batch_number,
            &self.batch_header_root,
            &self.end_state_root,
            &self.monero_anchor_txid_hash,
        );
        if self.checkpoint_id != expected {
            return Err("rollup settlement checkpoint id mismatch".to_string());
        }
        if !matches!(
            self.status.as_str(),
            ROLLUP_STATUS_SUBMITTED | ROLLUP_STATUS_FINAL | ROLLUP_STATUS_REJECTED
        ) {
            return Err("rollup settlement checkpoint status is invalid".to_string());
        }
        Ok(())
    }

    pub fn checkpoint_root(&self) -> String {
        domain_hash(
            "ROLLUP-SETTLEMENT-CHECKPOINT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_settlement_checkpoint",
            "chain_id": CHAIN_ID,
            "checkpoint_id": self.checkpoint_id,
            "epoch": self.epoch,
            "start_batch_number": self.start_batch_number,
            "end_batch_number": self.end_batch_number,
            "batch_count": self.batch_count,
            "start_state_root": self.start_state_root,
            "end_state_root": self.end_state_root,
            "batch_header_root": self.batch_header_root,
            "batch_id_root": self.batch_id_root,
            "withdrawal_root": self.withdrawal_root,
            "da_root": self.da_root,
            "validity_input_root": self.validity_input_root,
            "challenge_root": self.challenge_root,
            "total_tx_count": self.total_tx_count,
            "total_withdrawal_count": self.total_withdrawal_count,
            "finalized_at_height": self.finalized_at_height,
            "monero_anchor_txid_hash": self.monero_anchor_txid_hash,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupState {
    pub current_state_root: String,
    pub latest_batch_id: String,
    pub latest_batch_number: u64,
    pub forced_inclusion_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub state_values: BTreeMap<String, String>,
    pub transactions: BTreeMap<String, RollupTransactionEnvelope>,
    pub batch_headers: BTreeMap<String, RollupBatchHeader>,
    pub batches: BTreeMap<String, RollupSequencerBatch>,
    pub receipts: BTreeMap<String, RollupExecutionReceipt>,
    pub forced_inclusions: BTreeMap<String, RollupForcedInclusionRequest>,
    pub withdrawals: BTreeMap<String, RollupWithdrawalRequest>,
    pub da_references: BTreeMap<String, RollupDaReference>,
    pub validity_envelopes: BTreeMap<String, RollupValidityEnvelope>,
    pub fraud_challenges: BTreeMap<String, RollupFraudChallengeEnvelope>,
    pub settlement_checkpoints: BTreeMap<String, RollupSettlementCheckpoint>,
}

impl Default for RollupState {
    fn default() -> Self {
        Self::new("")
    }
}

impl RollupState {
    pub fn new(genesis_state_root: impl Into<String>) -> Self {
        let genesis_state_root = genesis_state_root.into();
        let current_state_root = if genesis_state_root.is_empty() {
            rollup_state_root_from_records(&BTreeMap::new())
        } else {
            genesis_state_root
        };
        Self {
            current_state_root,
            latest_batch_id: ROLLUP_GENESIS_BATCH_ID.to_string(),
            latest_batch_number: 0,
            forced_inclusion_window_blocks: ROLLUP_DEFAULT_FORCED_INCLUSION_WINDOW_BLOCKS,
            challenge_window_blocks: ROLLUP_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            state_values: BTreeMap::new(),
            transactions: BTreeMap::new(),
            batch_headers: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            forced_inclusions: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            da_references: BTreeMap::new(),
            validity_envelopes: BTreeMap::new(),
            fraud_challenges: BTreeMap::new(),
            settlement_checkpoints: BTreeMap::new(),
        }
    }

    pub fn state_value_root(&self) -> String {
        rollup_state_root_from_records(&self.state_values)
    }

    pub fn transaction_root(&self) -> String {
        merkle_root(
            "ROLLUP-STATE-TRANSACTION",
            &self
                .transactions
                .values()
                .map(RollupTransactionEnvelope::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn batch_header_root(&self) -> String {
        rollup_batch_header_root(&self.batch_headers.values().cloned().collect::<Vec<_>>())
    }

    pub fn receipt_root(&self) -> String {
        rollup_receipt_root(&self.receipts.values().cloned().collect::<Vec<_>>())
    }

    pub fn forced_inclusion_root(&self) -> String {
        rollup_forced_inclusion_root(&self.forced_inclusions.values().cloned().collect::<Vec<_>>())
    }

    pub fn withdrawal_root(&self) -> String {
        rollup_withdrawal_root(&self.withdrawals.values().cloned().collect::<Vec<_>>())
    }

    pub fn da_reference_root(&self) -> String {
        rollup_da_reference_root(&self.da_references.values().cloned().collect::<Vec<_>>())
    }

    pub fn validity_envelope_root(&self) -> String {
        rollup_validity_envelope_root(
            &self
                .validity_envelopes
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn fraud_challenge_root(&self) -> String {
        rollup_challenge_root(&self.fraud_challenges.values().cloned().collect::<Vec<_>>())
    }

    pub fn settlement_checkpoint_root(&self) -> String {
        rollup_settlement_checkpoint_root(
            &self
                .settlement_checkpoints
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn rollup_root(&self) -> String {
        merkle_root(
            "ROLLUP-STATE",
            &[json!({
                "current_state_root": self.current_state_root,
                "latest_batch_id": self.latest_batch_id,
                "latest_batch_number": self.latest_batch_number,
                "state_value_root": self.state_value_root(),
                "transaction_root": self.transaction_root(),
                "batch_header_root": self.batch_header_root(),
                "receipt_root": self.receipt_root(),
                "forced_inclusion_root": self.forced_inclusion_root(),
                "withdrawal_root": self.withdrawal_root(),
                "da_reference_root": self.da_reference_root(),
                "validity_envelope_root": self.validity_envelope_root(),
                "fraud_challenge_root": self.fraud_challenge_root(),
                "settlement_checkpoint_root": self.settlement_checkpoint_root(),
            })],
        )
    }

    pub fn open_forced_inclusion(
        &mut self,
        request: RollupForcedInclusionRequest,
    ) -> RollupResult<String> {
        request.validate()?;
        if request.status != ROLLUP_STATUS_PENDING {
            return Err("rollup forced inclusion must be pending when opened".to_string());
        }
        let request_id = request.request_id.clone();
        insert_unique_record(
            &mut self.forced_inclusions,
            request_id.clone(),
            request,
            "forced inclusion",
        )?;
        Ok(request_id)
    }

    pub fn apply_batch(&mut self, batch: RollupSequencerBatch) -> RollupResult<String> {
        batch.validate()?;
        let batch_id = batch.batch_id();
        if self.batches.contains_key(&batch_id) {
            return Err("rollup batch already exists".to_string());
        }
        if self.batch_headers.contains_key(&batch_id) {
            return Err("rollup batch header already exists".to_string());
        }
        if batch.header.previous_state_root != self.current_state_root {
            return Err("rollup batch previous state root mismatch".to_string());
        }
        if batch.header.parent_batch_id != self.latest_batch_id {
            return Err("rollup batch parent id mismatch".to_string());
        }
        let expected_batch_number = if self.batches.is_empty() {
            0
        } else {
            self.latest_batch_number.saturating_add(1)
        };
        if batch.header.batch_number != expected_batch_number {
            return Err("rollup batch number mismatch".to_string());
        }
        self.validate_forced_inclusion_windows(&batch)?;
        self.validate_batch_insertions(&batch)?;

        let mut state_values = self.state_values.clone();
        let mut computed_state_root = self.current_state_root.clone();
        for receipt in &batch.receipts {
            if receipt.pre_state_root != computed_state_root {
                return Err(
                    "rollup receipt pre-state root does not match execution cursor".to_string(),
                );
            }
            for write in &receipt.state_writes {
                apply_state_write(&mut state_values, write)?;
            }
            computed_state_root = rollup_state_root_from_records(&state_values);
            if receipt.post_state_root != computed_state_root {
                return Err("rollup receipt post-state root mismatch".to_string());
            }
        }
        if computed_state_root != batch.header.post_state_root {
            return Err("rollup batch post-state root mismatch".to_string());
        }

        for transaction in &batch.transactions {
            insert_unique_record(
                &mut self.transactions,
                transaction.tx_id.clone(),
                transaction.clone(),
                "transaction",
            )?;
        }
        for receipt in &batch.receipts {
            insert_unique_record(
                &mut self.receipts,
                receipt.receipt_id.clone(),
                receipt.clone(),
                "receipt",
            )?;
        }
        for withdrawal in &batch.withdrawals {
            let included = withdrawal.mark_included();
            insert_unique_record(
                &mut self.withdrawals,
                included.withdrawal_id.clone(),
                included,
                "withdrawal",
            )?;
        }
        for reference in &batch.da_references {
            insert_unique_record(
                &mut self.da_references,
                reference.reference_id.clone(),
                reference.clone(),
                "DA reference",
            )?;
        }
        for forced in &batch.forced_inclusions {
            let included = forced.include_in_batch(&batch_id, batch.header.l2_end_height);
            self.forced_inclusions
                .insert(included.request_id.clone(), included);
        }
        if let Some(envelope) = &batch.validity_envelope {
            insert_unique_record(
                &mut self.validity_envelopes,
                envelope.envelope_id.clone(),
                envelope.clone(),
                "validity envelope",
            )?;
        }

        self.state_values = state_values;
        self.current_state_root = computed_state_root;
        self.latest_batch_id = batch_id.clone();
        self.latest_batch_number = batch.header.batch_number;
        self.batch_headers
            .insert(batch_id.clone(), batch.header.clone());
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn submit_validity_envelope(
        &mut self,
        envelope: RollupValidityEnvelope,
    ) -> RollupResult<String> {
        envelope.validate()?;
        let header = self
            .batch_headers
            .get(&envelope.batch_id)
            .ok_or_else(|| "rollup validity envelope batch is missing".to_string())?;
        envelope.validate_for_batch_header(header)?;
        let envelope_id = envelope.envelope_id.clone();
        insert_unique_record(
            &mut self.validity_envelopes,
            envelope_id.clone(),
            envelope,
            "validity envelope",
        )?;
        Ok(envelope_id)
    }

    pub fn open_fraud_challenge(
        &mut self,
        challenge: RollupFraudChallengeEnvelope,
    ) -> RollupResult<String> {
        challenge.validate()?;
        let header = self
            .batch_headers
            .get(&challenge.batch_id)
            .ok_or_else(|| "rollup fraud challenge batch is missing".to_string())?;
        if challenge.opened_at_height
            > header
                .l2_end_height
                .saturating_add(self.challenge_window_blocks)
        {
            return Err("rollup fraud challenge opened after challenge window".to_string());
        }
        let receipt = self
            .receipts
            .get(&challenge.challenged_receipt_id)
            .ok_or_else(|| "rollup fraud challenge receipt is missing".to_string())?;
        if receipt.batch_id != challenge.batch_id {
            return Err("rollup fraud challenge receipt batch mismatch".to_string());
        }
        let challenge_id = challenge.challenge_id.clone();
        insert_unique_record(
            &mut self.fraud_challenges,
            challenge_id.clone(),
            challenge,
            "fraud challenge",
        )?;
        Ok(challenge_id)
    }

    pub fn resolve_fraud_challenge(
        &mut self,
        challenge_id: &str,
        resolution: RollupChallengeResolution,
    ) -> RollupResult<String> {
        let challenge = self
            .fraud_challenges
            .get(challenge_id)
            .ok_or_else(|| "rollup fraud challenge is missing".to_string())?
            .clone();
        let resolved = challenge.resolve(resolution)?;
        self.fraud_challenges
            .insert(challenge_id.to_string(), resolved);
        Ok(challenge_id.to_string())
    }

    pub fn apply_settlement_checkpoint(
        &mut self,
        checkpoint: RollupSettlementCheckpoint,
    ) -> RollupResult<String> {
        checkpoint.validate()?;
        if self
            .settlement_checkpoints
            .contains_key(&checkpoint.checkpoint_id)
        {
            return Err("rollup settlement checkpoint already exists".to_string());
        }
        let headers = (checkpoint.start_batch_number..=checkpoint.end_batch_number)
            .map(|batch_number| {
                self.batch_headers
                    .values()
                    .find(|header| {
                        header.batch_number == batch_number && header.epoch == checkpoint.epoch
                    })
                    .cloned()
                    .ok_or_else(|| {
                        "rollup settlement checkpoint batch header is missing".to_string()
                    })
            })
            .collect::<RollupResult<Vec<_>>>()?;
        let expected = RollupSettlementCheckpoint::from_batch_headers_with_anchor_hash(
            &headers,
            checkpoint.epoch,
            checkpoint.finalized_at_height,
            &checkpoint.monero_anchor_txid_hash,
            checkpoint.status.clone(),
        )?;
        if expected.public_record() != checkpoint.public_record() {
            return Err("rollup settlement checkpoint root mismatch".to_string());
        }
        let checkpoint_id = checkpoint.checkpoint_id.clone();
        self.settlement_checkpoints
            .insert(checkpoint_id.clone(), checkpoint);
        Ok(checkpoint_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollup_state",
            "chain_id": CHAIN_ID,
            "current_state_root": self.current_state_root,
            "latest_batch_id": self.latest_batch_id,
            "latest_batch_number": self.latest_batch_number,
            "forced_inclusion_window_blocks": self.forced_inclusion_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "state_value_root": self.state_value_root(),
            "transaction_root": self.transaction_root(),
            "batch_header_root": self.batch_header_root(),
            "receipt_root": self.receipt_root(),
            "forced_inclusion_root": self.forced_inclusion_root(),
            "withdrawal_root": self.withdrawal_root(),
            "da_reference_root": self.da_reference_root(),
            "validity_envelope_root": self.validity_envelope_root(),
            "fraud_challenge_root": self.fraud_challenge_root(),
            "settlement_checkpoint_root": self.settlement_checkpoint_root(),
            "rollup_root": self.rollup_root(),
            "batch_count": self.batches.len(),
            "transaction_count": self.transactions.len(),
            "receipt_count": self.receipts.len(),
            "withdrawal_count": self.withdrawals.len(),
            "forced_inclusion_count": self.forced_inclusions.len(),
            "da_reference_count": self.da_references.len(),
            "validity_envelope_count": self.validity_envelopes.len(),
            "fraud_challenge_count": self.fraud_challenges.len(),
            "settlement_checkpoint_count": self.settlement_checkpoints.len(),
        })
    }

    fn validate_forced_inclusion_windows(&self, batch: &RollupSequencerBatch) -> RollupResult<()> {
        let included = batch
            .forced_inclusions
            .iter()
            .map(|request| request.request_id.as_str())
            .collect::<BTreeSet<_>>();
        for request in self.forced_inclusions.values() {
            if request.is_due(batch.header.l2_end_height)
                && !included.contains(request.request_id.as_str())
            {
                return Err("rollup forced inclusion window missed".to_string());
            }
        }
        for request in &batch.forced_inclusions {
            if let Some(existing) = self.forced_inclusions.get(&request.request_id) {
                if existing.status != ROLLUP_STATUS_PENDING {
                    return Err("rollup forced inclusion request already consumed".to_string());
                }
                if existing.request_record() != request.request_record() {
                    return Err("rollup forced inclusion request record mismatch".to_string());
                }
            }
            if batch.header.l2_end_height > request.deadline_height {
                return Err("rollup forced inclusion included after deadline".to_string());
            }
            if batch.header.l2_end_height < request.opened_at_height {
                return Err("rollup forced inclusion included before opening height".to_string());
            }
        }
        Ok(())
    }

    fn validate_batch_insertions(&self, batch: &RollupSequencerBatch) -> RollupResult<()> {
        for transaction in &batch.transactions {
            if self.transactions.contains_key(&transaction.tx_id) {
                return Err("rollup transaction already exists".to_string());
            }
        }
        for receipt in &batch.receipts {
            if self.receipts.contains_key(&receipt.receipt_id) {
                return Err("rollup receipt already exists".to_string());
            }
        }
        for withdrawal in &batch.withdrawals {
            if self.withdrawals.contains_key(&withdrawal.withdrawal_id) {
                return Err("rollup withdrawal already exists".to_string());
            }
        }
        for reference in &batch.da_references {
            if self.da_references.contains_key(&reference.reference_id) {
                return Err("rollup DA reference already exists".to_string());
            }
        }
        if let Some(envelope) = &batch.validity_envelope {
            if self.validity_envelopes.contains_key(&envelope.envelope_id) {
                return Err("rollup validity envelope already exists".to_string());
            }
        }
        Ok(())
    }
}

pub fn rollup_tx_id(
    tx_kind: &str,
    sender_commitment: &str,
    nonce: u64,
    public_input: &Value,
    calldata_root: &str,
    authorization_root: &str,
) -> String {
    domain_hash(
        "ROLLUP-TX-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tx_kind),
            HashPart::Str(sender_commitment),
            HashPart::Int(nonce as i128),
            HashPart::Json(public_input),
            HashPart::Str(calldata_root),
            HashPart::Str(authorization_root),
        ],
        32,
    )
}

pub fn rollup_state_key_hash(key: &str) -> String {
    domain_hash("ROLLUP-STATE-KEY", &[HashPart::Str(key)], 32)
}

pub fn rollup_state_value_hash(value: &Value) -> String {
    rollup_value_hash("ROLLUP-STATE-VALUE", value)
}

pub fn rollup_empty_state_value_hash() -> String {
    domain_hash("ROLLUP-EMPTY-STATE-VALUE", &[], 32)
}

pub fn rollup_state_root_from_records(records: &BTreeMap<String, String>) -> String {
    merkle_root(
        "ROLLUP-STATE-VALUE",
        &records
            .iter()
            .map(|(key_hash, value_hash)| {
                json!({
                    "key_hash": key_hash,
                    "value_hash": value_hash,
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_state_write_root(writes: &[RollupStateWrite]) -> String {
    merkle_root(
        "ROLLUP-STATE-WRITE",
        &writes
            .iter()
            .map(RollupStateWrite::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_withdrawal_id(
    tx_id: &str,
    withdrawal_index: u64,
    asset_id: &str,
    amount: u64,
    fee_units: u64,
    recipient_commitment: &str,
    destination_chain: &str,
    destination_address_hash: &str,
) -> String {
    domain_hash(
        "ROLLUP-WITHDRAWAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tx_id),
            HashPart::Int(withdrawal_index as i128),
            HashPart::Str(asset_id),
            HashPart::Int(amount as i128),
            HashPart::Int(fee_units as i128),
            HashPart::Str(recipient_commitment),
            HashPart::Str(destination_chain),
            HashPart::Str(destination_address_hash),
        ],
        32,
    )
}

pub fn rollup_withdrawal_root(withdrawals: &[RollupWithdrawalRequest]) -> String {
    merkle_root(
        "ROLLUP-WITHDRAWAL",
        &withdrawals
            .iter()
            .map(RollupWithdrawalRequest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_receipt_id(
    batch_id: &str,
    tx_id: &str,
    tx_index: u64,
    transition_root: &str,
) -> String {
    domain_hash(
        "ROLLUP-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(tx_id),
            HashPart::Int(tx_index as i128),
            HashPart::Str(transition_root),
        ],
        32,
    )
}

pub fn rollup_receipt_root(receipts: &[RollupExecutionReceipt]) -> String {
    merkle_root(
        "ROLLUP-RECEIPT",
        &receipts
            .iter()
            .map(RollupExecutionReceipt::transition_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_forced_inclusion_id(
    tx_id: &str,
    tx_public_hash: &str,
    requester_commitment: &str,
    opened_at_height: u64,
    deadline_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-FORCED-INCLUSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tx_id),
            HashPart::Str(tx_public_hash),
            HashPart::Str(requester_commitment),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(deadline_height as i128),
        ],
        32,
    )
}

pub fn rollup_forced_inclusion_root(requests: &[RollupForcedInclusionRequest]) -> String {
    merkle_root(
        "ROLLUP-FORCED-INCLUSION",
        &requests
            .iter()
            .map(RollupForcedInclusionRequest::request_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_da_reference_id(
    provider: &str,
    namespace: &str,
    payload_hash: &str,
    shard_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-DA-REFERENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(provider),
            HashPart::Str(namespace),
            HashPart::Str(payload_hash),
            HashPart::Str(shard_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

pub fn rollup_da_reference_root(references: &[RollupDaReference]) -> String {
    merkle_root(
        "ROLLUP-DA-REFERENCE",
        &references
            .iter()
            .map(RollupDaReference::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_tx_root(transactions: &[RollupTransactionEnvelope]) -> String {
    merkle_root(
        "ROLLUP-TX",
        &transactions
            .iter()
            .map(RollupTransactionEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_batch_id(header: &RollupBatchHeader) -> String {
    domain_hash(
        "ROLLUP-BATCH-HEADER",
        &[HashPart::Json(&header.state_record())],
        32,
    )
}

pub fn rollup_batch_header_root(headers: &[RollupBatchHeader]) -> String {
    merkle_root(
        "ROLLUP-BATCH-HEADER",
        &headers
            .iter()
            .map(RollupBatchHeader::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_state_transition_root(
    previous_state_root: &str,
    post_state_root: &str,
    receipt_root: &str,
) -> String {
    domain_hash(
        "ROLLUP-STATE-TRANSITION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(previous_state_root),
            HashPart::Str(post_state_root),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

pub fn rollup_validity_public_input_hash(
    previous_state_root: &str,
    post_state_root: &str,
    tx_root: &str,
    receipt_root: &str,
    withdrawal_root: &str,
    da_root: &str,
) -> String {
    domain_hash(
        "ROLLUP-VALIDITY-PUBLIC-INPUT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(previous_state_root),
            HashPart::Str(post_state_root),
            HashPart::Str(tx_root),
            HashPart::Str(receipt_root),
            HashPart::Str(withdrawal_root),
            HashPart::Str(da_root),
        ],
        32,
    )
}

pub fn rollup_validity_envelope_id(
    batch_id: &str,
    state_transition_root: &str,
    public_input_hash: &str,
    proof_system: &str,
    proof_root: &str,
) -> String {
    domain_hash(
        "ROLLUP-VALIDITY-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(state_transition_root),
            HashPart::Str(public_input_hash),
            HashPart::Str(proof_system),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn rollup_validity_envelope_root(envelopes: &[RollupValidityEnvelope]) -> String {
    merkle_root(
        "ROLLUP-VALIDITY-ENVELOPE",
        &envelopes
            .iter()
            .map(RollupValidityEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_fraud_challenge_id(
    batch_id: &str,
    challenged_receipt_id: &str,
    challenge_kind: &str,
    claim_hash: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-FRAUD-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(challenged_receipt_id),
            HashPart::Str(challenge_kind),
            HashPart::Str(claim_hash),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn rollup_challenge_resolution_id(
    challenge_id: &str,
    outcome: &str,
    resolver_label: &str,
    evidence_root: &str,
    resolved_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-CHALLENGE-RESOLUTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(outcome),
            HashPart::Str(resolver_label),
            HashPart::Str(evidence_root),
            HashPart::Int(resolved_at_height as i128),
        ],
        32,
    )
}

pub fn rollup_challenge_root(challenges: &[RollupFraudChallengeEnvelope]) -> String {
    merkle_root(
        "ROLLUP-FRAUD-CHALLENGE",
        &challenges
            .iter()
            .map(RollupFraudChallengeEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_checkpoint_id(
    epoch: u64,
    start_batch_number: u64,
    end_batch_number: u64,
    batch_header_root: &str,
    end_state_root: &str,
    monero_anchor_txid_hash: &str,
) -> String {
    domain_hash(
        "ROLLUP-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Int(start_batch_number as i128),
            HashPart::Int(end_batch_number as i128),
            HashPart::Str(batch_header_root),
            HashPart::Str(end_state_root),
            HashPart::Str(monero_anchor_txid_hash),
        ],
        32,
    )
}

pub fn rollup_settlement_checkpoint_root(checkpoints: &[RollupSettlementCheckpoint]) -> String {
    merkle_root(
        "ROLLUP-SETTLEMENT-CHECKPOINT",
        &checkpoints
            .iter()
            .map(RollupSettlementCheckpoint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_monero_anchor_txid_hash(monero_txid: &str) -> String {
    domain_hash(
        "ROLLUP-MONERO-ANCHOR-TXID",
        &[HashPart::Str(monero_txid)],
        32,
    )
}

pub fn rollup_value_hash(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

pub fn rollup_value_root(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn rollup_string_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn rollup_fee_root(receipts: &[RollupExecutionReceipt]) -> String {
    merkle_root(
        "ROLLUP-FEE",
        &receipts
            .iter()
            .map(|receipt| {
                json!({
                    "tx_id": receipt.tx_id,
                    "tx_index": receipt.tx_index,
                    "gas_used": receipt.gas_used,
                    "fee_charged_units": receipt.fee_charged_units,
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn rollup_withdrawals_from_receipts(
    receipts: &[RollupExecutionReceipt],
) -> Vec<RollupWithdrawalRequest> {
    receipts
        .iter()
        .flat_map(|receipt| receipt.withdrawals.iter().cloned())
        .collect()
}

fn apply_state_write(
    records: &mut BTreeMap<String, String>,
    write: &RollupStateWrite,
) -> RollupResult<()> {
    write.validate()?;
    let current = records
        .get(&write.key_hash)
        .cloned()
        .unwrap_or_else(rollup_empty_state_value_hash);
    if current != write.previous_value_hash {
        return Err("rollup state write previous value mismatch".to_string());
    }
    match write.operation.as_str() {
        ROLLUP_STATE_WRITE_UPSERT => {
            records.insert(write.key_hash.clone(), write.new_value_hash.clone());
        }
        ROLLUP_STATE_WRITE_DELETE => {
            records.remove(&write.key_hash);
        }
        _ => return Err("rollup state write operation is invalid".to_string()),
    }
    Ok(())
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    record_id: String,
    record: T,
    record_kind: &str,
) -> RollupResult<()> {
    if records.contains_key(&record_id) {
        return Err(format!("rollup {record_kind} already exists"));
    }
    records.insert(record_id, record);
    Ok(())
}
