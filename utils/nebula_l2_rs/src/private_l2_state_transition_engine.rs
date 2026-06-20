use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2StateTransitionEngineResult<T> = Result<T, String>;

pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_PROTOCOL_VERSION: &str =
    "nebula-private-l2-state-transition-engine-v1";
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_PROOF_SYSTEM: &str = "zk-private-state-transition-v1";
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MIN_PRIVACY_SET: u64 = 256;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MAX_FEE_BPS: u64 = 35;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MAX_DELTA_COUNT: usize = 64;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_ACCOUNTS: usize = 65_536;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_ASSETS: usize = 4_096;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_CONTRACTS: usize = 16_384;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_POOLS: usize = 16_384;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_TRANSITIONS: usize = 65_536;
pub const PRIVATE_L2_STATE_TRANSITION_ENGINE_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateDomainKind {
    Account,
    ConfidentialAsset,
    PrivateContract,
    PrivateAmmPool,
    ProofAccumulator,
    FeeSponsor,
    MoneroExit,
}

impl StateDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::ConfidentialAsset => "confidential_asset",
            Self::PrivateContract => "private_contract",
            Self::PrivateAmmPool => "private_amm_pool",
            Self::ProofAccumulator => "proof_accumulator",
            Self::FeeSponsor => "fee_sponsor",
            Self::MoneroExit => "monero_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    PrivateTransfer,
    TokenMint,
    ContractCall,
    AmmSwap,
    ProofAggregate,
    FeeSponsorDebit,
    MoneroExitQueue,
    FullMvpFlow,
}

impl TransitionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::TokenMint => "token_mint",
            Self::ContractCall => "contract_call",
            Self::AmmSwap => "amm_swap",
            Self::ProofAggregate => "proof_aggregate",
            Self::FeeSponsorDebit => "fee_sponsor_debit",
            Self::MoneroExitQueue => "monero_exit_queue",
            Self::FullMvpFlow => "full_mvp_flow",
        }
    }

    pub fn touches(self) -> BTreeSet<StateDomainKind> {
        match self {
            Self::PrivateTransfer => [StateDomainKind::Account].into_iter().collect(),
            Self::TokenMint => [
                StateDomainKind::Account,
                StateDomainKind::ConfidentialAsset,
                StateDomainKind::PrivateContract,
            ]
            .into_iter()
            .collect(),
            Self::ContractCall => [
                StateDomainKind::Account,
                StateDomainKind::PrivateContract,
                StateDomainKind::ProofAccumulator,
            ]
            .into_iter()
            .collect(),
            Self::AmmSwap => [
                StateDomainKind::Account,
                StateDomainKind::PrivateAmmPool,
                StateDomainKind::ProofAccumulator,
            ]
            .into_iter()
            .collect(),
            Self::ProofAggregate => [StateDomainKind::ProofAccumulator].into_iter().collect(),
            Self::FeeSponsorDebit => [StateDomainKind::FeeSponsor].into_iter().collect(),
            Self::MoneroExitQueue => [
                StateDomainKind::Account,
                StateDomainKind::MoneroExit,
                StateDomainKind::ProofAccumulator,
            ]
            .into_iter()
            .collect(),
            Self::FullMvpFlow => [
                StateDomainKind::Account,
                StateDomainKind::ConfidentialAsset,
                StateDomainKind::PrivateContract,
                StateDomainKind::PrivateAmmPool,
                StateDomainKind::ProofAccumulator,
                StateDomainKind::FeeSponsor,
                StateDomainKind::MoneroExit,
            ]
            .into_iter()
            .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionStatus {
    Open,
    Applied,
    Rejected,
    Settled,
}

impl TransitionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaOpKind {
    Insert,
    Update,
    ConsumeNullifier,
    AppendReceipt,
}

impl DeltaOpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Update => "update",
            Self::ConsumeNullifier => "consume_nullifier",
            Self::AppendReceipt => "append_receipt",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub pq_signature_scheme: String,
    pub proof_system: String,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
    pub max_fee_bps: u64,
    pub max_delta_count: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_STATE_TRANSITION_ENGINE_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            pq_signature_scheme: PRIVATE_L2_STATE_TRANSITION_ENGINE_PQ_SIGNATURE_SCHEME.to_string(),
            proof_system: PRIVATE_L2_STATE_TRANSITION_ENGINE_PROOF_SYSTEM.to_string(),
            min_privacy_set: PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MAX_FEE_BPS,
            max_delta_count: PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MAX_DELTA_COUNT,
        }
    }

    pub fn validate(&self) -> PrivateL2StateTransitionEngineResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.pq_signature_scheme.is_empty()
            || self.proof_system.is_empty()
        {
            return Err("private l2 state transition config labels cannot be empty".to_string());
        }
        if self.max_fee_bps > PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_BPS {
            return Err("private l2 state transition fee cap cannot exceed 100%".to_string());
        }
        if self.min_privacy_set == 0 || self.min_pq_security_bits == 0 || self.max_delta_count == 0
        {
            return Err("private l2 state transition thresholds must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_state_transition_engine_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "pq_signature_scheme": self.pq_signature_scheme,
            "proof_system": self.proof_system,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "max_delta_count": self.max_delta_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateObject {
    pub object_id: String,
    pub domain: StateDomainKind,
    pub label: String,
    pub owner_commitment: String,
    pub value_commitment: String,
    pub metadata_root: String,
    pub version: u64,
    pub updated_height: u64,
}

impl StateObject {
    pub fn new(
        domain: StateDomainKind,
        label: &str,
        owner_label: &str,
        value: &Value,
        metadata: &Value,
        version: u64,
        updated_height: u64,
    ) -> PrivateL2StateTransitionEngineResult<Self> {
        if label.is_empty() || owner_label.is_empty() {
            return Err("private l2 state object labels cannot be empty".to_string());
        }
        if version == 0 {
            return Err("private l2 state object version must be positive".to_string());
        }
        let owner_commitment = private_l2_state_transition_string_root("OBJECT-OWNER", owner_label);
        let value_commitment = private_l2_state_transition_payload_root("OBJECT-VALUE", value);
        let metadata_root = private_l2_state_transition_payload_root("OBJECT-METADATA", metadata);
        let object_id = state_object_id(
            domain,
            label,
            &owner_commitment,
            &value_commitment,
            &metadata_root,
            version,
        );
        Ok(Self {
            object_id,
            domain,
            label: label.to_string(),
            owner_commitment,
            value_commitment,
            metadata_root,
            version,
            updated_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_state_object",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_STATE_TRANSITION_ENGINE_PROTOCOL_VERSION,
            "object_id": self.object_id,
            "domain": self.domain.as_str(),
            "label": self.label,
            "owner_commitment": self.owner_commitment,
            "value_commitment": self.value_commitment,
            "metadata_root": self.metadata_root,
            "version": self.version,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionRequest {
    pub transition_id: String,
    pub transition_kind: TransitionKind,
    pub status: TransitionStatus,
    pub height: u64,
    pub caller_commitment: String,
    pub input_root: String,
    pub nullifier_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub execution_receipt_root: String,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u64,
    pub touched_domains: BTreeSet<StateDomainKind>,
    pub delta_ids: Vec<String>,
}

impl TransitionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transition_kind: TransitionKind,
        height: u64,
        caller_label: &str,
        input: &Value,
        nullifier: &Value,
        pq_authorization: &Value,
        privacy_proof: &Value,
        execution_receipt: &Value,
        fee_bps: u64,
        privacy_set_size: u64,
        pq_security_bits: u64,
    ) -> PrivateL2StateTransitionEngineResult<Self> {
        if caller_label.is_empty() {
            return Err("private l2 transition caller cannot be empty".to_string());
        }
        if fee_bps > PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_BPS {
            return Err("private l2 transition fee cannot exceed 100%".to_string());
        }
        if privacy_set_size == 0 || pq_security_bits == 0 {
            return Err("private l2 transition security thresholds must be positive".to_string());
        }
        let caller_commitment = private_l2_state_transition_string_root("CALLER", caller_label);
        let input_root = private_l2_state_transition_payload_root("INPUT", input);
        let nullifier_root = private_l2_state_transition_payload_root("NULLIFIER", nullifier);
        let pq_authorization_root =
            private_l2_state_transition_payload_root("PQ-AUTHORIZATION", pq_authorization);
        let privacy_proof_root =
            private_l2_state_transition_payload_root("PRIVACY-PROOF", privacy_proof);
        let execution_receipt_root =
            private_l2_state_transition_payload_root("EXECUTION-RECEIPT", execution_receipt);
        let touched_domains = transition_kind.touches();
        let transition_id = transition_request_id(
            transition_kind,
            height,
            &caller_commitment,
            &input_root,
            &nullifier_root,
            &pq_authorization_root,
            &privacy_proof_root,
            &execution_receipt_root,
        );
        Ok(Self {
            transition_id,
            transition_kind,
            status: TransitionStatus::Open,
            height,
            caller_commitment,
            input_root,
            nullifier_root,
            pq_authorization_root,
            privacy_proof_root,
            execution_receipt_root,
            fee_bps,
            privacy_set_size,
            pq_security_bits,
            touched_domains,
            delta_ids: Vec::new(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_transition_request",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_STATE_TRANSITION_ENGINE_PROTOCOL_VERSION,
            "transition_id": self.transition_id,
            "transition_kind": self.transition_kind.as_str(),
            "status": self.status.as_str(),
            "height": self.height,
            "caller_commitment": self.caller_commitment,
            "input_root": self.input_root,
            "nullifier_root": self.nullifier_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "execution_receipt_root": self.execution_receipt_root,
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "touched_domains": self.touched_domains.iter().map(|domain| domain.as_str()).collect::<Vec<_>>(),
            "delta_ids": self.delta_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDelta {
    pub delta_id: String,
    pub transition_id: String,
    pub op_kind: DeltaOpKind,
    pub domain: StateDomainKind,
    pub object_id: String,
    pub before_root: String,
    pub after_root: String,
    pub height: u64,
}

impl StateDelta {
    pub fn new(
        transition_id: &str,
        op_kind: DeltaOpKind,
        domain: StateDomainKind,
        object_id: &str,
        before_root: &str,
        after_root: &str,
        height: u64,
    ) -> PrivateL2StateTransitionEngineResult<Self> {
        if transition_id.is_empty()
            || object_id.is_empty()
            || before_root.is_empty()
            || after_root.is_empty()
        {
            return Err("private l2 state delta identifiers cannot be empty".to_string());
        }
        let delta_id = state_delta_id(
            transition_id,
            op_kind,
            domain,
            object_id,
            before_root,
            after_root,
            height,
        );
        Ok(Self {
            delta_id,
            transition_id: transition_id.to_string(),
            op_kind,
            domain,
            object_id: object_id.to_string(),
            before_root: before_root.to_string(),
            after_root: after_root.to_string(),
            height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_state_delta",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_STATE_TRANSITION_ENGINE_PROTOCOL_VERSION,
            "delta_id": self.delta_id,
            "transition_id": self.transition_id,
            "op_kind": self.op_kind.as_str(),
            "domain": self.domain.as_str(),
            "object_id": self.object_id,
            "before_root": self.before_root,
            "after_root": self.after_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionReceipt {
    pub receipt_id: String,
    pub transition_id: String,
    pub height: u64,
    pub state_root_before: String,
    pub state_root_after: String,
    pub delta_root: String,
    pub nullifier_root: String,
    pub execution_receipt_root: String,
    pub settlement_binding_root: String,
}

impl TransitionReceipt {
    pub fn new(
        transition: &TransitionRequest,
        height: u64,
        state_root_before: &str,
        state_root_after: &str,
        deltas: &[StateDelta],
        settlement_binding: &Value,
    ) -> Self {
        let delta_records = deltas
            .iter()
            .map(StateDelta::public_record)
            .collect::<Vec<_>>();
        let delta_root = merkle_root("PRIVATE-L2-STATE-TRANSITION-DELTAS", &delta_records);
        let settlement_binding_root =
            private_l2_state_transition_payload_root("SETTLEMENT-BINDING", settlement_binding);
        let receipt_id = transition_receipt_id(
            &transition.transition_id,
            height,
            state_root_before,
            state_root_after,
            &delta_root,
            &transition.nullifier_root,
            &transition.execution_receipt_root,
            &settlement_binding_root,
        );
        Self {
            receipt_id,
            transition_id: transition.transition_id.clone(),
            height,
            state_root_before: state_root_before.to_string(),
            state_root_after: state_root_after.to_string(),
            delta_root,
            nullifier_root: transition.nullifier_root.clone(),
            execution_receipt_root: transition.execution_receipt_root.clone(),
            settlement_binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_state_transition_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_STATE_TRANSITION_ENGINE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "transition_id": self.transition_id,
            "height": self.height,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "delta_root": self.delta_root,
            "nullifier_root": self.nullifier_root,
            "execution_receipt_root": self.execution_receipt_root,
            "settlement_binding_root": self.settlement_binding_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub state_objects: u64,
    pub transitions_opened: u64,
    pub transitions_applied: u64,
    pub transitions_rejected: u64,
    pub deltas: u64,
    pub receipts: u64,
    pub nullifiers_consumed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_state_transition_engine_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_STATE_TRANSITION_ENGINE_PROTOCOL_VERSION,
            "state_objects": self.state_objects,
            "transitions_opened": self.transitions_opened,
            "transitions_applied": self.transitions_applied,
            "transitions_rejected": self.transitions_rejected,
            "deltas": self.deltas,
            "receipts": self.receipts,
            "nullifiers_consumed": self.nullifiers_consumed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub object_root: String,
    pub transition_root: String,
    pub delta_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        Self {
            config_root: private_l2_state_transition_payload_root(
                "CONFIG",
                &config.public_record(),
            ),
            object_root: merkle_root("PRIVATE-L2-STATE-OBJECTS", &[]),
            transition_root: merkle_root("PRIVATE-L2-STATE-TRANSITIONS", &[]),
            delta_root: merkle_root("PRIVATE-L2-STATE-DELTAS", &[]),
            receipt_root: merkle_root("PRIVATE-L2-STATE-RECEIPTS", &[]),
            nullifier_root: merkle_root("PRIVATE-L2-STATE-NULLIFIERS", &[]),
            counter_root: private_l2_state_transition_payload_root(
                "COUNTERS",
                &Counters::default().public_record(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_state_transition_engine_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_STATE_TRANSITION_ENGINE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "object_root": self.object_root,
            "transition_root": self.transition_root,
            "delta_root": self.delta_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub objects: BTreeMap<String, StateObject>,
    pub transitions: BTreeMap<String, TransitionRequest>,
    pub deltas: BTreeMap<String, StateDelta>,
    pub receipts: BTreeMap<String, TransitionReceipt>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub counters: Counters,
    pub roots: Roots,
    pub state_root: String,
}

impl State {
    pub fn new(config: Config, height: u64) -> PrivateL2StateTransitionEngineResult<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        let mut state = Self {
            config,
            height,
            objects: BTreeMap::new(),
            transitions: BTreeMap::new(),
            deltas: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            counters: Counters::default(),
            roots,
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> PrivateL2StateTransitionEngineResult<Self> {
        let mut state = Self::new(
            Config::devnet(),
            PRIVATE_L2_STATE_TRANSITION_ENGINE_DEVNET_HEIGHT,
        )?;
        state.bootstrap_devnet_objects()?;
        let transition =
            devnet_transition_request(PRIVATE_L2_STATE_TRANSITION_ENGINE_DEVNET_HEIGHT)?;
        let transition_id = state.open_transition(transition)?;
        state.apply_transition(
            &transition_id,
            PRIVATE_L2_STATE_TRANSITION_ENGINE_DEVNET_HEIGHT,
            &json!({"settlement_binding": "devnet"}),
        )?;
        Ok(state)
    }

    pub fn bootstrap_devnet_objects(&mut self) -> PrivateL2StateTransitionEngineResult<()> {
        for (domain, label, value) in [
            (
                StateDomainKind::Account,
                "devnet-private-account",
                json!({"balance_commitment": "devnet-account-balance"}),
            ),
            (
                StateDomainKind::ConfidentialAsset,
                "devnet-wrapped-xmr",
                json!({"supply_commitment": "devnet-wxmr-supply"}),
            ),
            (
                StateDomainKind::PrivateContract,
                "devnet-private-defi-contract",
                json!({"storage_commitment": "devnet-contract-storage"}),
            ),
            (
                StateDomainKind::PrivateAmmPool,
                "devnet-private-amm-pool",
                json!({"reserve_commitment": "devnet-pool-reserves"}),
            ),
            (
                StateDomainKind::ProofAccumulator,
                "devnet-recursive-proof-accumulator",
                json!({"proof_commitment": "devnet-proof-accumulator"}),
            ),
            (
                StateDomainKind::FeeSponsor,
                "devnet-proof-market-sponsor",
                json!({"sponsor_commitment": "devnet-sponsor-vault"}),
            ),
            (
                StateDomainKind::MoneroExit,
                "devnet-monero-exit-queue",
                json!({"exit_commitment": "devnet-exit-queue"}),
            ),
        ] {
            let object = StateObject::new(
                domain,
                label,
                "devnet-system",
                &value,
                &json!({"source": "devnet_bootstrap"}),
                1,
                self.height,
            )?;
            self.insert_object(object)?;
        }
        Ok(())
    }

    pub fn insert_object(
        &mut self,
        object: StateObject,
    ) -> PrivateL2StateTransitionEngineResult<String> {
        if self.objects.len()
            >= PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_ACCOUNTS
                + PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_ASSETS
                + PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_CONTRACTS
                + PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_POOLS
        {
            return Err("private l2 state object capacity exhausted".to_string());
        }
        let object_id = object.object_id.clone();
        if self.objects.insert(object_id.clone(), object).is_some() {
            return Err("private l2 state object already exists".to_string());
        }
        self.counters.state_objects = self.counters.state_objects.saturating_add(1);
        self.refresh();
        Ok(object_id)
    }

    pub fn open_transition(
        &mut self,
        transition: TransitionRequest,
    ) -> PrivateL2StateTransitionEngineResult<String> {
        if self.transitions.len() >= PRIVATE_L2_STATE_TRANSITION_ENGINE_MAX_TRANSITIONS {
            return Err("private l2 transition capacity exhausted".to_string());
        }
        self.validate_transition(&transition)?;
        if self
            .consumed_nullifiers
            .contains(&transition.nullifier_root)
        {
            return Err("private l2 transition nullifier already consumed".to_string());
        }
        let transition_id = transition.transition_id.clone();
        if self
            .transitions
            .insert(transition_id.clone(), transition)
            .is_some()
        {
            return Err("private l2 transition already exists".to_string());
        }
        self.counters.transitions_opened = self.counters.transitions_opened.saturating_add(1);
        self.refresh();
        Ok(transition_id)
    }

    pub fn apply_transition(
        &mut self,
        transition_id: &str,
        height: u64,
        settlement_binding: &Value,
    ) -> PrivateL2StateTransitionEngineResult<String> {
        self.height = height;
        let state_root_before = self.state_root.clone();
        let transition = self
            .transitions
            .get(transition_id)
            .ok_or_else(|| "private l2 transition not found".to_string())?
            .clone();
        if transition.status != TransitionStatus::Open {
            return Err("private l2 transition is not open".to_string());
        }
        if self
            .consumed_nullifiers
            .contains(&transition.nullifier_root)
        {
            return Err("private l2 transition nullifier already consumed".to_string());
        }

        let mut new_deltas = Vec::new();
        for domain in transition.touched_domains.iter().copied() {
            if new_deltas.len() >= self.config.max_delta_count {
                return Err("private l2 transition exceeded max delta count".to_string());
            }
            let object_id = self
                .objects
                .values()
                .find(|object| object.domain == domain)
                .map(|object| object.object_id.clone())
                .ok_or_else(|| {
                    format!("private l2 state object missing for {}", domain.as_str())
                })?;
            let object = self
                .objects
                .get_mut(&object_id)
                .ok_or_else(|| "private l2 state object not found".to_string())?;
            let before_root = object.value_commitment.clone();
            object.version = object.version.saturating_add(1);
            object.updated_height = height;
            object.value_commitment = private_l2_state_transition_payload_root(
                "UPDATED-OBJECT",
                &json!({
                    "transition_id": transition.transition_id.clone(),
                    "domain": domain.as_str(),
                    "previous": before_root.clone(),
                    "height": height,
                    "version": object.version,
                }),
            );
            let delta = StateDelta::new(
                &transition.transition_id,
                DeltaOpKind::Update,
                domain,
                &object.object_id,
                &before_root,
                &object.value_commitment,
                height,
            )?;
            new_deltas.push(delta);
        }
        let nullifier_delta = StateDelta::new(
            &transition.transition_id,
            DeltaOpKind::ConsumeNullifier,
            StateDomainKind::ProofAccumulator,
            &transition.nullifier_root,
            "unspent",
            "consumed",
            height,
        )?;
        new_deltas.push(nullifier_delta);
        self.consumed_nullifiers
            .insert(transition.nullifier_root.clone());
        for delta in &new_deltas {
            self.deltas.insert(delta.delta_id.clone(), delta.clone());
        }
        self.refresh();
        let state_root_after = self.state_root.clone();
        let receipt = TransitionReceipt::new(
            &transition,
            height,
            &state_root_before,
            &state_root_after,
            &new_deltas,
            settlement_binding,
        );
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        let transition = self
            .transitions
            .get_mut(transition_id)
            .ok_or_else(|| "private l2 transition not found".to_string())?;
        transition.status = TransitionStatus::Settled;
        transition.delta_ids = new_deltas
            .iter()
            .map(|delta| delta.delta_id.clone())
            .collect::<Vec<_>>();
        self.counters.transitions_applied = self.counters.transitions_applied.saturating_add(1);
        self.counters.deltas = self.counters.deltas.saturating_add(new_deltas.len() as u64);
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        self.counters.nullifiers_consumed = self.counters.nullifiers_consumed.saturating_add(1);
        self.refresh();
        Ok(receipt_id)
    }

    pub fn refresh(&mut self) {
        let object_records = self
            .objects
            .values()
            .map(StateObject::public_record)
            .collect::<Vec<_>>();
        let transition_records = self
            .transitions
            .values()
            .map(TransitionRequest::public_record)
            .collect::<Vec<_>>();
        let delta_records = self
            .deltas
            .values()
            .map(StateDelta::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(TransitionReceipt::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| json!(nullifier))
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: private_l2_state_transition_payload_root(
                "CONFIG",
                &self.config.public_record(),
            ),
            object_root: merkle_root("PRIVATE-L2-STATE-OBJECTS", &object_records),
            transition_root: merkle_root("PRIVATE-L2-STATE-TRANSITIONS", &transition_records),
            delta_root: merkle_root("PRIVATE-L2-STATE-DELTAS", &delta_records),
            receipt_root: merkle_root("PRIVATE-L2-STATE-RECEIPTS", &receipt_records),
            nullifier_root: merkle_root("PRIVATE-L2-STATE-NULLIFIERS", &nullifier_records),
            counter_root: private_l2_state_transition_payload_root(
                "COUNTERS",
                &self.counters.public_record(),
            ),
        };
        self.state_root =
            private_l2_state_transition_payload_root("STATE", &self.public_record_without_root());
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_state_transition_engine_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_STATE_TRANSITION_ENGINE_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root));
            object.insert(
                "objects".to_string(),
                json!(self
                    .objects
                    .values()
                    .map(StateObject::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "transitions".to_string(),
                json!(self
                    .transitions
                    .values()
                    .map(TransitionRequest::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "deltas".to_string(),
                json!(self
                    .deltas
                    .values()
                    .map(StateDelta::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "receipts".to_string(),
                json!(self
                    .receipts
                    .values()
                    .map(TransitionReceipt::public_record)
                    .collect::<Vec<_>>()),
            );
        }
        record
    }

    fn validate_transition(
        &mut self,
        transition: &TransitionRequest,
    ) -> PrivateL2StateTransitionEngineResult<()> {
        if transition.fee_bps > self.config.max_fee_bps {
            self.counters.transitions_rejected =
                self.counters.transitions_rejected.saturating_add(1);
            return Err("private l2 transition exceeds fee cap".to_string());
        }
        if transition.privacy_set_size < self.config.min_privacy_set {
            self.counters.transitions_rejected =
                self.counters.transitions_rejected.saturating_add(1);
            return Err("private l2 transition privacy set too small".to_string());
        }
        if transition.pq_security_bits < self.config.min_pq_security_bits {
            self.counters.transitions_rejected =
                self.counters.transitions_rejected.saturating_add(1);
            return Err("private l2 transition pq security too small".to_string());
        }
        Ok(())
    }
}

pub fn devnet_transition_request(
    height: u64,
) -> PrivateL2StateTransitionEngineResult<TransitionRequest> {
    TransitionRequest::new(
        TransitionKind::FullMvpFlow,
        height,
        "devnet-private-user",
        &json!({
            "gateway": "devnet-private-l2-mvp-intent-gateway",
            "execution_service": "devnet-private-l2-mvp-execution-service",
        }),
        &json!({"nullifier": format!("devnet-full-mvp-nullifier-{height}")}),
        &json!({"pq_scheme": PRIVATE_L2_STATE_TRANSITION_ENGINE_PQ_SIGNATURE_SCHEME, "height": height}),
        &json!({"proof_system": PRIVATE_L2_STATE_TRANSITION_ENGINE_PROOF_SYSTEM, "height": height}),
        &json!({"execution_receipt": "devnet-execution-receipt"}),
        PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MAX_FEE_BPS.min(20),
        PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MIN_PRIVACY_SET.saturating_mul(2),
        PRIVATE_L2_STATE_TRANSITION_ENGINE_DEFAULT_MIN_PQ_SECURITY_BITS,
    )
}

pub fn private_l2_state_transition_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-STATE-TRANSITION-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_l2_state_transition_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-STATE-TRANSITION-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

pub fn state_object_id(
    domain: StateDomainKind,
    label: &str,
    owner_commitment: &str,
    value_commitment: &str,
    metadata_root: &str,
    version: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-STATE-OBJECT-ID",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(label),
            HashPart::Str(owner_commitment),
            HashPart::Str(value_commitment),
            HashPart::Str(metadata_root),
            HashPart::Int(version as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn transition_request_id(
    transition_kind: TransitionKind,
    height: u64,
    caller_commitment: &str,
    input_root: &str,
    nullifier_root: &str,
    pq_authorization_root: &str,
    privacy_proof_root: &str,
    execution_receipt_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-STATE-TRANSITION-REQUEST-ID",
        &[
            HashPart::Str(transition_kind.as_str()),
            HashPart::Int(height as i128),
            HashPart::Str(caller_commitment),
            HashPart::Str(input_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(privacy_proof_root),
            HashPart::Str(execution_receipt_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn state_delta_id(
    transition_id: &str,
    op_kind: DeltaOpKind,
    domain: StateDomainKind,
    object_id: &str,
    before_root: &str,
    after_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-STATE-DELTA-ID",
        &[
            HashPart::Str(transition_id),
            HashPart::Str(op_kind.as_str()),
            HashPart::Str(domain.as_str()),
            HashPart::Str(object_id),
            HashPart::Str(before_root),
            HashPart::Str(after_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn transition_receipt_id(
    transition_id: &str,
    height: u64,
    state_root_before: &str,
    state_root_after: &str,
    delta_root: &str,
    nullifier_root: &str,
    execution_receipt_root: &str,
    settlement_binding_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-STATE-TRANSITION-RECEIPT-ID",
        &[
            HashPart::Str(transition_id),
            HashPart::Int(height as i128),
            HashPart::Str(state_root_before),
            HashPart::Str(state_root_after),
            HashPart::Str(delta_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(execution_receipt_root),
            HashPart::Str(settlement_binding_root),
        ],
        32,
    )
}

pub fn root_from_record(record: &Value) -> String {
    private_l2_state_transition_payload_root("RECORD", record)
}

pub fn devnet() -> PrivateL2StateTransitionEngineResult<State> {
    State::devnet()
}
