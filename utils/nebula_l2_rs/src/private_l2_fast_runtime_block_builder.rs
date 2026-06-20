use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastRuntimeBlockBuilderResult<T> = Result<T, String>;

pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-runtime-block-builder-v1";
pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_TARGET_BLOCK_MS: u64 = 500;
pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_MAX_COMPONENTS: usize = 96;
pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_MAX_BLOCKS: usize = 65_536;
pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_MAX_FEE_BPS: u64 = 35;
pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBlockComponentKind {
    PqMempoolBatch,
    IntentGatewayRoute,
    FastLaneFeeMarket,
    ContractRuntimeHost,
    StateTransition,
    ExecutionServiceReceipt,
    RecursiveProofAggregate,
    FeeSponsorSettlement,
    LiquidityBatch,
    SettlementManifest,
    MoneroFinalityEvidence,
    ExitClaimQueue,
    RuntimeCheckpoint,
}

impl RuntimeBlockComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqMempoolBatch => "pq_mempool_batch",
            Self::IntentGatewayRoute => "intent_gateway_route",
            Self::FastLaneFeeMarket => "fast_lane_fee_market",
            Self::ContractRuntimeHost => "contract_runtime_host",
            Self::StateTransition => "state_transition",
            Self::ExecutionServiceReceipt => "execution_service_receipt",
            Self::RecursiveProofAggregate => "recursive_proof_aggregate",
            Self::FeeSponsorSettlement => "fee_sponsor_settlement",
            Self::LiquidityBatch => "liquidity_batch",
            Self::SettlementManifest => "settlement_manifest",
            Self::MoneroFinalityEvidence => "monero_finality_evidence",
            Self::ExitClaimQueue => "exit_claim_queue",
            Self::RuntimeCheckpoint => "runtime_checkpoint",
        }
    }

    pub fn critical_for_fast_block(self) -> bool {
        matches!(
            self,
            Self::PqMempoolBatch
                | Self::IntentGatewayRoute
                | Self::StateTransition
                | Self::ExecutionServiceReceipt
                | Self::RecursiveProofAggregate
                | Self::SettlementManifest
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBlockStatus {
    Open,
    Sealed,
    Preconfirmed,
    SettlementReady,
    Finalized,
    Rejected,
}

impl RuntimeBlockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Preconfirmed => "preconfirmed",
            Self::SettlementReady => "settlement_ready",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationLane {
    FastPrivateDefi,
    ContractCall,
    TokenMint,
    MoneroExit,
    Emergency,
}

impl PreconfirmationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastPrivateDefi => "fast_private_defi",
            Self::ContractCall => "contract_call",
            Self::TokenMint => "token_mint",
            Self::MoneroExit => "monero_exit",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub target_block_ms: u64,
    pub max_components: usize,
    pub max_blocks: usize,
    pub min_pq_security_bits: u64,
    pub max_fee_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_HASH_SUITE.to_string(),
            pq_signature_scheme: PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PQ_SIGNATURE_SCHEME
                .to_string(),
            target_block_ms: PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_TARGET_BLOCK_MS,
            max_components: PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_MAX_COMPONENTS,
            max_blocks: PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_MAX_BLOCKS,
            min_pq_security_bits:
                PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEFAULT_MAX_FEE_BPS,
        }
    }

    pub fn validate(&self) -> PrivateL2FastRuntimeBlockBuilderResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.hash_suite.is_empty()
            || self.pq_signature_scheme.is_empty()
        {
            return Err("private l2 fast block builder labels cannot be empty".to_string());
        }
        if self.target_block_ms == 0
            || self.max_components == 0
            || self.max_blocks == 0
            || self.min_pq_security_bits == 0
        {
            return Err("private l2 fast block builder thresholds must be positive".to_string());
        }
        if self.max_fee_bps > PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_MAX_BPS {
            return Err("private l2 fast block fee cap cannot exceed 100%".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_runtime_block_builder_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "target_block_ms": self.target_block_ms,
            "max_components": self.max_components,
            "max_blocks": self.max_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBlockComponent {
    pub component_id: String,
    pub component_kind: RuntimeBlockComponentKind,
    pub label: String,
    pub state_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub pq_attestation_root: String,
    pub fee_root: String,
    pub weight: u64,
}

impl RuntimeBlockComponent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        component_kind: RuntimeBlockComponentKind,
        label: &str,
        state: &Value,
        receipt: &Value,
        nullifier: &Value,
        pq_attestation: &Value,
        fee: &Value,
        weight: u64,
    ) -> PrivateL2FastRuntimeBlockBuilderResult<Self> {
        if label.is_empty() {
            return Err("private l2 fast block component label cannot be empty".to_string());
        }
        if weight == 0 {
            return Err("private l2 fast block component weight must be positive".to_string());
        }
        let state_root = fast_runtime_block_payload_root("COMPONENT-STATE", state);
        let receipt_root = fast_runtime_block_payload_root("COMPONENT-RECEIPT", receipt);
        let nullifier_root = fast_runtime_block_payload_root("COMPONENT-NULLIFIER", nullifier);
        let pq_attestation_root =
            fast_runtime_block_payload_root("COMPONENT-PQ-ATTESTATION", pq_attestation);
        let fee_root = fast_runtime_block_payload_root("COMPONENT-FEE", fee);
        let component_id = runtime_block_component_id(
            component_kind,
            label,
            &state_root,
            &receipt_root,
            &nullifier_root,
            &pq_attestation_root,
            &fee_root,
            weight,
        );
        Ok(Self {
            component_id,
            component_kind,
            label: label.to_string(),
            state_root,
            receipt_root,
            nullifier_root,
            pq_attestation_root,
            fee_root,
            weight,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_runtime_block_component",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PROTOCOL_VERSION,
            "component_id": self.component_id,
            "component_kind": self.component_kind.as_str(),
            "label": self.label,
            "state_root": self.state_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "pq_attestation_root": self.pq_attestation_root,
            "fee_root": self.fee_root,
            "weight": self.weight,
            "critical_for_fast_block": self.component_kind.critical_for_fast_block(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBlock {
    pub block_id: String,
    pub height: u64,
    pub lane: PreconfirmationLane,
    pub status: RuntimeBlockStatus,
    pub opened_timestamp_ms: u64,
    pub sealed_timestamp_ms: Option<u64>,
    pub sequencer_commitment: String,
    pub component_ids: Vec<String>,
    pub component_root: String,
    pub block_root: String,
    pub preconfirmation_receipt_id: Option<String>,
}

impl RuntimeBlock {
    pub fn new(
        height: u64,
        lane: PreconfirmationLane,
        opened_timestamp_ms: u64,
        sequencer_label: &str,
    ) -> PrivateL2FastRuntimeBlockBuilderResult<Self> {
        if sequencer_label.is_empty() {
            return Err("private l2 fast block sequencer label cannot be empty".to_string());
        }
        let sequencer_commitment = fast_runtime_block_string_root("SEQUENCER", sequencer_label);
        let component_root = merkle_root("PRIVATE-L2-FAST-RUNTIME-BLOCK-COMPONENTS", &[]);
        let block_root = fast_runtime_block_payload_root(
            "BLOCK-OPEN",
            &json!({
                "height": height,
                "lane": lane.as_str(),
                "opened_timestamp_ms": opened_timestamp_ms,
                "sequencer_commitment": sequencer_commitment,
                "component_root": component_root,
            }),
        );
        let block_id = runtime_block_id(
            height,
            lane,
            opened_timestamp_ms,
            &sequencer_commitment,
            &component_root,
            &block_root,
        );
        Ok(Self {
            block_id,
            height,
            lane,
            status: RuntimeBlockStatus::Open,
            opened_timestamp_ms,
            sealed_timestamp_ms: None,
            sequencer_commitment,
            component_ids: Vec::new(),
            component_root,
            block_root,
            preconfirmation_receipt_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_runtime_block",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PROTOCOL_VERSION,
            "block_id": self.block_id,
            "height": self.height,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "opened_timestamp_ms": self.opened_timestamp_ms,
            "sealed_timestamp_ms": self.sealed_timestamp_ms,
            "sequencer_commitment": self.sequencer_commitment,
            "component_ids": self.component_ids,
            "component_root": self.component_root,
            "block_root": self.block_root,
            "preconfirmation_receipt_id": self.preconfirmation_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub block_id: String,
    pub height: u64,
    pub component_root: String,
    pub state_transition_root: String,
    pub proof_aggregate_root: String,
    pub settlement_hint_root: String,
    pub pq_signature_root: String,
    pub fee_root: String,
    pub latency_ms: u64,
}

impl PreconfirmationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_id: &str,
        height: u64,
        component_records: &[Value],
        state_transition: &Value,
        proof_aggregate: &Value,
        settlement_hint: &Value,
        pq_signature: &Value,
        fee: &Value,
        latency_ms: u64,
    ) -> PrivateL2FastRuntimeBlockBuilderResult<Self> {
        if block_id.is_empty() {
            return Err("private l2 fast block id cannot be empty".to_string());
        }
        if latency_ms == 0 {
            return Err("private l2 fast block latency must be positive".to_string());
        }
        let component_root = merkle_root(
            "PRIVATE-L2-FAST-RUNTIME-PRECONFIRMATION-COMPONENTS",
            component_records,
        );
        let state_transition_root =
            fast_runtime_block_payload_root("PRECONF-STATE-TRANSITION", state_transition);
        let proof_aggregate_root =
            fast_runtime_block_payload_root("PRECONF-PROOF-AGGREGATE", proof_aggregate);
        let settlement_hint_root =
            fast_runtime_block_payload_root("PRECONF-SETTLEMENT-HINT", settlement_hint);
        let pq_signature_root =
            fast_runtime_block_payload_root("PRECONF-PQ-SIGNATURE", pq_signature);
        let fee_root = fast_runtime_block_payload_root("PRECONF-FEE", fee);
        let receipt_id = preconfirmation_receipt_id(
            block_id,
            height,
            &component_root,
            &state_transition_root,
            &proof_aggregate_root,
            &settlement_hint_root,
            &pq_signature_root,
            &fee_root,
            latency_ms,
        );
        Ok(Self {
            receipt_id,
            block_id: block_id.to_string(),
            height,
            component_root,
            state_transition_root,
            proof_aggregate_root,
            settlement_hint_root,
            pq_signature_root,
            fee_root,
            latency_ms,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_runtime_preconfirmation_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "block_id": self.block_id,
            "height": self.height,
            "component_root": self.component_root,
            "state_transition_root": self.state_transition_root,
            "proof_aggregate_root": self.proof_aggregate_root,
            "settlement_hint_root": self.settlement_hint_root,
            "pq_signature_root": self.pq_signature_root,
            "fee_root": self.fee_root,
            "latency_ms": self.latency_ms,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub blocks_opened: u64,
    pub blocks_sealed: u64,
    pub blocks_preconfirmed: u64,
    pub components_added: u64,
    pub receipts: u64,
    pub rejected_blocks: u64,
    pub total_latency_ms: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_runtime_block_builder_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PROTOCOL_VERSION,
            "blocks_opened": self.blocks_opened,
            "blocks_sealed": self.blocks_sealed,
            "blocks_preconfirmed": self.blocks_preconfirmed,
            "components_added": self.components_added,
            "receipts": self.receipts,
            "rejected_blocks": self.rejected_blocks,
            "total_latency_ms": self.total_latency_ms,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub block_root: String,
    pub component_root: String,
    pub receipt_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        Self {
            config_root: fast_runtime_block_payload_root("CONFIG", &config.public_record()),
            block_root: merkle_root("PRIVATE-L2-FAST-RUNTIME-BLOCKS", &[]),
            component_root: merkle_root("PRIVATE-L2-FAST-RUNTIME-COMPONENTS", &[]),
            receipt_root: merkle_root("PRIVATE-L2-FAST-RUNTIME-RECEIPTS", &[]),
            counter_root: fast_runtime_block_payload_root(
                "COUNTERS",
                &Counters::default().public_record(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_runtime_block_builder_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "block_root": self.block_root,
            "component_root": self.component_root,
            "receipt_root": self.receipt_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub blocks: BTreeMap<String, RuntimeBlock>,
    pub components: BTreeMap<String, RuntimeBlockComponent>,
    pub receipts: BTreeMap<String, PreconfirmationReceipt>,
    pub counters: Counters,
    pub roots: Roots,
    pub state_root: String,
}

impl State {
    pub fn new(config: Config, height: u64) -> PrivateL2FastRuntimeBlockBuilderResult<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        let mut state = Self {
            config,
            height,
            blocks: BTreeMap::new(),
            components: BTreeMap::new(),
            receipts: BTreeMap::new(),
            counters: Counters::default(),
            roots,
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> PrivateL2FastRuntimeBlockBuilderResult<Self> {
        let mut state = Self::new(
            Config::devnet(),
            PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEVNET_HEIGHT,
        )?;
        let block_id = state.open_block(
            PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_DEVNET_HEIGHT,
            PreconfirmationLane::FastPrivateDefi,
            0,
            "devnet-sequencer",
        )?;
        for (kind, label) in [
            (RuntimeBlockComponentKind::PqMempoolBatch, "pq-mempool"),
            (RuntimeBlockComponentKind::IntentGatewayRoute, "gateway"),
            (
                RuntimeBlockComponentKind::ContractRuntimeHost,
                "contract-host",
            ),
            (
                RuntimeBlockComponentKind::StateTransition,
                "state-transition",
            ),
            (
                RuntimeBlockComponentKind::ExecutionServiceReceipt,
                "execution",
            ),
            (RuntimeBlockComponentKind::RecursiveProofAggregate, "proofs"),
            (RuntimeBlockComponentKind::SettlementManifest, "settlement"),
        ] {
            state.add_component(
                &block_id,
                RuntimeBlockComponent::new(
                    kind,
                    label,
                    &json!({"state": format!("devnet-{label}")}),
                    &json!({"receipt": format!("devnet-{label}")}),
                    &json!({"nullifier": format!("devnet-{label}")}),
                    &json!({"pq": format!("devnet-{label}")}),
                    &json!({"fee": format!("devnet-{label}")}),
                    1,
                )?,
            )?;
        }
        state.seal_block(
            &block_id,
            450,
            &json!({"state_transition": "devnet"}),
            &json!({"proof_aggregate": "devnet"}),
            &json!({"settlement_hint": "devnet"}),
            &json!({"pq_signature": "devnet"}),
            &json!({"fee": "devnet"}),
        )?;
        Ok(state)
    }

    pub fn open_block(
        &mut self,
        height: u64,
        lane: PreconfirmationLane,
        opened_timestamp_ms: u64,
        sequencer_label: &str,
    ) -> PrivateL2FastRuntimeBlockBuilderResult<String> {
        if self.blocks.len() >= self.config.max_blocks {
            return Err("private l2 fast block capacity exhausted".to_string());
        }
        let block = RuntimeBlock::new(height, lane, opened_timestamp_ms, sequencer_label)?;
        let block_id = block.block_id.clone();
        if self.blocks.insert(block_id.clone(), block).is_some() {
            return Err("private l2 fast block already exists".to_string());
        }
        self.counters.blocks_opened = self.counters.blocks_opened.saturating_add(1);
        self.refresh();
        Ok(block_id)
    }

    pub fn add_component(
        &mut self,
        block_id: &str,
        component: RuntimeBlockComponent,
    ) -> PrivateL2FastRuntimeBlockBuilderResult<String> {
        {
            let block = self
                .blocks
                .get(block_id)
                .ok_or_else(|| "private l2 fast block not found".to_string())?;
            if block.status != RuntimeBlockStatus::Open {
                return Err("private l2 fast block is not open".to_string());
            }
            if block.component_ids.len() >= self.config.max_components {
                return Err("private l2 fast block component limit exceeded".to_string());
            }
        }
        let component_id = component.component_id.clone();
        if self
            .components
            .insert(component_id.clone(), component)
            .is_some()
        {
            return Err("private l2 fast block component already exists".to_string());
        }
        {
            let block = self
                .blocks
                .get_mut(block_id)
                .ok_or_else(|| "private l2 fast block not found".to_string())?;
            block.component_ids.push(component_id.clone());
        }
        let component_root = self.component_root_for_block(block_id)?;
        let block_root = fast_runtime_block_payload_root(
            "BLOCK-COMPONENT-UPDATE",
            &json!({
                "block_id": block_id,
                "component_root": component_root,
            }),
        );
        let block = self
            .blocks
            .get_mut(block_id)
            .ok_or_else(|| "private l2 fast block not found".to_string())?;
        block.component_root = component_root;
        block.block_root = block_root;
        self.counters.components_added = self.counters.components_added.saturating_add(1);
        self.refresh();
        Ok(component_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn seal_block(
        &mut self,
        block_id: &str,
        latency_ms: u64,
        state_transition: &Value,
        proof_aggregate: &Value,
        settlement_hint: &Value,
        pq_signature: &Value,
        fee: &Value,
    ) -> PrivateL2FastRuntimeBlockBuilderResult<String> {
        let component_records = self.component_records_for_block(block_id)?;
        let block = self
            .blocks
            .get(block_id)
            .ok_or_else(|| "private l2 fast block not found".to_string())?
            .clone();
        if block.status != RuntimeBlockStatus::Open {
            return Err("private l2 fast block is not open".to_string());
        }
        if !self.has_critical_components(&block.component_ids) {
            return Err("private l2 fast block missing critical components".to_string());
        }
        let receipt = PreconfirmationReceipt::new(
            block_id,
            block.height,
            &component_records,
            state_transition,
            proof_aggregate,
            settlement_hint,
            pq_signature,
            fee,
            latency_ms,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        let block = self
            .blocks
            .get_mut(block_id)
            .ok_or_else(|| "private l2 fast block not found".to_string())?;
        block.status = RuntimeBlockStatus::Preconfirmed;
        block.sealed_timestamp_ms = Some(block.opened_timestamp_ms.saturating_add(latency_ms));
        block.preconfirmation_receipt_id = Some(receipt_id.clone());
        block.block_root = fast_runtime_block_payload_root(
            "BLOCK-SEALED",
            &json!({
                "block_id": block_id,
                "component_root": block.component_root,
                "receipt_id": receipt_id,
                "latency_ms": latency_ms,
            }),
        );
        self.counters.blocks_sealed = self.counters.blocks_sealed.saturating_add(1);
        self.counters.blocks_preconfirmed = self.counters.blocks_preconfirmed.saturating_add(1);
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        self.counters.total_latency_ms = self.counters.total_latency_ms.saturating_add(latency_ms);
        self.refresh();
        Ok(receipt_id)
    }

    pub fn refresh(&mut self) {
        let block_records = self
            .blocks
            .values()
            .map(RuntimeBlock::public_record)
            .collect::<Vec<_>>();
        let component_records = self
            .components
            .values()
            .map(RuntimeBlockComponent::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(PreconfirmationReceipt::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: fast_runtime_block_payload_root("CONFIG", &self.config.public_record()),
            block_root: merkle_root("PRIVATE-L2-FAST-RUNTIME-BLOCKS", &block_records),
            component_root: merkle_root("PRIVATE-L2-FAST-RUNTIME-COMPONENTS", &component_records),
            receipt_root: merkle_root("PRIVATE-L2-FAST-RUNTIME-RECEIPTS", &receipt_records),
            counter_root: fast_runtime_block_payload_root(
                "COUNTERS",
                &self.counters.public_record(),
            ),
        };
        self.state_root =
            fast_runtime_block_payload_root("STATE", &self.public_record_without_root());
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_fast_runtime_block_builder_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_FAST_RUNTIME_BLOCK_BUILDER_PROTOCOL_VERSION,
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
                "blocks".to_string(),
                json!(self
                    .blocks
                    .values()
                    .map(RuntimeBlock::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "components".to_string(),
                json!(self
                    .components
                    .values()
                    .map(RuntimeBlockComponent::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "receipts".to_string(),
                json!(self
                    .receipts
                    .values()
                    .map(PreconfirmationReceipt::public_record)
                    .collect::<Vec<_>>()),
            );
        }
        record
    }

    fn component_records_for_block(
        &self,
        block_id: &str,
    ) -> PrivateL2FastRuntimeBlockBuilderResult<Vec<Value>> {
        let block = self
            .blocks
            .get(block_id)
            .ok_or_else(|| "private l2 fast block not found".to_string())?;
        Ok(block
            .component_ids
            .iter()
            .filter_map(|component_id| self.components.get(component_id))
            .map(RuntimeBlockComponent::public_record)
            .collect::<Vec<_>>())
    }

    fn component_root_for_block(
        &self,
        block_id: &str,
    ) -> PrivateL2FastRuntimeBlockBuilderResult<String> {
        Ok(merkle_root(
            "PRIVATE-L2-FAST-RUNTIME-BLOCK-COMPONENTS",
            &self.component_records_for_block(block_id)?,
        ))
    }

    fn has_critical_components(&self, component_ids: &[String]) -> bool {
        let present = component_ids
            .iter()
            .filter_map(|component_id| self.components.get(component_id))
            .map(|component| component.component_kind)
            .collect::<BTreeSet<_>>();
        [
            RuntimeBlockComponentKind::PqMempoolBatch,
            RuntimeBlockComponentKind::IntentGatewayRoute,
            RuntimeBlockComponentKind::StateTransition,
            RuntimeBlockComponentKind::ExecutionServiceReceipt,
            RuntimeBlockComponentKind::RecursiveProofAggregate,
            RuntimeBlockComponentKind::SettlementManifest,
        ]
        .into_iter()
        .all(|kind| present.contains(&kind))
    }
}

pub fn fast_runtime_block_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-RUNTIME-BLOCK-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn fast_runtime_block_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-RUNTIME-BLOCK-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn runtime_block_component_id(
    component_kind: RuntimeBlockComponentKind,
    label: &str,
    state_root: &str,
    receipt_root: &str,
    nullifier_root: &str,
    pq_attestation_root: &str,
    fee_root: &str,
    weight: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-RUNTIME-BLOCK-COMPONENT-ID",
        &[
            HashPart::Str(component_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(state_root),
            HashPart::Str(receipt_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(pq_attestation_root),
            HashPart::Str(fee_root),
            HashPart::Int(weight as i128),
        ],
        32,
    )
}

pub fn runtime_block_id(
    height: u64,
    lane: PreconfirmationLane,
    opened_timestamp_ms: u64,
    sequencer_commitment: &str,
    component_root: &str,
    block_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-RUNTIME-BLOCK-ID",
        &[
            HashPart::Int(height as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_timestamp_ms as i128),
            HashPart::Str(sequencer_commitment),
            HashPart::Str(component_root),
            HashPart::Str(block_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn preconfirmation_receipt_id(
    block_id: &str,
    height: u64,
    component_root: &str,
    state_transition_root: &str,
    proof_aggregate_root: &str,
    settlement_hint_root: &str,
    pq_signature_root: &str,
    fee_root: &str,
    latency_ms: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-RUNTIME-PRECONFIRMATION-ID",
        &[
            HashPart::Str(block_id),
            HashPart::Int(height as i128),
            HashPart::Str(component_root),
            HashPart::Str(state_transition_root),
            HashPart::Str(proof_aggregate_root),
            HashPart::Str(settlement_hint_root),
            HashPart::Str(pq_signature_root),
            HashPart::Str(fee_root),
            HashPart::Int(latency_ms as i128),
        ],
        32,
    )
}

pub fn root_from_record(record: &Value) -> String {
    fast_runtime_block_payload_root("RECORD", record)
}

pub fn devnet() -> PrivateL2FastRuntimeBlockBuilderResult<State> {
    State::devnet()
}
