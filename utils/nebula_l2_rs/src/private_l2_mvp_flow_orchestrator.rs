use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2MvpFlowOrchestratorResult<T> = Result<T, String>;

pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PROTOCOL_VERSION: &str =
    "nebula-private-l2-mvp-flow-orchestrator-v1";
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PRIVACY_PROOF_SYSTEM: &str = "zk-private-l2-flow-v1";
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_RECURSIVE_PROOF_SYSTEM: &str =
    "zk-pq-recursive-flow-aggregate-v1";
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_MAX_USER_FEE_BPS: u64 = 35;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_MIN_PRIVACY_SET: u64 = 256;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_TARGET_LATENCY_BLOCKS: u64 = 2;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_EXIT_FINALITY_BLOCKS: u64 = 10;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_MAX_BATCH_WEIGHT: u64 = 256;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_FLOWS: usize = 4_096;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_STAGE_RECEIPTS: usize = 32_768;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_BATCHES: usize = 4_096;
pub const PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStageKind {
    Admission,
    PqAuthorization,
    ConfidentialTokenMint,
    PrivateContractCall,
    PrivateAmmSwap,
    LiquidityNetting,
    ProofAggregation,
    FeeSponsorship,
    DataAvailabilitySeal,
    MoneroExit,
}

impl FlowStageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::PqAuthorization => "pq_authorization",
            Self::ConfidentialTokenMint => "confidential_token_mint",
            Self::PrivateContractCall => "private_contract_call",
            Self::PrivateAmmSwap => "private_amm_swap",
            Self::LiquidityNetting => "liquidity_netting",
            Self::ProofAggregation => "proof_aggregation",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::DataAvailabilitySeal => "data_availability_seal",
            Self::MoneroExit => "monero_exit",
        }
    }

    pub fn required_for_full_mvp(self) -> bool {
        matches!(
            self,
            Self::Admission
                | Self::PqAuthorization
                | Self::ConfidentialTokenMint
                | Self::PrivateContractCall
                | Self::PrivateAmmSwap
                | Self::ProofAggregation
                | Self::FeeSponsorship
                | Self::MoneroExit
        )
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Admission => 1,
            Self::PqAuthorization => 2,
            Self::ConfidentialTokenMint => 8,
            Self::PrivateContractCall => 12,
            Self::PrivateAmmSwap => 10,
            Self::LiquidityNetting => 6,
            Self::ProofAggregation => 18,
            Self::FeeSponsorship => 3,
            Self::DataAvailabilitySeal => 5,
            Self::MoneroExit => 16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStatus {
    Open,
    Admitted,
    Executing,
    Proving,
    Sponsored,
    ExitQueued,
    Settled,
    Rejected,
    Expired,
}

impl FlowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Admitted => "admitted",
            Self::Executing => "executing",
            Self::Proving => "proving",
            Self::Sponsored => "sponsored",
            Self::ExitQueued => "exit_queued",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSponsorshipMode {
    UserPays,
    AppPaymaster,
    ProofMarketRebate,
    BridgeSubsidy,
    PublicGoods,
}

impl FeeSponsorshipMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPays => "user_pays",
            Self::AppPaymaster => "app_paymaster",
            Self::ProofMarketRebate => "proof_market_rebate",
            Self::BridgeSubsidy => "bridge_subsidy",
            Self::PublicGoods => "public_goods",
        }
    }

    pub fn sponsored(self) -> bool {
        !matches!(self, Self::UserPays)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowBatchStatus {
    Draft,
    Packed,
    Proving,
    Published,
    Settled,
}

impl FlowBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Packed => "packed",
            Self::Proving => "proving",
            Self::Published => "published",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub pq_signature_scheme: String,
    pub pq_kem_scheme: String,
    pub privacy_proof_system: String,
    pub recursive_proof_system: String,
    pub max_user_fee_bps: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
    pub target_latency_blocks: u64,
    pub exit_finality_blocks: u64,
    pub max_batch_weight: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            pq_signature_scheme: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PQ_SIGNATURE_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PQ_KEM_SCHEME.to_string(),
            privacy_proof_system: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PRIVACY_PROOF_SYSTEM.to_string(),
            recursive_proof_system: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_RECURSIVE_PROOF_SYSTEM
                .to_string(),
            max_user_fee_bps: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_latency_blocks: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_TARGET_LATENCY_BLOCKS,
            exit_finality_blocks: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_EXIT_FINALITY_BLOCKS,
            max_batch_weight: PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEFAULT_MAX_BATCH_WEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2MvpFlowOrchestratorResult<()> {
        if self.protocol_version.is_empty()
            || self.chain_id.is_empty()
            || self.pq_signature_scheme.is_empty()
            || self.pq_kem_scheme.is_empty()
            || self.privacy_proof_system.is_empty()
            || self.recursive_proof_system.is_empty()
        {
            return Err("private l2 mvp flow config identifiers cannot be empty".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_BPS {
            return Err("private l2 mvp flow fee cap cannot exceed 100%".to_string());
        }
        if self.min_privacy_set == 0
            || self.min_pq_security_bits == 0
            || self.target_latency_blocks == 0
            || self.exit_finality_blocks == 0
            || self.max_batch_weight == 0
        {
            return Err("private l2 mvp flow thresholds must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_flow_orchestrator_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "privacy_proof_system": self.privacy_proof_system,
            "recursive_proof_system": self.recursive_proof_system,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_latency_blocks": self.target_latency_blocks,
            "exit_finality_blocks": self.exit_finality_blocks,
            "max_batch_weight": self.max_batch_weight,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowIntent {
    pub flow_id: String,
    pub label: String,
    pub opened_height: u64,
    pub status: FlowStatus,
    pub user_commitment: String,
    pub token_commitment_root: String,
    pub contract_call_root: String,
    pub swap_route_root: String,
    pub exit_request_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u64,
    pub max_fee_bps: u64,
    pub requested_stages: BTreeSet<FlowStageKind>,
    pub stage_receipt_ids: Vec<String>,
    pub settlement_receipt_id: Option<String>,
}

impl FlowIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        opened_height: u64,
        user_label: &str,
        token_payload: &Value,
        contract_payload: &Value,
        swap_payload: &Value,
        exit_payload: &Value,
        privacy_set_size: u64,
        pq_security_bits: u64,
        max_fee_bps: u64,
        requested_stages: BTreeSet<FlowStageKind>,
    ) -> PrivateL2MvpFlowOrchestratorResult<Self> {
        if label.is_empty() || user_label.is_empty() {
            return Err("private l2 mvp flow labels cannot be empty".to_string());
        }
        if privacy_set_size == 0 || pq_security_bits == 0 {
            return Err(
                "private l2 mvp flow privacy and pq thresholds must be positive".to_string(),
            );
        }
        if max_fee_bps > PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_BPS {
            return Err("private l2 mvp flow max fee cannot exceed 100%".to_string());
        }
        if requested_stages.is_empty() {
            return Err("private l2 mvp flow must request at least one stage".to_string());
        }
        let user_commitment = private_l2_mvp_flow_string_root("FLOW-USER", user_label);
        let token_commitment_root = private_l2_mvp_flow_payload_root("FLOW-TOKEN", token_payload);
        let contract_call_root =
            private_l2_mvp_flow_payload_root("FLOW-CONTRACT", contract_payload);
        let swap_route_root = private_l2_mvp_flow_payload_root("FLOW-SWAP", swap_payload);
        let exit_request_root = private_l2_mvp_flow_payload_root("FLOW-EXIT", exit_payload);
        let flow_id = flow_intent_id(
            label,
            opened_height,
            &user_commitment,
            &token_commitment_root,
            &contract_call_root,
            &swap_route_root,
            &exit_request_root,
        );
        Ok(Self {
            flow_id,
            label: label.to_string(),
            opened_height,
            status: FlowStatus::Open,
            user_commitment,
            token_commitment_root,
            contract_call_root,
            swap_route_root,
            exit_request_root,
            privacy_set_size,
            pq_security_bits,
            max_fee_bps,
            requested_stages,
            stage_receipt_ids: Vec::new(),
            settlement_receipt_id: None,
        })
    }

    pub fn validate(&self) -> PrivateL2MvpFlowOrchestratorResult<()> {
        if self.flow_id.is_empty()
            || self.label.is_empty()
            || self.user_commitment.is_empty()
            || self.token_commitment_root.is_empty()
            || self.contract_call_root.is_empty()
            || self.swap_route_root.is_empty()
            || self.exit_request_root.is_empty()
        {
            return Err("private l2 mvp flow identifiers cannot be empty".to_string());
        }
        if self.privacy_set_size == 0 || self.pq_security_bits == 0 {
            return Err("private l2 mvp flow thresholds must be positive".to_string());
        }
        if self.max_fee_bps > PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_BPS {
            return Err("private l2 mvp flow max fee cannot exceed 100%".to_string());
        }
        if self.requested_stages.is_empty() {
            return Err("private l2 mvp flow requested stages cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn has_required_mvp_path(&self) -> bool {
        [
            FlowStageKind::Admission,
            FlowStageKind::PqAuthorization,
            FlowStageKind::ConfidentialTokenMint,
            FlowStageKind::PrivateContractCall,
            FlowStageKind::PrivateAmmSwap,
            FlowStageKind::ProofAggregation,
            FlowStageKind::FeeSponsorship,
            FlowStageKind::MoneroExit,
        ]
        .into_iter()
        .all(|stage| self.requested_stages.contains(&stage))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_flow_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PROTOCOL_VERSION,
            "flow_id": self.flow_id,
            "label": self.label,
            "opened_height": self.opened_height,
            "status": self.status.as_str(),
            "user_commitment": self.user_commitment,
            "token_commitment_root": self.token_commitment_root,
            "contract_call_root": self.contract_call_root,
            "swap_route_root": self.swap_route_root,
            "exit_request_root": self.exit_request_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "requested_stages": self.requested_stages.iter().map(|stage| stage.as_str()).collect::<Vec<_>>(),
            "stage_receipt_ids": self.stage_receipt_ids,
            "settlement_receipt_id": self.settlement_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageReceipt {
    pub receipt_id: String,
    pub flow_id: String,
    pub stage_kind: FlowStageKind,
    pub height: u64,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub fee_bps: u64,
    pub latency_blocks: u64,
    pub proof_weight: u64,
    pub pq_attestation_root: String,
    pub status: FlowStatus,
}

impl StageReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flow_id: &str,
        stage_kind: FlowStageKind,
        height: u64,
        payload: &Value,
        nullifier_payload: &Value,
        witness_payload: &Value,
        fee_bps: u64,
        latency_blocks: u64,
        proof_weight: u64,
        pq_attestation: &Value,
        status: FlowStatus,
    ) -> PrivateL2MvpFlowOrchestratorResult<Self> {
        if flow_id.is_empty() {
            return Err("private l2 mvp stage flow id cannot be empty".to_string());
        }
        if fee_bps > PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_BPS {
            return Err("private l2 mvp stage fee cannot exceed 100%".to_string());
        }
        if latency_blocks == 0 || proof_weight == 0 {
            return Err(
                "private l2 mvp stage latency and proof weight must be positive".to_string(),
            );
        }
        let commitment_root = private_l2_mvp_flow_payload_root("STAGE-COMMITMENT", payload);
        let nullifier_root = private_l2_mvp_flow_payload_root("STAGE-NULLIFIER", nullifier_payload);
        let witness_root = private_l2_mvp_flow_payload_root("STAGE-WITNESS", witness_payload);
        let pq_attestation_root =
            private_l2_mvp_flow_payload_root("STAGE-PQ-ATTESTATION", pq_attestation);
        let receipt_id = stage_receipt_id(
            flow_id,
            stage_kind,
            height,
            &commitment_root,
            &nullifier_root,
            &witness_root,
            &pq_attestation_root,
        );
        Ok(Self {
            receipt_id,
            flow_id: flow_id.to_string(),
            stage_kind,
            height,
            commitment_root,
            nullifier_root,
            witness_root,
            fee_bps,
            latency_blocks,
            proof_weight,
            pq_attestation_root,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_flow_stage_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "flow_id": self.flow_id,
            "stage_kind": self.stage_kind.as_str(),
            "height": self.height,
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "witness_root": self.witness_root,
            "fee_bps": self.fee_bps,
            "latency_blocks": self.latency_blocks,
            "proof_weight": self.proof_weight,
            "pq_attestation_root": self.pq_attestation_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowBatch {
    pub batch_id: String,
    pub opened_height: u64,
    pub status: FlowBatchStatus,
    pub flow_ids: Vec<String>,
    pub stage_receipt_ids: Vec<String>,
    pub total_proof_weight: u64,
    pub aggregate_fee_bps: u64,
    pub batch_commitment_root: String,
    pub recursive_proof_root: String,
}

impl FlowBatch {
    pub fn new(
        opened_height: u64,
        flow_ids: Vec<String>,
        stage_receipt_ids: Vec<String>,
        total_proof_weight: u64,
        aggregate_fee_bps: u64,
        batch_payload: &Value,
    ) -> PrivateL2MvpFlowOrchestratorResult<Self> {
        if flow_ids.is_empty() || stage_receipt_ids.is_empty() {
            return Err("private l2 mvp batch must include flows and receipts".to_string());
        }
        if total_proof_weight == 0 {
            return Err("private l2 mvp batch proof weight must be positive".to_string());
        }
        if aggregate_fee_bps > PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_BPS {
            return Err("private l2 mvp batch aggregate fee cannot exceed 100%".to_string());
        }
        let batch_commitment_root =
            private_l2_mvp_flow_payload_root("BATCH-COMMITMENT", batch_payload);
        let recursive_proof_root = private_l2_mvp_flow_payload_root(
            "BATCH-RECURSIVE-PROOF",
            &json!({
                "opened_height": opened_height,
                "flow_ids": flow_ids,
                "stage_receipt_ids": stage_receipt_ids,
                "total_proof_weight": total_proof_weight,
                "aggregate_fee_bps": aggregate_fee_bps,
                "batch_commitment_root": batch_commitment_root,
            }),
        );
        let batch_id = flow_batch_id(
            opened_height,
            &flow_ids,
            &stage_receipt_ids,
            total_proof_weight,
            aggregate_fee_bps,
            &batch_commitment_root,
            &recursive_proof_root,
        );
        Ok(Self {
            batch_id,
            opened_height,
            status: FlowBatchStatus::Packed,
            flow_ids,
            stage_receipt_ids,
            total_proof_weight,
            aggregate_fee_bps,
            batch_commitment_root,
            recursive_proof_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_flow_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "opened_height": self.opened_height,
            "status": self.status.as_str(),
            "flow_ids": self.flow_ids,
            "stage_receipt_ids": self.stage_receipt_ids,
            "total_proof_weight": self.total_proof_weight,
            "aggregate_fee_bps": self.aggregate_fee_bps,
            "batch_commitment_root": self.batch_commitment_root,
            "recursive_proof_root": self.recursive_proof_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub flow_id: String,
    pub batch_id: String,
    pub height: u64,
    pub fee_mode: FeeSponsorshipMode,
    pub user_fee_bps: u64,
    pub sponsor_commitment: String,
    pub monero_exit_root: String,
    pub da_publication_root: String,
    pub finality_height: u64,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flow_id: &str,
        batch_id: &str,
        height: u64,
        fee_mode: FeeSponsorshipMode,
        user_fee_bps: u64,
        sponsor_label: &str,
        monero_exit: &Value,
        da_publication: &Value,
        finality_height: u64,
    ) -> PrivateL2MvpFlowOrchestratorResult<Self> {
        if flow_id.is_empty() || batch_id.is_empty() || sponsor_label.is_empty() {
            return Err("private l2 mvp settlement identifiers cannot be empty".to_string());
        }
        if user_fee_bps > PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_BPS {
            return Err("private l2 mvp settlement fee cannot exceed 100%".to_string());
        }
        if finality_height < height {
            return Err("private l2 mvp settlement finality cannot precede height".to_string());
        }
        let sponsor_commitment =
            private_l2_mvp_flow_string_root("SETTLEMENT-SPONSOR", sponsor_label);
        let monero_exit_root =
            private_l2_mvp_flow_payload_root("SETTLEMENT-MONERO-EXIT", monero_exit);
        let da_publication_root = private_l2_mvp_flow_payload_root("SETTLEMENT-DA", da_publication);
        let settlement_id = settlement_receipt_id(
            flow_id,
            batch_id,
            height,
            fee_mode,
            user_fee_bps,
            &sponsor_commitment,
            &monero_exit_root,
            &da_publication_root,
            finality_height,
        );
        Ok(Self {
            settlement_id,
            flow_id: flow_id.to_string(),
            batch_id: batch_id.to_string(),
            height,
            fee_mode,
            user_fee_bps,
            sponsor_commitment,
            monero_exit_root,
            da_publication_root,
            finality_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_flow_settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PROTOCOL_VERSION,
            "settlement_id": self.settlement_id,
            "flow_id": self.flow_id,
            "batch_id": self.batch_id,
            "height": self.height,
            "fee_mode": self.fee_mode.as_str(),
            "fee_sponsored": self.fee_mode.sponsored(),
            "user_fee_bps": self.user_fee_bps,
            "sponsor_commitment": self.sponsor_commitment,
            "monero_exit_root": self.monero_exit_root,
            "da_publication_root": self.da_publication_root,
            "finality_height": self.finality_height,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub opened_flows: u64,
    pub admitted_flows: u64,
    pub rejected_flows: u64,
    pub finalized_flows: u64,
    pub stage_receipts: u64,
    pub sponsored_settlements: u64,
    pub batches: u64,
    pub monero_exits: u64,
    pub total_user_fee_bps: u64,
    pub total_proof_weight: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_flow_orchestrator_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PROTOCOL_VERSION,
            "opened_flows": self.opened_flows,
            "admitted_flows": self.admitted_flows,
            "rejected_flows": self.rejected_flows,
            "finalized_flows": self.finalized_flows,
            "stage_receipts": self.stage_receipts,
            "sponsored_settlements": self.sponsored_settlements,
            "batches": self.batches,
            "monero_exits": self.monero_exits,
            "total_user_fee_bps": self.total_user_fee_bps,
            "total_proof_weight": self.total_proof_weight,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub flow_root: String,
    pub stage_receipt_root: String,
    pub batch_root: String,
    pub settlement_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        Self {
            config_root: private_l2_mvp_flow_payload_root("CONFIG", &config.public_record()),
            flow_root: merkle_root("PRIVATE-L2-MVP-FLOW-FLOWS", &[]),
            stage_receipt_root: merkle_root("PRIVATE-L2-MVP-FLOW-STAGES", &[]),
            batch_root: merkle_root("PRIVATE-L2-MVP-FLOW-BATCHES", &[]),
            settlement_root: merkle_root("PRIVATE-L2-MVP-FLOW-SETTLEMENTS", &[]),
            counter_root: private_l2_mvp_flow_payload_root(
                "COUNTERS",
                &Counters::default().public_record(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_flow_orchestrator_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "flow_root": self.flow_root,
            "stage_receipt_root": self.stage_receipt_root,
            "batch_root": self.batch_root,
            "settlement_root": self.settlement_root,
            "counter_root": self.counter_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub flows: BTreeMap<String, FlowIntent>,
    pub stage_receipts: BTreeMap<String, StageReceipt>,
    pub batches: BTreeMap<String, FlowBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub counters: Counters,
    pub roots: Roots,
    pub state_root: String,
}

impl State {
    pub fn new(config: Config, height: u64) -> PrivateL2MvpFlowOrchestratorResult<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        let mut state = Self {
            config,
            height,
            flows: BTreeMap::new(),
            stage_receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            counters: Counters::default(),
            roots,
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn devnet() -> PrivateL2MvpFlowOrchestratorResult<Self> {
        let mut state = Self::new(
            Config::devnet(),
            PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEVNET_HEIGHT,
        )?;
        state.run_devnet_private_flow(
            "devnet-private-l2-mvp-flow",
            PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_DEVNET_HEIGHT,
        )?;
        Ok(state)
    }

    pub fn open_flow(&mut self, flow: FlowIntent) -> PrivateL2MvpFlowOrchestratorResult<String> {
        if self.flows.len() >= PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_FLOWS {
            return Err("private l2 mvp flow capacity exhausted".to_string());
        }
        flow.validate()?;
        if flow.privacy_set_size < self.config.min_privacy_set {
            return Err("private l2 mvp flow privacy set below configured minimum".to_string());
        }
        if flow.pq_security_bits < self.config.min_pq_security_bits {
            return Err("private l2 mvp flow pq security below configured minimum".to_string());
        }
        if flow.max_fee_bps > self.config.max_user_fee_bps {
            return Err("private l2 mvp flow fee exceeds configured low-fee cap".to_string());
        }
        if !flow.has_required_mvp_path() {
            return Err("private l2 mvp flow is missing required mvp stages".to_string());
        }
        let flow_id = flow.flow_id.clone();
        if self.flows.insert(flow_id.clone(), flow).is_some() {
            return Err("private l2 mvp flow already exists".to_string());
        }
        self.counters.opened_flows = self.counters.opened_flows.saturating_add(1);
        self.refresh();
        Ok(flow_id)
    }

    pub fn admit_flow(&mut self, flow_id: &str) -> PrivateL2MvpFlowOrchestratorResult<()> {
        let flow = self
            .flows
            .get_mut(flow_id)
            .ok_or_else(|| "private l2 mvp flow not found".to_string())?;
        if flow.status.terminal() {
            return Err("private l2 mvp terminal flow cannot be admitted".to_string());
        }
        flow.status = FlowStatus::Admitted;
        self.counters.admitted_flows = self.counters.admitted_flows.saturating_add(1);
        self.refresh();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_stage(
        &mut self,
        flow_id: &str,
        stage_kind: FlowStageKind,
        payload: &Value,
        nullifier_payload: &Value,
        witness_payload: &Value,
        fee_bps: u64,
        latency_blocks: u64,
        proof_weight: u64,
        pq_attestation: &Value,
    ) -> PrivateL2MvpFlowOrchestratorResult<String> {
        if self.stage_receipts.len() >= PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_STAGE_RECEIPTS {
            return Err("private l2 mvp stage receipt capacity exhausted".to_string());
        }
        let flow = self
            .flows
            .get(flow_id)
            .ok_or_else(|| "private l2 mvp flow not found".to_string())?;
        if flow.status.terminal() {
            return Err("private l2 mvp terminal flow cannot append stages".to_string());
        }
        if !flow.requested_stages.contains(&stage_kind) {
            return Err("private l2 mvp stage was not requested by flow".to_string());
        }
        if fee_bps > self.config.max_user_fee_bps {
            return Err("private l2 mvp stage fee exceeds low-fee cap".to_string());
        }
        if latency_blocks > self.config.target_latency_blocks.saturating_mul(4) {
            return Err("private l2 mvp stage latency exceeds fast-lane budget".to_string());
        }
        let next_status = match stage_kind {
            FlowStageKind::Admission | FlowStageKind::PqAuthorization => FlowStatus::Admitted,
            FlowStageKind::ConfidentialTokenMint
            | FlowStageKind::PrivateContractCall
            | FlowStageKind::PrivateAmmSwap
            | FlowStageKind::LiquidityNetting
            | FlowStageKind::DataAvailabilitySeal => FlowStatus::Executing,
            FlowStageKind::ProofAggregation => FlowStatus::Proving,
            FlowStageKind::FeeSponsorship => FlowStatus::Sponsored,
            FlowStageKind::MoneroExit => FlowStatus::ExitQueued,
        };
        let receipt = StageReceipt::new(
            flow_id,
            stage_kind,
            self.height,
            payload,
            nullifier_payload,
            witness_payload,
            fee_bps,
            latency_blocks,
            proof_weight,
            pq_attestation,
            next_status,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        if self
            .stage_receipts
            .insert(receipt_id.clone(), receipt)
            .is_some()
        {
            return Err("private l2 mvp stage receipt already exists".to_string());
        }
        let flow = self
            .flows
            .get_mut(flow_id)
            .ok_or_else(|| "private l2 mvp flow not found".to_string())?;
        flow.stage_receipt_ids.push(receipt_id.clone());
        flow.status = next_status;
        self.counters.stage_receipts = self.counters.stage_receipts.saturating_add(1);
        self.counters.total_user_fee_bps = self.counters.total_user_fee_bps.saturating_add(fee_bps);
        self.counters.total_proof_weight = self
            .counters
            .total_proof_weight
            .saturating_add(proof_weight);
        self.refresh();
        Ok(receipt_id)
    }

    pub fn select_batch(&mut self, height: u64) -> PrivateL2MvpFlowOrchestratorResult<String> {
        if self.batches.len() >= PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_MAX_BATCHES {
            return Err("private l2 mvp batch capacity exhausted".to_string());
        }
        self.height = height;
        let mut selected_flow_ids = Vec::new();
        let mut selected_receipt_ids = Vec::new();
        let mut total_weight = 0_u64;
        let mut total_fee_bps = 0_u64;
        for flow in self.flows.values() {
            if flow.status.terminal() || flow.stage_receipt_ids.is_empty() {
                continue;
            }
            for receipt_id in &flow.stage_receipt_ids {
                let Some(receipt) = self.stage_receipts.get(receipt_id) else {
                    continue;
                };
                if total_weight.saturating_add(receipt.proof_weight) > self.config.max_batch_weight
                {
                    continue;
                }
                selected_receipt_ids.push(receipt_id.clone());
                total_weight = total_weight.saturating_add(receipt.proof_weight);
                total_fee_bps = total_fee_bps.saturating_add(receipt.fee_bps);
            }
            if selected_receipt_ids.iter().any(|receipt_id| {
                self.stage_receipts
                    .get(receipt_id)
                    .map(|receipt| receipt.flow_id == flow.flow_id)
                    .unwrap_or(false)
            }) {
                selected_flow_ids.push(flow.flow_id.clone());
            }
        }
        if selected_flow_ids.is_empty() || selected_receipt_ids.is_empty() {
            return Err("private l2 mvp no eligible flow receipts for batch".to_string());
        }
        let aggregate_fee_bps = total_fee_bps
            .checked_div(selected_receipt_ids.len() as u64)
            .unwrap_or(0);
        let batch = FlowBatch::new(
            height,
            selected_flow_ids,
            selected_receipt_ids,
            total_weight,
            aggregate_fee_bps,
            &json!({
                "height": height,
                "scheduler": "pq_fast_private_mvp_lane",
                "target_latency_blocks": self.config.target_latency_blocks,
                "max_batch_weight": self.config.max_batch_weight,
            }),
        )?;
        let batch_id = batch.batch_id.clone();
        if self.batches.insert(batch_id.clone(), batch).is_some() {
            return Err("private l2 mvp batch already exists".to_string());
        }
        self.counters.batches = self.counters.batches.saturating_add(1);
        self.refresh();
        Ok(batch_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finalize_flow(
        &mut self,
        flow_id: &str,
        batch_id: &str,
        height: u64,
        fee_mode: FeeSponsorshipMode,
        sponsor_label: &str,
        monero_exit: &Value,
        da_publication: &Value,
    ) -> PrivateL2MvpFlowOrchestratorResult<String> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "private l2 mvp batch not found".to_string())?;
        if !batch.flow_ids.iter().any(|id| id == flow_id) {
            return Err("private l2 mvp batch does not include flow".to_string());
        }
        let user_fee_bps = if fee_mode.sponsored() {
            self.config.max_user_fee_bps.min(batch.aggregate_fee_bps)
        } else {
            batch.aggregate_fee_bps
        };
        let finality_height = height.saturating_add(self.config.exit_finality_blocks);
        let receipt = SettlementReceipt::new(
            flow_id,
            batch_id,
            height,
            fee_mode,
            user_fee_bps,
            sponsor_label,
            monero_exit,
            da_publication,
            finality_height,
        )?;
        let settlement_id = receipt.settlement_id.clone();
        if self
            .settlement_receipts
            .insert(settlement_id.clone(), receipt)
            .is_some()
        {
            return Err("private l2 mvp settlement already exists".to_string());
        }
        batch.status = FlowBatchStatus::Settled;
        let flow = self
            .flows
            .get_mut(flow_id)
            .ok_or_else(|| "private l2 mvp flow not found".to_string())?;
        flow.status = FlowStatus::Settled;
        flow.settlement_receipt_id = Some(settlement_id.clone());
        self.counters.finalized_flows = self.counters.finalized_flows.saturating_add(1);
        if fee_mode.sponsored() {
            self.counters.sponsored_settlements =
                self.counters.sponsored_settlements.saturating_add(1);
        }
        self.counters.monero_exits = self.counters.monero_exits.saturating_add(1);
        self.refresh();
        Ok(settlement_id)
    }

    pub fn run_devnet_private_flow(
        &mut self,
        label: &str,
        height: u64,
    ) -> PrivateL2MvpFlowOrchestratorResult<String> {
        self.height = height;
        let stages = full_mvp_stage_set();
        let flow = FlowIntent::new(
            label,
            height,
            "devnet-private-user",
            &json!({
                "asset": "confidential_wrapped_xmr",
                "supply_commitment": "devnet-token-supply-commitment",
                "launch_pool": "private-low-fee-token-launch",
            }),
            &json!({
                "contract": "private-defi-composer",
                "selector_commitment": "mint_swap_exit",
                "state_access": "shielded",
            }),
            &json!({
                "route": ["wrapped_xmr", "private_stable", "wrapped_xmr"],
                "venue": "private-confidential-stable-swap-pool",
                "slippage_bps": 12,
            }),
            &json!({
                "asset": "monero",
                "exit_lane": "pq-fast-exit",
                "subaddress_commitment": "devnet-exit-subaddress-commitment",
            }),
            self.config.min_privacy_set.saturating_mul(2),
            self.config.min_pq_security_bits,
            self.config.max_user_fee_bps.min(20),
            stages,
        )?;
        let flow_id = self.open_flow(flow)?;
        self.admit_flow(&flow_id)?;
        for stage in [
            FlowStageKind::Admission,
            FlowStageKind::PqAuthorization,
            FlowStageKind::ConfidentialTokenMint,
            FlowStageKind::PrivateContractCall,
            FlowStageKind::PrivateAmmSwap,
            FlowStageKind::LiquidityNetting,
            FlowStageKind::ProofAggregation,
            FlowStageKind::FeeSponsorship,
            FlowStageKind::DataAvailabilitySeal,
            FlowStageKind::MoneroExit,
        ] {
            self.append_stage(
                &flow_id,
                stage,
                &json!({
                    "flow_label": label,
                    "stage": stage.as_str(),
                    "height": height,
                    "commitment": format!("{label}-{}-commitment", stage.as_str()),
                }),
                &json!({
                    "stage": stage.as_str(),
                    "nullifier": format!("{label}-{}-nullifier", stage.as_str()),
                }),
                &json!({
                    "stage": stage.as_str(),
                    "witness": format!("{label}-{}-witness-root", stage.as_str()),
                }),
                self.config.max_user_fee_bps.min(20),
                self.config.target_latency_blocks,
                stage.default_weight(),
                &json!({
                    "pq_signature_scheme": self.config.pq_signature_scheme,
                    "pq_kem_scheme": self.config.pq_kem_scheme,
                    "security_bits": self.config.min_pq_security_bits,
                    "stage": stage.as_str(),
                }),
            )?;
        }
        let batch_id = self.select_batch(height)?;
        self.finalize_flow(
            &flow_id,
            &batch_id,
            height,
            FeeSponsorshipMode::ProofMarketRebate,
            "devnet-proof-market-sponsor",
            &json!({
                "flow_id": flow_id,
                "batch_id": batch_id,
                "monero_network": "devnet",
                "exit_commitment": "devnet-monero-exit-commitment",
            }),
            &json!({
                "flow_id": flow_id,
                "batch_id": batch_id,
                "da_lane": "pq-private-da-quorum",
                "publication_commitment": "devnet-da-publication",
            }),
        )
    }

    pub fn refresh(&mut self) {
        let flow_records = self
            .flows
            .values()
            .map(FlowIntent::public_record)
            .collect::<Vec<_>>();
        let stage_records = self
            .stage_receipts
            .values()
            .map(StageReceipt::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(FlowBatch::public_record)
            .collect::<Vec<_>>();
        let settlement_records = self
            .settlement_receipts
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: private_l2_mvp_flow_payload_root("CONFIG", &self.config.public_record()),
            flow_root: merkle_root("PRIVATE-L2-MVP-FLOW-FLOWS", &flow_records),
            stage_receipt_root: merkle_root("PRIVATE-L2-MVP-FLOW-STAGES", &stage_records),
            batch_root: merkle_root("PRIVATE-L2-MVP-FLOW-BATCHES", &batch_records),
            settlement_root: merkle_root("PRIVATE-L2-MVP-FLOW-SETTLEMENTS", &settlement_records),
            counter_root: private_l2_mvp_flow_payload_root(
                "COUNTERS",
                &self.counters.public_record(),
            ),
        };
        self.state_root =
            private_l2_mvp_flow_payload_root("STATE", &self.public_record_without_root());
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_l2_mvp_flow_orchestrator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_MVP_FLOW_ORCHESTRATOR_PROTOCOL_VERSION,
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
                "flows".to_string(),
                json!(self
                    .flows
                    .values()
                    .map(FlowIntent::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "stage_receipts".to_string(),
                json!(self
                    .stage_receipts
                    .values()
                    .map(StageReceipt::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "batches".to_string(),
                json!(self
                    .batches
                    .values()
                    .map(FlowBatch::public_record)
                    .collect::<Vec<_>>()),
            );
            object.insert(
                "settlement_receipts".to_string(),
                json!(self
                    .settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect::<Vec<_>>()),
            );
        }
        record
    }
}

pub fn full_mvp_stage_set() -> BTreeSet<FlowStageKind> {
    [
        FlowStageKind::Admission,
        FlowStageKind::PqAuthorization,
        FlowStageKind::ConfidentialTokenMint,
        FlowStageKind::PrivateContractCall,
        FlowStageKind::PrivateAmmSwap,
        FlowStageKind::LiquidityNetting,
        FlowStageKind::ProofAggregation,
        FlowStageKind::FeeSponsorship,
        FlowStageKind::DataAvailabilitySeal,
        FlowStageKind::MoneroExit,
    ]
    .into_iter()
    .collect()
}

pub fn private_l2_mvp_flow_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-MVP-FLOW-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn private_l2_mvp_flow_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-MVP-FLOW-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

pub fn flow_intent_id(
    label: &str,
    opened_height: u64,
    user_commitment: &str,
    token_commitment_root: &str,
    contract_call_root: &str,
    swap_route_root: &str,
    exit_request_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-FLOW-INTENT-ID",
        &[
            HashPart::Str(label),
            HashPart::Int(opened_height as i128),
            HashPart::Str(user_commitment),
            HashPart::Str(token_commitment_root),
            HashPart::Str(contract_call_root),
            HashPart::Str(swap_route_root),
            HashPart::Str(exit_request_root),
        ],
        32,
    )
}

pub fn stage_receipt_id(
    flow_id: &str,
    stage_kind: FlowStageKind,
    height: u64,
    commitment_root: &str,
    nullifier_root: &str,
    witness_root: &str,
    pq_attestation_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-FLOW-STAGE-RECEIPT-ID",
        &[
            HashPart::Str(flow_id),
            HashPart::Str(stage_kind.as_str()),
            HashPart::Int(height as i128),
            HashPart::Str(commitment_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(witness_root),
            HashPart::Str(pq_attestation_root),
        ],
        32,
    )
}

pub fn flow_batch_id(
    opened_height: u64,
    flow_ids: &[String],
    stage_receipt_ids: &[String],
    total_proof_weight: u64,
    aggregate_fee_bps: u64,
    batch_commitment_root: &str,
    recursive_proof_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-FLOW-BATCH-ID",
        &[
            HashPart::Int(opened_height as i128),
            HashPart::Json(&json!(flow_ids)),
            HashPart::Json(&json!(stage_receipt_ids)),
            HashPart::Int(total_proof_weight as i128),
            HashPart::Int(aggregate_fee_bps as i128),
            HashPart::Str(batch_commitment_root),
            HashPart::Str(recursive_proof_root),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    flow_id: &str,
    batch_id: &str,
    height: u64,
    fee_mode: FeeSponsorshipMode,
    user_fee_bps: u64,
    sponsor_commitment: &str,
    monero_exit_root: &str,
    da_publication_root: &str,
    finality_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-MVP-FLOW-SETTLEMENT-ID",
        &[
            HashPart::Str(flow_id),
            HashPart::Str(batch_id),
            HashPart::Int(height as i128),
            HashPart::Str(fee_mode.as_str()),
            HashPart::Int(user_fee_bps as i128),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(monero_exit_root),
            HashPart::Str(da_publication_root),
            HashPart::Int(finality_height as i128),
        ],
        32,
    )
}

pub fn root_from_record(record: &Value) -> String {
    private_l2_mvp_flow_payload_root("RECORD", record)
}

pub fn devnet() -> PrivateL2MvpFlowOrchestratorResult<State> {
    State::devnet()
}
