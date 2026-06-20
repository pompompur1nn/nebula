use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type RollupBatchOrchestratorResult<T> = Result<T, String>;

pub const ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION: &str = "nebula-rollup-batch-orchestrator-v1";
pub const ROLLUP_BATCH_ORCHESTRATOR_PQ_APPROVAL_SCHEME: &str = "ml-dsa-65-rollup-batch-approval-v1";
pub const ROLLUP_BATCH_ORCHESTRATOR_ROUTE_COMMITMENT_SCHEME: &str =
    "shake256-rollup-route-commitment-v1";
pub const ROLLUP_BATCH_ORCHESTRATOR_DEVNET_HEIGHT: u64 = 192;
pub const ROLLUP_BATCH_ORCHESTRATOR_MAX_BPS: u64 = 10_000;
pub const ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_BATCH_TTL_BLOCKS: u64 = 12;
pub const ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_PROOF_TTL_BLOCKS: u64 = 32;
pub const ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_FINALITY_TTL_BLOCKS: u64 = 96;
pub const ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_TARGET_SLOT_MS: u64 = 250;
pub const ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_MAX_BATCH_WEIGHT: u64 = 5_000_000;
pub const ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_LOW_FEE_SHARE_BPS: u64 = 6_500;
pub const ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_MIN_PROVER_CAPACITY_BPS: u64 = 7_000;
pub const ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_MIN_DA_COVERAGE_BPS: u64 = 9_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupBatchLane {
    PrivateTransfer,
    PrivateDefi,
    ContractExecution,
    MoneroBridge,
    ProofAggregation,
    LowFeeMaintenance,
    EmergencyExit,
}

impl RollupBatchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefi => "private_defi",
            Self::ContractExecution => "contract_execution",
            Self::MoneroBridge => "monero_bridge",
            Self::ProofAggregation => "proof_aggregation",
            Self::LowFeeMaintenance => "low_fee_maintenance",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyExit => 1_000,
            Self::MoneroBridge => 940,
            Self::PrivateDefi => 880,
            Self::ContractExecution => 820,
            Self::PrivateTransfer => 740,
            Self::ProofAggregation => 520,
            Self::LowFeeMaintenance => 420,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer | Self::PrivateDefi | Self::ContractExecution
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupBatchPhase {
    Intake,
    Assemble,
    Sequence,
    Execute,
    Prove,
    Anchor,
    Finalize,
    Recover,
}

impl RollupBatchPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intake => "intake",
            Self::Assemble => "assemble",
            Self::Sequence => "sequence",
            Self::Execute => "execute",
            Self::Prove => "prove",
            Self::Anchor => "anchor",
            Self::Finalize => "finalize",
            Self::Recover => "recover",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupBatchStatus {
    Planned,
    Open,
    Sealed,
    Executing,
    Proving,
    Anchoring,
    Finalized,
    Failed,
    Cancelled,
}

impl RollupBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Executing => "executing",
            Self::Proving => "proving",
            Self::Anchoring => "anchoring",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Planned
                | Self::Open
                | Self::Sealed
                | Self::Executing
                | Self::Proving
                | Self::Anchoring
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollupInputKind {
    EncryptedTransfer,
    PrivateDefiIntent,
    ContractCall,
    BridgeWithdrawal,
    FeeSponsorship,
    ProofReceipt,
    WatchtowerEvidence,
}

impl RollupInputKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptedTransfer => "encrypted_transfer",
            Self::PrivateDefiIntent => "private_defi_intent",
            Self::ContractCall => "contract_call",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::ProofReceipt => "proof_receipt",
            Self::WatchtowerEvidence => "watchtower_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataAvailabilityMode {
    FullBlob,
    ErasureCoded,
    CommitteeSampled,
    MoneroAnchoredDigest,
}

impl DataAvailabilityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullBlob => "full_blob",
            Self::ErasureCoded => "erasure_coded",
            Self::CommitteeSampled => "committee_sampled",
            Self::MoneroAnchoredDigest => "monero_anchored_digest",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityTier {
    Preconfirmed,
    SequencerFinal,
    ProofFinal,
    MoneroAnchored,
    EmergencyRecovered,
}

impl FinalityTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preconfirmed => "preconfirmed",
            Self::SequencerFinal => "sequencer_final",
            Self::ProofFinal => "proof_final",
            Self::MoneroAnchored => "monero_anchored",
            Self::EmergencyRecovered => "emergency_recovered",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrchestrationSignalKind {
    ProverCapacity,
    SequencerBackpressure,
    LowFeeBudget,
    PrivacySet,
    MoneroFinality,
    ContractPolicy,
    DefiRisk,
}

impl OrchestrationSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProverCapacity => "prover_capacity",
            Self::SequencerBackpressure => "sequencer_backpressure",
            Self::LowFeeBudget => "low_fee_budget",
            Self::PrivacySet => "privacy_set",
            Self::MoneroFinality => "monero_finality",
            Self::ContractPolicy => "contract_policy",
            Self::DefiRisk => "defi_risk",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqBatchApprovalSubject {
    AssemblyWindow,
    ExecutionBundle,
    ProverAssignment,
    MoneroSettlement,
    FinalityReceipt,
    EmergencyRecovery,
}

impl PqBatchApprovalSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AssemblyWindow => "assembly_window",
            Self::ExecutionBundle => "execution_bundle",
            Self::ProverAssignment => "prover_assignment",
            Self::MoneroSettlement => "monero_settlement",
            Self::FinalityReceipt => "finality_receipt",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqBatchApprovalStatus {
    Pending,
    Accepted,
    Revoked,
    Superseded,
    Expired,
}

impl PqBatchApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchIncidentSeverity {
    Info,
    Warning,
    Severe,
    Critical,
}

impl BatchIncidentSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Severe => "severe",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupBatchOrchestratorConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub batch_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub finality_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_slot_ms: u64,
    pub max_batch_weight: u64,
    pub low_fee_share_bps: u64,
    pub min_prover_capacity_bps: u64,
    pub min_da_coverage_bps: u64,
}

impl RollupBatchOrchestratorConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            batch_ttl_blocks: ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_BATCH_TTL_BLOCKS,
            proof_ttl_blocks: ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_PROOF_TTL_BLOCKS,
            finality_ttl_blocks: ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_FINALITY_TTL_BLOCKS,
            min_privacy_set_size: ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_slot_ms: ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_TARGET_SLOT_MS,
            max_batch_weight: ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_MAX_BATCH_WEIGHT,
            low_fee_share_bps: ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_LOW_FEE_SHARE_BPS,
            min_prover_capacity_bps: ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_MIN_PROVER_CAPACITY_BPS,
            min_da_coverage_bps: ROLLUP_BATCH_ORCHESTRATOR_DEFAULT_MIN_DA_COVERAGE_BPS,
        }
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<()> {
        if self.protocol_version != ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION {
            return Err("rollup batch orchestrator protocol version mismatch".to_string());
        }
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_positive("batch_ttl_blocks", self.batch_ttl_blocks)?;
        ensure_positive("proof_ttl_blocks", self.proof_ttl_blocks)?;
        ensure_positive("finality_ttl_blocks", self.finality_ttl_blocks)?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive("target_slot_ms", self.target_slot_ms)?;
        ensure_positive("max_batch_weight", self.max_batch_weight)?;
        ensure_bps("low_fee_share_bps", self.low_fee_share_bps)?;
        ensure_bps("min_prover_capacity_bps", self.min_prover_capacity_bps)?;
        ensure_bps("min_da_coverage_bps", self.min_da_coverage_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "finality_ttl_blocks": self.finality_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_slot_ms": self.target_slot_ms,
            "max_batch_weight": self.max_batch_weight,
            "low_fee_share_bps": self.low_fee_share_bps,
            "min_prover_capacity_bps": self.min_prover_capacity_bps,
            "min_da_coverage_bps": self.min_da_coverage_bps,
        })
    }

    pub fn config_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupBatchInput {
    pub input_id: String,
    pub lane: RollupBatchLane,
    pub kind: RollupInputKind,
    pub source_commitment: String,
    pub payload_root: String,
    pub nullifier_root: String,
    pub fee_commitment: String,
    pub privacy_set_size: u64,
    pub weight: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub pq_approval_ids: Vec<String>,
}

impl RollupBatchInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: RollupBatchLane,
        kind: RollupInputKind,
        source_commitment: &str,
        payload_root: &str,
        nullifier_root: &str,
        fee_commitment: &str,
        privacy_set_size: u64,
        weight: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        pq_approval_ids: Vec<String>,
    ) -> RollupBatchOrchestratorResult<Self> {
        let input_id = rollup_batch_input_id(
            lane,
            kind,
            source_commitment,
            payload_root,
            opened_at_height,
        );
        let input = Self {
            input_id,
            lane,
            kind,
            source_commitment: source_commitment.to_string(),
            payload_root: payload_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            fee_commitment: fee_commitment.to_string(),
            privacy_set_size,
            weight,
            opened_at_height,
            expires_at_height,
            pq_approval_ids,
        };
        input.validate()?;
        Ok(input)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "input_id": self.input_id,
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "source_commitment": self.source_commitment,
            "payload_root": self.payload_root,
            "nullifier_root": self.nullifier_root,
            "fee_commitment": self.fee_commitment,
            "privacy_set_size": self.privacy_set_size,
            "weight": self.weight,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_approval_ids": self.pq_approval_ids,
        })
    }

    pub fn input_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-INPUT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("input_id", &self.input_id)?;
        ensure_non_empty("source_commitment", &self.source_commitment)?;
        ensure_non_empty("payload_root", &self.payload_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("fee_commitment", &self.fee_commitment)?;
        ensure_positive("privacy_set_size", self.privacy_set_size)?;
        ensure_positive("weight", self.weight)?;
        ensure_height_window(self.opened_at_height, self.expires_at_height, "batch input")?;
        ensure_unique_strings(&self.pq_approval_ids, "input pq_approval_ids")?;
        Ok(self.input_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAssemblyWindow {
    pub window_id: String,
    pub lane: RollupBatchLane,
    pub status: RollupBatchStatus,
    pub phase: RollupBatchPhase,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub target_weight: u64,
    pub reserved_weight: u64,
    pub min_privacy_set_size: u64,
    pub low_fee_share_bps: u64,
    pub da_mode: DataAvailabilityMode,
    pub route_commitment_root: String,
    pub input_ids: Vec<String>,
}

impl BatchAssemblyWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: RollupBatchLane,
        opened_at_height: u64,
        closes_at_height: u64,
        target_weight: u64,
        reserved_weight: u64,
        min_privacy_set_size: u64,
        low_fee_share_bps: u64,
        da_mode: DataAvailabilityMode,
        route_commitment_root: &str,
        input_ids: Vec<String>,
    ) -> RollupBatchOrchestratorResult<Self> {
        let window_id = batch_assembly_window_id(lane, opened_at_height, route_commitment_root);
        let window = Self {
            window_id,
            lane,
            status: RollupBatchStatus::Open,
            phase: RollupBatchPhase::Assemble,
            opened_at_height,
            closes_at_height,
            target_weight,
            reserved_weight,
            min_privacy_set_size,
            low_fee_share_bps,
            da_mode,
            route_commitment_root: route_commitment_root.to_string(),
            input_ids,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "phase": self.phase.as_str(),
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "target_weight": self.target_weight,
            "reserved_weight": self.reserved_weight,
            "min_privacy_set_size": self.min_privacy_set_size,
            "low_fee_share_bps": self.low_fee_share_bps,
            "da_mode": self.da_mode.as_str(),
            "route_commitment_scheme": ROLLUP_BATCH_ORCHESTRATOR_ROUTE_COMMITMENT_SCHEME,
            "route_commitment_root": self.route_commitment_root,
            "input_ids": self.input_ids,
        })
    }

    pub fn window_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-ASSEMBLY-WINDOW",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("route_commitment_root", &self.route_commitment_root)?;
        ensure_height_window(
            self.opened_at_height,
            self.closes_at_height,
            "assembly window",
        )?;
        ensure_positive("target_weight", self.target_weight)?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_bps("low_fee_share_bps", self.low_fee_share_bps)?;
        if self.reserved_weight > self.target_weight {
            return Err("assembly window reserved weight exceeds target".to_string());
        }
        ensure_unique_strings(&self.input_ids, "assembly input_ids")?;
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerBatchCommitment {
    pub commitment_id: String,
    pub window_id: String,
    pub sequencer_commitment: String,
    pub ordered_input_root: String,
    pub preconfirmation_root: String,
    pub qos_root: String,
    pub performance_root: String,
    pub target_slot_ms: u64,
    pub observed_latency_ms: u64,
    pub backpressure_bps: u64,
    pub committed_at_height: u64,
}

impl SequencerBatchCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: &str,
        sequencer_commitment: &str,
        ordered_input_root: &str,
        preconfirmation_root: &str,
        qos_root: &str,
        performance_root: &str,
        target_slot_ms: u64,
        observed_latency_ms: u64,
        backpressure_bps: u64,
        committed_at_height: u64,
    ) -> RollupBatchOrchestratorResult<Self> {
        let commitment_id = sequencer_batch_commitment_id(
            window_id,
            sequencer_commitment,
            ordered_input_root,
            committed_at_height,
        );
        let commitment = Self {
            commitment_id,
            window_id: window_id.to_string(),
            sequencer_commitment: sequencer_commitment.to_string(),
            ordered_input_root: ordered_input_root.to_string(),
            preconfirmation_root: preconfirmation_root.to_string(),
            qos_root: qos_root.to_string(),
            performance_root: performance_root.to_string(),
            target_slot_ms,
            observed_latency_ms,
            backpressure_bps,
            committed_at_height,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "window_id": self.window_id,
            "sequencer_commitment": self.sequencer_commitment,
            "ordered_input_root": self.ordered_input_root,
            "preconfirmation_root": self.preconfirmation_root,
            "qos_root": self.qos_root,
            "performance_root": self.performance_root,
            "target_slot_ms": self.target_slot_ms,
            "observed_latency_ms": self.observed_latency_ms,
            "backpressure_bps": self.backpressure_bps,
            "committed_at_height": self.committed_at_height,
        })
    }

    pub fn commitment_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-SEQUENCER-COMMITMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("commitment_id", &self.commitment_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("sequencer_commitment", &self.sequencer_commitment)?;
        ensure_non_empty("ordered_input_root", &self.ordered_input_root)?;
        ensure_non_empty("preconfirmation_root", &self.preconfirmation_root)?;
        ensure_non_empty("qos_root", &self.qos_root)?;
        ensure_non_empty("performance_root", &self.performance_root)?;
        ensure_positive("target_slot_ms", self.target_slot_ms)?;
        ensure_bps("backpressure_bps", self.backpressure_bps)?;
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBundle {
    pub bundle_id: String,
    pub window_id: String,
    pub status: RollupBatchStatus,
    pub private_state_root_before: String,
    pub private_state_root_after: String,
    pub contract_execution_root: String,
    pub defi_settlement_root: String,
    pub token_delta_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub executed_at_height: u64,
    pub pq_approval_ids: Vec<String>,
}

impl ExecutionBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: &str,
        private_state_root_before: &str,
        private_state_root_after: &str,
        contract_execution_root: &str,
        defi_settlement_root: &str,
        token_delta_root: &str,
        nullifier_root: &str,
        witness_root: &str,
        executed_at_height: u64,
        pq_approval_ids: Vec<String>,
    ) -> RollupBatchOrchestratorResult<Self> {
        let bundle_id = execution_bundle_id(
            window_id,
            private_state_root_before,
            private_state_root_after,
            executed_at_height,
        );
        let bundle = Self {
            bundle_id,
            window_id: window_id.to_string(),
            status: RollupBatchStatus::Executing,
            private_state_root_before: private_state_root_before.to_string(),
            private_state_root_after: private_state_root_after.to_string(),
            contract_execution_root: contract_execution_root.to_string(),
            defi_settlement_root: defi_settlement_root.to_string(),
            token_delta_root: token_delta_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            witness_root: witness_root.to_string(),
            executed_at_height,
            pq_approval_ids,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "window_id": self.window_id,
            "status": self.status.as_str(),
            "private_state_root_before": self.private_state_root_before,
            "private_state_root_after": self.private_state_root_after,
            "contract_execution_root": self.contract_execution_root,
            "defi_settlement_root": self.defi_settlement_root,
            "token_delta_root": self.token_delta_root,
            "nullifier_root": self.nullifier_root,
            "witness_root": self.witness_root,
            "executed_at_height": self.executed_at_height,
            "pq_approval_ids": self.pq_approval_ids,
        })
    }

    pub fn bundle_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-EXECUTION-BUNDLE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("bundle_id", &self.bundle_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("private_state_root_before", &self.private_state_root_before)?;
        ensure_non_empty("private_state_root_after", &self.private_state_root_after)?;
        ensure_non_empty("contract_execution_root", &self.contract_execution_root)?;
        ensure_non_empty("defi_settlement_root", &self.defi_settlement_root)?;
        ensure_non_empty("token_delta_root", &self.token_delta_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_unique_strings(&self.pq_approval_ids, "execution pq_approval_ids")?;
        Ok(self.bundle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBatchAssignment {
    pub assignment_id: String,
    pub bundle_id: String,
    pub prover_commitment: String,
    pub proof_request_root: String,
    pub recursive_aggregation_root: String,
    pub verifier_key_root: String,
    pub capacity_bps: u64,
    pub fee_quote_micro_units: u64,
    pub assigned_at_height: u64,
    pub expires_at_height: u64,
    pub pq_approval_ids: Vec<String>,
}

impl ProverBatchAssignment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: &str,
        prover_commitment: &str,
        proof_request_root: &str,
        recursive_aggregation_root: &str,
        verifier_key_root: &str,
        capacity_bps: u64,
        fee_quote_micro_units: u64,
        assigned_at_height: u64,
        expires_at_height: u64,
        pq_approval_ids: Vec<String>,
    ) -> RollupBatchOrchestratorResult<Self> {
        let assignment_id = prover_batch_assignment_id(
            bundle_id,
            prover_commitment,
            proof_request_root,
            assigned_at_height,
        );
        let assignment = Self {
            assignment_id,
            bundle_id: bundle_id.to_string(),
            prover_commitment: prover_commitment.to_string(),
            proof_request_root: proof_request_root.to_string(),
            recursive_aggregation_root: recursive_aggregation_root.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            capacity_bps,
            fee_quote_micro_units,
            assigned_at_height,
            expires_at_height,
            pq_approval_ids,
        };
        assignment.validate()?;
        Ok(assignment)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "assignment_id": self.assignment_id,
            "bundle_id": self.bundle_id,
            "prover_commitment": self.prover_commitment,
            "proof_request_root": self.proof_request_root,
            "recursive_aggregation_root": self.recursive_aggregation_root,
            "verifier_key_root": self.verifier_key_root,
            "capacity_bps": self.capacity_bps,
            "fee_quote_micro_units": self.fee_quote_micro_units,
            "assigned_at_height": self.assigned_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_approval_ids": self.pq_approval_ids,
        })
    }

    pub fn assignment_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-PROVER-ASSIGNMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("assignment_id", &self.assignment_id)?;
        ensure_non_empty("bundle_id", &self.bundle_id)?;
        ensure_non_empty("prover_commitment", &self.prover_commitment)?;
        ensure_non_empty("proof_request_root", &self.proof_request_root)?;
        ensure_non_empty(
            "recursive_aggregation_root",
            &self.recursive_aggregation_root,
        )?;
        ensure_non_empty("verifier_key_root", &self.verifier_key_root)?;
        ensure_bps("capacity_bps", self.capacity_bps)?;
        ensure_positive("fee_quote_micro_units", self.fee_quote_micro_units)?;
        ensure_height_window(
            self.assigned_at_height,
            self.expires_at_height,
            "prover assignment",
        )?;
        ensure_unique_strings(&self.pq_approval_ids, "assignment pq_approval_ids")?;
        Ok(self.assignment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeBatchFundingPlan {
    pub funding_id: String,
    pub window_id: String,
    pub sponsor_market_root: String,
    pub batcher_root: String,
    pub sponsor_debit_root: String,
    pub rebate_receipt_root: String,
    pub user_fee_commitment_root: String,
    pub sponsor_share_bps: u64,
    pub available_budget_micro_units: u64,
    pub reserved_budget_micro_units: u64,
}

impl LowFeeBatchFundingPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: &str,
        sponsor_market_root: &str,
        batcher_root: &str,
        sponsor_debit_root: &str,
        rebate_receipt_root: &str,
        user_fee_commitment_root: &str,
        sponsor_share_bps: u64,
        available_budget_micro_units: u64,
        reserved_budget_micro_units: u64,
    ) -> RollupBatchOrchestratorResult<Self> {
        let funding_id = low_fee_batch_funding_plan_id(
            window_id,
            sponsor_market_root,
            sponsor_debit_root,
            sponsor_share_bps,
        );
        let plan = Self {
            funding_id,
            window_id: window_id.to_string(),
            sponsor_market_root: sponsor_market_root.to_string(),
            batcher_root: batcher_root.to_string(),
            sponsor_debit_root: sponsor_debit_root.to_string(),
            rebate_receipt_root: rebate_receipt_root.to_string(),
            user_fee_commitment_root: user_fee_commitment_root.to_string(),
            sponsor_share_bps,
            available_budget_micro_units,
            reserved_budget_micro_units,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "funding_id": self.funding_id,
            "window_id": self.window_id,
            "sponsor_market_root": self.sponsor_market_root,
            "batcher_root": self.batcher_root,
            "sponsor_debit_root": self.sponsor_debit_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "user_fee_commitment_root": self.user_fee_commitment_root,
            "sponsor_share_bps": self.sponsor_share_bps,
            "available_budget_micro_units": self.available_budget_micro_units,
            "reserved_budget_micro_units": self.reserved_budget_micro_units,
        })
    }

    pub fn funding_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-LOW-FEE-FUNDING",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("funding_id", &self.funding_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("sponsor_market_root", &self.sponsor_market_root)?;
        ensure_non_empty("batcher_root", &self.batcher_root)?;
        ensure_non_empty("sponsor_debit_root", &self.sponsor_debit_root)?;
        ensure_non_empty("rebate_receipt_root", &self.rebate_receipt_root)?;
        ensure_non_empty("user_fee_commitment_root", &self.user_fee_commitment_root)?;
        ensure_bps("sponsor_share_bps", self.sponsor_share_bps)?;
        ensure_positive(
            "available_budget_micro_units",
            self.available_budget_micro_units,
        )?;
        if self.reserved_budget_micro_units > self.available_budget_micro_units {
            return Err("reserved low-fee budget exceeds available budget".to_string());
        }
        Ok(self.funding_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBatchSettlementPlan {
    pub settlement_id: String,
    pub window_id: String,
    pub monero_network: String,
    pub bridge_adapter_root: String,
    pub reserve_monitor_root: String,
    pub watchtower_mesh_root: String,
    pub withdrawal_release_root: String,
    pub anchor_manifest_root: String,
    pub expected_anchor_height: u64,
    pub fee_bump_budget_piconero: u64,
    pub pq_approval_ids: Vec<String>,
}

impl MoneroBatchSettlementPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: &str,
        monero_network: &str,
        bridge_adapter_root: &str,
        reserve_monitor_root: &str,
        watchtower_mesh_root: &str,
        withdrawal_release_root: &str,
        anchor_manifest_root: &str,
        expected_anchor_height: u64,
        fee_bump_budget_piconero: u64,
        pq_approval_ids: Vec<String>,
    ) -> RollupBatchOrchestratorResult<Self> {
        let settlement_id = monero_batch_settlement_plan_id(
            window_id,
            monero_network,
            anchor_manifest_root,
            expected_anchor_height,
        );
        let plan = Self {
            settlement_id,
            window_id: window_id.to_string(),
            monero_network: monero_network.to_string(),
            bridge_adapter_root: bridge_adapter_root.to_string(),
            reserve_monitor_root: reserve_monitor_root.to_string(),
            watchtower_mesh_root: watchtower_mesh_root.to_string(),
            withdrawal_release_root: withdrawal_release_root.to_string(),
            anchor_manifest_root: anchor_manifest_root.to_string(),
            expected_anchor_height,
            fee_bump_budget_piconero,
            pq_approval_ids,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "window_id": self.window_id,
            "monero_network": self.monero_network,
            "bridge_adapter_root": self.bridge_adapter_root,
            "reserve_monitor_root": self.reserve_monitor_root,
            "watchtower_mesh_root": self.watchtower_mesh_root,
            "withdrawal_release_root": self.withdrawal_release_root,
            "anchor_manifest_root": self.anchor_manifest_root,
            "expected_anchor_height": self.expected_anchor_height,
            "fee_bump_budget_piconero": self.fee_bump_budget_piconero,
            "pq_approval_ids": self.pq_approval_ids,
        })
    }

    pub fn settlement_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-MONERO-SETTLEMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("settlement_id", &self.settlement_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("monero_network", &self.monero_network)?;
        ensure_non_empty("bridge_adapter_root", &self.bridge_adapter_root)?;
        ensure_non_empty("reserve_monitor_root", &self.reserve_monitor_root)?;
        ensure_non_empty("watchtower_mesh_root", &self.watchtower_mesh_root)?;
        ensure_non_empty("withdrawal_release_root", &self.withdrawal_release_root)?;
        ensure_non_empty("anchor_manifest_root", &self.anchor_manifest_root)?;
        ensure_positive("expected_anchor_height", self.expected_anchor_height)?;
        ensure_unique_strings(&self.pq_approval_ids, "settlement pq_approval_ids")?;
        Ok(self.settlement_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqBatchApproval {
    pub approval_id: String,
    pub subject: PqBatchApprovalSubject,
    pub subject_id: String,
    pub subject_root: String,
    pub status: PqBatchApprovalStatus,
    pub signer_commitment: String,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
}

impl PqBatchApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: PqBatchApprovalSubject,
        subject_id: &str,
        subject_root: &str,
        signer_commitment: &str,
        public_key_commitment: &str,
        signature_root: &str,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> RollupBatchOrchestratorResult<Self> {
        let approval_id = pq_batch_approval_id(
            subject,
            subject_id,
            subject_root,
            signer_commitment,
            signed_at_height,
        );
        let approval = Self {
            approval_id,
            subject,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            status: PqBatchApprovalStatus::Accepted,
            signer_commitment: signer_commitment.to_string(),
            public_key_commitment: public_key_commitment.to_string(),
            signature_root: signature_root.to_string(),
            signed_at_height,
            expires_at_height,
        };
        approval.validate()?;
        Ok(approval)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "subject": self.subject.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "status": self.status.as_str(),
            "scheme": ROLLUP_BATCH_ORCHESTRATOR_PQ_APPROVAL_SCHEME,
            "signer_commitment": self.signer_commitment,
            "public_key_commitment": self.public_key_commitment,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn approval_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-PQ-APPROVAL",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("approval_id", &self.approval_id)?;
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("subject_root", &self.subject_root)?;
        ensure_non_empty("signer_commitment", &self.signer_commitment)?;
        ensure_non_empty("public_key_commitment", &self.public_key_commitment)?;
        ensure_non_empty("signature_root", &self.signature_root)?;
        ensure_height_window(
            self.signed_at_height,
            self.expires_at_height,
            "pq batch approval",
        )?;
        Ok(self.approval_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFinalityReceipt {
    pub receipt_id: String,
    pub window_id: String,
    pub finality_tier: FinalityTier,
    pub batch_state_root: String,
    pub proof_root: String,
    pub da_root: String,
    pub monero_anchor_root: String,
    pub finalized_at_height: u64,
    pub expires_at_height: u64,
    pub pq_approval_ids: Vec<String>,
}

impl BatchFinalityReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: &str,
        finality_tier: FinalityTier,
        batch_state_root: &str,
        proof_root: &str,
        da_root: &str,
        monero_anchor_root: &str,
        finalized_at_height: u64,
        expires_at_height: u64,
        pq_approval_ids: Vec<String>,
    ) -> RollupBatchOrchestratorResult<Self> {
        let receipt_id = batch_finality_receipt_id(
            window_id,
            finality_tier,
            batch_state_root,
            finalized_at_height,
        );
        let receipt = Self {
            receipt_id,
            window_id: window_id.to_string(),
            finality_tier,
            batch_state_root: batch_state_root.to_string(),
            proof_root: proof_root.to_string(),
            da_root: da_root.to_string(),
            monero_anchor_root: monero_anchor_root.to_string(),
            finalized_at_height,
            expires_at_height,
            pq_approval_ids,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "window_id": self.window_id,
            "finality_tier": self.finality_tier.as_str(),
            "batch_state_root": self.batch_state_root,
            "proof_root": self.proof_root,
            "da_root": self.da_root,
            "monero_anchor_root": self.monero_anchor_root,
            "finalized_at_height": self.finalized_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_approval_ids": self.pq_approval_ids,
        })
    }

    pub fn receipt_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-FINALITY-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("receipt_id", &self.receipt_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("batch_state_root", &self.batch_state_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("da_root", &self.da_root)?;
        ensure_non_empty("monero_anchor_root", &self.monero_anchor_root)?;
        ensure_height_window(
            self.finalized_at_height,
            self.expires_at_height,
            "finality receipt",
        )?;
        ensure_unique_strings(&self.pq_approval_ids, "finality pq_approval_ids")?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestrationSignal {
    pub signal_id: String,
    pub kind: OrchestrationSignalKind,
    pub source_root: String,
    pub severity: BatchIncidentSeverity,
    pub measured_bps: u64,
    pub threshold_bps: u64,
    pub opened_at_height: u64,
    pub acknowledged: bool,
}

impl OrchestrationSignal {
    pub fn new(
        kind: OrchestrationSignalKind,
        source_root: &str,
        severity: BatchIncidentSeverity,
        measured_bps: u64,
        threshold_bps: u64,
        opened_at_height: u64,
        acknowledged: bool,
    ) -> RollupBatchOrchestratorResult<Self> {
        let signal_id = orchestration_signal_id(kind, source_root, opened_at_height);
        let signal = Self {
            signal_id,
            kind,
            source_root: source_root.to_string(),
            severity,
            measured_bps,
            threshold_bps,
            opened_at_height,
            acknowledged,
        };
        signal.validate()?;
        Ok(signal)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "kind": self.kind.as_str(),
            "source_root": self.source_root,
            "severity": self.severity.as_str(),
            "measured_bps": self.measured_bps,
            "threshold_bps": self.threshold_bps,
            "opened_at_height": self.opened_at_height,
            "acknowledged": self.acknowledged,
        })
    }

    pub fn signal_root(&self) -> String {
        rollup_batch_orchestrator_payload_root(
            "ROLLUP-BATCH-ORCHESTRATOR-SIGNAL",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        ensure_non_empty("signal_id", &self.signal_id)?;
        ensure_non_empty("source_root", &self.source_root)?;
        ensure_bps("measured_bps", self.measured_bps)?;
        ensure_bps("threshold_bps", self.threshold_bps)?;
        Ok(self.signal_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupBatchOrchestratorRoots {
    pub config_root: String,
    pub input_root: String,
    pub assembly_window_root: String,
    pub sequencer_commitment_root: String,
    pub execution_bundle_root: String,
    pub prover_assignment_root: String,
    pub low_fee_funding_root: String,
    pub monero_settlement_root: String,
    pub pq_approval_root: String,
    pub finality_receipt_root: String,
    pub signal_root: String,
}

impl RollupBatchOrchestratorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "input_root": self.input_root,
            "assembly_window_root": self.assembly_window_root,
            "sequencer_commitment_root": self.sequencer_commitment_root,
            "execution_bundle_root": self.execution_bundle_root,
            "prover_assignment_root": self.prover_assignment_root,
            "low_fee_funding_root": self.low_fee_funding_root,
            "monero_settlement_root": self.monero_settlement_root,
            "pq_approval_root": self.pq_approval_root,
            "finality_receipt_root": self.finality_receipt_root,
            "signal_root": self.signal_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupBatchOrchestratorCounters {
    pub input_count: u64,
    pub live_input_count: u64,
    pub assembly_window_count: u64,
    pub live_assembly_window_count: u64,
    pub sequencer_commitment_count: u64,
    pub execution_bundle_count: u64,
    pub prover_assignment_count: u64,
    pub low_fee_funding_count: u64,
    pub monero_settlement_count: u64,
    pub pq_approval_count: u64,
    pub usable_pq_approval_count: u64,
    pub finality_receipt_count: u64,
    pub signal_count: u64,
    pub open_signal_count: u64,
    pub total_pending_weight: u64,
}

impl RollupBatchOrchestratorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "input_count": self.input_count,
            "live_input_count": self.live_input_count,
            "assembly_window_count": self.assembly_window_count,
            "live_assembly_window_count": self.live_assembly_window_count,
            "sequencer_commitment_count": self.sequencer_commitment_count,
            "execution_bundle_count": self.execution_bundle_count,
            "prover_assignment_count": self.prover_assignment_count,
            "low_fee_funding_count": self.low_fee_funding_count,
            "monero_settlement_count": self.monero_settlement_count,
            "pq_approval_count": self.pq_approval_count,
            "usable_pq_approval_count": self.usable_pq_approval_count,
            "finality_receipt_count": self.finality_receipt_count,
            "signal_count": self.signal_count,
            "open_signal_count": self.open_signal_count,
            "total_pending_weight": self.total_pending_weight,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupBatchOrchestratorState {
    pub config: RollupBatchOrchestratorConfig,
    pub height: u64,
    pub inputs: BTreeMap<String, RollupBatchInput>,
    pub assembly_windows: BTreeMap<String, BatchAssemblyWindow>,
    pub sequencer_commitments: BTreeMap<String, SequencerBatchCommitment>,
    pub execution_bundles: BTreeMap<String, ExecutionBundle>,
    pub prover_assignments: BTreeMap<String, ProverBatchAssignment>,
    pub low_fee_funding_plans: BTreeMap<String, LowFeeBatchFundingPlan>,
    pub monero_settlement_plans: BTreeMap<String, MoneroBatchSettlementPlan>,
    pub pq_approvals: BTreeMap<String, PqBatchApproval>,
    pub finality_receipts: BTreeMap<String, BatchFinalityReceipt>,
    pub signals: BTreeMap<String, OrchestrationSignal>,
}

impl RollupBatchOrchestratorState {
    pub fn new(config: RollupBatchOrchestratorConfig) -> RollupBatchOrchestratorResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            inputs: BTreeMap::new(),
            assembly_windows: BTreeMap::new(),
            sequencer_commitments: BTreeMap::new(),
            execution_bundles: BTreeMap::new(),
            prover_assignments: BTreeMap::new(),
            low_fee_funding_plans: BTreeMap::new(),
            monero_settlement_plans: BTreeMap::new(),
            pq_approvals: BTreeMap::new(),
            finality_receipts: BTreeMap::new(),
            signals: BTreeMap::new(),
        })
    }

    pub fn devnet() -> RollupBatchOrchestratorResult<Self> {
        let mut state = Self::new(RollupBatchOrchestratorConfig::devnet())?;
        state.height = ROLLUP_BATCH_ORCHESTRATOR_DEVNET_HEIGHT;

        let defi_input = RollupBatchInput::new(
            RollupBatchLane::PrivateDefi,
            RollupInputKind::PrivateDefiIntent,
            "source:devnet-private-defi-composer",
            "payload-root:devnet-private-defi-intent",
            "nullifier-root:devnet-private-defi-intent",
            "fee-commitment:devnet-private-defi-intent",
            state.config.min_privacy_set_size,
            120_000,
            state.height,
            state.height + state.config.batch_ttl_blocks,
            Vec::new(),
        )?;
        let defi_input_id = defi_input.input_id.clone();
        state.insert_input(defi_input)?;

        let contract_input = RollupBatchInput::new(
            RollupBatchLane::ContractExecution,
            RollupInputKind::ContractCall,
            "source:devnet-contract-execution-policy",
            "payload-root:devnet-contract-call",
            "nullifier-root:devnet-contract-call",
            "fee-commitment:devnet-contract-call",
            state.config.min_privacy_set_size,
            80_000,
            state.height,
            state.height + state.config.batch_ttl_blocks,
            Vec::new(),
        )?;
        let contract_input_id = contract_input.input_id.clone();
        state.insert_input(contract_input)?;

        let ordered_input_root = rollup_batch_orchestrator_string_set_root(
            "ROLLUP-BATCH-ORCHESTRATOR-DEVNET-ORDERED-INPUTS",
            &[defi_input_id.clone(), contract_input_id.clone()],
        );
        let window = BatchAssemblyWindow::new(
            RollupBatchLane::PrivateDefi,
            state.height,
            state.height + state.config.batch_ttl_blocks,
            1_000_000,
            200_000,
            state.config.min_privacy_set_size,
            state.config.low_fee_share_bps,
            DataAvailabilityMode::ErasureCoded,
            "route-commitment-root:devnet-rollup-batch",
            vec![defi_input_id, contract_input_id],
        )?;
        let window_id = window.window_id.clone();
        state.insert_assembly_window(window)?;

        let sequencer_commitment = SequencerBatchCommitment::new(
            &window_id,
            "sequencer-commitment:devnet-rollup-batch",
            &ordered_input_root,
            "preconfirmation-root:devnet-rollup-batch",
            "sequencer-qos-root:devnet-rollup-batch",
            "sequencer-performance-root:devnet-rollup-batch",
            state.config.target_slot_ms,
            190,
            2_100,
            state.height,
        )?;
        state.insert_sequencer_commitment(sequencer_commitment)?;

        let execution_bundle = ExecutionBundle::new(
            &window_id,
            "private-state-root-before:devnet-rollup-batch",
            "private-state-root-after:devnet-rollup-batch",
            "contract-execution-root:devnet-rollup-batch",
            "defi-settlement-root:devnet-rollup-batch",
            "token-delta-root:devnet-rollup-batch",
            "nullifier-root:devnet-rollup-batch",
            "witness-root:devnet-rollup-batch",
            state.height + 1,
            Vec::new(),
        )?;
        let bundle_id = execution_bundle.bundle_id.clone();
        let bundle_root = execution_bundle.bundle_root();
        state.insert_execution_bundle(execution_bundle)?;

        let assignment = ProverBatchAssignment::new(
            &bundle_id,
            "prover-commitment:devnet-rollup-batch",
            "proof-request-root:devnet-rollup-batch",
            "recursive-aggregation-root:devnet-rollup-batch",
            "verifier-key-root:devnet-rollup-batch",
            8_600,
            90_000,
            state.height + 1,
            state.height + state.config.proof_ttl_blocks,
            Vec::new(),
        )?;
        state.insert_prover_assignment(assignment)?;

        let funding = LowFeeBatchFundingPlan::new(
            &window_id,
            "low-fee-sponsor-market-root:devnet-rollup-batch",
            "low-fee-batcher-root:devnet-rollup-batch",
            "sponsor-debit-root:devnet-rollup-batch",
            "rebate-receipt-root:devnet-rollup-batch",
            "user-fee-commitment-root:devnet-rollup-batch",
            state.config.low_fee_share_bps,
            800_000_000,
            120_000,
        )?;
        state.insert_low_fee_funding_plan(funding)?;

        let settlement = MoneroBatchSettlementPlan::new(
            &window_id,
            "stagenet",
            "monero-settlement-adapter-root:devnet-rollup-batch",
            "monero-reserve-monitor-root:devnet-rollup-batch",
            "monero-watchtower-mesh-root:devnet-rollup-batch",
            "withdrawal-release-root:devnet-rollup-batch",
            "anchor-manifest-root:devnet-rollup-batch",
            state.height + 8,
            40_000_000,
            Vec::new(),
        )?;
        state.insert_monero_settlement_plan(settlement)?;

        let approval = PqBatchApproval::new(
            PqBatchApprovalSubject::ExecutionBundle,
            &bundle_id,
            &bundle_root,
            "pq-signer:devnet-rollup-batch",
            "ml-dsa-public-key-commitment:devnet-rollup-batch",
            "ml-dsa-signature-root:devnet-rollup-batch",
            state.height,
            state.height + state.config.finality_ttl_blocks,
        )?;
        let approval_id = approval.approval_id.clone();
        state.insert_pq_approval(approval)?;

        let finality = BatchFinalityReceipt::new(
            &window_id,
            FinalityTier::ProofFinal,
            "batch-state-root:devnet-rollup-batch",
            "proof-root:devnet-rollup-batch",
            "da-root:devnet-rollup-batch",
            "monero-anchor-root:devnet-rollup-batch",
            state.height + 4,
            state.height + state.config.finality_ttl_blocks,
            vec![approval_id],
        )?;
        state.insert_finality_receipt(finality)?;

        let signal = OrchestrationSignal::new(
            OrchestrationSignalKind::ProverCapacity,
            "prover-backend-orchestrator-root:devnet-rollup-batch",
            BatchIncidentSeverity::Info,
            8_600,
            state.config.min_prover_capacity_bps,
            state.height,
            true,
        )?;
        state.insert_signal(signal)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> RollupBatchOrchestratorResult<String> {
        if height < self.height {
            return Err("rollup batch orchestrator height cannot move backwards".to_string());
        }
        self.height = height;
        for approval in self.pq_approvals.values_mut() {
            if approval.status.usable() && approval.expires_at_height < height {
                approval.status = PqBatchApprovalStatus::Expired;
            }
        }
        for window in self.assembly_windows.values_mut() {
            if window.status.live() && window.closes_at_height < height {
                window.status = RollupBatchStatus::Sealed;
                window.phase = RollupBatchPhase::Sequence;
            }
        }
        self.validate()
    }

    pub fn insert_input(
        &mut self,
        input: RollupBatchInput,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = input.validate()?;
        if input.weight > self.config.max_batch_weight {
            return Err("input weight exceeds max batch weight".to_string());
        }
        if input.lane.privacy_sensitive()
            && input.privacy_set_size < self.config.min_privacy_set_size
        {
            return Err("input privacy set below configured minimum".to_string());
        }
        self.inputs.insert(input.input_id.clone(), input);
        Ok(root)
    }

    pub fn insert_assembly_window(
        &mut self,
        window: BatchAssemblyWindow,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = window.validate()?;
        if window.target_weight > self.config.max_batch_weight {
            return Err("assembly window target weight exceeds configured maximum".to_string());
        }
        self.assembly_windows
            .insert(window.window_id.clone(), window);
        Ok(root)
    }

    pub fn insert_sequencer_commitment(
        &mut self,
        commitment: SequencerBatchCommitment,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = commitment.validate()?;
        self.sequencer_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(root)
    }

    pub fn insert_execution_bundle(
        &mut self,
        bundle: ExecutionBundle,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = bundle.validate()?;
        self.execution_bundles
            .insert(bundle.bundle_id.clone(), bundle);
        Ok(root)
    }

    pub fn insert_prover_assignment(
        &mut self,
        assignment: ProverBatchAssignment,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = assignment.validate()?;
        if assignment.capacity_bps < self.config.min_prover_capacity_bps {
            return Err("prover assignment below configured capacity minimum".to_string());
        }
        self.prover_assignments
            .insert(assignment.assignment_id.clone(), assignment);
        Ok(root)
    }

    pub fn insert_low_fee_funding_plan(
        &mut self,
        plan: LowFeeBatchFundingPlan,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = plan.validate()?;
        self.low_fee_funding_plans
            .insert(plan.funding_id.clone(), plan);
        Ok(root)
    }

    pub fn insert_monero_settlement_plan(
        &mut self,
        plan: MoneroBatchSettlementPlan,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = plan.validate()?;
        self.monero_settlement_plans
            .insert(plan.settlement_id.clone(), plan);
        Ok(root)
    }

    pub fn insert_pq_approval(
        &mut self,
        approval: PqBatchApproval,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = approval.validate()?;
        self.pq_approvals
            .insert(approval.approval_id.clone(), approval);
        Ok(root)
    }

    pub fn insert_finality_receipt(
        &mut self,
        receipt: BatchFinalityReceipt,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = receipt.validate()?;
        self.finality_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn insert_signal(
        &mut self,
        signal: OrchestrationSignal,
    ) -> RollupBatchOrchestratorResult<String> {
        let root = signal.validate()?;
        self.signals.insert(signal.signal_id.clone(), signal);
        Ok(root)
    }

    pub fn live_window_ids(&self) -> Vec<String> {
        self.assembly_windows
            .values()
            .filter(|window| window.status.live())
            .map(|window| window.window_id.clone())
            .collect()
    }

    pub fn open_signal_ids(&self) -> Vec<String> {
        self.signals
            .values()
            .filter(|signal| !signal.acknowledged)
            .map(|signal| signal.signal_id.clone())
            .collect()
    }

    pub fn total_pending_weight(&self) -> u64 {
        self.inputs.values().map(|input| input.weight).sum()
    }

    pub fn input_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-INPUT-COLLECTION",
            &self
                .inputs
                .values()
                .map(RollupBatchInput::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn assembly_window_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-ASSEMBLY-WINDOW-COLLECTION",
            &self
                .assembly_windows
                .values()
                .map(BatchAssemblyWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sequencer_commitment_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-SEQUENCER-COMMITMENT-COLLECTION",
            &self
                .sequencer_commitments
                .values()
                .map(SequencerBatchCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn execution_bundle_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-EXECUTION-BUNDLE-COLLECTION",
            &self
                .execution_bundles
                .values()
                .map(ExecutionBundle::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn prover_assignment_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-PROVER-ASSIGNMENT-COLLECTION",
            &self
                .prover_assignments
                .values()
                .map(ProverBatchAssignment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_funding_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-LOW-FEE-FUNDING-COLLECTION",
            &self
                .low_fee_funding_plans
                .values()
                .map(LowFeeBatchFundingPlan::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn monero_settlement_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-MONERO-SETTLEMENT-COLLECTION",
            &self
                .monero_settlement_plans
                .values()
                .map(MoneroBatchSettlementPlan::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_approval_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-PQ-APPROVAL-COLLECTION",
            &self
                .pq_approvals
                .values()
                .map(PqBatchApproval::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn finality_receipt_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-FINALITY-RECEIPT-COLLECTION",
            &self
                .finality_receipts
                .values()
                .map(BatchFinalityReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn signal_root(&self) -> String {
        rollup_batch_orchestrator_collection_root(
            "ROLLUP-BATCH-ORCHESTRATOR-SIGNAL-COLLECTION",
            &self
                .signals
                .values()
                .map(OrchestrationSignal::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> RollupBatchOrchestratorRoots {
        RollupBatchOrchestratorRoots {
            config_root: self.config.config_root(),
            input_root: self.input_root(),
            assembly_window_root: self.assembly_window_root(),
            sequencer_commitment_root: self.sequencer_commitment_root(),
            execution_bundle_root: self.execution_bundle_root(),
            prover_assignment_root: self.prover_assignment_root(),
            low_fee_funding_root: self.low_fee_funding_root(),
            monero_settlement_root: self.monero_settlement_root(),
            pq_approval_root: self.pq_approval_root(),
            finality_receipt_root: self.finality_receipt_root(),
            signal_root: self.signal_root(),
        }
    }

    pub fn counters(&self) -> RollupBatchOrchestratorCounters {
        RollupBatchOrchestratorCounters {
            input_count: self.inputs.len() as u64,
            live_input_count: self
                .inputs
                .values()
                .filter(|input| input.expires_at_height >= self.height)
                .count() as u64,
            assembly_window_count: self.assembly_windows.len() as u64,
            live_assembly_window_count: self
                .assembly_windows
                .values()
                .filter(|window| window.status.live())
                .count() as u64,
            sequencer_commitment_count: self.sequencer_commitments.len() as u64,
            execution_bundle_count: self.execution_bundles.len() as u64,
            prover_assignment_count: self.prover_assignments.len() as u64,
            low_fee_funding_count: self.low_fee_funding_plans.len() as u64,
            monero_settlement_count: self.monero_settlement_plans.len() as u64,
            pq_approval_count: self.pq_approvals.len() as u64,
            usable_pq_approval_count: self
                .pq_approvals
                .values()
                .filter(|approval| approval.status.usable())
                .count() as u64,
            finality_receipt_count: self.finality_receipts.len() as u64,
            signal_count: self.signals.len() as u64,
            open_signal_count: self
                .signals
                .values()
                .filter(|signal| !signal.acknowledged)
                .count() as u64,
            total_pending_weight: self.total_pending_weight(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_window_ids": self.live_window_ids(),
            "open_signal_ids": self.open_signal_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        rollup_batch_orchestrator_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> RollupBatchOrchestratorResult<String> {
        self.config.validate()?;
        let mut nullifiers = BTreeSet::new();
        for input in self.inputs.values() {
            input.validate()?;
            if input.weight > self.config.max_batch_weight {
                return Err(format!("input {} exceeds max batch weight", input.input_id));
            }
            if !nullifiers.insert(input.nullifier_root.clone()) {
                return Err("duplicate rollup input nullifier root".to_string());
            }
        }
        for window in self.assembly_windows.values() {
            window.validate()?;
            for input_id in &window.input_ids {
                if !self.inputs.contains_key(input_id) {
                    return Err(format!(
                        "window {} references missing input",
                        window.window_id
                    ));
                }
            }
        }
        for commitment in self.sequencer_commitments.values() {
            commitment.validate()?;
            if !self.assembly_windows.contains_key(&commitment.window_id) {
                return Err(format!(
                    "sequencer commitment {} references missing window",
                    commitment.commitment_id
                ));
            }
        }
        for bundle in self.execution_bundles.values() {
            bundle.validate()?;
            if !self.assembly_windows.contains_key(&bundle.window_id) {
                return Err(format!(
                    "bundle {} references missing window",
                    bundle.bundle_id
                ));
            }
        }
        for assignment in self.prover_assignments.values() {
            assignment.validate()?;
            if !self.execution_bundles.contains_key(&assignment.bundle_id) {
                return Err(format!(
                    "prover assignment {} references missing bundle",
                    assignment.assignment_id
                ));
            }
        }
        for funding in self.low_fee_funding_plans.values() {
            funding.validate()?;
            if !self.assembly_windows.contains_key(&funding.window_id) {
                return Err(format!(
                    "funding {} references missing window",
                    funding.funding_id
                ));
            }
        }
        for settlement in self.monero_settlement_plans.values() {
            settlement.validate()?;
            if !self.assembly_windows.contains_key(&settlement.window_id) {
                return Err(format!(
                    "settlement {} references missing window",
                    settlement.settlement_id
                ));
            }
        }
        for approval in self.pq_approvals.values() {
            approval.validate()?;
        }
        for receipt in self.finality_receipts.values() {
            receipt.validate()?;
            if !self.assembly_windows.contains_key(&receipt.window_id) {
                return Err(format!(
                    "receipt {} references missing window",
                    receipt.receipt_id
                ));
            }
        }
        for signal in self.signals.values() {
            signal.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn rollup_batch_orchestrator_state_root_from_record(record: &Value) -> String {
    rollup_batch_orchestrator_payload_root("ROLLUP-BATCH-ORCHESTRATOR-STATE-ROOT", record)
}

pub fn rollup_batch_orchestrator_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn rollup_batch_orchestrator_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn rollup_batch_orchestrator_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn rollup_batch_orchestrator_collection_root(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn rollup_batch_input_id(
    lane: RollupBatchLane,
    kind: RollupInputKind,
    source_commitment: &str,
    payload_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-INPUT-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_commitment),
            HashPart::Str(payload_root),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

pub fn batch_assembly_window_id(
    lane: RollupBatchLane,
    opened_at_height: u64,
    route_commitment_root: &str,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-ASSEMBLY-WINDOW-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(route_commitment_root),
        ],
        16,
    )
}

pub fn sequencer_batch_commitment_id(
    window_id: &str,
    sequencer_commitment: &str,
    ordered_input_root: &str,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-SEQUENCER-COMMITMENT-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(sequencer_commitment),
            HashPart::Str(ordered_input_root),
            HashPart::Int(committed_at_height as i128),
        ],
        16,
    )
}

pub fn execution_bundle_id(
    window_id: &str,
    private_state_root_before: &str,
    private_state_root_after: &str,
    executed_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-EXECUTION-BUNDLE-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(private_state_root_before),
            HashPart::Str(private_state_root_after),
            HashPart::Int(executed_at_height as i128),
        ],
        16,
    )
}

pub fn prover_batch_assignment_id(
    bundle_id: &str,
    prover_commitment: &str,
    proof_request_root: &str,
    assigned_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-PROVER-ASSIGNMENT-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(bundle_id),
            HashPart::Str(prover_commitment),
            HashPart::Str(proof_request_root),
            HashPart::Int(assigned_at_height as i128),
        ],
        16,
    )
}

pub fn low_fee_batch_funding_plan_id(
    window_id: &str,
    sponsor_market_root: &str,
    sponsor_debit_root: &str,
    sponsor_share_bps: u64,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-LOW-FEE-FUNDING-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(sponsor_market_root),
            HashPart::Str(sponsor_debit_root),
            HashPart::Int(sponsor_share_bps as i128),
        ],
        16,
    )
}

pub fn monero_batch_settlement_plan_id(
    window_id: &str,
    monero_network: &str,
    anchor_manifest_root: &str,
    expected_anchor_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-MONERO-SETTLEMENT-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(monero_network),
            HashPart::Str(anchor_manifest_root),
            HashPart::Int(expected_anchor_height as i128),
        ],
        16,
    )
}

pub fn pq_batch_approval_id(
    subject: PqBatchApprovalSubject,
    subject_id: &str,
    subject_root: &str,
    signer_commitment: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-PQ-APPROVAL-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(subject.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signer_commitment),
            HashPart::Int(signed_at_height as i128),
        ],
        16,
    )
}

pub fn batch_finality_receipt_id(
    window_id: &str,
    finality_tier: FinalityTier,
    batch_state_root: &str,
    finalized_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-FINALITY-RECEIPT-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(finality_tier.as_str()),
            HashPart::Str(batch_state_root),
            HashPart::Int(finalized_at_height as i128),
        ],
        16,
    )
}

pub fn orchestration_signal_id(
    kind: OrchestrationSignalKind,
    source_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "ROLLUP-BATCH-ORCHESTRATOR-SIGNAL-ID",
        &[
            HashPart::Str(ROLLUP_BATCH_ORCHESTRATOR_PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_root),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

fn ensure_non_empty(label: &str, value: &str) -> RollupBatchOrchestratorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> RollupBatchOrchestratorResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> RollupBatchOrchestratorResult<()> {
    if value > ROLLUP_BATCH_ORCHESTRATOR_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> RollupBatchOrchestratorResult<()> {
    if end < start {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}

fn ensure_unique_strings(values: &[String], label: &str) -> RollupBatchOrchestratorResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
