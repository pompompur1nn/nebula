use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type TransactionLifecycleCoordinatorResult<T> = Result<T, String>;

pub const TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION: &str =
    "nebula-transaction-lifecycle-coordinator-v1";
pub const TRANSACTION_LIFECYCLE_PQ_APPROVAL_SCHEME: &str =
    "ml-dsa-65-transaction-lifecycle-approval-v1";
pub const TRANSACTION_LIFECYCLE_COMMITMENT_SCHEME: &str =
    "shake256-transaction-lifecycle-commitment-v1";
pub const TRANSACTION_LIFECYCLE_DEVNET_HEIGHT: u64 = 224;
pub const TRANSACTION_LIFECYCLE_MAX_BPS: u64 = 10_000;
pub const TRANSACTION_LIFECYCLE_DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const TRANSACTION_LIFECYCLE_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 128;
pub const TRANSACTION_LIFECYCLE_DEFAULT_STATUS_TTL_BLOCKS: u64 = 96;
pub const TRANSACTION_LIFECYCLE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const TRANSACTION_LIFECYCLE_DEFAULT_LOW_FEE_TARGET_BPS: u64 = 6_500;
pub const TRANSACTION_LIFECYCLE_DEFAULT_MAX_LATENCY_MS: u64 = 1_000;
pub const TRANSACTION_LIFECYCLE_DEFAULT_MIN_PQ_APPROVALS: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleTransactionKind {
    PrivateTransfer,
    PrivateDefiSwap,
    ContractCall,
    PrivateTokenMint,
    LendingAction,
    BridgeDeposit,
    BridgeWithdrawal,
    WalletMaintenance,
}

impl LifecycleTransactionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefiSwap => "private_defi_swap",
            Self::ContractCall => "contract_call",
            Self::PrivateTokenMint => "private_token_mint",
            Self::LendingAction => "lending_action",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::WalletMaintenance => "wallet_maintenance",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer
                | Self::PrivateDefiSwap
                | Self::ContractCall
                | Self::PrivateTokenMint
                | Self::LendingAction
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    Planned,
    Signed,
    Admitted,
    Sequenced,
    Executed,
    Proved,
    Settled,
    Finalized,
    Failed,
    Cancelled,
}

impl LifecycleStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Signed => "signed",
            Self::Admitted => "admitted",
            Self::Sequenced => "sequenced",
            Self::Executed => "executed",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePrivacyMode {
    PublicMetadata,
    CommitmentsOnly,
    EncryptedMetadata,
    StealthRoute,
}

impl LifecyclePrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicMetadata => "public_metadata",
            Self::CommitmentsOnly => "commitments_only",
            Self::EncryptedMetadata => "encrypted_metadata",
            Self::StealthRoute => "stealth_route",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleFeeMode {
    UserPaid,
    SponsorAssisted,
    FullySponsored,
    RebateSettled,
}

impl LifecycleFeeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPaid => "user_paid",
            Self::SponsorAssisted => "sponsor_assisted",
            Self::FullySponsored => "fully_sponsored",
            Self::RebateSettled => "rebate_settled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleRouteSurface {
    WalletPlanner,
    ThresholdMempool,
    SequencerFastLane,
    PrivateDefiComposer,
    ContractExecutionPolicy,
    RollupBatchOrchestrator,
    MoneroSettlementAdapter,
}

impl LifecycleRouteSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletPlanner => "wallet_planner",
            Self::ThresholdMempool => "threshold_mempool",
            Self::SequencerFastLane => "sequencer_fast_lane",
            Self::PrivateDefiComposer => "private_defi_composer",
            Self::ContractExecutionPolicy => "contract_execution_policy",
            Self::RollupBatchOrchestrator => "rollup_batch_orchestrator",
            Self::MoneroSettlementAdapter => "monero_settlement_adapter",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleApprovalSubject {
    WalletPlan,
    MempoolAdmission,
    SequencerCommitment,
    ExecutionReceipt,
    ProofReceipt,
    SettlementReceipt,
    StatusProjection,
}

impl LifecycleApprovalSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletPlan => "wallet_plan",
            Self::MempoolAdmission => "mempool_admission",
            Self::SequencerCommitment => "sequencer_commitment",
            Self::ExecutionReceipt => "execution_receipt",
            Self::ProofReceipt => "proof_receipt",
            Self::SettlementReceipt => "settlement_receipt",
            Self::StatusProjection => "status_projection",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleApprovalStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
}

impl LifecycleApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionLifecycleCoordinatorConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub intent_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub status_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub low_fee_target_bps: u64,
    pub max_latency_ms: u64,
    pub min_pq_approvals: u64,
}

impl TransactionLifecycleCoordinatorConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            intent_ttl_blocks: TRANSACTION_LIFECYCLE_DEFAULT_INTENT_TTL_BLOCKS,
            receipt_ttl_blocks: TRANSACTION_LIFECYCLE_DEFAULT_RECEIPT_TTL_BLOCKS,
            status_ttl_blocks: TRANSACTION_LIFECYCLE_DEFAULT_STATUS_TTL_BLOCKS,
            min_privacy_set_size: TRANSACTION_LIFECYCLE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            low_fee_target_bps: TRANSACTION_LIFECYCLE_DEFAULT_LOW_FEE_TARGET_BPS,
            max_latency_ms: TRANSACTION_LIFECYCLE_DEFAULT_MAX_LATENCY_MS,
            min_pq_approvals: TRANSACTION_LIFECYCLE_DEFAULT_MIN_PQ_APPROVALS,
        }
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<()> {
        if self.protocol_version != TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION {
            return Err("transaction lifecycle protocol version mismatch".to_string());
        }
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_positive("intent_ttl_blocks", self.intent_ttl_blocks)?;
        ensure_positive("receipt_ttl_blocks", self.receipt_ttl_blocks)?;
        ensure_positive("status_ttl_blocks", self.status_ttl_blocks)?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_bps("low_fee_target_bps", self.low_fee_target_bps)?;
        ensure_positive("max_latency_ms", self.max_latency_ms)?;
        ensure_positive("min_pq_approvals", self.min_pq_approvals)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "status_ttl_blocks": self.status_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "low_fee_target_bps": self.low_fee_target_bps,
            "max_latency_ms": self.max_latency_ms,
            "min_pq_approvals": self.min_pq_approvals,
        })
    }

    pub fn config_root(&self) -> String {
        transaction_lifecycle_payload_root("TRANSACTION-LIFECYCLE-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleIntent {
    pub lifecycle_id: String,
    pub kind: LifecycleTransactionKind,
    pub stage: LifecycleStage,
    pub privacy_mode: LifecyclePrivacyMode,
    pub fee_mode: LifecycleFeeMode,
    pub user_commitment: String,
    pub wallet_plan_root: String,
    pub route_commitment_root: String,
    pub payload_commitment_root: String,
    pub nullifier_root: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub pq_approval_ids: Vec<String>,
}

impl LifecycleIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: LifecycleTransactionKind,
        privacy_mode: LifecyclePrivacyMode,
        fee_mode: LifecycleFeeMode,
        user_commitment: &str,
        wallet_plan_root: &str,
        route_commitment_root: &str,
        payload_commitment_root: &str,
        nullifier_root: &str,
        max_fee_micro_units: u64,
        privacy_set_size: u64,
        opened_at_height: u64,
        expires_at_height: u64,
        pq_approval_ids: Vec<String>,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        let lifecycle_id = lifecycle_intent_id(
            kind,
            user_commitment,
            wallet_plan_root,
            payload_commitment_root,
            opened_at_height,
        );
        let intent = Self {
            lifecycle_id,
            kind,
            stage: LifecycleStage::Planned,
            privacy_mode,
            fee_mode,
            user_commitment: user_commitment.to_string(),
            wallet_plan_root: wallet_plan_root.to_string(),
            route_commitment_root: route_commitment_root.to_string(),
            payload_commitment_root: payload_commitment_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            max_fee_micro_units,
            privacy_set_size,
            opened_at_height,
            expires_at_height,
            pq_approval_ids,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lifecycle_id": self.lifecycle_id,
            "kind": self.kind.as_str(),
            "stage": self.stage.as_str(),
            "privacy_mode": self.privacy_mode.as_str(),
            "fee_mode": self.fee_mode.as_str(),
            "user_commitment": self.user_commitment,
            "wallet_plan_root": self.wallet_plan_root,
            "route_commitment_scheme": TRANSACTION_LIFECYCLE_COMMITMENT_SCHEME,
            "route_commitment_root": self.route_commitment_root,
            "payload_commitment_root": self.payload_commitment_root,
            "nullifier_root": self.nullifier_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_approval_ids": self.pq_approval_ids,
        })
    }

    pub fn intent_root(&self) -> String {
        transaction_lifecycle_payload_root("TRANSACTION-LIFECYCLE-INTENT", &self.public_record())
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        ensure_non_empty("lifecycle_id", &self.lifecycle_id)?;
        ensure_non_empty("user_commitment", &self.user_commitment)?;
        ensure_non_empty("wallet_plan_root", &self.wallet_plan_root)?;
        ensure_non_empty("route_commitment_root", &self.route_commitment_root)?;
        ensure_non_empty("payload_commitment_root", &self.payload_commitment_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_positive("max_fee_micro_units", self.max_fee_micro_units)?;
        ensure_positive("privacy_set_size", self.privacy_set_size)?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "lifecycle intent",
        )?;
        ensure_unique_strings(&self.pq_approval_ids, "intent pq_approval_ids")?;
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolLifecycleAdmission {
    pub admission_id: String,
    pub lifecycle_id: String,
    pub encrypted_envelope_root: String,
    pub threshold_session_root: String,
    pub anti_spam_bond_root: String,
    pub admission_ticket_root: String,
    pub admitted_at_height: u64,
    pub expires_at_height: u64,
}

impl MempoolLifecycleAdmission {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lifecycle_id: &str,
        encrypted_envelope_root: &str,
        threshold_session_root: &str,
        anti_spam_bond_root: &str,
        admission_ticket_root: &str,
        admitted_at_height: u64,
        expires_at_height: u64,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        let admission_id = mempool_lifecycle_admission_id(
            lifecycle_id,
            encrypted_envelope_root,
            threshold_session_root,
            admitted_at_height,
        );
        let admission = Self {
            admission_id,
            lifecycle_id: lifecycle_id.to_string(),
            encrypted_envelope_root: encrypted_envelope_root.to_string(),
            threshold_session_root: threshold_session_root.to_string(),
            anti_spam_bond_root: anti_spam_bond_root.to_string(),
            admission_ticket_root: admission_ticket_root.to_string(),
            admitted_at_height,
            expires_at_height,
        };
        admission.validate()?;
        Ok(admission)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "admission_id": self.admission_id,
            "lifecycle_id": self.lifecycle_id,
            "encrypted_envelope_root": self.encrypted_envelope_root,
            "threshold_session_root": self.threshold_session_root,
            "anti_spam_bond_root": self.anti_spam_bond_root,
            "admission_ticket_root": self.admission_ticket_root,
            "admitted_at_height": self.admitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn admission_root(&self) -> String {
        transaction_lifecycle_payload_root(
            "TRANSACTION-LIFECYCLE-MEMPOOL-ADMISSION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        ensure_non_empty("admission_id", &self.admission_id)?;
        ensure_non_empty("lifecycle_id", &self.lifecycle_id)?;
        ensure_non_empty("encrypted_envelope_root", &self.encrypted_envelope_root)?;
        ensure_non_empty("threshold_session_root", &self.threshold_session_root)?;
        ensure_non_empty("anti_spam_bond_root", &self.anti_spam_bond_root)?;
        ensure_non_empty("admission_ticket_root", &self.admission_ticket_root)?;
        ensure_height_window(
            self.admitted_at_height,
            self.expires_at_height,
            "mempool admission",
        )?;
        Ok(self.admission_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerLifecycleCommitment {
    pub sequencer_commitment_id: String,
    pub lifecycle_id: String,
    pub surface: LifecycleRouteSurface,
    pub microblock_root: String,
    pub ordering_root: String,
    pub preconfirmation_root: String,
    pub qos_root: String,
    pub latency_ms: u64,
    pub sequenced_at_height: u64,
}

impl SequencerLifecycleCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lifecycle_id: &str,
        surface: LifecycleRouteSurface,
        microblock_root: &str,
        ordering_root: &str,
        preconfirmation_root: &str,
        qos_root: &str,
        latency_ms: u64,
        sequenced_at_height: u64,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        let sequencer_commitment_id = sequencer_lifecycle_commitment_id(
            lifecycle_id,
            surface,
            ordering_root,
            sequenced_at_height,
        );
        let commitment = Self {
            sequencer_commitment_id,
            lifecycle_id: lifecycle_id.to_string(),
            surface,
            microblock_root: microblock_root.to_string(),
            ordering_root: ordering_root.to_string(),
            preconfirmation_root: preconfirmation_root.to_string(),
            qos_root: qos_root.to_string(),
            latency_ms,
            sequenced_at_height,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sequencer_commitment_id": self.sequencer_commitment_id,
            "lifecycle_id": self.lifecycle_id,
            "surface": self.surface.as_str(),
            "microblock_root": self.microblock_root,
            "ordering_root": self.ordering_root,
            "preconfirmation_root": self.preconfirmation_root,
            "qos_root": self.qos_root,
            "latency_ms": self.latency_ms,
            "sequenced_at_height": self.sequenced_at_height,
        })
    }

    pub fn commitment_root(&self) -> String {
        transaction_lifecycle_payload_root(
            "TRANSACTION-LIFECYCLE-SEQUENCER-COMMITMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        ensure_non_empty("sequencer_commitment_id", &self.sequencer_commitment_id)?;
        ensure_non_empty("lifecycle_id", &self.lifecycle_id)?;
        ensure_non_empty("microblock_root", &self.microblock_root)?;
        ensure_non_empty("ordering_root", &self.ordering_root)?;
        ensure_non_empty("preconfirmation_root", &self.preconfirmation_root)?;
        ensure_non_empty("qos_root", &self.qos_root)?;
        ensure_positive("latency_ms", self.latency_ms)?;
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionLifecycleReceipt {
    pub execution_receipt_id: String,
    pub lifecycle_id: String,
    pub execution_root: String,
    pub private_state_root_before: String,
    pub private_state_root_after: String,
    pub contract_trace_root: String,
    pub token_delta_root: String,
    pub executed_at_height: u64,
    pub success: bool,
}

impl ExecutionLifecycleReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lifecycle_id: &str,
        execution_root: &str,
        private_state_root_before: &str,
        private_state_root_after: &str,
        contract_trace_root: &str,
        token_delta_root: &str,
        executed_at_height: u64,
        success: bool,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        let execution_receipt_id = execution_lifecycle_receipt_id(
            lifecycle_id,
            execution_root,
            private_state_root_after,
            executed_at_height,
        );
        let receipt = Self {
            execution_receipt_id,
            lifecycle_id: lifecycle_id.to_string(),
            execution_root: execution_root.to_string(),
            private_state_root_before: private_state_root_before.to_string(),
            private_state_root_after: private_state_root_after.to_string(),
            contract_trace_root: contract_trace_root.to_string(),
            token_delta_root: token_delta_root.to_string(),
            executed_at_height,
            success,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "execution_receipt_id": self.execution_receipt_id,
            "lifecycle_id": self.lifecycle_id,
            "execution_root": self.execution_root,
            "private_state_root_before": self.private_state_root_before,
            "private_state_root_after": self.private_state_root_after,
            "contract_trace_root": self.contract_trace_root,
            "token_delta_root": self.token_delta_root,
            "executed_at_height": self.executed_at_height,
            "success": self.success,
        })
    }

    pub fn receipt_root(&self) -> String {
        transaction_lifecycle_payload_root(
            "TRANSACTION-LIFECYCLE-EXECUTION-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        ensure_non_empty("execution_receipt_id", &self.execution_receipt_id)?;
        ensure_non_empty("lifecycle_id", &self.lifecycle_id)?;
        ensure_non_empty("execution_root", &self.execution_root)?;
        ensure_non_empty("private_state_root_before", &self.private_state_root_before)?;
        ensure_non_empty("private_state_root_after", &self.private_state_root_after)?;
        ensure_non_empty("contract_trace_root", &self.contract_trace_root)?;
        ensure_non_empty("token_delta_root", &self.token_delta_root)?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLifecycleReceipt {
    pub proof_receipt_id: String,
    pub lifecycle_id: String,
    pub proof_root: String,
    pub verifier_key_root: String,
    pub recursive_batch_root: String,
    pub prover_commitment: String,
    pub proof_fee_micro_units: u64,
    pub proved_at_height: u64,
    pub expires_at_height: u64,
}

impl ProofLifecycleReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lifecycle_id: &str,
        proof_root: &str,
        verifier_key_root: &str,
        recursive_batch_root: &str,
        prover_commitment: &str,
        proof_fee_micro_units: u64,
        proved_at_height: u64,
        expires_at_height: u64,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        let proof_receipt_id = proof_lifecycle_receipt_id(
            lifecycle_id,
            proof_root,
            prover_commitment,
            proved_at_height,
        );
        let receipt = Self {
            proof_receipt_id,
            lifecycle_id: lifecycle_id.to_string(),
            proof_root: proof_root.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            recursive_batch_root: recursive_batch_root.to_string(),
            prover_commitment: prover_commitment.to_string(),
            proof_fee_micro_units,
            proved_at_height,
            expires_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_receipt_id": self.proof_receipt_id,
            "lifecycle_id": self.lifecycle_id,
            "proof_root": self.proof_root,
            "verifier_key_root": self.verifier_key_root,
            "recursive_batch_root": self.recursive_batch_root,
            "prover_commitment": self.prover_commitment,
            "proof_fee_micro_units": self.proof_fee_micro_units,
            "proved_at_height": self.proved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn receipt_root(&self) -> String {
        transaction_lifecycle_payload_root(
            "TRANSACTION-LIFECYCLE-PROOF-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        ensure_non_empty("proof_receipt_id", &self.proof_receipt_id)?;
        ensure_non_empty("lifecycle_id", &self.lifecycle_id)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("verifier_key_root", &self.verifier_key_root)?;
        ensure_non_empty("recursive_batch_root", &self.recursive_batch_root)?;
        ensure_non_empty("prover_commitment", &self.prover_commitment)?;
        ensure_positive("proof_fee_micro_units", self.proof_fee_micro_units)?;
        ensure_height_window(
            self.proved_at_height,
            self.expires_at_height,
            "proof receipt",
        )?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementLifecycleReceipt {
    pub settlement_receipt_id: String,
    pub lifecycle_id: String,
    pub settlement_root: String,
    pub monero_anchor_root: String,
    pub finality_certificate_root: String,
    pub low_fee_rebate_root: String,
    pub settled_at_height: u64,
    pub finalized_at_height: u64,
}

impl SettlementLifecycleReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lifecycle_id: &str,
        settlement_root: &str,
        monero_anchor_root: &str,
        finality_certificate_root: &str,
        low_fee_rebate_root: &str,
        settled_at_height: u64,
        finalized_at_height: u64,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        let settlement_receipt_id = settlement_lifecycle_receipt_id(
            lifecycle_id,
            settlement_root,
            finality_certificate_root,
            finalized_at_height,
        );
        let receipt = Self {
            settlement_receipt_id,
            lifecycle_id: lifecycle_id.to_string(),
            settlement_root: settlement_root.to_string(),
            monero_anchor_root: monero_anchor_root.to_string(),
            finality_certificate_root: finality_certificate_root.to_string(),
            low_fee_rebate_root: low_fee_rebate_root.to_string(),
            settled_at_height,
            finalized_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_receipt_id": self.settlement_receipt_id,
            "lifecycle_id": self.lifecycle_id,
            "settlement_root": self.settlement_root,
            "monero_anchor_root": self.monero_anchor_root,
            "finality_certificate_root": self.finality_certificate_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "settled_at_height": self.settled_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }

    pub fn receipt_root(&self) -> String {
        transaction_lifecycle_payload_root(
            "TRANSACTION-LIFECYCLE-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        ensure_non_empty("settlement_receipt_id", &self.settlement_receipt_id)?;
        ensure_non_empty("lifecycle_id", &self.lifecycle_id)?;
        ensure_non_empty("settlement_root", &self.settlement_root)?;
        ensure_non_empty("monero_anchor_root", &self.monero_anchor_root)?;
        ensure_non_empty("finality_certificate_root", &self.finality_certificate_root)?;
        ensure_non_empty("low_fee_rebate_root", &self.low_fee_rebate_root)?;
        ensure_height_window(
            self.settled_at_height,
            self.finalized_at_height,
            "settlement receipt",
        )?;
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeLifecycleSponsorship {
    pub sponsorship_id: String,
    pub lifecycle_id: String,
    pub sponsor_budget_root: String,
    pub sponsor_market_root: String,
    pub rebate_receipt_root: String,
    pub sponsored_fee_micro_units: u64,
    pub target_discount_bps: u64,
}

impl LowFeeLifecycleSponsorship {
    pub fn new(
        lifecycle_id: &str,
        sponsor_budget_root: &str,
        sponsor_market_root: &str,
        rebate_receipt_root: &str,
        sponsored_fee_micro_units: u64,
        target_discount_bps: u64,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        let sponsorship_id = low_fee_lifecycle_sponsorship_id(
            lifecycle_id,
            sponsor_budget_root,
            rebate_receipt_root,
            target_discount_bps,
        );
        let sponsorship = Self {
            sponsorship_id,
            lifecycle_id: lifecycle_id.to_string(),
            sponsor_budget_root: sponsor_budget_root.to_string(),
            sponsor_market_root: sponsor_market_root.to_string(),
            rebate_receipt_root: rebate_receipt_root.to_string(),
            sponsored_fee_micro_units,
            target_discount_bps,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "lifecycle_id": self.lifecycle_id,
            "sponsor_budget_root": self.sponsor_budget_root,
            "sponsor_market_root": self.sponsor_market_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "target_discount_bps": self.target_discount_bps,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        transaction_lifecycle_payload_root(
            "TRANSACTION-LIFECYCLE-LOW-FEE-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        ensure_non_empty("sponsorship_id", &self.sponsorship_id)?;
        ensure_non_empty("lifecycle_id", &self.lifecycle_id)?;
        ensure_non_empty("sponsor_budget_root", &self.sponsor_budget_root)?;
        ensure_non_empty("sponsor_market_root", &self.sponsor_market_root)?;
        ensure_non_empty("rebate_receipt_root", &self.rebate_receipt_root)?;
        ensure_positive("sponsored_fee_micro_units", self.sponsored_fee_micro_units)?;
        ensure_bps("target_discount_bps", self.target_discount_bps)?;
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLifecycleApproval {
    pub approval_id: String,
    pub subject: LifecycleApprovalSubject,
    pub subject_id: String,
    pub subject_root: String,
    pub status: LifecycleApprovalStatus,
    pub signer_commitment: String,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
}

impl PqLifecycleApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: LifecycleApprovalSubject,
        subject_id: &str,
        subject_root: &str,
        signer_commitment: &str,
        public_key_commitment: &str,
        signature_root: &str,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        let approval_id = pq_lifecycle_approval_id(
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
            status: LifecycleApprovalStatus::Accepted,
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
            "scheme": TRANSACTION_LIFECYCLE_PQ_APPROVAL_SCHEME,
            "signer_commitment": self.signer_commitment,
            "public_key_commitment": self.public_key_commitment,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn approval_root(&self) -> String {
        transaction_lifecycle_payload_root(
            "TRANSACTION-LIFECYCLE-PQ-APPROVAL",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        ensure_non_empty("approval_id", &self.approval_id)?;
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("subject_root", &self.subject_root)?;
        ensure_non_empty("signer_commitment", &self.signer_commitment)?;
        ensure_non_empty("public_key_commitment", &self.public_key_commitment)?;
        ensure_non_empty("signature_root", &self.signature_root)?;
        ensure_height_window(self.signed_at_height, self.expires_at_height, "pq approval")?;
        Ok(self.approval_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleStatusProjection {
    pub projection_id: String,
    pub lifecycle_id: String,
    pub current_stage: LifecycleStage,
    pub status_root: String,
    pub user_visible_status_root: String,
    pub next_action_hint: String,
    pub updated_at_height: u64,
    pub expires_at_height: u64,
}

impl LifecycleStatusProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lifecycle_id: &str,
        current_stage: LifecycleStage,
        status_root: &str,
        user_visible_status_root: &str,
        next_action_hint: &str,
        updated_at_height: u64,
        expires_at_height: u64,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        let projection_id = lifecycle_status_projection_id(
            lifecycle_id,
            current_stage,
            status_root,
            updated_at_height,
        );
        let projection = Self {
            projection_id,
            lifecycle_id: lifecycle_id.to_string(),
            current_stage,
            status_root: status_root.to_string(),
            user_visible_status_root: user_visible_status_root.to_string(),
            next_action_hint: next_action_hint.to_string(),
            updated_at_height,
            expires_at_height,
        };
        projection.validate()?;
        Ok(projection)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "projection_id": self.projection_id,
            "lifecycle_id": self.lifecycle_id,
            "current_stage": self.current_stage.as_str(),
            "status_root": self.status_root,
            "user_visible_status_root": self.user_visible_status_root,
            "next_action_hint": self.next_action_hint,
            "updated_at_height": self.updated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn projection_root(&self) -> String {
        transaction_lifecycle_payload_root(
            "TRANSACTION-LIFECYCLE-STATUS-PROJECTION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        ensure_non_empty("projection_id", &self.projection_id)?;
        ensure_non_empty("lifecycle_id", &self.lifecycle_id)?;
        ensure_non_empty("status_root", &self.status_root)?;
        ensure_non_empty("user_visible_status_root", &self.user_visible_status_root)?;
        ensure_non_empty("next_action_hint", &self.next_action_hint)?;
        ensure_height_window(
            self.updated_at_height,
            self.expires_at_height,
            "status projection",
        )?;
        Ok(self.projection_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionLifecycleCoordinatorRoots {
    pub config_root: String,
    pub intent_root: String,
    pub mempool_admission_root: String,
    pub sequencer_commitment_root: String,
    pub execution_receipt_root: String,
    pub proof_receipt_root: String,
    pub settlement_receipt_root: String,
    pub low_fee_sponsorship_root: String,
    pub pq_approval_root: String,
    pub status_projection_root: String,
}

impl TransactionLifecycleCoordinatorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "intent_root": self.intent_root,
            "mempool_admission_root": self.mempool_admission_root,
            "sequencer_commitment_root": self.sequencer_commitment_root,
            "execution_receipt_root": self.execution_receipt_root,
            "proof_receipt_root": self.proof_receipt_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "pq_approval_root": self.pq_approval_root,
            "status_projection_root": self.status_projection_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionLifecycleCoordinatorCounters {
    pub intent_count: u64,
    pub live_intent_count: u64,
    pub mempool_admission_count: u64,
    pub sequencer_commitment_count: u64,
    pub execution_receipt_count: u64,
    pub successful_execution_count: u64,
    pub proof_receipt_count: u64,
    pub settlement_receipt_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub pq_approval_count: u64,
    pub usable_pq_approval_count: u64,
    pub status_projection_count: u64,
    pub total_sponsored_fee_micro_units: u64,
}

impl TransactionLifecycleCoordinatorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_count": self.intent_count,
            "live_intent_count": self.live_intent_count,
            "mempool_admission_count": self.mempool_admission_count,
            "sequencer_commitment_count": self.sequencer_commitment_count,
            "execution_receipt_count": self.execution_receipt_count,
            "successful_execution_count": self.successful_execution_count,
            "proof_receipt_count": self.proof_receipt_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "pq_approval_count": self.pq_approval_count,
            "usable_pq_approval_count": self.usable_pq_approval_count,
            "status_projection_count": self.status_projection_count,
            "total_sponsored_fee_micro_units": self.total_sponsored_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionLifecycleCoordinatorState {
    pub config: TransactionLifecycleCoordinatorConfig,
    pub height: u64,
    pub intents: BTreeMap<String, LifecycleIntent>,
    pub mempool_admissions: BTreeMap<String, MempoolLifecycleAdmission>,
    pub sequencer_commitments: BTreeMap<String, SequencerLifecycleCommitment>,
    pub execution_receipts: BTreeMap<String, ExecutionLifecycleReceipt>,
    pub proof_receipts: BTreeMap<String, ProofLifecycleReceipt>,
    pub settlement_receipts: BTreeMap<String, SettlementLifecycleReceipt>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeLifecycleSponsorship>,
    pub pq_approvals: BTreeMap<String, PqLifecycleApproval>,
    pub status_projections: BTreeMap<String, LifecycleStatusProjection>,
}

impl TransactionLifecycleCoordinatorState {
    pub fn new(
        config: TransactionLifecycleCoordinatorConfig,
    ) -> TransactionLifecycleCoordinatorResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            intents: BTreeMap::new(),
            mempool_admissions: BTreeMap::new(),
            sequencer_commitments: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            pq_approvals: BTreeMap::new(),
            status_projections: BTreeMap::new(),
        })
    }

    pub fn devnet() -> TransactionLifecycleCoordinatorResult<Self> {
        let mut state = Self::new(TransactionLifecycleCoordinatorConfig::devnet())?;
        state.height = TRANSACTION_LIFECYCLE_DEVNET_HEIGHT;

        let intent = LifecycleIntent::new(
            LifecycleTransactionKind::PrivateDefiSwap,
            LifecyclePrivacyMode::EncryptedMetadata,
            LifecycleFeeMode::SponsorAssisted,
            "user-commitment:devnet-lifecycle",
            "wallet-plan-root:devnet-lifecycle",
            "route-commitment-root:devnet-lifecycle",
            "payload-commitment-root:devnet-lifecycle",
            "nullifier-root:devnet-lifecycle",
            160_000,
            state.config.min_privacy_set_size,
            state.height,
            state.height + state.config.intent_ttl_blocks,
            Vec::new(),
        )?;
        let lifecycle_id = intent.lifecycle_id.clone();
        let intent_root = intent.intent_root();
        state.insert_intent(intent)?;

        let approval = PqLifecycleApproval::new(
            LifecycleApprovalSubject::WalletPlan,
            &lifecycle_id,
            &intent_root,
            "pq-signer:devnet-lifecycle",
            "ml-dsa-public-key-commitment:devnet-lifecycle",
            "ml-dsa-signature-root:devnet-lifecycle",
            state.height,
            state.height + state.config.receipt_ttl_blocks,
        )?;
        state.insert_pq_approval(approval)?;

        state.insert_mempool_admission(MempoolLifecycleAdmission::new(
            &lifecycle_id,
            "encrypted-envelope-root:devnet-lifecycle",
            "threshold-session-root:devnet-lifecycle",
            "anti-spam-bond-root:devnet-lifecycle",
            "admission-ticket-root:devnet-lifecycle",
            state.height,
            state.height + state.config.intent_ttl_blocks,
        )?)?;

        state.insert_sequencer_commitment(SequencerLifecycleCommitment::new(
            &lifecycle_id,
            LifecycleRouteSurface::SequencerFastLane,
            "microblock-root:devnet-lifecycle",
            "ordering-root:devnet-lifecycle",
            "preconfirmation-root:devnet-lifecycle",
            "qos-root:devnet-lifecycle",
            210,
            state.height + 1,
        )?)?;

        state.insert_execution_receipt(ExecutionLifecycleReceipt::new(
            &lifecycle_id,
            "execution-root:devnet-lifecycle",
            "private-state-before:devnet-lifecycle",
            "private-state-after:devnet-lifecycle",
            "contract-trace-root:devnet-lifecycle",
            "token-delta-root:devnet-lifecycle",
            state.height + 2,
            true,
        )?)?;

        state.insert_proof_receipt(ProofLifecycleReceipt::new(
            &lifecycle_id,
            "proof-root:devnet-lifecycle",
            "verifier-key-root:devnet-lifecycle",
            "recursive-batch-root:devnet-lifecycle",
            "prover-commitment:devnet-lifecycle",
            95_000,
            state.height + 3,
            state.height + state.config.receipt_ttl_blocks,
        )?)?;

        state.insert_low_fee_sponsorship(LowFeeLifecycleSponsorship::new(
            &lifecycle_id,
            "sponsor-budget-root:devnet-lifecycle",
            "sponsor-market-root:devnet-lifecycle",
            "rebate-receipt-root:devnet-lifecycle",
            90_000,
            state.config.low_fee_target_bps,
        )?)?;

        state.insert_settlement_receipt(SettlementLifecycleReceipt::new(
            &lifecycle_id,
            "settlement-root:devnet-lifecycle",
            "monero-anchor-root:devnet-lifecycle",
            "finality-certificate-root:devnet-lifecycle",
            "low-fee-rebate-root:devnet-lifecycle",
            state.height + 4,
            state.height + 8,
        )?)?;

        state.insert_status_projection(LifecycleStatusProjection::new(
            &lifecycle_id,
            LifecycleStage::Finalized,
            "status-root:devnet-lifecycle",
            "user-visible-status-root:devnet-lifecycle",
            "complete",
            state.height + 8,
            state.height + state.config.status_ttl_blocks,
        )?)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> TransactionLifecycleCoordinatorResult<String> {
        if height < self.height {
            return Err("transaction lifecycle height cannot move backwards".to_string());
        }
        self.height = height;
        for approval in self.pq_approvals.values_mut() {
            if approval.status.usable() && approval.expires_at_height < height {
                approval.status = LifecycleApprovalStatus::Expired;
            }
        }
        for intent in self.intents.values_mut() {
            if !intent.stage.terminal() && intent.expires_at_height < height {
                intent.stage = LifecycleStage::Failed;
            }
        }
        self.validate()
    }

    pub fn insert_intent(
        &mut self,
        intent: LifecycleIntent,
    ) -> TransactionLifecycleCoordinatorResult<String> {
        let root = intent.validate()?;
        if intent.kind.privacy_sensitive()
            && intent.privacy_set_size < self.config.min_privacy_set_size
        {
            return Err("intent privacy set below configured minimum".to_string());
        }
        self.intents.insert(intent.lifecycle_id.clone(), intent);
        Ok(root)
    }

    pub fn insert_mempool_admission(
        &mut self,
        admission: MempoolLifecycleAdmission,
    ) -> TransactionLifecycleCoordinatorResult<String> {
        let root = admission.validate()?;
        if !self.intents.contains_key(&admission.lifecycle_id) {
            return Err("mempool admission references missing lifecycle intent".to_string());
        }
        self.mempool_admissions
            .insert(admission.admission_id.clone(), admission);
        Ok(root)
    }

    pub fn insert_sequencer_commitment(
        &mut self,
        commitment: SequencerLifecycleCommitment,
    ) -> TransactionLifecycleCoordinatorResult<String> {
        let root = commitment.validate()?;
        if !self.intents.contains_key(&commitment.lifecycle_id) {
            return Err("sequencer commitment references missing lifecycle intent".to_string());
        }
        if commitment.latency_ms > self.config.max_latency_ms {
            return Err("sequencer commitment latency exceeds configured maximum".to_string());
        }
        self.sequencer_commitments
            .insert(commitment.sequencer_commitment_id.clone(), commitment);
        Ok(root)
    }

    pub fn insert_execution_receipt(
        &mut self,
        receipt: ExecutionLifecycleReceipt,
    ) -> TransactionLifecycleCoordinatorResult<String> {
        let root = receipt.validate()?;
        if !self.intents.contains_key(&receipt.lifecycle_id) {
            return Err("execution receipt references missing lifecycle intent".to_string());
        }
        self.execution_receipts
            .insert(receipt.execution_receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn insert_proof_receipt(
        &mut self,
        receipt: ProofLifecycleReceipt,
    ) -> TransactionLifecycleCoordinatorResult<String> {
        let root = receipt.validate()?;
        if !self.intents.contains_key(&receipt.lifecycle_id) {
            return Err("proof receipt references missing lifecycle intent".to_string());
        }
        self.proof_receipts
            .insert(receipt.proof_receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: SettlementLifecycleReceipt,
    ) -> TransactionLifecycleCoordinatorResult<String> {
        let root = receipt.validate()?;
        if !self.intents.contains_key(&receipt.lifecycle_id) {
            return Err("settlement receipt references missing lifecycle intent".to_string());
        }
        self.settlement_receipts
            .insert(receipt.settlement_receipt_id.clone(), receipt);
        Ok(root)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeLifecycleSponsorship,
    ) -> TransactionLifecycleCoordinatorResult<String> {
        let root = sponsorship.validate()?;
        if !self.intents.contains_key(&sponsorship.lifecycle_id) {
            return Err("low fee sponsorship references missing lifecycle intent".to_string());
        }
        self.low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);
        Ok(root)
    }

    pub fn insert_pq_approval(
        &mut self,
        approval: PqLifecycleApproval,
    ) -> TransactionLifecycleCoordinatorResult<String> {
        let root = approval.validate()?;
        self.pq_approvals
            .insert(approval.approval_id.clone(), approval);
        Ok(root)
    }

    pub fn insert_status_projection(
        &mut self,
        projection: LifecycleStatusProjection,
    ) -> TransactionLifecycleCoordinatorResult<String> {
        let root = projection.validate()?;
        if !self.intents.contains_key(&projection.lifecycle_id) {
            return Err("status projection references missing lifecycle intent".to_string());
        }
        self.status_projections
            .insert(projection.projection_id.clone(), projection);
        Ok(root)
    }

    pub fn live_lifecycle_ids(&self) -> Vec<String> {
        self.intents
            .values()
            .filter(|intent| !intent.stage.terminal())
            .map(|intent| intent.lifecycle_id.clone())
            .collect()
    }

    pub fn total_sponsored_fee_micro_units(&self) -> u64 {
        self.low_fee_sponsorships
            .values()
            .map(|sponsorship| sponsorship.sponsored_fee_micro_units)
            .sum()
    }

    pub fn intent_root(&self) -> String {
        transaction_lifecycle_collection_root(
            "TRANSACTION-LIFECYCLE-INTENT-COLLECTION",
            &self
                .intents
                .values()
                .map(LifecycleIntent::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn mempool_admission_root(&self) -> String {
        transaction_lifecycle_collection_root(
            "TRANSACTION-LIFECYCLE-MEMPOOL-ADMISSION-COLLECTION",
            &self
                .mempool_admissions
                .values()
                .map(MempoolLifecycleAdmission::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sequencer_commitment_root(&self) -> String {
        transaction_lifecycle_collection_root(
            "TRANSACTION-LIFECYCLE-SEQUENCER-COMMITMENT-COLLECTION",
            &self
                .sequencer_commitments
                .values()
                .map(SequencerLifecycleCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn execution_receipt_root(&self) -> String {
        transaction_lifecycle_collection_root(
            "TRANSACTION-LIFECYCLE-EXECUTION-RECEIPT-COLLECTION",
            &self
                .execution_receipts
                .values()
                .map(ExecutionLifecycleReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn proof_receipt_root(&self) -> String {
        transaction_lifecycle_collection_root(
            "TRANSACTION-LIFECYCLE-PROOF-RECEIPT-COLLECTION",
            &self
                .proof_receipts
                .values()
                .map(ProofLifecycleReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn settlement_receipt_root(&self) -> String {
        transaction_lifecycle_collection_root(
            "TRANSACTION-LIFECYCLE-SETTLEMENT-RECEIPT-COLLECTION",
            &self
                .settlement_receipts
                .values()
                .map(SettlementLifecycleReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        transaction_lifecycle_collection_root(
            "TRANSACTION-LIFECYCLE-LOW-FEE-SPONSORSHIP-COLLECTION",
            &self
                .low_fee_sponsorships
                .values()
                .map(LowFeeLifecycleSponsorship::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_approval_root(&self) -> String {
        transaction_lifecycle_collection_root(
            "TRANSACTION-LIFECYCLE-PQ-APPROVAL-COLLECTION",
            &self
                .pq_approvals
                .values()
                .map(PqLifecycleApproval::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn status_projection_root(&self) -> String {
        transaction_lifecycle_collection_root(
            "TRANSACTION-LIFECYCLE-STATUS-PROJECTION-COLLECTION",
            &self
                .status_projections
                .values()
                .map(LifecycleStatusProjection::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> TransactionLifecycleCoordinatorRoots {
        TransactionLifecycleCoordinatorRoots {
            config_root: self.config.config_root(),
            intent_root: self.intent_root(),
            mempool_admission_root: self.mempool_admission_root(),
            sequencer_commitment_root: self.sequencer_commitment_root(),
            execution_receipt_root: self.execution_receipt_root(),
            proof_receipt_root: self.proof_receipt_root(),
            settlement_receipt_root: self.settlement_receipt_root(),
            low_fee_sponsorship_root: self.low_fee_sponsorship_root(),
            pq_approval_root: self.pq_approval_root(),
            status_projection_root: self.status_projection_root(),
        }
    }

    pub fn counters(&self) -> TransactionLifecycleCoordinatorCounters {
        TransactionLifecycleCoordinatorCounters {
            intent_count: self.intents.len() as u64,
            live_intent_count: self
                .intents
                .values()
                .filter(|intent| !intent.stage.terminal())
                .count() as u64,
            mempool_admission_count: self.mempool_admissions.len() as u64,
            sequencer_commitment_count: self.sequencer_commitments.len() as u64,
            execution_receipt_count: self.execution_receipts.len() as u64,
            successful_execution_count: self
                .execution_receipts
                .values()
                .filter(|receipt| receipt.success)
                .count() as u64,
            proof_receipt_count: self.proof_receipts.len() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            pq_approval_count: self.pq_approvals.len() as u64,
            usable_pq_approval_count: self
                .pq_approvals
                .values()
                .filter(|approval| approval.status.usable())
                .count() as u64,
            status_projection_count: self.status_projections.len() as u64,
            total_sponsored_fee_micro_units: self.total_sponsored_fee_micro_units(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "live_lifecycle_ids": self.live_lifecycle_ids(),
        })
    }

    pub fn state_root(&self) -> String {
        transaction_lifecycle_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> TransactionLifecycleCoordinatorResult<String> {
        self.config.validate()?;
        let mut nullifiers = BTreeSet::new();
        for intent in self.intents.values() {
            intent.validate()?;
            if intent.kind.privacy_sensitive()
                && intent.privacy_set_size < self.config.min_privacy_set_size
            {
                return Err(format!(
                    "intent {} privacy set too small",
                    intent.lifecycle_id
                ));
            }
            if !nullifiers.insert(intent.nullifier_root.clone()) {
                return Err("duplicate lifecycle nullifier root".to_string());
            }
        }
        for admission in self.mempool_admissions.values() {
            admission.validate()?;
            ensure_lifecycle_exists(&self.intents, &admission.lifecycle_id, "mempool admission")?;
        }
        for commitment in self.sequencer_commitments.values() {
            commitment.validate()?;
            ensure_lifecycle_exists(
                &self.intents,
                &commitment.lifecycle_id,
                "sequencer commitment",
            )?;
        }
        for receipt in self.execution_receipts.values() {
            receipt.validate()?;
            ensure_lifecycle_exists(&self.intents, &receipt.lifecycle_id, "execution receipt")?;
        }
        for receipt in self.proof_receipts.values() {
            receipt.validate()?;
            ensure_lifecycle_exists(&self.intents, &receipt.lifecycle_id, "proof receipt")?;
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            ensure_lifecycle_exists(&self.intents, &receipt.lifecycle_id, "settlement receipt")?;
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
            ensure_lifecycle_exists(
                &self.intents,
                &sponsorship.lifecycle_id,
                "low fee sponsorship",
            )?;
        }
        for approval in self.pq_approvals.values() {
            approval.validate()?;
        }
        for projection in self.status_projections.values() {
            projection.validate()?;
            ensure_lifecycle_exists(&self.intents, &projection.lifecycle_id, "status projection")?;
        }
        Ok(self.state_root())
    }
}

pub fn transaction_lifecycle_state_root_from_record(record: &Value) -> String {
    transaction_lifecycle_payload_root("TRANSACTION-LIFECYCLE-STATE-ROOT", record)
}

pub fn transaction_lifecycle_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn transaction_lifecycle_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn transaction_lifecycle_collection_root(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn lifecycle_intent_id(
    kind: LifecycleTransactionKind,
    user_commitment: &str,
    wallet_plan_root: &str,
    payload_commitment_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "TRANSACTION-LIFECYCLE-INTENT-ID",
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(user_commitment),
            HashPart::Str(wallet_plan_root),
            HashPart::Str(payload_commitment_root),
            HashPart::Int(opened_at_height as i128),
        ],
        16,
    )
}

pub fn mempool_lifecycle_admission_id(
    lifecycle_id: &str,
    encrypted_envelope_root: &str,
    threshold_session_root: &str,
    admitted_at_height: u64,
) -> String {
    domain_hash(
        "TRANSACTION-LIFECYCLE-MEMPOOL-ADMISSION-ID",
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(lifecycle_id),
            HashPart::Str(encrypted_envelope_root),
            HashPart::Str(threshold_session_root),
            HashPart::Int(admitted_at_height as i128),
        ],
        16,
    )
}

pub fn sequencer_lifecycle_commitment_id(
    lifecycle_id: &str,
    surface: LifecycleRouteSurface,
    ordering_root: &str,
    sequenced_at_height: u64,
) -> String {
    domain_hash(
        "TRANSACTION-LIFECYCLE-SEQUENCER-COMMITMENT-ID",
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(lifecycle_id),
            HashPart::Str(surface.as_str()),
            HashPart::Str(ordering_root),
            HashPart::Int(sequenced_at_height as i128),
        ],
        16,
    )
}

pub fn execution_lifecycle_receipt_id(
    lifecycle_id: &str,
    execution_root: &str,
    private_state_root_after: &str,
    executed_at_height: u64,
) -> String {
    domain_hash(
        "TRANSACTION-LIFECYCLE-EXECUTION-RECEIPT-ID",
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(lifecycle_id),
            HashPart::Str(execution_root),
            HashPart::Str(private_state_root_after),
            HashPart::Int(executed_at_height as i128),
        ],
        16,
    )
}

pub fn proof_lifecycle_receipt_id(
    lifecycle_id: &str,
    proof_root: &str,
    prover_commitment: &str,
    proved_at_height: u64,
) -> String {
    domain_hash(
        "TRANSACTION-LIFECYCLE-PROOF-RECEIPT-ID",
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(lifecycle_id),
            HashPart::Str(proof_root),
            HashPart::Str(prover_commitment),
            HashPart::Int(proved_at_height as i128),
        ],
        16,
    )
}

pub fn settlement_lifecycle_receipt_id(
    lifecycle_id: &str,
    settlement_root: &str,
    finality_certificate_root: &str,
    finalized_at_height: u64,
) -> String {
    domain_hash(
        "TRANSACTION-LIFECYCLE-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(lifecycle_id),
            HashPart::Str(settlement_root),
            HashPart::Str(finality_certificate_root),
            HashPart::Int(finalized_at_height as i128),
        ],
        16,
    )
}

pub fn low_fee_lifecycle_sponsorship_id(
    lifecycle_id: &str,
    sponsor_budget_root: &str,
    rebate_receipt_root: &str,
    target_discount_bps: u64,
) -> String {
    domain_hash(
        "TRANSACTION-LIFECYCLE-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(lifecycle_id),
            HashPart::Str(sponsor_budget_root),
            HashPart::Str(rebate_receipt_root),
            HashPart::Int(target_discount_bps as i128),
        ],
        16,
    )
}

pub fn pq_lifecycle_approval_id(
    subject: LifecycleApprovalSubject,
    subject_id: &str,
    subject_root: &str,
    signer_commitment: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "TRANSACTION-LIFECYCLE-PQ-APPROVAL-ID",
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(subject.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(signer_commitment),
            HashPart::Int(signed_at_height as i128),
        ],
        16,
    )
}

pub fn lifecycle_status_projection_id(
    lifecycle_id: &str,
    stage: LifecycleStage,
    status_root: &str,
    updated_at_height: u64,
) -> String {
    domain_hash(
        "TRANSACTION-LIFECYCLE-STATUS-PROJECTION-ID",
        &[
            HashPart::Str(TRANSACTION_LIFECYCLE_COORDINATOR_PROTOCOL_VERSION),
            HashPart::Str(lifecycle_id),
            HashPart::Str(stage.as_str()),
            HashPart::Str(status_root),
            HashPart::Int(updated_at_height as i128),
        ],
        16,
    )
}

fn ensure_lifecycle_exists(
    intents: &BTreeMap<String, LifecycleIntent>,
    lifecycle_id: &str,
    label: &str,
) -> TransactionLifecycleCoordinatorResult<()> {
    if !intents.contains_key(lifecycle_id) {
        return Err(format!("{label} references missing lifecycle intent"));
    }
    Ok(())
}

fn ensure_non_empty(label: &str, value: &str) -> TransactionLifecycleCoordinatorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} is empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> TransactionLifecycleCoordinatorResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> TransactionLifecycleCoordinatorResult<()> {
    if value > TRANSACTION_LIFECYCLE_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_height_window(
    start: u64,
    end: u64,
    label: &str,
) -> TransactionLifecycleCoordinatorResult<()> {
    if end < start {
        return Err(format!("{label} height window is inverted"));
    }
    Ok(())
}

fn ensure_unique_strings(
    values: &[String],
    label: &str,
) -> TransactionLifecycleCoordinatorResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
