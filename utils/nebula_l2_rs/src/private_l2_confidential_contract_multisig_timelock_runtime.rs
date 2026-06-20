use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-contract-multisig-timelock-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-multisig-timelock-v1";
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEVNET_HEIGHT: u64 = 1_048_000;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_SIGNER_SETS:
    usize = 4_194_304;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_SIGNERS: usize =
    67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_OPERATIONS: usize =
    33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_APPROVALS: usize =
    134_217_728;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_QUEUE_ENTRIES:
    usize = 33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_RESERVATIONS:
    usize = 33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    16_777_216;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    67_108_864;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_REBATES: usize =
    33_554_432;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_NULLIFIERS: usize =
    268_435_456;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_BATCH_OPS: usize =
    8_192;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MIN_DELAY_BLOCKS: u64 =
    64;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_DELAY_BLOCKS: u64 =
    172_800;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MIN_PRIVACY_SET: u64 =
    65_536;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_TARGET_REBATE_BPS:
    u64 = 4;
pub const PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS:
    u64 = 5;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelockDomainKind {
    ContractUpgrade,
    TreasuryTransfer,
    OracleParameter,
    RiskParameter,
    FeePolicy,
    TokenMint,
    BridgeRoute,
    EmergencyPause,
}

impl TimelockDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractUpgrade => "contract_upgrade",
            Self::TreasuryTransfer => "treasury_transfer",
            Self::OracleParameter => "oracle_parameter",
            Self::RiskParameter => "risk_parameter",
            Self::FeePolicy => "fee_policy",
            Self::TokenMint => "token_mint",
            Self::BridgeRoute => "bridge_route",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    DeployContract,
    UpgradeContract,
    RotateVerifier,
    UpdateFeeSchedule,
    UpdateRiskLimit,
    MintConfidentialToken,
    MoveTreasuryLiquidity,
    PauseRuntime,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeployContract => "deploy_contract",
            Self::UpgradeContract => "upgrade_contract",
            Self::RotateVerifier => "rotate_verifier",
            Self::UpdateFeeSchedule => "update_fee_schedule",
            Self::UpdateRiskLimit => "update_risk_limit",
            Self::MintConfidentialToken => "mint_confidential_token",
            Self::MoveTreasuryLiquidity => "move_treasury_liquidity",
            Self::PauseRuntime => "pause_runtime",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Draft,
    Proposed,
    Approving,
    Queued,
    Executable,
    Executed,
    Cancelled,
    Expired,
}

impl OperationStatus {
    pub fn accepts_approval(self) -> bool {
        matches!(self, Self::Proposed | Self::Approving | Self::Queued)
    }

    pub fn anchors_state(self) -> bool {
        !matches!(self, Self::Draft)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Pending,
    Active,
    Suspended,
    Rotating,
    Retired,
}

impl SignerStatus {
    pub fn can_sign(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVerdict {
    Approve,
    Reject,
    Abstain,
    Challenge,
}

impl ApprovalVerdict {
    pub fn counts_for_threshold(self) -> bool {
        matches!(self, Self::Approve | Self::Challenge)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Open,
    Locked,
    Matured,
    Executed,
    Cancelled,
    Expired,
}

impl QueueStatus {
    pub fn is_live(self) -> bool {
        matches!(self, Self::Open | Self::Locked | Self::Matured)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Proving,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn anchors_state(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Proving | Self::Settled | Self::Disputed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Released,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    OperationQueued,
    ApprovalSettled,
    OperationExecuted,
    SponsorCharged,
    RebateCredited,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Claimable,
    Claimed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierFenceStatus {
    Locked,
    Consumed,
    Released,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub devnet_height: u64,
    pub max_signer_sets: usize,
    pub max_signers: usize,
    pub max_operations: usize,
    pub max_approvals: usize,
    pub max_queue_entries: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_nullifiers: usize,
    pub max_batch_operations: usize,
    pub min_delay_blocks: u64,
    pub max_delay_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_rebate_bps: u64,
    pub max_sponsor_fee_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_HASH_SUITE
                .to_string(),
            pq_auth_suite:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_PQ_AUTH_SUITE
                    .to_string(),
            devnet_height: PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEVNET_HEIGHT,
            max_signer_sets:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_SIGNER_SETS,
            max_signers:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_SIGNERS,
            max_operations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_OPERATIONS,
            max_approvals:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_APPROVALS,
            max_queue_entries:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_QUEUE_ENTRIES,
            max_reservations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_REBATES,
            max_nullifiers:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_NULLIFIERS,
            max_batch_operations:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_BATCH_OPS,
            min_delay_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MIN_DELAY_BLOCKS,
            max_delay_blocks:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_DELAY_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            max_sponsor_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub signer_set_count: u64,
    pub active_signer_set_count: u64,
    pub signer_count: u64,
    pub active_signer_count: u64,
    pub operation_count: u64,
    pub live_operation_count: u64,
    pub approval_count: u64,
    pub threshold_approval_count: u64,
    pub queue_entry_count: u64,
    pub live_queue_entry_count: u64,
    pub reservation_count: u64,
    pub batch_count: u64,
    pub settled_batch_count: u64,
    pub receipt_count: u64,
    pub rebate_count: u64,
    pub locked_nullifier_count: u64,
    pub event_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub signer_set_root: String,
    pub active_signer_set_root: String,
    pub signer_root: String,
    pub active_signer_root: String,
    pub operation_root: String,
    pub live_operation_root: String,
    pub approval_root: String,
    pub threshold_approval_root: String,
    pub queue_root: String,
    pub live_queue_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nullifier_fence_root: String,
    pub consumed_nullifier_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = json!({"empty": true});
        Self {
            signer_set_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-SIGNER-SETS", &[]),
            active_signer_set_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-MULTISIG-ACTIVE-SIGNER-SETS",
                &[],
            ),
            signer_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-SIGNERS", &[]),
            active_signer_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-ACTIVE-SIGNERS", &[]),
            operation_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-OPERATIONS", &[]),
            live_operation_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-MULTISIG-LIVE-OPERATIONS",
                &[],
            ),
            approval_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-APPROVALS", &[]),
            threshold_approval_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-MULTISIG-THRESHOLD-APPROVALS",
                &[],
            ),
            queue_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-QUEUE", &[]),
            live_queue_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-LIVE-QUEUE", &[]),
            reservation_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-RESERVATIONS", &[]),
            batch_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-BATCHES", &[]),
            receipt_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-RECEIPTS", &[]),
            rebate_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-REBATES", &[]),
            nullifier_fence_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-MULTISIG-NULLIFIER-FENCES",
                &[],
            ),
            consumed_nullifier_root: merkle_root(
                "PRIVATE-L2-CONFIDENTIAL-MULTISIG-CONSUMED-NULLIFIERS",
                &[],
            ),
            event_root: merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-EVENTS", &[]),
            public_record_root: domain_hash(
                "PRIVATE-L2-CONFIDENTIAL-MULTISIG-PUBLIC-RECORD",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(
                        PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_PROTOCOL_VERSION,
                    ),
                    HashPart::Json(&empty),
                ],
                32,
            ),
            state_root: domain_hash(
                "PRIVATE-L2-CONFIDENTIAL-MULTISIG-STATE",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(
                        PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_PROTOCOL_VERSION,
                    ),
                    HashPart::Json(&empty),
                ],
                32,
            ),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerSet {
    pub signer_set_id: String,
    pub domain_kind: TimelockDomainKind,
    pub label_commitment: String,
    pub signer_root: String,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub min_delay_blocks: u64,
    pub max_delay_blocks: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: SignerStatus,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl SignerSet {
    pub fn record(&self) -> Value {
        json!({
            "signer_set_id": self.signer_set_id,
            "domain_kind": self.domain_kind,
            "label_commitment": self.label_commitment,
            "signer_root": self.signer_root,
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "min_delay_blocks": self.min_delay_blocks,
            "max_delay_blocks": self.max_delay_blocks,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerCommitment {
    pub signer_id: String,
    pub signer_set_id: String,
    pub encrypted_identity_commitment: String,
    pub pq_key_commitment: String,
    pub weight: u64,
    pub status: SignerStatus,
    pub last_approval_height: u64,
    pub added_at_height: u64,
}

impl SignerCommitment {
    pub fn record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "signer_set_id": self.signer_set_id,
            "encrypted_identity_commitment": self.encrypted_identity_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "weight": self.weight,
            "status": self.status,
            "last_approval_height": self.last_approval_height,
            "added_at_height": self.added_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimelockOperation {
    pub operation_id: String,
    pub signer_set_id: String,
    pub domain_kind: TimelockDomainKind,
    pub operation_kind: OperationKind,
    pub encrypted_call_root: String,
    pub target_contract_commitment: String,
    pub value_commitment: String,
    pub dependency_root: String,
    pub operation_nullifier: String,
    pub status: OperationStatus,
    pub privacy_set_size: u64,
    pub proposed_at_height: u64,
    pub earliest_execute_height: u64,
    pub expires_at_height: u64,
}

impl TimelockOperation {
    pub fn record(&self) -> Value {
        json!({
            "operation_id": self.operation_id,
            "signer_set_id": self.signer_set_id,
            "domain_kind": self.domain_kind,
            "operation_kind": self.operation_kind,
            "encrypted_call_root": self.encrypted_call_root,
            "target_contract_commitment": self.target_contract_commitment,
            "value_commitment": self.value_commitment,
            "dependency_root": self.dependency_root,
            "operation_nullifier": self.operation_nullifier,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "proposed_at_height": self.proposed_at_height,
            "earliest_execute_height": self.earliest_execute_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedApproval {
    pub approval_id: String,
    pub operation_id: String,
    pub signer_id: String,
    pub encrypted_vote_payload: String,
    pub verdict: ApprovalVerdict,
    pub weight: u64,
    pub approval_nullifier: String,
    pub pq_signature_commitment: String,
    pub transcript_root: String,
    pub observed_at_height: u64,
}

impl EncryptedApproval {
    pub fn record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "operation_id": self.operation_id,
            "signer_id": self.signer_id,
            "encrypted_vote_payload": self.encrypted_vote_payload,
            "verdict": self.verdict,
            "weight": self.weight,
            "approval_nullifier": self.approval_nullifier,
            "pq_signature_commitment": self.pq_signature_commitment,
            "transcript_root": self.transcript_root,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimelockQueueEntry {
    pub queue_entry_id: String,
    pub operation_id: String,
    pub signer_set_id: String,
    pub approval_root: String,
    pub threshold_weight: u64,
    pub collected_weight: u64,
    pub queue_status: QueueStatus,
    pub queued_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
}

impl TimelockQueueEntry {
    pub fn record(&self) -> Value {
        json!({
            "queue_entry_id": self.queue_entry_id,
            "operation_id": self.operation_id,
            "signer_set_id": self.signer_set_id,
            "approval_root": self.approval_root,
            "threshold_weight": self.threshold_weight,
            "collected_weight": self.collected_weight,
            "queue_status": self.queue_status,
            "queued_at_height": self.queued_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub operation_id: String,
    pub sponsor_commitment: String,
    pub credit_root: String,
    pub max_fee_amount: u64,
    pub consumed_fee_amount: u64,
    pub sponsor_fee_bps: u64,
    pub rebate_bps: u64,
    pub status: ReservationStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "operation_id": self.operation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "credit_root": self.credit_root,
            "max_fee_amount": self.max_fee_amount,
            "consumed_fee_amount": self.consumed_fee_amount,
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionBatch {
    pub batch_id: String,
    pub operation_root: String,
    pub approval_root: String,
    pub queue_root: String,
    pub reservation_root: String,
    pub proof_commitment: String,
    pub status: BatchStatus,
    pub operation_count: u64,
    pub sponsor_fee_amount: u64,
    pub rebate_amount: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
}

impl ExecutionBatch {
    pub fn record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "operation_root": self.operation_root,
            "approval_root": self.approval_root,
            "queue_root": self.queue_root,
            "reservation_root": self.reservation_root,
            "proof_commitment": self.proof_commitment,
            "status": self.status,
            "operation_count": self.operation_count,
            "sponsor_fee_amount": self.sponsor_fee_amount,
            "rebate_amount": self.rebate_amount,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub operation_id: String,
    pub reservation_id: String,
    pub kind: ReceiptKind,
    pub execution_root: String,
    pub fee_amount: u64,
    pub rebate_amount: u64,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "operation_id": self.operation_id,
            "reservation_id": self.reservation_id,
            "kind": self.kind,
            "execution_root": self.execution_root,
            "fee_amount": self.fee_amount,
            "rebate_amount": self.rebate_amount,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub sponsor_commitment: String,
    pub rebate_amount: u64,
    pub status: RebateStatus,
    pub claim_after_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_amount": self.rebate_amount,
            "status": self.status,
            "claim_after_height": self.claim_after_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierFence {
    pub nullifier: String,
    pub subject_id: String,
    pub fence_root: String,
    pub status: NullifierFenceStatus,
    pub locked_at_height: u64,
    pub released_at_height: u64,
}

impl NullifierFence {
    pub fn record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "subject_id": self.subject_id,
            "fence_root": self.fence_root,
            "status": self.status,
            "locked_at_height": self.locked_at_height,
            "released_at_height": self.released_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub signer_sets: BTreeMap<String, SignerSet>,
    pub signers: BTreeMap<String, SignerCommitment>,
    pub operations: BTreeMap<String, TimelockOperation>,
    pub approvals: BTreeMap<String, EncryptedApproval>,
    pub queue_entries: BTreeMap<String, TimelockQueueEntry>,
    pub reservations: BTreeMap<String, SponsorReservation>,
    pub batches: BTreeMap<String, ExecutionBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: Vec<Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            signer_sets: BTreeMap::new(),
            signers: BTreeMap::new(),
            operations: BTreeMap::new(),
            approvals: BTreeMap::new(),
            queue_entries: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let height = state.config.devnet_height;
        let label_commitment = payload_root(
            "multisig-timelock:domain-label",
            &json!({"domain": "confidential-contract-upgrades", "scope": "devnet"}),
        );
        let set_id = signer_set_id(
            TimelockDomainKind::ContractUpgrade,
            &label_commitment,
            "devnet-upgrade-set",
            0,
        );
        let signer_root = root_from_values(
            "multisig-timelock:signer-root",
            &["alice-pq", "boron-pq", "cedar-pq", "dahlia-pq", "ember-pq"],
        );
        let signer_set = SignerSet {
            signer_set_id: set_id.clone(),
            domain_kind: TimelockDomainKind::ContractUpgrade,
            label_commitment: label_commitment.clone(),
            signer_root,
            threshold_weight: 3,
            total_weight: 5,
            min_delay_blocks: state.config.min_delay_blocks,
            max_delay_blocks: state.config.max_delay_blocks,
            privacy_set_size: state.config.min_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            status: SignerStatus::Active,
            activated_at_height: height - 10_000,
            expires_at_height: height + 262_800,
        };
        state
            .register_signer_set(signer_set.clone())
            .expect("devnet signer set");

        let signer_id = signer_id(&set_id, "alice-pq", 0);
        let signer = SignerCommitment {
            signer_id: signer_id.clone(),
            signer_set_id: set_id.clone(),
            encrypted_identity_commitment: payload_root(
                "multisig-timelock:signer-identity",
                &json!({"signer": "alice-pq", "suite": "ml-kem-1024"}),
            ),
            pq_key_commitment: payload_root(
                "multisig-timelock:pq-key",
                &json!({"signer": "alice-pq", "scheme": "ml-dsa-87"}),
            ),
            weight: 1,
            status: SignerStatus::Active,
            last_approval_height: height - 2,
            added_at_height: height - 9_950,
        };
        state
            .register_signer(signer.clone())
            .expect("devnet signer");

        let operation_nullifier_value = operation_nullifier(&set_id, "upgrade-vault-router-v2", 0);
        let operation_id = operation_id(
            &set_id,
            OperationKind::UpgradeContract,
            &operation_nullifier_value,
            0,
        );
        let operation = TimelockOperation {
            operation_id: operation_id.clone(),
            signer_set_id: set_id.clone(),
            domain_kind: TimelockDomainKind::ContractUpgrade,
            operation_kind: OperationKind::UpgradeContract,
            encrypted_call_root: payload_root(
                "multisig-timelock:encrypted-call",
                &json!({"target": "private-vault-router", "call": "upgrade_to_v2", "suite": "ml-kem-1024"}),
            ),
            target_contract_commitment: payload_root(
                "multisig-timelock:target-contract",
                &json!({"contract": "private_l2_confidential_vault_strategy_router_runtime"}),
            ),
            value_commitment: payload_root(
                "multisig-timelock:value",
                &json!({"value": "hidden", "asset": "fee-credit"}),
            ),
            dependency_root: root_from_values(
                "multisig-timelock:dependencies",
                &["verifier-cache-ready", "policy-engine-approved"],
            ),
            operation_nullifier: operation_nullifier_value.clone(),
            status: OperationStatus::Queued,
            privacy_set_size: state.config.min_privacy_set_size,
            proposed_at_height: height - 96,
            earliest_execute_height: height + state.config.min_delay_blocks,
            expires_at_height: height + 7_200,
        };
        state
            .submit_operation(operation.clone())
            .expect("devnet operation");

        let approval_nullifier = operation_nullifier(&operation_id, &signer_id, 0);
        let approval = EncryptedApproval {
            approval_id: approval_id(&operation_id, &signer_id, 0),
            operation_id: operation_id.clone(),
            signer_id: signer_id.clone(),
            encrypted_vote_payload: payload_root(
                "multisig-timelock:approval-payload",
                &json!({"vote": "approve", "ciphertext": "devnet-approval-alpha"}),
            ),
            verdict: ApprovalVerdict::Approve,
            weight: signer.weight,
            approval_nullifier: approval_nullifier.clone(),
            pq_signature_commitment: payload_root(
                "multisig-timelock:approval-signature",
                &json!({"signature": "devnet-ml-dsa-signature", "scheme": "ml-dsa-87"}),
            ),
            transcript_root: payload_root(
                "multisig-timelock:approval-transcript",
                &json!({"operation_id": operation_id.clone(), "height": height - 80}),
            ),
            observed_at_height: height - 80,
        };
        state
            .record_approval(approval.clone())
            .expect("devnet approval");

        let queue_entry = TimelockQueueEntry {
            queue_entry_id: queue_entry_id(&operation_id, height - 72, 0),
            operation_id: operation_id.clone(),
            signer_set_id: set_id.clone(),
            approval_root: root_from_record("multisig-timelock:approval", &approval.record()),
            threshold_weight: signer_set.threshold_weight,
            collected_weight: signer_set.threshold_weight,
            queue_status: QueueStatus::Locked,
            queued_at_height: height - 72,
            executable_at_height: height + state.config.min_delay_blocks,
            expires_at_height: height + 7_200,
        };
        state
            .queue_operation(queue_entry.clone())
            .expect("devnet queue");

        let reservation = SponsorReservation {
            reservation_id: sponsor_reservation_id(&operation_id, "multisig-fee-vault", 0),
            operation_id: operation_id.clone(),
            sponsor_commitment: payload_root(
                "multisig-timelock:sponsor",
                &json!({"vault": "multisig-fee-vault", "policy": "low-fee-upgrades"}),
            ),
            credit_root: payload_root(
                "multisig-timelock:sponsor-credit",
                &json!({"credit": "devnet-multisig-credit", "nonce": 42}),
            ),
            max_fee_amount: 880_000,
            consumed_fee_amount: 560_000,
            sponsor_fee_bps: 3,
            rebate_bps: state.config.target_rebate_bps,
            status: ReservationStatus::RebateQueued,
            created_at_height: height - 70,
            expires_at_height: height + 7_200,
        };
        state
            .reserve_sponsor(reservation.clone())
            .expect("devnet reservation");

        let batch_id = execution_batch_id(&set_id, height - 2, 0);
        let batch = ExecutionBatch {
            batch_id: batch_id.clone(),
            operation_root: root_from_record("multisig-timelock:operation", &operation.record()),
            approval_root: root_from_record("multisig-timelock:approval", &approval.record()),
            queue_root: root_from_record("multisig-timelock:queue", &queue_entry.record()),
            reservation_root: root_from_record(
                "multisig-timelock:reservation",
                &reservation.record(),
            ),
            proof_commitment: payload_root(
                "multisig-timelock:batch-proof",
                &json!({"proof": "devnet-recursive-multisig-proof", "backend": "pq"}),
            ),
            status: BatchStatus::Settled,
            operation_count: 1,
            sponsor_fee_amount: reservation.consumed_fee_amount,
            rebate_amount: 280,
            opened_at_height: height - 16,
            sealed_at_height: height - 2,
        };
        state.record_batch(batch.clone()).expect("devnet batch");

        let receipt = SettlementReceipt {
            receipt_id: receipt_id(&batch_id, &operation_id, 0),
            batch_id: batch_id.clone(),
            operation_id: operation_id.clone(),
            reservation_id: reservation.reservation_id.clone(),
            kind: ReceiptKind::OperationQueued,
            execution_root: payload_root(
                "multisig-timelock:execution",
                &json!({"operation_id": operation_id.clone(), "status": "queued"}),
            ),
            fee_amount: reservation.consumed_fee_amount,
            rebate_amount: batch.rebate_amount,
            settled_at_height: height - 1,
        };
        state
            .record_receipt(receipt.clone())
            .expect("devnet receipt");

        let rebate = FeeRebate {
            rebate_id: rebate_id(&receipt.receipt_id, &reservation.sponsor_commitment, 0),
            receipt_id: receipt.receipt_id.clone(),
            sponsor_commitment: reservation.sponsor_commitment,
            rebate_amount: receipt.rebate_amount,
            status: RebateStatus::Claimable,
            claim_after_height: height + 1,
            expires_at_height: height + 7_200,
        };
        state.record_rebate(rebate).expect("devnet rebate");
        state.events.push(json!({
            "kind": "devnet_multisig_timelock_batch",
            "batch_id": batch_id,
            "operation_id": operation_id,
        }));
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn register_signer_set(
        &mut self,
        signer_set: SignerSet,
    ) -> PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<()> {
        if self.signer_sets.len() >= self.config.max_signer_sets {
            return Err("signer set capacity exceeded".to_string());
        }
        if signer_set.threshold_weight == 0 || signer_set.threshold_weight > signer_set.total_weight
        {
            return Err("invalid signer set threshold".to_string());
        }
        if signer_set.min_delay_blocks < self.config.min_delay_blocks {
            return Err("signer set delay below runtime floor".to_string());
        }
        if signer_set.max_delay_blocks > self.config.max_delay_blocks {
            return Err("signer set delay above runtime ceiling".to_string());
        }
        if signer_set.privacy_set_size < self.config.min_privacy_set_size {
            return Err("signer set privacy below runtime floor".to_string());
        }
        if signer_set.pq_security_bits < self.config.min_pq_security_bits {
            return Err("signer set pq security below runtime floor".to_string());
        }
        self.signer_sets
            .insert(signer_set.signer_set_id.clone(), signer_set);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn register_signer(
        &mut self,
        signer: SignerCommitment,
    ) -> PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<()> {
        if self.signers.len() >= self.config.max_signers {
            return Err("signer capacity exceeded".to_string());
        }
        if !self.signer_sets.contains_key(&signer.signer_set_id) {
            return Err("signer references unknown signer set".to_string());
        }
        if signer.weight == 0 {
            return Err("signer weight must be nonzero".to_string());
        }
        self.signers.insert(signer.signer_id.clone(), signer);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn submit_operation(
        &mut self,
        operation: TimelockOperation,
    ) -> PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<()> {
        if self.operations.len() >= self.config.max_operations {
            return Err("operation capacity exceeded".to_string());
        }
        let Some(signer_set) = self.signer_sets.get(&operation.signer_set_id) else {
            return Err("operation references unknown signer set".to_string());
        };
        if !signer_set.status.can_sign() {
            return Err("operation signer set cannot sign".to_string());
        }
        if !operation.status.anchors_state() {
            return Err("operation status is not submittable".to_string());
        }
        if operation.privacy_set_size < self.config.min_privacy_set_size {
            return Err("operation privacy set below runtime floor".to_string());
        }
        if operation
            .earliest_execute_height
            .saturating_sub(operation.proposed_at_height)
            < signer_set.min_delay_blocks
        {
            return Err("operation delay below signer set floor".to_string());
        }
        if self
            .consumed_nullifiers
            .contains(&operation.operation_nullifier)
        {
            return Err("operation nullifier already consumed".to_string());
        }
        let fence = NullifierFence {
            nullifier: operation.operation_nullifier.clone(),
            subject_id: operation.operation_id.clone(),
            fence_root: nullifier_fence_leaf(
                &operation.signer_set_id,
                &operation.operation_nullifier,
            ),
            status: NullifierFenceStatus::Locked,
            locked_at_height: operation.proposed_at_height,
            released_at_height: 0,
        };
        self.consumed_nullifiers
            .insert(operation.operation_nullifier.clone());
        self.nullifier_fences.insert(fence.nullifier.clone(), fence);
        self.operations
            .insert(operation.operation_id.clone(), operation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_approval(
        &mut self,
        approval: EncryptedApproval,
    ) -> PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<()> {
        if self.approvals.len() >= self.config.max_approvals {
            return Err("approval capacity exceeded".to_string());
        }
        let Some(operation) = self.operations.get(&approval.operation_id) else {
            return Err("approval references unknown operation".to_string());
        };
        if !operation.status.accepts_approval() {
            return Err("operation does not accept approvals".to_string());
        }
        let Some(signer) = self.signers.get(&approval.signer_id) else {
            return Err("approval references unknown signer".to_string());
        };
        if !signer.status.can_sign() {
            return Err("signer cannot approve".to_string());
        }
        if self
            .consumed_nullifiers
            .contains(&approval.approval_nullifier)
        {
            return Err("approval nullifier already consumed".to_string());
        }
        let fence = NullifierFence {
            nullifier: approval.approval_nullifier.clone(),
            subject_id: approval.approval_id.clone(),
            fence_root: nullifier_fence_leaf(
                &operation.signer_set_id,
                &approval.approval_nullifier,
            ),
            status: NullifierFenceStatus::Locked,
            locked_at_height: approval.observed_at_height,
            released_at_height: 0,
        };
        self.consumed_nullifiers
            .insert(approval.approval_nullifier.clone());
        self.nullifier_fences.insert(fence.nullifier.clone(), fence);
        self.approvals
            .insert(approval.approval_id.clone(), approval);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn queue_operation(
        &mut self,
        queue_entry: TimelockQueueEntry,
    ) -> PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<()> {
        if self.queue_entries.len() >= self.config.max_queue_entries {
            return Err("queue capacity exceeded".to_string());
        }
        let Some(signer_set) = self.signer_sets.get(&queue_entry.signer_set_id) else {
            return Err("queue entry references unknown signer set".to_string());
        };
        if !self.operations.contains_key(&queue_entry.operation_id) {
            return Err("queue entry references unknown operation".to_string());
        }
        if queue_entry.collected_weight < signer_set.threshold_weight {
            return Err("queue entry below signer set threshold".to_string());
        }
        if queue_entry.executable_at_height < queue_entry.queued_at_height {
            return Err("queue executable height before queued height".to_string());
        }
        self.queue_entries
            .insert(queue_entry.queue_entry_id.clone(), queue_entry);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn reserve_sponsor(
        &mut self,
        reservation: SponsorReservation,
    ) -> PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<()> {
        if self.reservations.len() >= self.config.max_reservations {
            return Err("reservation capacity exceeded".to_string());
        }
        if !self.operations.contains_key(&reservation.operation_id) {
            return Err("reservation references unknown operation".to_string());
        }
        if reservation.sponsor_fee_bps > self.config.max_sponsor_fee_bps {
            return Err("reservation sponsor fee above runtime ceiling".to_string());
        }
        if reservation.consumed_fee_amount > reservation.max_fee_amount {
            return Err("reservation consumed fee exceeds max fee".to_string());
        }
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_batch(
        &mut self,
        batch: ExecutionBatch,
    ) -> PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<()> {
        if self.batches.len() >= self.config.max_batches {
            return Err("batch capacity exceeded".to_string());
        }
        if batch.operation_count as usize > self.config.max_batch_operations {
            return Err("batch operation count exceeds runtime limit".to_string());
        }
        if !batch.status.anchors_state() && batch.status != BatchStatus::Open {
            return Err("batch status is not recordable".to_string());
        }
        self.batches.insert(batch.batch_id.clone(), batch);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("receipt capacity exceeded".to_string());
        }
        if !self.batches.contains_key(&receipt.batch_id) {
            return Err("receipt references unknown batch".to_string());
        }
        if !self.operations.contains_key(&receipt.operation_id) {
            return Err("receipt references unknown operation".to_string());
        }
        if !self.reservations.contains_key(&receipt.reservation_id) {
            return Err("receipt references unknown reservation".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_rebate(
        &mut self,
        rebate: FeeRebate,
    ) -> PrivateL2ConfidentialContractMultisigTimelockRuntimeResult<()> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("rebate capacity exceeded".to_string());
        }
        if !self.receipts.contains_key(&rebate.receipt_id) {
            return Err("rebate references unknown receipt".to_string());
        }
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            signer_set_count: self.signer_sets.len() as u64,
            active_signer_set_count: self
                .signer_sets
                .values()
                .filter(|set| set.status.can_sign())
                .count() as u64,
            signer_count: self.signers.len() as u64,
            active_signer_count: self
                .signers
                .values()
                .filter(|signer| signer.status.can_sign())
                .count() as u64,
            operation_count: self.operations.len() as u64,
            live_operation_count: self
                .operations
                .values()
                .filter(|operation| operation.status.accepts_approval())
                .count() as u64,
            approval_count: self.approvals.len() as u64,
            threshold_approval_count: self
                .approvals
                .values()
                .filter(|approval| approval.verdict.counts_for_threshold())
                .count() as u64,
            queue_entry_count: self.queue_entries.len() as u64,
            live_queue_entry_count: self
                .queue_entries
                .values()
                .filter(|entry| entry.queue_status.is_live())
                .count() as u64,
            reservation_count: self.reservations.len() as u64,
            batch_count: self.batches.len() as u64,
            settled_batch_count: self
                .batches
                .values()
                .filter(|batch| batch.status == BatchStatus::Settled)
                .count() as u64,
            receipt_count: self.receipts.len() as u64,
            rebate_count: self.rebates.len() as u64,
            locked_nullifier_count: self
                .nullifier_fences
                .values()
                .filter(|fence| fence.status == NullifierFenceStatus::Locked)
                .count() as u64,
            event_count: self.events.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        let signer_set_records = self
            .signer_sets
            .values()
            .map(SignerSet::record)
            .collect::<Vec<_>>();
        let active_signer_set_records = self
            .signer_sets
            .values()
            .filter(|set| set.status.can_sign())
            .map(SignerSet::record)
            .collect::<Vec<_>>();
        let signer_records = self
            .signers
            .values()
            .map(SignerCommitment::record)
            .collect::<Vec<_>>();
        let active_signer_records = self
            .signers
            .values()
            .filter(|signer| signer.status.can_sign())
            .map(SignerCommitment::record)
            .collect::<Vec<_>>();
        let operation_records = self
            .operations
            .values()
            .map(TimelockOperation::record)
            .collect::<Vec<_>>();
        let live_operation_records = self
            .operations
            .values()
            .filter(|operation| operation.status.accepts_approval())
            .map(TimelockOperation::record)
            .collect::<Vec<_>>();
        let approval_records = self
            .approvals
            .values()
            .map(EncryptedApproval::record)
            .collect::<Vec<_>>();
        let threshold_approval_records = self
            .approvals
            .values()
            .filter(|approval| approval.verdict.counts_for_threshold())
            .map(EncryptedApproval::record)
            .collect::<Vec<_>>();
        let queue_records = self
            .queue_entries
            .values()
            .map(TimelockQueueEntry::record)
            .collect::<Vec<_>>();
        let live_queue_records = self
            .queue_entries
            .values()
            .filter(|entry| entry.queue_status.is_live())
            .map(TimelockQueueEntry::record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .reservations
            .values()
            .map(SponsorReservation::record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(ExecutionBatch::record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(SettlementReceipt::record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebates
            .values()
            .map(FeeRebate::record)
            .collect::<Vec<_>>();
        let nullifier_fence_records = self
            .nullifier_fences
            .values()
            .map(NullifierFence::record)
            .collect::<Vec<_>>();
        let consumed_nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| json!({"nullifier": nullifier}))
            .collect::<Vec<_>>();

        self.roots.signer_set_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-SIGNER-SETS",
            &signer_set_records,
        );
        self.roots.active_signer_set_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-ACTIVE-SIGNER-SETS",
            &active_signer_set_records,
        );
        self.roots.signer_root =
            merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-SIGNERS", &signer_records);
        self.roots.active_signer_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-ACTIVE-SIGNERS",
            &active_signer_records,
        );
        self.roots.operation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-OPERATIONS",
            &operation_records,
        );
        self.roots.live_operation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-LIVE-OPERATIONS",
            &live_operation_records,
        );
        self.roots.approval_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-APPROVALS",
            &approval_records,
        );
        self.roots.threshold_approval_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-THRESHOLD-APPROVALS",
            &threshold_approval_records,
        );
        self.roots.queue_root =
            merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-QUEUE", &queue_records);
        self.roots.live_queue_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-LIVE-QUEUE",
            &live_queue_records,
        );
        self.roots.reservation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-RESERVATIONS",
            &reservation_records,
        );
        self.roots.batch_root =
            merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-BATCHES", &batch_records);
        self.roots.receipt_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-RECEIPTS",
            &receipt_records,
        );
        self.roots.rebate_root =
            merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-REBATES", &rebate_records);
        self.roots.nullifier_fence_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-NULLIFIER-FENCES",
            &nullifier_fence_records,
        );
        self.roots.consumed_nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-MULTISIG-CONSUMED-NULLIFIERS",
            &consumed_nullifier_records,
        );
        self.roots.event_root =
            merkle_root("PRIVATE-L2-CONFIDENTIAL-MULTISIG-EVENTS", &self.events);
        let record = self.public_record();
        self.roots.public_record_root =
            root_from_record("PRIVATE-L2-CONFIDENTIAL-MULTISIG-PUBLIC-RECORD", &record);
        self.roots.state_root = state_root_from_record(&record);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "counters": self.counters,
            "roots": self.roots,
            "limits": {
                "max_signer_sets": self.config.max_signer_sets,
                "max_signers": self.config.max_signers,
                "max_operations": self.config.max_operations,
                "max_batch_operations": self.config.max_batch_operations,
                "min_delay_blocks": self.config.min_delay_blocks,
                "max_delay_blocks": self.config.max_delay_blocks,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "target_rebate_bps": self.config.target_rebate_bps,
                "max_sponsor_fee_bps": self.config.max_sponsor_fee_bps,
            },
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_confidential_contract_multisig_timelock_runtime_public_record() -> Value {
    State::devnet().public_record()
}

pub fn private_l2_confidential_contract_multisig_timelock_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn signer_set_id(
    domain_kind: TimelockDomainKind,
    label_commitment: &str,
    salt: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-SIGNER-SET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain_kind.as_str()),
            HashPart::Str(label_commitment),
            HashPart::Str(salt),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn signer_id(signer_set_id: &str, signer_label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-SIGNER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_set_id),
            HashPart::Str(signer_label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn operation_id(
    signer_set_id: &str,
    operation_kind: OperationKind,
    nullifier: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-OPERATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_set_id),
            HashPart::Str(operation_kind.as_str()),
            HashPart::Str(nullifier),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn approval_id(operation_id: &str, signer_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operation_id),
            HashPart::Str(signer_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn queue_entry_id(operation_id: &str, queued_at_height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-QUEUE-ENTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operation_id),
            HashPart::U64(queued_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(operation_id: &str, sponsor_label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operation_id),
            HashPart::Str(sponsor_label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn execution_batch_id(signer_set_id: &str, sealed_at_height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-EXECUTION-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_set_id),
            HashPart::U64(sealed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn receipt_id(batch_id: &str, operation_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(operation_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, sponsor_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn operation_nullifier(scope_id: &str, label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-OPERATION-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope_id),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn nullifier_fence_leaf(scope_id: &str, nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-MULTISIG-NULLIFIER-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_CONFIDENTIAL_CONTRACT_MULTISIG_TIMELOCK_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-CONFIDENTIAL-MULTISIG-STATE-ROOT", record)
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let records = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}
