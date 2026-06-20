use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeeCrossContractBatchSettlementRuntimeResult<T> = Result<T>;

pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-cross-contract-batch-settlement-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_TICKET_SCHEME: &str =
    "ml-kem-1024+zk-encrypted-cross-contract-batch-ticket-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_CALL_GROUP_SCHEME: &str =
    "roots-only-private-contract-call-group-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-cross-contract-sponsor-reservation-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_PROOF_AGGREGATION_SCHEME: &str =
    "recursive-pq-proof-aggregation-slot-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_RECEIPT_SCHEME: &str =
    "zk-pq-cross-contract-batch-settlement-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_REBATE_SCHEME: &str =
    "private-cross-contract-fee-rebate-credit-root-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_QUARANTINE_SCHEME: &str =
    "failure-quarantine-private-call-group-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_PRIVACY_FENCE_SCHEME: &str =
    "nullifier-fenced-cross-contract-settlement-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_PQ_COMMITMENT_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-pq-settlement-commitment-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT: u64 = 1_238_000;
pub const DEFAULT_MAX_BATCH_TICKETS: usize = 4_194_304;
pub const DEFAULT_MAX_CALL_GROUPS: usize = 1_048_576;
pub const DEFAULT_MAX_CALLS_PER_GROUP: usize = 128;
pub const DEFAULT_MAX_SPONSOR_RESERVATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_PROOF_SLOTS: usize = 524_288;
pub const DEFAULT_MAX_SETTLEMENT_BATCHES: usize = 262_144;
pub const DEFAULT_MAX_SETTLEMENT_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_REBATE_CREDITS: usize = 2_097_152;
pub const DEFAULT_MAX_FAILURE_QUARANTINES: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIERS: usize = 33_554_432;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_CALL_GROUP_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_PROOF_SLOT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_MIN_TICKET_PRIVACY_SET_SIZE: u64 = 512;
pub const DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 2_048;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 18;
pub const DEFAULT_MIN_COMPRESSION_RATIO_BPS: u64 = 4_500;
pub const DEFAULT_MAX_AGGREGATED_PROOF_BYTES: u64 = 2_097_152;
pub const DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 = 480_000_000;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 32_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomainKind {
    Dex,
    Lending,
    StableSwap,
    Vault,
    Perps,
    Options,
    Governance,
    Bridge,
    Oracle,
    Treasury,
}

impl ContractDomainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::StableSwap => "stable_swap",
            Self::Vault => "vault",
            Self::Perps => "perps",
            Self::Options => "options",
            Self::Governance => "governance",
            Self::Bridge => "bridge",
            Self::Oracle => "oracle",
            Self::Treasury => "treasury",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchTicketKind {
    AtomicCall,
    ComposableSwap,
    VaultRebalance,
    LiquidationBundle,
    OracleRefresh,
    GovernanceAction,
    BridgeFinalize,
    SponsoredMaintenance,
}

impl BatchTicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AtomicCall => "atomic_call",
            Self::ComposableSwap => "composable_swap",
            Self::VaultRebalance => "vault_rebalance",
            Self::LiquidationBundle => "liquidation_bundle",
            Self::OracleRefresh => "oracle_refresh",
            Self::GovernanceAction => "governance_action",
            Self::BridgeFinalize => "bridge_finalize",
            Self::SponsoredMaintenance => "sponsored_maintenance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchTicketStatus {
    Submitted,
    Grouped,
    Sponsored,
    Proving,
    Settled,
    Quarantined,
    Rejected,
    Expired,
}

impl BatchTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Grouped => "grouped",
            Self::Sponsored => "sponsored",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn groupable(self) -> bool {
        matches!(self, Self::Submitted | Self::Grouped | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallGroupStatus {
    Draft,
    Open,
    Sponsored,
    Slotted,
    Batched,
    Settled,
    Quarantined,
    Expired,
}

impl CallGroupStatus {
    pub fn batchable(self) -> bool {
        matches!(self, Self::Sponsored | Self::Slotted | Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Attached,
    Consumed,
    RebateQueued,
    Released,
    Expired,
}

impl SponsorReservationStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Reserved | Self::Attached)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSlotStatus {
    Reserved,
    Filling,
    Aggregating,
    Proven,
    Failed,
    Expired,
}

impl ProofSlotStatus {
    pub fn accepts_group(self) -> bool {
        matches!(self, Self::Reserved | Self::Filling | Self::Aggregating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Open,
    Sealed,
    Proving,
    Settled,
    PartiallySettled,
    Quarantined,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptKind {
    BatchSettled,
    GroupSettled,
    SponsorCharged,
    RebateCredited,
    FailureQuarantined,
    PrivacyFenceAnchored,
}

impl SettlementReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchSettled => "batch_settled",
            Self::GroupSettled => "group_settled",
            Self::SponsorCharged => "sponsor_charged",
            Self::RebateCredited => "rebate_credited",
            Self::FailureQuarantined => "failure_quarantined",
            Self::PrivacyFenceAnchored => "privacy_fence_anchored",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    ProofFailure,
    ContractRevert,
    FeeShortfall,
    NullifierConflict,
    PrivacySetTooSmall,
    StateRootMismatch,
    Timeout,
    OperatorChallenge,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProofFailure => "proof_failure",
            Self::ContractRevert => "contract_revert",
            Self::FeeShortfall => "fee_shortfall",
            Self::NullifierConflict => "nullifier_conflict",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::StateRootMismatch => "state_root_mismatch",
            Self::Timeout => "timeout",
            Self::OperatorChallenge => "operator_challenge",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub ticket_scheme: String,
    pub call_group_scheme: String,
    pub sponsor_scheme: String,
    pub proof_aggregation_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub quarantine_scheme: String,
    pub privacy_fence_scheme: String,
    pub pq_commitment_scheme: String,
    pub max_batch_tickets: usize,
    pub max_call_groups: usize,
    pub max_calls_per_group: usize,
    pub max_sponsor_reservations: usize,
    pub max_proof_slots: usize,
    pub max_settlement_batches: usize,
    pub max_settlement_receipts: usize,
    pub max_rebate_credits: usize,
    pub max_failure_quarantines: usize,
    pub max_nullifiers: usize,
    pub ticket_ttl_blocks: u64,
    pub call_group_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub proof_slot_ttl_blocks: u64,
    pub min_ticket_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_compression_ratio_bps: u64,
    pub max_aggregated_proof_bytes: u64,
    pub sponsor_budget_micro_units: u64,
    pub low_fee_target_micro_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_HASH_SUITE.to_string(),
            ticket_scheme: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_TICKET_SCHEME
                .to_string(),
            call_group_scheme: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_CALL_GROUP_SCHEME
                .to_string(),
            sponsor_scheme: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_SPONSOR_SCHEME
                .to_string(),
            proof_aggregation_scheme:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_PROOF_AGGREGATION_SCHEME
                    .to_string(),
            receipt_scheme: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_RECEIPT_SCHEME
                .to_string(),
            rebate_scheme: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_REBATE_SCHEME
                .to_string(),
            quarantine_scheme: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_QUARANTINE_SCHEME
                .to_string(),
            privacy_fence_scheme:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_PRIVACY_FENCE_SCHEME.to_string(),
            pq_commitment_scheme:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_PQ_COMMITMENT_SCHEME.to_string(),
            max_batch_tickets: DEFAULT_MAX_BATCH_TICKETS,
            max_call_groups: DEFAULT_MAX_CALL_GROUPS,
            max_calls_per_group: DEFAULT_MAX_CALLS_PER_GROUP,
            max_sponsor_reservations: DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_proof_slots: DEFAULT_MAX_PROOF_SLOTS,
            max_settlement_batches: DEFAULT_MAX_SETTLEMENT_BATCHES,
            max_settlement_receipts: DEFAULT_MAX_SETTLEMENT_RECEIPTS,
            max_rebate_credits: DEFAULT_MAX_REBATE_CREDITS,
            max_failure_quarantines: DEFAULT_MAX_FAILURE_QUARANTINES,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            call_group_ttl_blocks: DEFAULT_CALL_GROUP_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            proof_slot_ttl_blocks: DEFAULT_PROOF_SLOT_TTL_BLOCKS,
            min_ticket_privacy_set_size: DEFAULT_MIN_TICKET_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size: DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps: DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_compression_ratio_bps: DEFAULT_MIN_COMPRESSION_RATIO_BPS,
            max_aggregated_proof_bytes: DEFAULT_MAX_AGGREGATED_PROOF_BYTES,
            sponsor_budget_micro_units: DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedBatchTicket {
    pub ticket_id: String,
    pub ticket_kind: BatchTicketKind,
    pub status: BatchTicketStatus,
    pub owner_commitment: String,
    pub contract_domain: ContractDomainKind,
    pub target_contract_commitment: String,
    pub encrypted_call_root: String,
    pub call_witness_root: String,
    pub max_user_fee_micro_units: u64,
    pub user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
    pub pq_commitment_root: String,
    pub nullifier: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub group_id: Option<String>,
}

impl EncryptedBatchTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "ticket_kind": self.ticket_kind,
            "status": self.status,
            "owner_commitment": self.owner_commitment,
            "contract_domain": self.contract_domain,
            "target_contract_commitment": self.target_contract_commitment,
            "encrypted_call_root": self.encrypted_call_root,
            "call_witness_root": self.call_witness_root,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "user_fee_bps": self.user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "pq_commitment_root": self.pq_commitment_root,
            "nullifier": self.nullifier,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "group_id": self.group_id,
        })
    }

    pub fn ticket_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-TICKET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ContractCallGroup {
    pub group_id: String,
    pub status: CallGroupStatus,
    pub coordinator_commitment: String,
    pub contract_domain: ContractDomainKind,
    pub ticket_ids: Vec<String>,
    pub contract_commitment_root: String,
    pub call_graph_root: String,
    pub dependency_root: String,
    pub aggregated_call_witness_root: String,
    pub expected_state_read_root: String,
    pub expected_state_write_root: String,
    pub privacy_fence_root: String,
    pub combined_nullifier_root: String,
    pub low_fee_score: u128,
    pub estimated_gas_units: u64,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sponsor_reservation_id: Option<String>,
    pub proof_slot_id: Option<String>,
    pub settlement_batch_id: Option<String>,
}

impl ContractCallGroup {
    pub fn compression_ratio_bps(&self) -> u64 {
        if self.uncompressed_bytes == 0 {
            return 0;
        }
        self.compressed_bytes
            .saturating_mul(MAX_BPS)
            .saturating_div(self.uncompressed_bytes)
            .min(MAX_BPS)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "group_id": self.group_id,
            "status": self.status,
            "coordinator_commitment": self.coordinator_commitment,
            "contract_domain": self.contract_domain,
            "ticket_ids": self.ticket_ids,
            "contract_commitment_root": self.contract_commitment_root,
            "call_graph_root": self.call_graph_root,
            "dependency_root": self.dependency_root,
            "aggregated_call_witness_root": self.aggregated_call_witness_root,
            "expected_state_read_root": self.expected_state_read_root,
            "expected_state_write_root": self.expected_state_write_root,
            "privacy_fence_root": self.privacy_fence_root,
            "combined_nullifier_root": self.combined_nullifier_root,
            "low_fee_score": self.low_fee_score.to_string(),
            "estimated_gas_units": self.estimated_gas_units,
            "compressed_bytes": self.compressed_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "compression_ratio_bps": self.compression_ratio_bps(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "proof_slot_id": self.proof_slot_id,
            "settlement_batch_id": self.settlement_batch_id,
        })
    }

    pub fn group_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-GROUP",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeSponsorReservation {
    pub reservation_id: String,
    pub status: SponsorReservationStatus,
    pub sponsor_commitment: String,
    pub group_ids: Vec<String>,
    pub ticket_root: String,
    pub fee_cap_micro_units: u64,
    pub reserved_micro_units: u64,
    pub consumed_micro_units: u64,
    pub sponsor_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub privacy_budget_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorReservation {
    pub fn remaining_micro_units(&self) -> u64 {
        self.reserved_micro_units
            .saturating_sub(self.consumed_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "status": self.status,
            "sponsor_commitment": self.sponsor_commitment,
            "group_ids": self.group_ids,
            "ticket_root": self.ticket_root,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "consumed_micro_units": self.consumed_micro_units,
            "remaining_micro_units": self.remaining_micro_units(),
            "sponsor_fee_bps": self.sponsor_fee_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "privacy_budget_root": self.privacy_budget_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProofAggregationSlot {
    pub slot_id: String,
    pub status: ProofSlotStatus,
    pub aggregator_commitment: String,
    pub group_ids: Vec<String>,
    pub group_root: String,
    pub recursive_circuit_root: String,
    pub public_input_root: String,
    pub aggregated_proof_root: String,
    pub proof_bytes: u64,
    pub pq_attestation_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub sealed_at_height: Option<u64>,
}

impl ProofAggregationSlot {
    pub fn public_record(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "status": self.status,
            "aggregator_commitment": self.aggregator_commitment,
            "group_ids": self.group_ids,
            "group_root": self.group_root,
            "recursive_circuit_root": self.recursive_circuit_root,
            "public_input_root": self.public_input_root,
            "aggregated_proof_root": self.aggregated_proof_root,
            "proof_bytes": self.proof_bytes,
            "pq_attestation_root": self.pq_attestation_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "sealed_at_height": self.sealed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub status: SettlementBatchStatus,
    pub builder_commitment: String,
    pub group_ids: Vec<String>,
    pub ticket_root: String,
    pub group_root: String,
    pub reservation_root: String,
    pub proof_slot_root: String,
    pub state_read_root: String,
    pub state_write_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub fee_debit_root: String,
    pub rebate_credit_root: String,
    pub aggregate_proof_root: String,
    pub low_fee_score: u128,
    pub total_user_fee_micro_units: u64,
    pub total_sponsor_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status,
            "builder_commitment": self.builder_commitment,
            "group_ids": self.group_ids,
            "ticket_root": self.ticket_root,
            "group_root": self.group_root,
            "reservation_root": self.reservation_root,
            "proof_slot_root": self.proof_slot_root,
            "state_read_root": self.state_read_root,
            "state_write_root": self.state_write_root,
            "privacy_fence_root": self.privacy_fence_root,
            "nullifier_root": self.nullifier_root,
            "fee_debit_root": self.fee_debit_root,
            "rebate_credit_root": self.rebate_credit_root,
            "aggregate_proof_root": self.aggregate_proof_root,
            "low_fee_score": self.low_fee_score.to_string(),
            "total_user_fee_micro_units": self.total_user_fee_micro_units,
            "total_sponsor_fee_micro_units": self.total_sponsor_fee_micro_units,
            "total_rebate_micro_units": self.total_rebate_micro_units,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub receipt_kind: SettlementReceiptKind,
    pub batch_id: String,
    pub group_id: Option<String>,
    pub ticket_root: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub fee_debit_root: String,
    pub rebate_credit_root: String,
    pub nullifier_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind,
            "batch_id": self.batch_id,
            "group_id": self.group_id,
            "ticket_root": self.ticket_root,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "fee_debit_root": self.fee_debit_root,
            "rebate_credit_root": self.rebate_credit_root,
            "nullifier_root": self.nullifier_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RebateCredit {
    pub rebate_id: String,
    pub receipt_id: String,
    pub reservation_id: Option<String>,
    pub sponsor_commitment: String,
    pub recipient_commitment: String,
    pub credit_micro_units: u64,
    pub rebate_bps: u64,
    pub claim_root: String,
    pub claimed_nullifier_root: String,
    pub credited_at_height: u64,
}

impl RebateCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "recipient_commitment": self.recipient_commitment,
            "credit_micro_units": self.credit_micro_units,
            "rebate_bps": self.rebate_bps,
            "claim_root": self.claim_root,
            "claimed_nullifier_root": self.claimed_nullifier_root,
            "credited_at_height": self.credited_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FailureQuarantine {
    pub quarantine_id: String,
    pub reason: QuarantineReason,
    pub batch_id: Option<String>,
    pub group_id: Option<String>,
    pub ticket_root: String,
    pub failure_root: String,
    pub recovery_hint_root: String,
    pub released_nullifier_root: String,
    pub quarantined_at_height: u64,
    pub review_after_height: u64,
}

impl FailureQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "reason": self.reason,
            "batch_id": self.batch_id,
            "group_id": self.group_id,
            "ticket_root": self.ticket_root,
            "failure_root": self.failure_root,
            "recovery_hint_root": self.recovery_hint_root,
            "released_nullifier_root": self.released_nullifier_root,
            "quarantined_at_height": self.quarantined_at_height,
            "review_after_height": self.review_after_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub scope_id: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub fence_leaf_root: String,
    pub anchored_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "scope_id": self.scope_id,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "fence_leaf_root": self.fence_leaf_root,
            "anchored_at_height": self.anchored_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubmitBatchTicketRequest {
    pub ticket_kind: BatchTicketKind,
    pub owner_commitment: String,
    pub contract_domain: ContractDomainKind,
    pub target_contract_commitment: String,
    pub encrypted_call_root: String,
    pub call_witness_root: String,
    pub max_user_fee_micro_units: u64,
    pub user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
    pub pq_commitment_root: String,
    pub nullifier: String,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OpenCallGroupRequest {
    pub coordinator_commitment: String,
    pub contract_domain: ContractDomainKind,
    pub ticket_ids: Vec<String>,
    pub contract_commitment_root: String,
    pub call_graph_root: String,
    pub dependency_root: String,
    pub aggregated_call_witness_root: String,
    pub expected_state_read_root: String,
    pub expected_state_write_root: String,
    pub privacy_fence_root: String,
    pub combined_nullifier_root: String,
    pub estimated_gas_units: u64,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReserveFeeSponsorRequest {
    pub sponsor_commitment: String,
    pub group_ids: Vec<String>,
    pub ticket_root: String,
    pub fee_cap_micro_units: u64,
    pub reserved_micro_units: u64,
    pub sponsor_fee_bps: u64,
    pub rebate_commitment_root: String,
    pub privacy_budget_root: String,
    pub reserved_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReserveProofSlotRequest {
    pub aggregator_commitment: String,
    pub group_ids: Vec<String>,
    pub group_root: String,
    pub recursive_circuit_root: String,
    pub public_input_root: String,
    pub aggregated_proof_root: String,
    pub proof_bytes: u64,
    pub pq_attestation_root: String,
    pub reserved_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BuildSettlementBatchRequest {
    pub builder_commitment: String,
    pub group_ids: Vec<String>,
    pub ticket_root: String,
    pub group_root: String,
    pub reservation_root: String,
    pub proof_slot_root: String,
    pub state_read_root: String,
    pub state_write_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub fee_debit_root: String,
    pub rebate_credit_root: String,
    pub aggregate_proof_root: String,
    pub total_user_fee_micro_units: u64,
    pub total_sponsor_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub built_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub fee_debit_root: String,
    pub rebate_credit_root: String,
    pub nullifier_root: String,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RecordRebateCreditRequest {
    pub receipt_id: String,
    pub reservation_id: Option<String>,
    pub sponsor_commitment: String,
    pub recipient_commitment: String,
    pub credit_micro_units: u64,
    pub rebate_bps: u64,
    pub claim_root: String,
    pub claimed_nullifier_root: String,
    pub credited_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct QuarantineFailureRequest {
    pub reason: QuarantineReason,
    pub batch_id: Option<String>,
    pub group_id: Option<String>,
    pub ticket_root: String,
    pub failure_root: String,
    pub recovery_hint_root: String,
    pub released_nullifier_root: String,
    pub quarantined_at_height: u64,
    pub review_after_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AnchorPrivacyFenceRequest {
    pub scope_id: String,
    pub nullifiers: Vec<String>,
    pub privacy_set_size: u64,
    pub anchored_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub tickets_submitted: u64,
    pub call_groups_opened: u64,
    pub sponsor_reservations: u64,
    pub proof_slots_reserved: u64,
    pub settlement_batches_built: u64,
    pub settlement_receipts: u64,
    pub rebate_credits: u64,
    pub failure_quarantines: u64,
    pub privacy_fences: u64,
    pub nullifiers_consumed: u64,
    pub events_emitted: u64,
    pub total_user_fee_micro_units: u64,
    pub total_sponsor_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            tickets_submitted: 0,
            call_groups_opened: 0,
            sponsor_reservations: 0,
            proof_slots_reserved: 0,
            settlement_batches_built: 0,
            settlement_receipts: 0,
            rebate_credits: 0,
            failure_quarantines: 0,
            privacy_fences: 0,
            nullifiers_consumed: 0,
            events_emitted: 0,
            total_user_fee_micro_units: 0,
            total_sponsor_fee_micro_units: 0,
            total_rebate_micro_units: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub ticket_root: String,
    pub call_group_root: String,
    pub sponsor_reservation_root: String,
    pub proof_slot_root: String,
    pub settlement_batch_root: String,
    pub settlement_receipt_root: String,
    pub rebate_credit_root: String,
    pub failure_quarantine_root: String,
    pub privacy_fence_root: String,
    pub consumed_nullifier_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            ticket_root: merkle_root("PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-TICKETS", &[]),
            call_group_root: merkle_root("PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-GROUPS", &[]),
            sponsor_reservation_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SPONSOR-RESERVATIONS",
                &[],
            ),
            proof_slot_root: merkle_root("PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PROOF-SLOTS", &[]),
            settlement_batch_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SETTLEMENT-BATCHES",
                &[],
            ),
            settlement_receipt_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SETTLEMENT-RECEIPTS",
                &[],
            ),
            rebate_credit_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-REBATE-CREDITS",
                &[],
            ),
            failure_quarantine_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-FAILURE-QUARANTINES",
                &[],
            ),
            privacy_fence_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PRIVACY-FENCES",
                &[],
            ),
            consumed_nullifier_root: merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CONSUMED-NULLIFIERS",
                &[],
            ),
            event_root: merkle_root("PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-EVENTS", &[]),
            public_record_root: domain_hash(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PUBLIC-RECORD-ROOT:empty",
                &[HashPart::Str(CHAIN_ID)],
                32,
            ),
            state_root: domain_hash(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-STATE-ROOT:empty",
                &[HashPart::Str(CHAIN_ID)],
                32,
            ),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub batch_tickets: BTreeMap<String, EncryptedBatchTicket>,
    pub call_groups: BTreeMap<String, ContractCallGroup>,
    pub sponsor_reservations: BTreeMap<String, FeeSponsorReservation>,
    pub proof_slots: BTreeMap<String, ProofAggregationSlot>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebate_credits: BTreeMap<String, RebateCredit>,
    pub failure_quarantines: BTreeMap<String, FailureQuarantine>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            batch_tickets: BTreeMap::new(),
            call_groups: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            proof_slots: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebate_credits: BTreeMap::new(),
            failure_quarantines: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let ticket_a = state
            .submit_batch_ticket(SubmitBatchTicketRequest {
                ticket_kind: BatchTicketKind::ComposableSwap,
                owner_commitment: commitment("alice-owner"),
                contract_domain: ContractDomainKind::Dex,
                target_contract_commitment: commitment("private-stable-swap"),
                encrypted_call_root: sample_root("alice-encrypted-call"),
                call_witness_root: sample_root("alice-call-witness"),
                max_user_fee_micro_units: 18_000,
                user_fee_bps: 6,
                privacy_set_size: 4_096,
                pq_ciphertext_root: sample_root("alice-pq-ciphertext"),
                pq_commitment_root: sample_root("alice-pq-commitment"),
                nullifier: operation_nullifier("alice", "swap", 0),
                submitted_at_height:
                    PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT,
            })
            .expect("devnet ticket a");
        let ticket_b = state
            .submit_batch_ticket(SubmitBatchTicketRequest {
                ticket_kind: BatchTicketKind::VaultRebalance,
                owner_commitment: commitment("vault-owner"),
                contract_domain: ContractDomainKind::Vault,
                target_contract_commitment: commitment("private-yield-vault"),
                encrypted_call_root: sample_root("vault-encrypted-call"),
                call_witness_root: sample_root("vault-call-witness"),
                max_user_fee_micro_units: 22_000,
                user_fee_bps: 7,
                privacy_set_size: 4_096,
                pq_ciphertext_root: sample_root("vault-pq-ciphertext"),
                pq_commitment_root: sample_root("vault-pq-commitment"),
                nullifier: operation_nullifier("vault", "rebalance", 0),
                submitted_at_height:
                    PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT + 1,
            })
            .expect("devnet ticket b");
        let group = state
            .open_call_group(OpenCallGroupRequest {
                coordinator_commitment: commitment("batch-coordinator"),
                contract_domain: ContractDomainKind::Dex,
                ticket_ids: vec![ticket_a.ticket_id.clone(), ticket_b.ticket_id.clone()],
                contract_commitment_root: root_from_values(
                    "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-DEVNET-CONTRACTS",
                    &[
                        &ticket_a.target_contract_commitment,
                        &ticket_b.target_contract_commitment,
                    ],
                ),
                call_graph_root: sample_root("call-graph"),
                dependency_root: sample_root("dependency"),
                aggregated_call_witness_root: sample_root("aggregated-witness"),
                expected_state_read_root: sample_root("state-read"),
                expected_state_write_root: sample_root("state-write"),
                privacy_fence_root: sample_root("privacy-fence"),
                combined_nullifier_root: root_from_values(
                    "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-DEVNET-NULLIFIERS",
                    &[&ticket_a.nullifier, &ticket_b.nullifier],
                ),
                estimated_gas_units: 188_000,
                compressed_bytes: 18_432,
                uncompressed_bytes: 59_904,
                opened_at_height: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT
                    + 2,
            })
            .expect("devnet call group");
        let reservation = state
            .reserve_fee_sponsor(ReserveFeeSponsorRequest {
                sponsor_commitment: commitment("fee-sponsor"),
                group_ids: vec![group.group_id.clone()],
                ticket_root: root_from_values(
                    "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-DEVNET-TICKET-IDS",
                    &[&ticket_a.ticket_id, &ticket_b.ticket_id],
                ),
                fee_cap_micro_units: 64_000,
                reserved_micro_units: 42_000,
                sponsor_fee_bps: 3,
                rebate_commitment_root: sample_root("rebate-commitment"),
                privacy_budget_root: sample_root("privacy-budget"),
                reserved_at_height: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT
                    + 3,
            })
            .expect("devnet sponsor reservation");
        let slot = state
            .reserve_proof_slot(ReserveProofSlotRequest {
                aggregator_commitment: commitment("proof-aggregator"),
                group_ids: vec![group.group_id.clone()],
                group_root: group.group_root(),
                recursive_circuit_root: sample_root("recursive-circuit"),
                public_input_root: sample_root("public-input"),
                aggregated_proof_root: sample_root("aggregate-proof"),
                proof_bytes: 262_144,
                pq_attestation_root: sample_root("pq-attestation"),
                reserved_at_height: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT
                    + 4,
            })
            .expect("devnet proof slot");
        let batch = state
            .build_settlement_batch(BuildSettlementBatchRequest {
                builder_commitment: commitment("low-fee-builder"),
                group_ids: vec![group.group_id.clone()],
                ticket_root: reservation.ticket_root.clone(),
                group_root: group.group_root(),
                reservation_root: root_from_values(
                    "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-DEVNET-RESERVATIONS",
                    &[&reservation.reservation_id],
                ),
                proof_slot_root: root_from_values(
                    "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-DEVNET-SLOTS",
                    &[&slot.slot_id],
                ),
                state_read_root: group.expected_state_read_root.clone(),
                state_write_root: group.expected_state_write_root.clone(),
                privacy_fence_root: group.privacy_fence_root.clone(),
                nullifier_root: group.combined_nullifier_root.clone(),
                fee_debit_root: sample_root("fee-debit"),
                rebate_credit_root: sample_root("rebate-credit"),
                aggregate_proof_root: slot.aggregated_proof_root.clone(),
                total_user_fee_micro_units: 28_000,
                total_sponsor_fee_micro_units: 11_000,
                total_rebate_micro_units: 2_400,
                built_at_height: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT
                    + 5,
            })
            .expect("devnet settlement batch");
        let receipt = state
            .settle_batch(SettleBatchRequest {
                batch_id: batch.batch_id.clone(),
                settlement_tx_root: sample_root("settlement-tx"),
                settlement_proof_root: slot.aggregated_proof_root.clone(),
                fee_debit_root: batch.fee_debit_root.clone(),
                rebate_credit_root: batch.rebate_credit_root.clone(),
                nullifier_root: batch.nullifier_root.clone(),
                settled_at_height: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT
                    + 8,
            })
            .expect("devnet receipt");
        state
            .record_rebate_credit(RecordRebateCreditRequest {
                receipt_id: receipt.receipt_id.clone(),
                reservation_id: Some(reservation.reservation_id.clone()),
                sponsor_commitment: reservation.sponsor_commitment.clone(),
                recipient_commitment: commitment("alice-rebate-recipient"),
                credit_micro_units: 2_400,
                rebate_bps: state.config.target_rebate_bps,
                claim_root: sample_root("rebate-claim"),
                claimed_nullifier_root: sample_root("rebate-nullifier"),
                credited_at_height: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT
                    + 9,
            })
            .expect("devnet rebate");
        state
            .anchor_privacy_fence(AnchorPrivacyFenceRequest {
                scope_id: batch.batch_id.clone(),
                nullifiers: vec![ticket_a.nullifier.clone(), ticket_b.nullifier.clone()],
                privacy_set_size: 4_096,
                anchored_at_height: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_DEVNET_HEIGHT
                    + 10,
            })
            .expect("devnet privacy fence");
        state
    }

    pub fn submit_batch_ticket(
        &mut self,
        request: SubmitBatchTicketRequest,
    ) -> Result<EncryptedBatchTicket> {
        self.ensure_capacity(
            "batch tickets",
            self.batch_tickets.len(),
            self.config.max_batch_tickets,
        )?;
        require_non_empty("owner commitment", &request.owner_commitment)?;
        require_root("encrypted call root", &request.encrypted_call_root)?;
        require_root("call witness root", &request.call_witness_root)?;
        require_root("pq ciphertext root", &request.pq_ciphertext_root)?;
        require_root("pq commitment root", &request.pq_commitment_root)?;
        require_root("nullifier", &request.nullifier)?;
        require_bps(
            "user fee bps",
            request.user_fee_bps,
            self.config.max_user_fee_bps,
        )?;
        if request.privacy_set_size < self.config.min_ticket_privacy_set_size {
            return Err("ticket privacy set is below configured floor".to_string());
        }
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err("ticket nullifier already consumed".to_string());
        }
        let nonce = self.counters.tickets_submitted.saturating_add(1);
        let ticket_id = batch_ticket_id(&request, nonce);
        let ticket = EncryptedBatchTicket {
            ticket_id: ticket_id.clone(),
            ticket_kind: request.ticket_kind,
            status: BatchTicketStatus::Submitted,
            owner_commitment: request.owner_commitment,
            contract_domain: request.contract_domain,
            target_contract_commitment: request.target_contract_commitment,
            encrypted_call_root: request.encrypted_call_root,
            call_witness_root: request.call_witness_root,
            max_user_fee_micro_units: request.max_user_fee_micro_units,
            user_fee_bps: request.user_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_ciphertext_root: request.pq_ciphertext_root,
            pq_commitment_root: request.pq_commitment_root,
            nullifier: request.nullifier,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.ticket_ttl_blocks),
            group_id: None,
        };
        self.batch_tickets.insert(ticket_id.clone(), ticket.clone());
        self.counters.tickets_submitted = nonce;
        self.emit_event(
            "batch_ticket_submitted",
            &ticket_id,
            ticket.submitted_at_height,
        );
        self.recompute_roots();
        Ok(ticket)
    }

    pub fn open_call_group(&mut self, request: OpenCallGroupRequest) -> Result<ContractCallGroup> {
        self.ensure_capacity(
            "call groups",
            self.call_groups.len(),
            self.config.max_call_groups,
        )?;
        if request.ticket_ids.is_empty() {
            return Err("call group requires at least one ticket".to_string());
        }
        if request.ticket_ids.len() > self.config.max_calls_per_group {
            return Err("call group exceeds configured ticket limit".to_string());
        }
        require_root(
            "contract commitment root",
            &request.contract_commitment_root,
        )?;
        require_root("call graph root", &request.call_graph_root)?;
        require_root("dependency root", &request.dependency_root)?;
        require_root(
            "aggregated call witness root",
            &request.aggregated_call_witness_root,
        )?;
        require_root("state read root", &request.expected_state_read_root)?;
        require_root("state write root", &request.expected_state_write_root)?;
        require_root("privacy fence root", &request.privacy_fence_root)?;
        require_root("combined nullifier root", &request.combined_nullifier_root)?;
        let compression_ratio =
            compression_ratio_bps(request.compressed_bytes, request.uncompressed_bytes);
        if compression_ratio == 0 || compression_ratio > self.config.min_compression_ratio_bps {
            return Err("call group does not meet low-fee compression target".to_string());
        }
        for ticket_id in &request.ticket_ids {
            let ticket = self
                .batch_tickets
                .get(ticket_id)
                .ok_or_else(|| format!("ticket {ticket_id} is missing"))?;
            if !ticket.status.groupable() {
                return Err(format!("ticket {ticket_id} is not groupable"));
            }
        }
        let nonce = self.counters.call_groups_opened.saturating_add(1);
        let low_fee_score = low_fee_score(
            request.estimated_gas_units,
            request.compressed_bytes,
            request.uncompressed_bytes,
            request.ticket_ids.len() as u64,
        );
        let group_id = call_group_id(&request, low_fee_score, nonce);
        let group = ContractCallGroup {
            group_id: group_id.clone(),
            status: CallGroupStatus::Open,
            coordinator_commitment: request.coordinator_commitment,
            contract_domain: request.contract_domain,
            ticket_ids: request.ticket_ids.clone(),
            contract_commitment_root: request.contract_commitment_root,
            call_graph_root: request.call_graph_root,
            dependency_root: request.dependency_root,
            aggregated_call_witness_root: request.aggregated_call_witness_root,
            expected_state_read_root: request.expected_state_read_root,
            expected_state_write_root: request.expected_state_write_root,
            privacy_fence_root: request.privacy_fence_root,
            combined_nullifier_root: request.combined_nullifier_root,
            low_fee_score,
            estimated_gas_units: request.estimated_gas_units,
            compressed_bytes: request.compressed_bytes,
            uncompressed_bytes: request.uncompressed_bytes,
            opened_at_height: request.opened_at_height,
            expires_at_height: request
                .opened_at_height
                .saturating_add(self.config.call_group_ttl_blocks),
            sponsor_reservation_id: None,
            proof_slot_id: None,
            settlement_batch_id: None,
        };
        for ticket_id in &request.ticket_ids {
            if let Some(ticket) = self.batch_tickets.get_mut(ticket_id) {
                ticket.status = BatchTicketStatus::Grouped;
                ticket.group_id = Some(group_id.clone());
            }
        }
        self.call_groups.insert(group_id.clone(), group.clone());
        self.counters.call_groups_opened = nonce;
        self.emit_event("call_group_opened", &group_id, group.opened_at_height);
        self.recompute_roots();
        Ok(group)
    }

    pub fn reserve_fee_sponsor(
        &mut self,
        request: ReserveFeeSponsorRequest,
    ) -> Result<FeeSponsorReservation> {
        self.ensure_capacity(
            "sponsor reservations",
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
        )?;
        require_non_empty("sponsor commitment", &request.sponsor_commitment)?;
        require_root("ticket root", &request.ticket_root)?;
        require_root("rebate commitment root", &request.rebate_commitment_root)?;
        require_root("privacy budget root", &request.privacy_budget_root)?;
        require_bps(
            "sponsor fee bps",
            request.sponsor_fee_bps,
            self.config.max_sponsor_fee_bps,
        )?;
        if request.reserved_micro_units > request.fee_cap_micro_units {
            return Err("reserved sponsor amount exceeds fee cap".to_string());
        }
        if request.reserved_micro_units > self.config.sponsor_budget_micro_units {
            return Err("reserved sponsor amount exceeds runtime budget".to_string());
        }
        for group_id in &request.group_ids {
            let group = self
                .call_groups
                .get(group_id)
                .ok_or_else(|| format!("call group {group_id} is missing"))?;
            if !group.status.batchable() {
                return Err(format!("call group {group_id} cannot be sponsored"));
            }
        }
        let nonce = self.counters.sponsor_reservations.saturating_add(1);
        let reservation_id = fee_sponsor_reservation_id(&request, nonce);
        let reservation = FeeSponsorReservation {
            reservation_id: reservation_id.clone(),
            status: SponsorReservationStatus::Reserved,
            sponsor_commitment: request.sponsor_commitment,
            group_ids: request.group_ids.clone(),
            ticket_root: request.ticket_root,
            fee_cap_micro_units: request.fee_cap_micro_units,
            reserved_micro_units: request.reserved_micro_units,
            consumed_micro_units: 0,
            sponsor_fee_bps: request.sponsor_fee_bps,
            rebate_commitment_root: request.rebate_commitment_root,
            privacy_budget_root: request.privacy_budget_root,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request
                .reserved_at_height
                .saturating_add(self.config.batch_ttl_blocks),
        };
        for group_id in &request.group_ids {
            if let Some(group) = self.call_groups.get_mut(group_id) {
                group.status = CallGroupStatus::Sponsored;
                group.sponsor_reservation_id = Some(reservation_id.clone());
            }
            self.mark_group_tickets(group_id, BatchTicketStatus::Sponsored);
        }
        self.sponsor_reservations
            .insert(reservation_id.clone(), reservation.clone());
        self.counters.sponsor_reservations = nonce;
        self.emit_event(
            "fee_sponsor_reserved",
            &reservation_id,
            reservation.reserved_at_height,
        );
        self.recompute_roots();
        Ok(reservation)
    }

    pub fn reserve_proof_slot(
        &mut self,
        request: ReserveProofSlotRequest,
    ) -> Result<ProofAggregationSlot> {
        self.ensure_capacity(
            "proof slots",
            self.proof_slots.len(),
            self.config.max_proof_slots,
        )?;
        require_non_empty("aggregator commitment", &request.aggregator_commitment)?;
        require_root("group root", &request.group_root)?;
        require_root("recursive circuit root", &request.recursive_circuit_root)?;
        require_root("public input root", &request.public_input_root)?;
        require_root("aggregated proof root", &request.aggregated_proof_root)?;
        require_root("pq attestation root", &request.pq_attestation_root)?;
        if request.proof_bytes > self.config.max_aggregated_proof_bytes {
            return Err("aggregated proof exceeds configured byte ceiling".to_string());
        }
        for group_id in &request.group_ids {
            let group = self
                .call_groups
                .get(group_id)
                .ok_or_else(|| format!("call group {group_id} is missing"))?;
            if !group.status.batchable() {
                return Err(format!("call group {group_id} cannot enter proof slot"));
            }
        }
        let nonce = self.counters.proof_slots_reserved.saturating_add(1);
        let slot_id = proof_aggregation_slot_id(&request, nonce);
        let slot = ProofAggregationSlot {
            slot_id: slot_id.clone(),
            status: ProofSlotStatus::Filling,
            aggregator_commitment: request.aggregator_commitment,
            group_ids: request.group_ids.clone(),
            group_root: request.group_root,
            recursive_circuit_root: request.recursive_circuit_root,
            public_input_root: request.public_input_root,
            aggregated_proof_root: request.aggregated_proof_root,
            proof_bytes: request.proof_bytes,
            pq_attestation_root: request.pq_attestation_root,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request
                .reserved_at_height
                .saturating_add(self.config.proof_slot_ttl_blocks),
            sealed_at_height: None,
        };
        for group_id in &request.group_ids {
            if let Some(group) = self.call_groups.get_mut(group_id) {
                group.status = CallGroupStatus::Slotted;
                group.proof_slot_id = Some(slot_id.clone());
            }
        }
        self.proof_slots.insert(slot_id.clone(), slot.clone());
        self.counters.proof_slots_reserved = nonce;
        self.emit_event("proof_slot_reserved", &slot_id, slot.reserved_at_height);
        self.recompute_roots();
        Ok(slot)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildSettlementBatchRequest,
    ) -> Result<SettlementBatch> {
        self.ensure_capacity(
            "settlement batches",
            self.settlement_batches.len(),
            self.config.max_settlement_batches,
        )?;
        if request.group_ids.is_empty() {
            return Err("settlement batch requires at least one call group".to_string());
        }
        require_root("ticket root", &request.ticket_root)?;
        require_root("group root", &request.group_root)?;
        require_root("reservation root", &request.reservation_root)?;
        require_root("proof slot root", &request.proof_slot_root)?;
        require_root("state read root", &request.state_read_root)?;
        require_root("state write root", &request.state_write_root)?;
        require_root("privacy fence root", &request.privacy_fence_root)?;
        require_root("nullifier root", &request.nullifier_root)?;
        require_root("fee debit root", &request.fee_debit_root)?;
        require_root("rebate credit root", &request.rebate_credit_root)?;
        require_root("aggregate proof root", &request.aggregate_proof_root)?;
        let mut low_fee_score_sum = 0u128;
        for group_id in &request.group_ids {
            let group = self
                .call_groups
                .get(group_id)
                .ok_or_else(|| format!("call group {group_id} is missing"))?;
            if !group.status.batchable() {
                return Err(format!("call group {group_id} cannot be batched"));
            }
            low_fee_score_sum = low_fee_score_sum.saturating_add(group.low_fee_score);
        }
        let nonce = self.counters.settlement_batches_built.saturating_add(1);
        let batch_id = settlement_batch_id(&request, nonce);
        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            status: SettlementBatchStatus::Proving,
            builder_commitment: request.builder_commitment,
            group_ids: request.group_ids.clone(),
            ticket_root: request.ticket_root,
            group_root: request.group_root,
            reservation_root: request.reservation_root,
            proof_slot_root: request.proof_slot_root,
            state_read_root: request.state_read_root,
            state_write_root: request.state_write_root,
            privacy_fence_root: request.privacy_fence_root,
            nullifier_root: request.nullifier_root,
            fee_debit_root: request.fee_debit_root,
            rebate_credit_root: request.rebate_credit_root,
            aggregate_proof_root: request.aggregate_proof_root,
            low_fee_score: low_fee_score_sum,
            total_user_fee_micro_units: request.total_user_fee_micro_units,
            total_sponsor_fee_micro_units: request.total_sponsor_fee_micro_units,
            total_rebate_micro_units: request.total_rebate_micro_units,
            built_at_height: request.built_at_height,
            expires_at_height: request
                .built_at_height
                .saturating_add(self.config.batch_ttl_blocks),
        };
        for group_id in &request.group_ids {
            if let Some(group) = self.call_groups.get_mut(group_id) {
                group.status = CallGroupStatus::Batched;
                group.settlement_batch_id = Some(batch_id.clone());
            }
        }
        self.settlement_batches
            .insert(batch_id.clone(), batch.clone());
        self.counters.settlement_batches_built = nonce;
        self.emit_event("settlement_batch_built", &batch_id, batch.built_at_height);
        self.recompute_roots();
        Ok(batch)
    }

    pub fn settle_batch(&mut self, request: SettleBatchRequest) -> Result<SettlementReceipt> {
        self.ensure_capacity(
            "settlement receipts",
            self.settlement_receipts.len(),
            self.config.max_settlement_receipts,
        )?;
        require_root("settlement tx root", &request.settlement_tx_root)?;
        require_root("settlement proof root", &request.settlement_proof_root)?;
        require_root("fee debit root", &request.fee_debit_root)?;
        require_root("rebate credit root", &request.rebate_credit_root)?;
        require_root("nullifier root", &request.nullifier_root)?;
        let state_root_before = self.state_root();
        let batch = self
            .settlement_batches
            .get(&request.batch_id)
            .ok_or_else(|| "settlement batch is missing".to_string())?
            .clone();
        if !matches!(
            batch.status,
            SettlementBatchStatus::Open
                | SettlementBatchStatus::Sealed
                | SettlementBatchStatus::Proving
        ) {
            return Err("settlement batch is not settleable".to_string());
        }
        let nonce = self.counters.settlement_receipts.saturating_add(1);
        let receipt_id = settlement_receipt_id(&request, &state_root_before, nonce);
        let mut receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            receipt_kind: SettlementReceiptKind::BatchSettled,
            batch_id: request.batch_id.clone(),
            group_id: None,
            ticket_root: batch.ticket_root.clone(),
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            fee_debit_root: request.fee_debit_root,
            rebate_credit_root: request.rebate_credit_root,
            nullifier_root: request.nullifier_root,
            state_root_before,
            state_root_after: String::new(),
            settled_at_height: request.settled_at_height,
        };
        if let Some(batch_mut) = self.settlement_batches.get_mut(&request.batch_id) {
            batch_mut.status = SettlementBatchStatus::Settled;
        }
        for group_id in &batch.group_ids {
            if let Some(group) = self.call_groups.get_mut(group_id) {
                group.status = CallGroupStatus::Settled;
            }
            self.mark_group_tickets(group_id, BatchTicketStatus::Settled);
        }
        self.consume_batch_nullifiers(&batch.group_ids)?;
        self.counters.total_user_fee_micro_units = self
            .counters
            .total_user_fee_micro_units
            .saturating_add(batch.total_user_fee_micro_units);
        self.counters.total_sponsor_fee_micro_units = self
            .counters
            .total_sponsor_fee_micro_units
            .saturating_add(batch.total_sponsor_fee_micro_units);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(batch.total_rebate_micro_units);
        self.settlement_receipts
            .insert(receipt_id.clone(), receipt.clone());
        self.counters.settlement_receipts = nonce;
        self.emit_event(
            "settlement_batch_settled",
            &receipt_id,
            receipt.settled_at_height,
        );
        self.recompute_roots();
        receipt.state_root_after = self.state_root();
        self.settlement_receipts
            .insert(receipt_id.clone(), receipt.clone());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn record_rebate_credit(
        &mut self,
        request: RecordRebateCreditRequest,
    ) -> Result<RebateCredit> {
        self.ensure_capacity(
            "rebate credits",
            self.rebate_credits.len(),
            self.config.max_rebate_credits,
        )?;
        require_root("claim root", &request.claim_root)?;
        require_root("claimed nullifier root", &request.claimed_nullifier_root)?;
        require_bps("rebate bps", request.rebate_bps, self.config.max_rebate_bps)?;
        if !self.settlement_receipts.contains_key(&request.receipt_id) {
            return Err("rebate receipt is missing".to_string());
        }
        let nonce = self.counters.rebate_credits.saturating_add(1);
        let rebate_id = rebate_credit_id(&request, nonce);
        let rebate = RebateCredit {
            rebate_id: rebate_id.clone(),
            receipt_id: request.receipt_id,
            reservation_id: request.reservation_id,
            sponsor_commitment: request.sponsor_commitment,
            recipient_commitment: request.recipient_commitment,
            credit_micro_units: request.credit_micro_units,
            rebate_bps: request.rebate_bps,
            claim_root: request.claim_root,
            claimed_nullifier_root: request.claimed_nullifier_root,
            credited_at_height: request.credited_at_height,
        };
        self.rebate_credits
            .insert(rebate_id.clone(), rebate.clone());
        self.counters.rebate_credits = nonce;
        self.emit_event(
            "rebate_credit_recorded",
            &rebate_id,
            rebate.credited_at_height,
        );
        self.recompute_roots();
        Ok(rebate)
    }

    pub fn quarantine_failure(
        &mut self,
        request: QuarantineFailureRequest,
    ) -> Result<FailureQuarantine> {
        self.ensure_capacity(
            "failure quarantines",
            self.failure_quarantines.len(),
            self.config.max_failure_quarantines,
        )?;
        require_root("ticket root", &request.ticket_root)?;
        require_root("failure root", &request.failure_root)?;
        require_root("recovery hint root", &request.recovery_hint_root)?;
        require_root("released nullifier root", &request.released_nullifier_root)?;
        let nonce = self.counters.failure_quarantines.saturating_add(1);
        let quarantine_id = failure_quarantine_id(&request, nonce);
        let quarantine = FailureQuarantine {
            quarantine_id: quarantine_id.clone(),
            reason: request.reason,
            batch_id: request.batch_id.clone(),
            group_id: request.group_id.clone(),
            ticket_root: request.ticket_root,
            failure_root: request.failure_root,
            recovery_hint_root: request.recovery_hint_root,
            released_nullifier_root: request.released_nullifier_root,
            quarantined_at_height: request.quarantined_at_height,
            review_after_height: request.review_after_height,
        };
        if let Some(batch_id) = &request.batch_id {
            if let Some(batch) = self.settlement_batches.get_mut(batch_id) {
                batch.status = SettlementBatchStatus::Quarantined;
            }
        }
        if let Some(group_id) = &request.group_id {
            if let Some(group) = self.call_groups.get_mut(group_id) {
                group.status = CallGroupStatus::Quarantined;
            }
            self.mark_group_tickets(group_id, BatchTicketStatus::Quarantined);
        }
        self.failure_quarantines
            .insert(quarantine_id.clone(), quarantine.clone());
        self.counters.failure_quarantines = nonce;
        self.emit_event(
            "failure_quarantined",
            &quarantine_id,
            quarantine.quarantined_at_height,
        );
        self.recompute_roots();
        Ok(quarantine)
    }

    pub fn anchor_privacy_fence(
        &mut self,
        request: AnchorPrivacyFenceRequest,
    ) -> Result<PrivacyFence> {
        self.ensure_capacity(
            "privacy fences",
            self.privacy_fences.len(),
            self.config.max_nullifiers,
        )?;
        if request.nullifiers.is_empty() {
            return Err("privacy fence requires nullifiers".to_string());
        }
        if request.privacy_set_size < self.config.min_batch_privacy_set_size {
            return Err("privacy fence privacy set is below configured floor".to_string());
        }
        let nullifier_records = request
            .nullifiers
            .iter()
            .map(|nullifier| {
                require_root("privacy fence nullifier", nullifier)?;
                Ok(json!(nullifier))
            })
            .collect::<Result<Vec<_>>>()?;
        let nullifier_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PRIVACY-FENCE-NULLIFIERS",
            &nullifier_records,
        );
        let leaf_records = request
            .nullifiers
            .iter()
            .map(|nullifier| json!(nullifier_fence_leaf(&request.scope_id, nullifier)))
            .collect::<Vec<_>>();
        let fence_leaf_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PRIVACY-FENCE-LEAVES",
            &leaf_records,
        );
        let nonce = self.counters.privacy_fences.saturating_add(1);
        let fence_id = privacy_fence_id(&request.scope_id, &nullifier_root, nonce);
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            scope_id: request.scope_id,
            nullifier_root,
            privacy_set_size: request.privacy_set_size,
            fence_leaf_root,
            anchored_at_height: request.anchored_at_height,
        };
        self.privacy_fences.insert(fence_id.clone(), fence.clone());
        self.counters.privacy_fences = nonce;
        self.emit_event(
            "privacy_fence_anchored",
            &fence_id,
            fence.anchored_at_height,
        );
        self.recompute_roots();
        Ok(fence)
    }

    pub fn recompute_roots(&mut self) {
        let ticket_records = self
            .batch_tickets
            .values()
            .map(EncryptedBatchTicket::public_record)
            .collect::<Vec<_>>();
        let group_records = self
            .call_groups
            .values()
            .map(ContractCallGroup::public_record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .sponsor_reservations
            .values()
            .map(FeeSponsorReservation::public_record)
            .collect::<Vec<_>>();
        let slot_records = self
            .proof_slots
            .values()
            .map(ProofAggregationSlot::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .settlement_batches
            .values()
            .map(SettlementBatch::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .settlement_receipts
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebate_credits
            .values()
            .map(RebateCredit::public_record)
            .collect::<Vec<_>>();
        let quarantine_records = self
            .failure_quarantines
            .values()
            .map(FailureQuarantine::public_record)
            .collect::<Vec<_>>();
        let fence_records = self
            .privacy_fences
            .values()
            .map(PrivacyFence::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| json!(nullifier))
            .collect::<Vec<_>>();
        self.roots.ticket_root =
            merkle_root("PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-TICKETS", &ticket_records);
        self.roots.call_group_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-GROUPS",
            &group_records,
        );
        self.roots.sponsor_reservation_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SPONSOR-RESERVATIONS",
            &reservation_records,
        );
        self.roots.proof_slot_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PROOF-SLOTS",
            &slot_records,
        );
        self.roots.settlement_batch_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SETTLEMENT-BATCHES",
            &batch_records,
        );
        self.roots.settlement_receipt_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SETTLEMENT-RECEIPTS",
            &receipt_records,
        );
        self.roots.rebate_credit_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-REBATE-CREDITS",
            &rebate_records,
        );
        self.roots.failure_quarantine_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-FAILURE-QUARANTINES",
            &quarantine_records,
        );
        self.roots.privacy_fence_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PRIVACY-FENCES",
            &fence_records,
        );
        self.roots.consumed_nullifier_root = merkle_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CONSUMED-NULLIFIERS",
            &nullifier_records,
        );
        self.roots.event_root =
            merkle_root("PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-EVENTS", &self.events);
        let record = self.public_record();
        self.roots.public_record_root = root_from_record(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PUBLIC-RECORD-ROOT",
            &record,
        );
        self.roots.state_root = state_root_from_record(&record);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": self.config.hash_suite,
            "schemes": {
                "ticket": self.config.ticket_scheme,
                "call_group": self.config.call_group_scheme,
                "sponsor": self.config.sponsor_scheme,
                "proof_aggregation": self.config.proof_aggregation_scheme,
                "receipt": self.config.receipt_scheme,
                "rebate": self.config.rebate_scheme,
                "quarantine": self.config.quarantine_scheme,
                "privacy_fence": self.config.privacy_fence_scheme,
                "pq_commitment": self.config.pq_commitment_scheme,
            },
            "counters": self.counters,
            "roots": self.roots,
            "limits": {
                "max_batch_tickets": self.config.max_batch_tickets,
                "max_call_groups": self.config.max_call_groups,
                "max_calls_per_group": self.config.max_calls_per_group,
                "max_sponsor_reservations": self.config.max_sponsor_reservations,
                "max_proof_slots": self.config.max_proof_slots,
                "max_settlement_batches": self.config.max_settlement_batches,
                "max_settlement_receipts": self.config.max_settlement_receipts,
                "max_rebate_credits": self.config.max_rebate_credits,
                "max_failure_quarantines": self.config.max_failure_quarantines,
                "max_nullifiers": self.config.max_nullifiers,
                "ticket_ttl_blocks": self.config.ticket_ttl_blocks,
                "call_group_ttl_blocks": self.config.call_group_ttl_blocks,
                "batch_ttl_blocks": self.config.batch_ttl_blocks,
                "proof_slot_ttl_blocks": self.config.proof_slot_ttl_blocks,
                "min_ticket_privacy_set_size": self.config.min_ticket_privacy_set_size,
                "min_batch_privacy_set_size": self.config.min_batch_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "max_user_fee_bps": self.config.max_user_fee_bps,
                "max_sponsor_fee_bps": self.config.max_sponsor_fee_bps,
                "target_rebate_bps": self.config.target_rebate_bps,
                "max_rebate_bps": self.config.max_rebate_bps,
                "min_compression_ratio_bps": self.config.min_compression_ratio_bps,
                "max_aggregated_proof_bytes": self.config.max_aggregated_proof_bytes,
                "sponsor_budget_micro_units": self.config.sponsor_budget_micro_units,
                "low_fee_target_micro_units": self.config.low_fee_target_micro_units,
            },
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn ensure_capacity(&self, label: &str, current: usize, max: usize) -> Result<()> {
        if current >= max {
            return Err(format!("{label} capacity exceeded"));
        }
        Ok(())
    }

    fn emit_event(&mut self, event_kind: &str, subject_id: &str, height: u64) {
        let nonce = self.counters.events_emitted.saturating_add(1);
        let payload = json!({
            "event_kind": event_kind,
            "subject_id": subject_id,
            "height": height,
        });
        let event = PublicEvent {
            event_id: public_event_id(event_kind, subject_id, nonce),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root: payload_root("PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-EVENT-PAYLOAD", &payload),
            emitted_at_height: height,
        };
        self.events.push(event.public_record());
        self.counters.events_emitted = nonce;
    }

    fn mark_group_tickets(&mut self, group_id: &str, status: BatchTicketStatus) {
        let ticket_ids = self
            .call_groups
            .get(group_id)
            .map(|group| group.ticket_ids.clone())
            .unwrap_or_default();
        for ticket_id in ticket_ids {
            if let Some(ticket) = self.batch_tickets.get_mut(&ticket_id) {
                ticket.status = status;
            }
        }
    }

    fn consume_batch_nullifiers(&mut self, group_ids: &[String]) -> Result<()> {
        for group_id in group_ids {
            let group = self
                .call_groups
                .get(group_id)
                .ok_or_else(|| format!("call group {group_id} is missing"))?;
            for ticket_id in &group.ticket_ids {
                let ticket = self
                    .batch_tickets
                    .get(ticket_id)
                    .ok_or_else(|| format!("ticket {ticket_id} is missing"))?;
                if self.consumed_nullifiers.contains(&ticket.nullifier) {
                    return Err("settlement would consume a duplicate nullifier".to_string());
                }
            }
        }
        for group_id in group_ids {
            if let Some(group) = self.call_groups.get(group_id) {
                for ticket_id in &group.ticket_ids {
                    if let Some(ticket) = self.batch_tickets.get(ticket_id) {
                        self.consumed_nullifiers.insert(ticket.nullifier.clone());
                        self.counters.nullifiers_consumed =
                            self.counters.nullifiers_consumed.saturating_add(1);
                    }
                }
            }
        }
        Ok(())
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_low_fee_cross_contract_batch_settlement_runtime_public_record() -> Value {
    State::devnet().public_record()
}

pub fn private_l2_low_fee_cross_contract_batch_settlement_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn batch_ticket_id(request: &SubmitBatchTicketRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-BATCH-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.ticket_kind.as_str()),
            HashPart::Str(request.contract_domain.as_str()),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.target_contract_commitment),
            HashPart::Str(&request.encrypted_call_root),
            HashPart::Str(&request.nullifier),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn call_group_id(request: &OpenCallGroupRequest, low_fee_score: u128, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-GROUP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.coordinator_commitment),
            HashPart::Str(request.contract_domain.as_str()),
            HashPart::Str(&root_from_values_vec(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-GROUP-TICKETS",
                &request.ticket_ids,
            )),
            HashPart::Str(&request.call_graph_root),
            HashPart::Str(&request.combined_nullifier_root),
            HashPart::Int(low_fee_score.min(i128::MAX as u128) as i128),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_sponsor_reservation_id(request: &ReserveFeeSponsorRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&root_from_values_vec(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SPONSOR-GROUPS",
                &request.group_ids,
            )),
            HashPart::Str(&request.ticket_root),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Int(request.reserved_micro_units as i128),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn proof_aggregation_slot_id(request: &ReserveProofSlotRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PROOF-AGGREGATION-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.aggregator_commitment),
            HashPart::Str(&request.group_root),
            HashPart::Str(&request.recursive_circuit_root),
            HashPart::Str(&request.public_input_root),
            HashPart::Str(&request.aggregated_proof_root),
            HashPart::Int(request.proof_bytes as i128),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_batch_id(request: &BuildSettlementBatchRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.builder_commitment),
            HashPart::Str(&request.group_root),
            HashPart::Str(&request.reservation_root),
            HashPart::Str(&request.proof_slot_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.aggregate_proof_root),
            HashPart::U64(request.built_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    request: &SettleBatchRequest,
    state_root_before: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(state_root_before),
            HashPart::U64(request.settled_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_credit_id(request: &RecordRebateCreditRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-REBATE-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.receipt_id),
            HashPart::Str(request.reservation_id.as_deref().unwrap_or("none")),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.recipient_commitment),
            HashPart::Str(&request.claim_root),
            HashPart::Str(&request.claimed_nullifier_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn failure_quarantine_id(request: &QuarantineFailureRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-FAILURE-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(request.batch_id.as_deref().unwrap_or("none")),
            HashPart::Str(request.group_id.as_deref().unwrap_or("none")),
            HashPart::Str(&request.ticket_root),
            HashPart::Str(&request.failure_root),
            HashPart::U64(request.quarantined_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(scope_id: &str, nullifier_root: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope_id),
            HashPart::Str(nullifier_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn operation_nullifier(scope_id: &str, label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-OPERATION-NULLIFIER",
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
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-NULLIFIER-FENCE-LEAF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn public_event_id(event_kind: &str, subject_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::U64(sequence),
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
            HashPart::Str(PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_BATCH_SETTLEMENT_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-STATE-ROOT", record)
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let records = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn root_from_values_vec(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn compression_ratio_bps(compressed_bytes: u64, uncompressed_bytes: u64) -> u64 {
    if uncompressed_bytes == 0 {
        return 0;
    }
    compressed_bytes
        .saturating_mul(MAX_BPS)
        .saturating_div(uncompressed_bytes)
        .min(MAX_BPS)
}

pub fn low_fee_score(
    estimated_gas_units: u64,
    compressed_bytes: u64,
    uncompressed_bytes: u64,
    ticket_count: u64,
) -> u128 {
    let compression =
        MAX_BPS.saturating_sub(compression_ratio_bps(compressed_bytes, uncompressed_bytes)) as u128;
    let density = ticket_count.max(1) as u128 * 1_000_000;
    let gas_penalty = estimated_gas_units as u128;
    compression
        .saturating_mul(density)
        .saturating_sub(gas_penalty)
}

fn commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-DEVNET-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-DEVNET-SAMPLE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> Result<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64, limit: u64) -> Result<()> {
    if value > limit || value > MAX_BPS {
        return Err(format!("{label} exceeds allowed bps limit"));
    }
    Ok(())
}
