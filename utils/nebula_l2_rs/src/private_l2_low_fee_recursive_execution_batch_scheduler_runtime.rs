use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeeRecursiveExecutionBatchSchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-recursive-execution-batch-scheduler-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-low-fee-recursive-execution-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_LANE_SCHEME: &str =
    "private-microbatch-lane-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_TASK_SCHEME: &str =
    "encrypted-private-contract-execution-task-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_PRECONF_SCHEME: &str =
    "preconfirmation-sla-commitment-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_WINDOW_SCHEME: &str =
    "recursive-proof-window-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_SPONSOR_SCHEME: &str =
    "low-fee-sponsor-reservation-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_RECEIPT_SCHEME: &str =
    "compressed-private-execution-receipt-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_REBATE_SCHEME: &str =
    "private-execution-low-fee-rebate-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_ORDERING_SCHEME: &str =
    "anti-mev-ordering-commitment-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_SETTLEMENT_SCHEME: &str =
    "monero-l2-recursive-execution-settlement-batch-root-v1";
pub const PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_DEVNET_HEIGHT: u64 =
    1_432_000;
pub const DEFAULT_MAX_LANES: usize = 256;
pub const DEFAULT_MAX_TASKS: usize = 4_194_304;
pub const DEFAULT_MAX_PRECONFIRMATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_PROOF_WINDOWS: usize = 524_288;
pub const DEFAULT_MAX_SPONSOR_RESERVATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_ORDERING_COMMITMENTS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENT_BATCHES: usize = 262_144;
pub const DEFAULT_MAX_TASKS_PER_WINDOW: usize = 16_384;
pub const DEFAULT_MAX_WINDOWS_PER_SETTLEMENT: usize = 128;
pub const DEFAULT_TASK_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_PRECONF_TTL_BLOCKS: u64 = 6;
pub const DEFAULT_PROOF_WINDOW_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_TARGET_PRECONF_MS: u64 = 320;
pub const DEFAULT_TARGET_PROOF_WINDOW_MS: u64 = 1_800;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_WINDOW_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 5;
pub const DEFAULT_MAX_SPONSOR_COVER_BPS: u64 = 9_500;
pub const DEFAULT_LOW_FEE_CEILING_MICRO_UNITS: u64 = 900;
pub const DEFAULT_BASE_MICRO_FEE_MICRO_UNITS: u64 = 180;
pub const DEFAULT_MIN_COMPRESSION_RATIO_BPS: u64 = 5_500;
pub const DEFAULT_MAX_COMPRESSED_RECEIPT_BYTES: u64 = 512;
pub const DEFAULT_MAX_AGGREGATED_PROOF_BYTES: u64 = 2_097_152;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MicrobatchLaneKind {
    UltraFastContractCall,
    LowFeeContractCall,
    DefiNetting,
    StableSwap,
    Lending,
    Perpetuals,
    Options,
    VaultStrategy,
    AccountAbstraction,
    OracleCallback,
    MoneroBridge,
    SettlementHook,
    BackgroundCompression,
    EmergencyEscape,
}

impl MicrobatchLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraFastContractCall => "ultra_fast_contract_call",
            Self::LowFeeContractCall => "low_fee_contract_call",
            Self::DefiNetting => "defi_netting",
            Self::StableSwap => "stable_swap",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::VaultStrategy => "vault_strategy",
            Self::AccountAbstraction => "account_abstraction",
            Self::OracleCallback => "oracle_callback",
            Self::MoneroBridge => "monero_bridge",
            Self::SettlementHook => "settlement_hook",
            Self::BackgroundCompression => "background_compression",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::SettlementHook => 9_800,
            Self::MoneroBridge => 9_500,
            Self::Perpetuals => 9_250,
            Self::DefiNetting => 9_100,
            Self::StableSwap => 8_900,
            Self::UltraFastContractCall => 8_800,
            Self::OracleCallback => 8_600,
            Self::Lending => 8_300,
            Self::Options => 8_000,
            Self::AccountAbstraction => 7_800,
            Self::VaultStrategy => 7_600,
            Self::LowFeeContractCall => 7_400,
            Self::BackgroundCompression => 5_500,
        }
    }

    pub fn latency_sensitive(self) -> bool {
        matches!(
            self,
            Self::UltraFastContractCall
                | Self::DefiNetting
                | Self::Perpetuals
                | Self::MoneroBridge
                | Self::SettlementHook
                | Self::EmergencyEscape
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    SponsorOnly,
    ProofBacklog,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_tasks(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Congested | Self::SponsorOnly | Self::ProofBacklog
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTaskKind {
    PrivateCall,
    MultiCall,
    ConfidentialTransfer,
    AmmSwap,
    StableSwap,
    LendingSupply,
    LendingBorrow,
    PerpOpen,
    PerpClose,
    OptionMint,
    VaultDeposit,
    VaultWithdraw,
    AccountAbstractionUserOp,
    OracleReadThenCall,
    BridgeLock,
    BridgeRelease,
    SettlementCallback,
    MaintenanceHook,
}

impl ExecutionTaskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCall => "private_call",
            Self::MultiCall => "multi_call",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::AmmSwap => "amm_swap",
            Self::StableSwap => "stable_swap",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::PerpOpen => "perp_open",
            Self::PerpClose => "perp_close",
            Self::OptionMint => "option_mint",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::AccountAbstractionUserOp => "account_abstraction_user_op",
            Self::OracleReadThenCall => "oracle_read_then_call",
            Self::BridgeLock => "bridge_lock",
            Self::BridgeRelease => "bridge_release",
            Self::SettlementCallback => "settlement_callback",
            Self::MaintenanceHook => "maintenance_hook",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTaskStatus {
    Encrypted,
    Preconfirmed,
    Sponsored,
    Windowed,
    Executed,
    Settled,
    Rebated,
    Rejected,
    Expired,
}

impl ExecutionTaskStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Preconfirmed | Self::Sponsored | Self::Windowed
        )
    }

    pub fn windowable(self) -> bool {
        matches!(self, Self::Encrypted | Self::Preconfirmed | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationStatus {
    Offered,
    Accepted,
    Met,
    Missed,
    Slashed,
    Expired,
}

impl PreconfirmationStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Offered | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofWindowStatus {
    Open,
    Filling,
    Sealed,
    Proving,
    Proven,
    Settled,
    Failed,
    Expired,
}

impl ProofWindowStatus {
    pub fn accepts_tasks(self) -> bool {
        matches!(self, Self::Open | Self::Filling)
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
    Slashed,
}

impl SponsorReservationStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Reserved | Self::Attached)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Compressed,
    Published,
    Settled,
    Reorged,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Claimed,
    Expired,
    Voided,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingCommitmentStatus {
    Draft,
    Committed,
    Revealed,
    Challenged,
    Finalized,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Open,
    Sealed,
    Proving,
    Submitted,
    Settled,
    PartiallySettled,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodec {
    ZstdDictionary,
    PoseidonDelta,
    RecursiveReceiptTrie,
    MoneroViewTagBitmap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub lane_scheme: String,
    pub task_scheme: String,
    pub preconfirmation_scheme: String,
    pub proof_window_scheme: String,
    pub sponsor_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub ordering_scheme: String,
    pub settlement_scheme: String,
    pub max_lanes: usize,
    pub max_tasks: usize,
    pub max_preconfirmations: usize,
    pub max_proof_windows: usize,
    pub max_sponsor_reservations: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_ordering_commitments: usize,
    pub max_settlement_batches: usize,
    pub max_tasks_per_window: usize,
    pub max_windows_per_settlement: usize,
    pub task_ttl_blocks: u64,
    pub preconfirmation_ttl_blocks: u64,
    pub proof_window_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub target_preconfirmation_ms: u64,
    pub target_proof_window_ms: u64,
    pub min_privacy_set_size: u64,
    pub window_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_sponsor_cover_bps: u64,
    pub low_fee_ceiling_microunits: u64,
    pub base_micro_fee_microunits: u64,
    pub min_compression_ratio_bps: u64,
    pub max_compressed_receipt_bytes: u64,
    pub max_aggregated_proof_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_HASH_SUITE
                .to_string(),
            pq_auth_suite:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_PQ_AUTH_SUITE
                    .to_string(),
            lane_scheme: PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_LANE_SCHEME
                .to_string(),
            task_scheme: PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_TASK_SCHEME
                .to_string(),
            preconfirmation_scheme:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_PRECONF_SCHEME
                    .to_string(),
            proof_window_scheme:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_WINDOW_SCHEME
                    .to_string(),
            sponsor_scheme:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_SPONSOR_SCHEME
                    .to_string(),
            receipt_scheme:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_RECEIPT_SCHEME
                    .to_string(),
            rebate_scheme:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_REBATE_SCHEME
                    .to_string(),
            ordering_scheme:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_ORDERING_SCHEME
                    .to_string(),
            settlement_scheme:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_SETTLEMENT_SCHEME
                    .to_string(),
            max_lanes: DEFAULT_MAX_LANES,
            max_tasks: DEFAULT_MAX_TASKS,
            max_preconfirmations: DEFAULT_MAX_PRECONFIRMATIONS,
            max_proof_windows: DEFAULT_MAX_PROOF_WINDOWS,
            max_sponsor_reservations: DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_ordering_commitments: DEFAULT_MAX_ORDERING_COMMITMENTS,
            max_settlement_batches: DEFAULT_MAX_SETTLEMENT_BATCHES,
            max_tasks_per_window: DEFAULT_MAX_TASKS_PER_WINDOW,
            max_windows_per_settlement: DEFAULT_MAX_WINDOWS_PER_SETTLEMENT,
            task_ttl_blocks: DEFAULT_TASK_TTL_BLOCKS,
            preconfirmation_ttl_blocks: DEFAULT_PRECONF_TTL_BLOCKS,
            proof_window_ttl_blocks: DEFAULT_PROOF_WINDOW_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONF_MS,
            target_proof_window_ms: DEFAULT_TARGET_PROOF_WINDOW_MS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            window_privacy_set_size: DEFAULT_WINDOW_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_sponsor_cover_bps: DEFAULT_MAX_SPONSOR_COVER_BPS,
            low_fee_ceiling_microunits: DEFAULT_LOW_FEE_CEILING_MICRO_UNITS,
            base_micro_fee_microunits: DEFAULT_BASE_MICRO_FEE_MICRO_UNITS,
            min_compression_ratio_bps: DEFAULT_MIN_COMPRESSION_RATIO_BPS,
            max_compressed_receipt_bytes: DEFAULT_MAX_COMPRESSED_RECEIPT_BYTES,
            max_aggregated_proof_bytes: DEFAULT_MAX_AGGREGATED_PROOF_BYTES,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "lane_scheme": self.lane_scheme,
            "task_scheme": self.task_scheme,
            "preconfirmation_scheme": self.preconfirmation_scheme,
            "proof_window_scheme": self.proof_window_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "receipt_scheme": self.receipt_scheme,
            "rebate_scheme": self.rebate_scheme,
            "ordering_scheme": self.ordering_scheme,
            "settlement_scheme": self.settlement_scheme,
            "max_lanes": self.max_lanes,
            "max_tasks": self.max_tasks,
            "max_preconfirmations": self.max_preconfirmations,
            "max_proof_windows": self.max_proof_windows,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_ordering_commitments": self.max_ordering_commitments,
            "max_settlement_batches": self.max_settlement_batches,
            "max_tasks_per_window": self.max_tasks_per_window,
            "max_windows_per_settlement": self.max_windows_per_settlement,
            "task_ttl_blocks": self.task_ttl_blocks,
            "preconfirmation_ttl_blocks": self.preconfirmation_ttl_blocks,
            "proof_window_ttl_blocks": self.proof_window_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "target_proof_window_ms": self.target_proof_window_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "window_privacy_set_size": self.window_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_sponsor_cover_bps": self.max_sponsor_cover_bps,
            "low_fee_ceiling_microunits": self.low_fee_ceiling_microunits,
            "base_micro_fee_microunits": self.base_micro_fee_microunits,
            "min_compression_ratio_bps": self.min_compression_ratio_bps,
            "max_compressed_receipt_bytes": self.max_compressed_receipt_bytes,
            "max_aggregated_proof_bytes": self.max_aggregated_proof_bytes,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateMicrobatchLane {
    pub lane_id: String,
    pub lane_kind: MicrobatchLaneKind,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub encryption_key_commitment: String,
    pub accepted_contract_root: String,
    pub sponsor_allowlist_root: String,
    pub sequencing_policy_root: String,
    pub priority_weight: u64,
    pub base_fee_microunits: u64,
    pub congestion_multiplier_bps: u64,
    pub target_preconfirmation_ms: u64,
    pub target_window_ms: u64,
    pub max_tasks_per_window: usize,
    pub privacy_set_size: u64,
    pub queued_tasks: u64,
    pub open_window_id: Option<String>,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl PrivateMicrobatchLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind,
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "encryption_key_commitment": self.encryption_key_commitment,
            "accepted_contract_root": self.accepted_contract_root,
            "sponsor_allowlist_root": self.sponsor_allowlist_root,
            "sequencing_policy_root": self.sequencing_policy_root,
            "priority_weight": self.priority_weight,
            "base_fee_microunits": self.base_fee_microunits,
            "congestion_multiplier_bps": self.congestion_multiplier_bps,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "target_window_ms": self.target_window_ms,
            "max_tasks_per_window": self.max_tasks_per_window,
            "privacy_set_size": self.privacy_set_size,
            "queued_tasks": self.queued_tasks,
            "open_window_id": self.open_window_id,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedExecutionTask {
    pub task_id: String,
    pub lane_id: String,
    pub sponsor_id: Option<String>,
    pub task_kind: ExecutionTaskKind,
    pub status: ExecutionTaskStatus,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub encrypted_call_root: String,
    pub witness_hint_root: String,
    pub read_set_root: String,
    pub write_set_commitment: String,
    pub nullifier_hash: String,
    pub priority_fee_microunits: u64,
    pub max_user_fee_microunits: u64,
    pub estimated_gas: u64,
    pub preconfirmation_deadline_ms: u64,
    pub expires_at_height: u64,
    pub submitted_at_height: u64,
    pub scheduled_window_id: Option<String>,
    pub ordering_commitment_id: Option<String>,
}

impl EncryptedExecutionTask {
    pub fn public_record(&self) -> Value {
        json!({
            "task_id": self.task_id,
            "lane_id": self.lane_id,
            "sponsor_id": self.sponsor_id,
            "task_kind": self.task_kind,
            "status": self.status,
            "sender_commitment": self.sender_commitment,
            "contract_commitment": self.contract_commitment,
            "encrypted_call_root": self.encrypted_call_root,
            "witness_hint_root": self.witness_hint_root,
            "read_set_root": self.read_set_root,
            "write_set_commitment": self.write_set_commitment,
            "nullifier_hash": self.nullifier_hash,
            "priority_fee_microunits": self.priority_fee_microunits,
            "max_user_fee_microunits": self.max_user_fee_microunits,
            "estimated_gas": self.estimated_gas,
            "preconfirmation_deadline_ms": self.preconfirmation_deadline_ms,
            "expires_at_height": self.expires_at_height,
            "submitted_at_height": self.submitted_at_height,
            "scheduled_window_id": self.scheduled_window_id,
            "ordering_commitment_id": self.ordering_commitment_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreconfirmationSla {
    pub preconfirmation_id: String,
    pub task_id: String,
    pub lane_id: String,
    pub status: PreconfirmationStatus,
    pub sequencer_commitment: String,
    pub promised_latency_ms: u64,
    pub max_fee_microunits: u64,
    pub penalty_bond_microunits: u64,
    pub privacy_set_size: u64,
    pub accepted_at_height: u64,
    pub expires_at_height: u64,
    pub fulfilled_at_height: Option<u64>,
}

impl PreconfirmationSla {
    pub fn public_record(&self) -> Value {
        json!({
            "preconfirmation_id": self.preconfirmation_id,
            "task_id": self.task_id,
            "lane_id": self.lane_id,
            "status": self.status,
            "sequencer_commitment": self.sequencer_commitment,
            "promised_latency_ms": self.promised_latency_ms,
            "max_fee_microunits": self.max_fee_microunits,
            "penalty_bond_microunits": self.penalty_bond_microunits,
            "privacy_set_size": self.privacy_set_size,
            "accepted_at_height": self.accepted_at_height,
            "expires_at_height": self.expires_at_height,
            "fulfilled_at_height": self.fulfilled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecursiveProofWindow {
    pub window_id: String,
    pub lane_id: String,
    pub status: ProofWindowStatus,
    pub task_ids: Vec<String>,
    pub ordering_commitment_id: Option<String>,
    pub task_root: String,
    pub nullifier_root: String,
    pub read_set_root: String,
    pub witness_root: String,
    pub recursive_input_root: String,
    pub recursive_output_root: String,
    pub proof_commitment: String,
    pub aggregated_proof_bytes: u64,
    pub privacy_set_size: u64,
    pub estimated_fee_microunits: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: Option<u64>,
    pub expires_at_height: u64,
}

impl RecursiveProofWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "status": self.status,
            "task_ids": self.task_ids,
            "ordering_commitment_id": self.ordering_commitment_id,
            "task_root": self.task_root,
            "nullifier_root": self.nullifier_root,
            "read_set_root": self.read_set_root,
            "witness_root": self.witness_root,
            "recursive_input_root": self.recursive_input_root,
            "recursive_output_root": self.recursive_output_root,
            "proof_commitment": self.proof_commitment,
            "aggregated_proof_bytes": self.aggregated_proof_bytes,
            "privacy_set_size": self.privacy_set_size,
            "estimated_fee_microunits": self.estimated_fee_microunits,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_id: String,
    pub lane_id: String,
    pub task_id: Option<String>,
    pub window_id: Option<String>,
    pub status: SponsorReservationStatus,
    pub sponsor_commitment: String,
    pub policy_root: String,
    pub reserved_microunits: u64,
    pub consumed_microunits: u64,
    pub max_cover_bps: u64,
    pub rebate_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "task_id": self.task_id,
            "window_id": self.window_id,
            "status": self.status,
            "sponsor_commitment": self.sponsor_commitment,
            "policy_root": self.policy_root,
            "reserved_microunits": self.reserved_microunits,
            "consumed_microunits": self.consumed_microunits,
            "max_cover_bps": self.max_cover_bps,
            "rebate_bps": self.rebate_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OrderingCommitment {
    pub ordering_id: String,
    pub lane_id: String,
    pub window_id: Option<String>,
    pub status: OrderingCommitmentStatus,
    pub commit_root: String,
    pub reveal_root: String,
    pub encrypted_orderflow_root: String,
    pub fairness_proof_root: String,
    pub anti_mev_score: u64,
    pub first_seen_height: u64,
    pub reveal_deadline_height: u64,
}

impl OrderingCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "ordering_id": self.ordering_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "status": self.status,
            "commit_root": self.commit_root,
            "reveal_root": self.reveal_root,
            "encrypted_orderflow_root": self.encrypted_orderflow_root,
            "fairness_proof_root": self.fairness_proof_root,
            "anti_mev_score": self.anti_mev_score,
            "first_seen_height": self.first_seen_height,
            "reveal_deadline_height": self.reveal_deadline_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompressedReceipt {
    pub receipt_id: String,
    pub task_id: String,
    pub window_id: String,
    pub batch_id: Option<String>,
    pub status: ReceiptStatus,
    pub codec: CompressionCodec,
    pub receipt_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub execution_trace_root: String,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub user_fee_microunits: u64,
    pub sponsor_fee_microunits: u64,
    pub rebate_microunits: u64,
    pub settled_at_height: u64,
}

impl CompressedReceipt {
    pub fn compression_ratio_bps(&self) -> u64 {
        if self.uncompressed_bytes == 0 {
            return MAX_BPS;
        }
        self.compressed_bytes.saturating_mul(MAX_BPS) / self.uncompressed_bytes
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "window_id": self.window_id,
            "batch_id": self.batch_id,
            "status": self.status,
            "codec": self.codec,
            "receipt_root": self.receipt_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "execution_trace_root": self.execution_trace_root,
            "compressed_bytes": self.compressed_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "compression_ratio_bps": self.compression_ratio_bps(),
            "user_fee_microunits": self.user_fee_microunits,
            "sponsor_fee_microunits": self.sponsor_fee_microunits,
            "rebate_microunits": self.rebate_microunits,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub task_id: String,
    pub sponsor_id: Option<String>,
    pub status: RebateStatus,
    pub claimant_commitment: String,
    pub rebate_root: String,
    pub amount_microunits: u64,
    pub reason: String,
    pub accrued_at_height: u64,
    pub claimable_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "claimant_commitment": self.claimant_commitment,
            "rebate_root": self.rebate_root,
            "amount_microunits": self.amount_microunits,
            "reason": self.reason,
            "accrued_at_height": self.accrued_at_height,
            "claimable_at_height": self.claimable_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub status: SettlementBatchStatus,
    pub window_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub builder_commitment: String,
    pub settlement_tx_hash: String,
    pub window_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub recursive_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub total_user_fee_microunits: u64,
    pub total_sponsor_fee_microunits: u64,
    pub total_rebate_microunits: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: Option<u64>,
    pub settled_at_height: Option<u64>,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status,
            "window_ids": self.window_ids,
            "receipt_ids": self.receipt_ids,
            "builder_commitment": self.builder_commitment,
            "settlement_tx_hash": self.settlement_tx_hash,
            "window_root": self.window_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "recursive_proof_root": self.recursive_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "total_user_fee_microunits": self.total_user_fee_microunits,
            "total_sponsor_fee_microunits": self.total_sponsor_fee_microunits,
            "total_rebate_microunits": self.total_rebate_microunits,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub lane_count: usize,
    pub task_count: usize,
    pub active_task_count: usize,
    pub preconfirmation_count: usize,
    pub proof_window_count: usize,
    pub sponsor_reservation_count: usize,
    pub receipt_count: usize,
    pub rebate_count: usize,
    pub ordering_commitment_count: usize,
    pub settlement_batch_count: usize,
    pub consumed_nullifier_count: usize,
    pub events_emitted: u64,
    pub total_user_fee_microunits: u64,
    pub total_sponsor_fee_microunits: u64,
    pub total_rebate_microunits: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "task_count": self.task_count,
            "active_task_count": self.active_task_count,
            "preconfirmation_count": self.preconfirmation_count,
            "proof_window_count": self.proof_window_count,
            "sponsor_reservation_count": self.sponsor_reservation_count,
            "receipt_count": self.receipt_count,
            "rebate_count": self.rebate_count,
            "ordering_commitment_count": self.ordering_commitment_count,
            "settlement_batch_count": self.settlement_batch_count,
            "consumed_nullifier_count": self.consumed_nullifier_count,
            "events_emitted": self.events_emitted,
            "total_user_fee_microunits": self.total_user_fee_microunits,
            "total_sponsor_fee_microunits": self.total_sponsor_fee_microunits,
            "total_rebate_microunits": self.total_rebate_microunits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SchedulerEvent {
    pub event_id: String,
    pub event_kind: String,
    pub severity: EventSeverity,
    pub subject_id: String,
    pub lane_id: Option<String>,
    pub height: u64,
    pub payload_root: String,
}

impl SchedulerEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "severity": self.severity,
            "subject_id": self.subject_id,
            "lane_id": self.lane_id,
            "height": self.height,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub task_root: String,
    pub preconfirmation_root: String,
    pub proof_window_root: String,
    pub sponsor_reservation_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub ordering_commitment_root: String,
    pub settlement_batch_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "task_root": self.task_root,
            "preconfirmation_root": self.preconfirmation_root,
            "proof_window_root": self.proof_window_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "ordering_commitment_root": self.ordering_commitment_root,
            "settlement_batch_root": self.settlement_batch_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitExecutionTaskRequest {
    pub lane_id: String,
    pub sponsor_id: Option<String>,
    pub task_kind: ExecutionTaskKind,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub encrypted_call_root: String,
    pub witness_hint_root: String,
    pub read_set_root: String,
    pub write_set_commitment: String,
    pub nullifier_hash: String,
    pub priority_fee_microunits: u64,
    pub max_user_fee_microunits: u64,
    pub estimated_gas: u64,
    pub preconfirmation_deadline_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OfferPreconfirmationRequest {
    pub task_id: String,
    pub sequencer_commitment: String,
    pub promised_latency_ms: u64,
    pub max_fee_microunits: u64,
    pub penalty_bond_microunits: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveSponsorRequest {
    pub sponsor_id: String,
    pub lane_id: String,
    pub task_id: Option<String>,
    pub sponsor_commitment: String,
    pub policy_root: String,
    pub reserved_microunits: u64,
    pub max_cover_bps: u64,
    pub rebate_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenProofWindowRequest {
    pub lane_id: String,
    pub ordering_commitment_id: Option<String>,
    pub estimated_fee_microunits: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitOrderingRequest {
    pub lane_id: String,
    pub window_id: Option<String>,
    pub commit_root: String,
    pub encrypted_orderflow_root: String,
    pub fairness_proof_root: String,
    pub anti_mev_score: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettleWindowRequest {
    pub window_id: String,
    pub codec: CompressionCodec,
    pub proof_commitment: String,
    pub recursive_output_root: String,
    pub execution_trace_root: String,
    pub compressed_bytes_per_task: u64,
    pub uncompressed_bytes_per_task: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuildSettlementBatchRequest {
    pub window_ids: Vec<String>,
    pub builder_commitment: String,
    pub settlement_tx_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub lanes: BTreeMap<String, PrivateMicrobatchLane>,
    pub tasks: BTreeMap<String, EncryptedExecutionTask>,
    pub preconfirmations: BTreeMap<String, PreconfirmationSla>,
    pub proof_windows: BTreeMap<String, RecursiveProofWindow>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub compressed_receipts: BTreeMap<String, CompressedReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub ordering_commitments: BTreeMap<String, OrderingCommitment>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: Vec<SchedulerEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            current_height:
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_DEVNET_HEIGHT,
            lanes: BTreeMap::new(),
            tasks: BTreeMap::new(),
            preconfirmations: BTreeMap::new(),
            proof_windows: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            compressed_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            ordering_commitments: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let fast_lane = PrivateMicrobatchLane {
            lane_id: lane_id(MicrobatchLaneKind::UltraFastContractCall, "devnet-fast", 0),
            lane_kind: MicrobatchLaneKind::UltraFastContractCall,
            status: LaneStatus::Open,
            operator_commitment: root_from_values("DEVNET-FAST-OPERATOR", &["sequencer-a"]),
            encryption_key_commitment: root_from_values("DEVNET-FAST-KEY", &["ml-kem-fast"]),
            accepted_contract_root: root_from_values("DEVNET-FAST-CONTRACTS", &["router", "vault"]),
            sponsor_allowlist_root: root_from_values("DEVNET-FAST-SPONSORS", &["sponsor-alpha"]),
            sequencing_policy_root: root_from_values("DEVNET-FAST-POLICY", &["fair-first-seen"]),
            priority_weight: MicrobatchLaneKind::UltraFastContractCall.default_priority(),
            base_fee_microunits: 220,
            congestion_multiplier_bps: 9_800,
            target_preconfirmation_ms: 260,
            target_window_ms: 1_200,
            max_tasks_per_window: 8_192,
            privacy_set_size: 65_536,
            queued_tasks: 0,
            open_window_id: None,
            created_at_height: state.current_height,
            updated_at_height: state.current_height,
        };
        let defi_lane = PrivateMicrobatchLane {
            lane_id: lane_id(MicrobatchLaneKind::DefiNetting, "devnet-defi", 1),
            lane_kind: MicrobatchLaneKind::DefiNetting,
            status: LaneStatus::Open,
            operator_commitment: root_from_values("DEVNET-DEFI-OPERATOR", &["sequencer-b"]),
            encryption_key_commitment: root_from_values("DEVNET-DEFI-KEY", &["ml-kem-defi"]),
            accepted_contract_root: root_from_values(
                "DEVNET-DEFI-CONTRACTS",
                &["amm", "stable-swap"],
            ),
            sponsor_allowlist_root: root_from_values(
                "DEVNET-DEFI-SPONSORS",
                &["sponsor-alpha", "sponsor-beta"],
            ),
            sequencing_policy_root: root_from_values(
                "DEVNET-DEFI-POLICY",
                &["batch-netting", "anti-mev"],
            ),
            priority_weight: MicrobatchLaneKind::DefiNetting.default_priority(),
            base_fee_microunits: 180,
            congestion_multiplier_bps: 9_300,
            target_preconfirmation_ms: 320,
            target_window_ms: 1_600,
            max_tasks_per_window: 16_384,
            privacy_set_size: 262_144,
            queued_tasks: 0,
            open_window_id: None,
            created_at_height: state.current_height,
            updated_at_height: state.current_height,
        };
        let bridge_lane = PrivateMicrobatchLane {
            lane_id: lane_id(MicrobatchLaneKind::MoneroBridge, "devnet-bridge", 2),
            lane_kind: MicrobatchLaneKind::MoneroBridge,
            status: LaneStatus::SponsorOnly,
            operator_commitment: root_from_values("DEVNET-BRIDGE-OPERATOR", &["sequencer-c"]),
            encryption_key_commitment: root_from_values("DEVNET-BRIDGE-KEY", &["ml-kem-bridge"]),
            accepted_contract_root: root_from_values(
                "DEVNET-BRIDGE-CONTRACTS",
                &["monero-exit", "settlement"],
            ),
            sponsor_allowlist_root: root_from_values("DEVNET-BRIDGE-SPONSORS", &["sponsor-beta"]),
            sequencing_policy_root: root_from_values(
                "DEVNET-BRIDGE-POLICY",
                &["safety-first", "fair-first-seen"],
            ),
            priority_weight: MicrobatchLaneKind::MoneroBridge.default_priority(),
            base_fee_microunits: 480,
            congestion_multiplier_bps: 10_000,
            target_preconfirmation_ms: 400,
            target_window_ms: 1_800,
            max_tasks_per_window: 4_096,
            privacy_set_size: 131_072,
            queued_tasks: 0,
            open_window_id: None,
            created_at_height: state.current_height,
            updated_at_height: state.current_height,
        };
        let fast_lane_id = fast_lane.lane_id.clone();
        let defi_lane_id = defi_lane.lane_id.clone();
        let bridge_lane_id = bridge_lane.lane_id.clone();
        state.add_lane(fast_lane).expect("devnet fast lane");
        state.add_lane(defi_lane).expect("devnet defi lane");
        state.add_lane(bridge_lane).expect("devnet bridge lane");
        let task_a = state
            .submit_execution_task(SubmitExecutionTaskRequest {
                lane_id: fast_lane_id,
                sponsor_id: Some("sponsor-alpha".to_string()),
                task_kind: ExecutionTaskKind::PrivateCall,
                sender_commitment: "devnet-sender-fast".to_string(),
                contract_commitment: "devnet-vault-contract".to_string(),
                encrypted_call_root: payload_root("DEVNET-CALL-A", &json!({"ciphertext": "fast"})),
                witness_hint_root: root_from_values("DEVNET-WITNESS-A", &["hint-a"]),
                read_set_root: root_from_values("DEVNET-READ-A", &["vault:slot:1"]),
                write_set_commitment: "devnet-write-a".to_string(),
                nullifier_hash: deterministic_id("DEVNET-NULLIFIER", "fast", 0),
                priority_fee_microunits: 12,
                max_user_fee_microunits: 420,
                estimated_gas: 1_120_000,
                preconfirmation_deadline_ms: 320,
            })
            .expect("devnet task a");
        let task_b = state
            .submit_execution_task(SubmitExecutionTaskRequest {
                lane_id: defi_lane_id.clone(),
                sponsor_id: Some("sponsor-beta".to_string()),
                task_kind: ExecutionTaskKind::AmmSwap,
                sender_commitment: "devnet-sender-defi".to_string(),
                contract_commitment: "devnet-amm-contract".to_string(),
                encrypted_call_root: payload_root("DEVNET-CALL-B", &json!({"ciphertext": "swap"})),
                witness_hint_root: root_from_values("DEVNET-WITNESS-B", &["hint-b"]),
                read_set_root: root_from_values("DEVNET-READ-B", &["amm:pool:1"]),
                write_set_commitment: "devnet-write-b".to_string(),
                nullifier_hash: deterministic_id("DEVNET-NULLIFIER", "defi", 1),
                priority_fee_microunits: 8,
                max_user_fee_microunits: 360,
                estimated_gas: 980_000,
                preconfirmation_deadline_ms: 360,
            })
            .expect("devnet task b");
        let _bridge_reservation = state
            .reserve_sponsor(ReserveSponsorRequest {
                sponsor_id: "sponsor-beta".to_string(),
                lane_id: bridge_lane_id,
                task_id: None,
                sponsor_commitment: "devnet-sponsor-beta".to_string(),
                policy_root: root_from_values("DEVNET-SPONSOR-BETA-POLICY", &["bridge-only"]),
                reserved_microunits: 7_500_000,
                max_cover_bps: 9_500,
                rebate_bps: 6,
            })
            .expect("devnet sponsor reservation");
        state
            .offer_preconfirmation(OfferPreconfirmationRequest {
                task_id: task_a.clone(),
                sequencer_commitment: "devnet-sequencer-a".to_string(),
                promised_latency_ms: 250,
                max_fee_microunits: 280,
                penalty_bond_microunits: 2_000_000,
            })
            .expect("devnet preconfirmation a");
        state
            .offer_preconfirmation(OfferPreconfirmationRequest {
                task_id: task_b,
                sequencer_commitment: "devnet-sequencer-b".to_string(),
                promised_latency_ms: 310,
                max_fee_microunits: 240,
                penalty_bond_microunits: 1_600_000,
            })
            .expect("devnet preconfirmation b");
        let ordering_id = state
            .commit_ordering(CommitOrderingRequest {
                lane_id: defi_lane_id.clone(),
                window_id: None,
                commit_root: root_from_values("DEVNET-ORDER-COMMIT", &["first-seen", "encrypted"]),
                encrypted_orderflow_root: root_from_values("DEVNET-ORDER-FLOW", &["task-b"]),
                fairness_proof_root: root_from_values("DEVNET-FAIRNESS", &["anti-mev"]),
                anti_mev_score: 9_700,
            })
            .expect("devnet ordering");
        let window_id = state
            .open_proof_window(OpenProofWindowRequest {
                lane_id: defi_lane_id,
                ordering_commitment_id: Some(ordering_id),
                estimated_fee_microunits: 620,
            })
            .expect("devnet window");
        let task_ids = state
            .tasks
            .values()
            .filter(|task| task.lane_id == state.proof_windows[&window_id].lane_id)
            .map(|task| task.task_id.clone())
            .collect::<Vec<_>>();
        for task_id in task_ids {
            state
                .attach_task_to_window(&task_id, &window_id)
                .expect("attach");
        }
        state
    }

    pub fn add_lane(&mut self, lane: PrivateMicrobatchLane) -> Result<()> {
        self.ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        if self.lanes.contains_key(&lane.lane_id) {
            return Err("lane already exists".to_string());
        }
        if lane.privacy_set_size < self.config.min_privacy_set_size {
            return Err("lane privacy set is below scheduler minimum".to_string());
        }
        self.emit_event(
            "lane_added",
            &lane.lane_id,
            Some(&lane.lane_id),
            EventSeverity::Info,
            &lane.public_record(),
        );
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn submit_execution_task(&mut self, request: SubmitExecutionTaskRequest) -> Result<String> {
        self.ensure_capacity("tasks", self.tasks.len(), self.config.max_tasks)?;
        if self.consumed_nullifiers.contains(&request.nullifier_hash) {
            return Err("nullifier already consumed".to_string());
        }
        let lane = self
            .lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| "lane is missing".to_string())?;
        if !lane.status.accepts_tasks() {
            return Err("lane does not accept tasks".to_string());
        }
        if request.max_user_fee_microunits > self.config.low_fee_ceiling_microunits {
            return Err("task exceeds low-fee ceiling".to_string());
        }
        let sequence = self.tasks.len() as u64 + 1;
        let task_id = execution_task_id(&request, sequence);
        let task = EncryptedExecutionTask {
            task_id: task_id.clone(),
            lane_id: request.lane_id.clone(),
            sponsor_id: request.sponsor_id,
            task_kind: request.task_kind,
            status: ExecutionTaskStatus::Encrypted,
            sender_commitment: request.sender_commitment,
            contract_commitment: request.contract_commitment,
            encrypted_call_root: request.encrypted_call_root,
            witness_hint_root: request.witness_hint_root,
            read_set_root: request.read_set_root,
            write_set_commitment: request.write_set_commitment,
            nullifier_hash: request.nullifier_hash,
            priority_fee_microunits: request.priority_fee_microunits,
            max_user_fee_microunits: request.max_user_fee_microunits,
            estimated_gas: request.estimated_gas,
            preconfirmation_deadline_ms: request.preconfirmation_deadline_ms,
            expires_at_height: self.current_height + self.config.task_ttl_blocks,
            submitted_at_height: self.current_height,
            scheduled_window_id: None,
            ordering_commitment_id: None,
        };
        lane.queued_tasks = lane.queued_tasks.saturating_add(1);
        lane.updated_at_height = self.current_height;
        self.consumed_nullifiers.insert(task.nullifier_hash.clone());
        self.emit_event(
            "task_submitted",
            &task_id,
            Some(&request.lane_id),
            EventSeverity::Info,
            &task.public_record(),
        );
        self.tasks.insert(task_id.clone(), task);
        Ok(task_id)
    }

    pub fn offer_preconfirmation(
        &mut self,
        request: OfferPreconfirmationRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "preconfirmations",
            self.preconfirmations.len(),
            self.config.max_preconfirmations,
        )?;
        let (lane_id, privacy_set_size) = {
            let task = self
                .tasks
                .get(&request.task_id)
                .ok_or_else(|| "task is missing".to_string())?;
            let lane = self
                .lanes
                .get(&task.lane_id)
                .ok_or_else(|| "lane is missing".to_string())?;
            if request.promised_latency_ms > lane.target_preconfirmation_ms {
                return Err("preconfirmation misses lane latency target".to_string());
            }
            if request.max_fee_microunits > task.max_user_fee_microunits {
                return Err("preconfirmation exceeds user fee limit".to_string());
            }
            (task.lane_id.clone(), lane.privacy_set_size)
        };
        let sequence = self.preconfirmations.len() as u64 + 1;
        let preconfirmation_id = preconfirmation_id(&request, &lane_id, sequence);
        let preconfirmation = PreconfirmationSla {
            preconfirmation_id: preconfirmation_id.clone(),
            task_id: request.task_id.clone(),
            lane_id: lane_id.clone(),
            status: PreconfirmationStatus::Accepted,
            sequencer_commitment: request.sequencer_commitment,
            promised_latency_ms: request.promised_latency_ms,
            max_fee_microunits: request.max_fee_microunits,
            penalty_bond_microunits: request.penalty_bond_microunits,
            privacy_set_size,
            accepted_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.preconfirmation_ttl_blocks,
            fulfilled_at_height: None,
        };
        if let Some(task) = self.tasks.get_mut(&request.task_id) {
            task.status = ExecutionTaskStatus::Preconfirmed;
        }
        self.emit_event(
            "preconfirmation_accepted",
            &preconfirmation_id,
            Some(&lane_id),
            EventSeverity::Info,
            &preconfirmation.public_record(),
        );
        self.preconfirmations
            .insert(preconfirmation_id.clone(), preconfirmation);
        Ok(preconfirmation_id)
    }

    pub fn reserve_sponsor(&mut self, request: ReserveSponsorRequest) -> Result<String> {
        self.ensure_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
        )?;
        let lane = self
            .lanes
            .get(&request.lane_id)
            .ok_or_else(|| "lane is missing".to_string())?;
        if request.max_cover_bps > self.config.max_sponsor_cover_bps {
            return Err("sponsor cover exceeds runtime cap".to_string());
        }
        if let Some(task_id) = request.task_id.as_deref() {
            let task = self
                .tasks
                .get(task_id)
                .ok_or_else(|| "task is missing".to_string())?;
            if task.lane_id != request.lane_id {
                return Err("sponsor reservation lane does not match task".to_string());
            }
        }
        let sequence = self.sponsor_reservations.len() as u64 + 1;
        let reservation_id = sponsor_reservation_id(&request, sequence);
        let reservation = SponsorReservation {
            reservation_id: reservation_id.clone(),
            sponsor_id: request.sponsor_id.clone(),
            lane_id: request.lane_id.clone(),
            task_id: request.task_id.clone(),
            window_id: None,
            status: SponsorReservationStatus::Reserved,
            sponsor_commitment: request.sponsor_commitment,
            policy_root: request.policy_root,
            reserved_microunits: request.reserved_microunits,
            consumed_microunits: 0,
            max_cover_bps: request.max_cover_bps,
            rebate_bps: request.rebate_bps,
            opened_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.task_ttl_blocks,
        };
        if let Some(task_id) = request.task_id.as_deref() {
            if let Some(task) = self.tasks.get_mut(task_id) {
                task.status = ExecutionTaskStatus::Sponsored;
                task.sponsor_id = Some(request.sponsor_id);
            }
        }
        self.emit_event(
            "sponsor_reserved",
            &reservation_id,
            Some(&lane.lane_id),
            EventSeverity::Info,
            &reservation.public_record(),
        );
        self.sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        Ok(reservation_id)
    }

    pub fn commit_ordering(&mut self, request: CommitOrderingRequest) -> Result<String> {
        self.ensure_capacity(
            "ordering_commitments",
            self.ordering_commitments.len(),
            self.config.max_ordering_commitments,
        )?;
        if !self.lanes.contains_key(&request.lane_id) {
            return Err("lane is missing".to_string());
        }
        if request.anti_mev_score < 7_500 {
            return Err("anti-MEV score is below scheduler minimum".to_string());
        }
        let sequence = self.ordering_commitments.len() as u64 + 1;
        let ordering_id = ordering_commitment_id(&request, sequence);
        let ordering = OrderingCommitment {
            ordering_id: ordering_id.clone(),
            lane_id: request.lane_id.clone(),
            window_id: request.window_id,
            status: OrderingCommitmentStatus::Committed,
            commit_root: request.commit_root,
            reveal_root: merkle_root("RECURSIVE-EXECUTION-ORDERING-REVEAL:pending", &[]),
            encrypted_orderflow_root: request.encrypted_orderflow_root,
            fairness_proof_root: request.fairness_proof_root,
            anti_mev_score: request.anti_mev_score,
            first_seen_height: self.current_height,
            reveal_deadline_height: self.current_height + self.config.proof_window_ttl_blocks,
        };
        self.emit_event(
            "ordering_committed",
            &ordering_id,
            Some(&request.lane_id),
            EventSeverity::Info,
            &ordering.public_record(),
        );
        self.ordering_commitments
            .insert(ordering_id.clone(), ordering);
        Ok(ordering_id)
    }

    pub fn open_proof_window(&mut self, request: OpenProofWindowRequest) -> Result<String> {
        self.ensure_capacity(
            "proof_windows",
            self.proof_windows.len(),
            self.config.max_proof_windows,
        )?;
        let lane = self
            .lanes
            .get(&request.lane_id)
            .ok_or_else(|| "lane is missing".to_string())?;
        if !lane.status.accepts_tasks() {
            return Err("lane does not accept proof windows".to_string());
        }
        if let Some(ordering_id) = request.ordering_commitment_id.as_deref() {
            let ordering = self
                .ordering_commitments
                .get(ordering_id)
                .ok_or_else(|| "ordering commitment is missing".to_string())?;
            if ordering.lane_id != request.lane_id {
                return Err("ordering commitment lane mismatch".to_string());
            }
        }
        let sequence = self.proof_windows.len() as u64 + 1;
        let window_id = proof_window_id(&request, sequence);
        let window = RecursiveProofWindow {
            window_id: window_id.clone(),
            lane_id: request.lane_id.clone(),
            status: ProofWindowStatus::Open,
            task_ids: Vec::new(),
            ordering_commitment_id: request.ordering_commitment_id.clone(),
            task_root: merkle_root("RECURSIVE-EXECUTION-WINDOW-TASKS:empty", &[]),
            nullifier_root: merkle_root("RECURSIVE-EXECUTION-WINDOW-NULLIFIERS:empty", &[]),
            read_set_root: merkle_root("RECURSIVE-EXECUTION-WINDOW-READSETS:empty", &[]),
            witness_root: merkle_root("RECURSIVE-EXECUTION-WINDOW-WITNESSES:empty", &[]),
            recursive_input_root: merkle_root("RECURSIVE-EXECUTION-WINDOW-INPUTS:empty", &[]),
            recursive_output_root: merkle_root("RECURSIVE-EXECUTION-WINDOW-OUTPUTS:pending", &[]),
            proof_commitment: String::new(),
            aggregated_proof_bytes: 0,
            privacy_set_size: lane
                .privacy_set_size
                .max(self.config.window_privacy_set_size),
            estimated_fee_microunits: request.estimated_fee_microunits,
            opened_at_height: self.current_height,
            sealed_at_height: None,
            expires_at_height: self.current_height + self.config.proof_window_ttl_blocks,
        };
        if let Some(lane) = self.lanes.get_mut(&request.lane_id) {
            lane.open_window_id = Some(window_id.clone());
            lane.updated_at_height = self.current_height;
        }
        if let Some(ordering_id) = request.ordering_commitment_id.as_deref() {
            if let Some(ordering) = self.ordering_commitments.get_mut(ordering_id) {
                ordering.window_id = Some(window_id.clone());
            }
        }
        self.emit_event(
            "proof_window_opened",
            &window_id,
            Some(&request.lane_id),
            EventSeverity::Info,
            &window.public_record(),
        );
        self.proof_windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn attach_task_to_window(&mut self, task_id: &str, window_id: &str) -> Result<()> {
        let (lane_id, task_status) = {
            let task = self
                .tasks
                .get(task_id)
                .ok_or_else(|| "task is missing".to_string())?;
            (task.lane_id.clone(), task.status)
        };
        if !task_status.windowable() {
            return Err("task cannot be added to a proof window".to_string());
        }
        let max_tasks_per_window = self.config.max_tasks_per_window;
        let window = self
            .proof_windows
            .get_mut(window_id)
            .ok_or_else(|| "proof window is missing".to_string())?;
        if window.lane_id != lane_id {
            return Err("task lane does not match proof window lane".to_string());
        }
        if !window.status.accepts_tasks() {
            return Err("proof window does not accept tasks".to_string());
        }
        if window.task_ids.len() >= max_tasks_per_window {
            return Err("proof window task capacity reached".to_string());
        }
        if !window.task_ids.iter().any(|id| id == task_id) {
            window.task_ids.push(task_id.to_string());
        }
        window.status = ProofWindowStatus::Filling;
        if let Some(task) = self.tasks.get_mut(task_id) {
            task.status = ExecutionTaskStatus::Windowed;
            task.scheduled_window_id = Some(window_id.to_string());
            task.ordering_commitment_id = window.ordering_commitment_id.clone();
        }
        self.refresh_window_roots(window_id)?;
        self.emit_event(
            "task_windowed",
            task_id,
            Some(&lane_id),
            EventSeverity::Info,
            &json!({"task_id": task_id, "window_id": window_id}),
        );
        Ok(())
    }

    pub fn seal_proof_window(&mut self, window_id: &str) -> Result<()> {
        {
            let window = self
                .proof_windows
                .get(window_id)
                .ok_or_else(|| "proof window is missing".to_string())?;
            if window.task_ids.is_empty() {
                return Err("cannot seal empty proof window".to_string());
            }
        }
        self.refresh_window_roots(window_id)?;
        let lane_id = {
            let window = self
                .proof_windows
                .get_mut(window_id)
                .ok_or_else(|| "proof window is missing".to_string())?;
            window.status = ProofWindowStatus::Sealed;
            window.sealed_at_height = Some(self.current_height);
            window.lane_id.clone()
        };
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            if lane.open_window_id.as_deref() == Some(window_id) {
                lane.open_window_id = None;
            }
            lane.updated_at_height = self.current_height;
        }
        let record = self.proof_windows[window_id].public_record();
        self.emit_event(
            "proof_window_sealed",
            window_id,
            Some(&lane_id),
            EventSeverity::Info,
            &record,
        );
        Ok(())
    }

    pub fn settle_window(&mut self, request: SettleWindowRequest) -> Result<Vec<String>> {
        self.seal_proof_window(&request.window_id)?;
        let state_root_before = self.state_root();
        let task_ids = {
            let window = self
                .proof_windows
                .get_mut(&request.window_id)
                .ok_or_else(|| "proof window is missing".to_string())?;
            window.status = ProofWindowStatus::Proven;
            window.proof_commitment = request.proof_commitment.clone();
            window.recursive_output_root = request.recursive_output_root.clone();
            window.aggregated_proof_bytes = request
                .compressed_bytes_per_task
                .saturating_mul(window.task_ids.len() as u64);
            window.task_ids.clone()
        };
        let mut receipt_ids = Vec::with_capacity(task_ids.len());
        for task_id in task_ids {
            let task = self
                .tasks
                .get(&task_id)
                .ok_or_else(|| "task is missing".to_string())?
                .clone();
            let user_fee = self.low_fee_for_task(&task);
            let sponsor_fee = self.sponsor_fee_for_task(&task, user_fee);
            let rebate = user_fee.saturating_mul(self.config.target_rebate_bps) / MAX_BPS;
            let sequence = self.compressed_receipts.len() as u64 + 1;
            let receipt_id = receipt_id(&task, &request.window_id, sequence);
            let receipt = CompressedReceipt {
                receipt_id: receipt_id.clone(),
                task_id: task_id.clone(),
                window_id: request.window_id.clone(),
                batch_id: None,
                status: ReceiptStatus::Compressed,
                codec: request.codec,
                receipt_root: payload_root(
                    "RECURSIVE-EXECUTION-COMPRESSED-RECEIPT",
                    &json!({"task_id": task_id, "window_id": request.window_id}),
                ),
                state_root_before: state_root_before.clone(),
                state_root_after: String::new(),
                execution_trace_root: request.execution_trace_root.clone(),
                compressed_bytes: request.compressed_bytes_per_task,
                uncompressed_bytes: request.uncompressed_bytes_per_task,
                user_fee_microunits: user_fee,
                sponsor_fee_microunits: sponsor_fee,
                rebate_microunits: rebate,
                settled_at_height: self.current_height,
            };
            if receipt.compressed_bytes > self.config.max_compressed_receipt_bytes {
                return Err("compressed receipt exceeds byte cap".to_string());
            }
            if receipt.compression_ratio_bps() > self.config.min_compression_ratio_bps {
                return Err("receipt compression ratio is not low-fee enough".to_string());
            }
            self.compressed_receipts.insert(receipt_id.clone(), receipt);
            if let Some(task) = self.tasks.get_mut(&task_id) {
                task.status = ExecutionTaskStatus::Settled;
            }
            self.accrue_rebate(&receipt_id)?;
            receipt_ids.push(receipt_id);
        }
        let state_root_after = self.state_root();
        for receipt_id in &receipt_ids {
            if let Some(receipt) = self.compressed_receipts.get_mut(receipt_id) {
                receipt.status = ReceiptStatus::Published;
                receipt.state_root_after = state_root_after.clone();
            }
        }
        if let Some(window) = self.proof_windows.get_mut(&request.window_id) {
            window.status = ProofWindowStatus::Settled;
        }
        self.emit_event(
            "proof_window_settled",
            &request.window_id,
            None,
            EventSeverity::Info,
            &json!({"window_id": request.window_id, "receipts": receipt_ids}),
        );
        Ok(receipt_ids)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildSettlementBatchRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "settlement_batches",
            self.settlement_batches.len(),
            self.config.max_settlement_batches,
        )?;
        if request.window_ids.is_empty() {
            return Err("settlement batch requires at least one window".to_string());
        }
        if request.window_ids.len() > self.config.max_windows_per_settlement {
            return Err("too many proof windows for settlement batch".to_string());
        }
        let state_root_before = self.state_root();
        let mut receipt_ids = Vec::new();
        for window_id in &request.window_ids {
            let window = self
                .proof_windows
                .get(window_id)
                .ok_or_else(|| "proof window is missing".to_string())?;
            if window.status != ProofWindowStatus::Settled {
                return Err("only settled proof windows can enter settlement batch".to_string());
            }
            receipt_ids.extend(
                self.compressed_receipts
                    .values()
                    .filter(|receipt| &receipt.window_id == window_id)
                    .map(|receipt| receipt.receipt_id.clone()),
            );
        }
        let sequence = self.settlement_batches.len() as u64 + 1;
        let batch_id = settlement_batch_id(&request, sequence);
        let receipt_records = receipt_ids
            .iter()
            .filter_map(|id| self.compressed_receipts.get(id))
            .map(CompressedReceipt::public_record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebates
            .values()
            .filter(|rebate| receipt_ids.iter().any(|id| id == &rebate.receipt_id))
            .map(FeeRebate::public_record)
            .collect::<Vec<_>>();
        let total_user_fee_microunits = receipt_ids
            .iter()
            .filter_map(|id| self.compressed_receipts.get(id))
            .map(|receipt| receipt.user_fee_microunits)
            .sum();
        let total_sponsor_fee_microunits = receipt_ids
            .iter()
            .filter_map(|id| self.compressed_receipts.get(id))
            .map(|receipt| receipt.sponsor_fee_microunits)
            .sum();
        let total_rebate_microunits = receipt_ids
            .iter()
            .filter_map(|id| self.compressed_receipts.get(id))
            .map(|receipt| receipt.rebate_microunits)
            .sum();
        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            status: SettlementBatchStatus::Settled,
            window_ids: request.window_ids.clone(),
            receipt_ids: receipt_ids.clone(),
            builder_commitment: request.builder_commitment,
            settlement_tx_hash: request.settlement_tx_hash,
            window_root: root_from_values_vec(
                "RECURSIVE-EXECUTION-SETTLEMENT-WINDOWS",
                &request.window_ids,
            ),
            receipt_root: merkle_root("RECURSIVE-EXECUTION-SETTLEMENT-RECEIPTS", &receipt_records),
            rebate_root: merkle_root("RECURSIVE-EXECUTION-SETTLEMENT-REBATES", &rebate_records),
            recursive_proof_root: payload_root(
                "RECURSIVE-EXECUTION-SETTLEMENT-PROOF",
                &json!({"windows": request.window_ids, "receipts": receipt_ids}),
            ),
            state_root_before,
            state_root_after: String::new(),
            total_user_fee_microunits,
            total_sponsor_fee_microunits,
            total_rebate_microunits,
            opened_at_height: self.current_height,
            sealed_at_height: Some(self.current_height),
            settled_at_height: Some(self.current_height),
        };
        self.settlement_batches.insert(batch_id.clone(), batch);
        let state_root_after = self.state_root();
        if let Some(batch) = self.settlement_batches.get_mut(&batch_id) {
            batch.state_root_after = state_root_after;
        }
        for receipt_id in receipt_ids {
            if let Some(receipt) = self.compressed_receipts.get_mut(&receipt_id) {
                receipt.batch_id = Some(batch_id.clone());
                receipt.status = ReceiptStatus::Settled;
            }
        }
        let record = self.settlement_batches[&batch_id].public_record();
        self.emit_event(
            "settlement_batch_settled",
            &batch_id,
            None,
            EventSeverity::Info,
            &record,
        );
        Ok(batch_id)
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.current_height {
            return Err("cannot rewind scheduler height".to_string());
        }
        self.current_height = height;
        self.expire_stale_items();
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        Counters {
            lane_count: self.lanes.len(),
            task_count: self.tasks.len(),
            active_task_count: self
                .tasks
                .values()
                .filter(|task| task.status.active())
                .count(),
            preconfirmation_count: self.preconfirmations.len(),
            proof_window_count: self.proof_windows.len(),
            sponsor_reservation_count: self.sponsor_reservations.len(),
            receipt_count: self.compressed_receipts.len(),
            rebate_count: self.rebates.len(),
            ordering_commitment_count: self.ordering_commitments.len(),
            settlement_batch_count: self.settlement_batches.len(),
            consumed_nullifier_count: self.consumed_nullifiers.len(),
            events_emitted: self.events.len() as u64,
            total_user_fee_microunits: self
                .compressed_receipts
                .values()
                .map(|receipt| receipt.user_fee_microunits)
                .sum(),
            total_sponsor_fee_microunits: self
                .compressed_receipts
                .values()
                .map(|receipt| receipt.sponsor_fee_microunits)
                .sum(),
            total_rebate_microunits: self
                .rebates
                .values()
                .map(|rebate| rebate.amount_microunits)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let config_root = payload_root(
            "RECURSIVE-EXECUTION-SCHEDULER-CONFIG",
            &self.config.public_record(),
        );
        let lane_root = map_root("RECURSIVE-EXECUTION-SCHEDULER-LANES", &self.lanes);
        let task_root = map_root("RECURSIVE-EXECUTION-SCHEDULER-TASKS", &self.tasks);
        let preconfirmation_root = map_root(
            "RECURSIVE-EXECUTION-SCHEDULER-PRECONFIRMATIONS",
            &self.preconfirmations,
        );
        let proof_window_root = map_root(
            "RECURSIVE-EXECUTION-SCHEDULER-PROOF-WINDOWS",
            &self.proof_windows,
        );
        let sponsor_reservation_root = map_root(
            "RECURSIVE-EXECUTION-SCHEDULER-SPONSORS",
            &self.sponsor_reservations,
        );
        let receipt_root = map_root(
            "RECURSIVE-EXECUTION-SCHEDULER-RECEIPTS",
            &self.compressed_receipts,
        );
        let rebate_root = map_root("RECURSIVE-EXECUTION-SCHEDULER-REBATES", &self.rebates);
        let ordering_commitment_root = map_root(
            "RECURSIVE-EXECUTION-SCHEDULER-ORDERING",
            &self.ordering_commitments,
        );
        let settlement_batch_root = map_root(
            "RECURSIVE-EXECUTION-SCHEDULER-SETTLEMENTS",
            &self.settlement_batches,
        );
        let nullifier_root = root_from_values_vec(
            "RECURSIVE-EXECUTION-SCHEDULER-NULLIFIERS",
            &self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>(),
        );
        let event_root = merkle_root(
            "RECURSIVE-EXECUTION-SCHEDULER-EVENTS",
            &self
                .events
                .iter()
                .map(SchedulerEvent::public_record)
                .collect::<Vec<_>>(),
        );
        let counters_root = payload_root(
            "RECURSIVE-EXECUTION-SCHEDULER-COUNTERS",
            &counters.public_record(),
        );
        let partial = json!({
            "config_root": config_root,
            "lane_root": lane_root,
            "task_root": task_root,
            "preconfirmation_root": preconfirmation_root,
            "proof_window_root": proof_window_root,
            "sponsor_reservation_root": sponsor_reservation_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "ordering_commitment_root": ordering_commitment_root,
            "settlement_batch_root": settlement_batch_root,
            "nullifier_root": nullifier_root,
            "event_root": event_root,
            "counters_root": counters_root,
        });
        Roots {
            config_root: partial["config_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            lane_root: partial["lane_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            task_root: partial["task_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            preconfirmation_root: partial["preconfirmation_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            proof_window_root: partial["proof_window_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            sponsor_reservation_root: partial["sponsor_reservation_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            receipt_root: partial["receipt_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            rebate_root: partial["rebate_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            ordering_commitment_root: partial["ordering_commitment_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            settlement_batch_root: partial["settlement_batch_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            nullifier_root: partial["nullifier_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            event_root: partial["event_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            counters_root: partial["counters_root"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            public_record_root: public_record_root(&partial),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(state_root_from_record(&record));
        record
    }

    pub fn public_record_root(&self) -> String {
        public_record_root(&self.public_record_without_state_root())
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let counters = self.counters();
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "lanes": self.lanes.values().map(PrivateMicrobatchLane::public_record).collect::<Vec<_>>(),
            "tasks": self.tasks.values().map(EncryptedExecutionTask::public_record).collect::<Vec<_>>(),
            "preconfirmations": self.preconfirmations.values().map(PreconfirmationSla::public_record).collect::<Vec<_>>(),
            "proof_windows": self.proof_windows.values().map(RecursiveProofWindow::public_record).collect::<Vec<_>>(),
            "sponsor_reservations": self.sponsor_reservations.values().map(SponsorReservation::public_record).collect::<Vec<_>>(),
            "compressed_receipts": self.compressed_receipts.values().map(CompressedReceipt::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(FeeRebate::public_record).collect::<Vec<_>>(),
            "ordering_commitments": self.ordering_commitments.values().map(OrderingCommitment::public_record).collect::<Vec<_>>(),
            "settlement_batches": self.settlement_batches.values().map(SettlementBatch::public_record).collect::<Vec<_>>(),
            "consumed_nullifiers": self.consumed_nullifiers,
            "events": self.events.iter().map(SchedulerEvent::public_record).collect::<Vec<_>>(),
            "counters": counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    fn ensure_capacity(&self, label: &str, current: usize, max: usize) -> Result<()> {
        if current >= max {
            return Err(format!("{label} capacity reached"));
        }
        Ok(())
    }

    fn emit_event(
        &mut self,
        kind: &str,
        subject_id: &str,
        lane_id: Option<&str>,
        severity: EventSeverity,
        payload: &Value,
    ) {
        let sequence = self.events.len() as u64 + 1;
        let event = SchedulerEvent {
            event_id: event_id(kind, subject_id, sequence),
            event_kind: kind.to_string(),
            severity,
            subject_id: subject_id.to_string(),
            lane_id: lane_id.map(str::to_string),
            height: self.current_height,
            payload_root: payload_root("RECURSIVE-EXECUTION-SCHEDULER-EVENT-PAYLOAD", payload),
        };
        self.events.push(event);
    }

    fn refresh_window_roots(&mut self, window_id: &str) -> Result<()> {
        let task_ids = self
            .proof_windows
            .get(window_id)
            .ok_or_else(|| "proof window is missing".to_string())?
            .task_ids
            .clone();
        let task_records = task_ids
            .iter()
            .filter_map(|id| self.tasks.get(id))
            .map(EncryptedExecutionTask::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = task_ids
            .iter()
            .filter_map(|id| self.tasks.get(id))
            .map(|task| Value::String(task.nullifier_hash.clone()))
            .collect::<Vec<_>>();
        let read_records = task_ids
            .iter()
            .filter_map(|id| self.tasks.get(id))
            .map(|task| Value::String(task.read_set_root.clone()))
            .collect::<Vec<_>>();
        let witness_records = task_ids
            .iter()
            .filter_map(|id| self.tasks.get(id))
            .map(|task| Value::String(task.witness_hint_root.clone()))
            .collect::<Vec<_>>();
        let input_records = task_ids
            .iter()
            .filter_map(|id| self.tasks.get(id))
            .map(|task| json!({"task_id": task.task_id, "call_root": task.encrypted_call_root}))
            .collect::<Vec<_>>();
        if let Some(window) = self.proof_windows.get_mut(window_id) {
            window.task_root = merkle_root("RECURSIVE-EXECUTION-WINDOW-TASKS", &task_records);
            window.nullifier_root =
                merkle_root("RECURSIVE-EXECUTION-WINDOW-NULLIFIERS", &nullifier_records);
            window.read_set_root =
                merkle_root("RECURSIVE-EXECUTION-WINDOW-READSETS", &read_records);
            window.witness_root =
                merkle_root("RECURSIVE-EXECUTION-WINDOW-WITNESSES", &witness_records);
            window.recursive_input_root =
                merkle_root("RECURSIVE-EXECUTION-WINDOW-INPUTS", &input_records);
        }
        Ok(())
    }

    fn low_fee_for_task(&self, task: &EncryptedExecutionTask) -> u64 {
        let lane_fee = self
            .lanes
            .get(&task.lane_id)
            .map(|lane| {
                lane.base_fee_microunits
                    .saturating_mul(lane.congestion_multiplier_bps)
                    / MAX_BPS
            })
            .unwrap_or(self.config.base_micro_fee_microunits);
        lane_fee
            .saturating_add(task.priority_fee_microunits)
            .min(task.max_user_fee_microunits)
            .min(self.config.low_fee_ceiling_microunits)
    }

    fn sponsor_fee_for_task(&mut self, task: &EncryptedExecutionTask, user_fee: u64) -> u64 {
        let Some(sponsor_id) = task.sponsor_id.as_deref() else {
            return 0;
        };
        let reservation = self.sponsor_reservations.values_mut().find(|reservation| {
            reservation.sponsor_id == sponsor_id
                && reservation.lane_id == task.lane_id
                && reservation.status.spendable()
        });
        let Some(reservation) = reservation else {
            return 0;
        };
        let max_cover = user_fee.saturating_mul(reservation.max_cover_bps) / MAX_BPS;
        let available = reservation
            .reserved_microunits
            .saturating_sub(reservation.consumed_microunits);
        let sponsor_fee = max_cover.min(available);
        reservation.consumed_microunits =
            reservation.consumed_microunits.saturating_add(sponsor_fee);
        reservation.status = SponsorReservationStatus::Consumed;
        sponsor_fee
    }

    fn accrue_rebate(&mut self, receipt_id: &str) -> Result<String> {
        self.ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        let receipt = self
            .compressed_receipts
            .get(receipt_id)
            .ok_or_else(|| "receipt is missing".to_string())?
            .clone();
        if receipt.rebate_microunits == 0 {
            return Ok(String::new());
        }
        let task = self
            .tasks
            .get(&receipt.task_id)
            .ok_or_else(|| "task is missing".to_string())?;
        let sequence = self.rebates.len() as u64 + 1;
        let rebate_id = rebate_id(&receipt, sequence);
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt_id.to_string(),
            task_id: receipt.task_id.clone(),
            sponsor_id: task.sponsor_id.clone(),
            status: RebateStatus::Claimable,
            claimant_commitment: task.sender_commitment.clone(),
            rebate_root: payload_root(
                "RECURSIVE-EXECUTION-REBATE",
                &json!({"receipt_id": receipt_id, "amount": receipt.rebate_microunits}),
            ),
            amount_microunits: receipt.rebate_microunits,
            reason: "compressed_recursive_receipt_low_fee_rebate".to_string(),
            accrued_at_height: self.current_height,
            claimable_at_height: self.current_height,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    fn expire_stale_items(&mut self) {
        for task in self.tasks.values_mut() {
            if task.status.active() && task.expires_at_height < self.current_height {
                task.status = ExecutionTaskStatus::Expired;
            }
        }
        for preconfirmation in self.preconfirmations.values_mut() {
            if preconfirmation.status.live()
                && preconfirmation.expires_at_height < self.current_height
            {
                preconfirmation.status = PreconfirmationStatus::Expired;
            }
        }
        for window in self.proof_windows.values_mut() {
            if window.status.accepts_tasks() && window.expires_at_height < self.current_height {
                window.status = ProofWindowStatus::Expired;
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if reservation.status.spendable() && reservation.expires_at_height < self.current_height
            {
                reservation.status = SponsorReservationStatus::Expired;
            }
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_low_fee_recursive_execution_batch_scheduler_runtime_public_record() -> Value {
    State::devnet().public_record()
}

pub fn private_l2_low_fee_recursive_execution_batch_scheduler_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn lane_id(kind: MicrobatchLaneKind, label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn execution_task_id(request: &SubmitExecutionTaskRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-TASK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.lane_id),
            HashPart::Str(request.task_kind.as_str()),
            HashPart::Str(&request.sender_commitment),
            HashPart::Str(&request.contract_commitment),
            HashPart::Str(&request.nullifier_hash),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn preconfirmation_id(
    request: &OfferPreconfirmationRequest,
    lane_id: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-PRECONFIRMATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(&request.task_id),
            HashPart::Str(&request.sequencer_commitment),
            HashPart::U64(request.promised_latency_ms),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &ReserveSponsorRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(&request.lane_id),
            HashPart::Str(request.task_id.as_deref().unwrap_or("lane")),
            HashPart::U64(request.reserved_microunits),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn ordering_commitment_id(request: &CommitOrderingRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-ORDERING-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.lane_id),
            HashPart::Str(request.window_id.as_deref().unwrap_or("pending")),
            HashPart::Str(&request.commit_root),
            HashPart::Str(&request.encrypted_orderflow_root),
            HashPart::U64(request.anti_mev_score),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn proof_window_id(request: &OpenProofWindowRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-PROOF-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.lane_id),
            HashPart::Str(request.ordering_commitment_id.as_deref().unwrap_or("none")),
            HashPart::U64(request.estimated_fee_microunits),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn receipt_id(task: &EncryptedExecutionTask, window_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-COMPRESSED-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&task.task_id),
            HashPart::Str(window_id),
            HashPart::Str(&task.nullifier_hash),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(receipt: &CompressedReceipt, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&receipt.receipt_id),
            HashPart::Str(&receipt.task_id),
            HashPart::U64(receipt.rebate_microunits),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_batch_id(request: &BuildSettlementBatchRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.builder_commitment),
            HashPart::Str(&request.settlement_tx_hash),
            HashPart::Json(&json!(request.window_ids)),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn event_id(kind: &str, subject_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn deterministic_id(domain: &str, label: &str, sequence: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_RECURSIVE_EXECUTION_BATCH_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    root_from_record(domain, record)
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-PUBLIC-RECORD-ROOT",
        record,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-LOW-FEE-RECURSIVE-EXECUTION-STATE-ROOT", record)
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

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for PrivateMicrobatchLane {
    fn public_record(&self) -> Value {
        PrivateMicrobatchLane::public_record(self)
    }
}

impl PublicRecord for EncryptedExecutionTask {
    fn public_record(&self) -> Value {
        EncryptedExecutionTask::public_record(self)
    }
}

impl PublicRecord for PreconfirmationSla {
    fn public_record(&self) -> Value {
        PreconfirmationSla::public_record(self)
    }
}

impl PublicRecord for RecursiveProofWindow {
    fn public_record(&self) -> Value {
        RecursiveProofWindow::public_record(self)
    }
}

impl PublicRecord for SponsorReservation {
    fn public_record(&self) -> Value {
        SponsorReservation::public_record(self)
    }
}

impl PublicRecord for CompressedReceipt {
    fn public_record(&self) -> Value {
        CompressedReceipt::public_record(self)
    }
}

impl PublicRecord for FeeRebate {
    fn public_record(&self) -> Value {
        FeeRebate::public_record(self)
    }
}

impl PublicRecord for OrderingCommitment {
    fn public_record(&self) -> Value {
        OrderingCommitment::public_record(self)
    }
}

impl PublicRecord for SettlementBatch {
    fn public_record(&self) -> Value {
        SettlementBatch::public_record(self)
    }
}

fn map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let records = values
        .iter()
        .map(|(id, value)| json!({"id": id, "record": value.public_record()}))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}
