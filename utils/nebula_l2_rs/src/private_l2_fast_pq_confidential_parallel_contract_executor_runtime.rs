use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub type PrivateL2FastPqConfidentialParallelContractExecutorRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2FastPqConfidentialParallelContractExecutorRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_CONTRACT_EXECUTOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-parallel-contract-executor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_CONTRACT_EXECUTOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "stable-fnv1a64-domain-separated-canonical-json-demo";
pub const PQ_PROOF_SUITE: &str = "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f";
pub const CONFIDENTIAL_VM_SUITE: &str = "confidential-contract-vm-parallel-lane-v1";
pub const DEPENDENCY_GRAPH_SUITE: &str = "redacted-dependency-graph-commitment-v1";
pub const PRECONFIRMATION_SUITE: &str = "private-l2-fast-preconfirmation-receipt-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 2_460_000;
pub const DEFAULT_DEVNET_EPOCH: u64 = 30_720;
pub const DEFAULT_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MAX_SHARDS: usize = 256;
pub const DEFAULT_MAX_CONTRACTS: usize = 1_048_576;
pub const DEFAULT_MAX_DEPENDENCY_GRAPHS: usize = 262_144;
pub const DEFAULT_MAX_WITNESS_HINTS: usize = 4_194_304;
pub const DEFAULT_MAX_SCHEDULER_SLOTS: usize = 2_097_152;
pub const DEFAULT_MAX_PROOF_RESERVATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_CONFLICTS: usize = 1_048_576;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_SERIAL_LANES: usize = 16_384;
pub const DEFAULT_MAX_FEE_CAPS: usize = 1_048_576;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_DEVNET_FIXTURES: usize = 4_096;
pub const DEFAULT_SLOT_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_TARGET_SLOT_MS: u64 = 180;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 450;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_FEE_BPS: u64 = 12;
pub const DEFAULT_SERIAL_FALLBACK_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_CALL: u64 = 64;
pub const DEFAULT_MAX_REVEALED_FIELDS_PER_RECEIPT: u64 = 3;
pub const DEFAULT_MAX_PARALLELISM_PER_SHARD: u64 = 256;
pub const DEFAULT_MAX_DEPENDENCIES_PER_GRAPH: usize = 512;
pub const DEFAULT_MAX_WITNESS_HINTS_PER_SLOT: usize = 128;
pub const DEFAULT_MAX_PROOF_RESERVATIONS_PER_SLOT: usize = 96;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionShardKind {
    UltraFastDefi,
    ConfidentialTransfer,
    TokenRuntime,
    ShieldedContract,
    Lending,
    Perpetuals,
    Oracle,
    Bridge,
    Paymaster,
    BackgroundProof,
    SerialFallback,
    Emergency,
}

impl ExecutionShardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraFastDefi => "ultra_fast_defi",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::TokenRuntime => "token_runtime",
            Self::ShieldedContract => "shielded_contract",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Paymaster => "paymaster",
            Self::BackgroundProof => "background_proof",
            Self::SerialFallback => "serial_fallback",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::Bridge => 9_800,
            Self::Perpetuals => 9_600,
            Self::UltraFastDefi => 9_400,
            Self::Lending => 9_000,
            Self::ShieldedContract => 8_700,
            Self::TokenRuntime => 8_400,
            Self::ConfidentialTransfer => 8_200,
            Self::Paymaster => 7_900,
            Self::Oracle => 7_700,
            Self::BackgroundProof => 6_800,
            Self::SerialFallback => 6_400,
        }
    }

    pub fn requires_serial_safety(self) -> bool {
        matches!(self, Self::SerialFallback | Self::Emergency | Self::Bridge)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCallKind {
    PrivateCall,
    ConfidentialTransfer,
    TokenMint,
    TokenBurn,
    Swap,
    AddLiquidity,
    RemoveLiquidity,
    Borrow,
    Repay,
    Liquidate,
    VaultDeposit,
    VaultRedeem,
    OracleRead,
    BridgeLock,
    BridgeRelease,
    PaymasterSponsor,
    GovernanceAction,
}

impl ContractCallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCall => "private_call",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::Swap => "swap",
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::Liquidate => "liquidate",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultRedeem => "vault_redeem",
            Self::OracleRead => "oracle_read",
            Self::BridgeLock => "bridge_lock",
            Self::BridgeRelease => "bridge_release",
            Self::PaymasterSponsor => "paymaster_sponsor",
            Self::GovernanceAction => "governance_action",
        }
    }

    pub fn mutates_state(self) -> bool {
        !matches!(self, Self::OracleRead)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    ReadSet,
    WriteSet,
    NullifierSet,
    ContractCode,
    TokenClass,
    LiquidityPool,
    LendingMarket,
    OracleSample,
    BridgeFinality,
    PaymasterAllowance,
    FeeAccount,
    PrivacySet,
}

impl DependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadSet => "read_set",
            Self::WriteSet => "write_set",
            Self::NullifierSet => "nullifier_set",
            Self::ContractCode => "contract_code",
            Self::TokenClass => "token_class",
            Self::LiquidityPool => "liquidity_pool",
            Self::LendingMarket => "lending_market",
            Self::OracleSample => "oracle_sample",
            Self::BridgeFinality => "bridge_finality",
            Self::PaymasterAllowance => "paymaster_allowance",
            Self::FeeAccount => "fee_account",
            Self::PrivacySet => "privacy_set",
        }
    }

    pub fn conflict_scope(self) -> &'static str {
        match self {
            Self::ReadSet | Self::ContractCode | Self::OracleSample | Self::PrivacySet => "read",
            Self::WriteSet | Self::NullifierSet | Self::LiquidityPool | Self::LendingMarket => {
                "write"
            }
            Self::TokenClass
            | Self::BridgeFinality
            | Self::PaymasterAllowance
            | Self::FeeAccount => "metered",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessHintKind {
    ContractBytecode,
    AccountNote,
    NullifierWindow,
    MerkleBranch,
    OraclePacket,
    BridgeProof,
    TokenMetadata,
    FeeSponsor,
    PrivacyCoverSet,
    PqVerificationKey,
}

impl WitnessHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractBytecode => "contract_bytecode",
            Self::AccountNote => "account_note",
            Self::NullifierWindow => "nullifier_window",
            Self::MerkleBranch => "merkle_branch",
            Self::OraclePacket => "oracle_packet",
            Self::BridgeProof => "bridge_proof",
            Self::TokenMetadata => "token_metadata",
            Self::FeeSponsor => "fee_sponsor",
            Self::PrivacyCoverSet => "privacy_cover_set",
            Self::PqVerificationKey => "pq_verification_key",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Open,
    DependencyChecked,
    WitnessPrefetching,
    ProofReserved,
    Executing,
    Preconfirmed,
    SerialFallback,
    Conflicted,
    Expired,
    Cancelled,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::DependencyChecked => "dependency_checked",
            Self::WitnessPrefetching => "witness_prefetching",
            Self::ProofReserved => "proof_reserved",
            Self::Executing => "executing",
            Self::Preconfirmed => "preconfirmed",
            Self::SerialFallback => "serial_fallback",
            Self::Conflicted => "conflicted",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::DependencyChecked
                | Self::WitnessPrefetching
                | Self::ProofReserved
                | Self::Executing
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofReservationStatus {
    Reserved,
    Assigned,
    Proven,
    Released,
    Expired,
    Slashed,
}

impl ProofReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Assigned => "assigned",
            Self::Proven => "proven",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    WriteWrite,
    NullifierReuse,
    FeeCapExceeded,
    PrivacyBudgetExceeded,
    DependencyStale,
    ProofUnavailable,
    SerialLaneOverflow,
    SchedulerRace,
}

impl ConflictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WriteWrite => "write_write",
            Self::NullifierReuse => "nullifier_reuse",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::DependencyStale => "dependency_stale",
            Self::ProofUnavailable => "proof_unavailable",
            Self::SerialLaneOverflow => "serial_lane_overflow",
            Self::SchedulerRace => "scheduler_race",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Preconfirmed,
    FinalityPending,
    Finalized,
    Disputed,
    RolledBack,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preconfirmed => "preconfirmed",
            Self::FinalityPending => "finality_pending",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_proof_suite: String,
    pub confidential_vm_suite: String,
    pub dependency_graph_suite: String,
    pub preconfirmation_suite: String,
    pub max_shards: usize,
    pub max_contracts: usize,
    pub max_dependency_graphs: usize,
    pub max_witness_hints: usize,
    pub max_scheduler_slots: usize,
    pub max_proof_reservations: usize,
    pub max_conflicts: usize,
    pub max_receipts: usize,
    pub max_serial_lanes: usize,
    pub max_fee_caps: usize,
    pub max_redaction_budgets: usize,
    pub max_devnet_fixtures: usize,
    pub slot_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub target_slot_ms: u64,
    pub target_preconfirmation_ms: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub serial_fallback_fee_bps: u64,
    pub max_redaction_units_per_call: u64,
    pub max_revealed_fields_per_receipt: u64,
    pub max_parallelism_per_shard: u64,
    pub max_dependencies_per_graph: usize,
    pub max_witness_hints_per_slot: usize,
    pub max_proof_reservations_per_slot: usize,
    pub require_conflict_commitments: bool,
    pub require_preconfirmation_signatures: bool,
    pub enable_demo_serial_fallback: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_proof_suite: PQ_PROOF_SUITE.to_string(),
            confidential_vm_suite: CONFIDENTIAL_VM_SUITE.to_string(),
            dependency_graph_suite: DEPENDENCY_GRAPH_SUITE.to_string(),
            preconfirmation_suite: PRECONFIRMATION_SUITE.to_string(),
            max_shards: DEFAULT_MAX_SHARDS,
            max_contracts: DEFAULT_MAX_CONTRACTS,
            max_dependency_graphs: DEFAULT_MAX_DEPENDENCY_GRAPHS,
            max_witness_hints: DEFAULT_MAX_WITNESS_HINTS,
            max_scheduler_slots: DEFAULT_MAX_SCHEDULER_SLOTS,
            max_proof_reservations: DEFAULT_MAX_PROOF_RESERVATIONS,
            max_conflicts: DEFAULT_MAX_CONFLICTS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_serial_lanes: DEFAULT_MAX_SERIAL_LANES,
            max_fee_caps: DEFAULT_MAX_FEE_CAPS,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_devnet_fixtures: DEFAULT_MAX_DEVNET_FIXTURES,
            slot_ttl_blocks: DEFAULT_SLOT_TTL_BLOCKS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            target_slot_ms: DEFAULT_TARGET_SLOT_MS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            serial_fallback_fee_bps: DEFAULT_SERIAL_FALLBACK_FEE_BPS,
            max_redaction_units_per_call: DEFAULT_MAX_REDACTION_UNITS_PER_CALL,
            max_revealed_fields_per_receipt: DEFAULT_MAX_REVEALED_FIELDS_PER_RECEIPT,
            max_parallelism_per_shard: DEFAULT_MAX_PARALLELISM_PER_SHARD,
            max_dependencies_per_graph: DEFAULT_MAX_DEPENDENCIES_PER_GRAPH,
            max_witness_hints_per_slot: DEFAULT_MAX_WITNESS_HINTS_PER_SLOT,
            max_proof_reservations_per_slot: DEFAULT_MAX_PROOF_RESERVATIONS_PER_SLOT,
            require_conflict_commitments: true,
            require_preconfirmation_signatures: true,
            enable_demo_serial_fallback: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("l2_network", &self.l2_network)?;
        ensure_non_empty("monero_network", &self.monero_network)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive_usize("max_shards", self.max_shards)?;
        ensure_positive_usize("max_contracts", self.max_contracts)?;
        ensure_positive_usize("max_scheduler_slots", self.max_scheduler_slots)?;
        ensure_positive("slot_ttl_blocks", self.slot_ttl_blocks)?;
        ensure_positive("proof_ttl_blocks", self.proof_ttl_blocks)?;
        ensure_positive("receipt_ttl_blocks", self.receipt_ttl_blocks)?;
        ensure_positive("target_slot_ms", self.target_slot_ms)?;
        ensure_positive("target_preconfirmation_ms", self.target_preconfirmation_ms)?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive("target_privacy_set_size", self.target_privacy_set_size)?;
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set must cover minimum privacy set".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below runtime floor".to_string());
        }
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        ensure_bps("serial_fallback_fee_bps", self.serial_fallback_fee_bps)?;
        if self.serial_fallback_fee_bps > self.max_fee_bps {
            return Err("serial fallback fee cannot exceed max fee".to_string());
        }
        ensure_positive(
            "max_redaction_units_per_call",
            self.max_redaction_units_per_call,
        )?;
        ensure_positive("max_parallelism_per_shard", self.max_parallelism_per_shard)?;
        ensure_positive_usize(
            "max_dependencies_per_graph",
            self.max_dependencies_per_graph,
        )?;
        ensure_positive_usize(
            "max_witness_hints_per_slot",
            self.max_witness_hints_per_slot,
        )?;
        ensure_positive_usize(
            "max_proof_reservations_per_slot",
            self.max_proof_reservations_per_slot,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_proof_suite": self.pq_proof_suite,
            "confidential_vm_suite": self.confidential_vm_suite,
            "dependency_graph_suite": self.dependency_graph_suite,
            "preconfirmation_suite": self.preconfirmation_suite,
            "max_shards": self.max_shards,
            "max_contracts": self.max_contracts,
            "max_dependency_graphs": self.max_dependency_graphs,
            "max_witness_hints": self.max_witness_hints,
            "max_scheduler_slots": self.max_scheduler_slots,
            "max_proof_reservations": self.max_proof_reservations,
            "max_conflicts": self.max_conflicts,
            "max_receipts": self.max_receipts,
            "max_serial_lanes": self.max_serial_lanes,
            "max_fee_caps": self.max_fee_caps,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_devnet_fixtures": self.max_devnet_fixtures,
            "slot_ttl_blocks": self.slot_ttl_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "target_slot_ms": self.target_slot_ms,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "serial_fallback_fee_bps": self.serial_fallback_fee_bps,
            "max_redaction_units_per_call": self.max_redaction_units_per_call,
            "max_revealed_fields_per_receipt": self.max_revealed_fields_per_receipt,
            "max_parallelism_per_shard": self.max_parallelism_per_shard,
            "max_dependencies_per_graph": self.max_dependencies_per_graph,
            "max_witness_hints_per_slot": self.max_witness_hints_per_slot,
            "max_proof_reservations_per_slot": self.max_proof_reservations_per_slot,
            "require_conflict_commitments": self.require_conflict_commitments,
            "require_preconfirmation_signatures": self.require_preconfirmation_signatures,
            "enable_demo_serial_fallback": self.enable_demo_serial_fallback,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub shards_opened: u64,
    pub contracts_registered: u64,
    pub dependency_graphs_committed: u64,
    pub witness_hints_registered: u64,
    pub scheduler_slots_opened: u64,
    pub proof_reservations_opened: u64,
    pub conflicts_detected: u64,
    pub receipts_preconfirmed: u64,
    pub serial_lanes_opened: u64,
    pub fee_caps_registered: u64,
    pub redaction_budgets_registered: u64,
    pub devnet_fixtures_loaded: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "shards_opened": self.shards_opened,
            "contracts_registered": self.contracts_registered,
            "dependency_graphs_committed": self.dependency_graphs_committed,
            "witness_hints_registered": self.witness_hints_registered,
            "scheduler_slots_opened": self.scheduler_slots_opened,
            "proof_reservations_opened": self.proof_reservations_opened,
            "conflicts_detected": self.conflicts_detected,
            "receipts_preconfirmed": self.receipts_preconfirmed,
            "serial_lanes_opened": self.serial_lanes_opened,
            "fee_caps_registered": self.fee_caps_registered,
            "redaction_budgets_registered": self.redaction_budgets_registered,
            "devnet_fixtures_loaded": self.devnet_fixtures_loaded,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub shard_root: String,
    pub contract_root: String,
    pub dependency_graph_root: String,
    pub witness_hint_root: String,
    pub scheduler_slot_root: String,
    pub proof_reservation_root: String,
    pub conflict_root: String,
    pub receipt_root: String,
    pub serial_lane_root: String,
    pub fee_cap_root: String,
    pub redaction_budget_root: String,
    pub devnet_fixture_root: String,
    pub operator_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_root": self.shard_root,
            "contract_root": self.contract_root,
            "dependency_graph_root": self.dependency_graph_root,
            "witness_hint_root": self.witness_hint_root,
            "scheduler_slot_root": self.scheduler_slot_root,
            "proof_reservation_root": self.proof_reservation_root,
            "conflict_root": self.conflict_root,
            "receipt_root": self.receipt_root,
            "serial_lane_root": self.serial_lane_root,
            "fee_cap_root": self.fee_cap_root,
            "redaction_budget_root": self.redaction_budget_root,
            "devnet_fixture_root": self.devnet_fixture_root,
            "operator_root": self.operator_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionShard {
    pub shard_id: String,
    pub kind: ExecutionShardKind,
    pub operator_commitment: String,
    pub admission_root: String,
    pub encrypted_mempool_root: String,
    pub local_state_root: String,
    pub max_parallelism: u64,
    pub fee_cap_bps: u64,
    pub privacy_set_size: u64,
    pub active_slot_ids: BTreeSet<String>,
    pub fallback_lane_ids: BTreeSet<String>,
    pub status: String,
}

impl ExecutionShard {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "kind": self.kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "admission_root": self.admission_root,
            "encrypted_mempool_root": self.encrypted_mempool_root,
            "local_state_root": self.local_state_root,
            "max_parallelism": self.max_parallelism,
            "fee_cap_bps": self.fee_cap_bps,
            "privacy_set_size": self.privacy_set_size,
            "active_slot_ids": sorted_values(&self.active_slot_ids),
            "fallback_lane_ids": sorted_values(&self.fallback_lane_ids),
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractDescriptor {
    pub contract_id: String,
    pub shard_id: String,
    pub call_kind: ContractCallKind,
    pub contract_commitment: String,
    pub code_root: String,
    pub storage_schema_root: String,
    pub verifier_key_root: String,
    pub privacy_policy_root: String,
    pub fee_cap_id: String,
    pub redaction_budget_id: String,
    pub registered_at_height: u64,
    pub pq_security_bits: u16,
    pub enabled: bool,
}

impl ContractDescriptor {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "shard_id": self.shard_id,
            "call_kind": self.call_kind.as_str(),
            "contract_commitment": self.contract_commitment,
            "code_root": self.code_root,
            "storage_schema_root": self.storage_schema_root,
            "verifier_key_root": self.verifier_key_root,
            "privacy_policy_root": self.privacy_policy_root,
            "fee_cap_id": self.fee_cap_id,
            "redaction_budget_id": self.redaction_budget_id,
            "registered_at_height": self.registered_at_height,
            "pq_security_bits": self.pq_security_bits,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DependencyGraphCommitment {
    pub graph_id: String,
    pub slot_id: String,
    pub contract_id: String,
    pub dependency_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub nullifier_root: String,
    pub graph_shape_commitment: String,
    pub conflict_salt_root: String,
    pub dependency_kinds: BTreeSet<DependencyKind>,
    pub declared_dependency_count: u64,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
}

impl DependencyGraphCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "graph_id": self.graph_id,
            "slot_id": self.slot_id,
            "contract_id": self.contract_id,
            "dependency_root": self.dependency_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "nullifier_root": self.nullifier_root,
            "graph_shape_commitment": self.graph_shape_commitment,
            "conflict_salt_root": self.conflict_salt_root,
            "dependency_kinds": self.dependency_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "declared_dependency_count": self.declared_dependency_count,
            "committed_at_height": self.committed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessPrefetchHint {
    pub hint_id: String,
    pub slot_id: String,
    pub graph_id: String,
    pub hint_kind: WitnessHintKind,
    pub encrypted_location_root: String,
    pub provider_commitment: String,
    pub witness_bundle_root: String,
    pub expected_bytes: u64,
    pub priority: u64,
    pub ready_at_height: u64,
    pub expires_at_height: u64,
}

impl WitnessPrefetchHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "slot_id": self.slot_id,
            "graph_id": self.graph_id,
            "hint_kind": self.hint_kind.as_str(),
            "encrypted_location_root": self.encrypted_location_root,
            "provider_commitment": self.provider_commitment,
            "witness_bundle_root": self.witness_bundle_root,
            "expected_bytes": self.expected_bytes,
            "priority": self.priority,
            "ready_at_height": self.ready_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SchedulerSlot {
    pub slot_id: String,
    pub shard_id: String,
    pub contract_id: String,
    pub call_kind: ContractCallKind,
    pub caller_commitment: String,
    pub encrypted_call_root: String,
    pub dependency_graph_ids: BTreeSet<String>,
    pub witness_hint_ids: BTreeSet<String>,
    pub proof_reservation_ids: BTreeSet<String>,
    pub requested_fee_cap_id: String,
    pub requested_redaction_budget_id: String,
    pub sequence: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SlotStatus,
    pub status_height: u64,
}

impl SchedulerSlot {
    pub fn public_record(&self) -> Value {
        json!({
            "slot_id": self.slot_id,
            "shard_id": self.shard_id,
            "contract_id": self.contract_id,
            "call_kind": self.call_kind.as_str(),
            "caller_commitment": self.caller_commitment,
            "encrypted_call_root": self.encrypted_call_root,
            "dependency_graph_ids": sorted_values(&self.dependency_graph_ids),
            "witness_hint_ids": sorted_values(&self.witness_hint_ids),
            "proof_reservation_ids": sorted_values(&self.proof_reservation_ids),
            "requested_fee_cap_id": self.requested_fee_cap_id,
            "requested_redaction_budget_id": self.requested_redaction_budget_id,
            "sequence": self.sequence,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "status_height": self.status_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParallelProofReservation {
    pub reservation_id: String,
    pub slot_id: String,
    pub shard_id: String,
    pub prover_commitment: String,
    pub pq_verifier_key_root: String,
    pub proof_queue_root: String,
    pub max_proof_ms: u64,
    pub fee_bid_bps: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: ProofReservationStatus,
    pub proof_root: Option<String>,
}

impl ParallelProofReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "slot_id": self.slot_id,
            "shard_id": self.shard_id,
            "prover_commitment": self.prover_commitment,
            "pq_verifier_key_root": self.pq_verifier_key_root,
            "proof_queue_root": self.proof_queue_root,
            "max_proof_ms": self.max_proof_ms,
            "fee_bid_bps": self.fee_bid_bps,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConflictDetectionRecord {
    pub conflict_id: String,
    pub conflict_kind: ConflictKind,
    pub primary_slot_id: String,
    pub conflicting_slot_id: Option<String>,
    pub dependency_graph_id: Option<String>,
    pub conflict_key_root: String,
    pub conflict_evidence_root: String,
    pub resolver_commitment: String,
    pub fallback_lane_id: Option<String>,
    pub detected_at_height: u64,
    pub resolved: bool,
}

impl ConflictDetectionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "conflict_id": self.conflict_id,
            "conflict_kind": self.conflict_kind.as_str(),
            "primary_slot_id": self.primary_slot_id,
            "conflicting_slot_id": self.conflicting_slot_id,
            "dependency_graph_id": self.dependency_graph_id,
            "conflict_key_root": self.conflict_key_root,
            "conflict_evidence_root": self.conflict_evidence_root,
            "resolver_commitment": self.resolver_commitment,
            "fallback_lane_id": self.fallback_lane_id,
            "detected_at_height": self.detected_at_height,
            "resolved": self.resolved,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationReceipt {
    pub receipt_id: String,
    pub slot_id: String,
    pub shard_id: String,
    pub contract_id: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub execution_trace_root: String,
    pub proof_root: String,
    pub redacted_public_output_root: String,
    pub fee_charged_bps: u64,
    pub privacy_units_spent: u64,
    pub preconfirmed_at_height: u64,
    pub expires_at_height: u64,
    pub sequencer_signature_root: String,
    pub status: ReceiptStatus,
}

impl PreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "slot_id": self.slot_id,
            "shard_id": self.shard_id,
            "contract_id": self.contract_id,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "execution_trace_root": self.execution_trace_root,
            "proof_root": self.proof_root,
            "redacted_public_output_root": self.redacted_public_output_root,
            "fee_charged_bps": self.fee_charged_bps,
            "privacy_units_spent": self.privacy_units_spent,
            "preconfirmed_at_height": self.preconfirmed_at_height,
            "expires_at_height": self.expires_at_height,
            "sequencer_signature_root": self.sequencer_signature_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SerialFallbackLane {
    pub lane_id: String,
    pub shard_id: String,
    pub reason: ConflictKind,
    pub operator_commitment: String,
    pub queue_root: String,
    pub ordered_slot_ids: BTreeSet<String>,
    pub max_queue_depth: u64,
    pub fee_cap_bps: u64,
    pub opened_at_height: u64,
    pub active: bool,
}

impl SerialFallbackLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "reason": self.reason.as_str(),
            "operator_commitment": self.operator_commitment,
            "queue_root": self.queue_root,
            "ordered_slot_ids": sorted_values(&self.ordered_slot_ids),
            "max_queue_depth": self.max_queue_depth,
            "fee_cap_bps": self.fee_cap_bps,
            "opened_at_height": self.opened_at_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCap {
    pub fee_cap_id: String,
    pub contract_id: String,
    pub payer_commitment: String,
    pub asset_id: String,
    pub max_fee_bps: u64,
    pub max_absolute_fee_commitment: String,
    pub paymaster_root: Option<String>,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl FeeCap {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_cap_id": self.fee_cap_id,
            "contract_id": self.contract_id,
            "payer_commitment": self.payer_commitment,
            "asset_id": self.asset_id,
            "max_fee_bps": self.max_fee_bps,
            "max_absolute_fee_commitment": self.max_absolute_fee_commitment,
            "paymaster_root": self.paymaster_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub contract_id: String,
    pub owner_commitment: String,
    pub redaction_policy_root: String,
    pub max_redaction_units: u64,
    pub remaining_redaction_units: u64,
    pub max_revealed_fields: u64,
    pub spent_receipt_ids: BTreeSet<String>,
    pub valid_until_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "contract_id": self.contract_id,
            "owner_commitment": self.owner_commitment,
            "redaction_policy_root": self.redaction_policy_root,
            "max_redaction_units": self.max_redaction_units,
            "remaining_redaction_units": self.remaining_redaction_units,
            "max_revealed_fields": self.max_revealed_fields,
            "spent_receipt_ids": sorted_values(&self.spent_receipt_ids),
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub shard_id: String,
    pub slot_id: Option<String>,
    pub contract_id: Option<String>,
    pub fixture_root: String,
    pub notes: String,
}

impl DevnetFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "label": self.label,
            "shard_id": self.shard_id,
            "slot_id": self.slot_id,
            "contract_id": self.contract_id,
            "fixture_root": self.fixture_root,
            "notes": self.notes,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub counters: Counters,
    pub shards: BTreeMap<String, ExecutionShard>,
    pub contracts: BTreeMap<String, ContractDescriptor>,
    pub dependency_graphs: BTreeMap<String, DependencyGraphCommitment>,
    pub witness_hints: BTreeMap<String, WitnessPrefetchHint>,
    pub scheduler_slots: BTreeMap<String, SchedulerSlot>,
    pub proof_reservations: BTreeMap<String, ParallelProofReservation>,
    pub conflicts: BTreeMap<String, ConflictDetectionRecord>,
    pub preconfirmation_receipts: BTreeMap<String, PreconfirmationReceipt>,
    pub serial_lanes: BTreeMap<String, SerialFallbackLane>,
    pub fee_caps: BTreeMap<String, FeeCap>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
    pub operator_commitments: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::empty(
            Config::devnet(),
            DEFAULT_DEVNET_HEIGHT,
            DEFAULT_DEVNET_EPOCH,
        );
        state.load_devnet_sample();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn empty(config: Config, current_height: u64, current_epoch: u64) -> Self {
        Self {
            config,
            current_height,
            current_epoch,
            counters: Counters::default(),
            shards: BTreeMap::new(),
            contracts: BTreeMap::new(),
            dependency_graphs: BTreeMap::new(),
            witness_hints: BTreeMap::new(),
            scheduler_slots: BTreeMap::new(),
            proof_reservations: BTreeMap::new(),
            conflicts: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            serial_lanes: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
            operator_commitments: BTreeSet::new(),
        }
    }

    pub fn with_config(config: Config, current_height: u64, current_epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self::empty(config, current_height, current_epoch))
    }

    pub fn register_shard(
        &mut self,
        kind: ExecutionShardKind,
        operator_commitment: String,
        max_parallelism: u64,
        fee_cap_bps: u64,
        privacy_set_size: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.shards.len(), self.config.max_shards, "shards")?;
        ensure_root("operator_commitment", &operator_commitment)?;
        ensure_positive("max_parallelism", max_parallelism)?;
        ensure_bps("fee_cap_bps", fee_cap_bps)?;
        if fee_cap_bps > self.config.max_fee_bps {
            return Err("shard fee cap exceeds runtime maximum".to_string());
        }
        if max_parallelism > self.config.max_parallelism_per_shard {
            return Err("shard parallelism exceeds runtime maximum".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("shard privacy set is too small".to_string());
        }
        let sequence = self.counters.shards_opened + 1;
        let shard_id = deterministic_id(
            "shard",
            sequence,
            &json!({
                "kind": kind.as_str(),
                "operator_commitment": operator_commitment,
                "max_parallelism": max_parallelism,
            }),
        );
        let shard = ExecutionShard {
            shard_id: shard_id.clone(),
            kind,
            operator_commitment: operator_commitment.clone(),
            admission_root: deterministic_root("admission", &shard_id, sequence),
            encrypted_mempool_root: deterministic_root("encrypted-mempool", &shard_id, sequence),
            local_state_root: deterministic_root("local-state", &shard_id, sequence),
            max_parallelism,
            fee_cap_bps,
            privacy_set_size,
            active_slot_ids: BTreeSet::new(),
            fallback_lane_ids: BTreeSet::new(),
            status: "open".to_string(),
        };
        self.operator_commitments.insert(operator_commitment);
        self.shards.insert(shard_id.clone(), shard);
        self.counters.shards_opened += 1;
        Ok(shard_id)
    }

    pub fn register_contract(
        &mut self,
        shard_id: &str,
        call_kind: ContractCallKind,
        contract_commitment: String,
        fee_cap_id: String,
        redaction_budget_id: String,
    ) -> Result<String> {
        self.ensure_capacity(self.contracts.len(), self.config.max_contracts, "contracts")?;
        self.ensure_shard(shard_id)?;
        ensure_root("contract_commitment", &contract_commitment)?;
        let sequence = self.counters.contracts_registered + 1;
        let contract_id = deterministic_id(
            "contract",
            sequence,
            &json!({
                "shard_id": shard_id,
                "call_kind": call_kind.as_str(),
                "contract_commitment": contract_commitment,
            }),
        );
        let contract = ContractDescriptor {
            contract_id: contract_id.clone(),
            shard_id: shard_id.to_string(),
            call_kind,
            contract_commitment,
            code_root: deterministic_root("code", &contract_id, sequence),
            storage_schema_root: deterministic_root("storage-schema", &contract_id, sequence),
            verifier_key_root: deterministic_root("verifier-key", &contract_id, sequence),
            privacy_policy_root: deterministic_root("privacy-policy", &contract_id, sequence),
            fee_cap_id,
            redaction_budget_id,
            registered_at_height: self.current_height,
            pq_security_bits: self.config.min_pq_security_bits,
            enabled: true,
        };
        self.contracts.insert(contract_id.clone(), contract);
        self.counters.contracts_registered += 1;
        Ok(contract_id)
    }

    pub fn open_scheduler_slot(
        &mut self,
        shard_id: &str,
        contract_id: &str,
        caller_commitment: String,
        encrypted_call_root: String,
    ) -> Result<String> {
        self.ensure_capacity(
            self.scheduler_slots.len(),
            self.config.max_scheduler_slots,
            "scheduler_slots",
        )?;
        self.ensure_shard(shard_id)?;
        let contract = self.ensure_contract(contract_id)?;
        if contract.shard_id != shard_id {
            return Err("contract is not assigned to requested shard".to_string());
        }
        ensure_root("caller_commitment", &caller_commitment)?;
        ensure_root("encrypted_call_root", &encrypted_call_root)?;
        let sequence = self.counters.scheduler_slots_opened + 1;
        let slot_id = deterministic_id(
            "scheduler-slot",
            sequence,
            &json!({
                "shard_id": shard_id,
                "contract_id": contract_id,
                "caller_commitment": caller_commitment,
                "encrypted_call_root": encrypted_call_root,
            }),
        );
        let slot = SchedulerSlot {
            slot_id: slot_id.clone(),
            shard_id: shard_id.to_string(),
            contract_id: contract_id.to_string(),
            call_kind: contract.call_kind,
            caller_commitment,
            encrypted_call_root,
            dependency_graph_ids: BTreeSet::new(),
            witness_hint_ids: BTreeSet::new(),
            proof_reservation_ids: BTreeSet::new(),
            requested_fee_cap_id: contract.fee_cap_id.clone(),
            requested_redaction_budget_id: contract.redaction_budget_id.clone(),
            sequence,
            opened_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.slot_ttl_blocks,
            status: SlotStatus::Open,
            status_height: self.current_height,
        };
        self.scheduler_slots.insert(slot_id.clone(), slot);
        if let Some(shard) = self.shards.get_mut(shard_id) {
            shard.active_slot_ids.insert(slot_id.clone());
        }
        self.counters.scheduler_slots_opened += 1;
        Ok(slot_id)
    }

    pub fn commit_dependency_graph(
        &mut self,
        slot_id: &str,
        dependency_kinds: BTreeSet<DependencyKind>,
        declared_dependency_count: u64,
        conflict_salt_root: String,
    ) -> Result<String> {
        self.ensure_capacity(
            self.dependency_graphs.len(),
            self.config.max_dependency_graphs,
            "dependency_graphs",
        )?;
        ensure_positive("declared_dependency_count", declared_dependency_count)?;
        if declared_dependency_count as usize > self.config.max_dependencies_per_graph {
            return Err("dependency graph exceeds runtime dependency limit".to_string());
        }
        ensure_root("conflict_salt_root", &conflict_salt_root)?;
        let (contract_id, slot_status) = {
            let slot = self.ensure_slot(slot_id)?;
            (slot.contract_id.clone(), slot.status)
        };
        if !slot_status.is_active() {
            return Err("scheduler slot is not active for dependency graph".to_string());
        }
        let sequence = self.counters.dependency_graphs_committed + 1;
        let graph_id = deterministic_id(
            "dependency-graph",
            sequence,
            &json!({
                "slot_id": slot_id,
                "contract_id": contract_id,
                "dependency_kinds": dependency_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
                "declared_dependency_count": declared_dependency_count,
                "conflict_salt_root": conflict_salt_root,
            }),
        );
        let graph = DependencyGraphCommitment {
            graph_id: graph_id.clone(),
            slot_id: slot_id.to_string(),
            contract_id,
            dependency_root: deterministic_root("dependency-root", &graph_id, sequence),
            read_set_root: deterministic_root("read-set", &graph_id, sequence),
            write_set_root: deterministic_root("write-set", &graph_id, sequence),
            nullifier_root: deterministic_root("nullifier-set", &graph_id, sequence),
            graph_shape_commitment: deterministic_root("graph-shape", &graph_id, sequence),
            conflict_salt_root,
            dependency_kinds,
            declared_dependency_count,
            committed_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.slot_ttl_blocks,
        };
        let conflict = self.find_graph_conflict(&graph);
        self.dependency_graphs.insert(graph_id.clone(), graph);
        if let Some(slot) = self.scheduler_slots.get_mut(slot_id) {
            slot.dependency_graph_ids.insert(graph_id.clone());
            slot.status = SlotStatus::DependencyChecked;
            slot.status_height = self.current_height;
        }
        if let Some(conflicting_graph_id) = conflict {
            self.record_conflict(
                ConflictKind::WriteWrite,
                slot_id,
                None,
                Some(graph_id.clone()),
                deterministic_root("conflict-key", &conflicting_graph_id, sequence),
            )?;
        }
        self.counters.dependency_graphs_committed += 1;
        Ok(graph_id)
    }

    pub fn register_witness_prefetch_hint(
        &mut self,
        slot_id: &str,
        graph_id: &str,
        hint_kind: WitnessHintKind,
        provider_commitment: String,
        expected_bytes: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.witness_hints.len(),
            self.config.max_witness_hints,
            "witness_hints",
        )?;
        self.ensure_slot(slot_id)?;
        self.ensure_graph(graph_id)?;
        ensure_root("provider_commitment", &provider_commitment)?;
        ensure_positive("expected_bytes", expected_bytes)?;
        let hint_count = self
            .scheduler_slots
            .get(slot_id)
            .map(|slot| slot.witness_hint_ids.len())
            .unwrap_or_default();
        if hint_count >= self.config.max_witness_hints_per_slot {
            return Err("scheduler slot witness hint limit exceeded".to_string());
        }
        let sequence = self.counters.witness_hints_registered + 1;
        let hint_id = deterministic_id(
            "witness-prefetch-hint",
            sequence,
            &json!({
                "slot_id": slot_id,
                "graph_id": graph_id,
                "hint_kind": hint_kind.as_str(),
                "provider_commitment": provider_commitment,
            }),
        );
        let hint = WitnessPrefetchHint {
            hint_id: hint_id.clone(),
            slot_id: slot_id.to_string(),
            graph_id: graph_id.to_string(),
            hint_kind,
            encrypted_location_root: deterministic_root("encrypted-location", &hint_id, sequence),
            provider_commitment,
            witness_bundle_root: deterministic_root("witness-bundle", &hint_id, sequence),
            expected_bytes,
            priority: hint_kind_priority(hint_kind),
            ready_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.slot_ttl_blocks,
        };
        self.witness_hints.insert(hint_id.clone(), hint);
        if let Some(slot) = self.scheduler_slots.get_mut(slot_id) {
            slot.witness_hint_ids.insert(hint_id.clone());
            slot.status = SlotStatus::WitnessPrefetching;
            slot.status_height = self.current_height;
        }
        self.counters.witness_hints_registered += 1;
        Ok(hint_id)
    }

    pub fn reserve_parallel_proof(
        &mut self,
        slot_id: &str,
        prover_commitment: String,
        max_proof_ms: u64,
        fee_bid_bps: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.proof_reservations.len(),
            self.config.max_proof_reservations,
            "proof_reservations",
        )?;
        let shard_id = self.ensure_slot(slot_id)?.shard_id.clone();
        ensure_root("prover_commitment", &prover_commitment)?;
        ensure_positive("max_proof_ms", max_proof_ms)?;
        ensure_bps("fee_bid_bps", fee_bid_bps)?;
        if fee_bid_bps > self.config.max_fee_bps {
            return Err("proof reservation fee bid exceeds runtime maximum".to_string());
        }
        let reservation_count = self
            .scheduler_slots
            .get(slot_id)
            .map(|slot| slot.proof_reservation_ids.len())
            .unwrap_or_default();
        if reservation_count >= self.config.max_proof_reservations_per_slot {
            return Err("scheduler slot proof reservation limit exceeded".to_string());
        }
        let sequence = self.counters.proof_reservations_opened + 1;
        let reservation_id = deterministic_id(
            "parallel-proof-reservation",
            sequence,
            &json!({
                "slot_id": slot_id,
                "prover_commitment": prover_commitment,
                "max_proof_ms": max_proof_ms,
            }),
        );
        let reservation = ParallelProofReservation {
            reservation_id: reservation_id.clone(),
            slot_id: slot_id.to_string(),
            shard_id,
            prover_commitment,
            pq_verifier_key_root: deterministic_root("pq-verifier-key", &reservation_id, sequence),
            proof_queue_root: deterministic_root("proof-queue", &reservation_id, sequence),
            max_proof_ms,
            fee_bid_bps,
            reserved_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.proof_ttl_blocks,
            status: ProofReservationStatus::Reserved,
            proof_root: None,
        };
        self.proof_reservations
            .insert(reservation_id.clone(), reservation);
        if let Some(slot) = self.scheduler_slots.get_mut(slot_id) {
            slot.proof_reservation_ids.insert(reservation_id.clone());
            slot.status = SlotStatus::ProofReserved;
            slot.status_height = self.current_height;
        }
        self.counters.proof_reservations_opened += 1;
        Ok(reservation_id)
    }

    pub fn mark_proof_complete(&mut self, reservation_id: &str, proof_root: String) -> Result<()> {
        ensure_root("proof_root", &proof_root)?;
        let reservation = self
            .proof_reservations
            .get_mut(reservation_id)
            .ok_or_else(|| "proof reservation not found".to_string())?;
        reservation.proof_root = Some(proof_root);
        reservation.status = ProofReservationStatus::Proven;
        if let Some(slot) = self.scheduler_slots.get_mut(&reservation.slot_id) {
            slot.status = SlotStatus::Executing;
            slot.status_height = self.current_height;
        }
        Ok(())
    }

    pub fn preconfirm_slot(
        &mut self,
        slot_id: &str,
        post_state_root: String,
        privacy_units_spent: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.preconfirmation_receipts.len(),
            self.config.max_receipts,
            "preconfirmation_receipts",
        )?;
        ensure_root("post_state_root", &post_state_root)?;
        if privacy_units_spent > self.config.max_redaction_units_per_call {
            self.record_conflict(
                ConflictKind::PrivacyBudgetExceeded,
                slot_id,
                None,
                None,
                deterministic_root("privacy-budget-conflict", slot_id, privacy_units_spent),
            )?;
            return Err("privacy redaction budget exceeded".to_string());
        }
        let slot = self.ensure_slot(slot_id)?.clone();
        let fee_cap = self.ensure_fee_cap(&slot.requested_fee_cap_id)?;
        let budget = self.ensure_redaction_budget(&slot.requested_redaction_budget_id)?;
        if fee_cap.max_fee_bps > self.config.max_fee_bps {
            return Err("slot fee cap exceeds runtime maximum".to_string());
        }
        if budget.remaining_redaction_units < privacy_units_spent {
            return Err("slot redaction budget has insufficient units".to_string());
        }
        let proof_root = self.best_proof_root(slot_id)?;
        let sequence = self.counters.receipts_preconfirmed + 1;
        let receipt_id = deterministic_id(
            "preconfirmation-receipt",
            sequence,
            &json!({
                "slot_id": slot_id,
                "post_state_root": post_state_root,
                "privacy_units_spent": privacy_units_spent,
            }),
        );
        let receipt = PreconfirmationReceipt {
            receipt_id: receipt_id.clone(),
            slot_id: slot_id.to_string(),
            shard_id: slot.shard_id.clone(),
            contract_id: slot.contract_id.clone(),
            pre_state_root: self
                .shards
                .get(&slot.shard_id)
                .map(|shard| shard.local_state_root.clone())
                .unwrap_or_else(|| deterministic_root("missing-pre-state", slot_id, 0)),
            post_state_root,
            execution_trace_root: deterministic_root("execution-trace", &receipt_id, sequence),
            proof_root,
            redacted_public_output_root: deterministic_root(
                "redacted-public-output",
                &receipt_id,
                sequence,
            ),
            fee_charged_bps: fee_cap.max_fee_bps,
            privacy_units_spent,
            preconfirmed_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.receipt_ttl_blocks,
            sequencer_signature_root: deterministic_root(
                "sequencer-signature",
                &receipt_id,
                sequence,
            ),
            status: ReceiptStatus::Preconfirmed,
        };
        self.preconfirmation_receipts
            .insert(receipt_id.clone(), receipt);
        if let Some(slot_mut) = self.scheduler_slots.get_mut(slot_id) {
            slot_mut.status = SlotStatus::Preconfirmed;
            slot_mut.status_height = self.current_height;
        }
        if let Some(budget_mut) = self
            .redaction_budgets
            .get_mut(&slot.requested_redaction_budget_id)
        {
            budget_mut.remaining_redaction_units -= privacy_units_spent;
            budget_mut.spent_receipt_ids.insert(receipt_id.clone());
        }
        self.counters.receipts_preconfirmed += 1;
        Ok(receipt_id)
    }

    pub fn open_serial_fallback_lane(
        &mut self,
        shard_id: &str,
        reason: ConflictKind,
        operator_commitment: String,
    ) -> Result<String> {
        self.ensure_capacity(
            self.serial_lanes.len(),
            self.config.max_serial_lanes,
            "serial_lanes",
        )?;
        self.ensure_shard(shard_id)?;
        ensure_root("operator_commitment", &operator_commitment)?;
        let sequence = self.counters.serial_lanes_opened + 1;
        let lane_id = deterministic_id(
            "serial-fallback-lane",
            sequence,
            &json!({
                "shard_id": shard_id,
                "reason": reason.as_str(),
                "operator_commitment": operator_commitment,
            }),
        );
        let lane = SerialFallbackLane {
            lane_id: lane_id.clone(),
            shard_id: shard_id.to_string(),
            reason,
            operator_commitment: operator_commitment.clone(),
            queue_root: deterministic_root("serial-queue", &lane_id, sequence),
            ordered_slot_ids: BTreeSet::new(),
            max_queue_depth: 16_384,
            fee_cap_bps: self.config.serial_fallback_fee_bps,
            opened_at_height: self.current_height,
            active: true,
        };
        self.operator_commitments.insert(operator_commitment);
        self.serial_lanes.insert(lane_id.clone(), lane);
        if let Some(shard) = self.shards.get_mut(shard_id) {
            shard.fallback_lane_ids.insert(lane_id.clone());
        }
        self.counters.serial_lanes_opened += 1;
        Ok(lane_id)
    }

    pub fn register_fee_cap(
        &mut self,
        contract_id: String,
        payer_commitment: String,
        max_fee_bps: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.fee_caps.len(), self.config.max_fee_caps, "fee_caps")?;
        ensure_root("payer_commitment", &payer_commitment)?;
        ensure_bps("max_fee_bps", max_fee_bps)?;
        if max_fee_bps > self.config.max_fee_bps {
            return Err("fee cap exceeds runtime maximum".to_string());
        }
        let sequence = self.counters.fee_caps_registered + 1;
        let fee_cap_id = deterministic_id(
            "fee-cap",
            sequence,
            &json!({
                "contract_id": contract_id,
                "payer_commitment": payer_commitment,
                "max_fee_bps": max_fee_bps,
            }),
        );
        let fee_cap = FeeCap {
            fee_cap_id: fee_cap_id.clone(),
            contract_id,
            payer_commitment,
            asset_id: self.config.fee_asset_id.clone(),
            max_fee_bps,
            max_absolute_fee_commitment: deterministic_root(
                "max-absolute-fee",
                &fee_cap_id,
                sequence,
            ),
            paymaster_root: Some(deterministic_root("paymaster", &fee_cap_id, sequence)),
            valid_from_height: self.current_height,
            valid_until_height: self.current_height + self.config.receipt_ttl_blocks * 32,
        };
        self.fee_caps.insert(fee_cap_id.clone(), fee_cap);
        self.counters.fee_caps_registered += 1;
        Ok(fee_cap_id)
    }

    pub fn register_redaction_budget(
        &mut self,
        contract_id: String,
        owner_commitment: String,
        max_redaction_units: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.redaction_budgets.len(),
            self.config.max_redaction_budgets,
            "redaction_budgets",
        )?;
        ensure_root("owner_commitment", &owner_commitment)?;
        ensure_positive("max_redaction_units", max_redaction_units)?;
        let sequence = self.counters.redaction_budgets_registered + 1;
        let budget_id = deterministic_id(
            "privacy-redaction-budget",
            sequence,
            &json!({
                "contract_id": contract_id,
                "owner_commitment": owner_commitment,
                "max_redaction_units": max_redaction_units,
            }),
        );
        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            contract_id,
            owner_commitment,
            redaction_policy_root: deterministic_root("redaction-policy", &budget_id, sequence),
            max_redaction_units,
            remaining_redaction_units: max_redaction_units,
            max_revealed_fields: self.config.max_revealed_fields_per_receipt,
            spent_receipt_ids: BTreeSet::new(),
            valid_until_height: self.current_height + self.config.receipt_ttl_blocks * 32,
        };
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.counters.redaction_budgets_registered += 1;
        Ok(budget_id)
    }

    pub fn roots(&self) -> Roots {
        let (
            shard_root,
            contract_root,
            dependency_graph_root,
            witness_hint_root,
            scheduler_slot_root,
            proof_reservation_root,
            conflict_root,
            receipt_root,
            serial_lane_root,
            fee_cap_root,
            redaction_budget_root,
            devnet_fixture_root,
            operator_root,
        ) = self.roots_without_state_root();
        let state_root = state_root_from_record(&self.public_record_without_state_root_with_roots(
            &shard_root,
            &contract_root,
            &dependency_graph_root,
            &witness_hint_root,
            &scheduler_slot_root,
            &proof_reservation_root,
            &conflict_root,
            &receipt_root,
            &serial_lane_root,
            &fee_cap_root,
            &redaction_budget_root,
            &devnet_fixture_root,
            &operator_root,
        ));
        Roots {
            shard_root,
            contract_root,
            dependency_graph_root,
            witness_hint_root,
            scheduler_slot_root,
            proof_reservation_root,
            conflict_root,
            receipt_root,
            serial_lane_root,
            fee_cap_root,
            redaction_budget_root,
            devnet_fixture_root,
            operator_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root_with_roots(
            &roots.shard_root,
            &roots.contract_root,
            &roots.dependency_graph_root,
            &roots.witness_hint_root,
            &roots.scheduler_slot_root,
            &roots.proof_reservation_root,
            &roots.conflict_root,
            &roots.receipt_root,
            &roots.serial_lane_root,
            &roots.fee_cap_root,
            &roots.redaction_budget_root,
            &roots.devnet_fixture_root,
            &roots.operator_root,
        );
        if let Some(object) = record.as_object_mut() {
            object.insert("roots".to_string(), roots.public_record());
            object.insert("state_root".to_string(), Value::String(roots.state_root));
        }
        record
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            return Err(format!(
                "parallel contract executor {label} capacity exceeded"
            ));
        }
        Ok(())
    }

    fn ensure_shard(&self, shard_id: &str) -> Result<&ExecutionShard> {
        ensure_non_empty("shard_id", shard_id)?;
        self.shards
            .get(shard_id)
            .ok_or_else(|| "execution shard not found".to_string())
    }

    fn ensure_contract(&self, contract_id: &str) -> Result<&ContractDescriptor> {
        ensure_non_empty("contract_id", contract_id)?;
        self.contracts
            .get(contract_id)
            .ok_or_else(|| "contract descriptor not found".to_string())
    }

    fn ensure_slot(&self, slot_id: &str) -> Result<&SchedulerSlot> {
        ensure_non_empty("slot_id", slot_id)?;
        self.scheduler_slots
            .get(slot_id)
            .ok_or_else(|| "scheduler slot not found".to_string())
    }

    fn ensure_graph(&self, graph_id: &str) -> Result<&DependencyGraphCommitment> {
        ensure_non_empty("graph_id", graph_id)?;
        self.dependency_graphs
            .get(graph_id)
            .ok_or_else(|| "dependency graph not found".to_string())
    }

    fn ensure_fee_cap(&self, fee_cap_id: &str) -> Result<&FeeCap> {
        ensure_non_empty("fee_cap_id", fee_cap_id)?;
        self.fee_caps
            .get(fee_cap_id)
            .ok_or_else(|| "fee cap not found".to_string())
    }

    fn ensure_redaction_budget(&self, budget_id: &str) -> Result<&PrivacyRedactionBudget> {
        ensure_non_empty("budget_id", budget_id)?;
        self.redaction_budgets
            .get(budget_id)
            .ok_or_else(|| "privacy redaction budget not found".to_string())
    }

    fn find_graph_conflict(&self, graph: &DependencyGraphCommitment) -> Option<String> {
        self.dependency_graphs
            .iter()
            .find(|(_, existing)| {
                existing.slot_id != graph.slot_id
                    && existing.expires_at_height >= self.current_height
                    && existing.write_set_root == graph.write_set_root
                    && existing.conflict_salt_root != graph.conflict_salt_root
            })
            .map(|(graph_id, _)| graph_id.clone())
    }

    fn record_conflict(
        &mut self,
        conflict_kind: ConflictKind,
        primary_slot_id: &str,
        conflicting_slot_id: Option<String>,
        dependency_graph_id: Option<String>,
        conflict_key_root: String,
    ) -> Result<String> {
        self.ensure_capacity(self.conflicts.len(), self.config.max_conflicts, "conflicts")?;
        ensure_root("conflict_key_root", &conflict_key_root)?;
        let sequence = self.counters.conflicts_detected + 1;
        let shard_id = self
            .scheduler_slots
            .get(primary_slot_id)
            .map(|slot| slot.shard_id.clone())
            .unwrap_or_default();
        let fallback_lane_id = if self.config.enable_demo_serial_fallback && !shard_id.is_empty() {
            let operator = deterministic_root("serial-operator", primary_slot_id, sequence);
            Some(self.open_serial_fallback_lane(&shard_id, conflict_kind, operator)?)
        } else {
            None
        };
        let conflict_id = deterministic_id(
            "conflict",
            sequence,
            &json!({
                "conflict_kind": conflict_kind.as_str(),
                "primary_slot_id": primary_slot_id,
                "conflicting_slot_id": conflicting_slot_id,
                "dependency_graph_id": dependency_graph_id,
                "conflict_key_root": conflict_key_root,
            }),
        );
        let conflict = ConflictDetectionRecord {
            conflict_id: conflict_id.clone(),
            conflict_kind,
            primary_slot_id: primary_slot_id.to_string(),
            conflicting_slot_id,
            dependency_graph_id,
            conflict_key_root,
            conflict_evidence_root: deterministic_root("conflict-evidence", &conflict_id, sequence),
            resolver_commitment: deterministic_root("resolver", &conflict_id, sequence),
            fallback_lane_id: fallback_lane_id.clone(),
            detected_at_height: self.current_height,
            resolved: fallback_lane_id.is_some(),
        };
        self.conflicts.insert(conflict_id.clone(), conflict);
        if let Some(slot) = self.scheduler_slots.get_mut(primary_slot_id) {
            slot.status = if fallback_lane_id.is_some() {
                SlotStatus::SerialFallback
            } else {
                SlotStatus::Conflicted
            };
            slot.status_height = self.current_height;
        }
        if let Some(lane_id) = fallback_lane_id {
            if let Some(lane) = self.serial_lanes.get_mut(&lane_id) {
                lane.ordered_slot_ids.insert(primary_slot_id.to_string());
            }
        }
        self.counters.conflicts_detected += 1;
        Ok(conflict_id)
    }

    fn best_proof_root(&self, slot_id: &str) -> Result<String> {
        let slot = self.ensure_slot(slot_id)?;
        for reservation_id in &slot.proof_reservation_ids {
            if let Some(reservation) = self.proof_reservations.get(reservation_id) {
                if reservation.status == ProofReservationStatus::Proven {
                    if let Some(proof_root) = &reservation.proof_root {
                        return Ok(proof_root.clone());
                    }
                }
            }
        }
        Err("scheduler slot has no completed proof reservation".to_string())
    }

    #[allow(clippy::too_many_arguments)]
    fn public_record_without_state_root_with_roots(
        &self,
        shard_root: &str,
        contract_root: &str,
        dependency_graph_root: &str,
        witness_hint_root: &str,
        scheduler_slot_root: &str,
        proof_reservation_root: &str,
        conflict_root: &str,
        receipt_root: &str,
        serial_lane_root: &str,
        fee_cap_root: &str,
        redaction_budget_root: &str,
        devnet_fixture_root: &str,
        operator_root: &str,
    ) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "shard_root": shard_root,
            "contract_root": contract_root,
            "dependency_graph_root": dependency_graph_root,
            "witness_hint_root": witness_hint_root,
            "scheduler_slot_root": scheduler_slot_root,
            "proof_reservation_root": proof_reservation_root,
            "conflict_root": conflict_root,
            "receipt_root": receipt_root,
            "serial_lane_root": serial_lane_root,
            "fee_cap_root": fee_cap_root,
            "redaction_budget_root": redaction_budget_root,
            "devnet_fixture_root": devnet_fixture_root,
            "operator_root": operator_root,
        })
    }

    fn roots_without_state_root(
        &self,
    ) -> (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ) {
        (
            map_root("PCE-SHARDS", &self.shards, ExecutionShard::public_record),
            map_root(
                "PCE-CONTRACTS",
                &self.contracts,
                ContractDescriptor::public_record,
            ),
            map_root(
                "PCE-DEPENDENCY-GRAPHS",
                &self.dependency_graphs,
                DependencyGraphCommitment::public_record,
            ),
            map_root(
                "PCE-WITNESS-HINTS",
                &self.witness_hints,
                WitnessPrefetchHint::public_record,
            ),
            map_root(
                "PCE-SCHEDULER-SLOTS",
                &self.scheduler_slots,
                SchedulerSlot::public_record,
            ),
            map_root(
                "PCE-PROOF-RESERVATIONS",
                &self.proof_reservations,
                ParallelProofReservation::public_record,
            ),
            map_root(
                "PCE-CONFLICTS",
                &self.conflicts,
                ConflictDetectionRecord::public_record,
            ),
            map_root(
                "PCE-PRECONFIRMATION-RECEIPTS",
                &self.preconfirmation_receipts,
                PreconfirmationReceipt::public_record,
            ),
            map_root(
                "PCE-SERIAL-LANES",
                &self.serial_lanes,
                SerialFallbackLane::public_record,
            ),
            map_root("PCE-FEE-CAPS", &self.fee_caps, FeeCap::public_record),
            map_root(
                "PCE-REDACTION-BUDGETS",
                &self.redaction_budgets,
                PrivacyRedactionBudget::public_record,
            ),
            map_root(
                "PCE-DEVNET-FIXTURES",
                &self.devnet_fixtures,
                DevnetFixture::public_record,
            ),
            set_root("PCE-OPERATORS", &self.operator_commitments),
        )
    }

    fn load_devnet_sample(&mut self) {
        let operator = deterministic_root("operator", "devnet-fast-confidential-executor", 0);
        let shard_id = self
            .register_shard(
                ExecutionShardKind::UltraFastDefi,
                operator,
                128,
                8,
                self.config.target_privacy_set_size,
            )
            .expect("devnet shard");
        let fee_cap_id = self
            .register_fee_cap(
                "pending-contract".to_string(),
                deterministic_root("payer", "devnet-alice", 0),
                7,
            )
            .expect("devnet fee cap");
        let budget_id = self
            .register_redaction_budget(
                "pending-contract".to_string(),
                deterministic_root("owner", "devnet-alice", 0),
                128,
            )
            .expect("devnet redaction budget");
        let contract_id = self
            .register_contract(
                &shard_id,
                ContractCallKind::Swap,
                deterministic_root("contract", "devnet-confidential-amm", 0),
                fee_cap_id.clone(),
                budget_id.clone(),
            )
            .expect("devnet contract");
        if let Some(fee_cap) = self.fee_caps.get_mut(&fee_cap_id) {
            fee_cap.contract_id = contract_id.clone();
        }
        if let Some(budget) = self.redaction_budgets.get_mut(&budget_id) {
            budget.contract_id = contract_id.clone();
        }
        let slot_id = self
            .open_scheduler_slot(
                &shard_id,
                &contract_id,
                deterministic_root("caller", "devnet-alice", 0),
                deterministic_root("encrypted-call", "devnet-swap", 0),
            )
            .expect("devnet slot");
        let mut dependency_kinds = BTreeSet::new();
        dependency_kinds.insert(DependencyKind::ReadSet);
        dependency_kinds.insert(DependencyKind::WriteSet);
        dependency_kinds.insert(DependencyKind::NullifierSet);
        dependency_kinds.insert(DependencyKind::LiquidityPool);
        let graph_id = self
            .commit_dependency_graph(
                &slot_id,
                dependency_kinds,
                4,
                deterministic_root("conflict-salt", "devnet-swap", 0),
            )
            .expect("devnet graph");
        let _hint_id = self
            .register_witness_prefetch_hint(
                &slot_id,
                &graph_id,
                WitnessHintKind::MerkleBranch,
                deterministic_root("provider", "devnet-witness-cache", 0),
                16_384,
            )
            .expect("devnet hint");
        let reservation_id = self
            .reserve_parallel_proof(
                &slot_id,
                deterministic_root("prover", "devnet-proof-worker", 0),
                90,
                5,
            )
            .expect("devnet proof reservation");
        self.mark_proof_complete(
            &reservation_id,
            deterministic_root("proof", "devnet-swap-proof", 0),
        )
        .expect("devnet proof complete");
        let receipt_id = self
            .preconfirm_slot(
                &slot_id,
                deterministic_root("post-state", "devnet-swap", 0),
                9,
            )
            .expect("devnet receipt");
        if self.config.enable_demo_serial_fallback {
            let conflict_slot_id = self
                .open_scheduler_slot(
                    &shard_id,
                    &contract_id,
                    deterministic_root("caller", "devnet-bob", 0),
                    deterministic_root("encrypted-call", "devnet-conflict", 0),
                )
                .expect("devnet conflict slot");
            let _ = self.record_conflict(
                ConflictKind::NullifierReuse,
                &conflict_slot_id,
                Some(slot_id.clone()),
                Some(graph_id.clone()),
                deterministic_root("nullifier-conflict", "devnet-conflict", 0),
            );
        }
        let fixture_id = deterministic_id(
            "devnet-fixture",
            1,
            &json!({
                "shard_id": shard_id,
                "contract_id": contract_id,
                "slot_id": slot_id,
                "receipt_id": receipt_id,
            }),
        );
        self.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                label: "devnet confidential AMM swap with parallel proof".to_string(),
                shard_id,
                slot_id: Some(slot_id),
                contract_id: Some(contract_id),
                fixture_root: deterministic_root("fixture", "devnet-confidential-amm", 0),
                notes: "sample state covers shards, dependency commitments, prefetch hints, proof reservations, preconfirmations, and serial fallback".to_string(),
            },
        );
        self.counters.devnet_fixtures_loaded += 1;
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("PCE-STATE-ROOT", record)
}

pub fn deterministic_root(label: &str, subject: &str, nonce: u64) -> String {
    stable_hash_hex(&format!(
        "{}|{}|{}|{}|{}",
        PROTOCOL_VERSION, "root", label, subject, nonce
    ))
}

pub fn deterministic_id(label: &str, sequence: u64, record: &Value) -> String {
    stable_hash_hex(&format!(
        "{}|{}|{}|{}",
        PROTOCOL_VERSION,
        label,
        sequence,
        canonical_json(record)
    ))
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    stable_hash_hex(&format!(
        "{}|{}|{}",
        PROTOCOL_VERSION,
        domain,
        canonical_json(payload)
    ))
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let joined = records
        .iter()
        .map(canonical_json)
        .collect::<Vec<_>>()
        .join("|");
    stable_hash_hex(&format!("{}|{}|{}", PROTOCOL_VERSION, domain, joined))
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = map.values().map(public_record).collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set.iter().cloned().map(Value::String).collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn sorted_values(set: &BTreeSet<String>) -> Vec<String> {
    set.iter().cloned().collect()
}

fn hint_kind_priority(kind: WitnessHintKind) -> u64 {
    match kind {
        WitnessHintKind::PqVerificationKey => 10_000,
        WitnessHintKind::NullifierWindow => 9_600,
        WitnessHintKind::MerkleBranch => 9_200,
        WitnessHintKind::BridgeProof => 9_000,
        WitnessHintKind::ContractBytecode => 8_700,
        WitnessHintKind::AccountNote => 8_300,
        WitnessHintKind::OraclePacket => 8_000,
        WitnessHintKind::TokenMetadata => 7_600,
        WitnessHintKind::FeeSponsor => 7_400,
        WitnessHintKind::PrivacyCoverSet => 7_000,
    }
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

fn ensure_root(name: &str, value: &str) -> Result<()> {
    ensure_non_empty(name, value)?;
    if value.len() < 16 {
        return Err(format!("{name} must be hash-like"));
    }
    Ok(())
}

fn ensure_positive(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn ensure_positive_usize(name: &str, value: usize) -> Result<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} cannot exceed 100%"));
    }
    Ok(())
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => json!(text).to_string(),
        Value::Array(items) => {
            let body = items
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        Value::Object(map) => {
            let body = map
                .iter()
                .map(|(key, item)| format!("{}:{}", json!(key), canonical_json(item)))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
    }
}

fn stable_hash_hex(input: &str) -> String {
    let mut lanes = [
        0xcbf29ce484222325_u64,
        0x9e3779b97f4a7c15_u64,
        0x94d049bb133111eb_u64,
        0x2545f4914f6cdd1d_u64,
    ];
    for (index, byte) in input.as_bytes().iter().enumerate() {
        let lane = index % lanes.len();
        lanes[lane] ^= u64::from(*byte);
        lanes[lane] = lanes[lane].wrapping_mul(0x100000001b3);
        lanes[lane] ^= lanes[(lane + lanes.len() - 1) % lanes.len()].rotate_left(13);
    }
    format!(
        "{:016x}{:016x}{:016x}{:016x}",
        lanes[0], lanes[1], lanes[2], lanes[3]
    )
}
