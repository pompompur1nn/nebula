use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingSettlementRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> =
    PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingSettlementRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_SETTLEMENT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-storage-receipt-fee-netting-settlement-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_SETTLEMENT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SETTLEMENT_SUITE: &str =
    "pq-confidential-contract-sealed-storage-receipt-fee-netting-settlement-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-storage-receipt-fee-netting-settlement-public-record-v1";
pub const SETTLEMENT_EPOCH_SCHEME: &str =
    "sealed-storage-receipt-fee-netting-settlement-epoch-root-v1";
pub const SETTLEMENT_NETTING_SET_SCHEME: &str =
    "sealed-storage-receipt-fee-netting-settlement-netting-set-root-v1";
pub const SETTLED_RECEIPT_SCHEME: &str =
    "sealed-storage-receipt-fee-netting-settled-receipt-root-v1";
pub const SETTLEMENT_INSTRUCTION_SCHEME: &str =
    "confidential-contract-sealed-storage-settlement-instruction-root-v1";
pub const LIQUIDITY_RESERVE_SCHEME: &str =
    "confidential-contract-sealed-storage-fee-liquidity-reserve-root-v1";
pub const SETTLEMENT_QUOTE_SCHEME: &str =
    "low-fee-confidential-receipt-netting-settlement-quote-root-v1";
pub const SETTLEMENT_ATTESTATION_SCHEME: &str =
    "pq-confidential-receipt-netting-settlement-attestation-root-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str =
    "fast-confidential-receipt-netting-settlement-batch-root-v1";
pub const REPLAY_LOCK_SCHEME: &str = "confidential-receipt-netting-settlement-replay-lock-root-v1";
pub const FINALITY_TRACK_SCHEME: &str =
    "confidential-contract-receipt-netting-settlement-finality-track-root-v1";
pub const SETTLEMENT_FEE_LEDGER_SCHEME: &str =
    "confidential-contract-receipt-netting-settlement-fee-ledger-root-v1";
pub const POLICY_ROOT_SCHEME: &str = "netting-settlement-privacy-pq-policy-root-v1";
pub const PUBLIC_RECORD_ROOT_SCHEME: &str =
    "storage-receipt-netting-settlement-roots-only-public-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 6_021_888;
pub const DEVNET_EPOCH: u64 = 11_761;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 2;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const DEFAULT_MAX_NETTING_SET_HOPS: u8 = 4;
pub const DEFAULT_MAX_SETTLEMENT_EDGES: usize = 32_768;
pub const DEFAULT_MAX_SEALED_RECEIPTS_PER_EPOCH: usize = 16_384;
pub const DEFAULT_MAX_INSTRUCTIONS_PER_EPOCH: usize = 12_288;
pub const DEFAULT_MAX_QUOTES_PER_EPOCH: usize = 8_192;
pub const DEFAULT_MAX_BATCH_MATCHES: usize = 6_144;
pub const DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH: u64 = 8_388_608;
pub const DEFAULT_MAX_STORAGE_KEYS_PER_RECEIPT: u64 = 98_304;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_MICRO_FEE: u64 = 1;
pub const DEFAULT_BASE_MICRO_FEE: u64 = 2;
pub const DEFAULT_SETTLEMENT_OPERATOR_FEE_BPS: u64 = 2;
pub const DEFAULT_SETTLEMENT_REBATE_BPS: u64 = 22;
pub const DEFAULT_NETTING_COMPRESSION_REBATE_BPS: u64 = 11;
pub const DEFAULT_CONGESTION_FEE_BPS: u64 = 4;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_FAST_FINALITY_QUORUM_BPS: u64 = 8_400;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    ContractExecution,
    DefiSettlement,
    BridgeExit,
    BridgeEntry,
    OracleRefresh,
    GovernanceAction,
    AccountRecovery,
    EmergencyStorage,
    PayrollStream,
    CrossShardSync,
    BatchMaintenance,
}

impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractExecution => "contract_execution",
            Self::DefiSettlement => "defi_settlement",
            Self::BridgeExit => "bridge_exit",
            Self::BridgeEntry => "bridge_entry",
            Self::OracleRefresh => "oracle_refresh",
            Self::GovernanceAction => "governance_action",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyStorage => "emergency_storage",
            Self::PayrollStream => "payroll_stream",
            Self::CrossShardSync => "cross_shard_sync",
            Self::BatchMaintenance => "batch_maintenance",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyStorage => 10_000,
            Self::AccountRecovery => 9_850,
            Self::BridgeExit => 9_550,
            Self::BridgeEntry => 9_350,
            Self::CrossShardSync => 9_100,
            Self::OracleRefresh => 8_950,
            Self::DefiSettlement => 8_750,
            Self::ContractExecution => 8_500,
            Self::PayrollStream => 8_200,
            Self::GovernanceAction => 8_000,
            Self::BatchMaintenance => 7_650,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementEpochStatus {
    Announced,
    AcceptingReceipts,
    Routing,
    Quoting,
    PqAttested,
    FastSettling,
    Settled,
    Cancelled,
    Expired,
}

impl SettlementEpochStatus {
    pub fn accepts_receipts(self) -> bool {
        matches!(self, Self::Announced | Self::AcceptingReceipts)
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::AcceptingReceipts
                | Self::Routing
                | Self::Quoting
                | Self::PqAttested
                | Self::FastSettling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementNettingSetKind {
    LocalNetting,
    CrossContract,
    CrossShard,
    BridgeIngress,
    BridgeEgress,
    FeeSponsor,
    RebateReturn,
    RecoveryFallback,
}

impl SettlementNettingSetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalNetting => "local_netting",
            Self::CrossContract => "cross_contract",
            Self::CrossShard => "cross_shard",
            Self::BridgeIngress => "bridge_ingress",
            Self::BridgeEgress => "bridge_egress",
            Self::FeeSponsor => "fee_sponsor",
            Self::RebateReturn => "rebate_return",
            Self::RecoveryFallback => "recovery_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedSettlementReceiptStatus {
    Sealed,
    ReplayLocked,
    InstructionBound,
    Settled,
    Quoted,
    Netted,
    Settled,
    Repriced,
    Refunded,
    DuplicateRejected,
    Expired,
}

impl SealedSettlementReceiptStatus {
    pub fn routable(self) -> bool {
        matches!(
            self,
            Self::ReplayLocked | Self::InstructionBound | Self::Settled | Self::Quoted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingInstructionStatus {
    Pending,
    SettlementLocked,
    QuoteReady,
    PartiallyNetted,
    FullyNetted,
    DustRefund,
    Challenged,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementQuoteStatus {
    Proposed,
    FeeDeltaBound,
    LiquidityChecked,
    ExecutorAttested,
    VerifierAttested,
    QuorumReady,
    Included,
    Challenged,
    Rejected,
}

impl SettlementQuoteStatus {
    pub fn settlement_ready(self) -> bool {
        matches!(
            self,
            Self::FeeDeltaBound
                | Self::LiquidityChecked
                | Self::ExecutorAttested
                | Self::VerifierAttested
                | Self::QuorumReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAttestationRole {
    SettlementEpochner,
    NettingExecutor,
    ReceiptVerifier,
    LiquidityAuditor,
    PrivacySetAuditor,
    Watchtower,
}

impl SettlementAttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementEpochner => "settlement_epochner",
            Self::NettingExecutor => "netting_executor",
            Self::ReceiptVerifier => "receipt_verifier",
            Self::LiquidityAuditor => "liquidity_auditor",
            Self::PrivacySetAuditor => "privacy_set_auditor",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAttestationStatus {
    Pending,
    Verified,
    Aggregated,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayLockStatus {
    Reserved,
    Armed,
    Consumed,
    DuplicateRejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastSettlementBatchStatus {
    Queued,
    PqQuorum,
    FastFinal,
    Settled,
    Repriced,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementTrackStatus {
    Open,
    Sealed,
    FastFinal,
    Settled,
    Suspended,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub settlement_window_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub replay_window_blocks: u64,
    pub max_netting_set_hops: u8,
    pub max_settlement_netting_sets: usize,
    pub max_sealed_receipts_per_epoch: usize,
    pub max_instructions_per_epoch: usize,
    pub max_quotes_per_epoch: usize,
    pub max_batch_matches: usize,
    pub max_receipt_bytes_per_batch: u64,
    pub max_storage_keys_per_receipt: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_micro_fee: u64,
    pub base_micro_fee: u64,
    pub settlement_operator_fee_bps: u64,
    pub settlement_rebate_bps: u64,
    pub netting_compression_rebate_bps: u64,
    pub congestion_fee_bps: u64,
    pub quorum_bps: u64,
    pub fast_finality_quorum_bps: u64,
    pub require_roots_only_public_records: bool,
    pub prefer_low_fee_settlements: bool,
    pub prefer_fast_receipt_settlement: bool,
    pub require_pq_attestations: bool,
    pub require_replay_locks: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            fast_settlement_blocks: DEFAULT_FAST_SETTLEMENT_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            max_netting_set_hops: DEFAULT_MAX_NETTING_SET_HOPS,
            max_settlement_netting_sets: DEFAULT_MAX_SETTLEMENT_EDGES,
            max_sealed_receipts_per_epoch: DEFAULT_MAX_SEALED_RECEIPTS_PER_EPOCH,
            max_instructions_per_epoch: DEFAULT_MAX_INSTRUCTIONS_PER_EPOCH,
            max_quotes_per_epoch: DEFAULT_MAX_QUOTES_PER_EPOCH,
            max_batch_matches: DEFAULT_MAX_BATCH_MATCHES,
            max_receipt_bytes_per_batch: DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH,
            max_storage_keys_per_receipt: DEFAULT_MAX_STORAGE_KEYS_PER_RECEIPT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_micro_fee: DEFAULT_MIN_MICRO_FEE,
            base_micro_fee: DEFAULT_BASE_MICRO_FEE,
            settlement_operator_fee_bps: DEFAULT_SETTLEMENT_OPERATOR_FEE_BPS,
            settlement_rebate_bps: DEFAULT_SETTLEMENT_REBATE_BPS,
            netting_compression_rebate_bps: DEFAULT_NETTING_COMPRESSION_REBATE_BPS,
            congestion_fee_bps: DEFAULT_CONGESTION_FEE_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            fast_finality_quorum_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
            require_roots_only_public_records: true,
            prefer_low_fee_settlements: true,
            prefer_fast_receipt_settlement: true,
            require_pq_attestations: true,
            require_replay_locks: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported netting settlement protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported netting settlement schema version".to_string());
        }
        if self.settlement_window_blocks == 0 {
            return Err("settlement_window_blocks must be positive".to_string());
        }
        if self.fast_settlement_blocks == 0 {
            return Err("fast_settlement_blocks must be positive".to_string());
        }
        if self.replay_window_blocks < self.settlement_window_blocks {
            return Err("replay_window_blocks must cover settlement_window_blocks".to_string());
        }
        if self.max_netting_set_hops == 0 {
            return Err("max_netting_set_hops must be positive".to_string());
        }
        if self.max_settlement_netting_sets == 0 {
            return Err("max_settlement_netting_sets must be positive".to_string());
        }
        if self.max_sealed_receipts_per_epoch == 0 {
            return Err("max_sealed_receipts_per_epoch must be positive".to_string());
        }
        if self.max_instructions_per_epoch == 0 {
            return Err("max_instructions_per_epoch must be positive".to_string());
        }
        if self.max_quotes_per_epoch == 0 {
            return Err("max_quotes_per_epoch must be positive".to_string());
        }
        if self.max_batch_matches == 0 {
            return Err("max_batch_matches must be positive".to_string());
        }
        if self.max_receipt_bytes_per_batch == 0 {
            return Err("max_receipt_bytes_per_batch must be positive".to_string());
        }
        if self.max_storage_keys_per_receipt == 0 {
            return Err("max_storage_keys_per_receipt must be positive".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set thresholds are invalid".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        for (name, bps) in [
            (
                "settlement_operator_fee_bps",
                self.settlement_operator_fee_bps,
            ),
            ("settlement_rebate_bps", self.settlement_rebate_bps),
            (
                "netting_compression_rebate_bps",
                self.netting_compression_rebate_bps,
            ),
            ("congestion_fee_bps", self.congestion_fee_bps),
            ("quorum_bps", self.quorum_bps),
            ("fast_finality_quorum_bps", self.fast_finality_quorum_bps),
        ] {
            if bps > MAX_BPS {
                return Err(format!("{name} exceeds MAX_BPS"));
            }
        }
        if self.fast_finality_quorum_bps < self.quorum_bps {
            return Err("fast finality quorum cannot be below base quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "settlement_window_blocks": self.settlement_window_blocks,
            "fast_settlement_blocks": self.fast_settlement_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "max_netting_set_hops": self.max_netting_set_hops,
            "max_settlement_netting_sets": self.max_settlement_netting_sets,
            "max_sealed_receipts_per_epoch": self.max_sealed_receipts_per_epoch,
            "max_instructions_per_epoch": self.max_instructions_per_epoch,
            "max_quotes_per_epoch": self.max_quotes_per_epoch,
            "max_batch_matches": self.max_batch_matches,
            "max_receipt_bytes_per_batch": self.max_receipt_bytes_per_batch,
            "max_storage_keys_per_receipt": self.max_storage_keys_per_receipt,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_micro_fee": self.min_micro_fee,
            "base_micro_fee": self.base_micro_fee,
            "settlement_operator_fee_bps": self.settlement_operator_fee_bps,
            "settlement_rebate_bps": self.settlement_rebate_bps,
            "netting_compression_rebate_bps": self.netting_compression_rebate_bps,
            "congestion_fee_bps": self.congestion_fee_bps,
            "quorum_bps": self.quorum_bps,
            "fast_finality_quorum_bps": self.fast_finality_quorum_bps,
            "require_roots_only_public_records": self.require_roots_only_public_records,
            "prefer_low_fee_settlements": self.prefer_low_fee_settlements,
            "prefer_fast_receipt_settlement": self.prefer_fast_receipt_settlement,
            "require_pq_attestations": self.require_pq_attestations,
            "require_replay_locks": self.require_replay_locks,
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub settlement_epochs_opened: u64,
    pub settlement_netting_sets_registered: u64,
    pub sealed_receipts_submitted: u64,
    pub netting_instructions_bound: u64,
    pub liquidity_reserves_registered: u64,
    pub settlement_quotes_proposed: u64,
    pub settlement_attestations_recorded: u64,
    pub replay_locks_consumed: u64,
    pub fast_batches_finalized: u64,
    pub settlement_tracks_opened: u64,
    pub settlement_fee_ledger_entries_appended: u64,
    pub receipts_settled: u64,
    pub receipts_refunded: u64,
    pub receipts_repriced: u64,
    pub duplicate_receipts_rejected: u64,
    pub total_receipt_bytes_settled: u64,
    pub total_storage_keys_settled: u64,
    pub gross_micro_fees_quoted: u64,
    pub net_micro_fees_settled: u64,
    pub rebate_micro_fees_returned: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_epochs_opened": self.settlement_epochs_opened,
            "settlement_netting_sets_registered": self.settlement_netting_sets_registered,
            "sealed_receipts_submitted": self.sealed_receipts_submitted,
            "netting_instructions_bound": self.netting_instructions_bound,
            "liquidity_reserves_registered": self.liquidity_reserves_registered,
            "settlement_quotes_proposed": self.settlement_quotes_proposed,
            "settlement_attestations_recorded": self.settlement_attestations_recorded,
            "replay_locks_consumed": self.replay_locks_consumed,
            "fast_batches_finalized": self.fast_batches_finalized,
            "settlement_tracks_opened": self.settlement_tracks_opened,
            "settlement_fee_ledger_entries_appended": self.settlement_fee_ledger_entries_appended,
            "receipts_settled": self.receipts_settled,
            "receipts_refunded": self.receipts_refunded,
            "receipts_repriced": self.receipts_repriced,
            "duplicate_receipts_rejected": self.duplicate_receipts_rejected,
            "total_receipt_bytes_settled": self.total_receipt_bytes_settled,
            "total_storage_keys_settled": self.total_storage_keys_settled,
            "gross_micro_fees_quoted": self.gross_micro_fees_quoted,
            "net_micro_fees_settled": self.net_micro_fees_settled,
            "rebate_micro_fees_returned": self.rebate_micro_fees_returned,
        })
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub settlement_epoch_root: String,
    pub settlement_netting_set_root: String,
    pub sealed_settlement_receipt_root: String,
    pub netting_instruction_root: String,
    pub liquidity_reserve_root: String,
    pub settlement_quote_root: String,
    pub settlement_attestation_root: String,
    pub settlement_batch_root: String,
    pub replay_lock_root: String,
    pub settlement_track_root: String,
    pub settlement_fee_ledger_root: String,
    pub policy_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "settlement_epoch_root": self.settlement_epoch_root,
            "settlement_netting_set_root": self.settlement_netting_set_root,
            "sealed_settlement_receipt_root": self.sealed_settlement_receipt_root,
            "netting_instruction_root": self.netting_instruction_root,
            "liquidity_reserve_root": self.liquidity_reserve_root,
            "settlement_quote_root": self.settlement_quote_root,
            "settlement_attestation_root": self.settlement_attestation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "replay_lock_root": self.replay_lock_root,
            "settlement_track_root": self.settlement_track_root,
            "settlement_fee_ledger_root": self.settlement_fee_ledger_root,
            "policy_root": self.policy_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementEpochInput {
    pub lane: SettlementLane,
    pub source_namespace_root: String,
    pub target_namespace_root: String,
    pub eligible_contract_set_root: String,
    pub settlement_committee_root: String,
    pub liquidity_reserve_set_root: String,
    pub target_receipt_bytes: u64,
    pub target_storage_keys: u64,
    pub min_settlement_micro_fee: u64,
    pub privacy_set_size: u64,
    pub pq_policy_root: String,
    pub epoch_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementNettingSetInput {
    pub epoch_id: String,
    pub netting_set_kind: SettlementNettingSetKind,
    pub source_contract_commitment: String,
    pub target_contract_commitment: String,
    pub source_storage_root: String,
    pub target_storage_root: String,
    pub fee_asset_commitment: String,
    pub liquidity_reserve_root: String,
    pub max_hops_from_source: u8,
    pub netting_set_weight_bps: u64,
    pub netting_set_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedSettlementReceiptInput {
    pub epoch_id: String,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub sealed_receipt_root: String,
    pub encrypted_storage_delta_root: String,
    pub settlement_reserve_root: String,
    pub replay_nullifier_root: String,
    pub max_micro_fee: u64,
    pub receipt_bytes_upper_bound: u64,
    pub storage_keys_upper_bound: u64,
    pub receipt_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettingInstructionInput {
    pub epoch_id: String,
    pub receipt_ids: Vec<String>,
    pub settlement_netting_set_ids: Vec<String>,
    pub aggregate_position_commitment_root: String,
    pub aggregate_fee_delta_root: String,
    pub settlement_lane_root: String,
    pub privacy_witness_root: String,
    pub instruction_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LiquidityReserveInput {
    pub epoch_id: String,
    pub settlement_netting_set_id: String,
    pub sponsor_commitment: String,
    pub liquidity_commitment_root: String,
    pub low_fee_curve_root: String,
    pub rebate_commitment_root: String,
    pub available_liquidity_bucket: u64,
    pub expires_height: u64,
    pub reserve_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementQuoteInput {
    pub epoch_id: String,
    pub instruction_id: String,
    pub liquidity_reserve_ids: Vec<String>,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub sealed_settlement_receipt_batch_root: String,
    pub netted_fee_delta_root: String,
    pub quote_price_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub gross_micro_fee: u64,
    pub quote_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementAttestationInput {
    pub quote_id: String,
    pub role: SettlementAttestationRole,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_settlement_root: String,
    pub attested_receipt_root: String,
    pub attested_storage_root: String,
    pub pq_public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub attestation_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FastSettlementBatchInput {
    pub epoch_id: String,
    pub quote_ids: Vec<String>,
    pub operator_commitment: String,
    pub settlement_lane_root: String,
    pub aggregate_receipt_root: String,
    pub aggregate_storage_root: String,
    pub aggregate_settlement_fee_ledger_root: String,
    pub batch_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementTrackInput {
    pub batch_id: String,
    pub epoch_id: String,
    pub settlement_lane_root: String,
    pub pre_settlement_root: String,
    pub post_settlement_root: String,
    pub receipt_count: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub track_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementFeeLedgerEntryInput {
    pub settlement_track_id: String,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub settlement_rebate_note_commitment: String,
    pub fee_delta_commitment_root: String,
    pub accounting_delta_root: String,
    pub receipt_count: u64,
    pub storage_keys_touched: u64,
    pub gross_micro_fee: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub ledger_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementEpoch {
    pub epoch_id: String,
    pub lane: SettlementLane,
    pub status: SettlementEpochStatus,
    pub source_namespace_root: String,
    pub target_namespace_root: String,
    pub eligible_contract_set_root: String,
    pub settlement_committee_root: String,
    pub liquidity_reserve_set_root: String,
    pub target_receipt_bytes: u64,
    pub target_storage_keys: u64,
    pub min_settlement_micro_fee: u64,
    pub privacy_set_size: u64,
    pub pq_policy_root: String,
    pub opened_height: u64,
    pub instruction_deadline_height: u64,
    pub fast_instruction_deadline_height: u64,
}

impl SettlementEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "lane": self.lane.as_str(),
            "status": self.status,
            "source_namespace_root": self.source_namespace_root,
            "target_namespace_root": self.target_namespace_root,
            "eligible_contract_set_root": self.eligible_contract_set_root,
            "settlement_committee_root": self.settlement_committee_root,
            "liquidity_reserve_set_root": self.liquidity_reserve_set_root,
            "target_receipt_bytes": self.target_receipt_bytes,
            "target_storage_keys": self.target_storage_keys,
            "min_settlement_micro_fee": self.min_settlement_micro_fee,
            "privacy_set_size": self.privacy_set_size,
            "pq_policy_root": self.pq_policy_root,
            "opened_height": self.opened_height,
            "instruction_deadline_height": self.instruction_deadline_height,
            "fast_instruction_deadline_height": self.fast_instruction_deadline_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-EPOCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementNettingSet {
    pub netting_set_id: String,
    pub epoch_id: String,
    pub netting_set_kind: SettlementNettingSetKind,
    pub source_contract_commitment: String,
    pub target_contract_commitment: String,
    pub source_storage_root: String,
    pub target_storage_root: String,
    pub fee_asset_commitment: String,
    pub liquidity_reserve_root: String,
    pub max_hops_from_source: u8,
    pub netting_set_weight_bps: u64,
    pub opened_height: u64,
}

impl SettlementNettingSet {
    pub fn public_record(&self) -> Value {
        json!({
            "netting_set_id": self.netting_set_id,
            "epoch_id": self.epoch_id,
            "netting_set_kind": self.netting_set_kind.as_str(),
            "source_contract_commitment": self.source_contract_commitment,
            "target_contract_commitment": self.target_contract_commitment,
            "source_storage_root": self.source_storage_root,
            "target_storage_root": self.target_storage_root,
            "fee_asset_commitment": self.fee_asset_commitment,
            "liquidity_reserve_root": self.liquidity_reserve_root,
            "max_hops_from_source": self.max_hops_from_source,
            "netting_set_weight_bps": self.netting_set_weight_bps,
            "opened_height": self.opened_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-NETTING-SET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedSettlementReceipt {
    pub receipt_id: String,
    pub epoch_id: String,
    pub status: SealedSettlementReceiptStatus,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub sealed_receipt_root: String,
    pub encrypted_storage_delta_root: String,
    pub settlement_reserve_root: String,
    pub replay_nullifier_root: String,
    pub quoted_micro_fee: u64,
    pub max_micro_fee: u64,
    pub receipt_bytes_upper_bound: u64,
    pub storage_keys_upper_bound: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl SealedSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "epoch_id": self.epoch_id,
            "status": self.status,
            "contract_commitment": self.contract_commitment,
            "payer_note_commitment": self.payer_note_commitment,
            "sealed_receipt_root": self.sealed_receipt_root,
            "encrypted_storage_delta_root": self.encrypted_storage_delta_root,
            "settlement_reserve_root": self.settlement_reserve_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "quoted_micro_fee": self.quoted_micro_fee,
            "max_micro_fee": self.max_micro_fee,
            "receipt_bytes_upper_bound": self.receipt_bytes_upper_bound,
            "storage_keys_upper_bound": self.storage_keys_upper_bound,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SEALED-SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettingInstruction {
    pub instruction_id: String,
    pub epoch_id: String,
    pub status: NettingInstructionStatus,
    pub receipt_ids: Vec<String>,
    pub settlement_netting_set_ids: Vec<String>,
    pub aggregate_position_commitment_root: String,
    pub aggregate_fee_delta_root: String,
    pub settlement_lane_root: String,
    pub privacy_witness_root: String,
    pub created_height: u64,
}

impl NettingInstruction {
    pub fn public_record(&self) -> Value {
        json!({
            "instruction_id": self.instruction_id,
            "epoch_id": self.epoch_id,
            "status": self.status,
            "receipt_ids_root": string_list_root("INTENT-RECEIPT-IDS", &self.receipt_ids),
            "settlement_netting_set_ids_root": string_list_root("INSTRUCTION-NETTING-SET-IDS", &self.settlement_netting_set_ids),
            "aggregate_position_commitment_root": self.aggregate_position_commitment_root,
            "aggregate_fee_delta_root": self.aggregate_fee_delta_root,
            "settlement_lane_root": self.settlement_lane_root,
            "privacy_witness_root": self.privacy_witness_root,
            "created_height": self.created_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-INSTRUCTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LiquidityReserve {
    pub reserve_id: String,
    pub epoch_id: String,
    pub settlement_netting_set_id: String,
    pub sponsor_commitment: String,
    pub liquidity_commitment_root: String,
    pub low_fee_curve_root: String,
    pub rebate_commitment_root: String,
    pub available_liquidity_bucket: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl LiquidityReserve {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "epoch_id": self.epoch_id,
            "settlement_netting_set_id": self.settlement_netting_set_id,
            "sponsor_commitment": self.sponsor_commitment,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "low_fee_curve_root": self.low_fee_curve_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "available_liquidity_bucket": self.available_liquidity_bucket,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("LIQUIDITY-RESERVE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementQuote {
    pub quote_id: String,
    pub epoch_id: String,
    pub instruction_id: String,
    pub status: SettlementQuoteStatus,
    pub liquidity_reserve_ids: Vec<String>,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub sealed_settlement_receipt_batch_root: String,
    pub netted_fee_delta_root: String,
    pub quote_price_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub gross_micro_fee: u64,
    pub estimated_net_micro_fee: u64,
    pub estimated_rebate_micro_fee: u64,
    pub proposed_height: u64,
}

impl SettlementQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "epoch_id": self.epoch_id,
            "instruction_id": self.instruction_id,
            "status": self.status,
            "liquidity_reserve_ids_root": string_list_root("QUOTE-LIQUIDITY-RESERVE-IDS", &self.liquidity_reserve_ids),
            "pre_storage_root": self.pre_storage_root,
            "post_storage_root": self.post_storage_root,
            "sealed_settlement_receipt_batch_root": self.sealed_settlement_receipt_batch_root,
            "netted_fee_delta_root": self.netted_fee_delta_root,
            "quote_price_root": self.quote_price_root,
            "receipt_bytes": self.receipt_bytes,
            "storage_keys_touched": self.storage_keys_touched,
            "gross_micro_fee": self.gross_micro_fee,
            "estimated_net_micro_fee": self.estimated_net_micro_fee,
            "estimated_rebate_micro_fee": self.estimated_rebate_micro_fee,
            "proposed_height": self.proposed_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-QUOTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementAttestation {
    pub attestation_id: String,
    pub quote_id: String,
    pub role: SettlementAttestationRole,
    pub status: SettlementAttestationStatus,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_settlement_root: String,
    pub attested_receipt_root: String,
    pub attested_storage_root: String,
    pub pq_public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub attested_height: u64,
    pub expires_height: u64,
}

impl SettlementAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "quote_id": self.quote_id,
            "role": self.role.as_str(),
            "status": self.status,
            "committee_id": self.committee_id,
            "signer_set_root": self.signer_set_root,
            "attested_settlement_root": self.attested_settlement_root,
            "attested_receipt_root": self.attested_receipt_root,
            "attested_storage_root": self.attested_storage_root,
            "pq_public_key_digest": self.pq_public_key_digest,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "attested_height": self.attested_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayLock {
    pub replay_lock_id: String,
    pub epoch_id: String,
    pub receipt_id: String,
    pub replay_nullifier_root: String,
    pub status: ReplayLockStatus,
    pub reserved_height: u64,
    pub expires_height: u64,
}

impl ReplayLock {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_lock_id": self.replay_lock_id,
            "epoch_id": self.epoch_id,
            "receipt_id": self.receipt_id,
            "replay_nullifier_root": self.replay_nullifier_root,
            "status": self.status,
            "reserved_height": self.reserved_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("REPLAY-GUARD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FastSettlementBatch {
    pub batch_id: String,
    pub epoch_id: String,
    pub quote_ids: Vec<String>,
    pub status: FastSettlementBatchStatus,
    pub operator_commitment: String,
    pub settlement_lane_root: String,
    pub aggregate_receipt_root: String,
    pub aggregate_storage_root: String,
    pub aggregate_settlement_fee_ledger_root: String,
    pub total_receipt_bytes: u64,
    pub total_storage_keys: u64,
    pub total_net_micro_fee: u64,
    pub finalized_height: u64,
}

impl FastSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "quote_ids_root": string_list_root("FAST-SETTLEMENT-BATCH-QUOTE-IDS", &self.quote_ids),
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "settlement_lane_root": self.settlement_lane_root,
            "aggregate_receipt_root": self.aggregate_receipt_root,
            "aggregate_storage_root": self.aggregate_storage_root,
            "aggregate_settlement_fee_ledger_root": self.aggregate_settlement_fee_ledger_root,
            "total_receipt_bytes": self.total_receipt_bytes,
            "total_storage_keys": self.total_storage_keys,
            "total_net_micro_fee": self.total_net_micro_fee,
            "finalized_height": self.finalized_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FAST-SETTLEMENT-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementTrack {
    pub settlement_track_id: String,
    pub batch_id: String,
    pub epoch_id: String,
    pub settlement_lane_root: String,
    pub pre_settlement_root: String,
    pub post_settlement_root: String,
    pub status: SettlementTrackStatus,
    pub receipt_count: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub opened_height: u64,
}

impl SettlementTrack {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_track_id": self.settlement_track_id,
            "batch_id": self.batch_id,
            "epoch_id": self.epoch_id,
            "settlement_lane_root": self.settlement_lane_root,
            "pre_settlement_root": self.pre_settlement_root,
            "post_settlement_root": self.post_settlement_root,
            "status": self.status,
            "receipt_count": self.receipt_count,
            "net_micro_fee": self.net_micro_fee,
            "rebate_micro_fee": self.rebate_micro_fee,
            "opened_height": self.opened_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-TRACK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementFeeLedgerEntry {
    pub ledger_entry_id: String,
    pub settlement_track_id: String,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub settlement_rebate_note_commitment: String,
    pub fee_delta_commitment_root: String,
    pub accounting_delta_root: String,
    pub receipt_count: u64,
    pub storage_keys_touched: u64,
    pub gross_micro_fee: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub appended_height: u64,
}

impl SettlementFeeLedgerEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "ledger_entry_id": self.ledger_entry_id,
            "settlement_track_id": self.settlement_track_id,
            "contract_commitment": self.contract_commitment,
            "payer_note_commitment": self.payer_note_commitment,
            "settlement_rebate_note_commitment": self.settlement_rebate_note_commitment,
            "fee_delta_commitment_root": self.fee_delta_commitment_root,
            "accounting_delta_root": self.accounting_delta_root,
            "receipt_count": self.receipt_count,
            "storage_keys_touched": self.storage_keys_touched,
            "gross_micro_fee": self.gross_micro_fee,
            "net_micro_fee": self.net_micro_fee,
            "rebate_micro_fee": self.rebate_micro_fee,
            "appended_height": self.appended_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FEE-LEDGER-ENTRY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub current_epoch: u64,
    pub settlement_epochs: BTreeMap<String, SettlementEpoch>,
    pub settlement_netting_sets: BTreeMap<String, SettlementNettingSet>,
    pub sealed_receipts: BTreeMap<String, SealedSettlementReceipt>,
    pub netting_instructions: BTreeMap<String, NettingInstruction>,
    pub liquidity_reserves: BTreeMap<String, LiquidityReserve>,
    pub settlement_quotes: BTreeMap<String, SettlementQuote>,
    pub settlement_attestations: BTreeMap<String, SettlementAttestation>,
    pub replay_locks: BTreeMap<String, ReplayLock>,
    pub fast_batches: BTreeMap<String, FastSettlementBatch>,
    pub settlement_tracks: BTreeMap<String, SettlementTrack>,
    pub settlement_fee_ledger_entries: BTreeMap<String, SettlementFeeLedgerEntry>,
    pub consumed_replay_nullifier_roots: BTreeSet<String>,
    pub policy_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: DEVNET_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            settlement_epochs: BTreeMap::new(),
            settlement_netting_sets: BTreeMap::new(),
            sealed_receipts: BTreeMap::new(),
            netting_instructions: BTreeMap::new(),
            liquidity_reserves: BTreeMap::new(),
            settlement_quotes: BTreeMap::new(),
            settlement_attestations: BTreeMap::new(),
            replay_locks: BTreeMap::new(),
            fast_batches: BTreeMap::new(),
            settlement_tracks: BTreeMap::new(),
            settlement_fee_ledger_entries: BTreeMap::new(),
            consumed_replay_nullifier_roots: BTreeSet::new(),
            policy_roots: BTreeSet::new(),
        };
        state.policy_roots.insert(state.policy_root());
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state =
            Self::new(Config::devnet()).expect("devnet netting settlement config is valid");
        let epoch_id = state
            .open_settlement_epoch(SettlementEpochInput {
                lane: SettlementLane::DefiSettlement,
                source_namespace_root: "storage:namespace:root:private-dex-source".to_string(),
                target_namespace_root: "storage:namespace:root:private-dex-target".to_string(),
                eligible_contract_set_root: "contract:set:root:settlement-eligible-defi"
                    .to_string(),
                settlement_committee_root: "committee:root:pq-netting-settlement-devnet"
                    .to_string(),
                liquidity_reserve_set_root: "liquidity:reserve:set:root:devnet-settlement"
                    .to_string(),
                target_receipt_bytes: 393_216,
                target_storage_keys: 49_152,
                min_settlement_micro_fee: 1,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                pq_policy_root: state.policy_root(),
                epoch_nonce: 1,
            })
            .expect("devnet settlement epoch opens");
        let netting_set_id = state
            .register_settlement_netting_set(SettlementNettingSetInput {
                epoch_id: epoch_id.clone(),
                netting_set_kind: SettlementNettingSetKind::LocalNetting,
                source_contract_commitment: "contract:commitment:private-dex-settlement"
                    .to_string(),
                target_contract_commitment: "contract:commitment:private-dex-vault".to_string(),
                source_storage_root: "storage:root:private-dex-settlement:before".to_string(),
                target_storage_root: "storage:root:private-dex-vault:before".to_string(),
                fee_asset_commitment: "asset:commitment:piconero-devnet".to_string(),
                liquidity_reserve_root: "liquidity:reserve:root:local-netting".to_string(),
                max_hops_from_source: 1,
                netting_set_weight_bps: 8_500,
                netting_set_nonce: 1,
            })
            .expect("devnet settlement netting_set registers");
        let receipt_id = state
            .submit_sealed_settlement_receipt(SealedSettlementReceiptInput {
                epoch_id: epoch_id.clone(),
                contract_commitment: "contract:commitment:private-dex-settlement".to_string(),
                payer_note_commitment: "note:commitment:settlement-fee-payer:001".to_string(),
                sealed_receipt_root: "sealed:receipt:root:settlement:ml-kem:001".to_string(),
                encrypted_storage_delta_root: "encrypted:storage-delta:root:settlement:001"
                    .to_string(),
                settlement_reserve_root: "settlement:reserve:root:local-netting:001".to_string(),
                replay_nullifier_root: "nullifier:root:netting-settlement:001".to_string(),
                max_micro_fee: 3,
                receipt_bytes_upper_bound: 98_304,
                storage_keys_upper_bound: 12_288,
                receipt_nonce: 1,
            })
            .expect("devnet sealed settlement receipt accepts");
        let instruction_id = state
            .bind_netting_instruction(NettingInstructionInput {
                epoch_id: epoch_id.clone(),
                receipt_ids: vec![receipt_id.clone()],
                settlement_netting_set_ids: vec![netting_set_id.clone()],
                aggregate_position_commitment_root: "position:commitment:root:settlement:001"
                    .to_string(),
                aggregate_fee_delta_root: "fee:delta:root:settlement:001".to_string(),
                settlement_lane_root: "settlement:lane:root:fast-settlement:001".to_string(),
                privacy_witness_root: "privacy:witness:root:settlement:001".to_string(),
                instruction_nonce: 1,
            })
            .expect("devnet instruction binds");
        let reserve_id = state
            .register_liquidity_reserve(LiquidityReserveInput {
                epoch_id: epoch_id.clone(),
                settlement_netting_set_id: netting_set_id,
                sponsor_commitment: "sponsor:commitment:settlement:devnet:001".to_string(),
                liquidity_commitment_root: "liquidity:commitment:root:settlement:001".to_string(),
                low_fee_curve_root: "low-fee:curve:root:settlement:001".to_string(),
                rebate_commitment_root: "rebate:commitment:root:settlement:001".to_string(),
                available_liquidity_bucket: 64,
                expires_height: DEVNET_HEIGHT + 64,
                reserve_nonce: 1,
            })
            .expect("devnet liquidity reserve registers");
        let quote_id = state
            .propose_settlement_quote(SettlementQuoteInput {
                epoch_id: epoch_id.clone(),
                instruction_id: instruction_id.clone(),
                liquidity_reserve_ids: vec![reserve_id],
                pre_storage_root: "storage:root:aggregate:settlement:before".to_string(),
                post_storage_root: "storage:root:aggregate:settlement:after".to_string(),
                sealed_settlement_receipt_batch_root: "receipt:batch:root:settlement:001"
                    .to_string(),
                netted_fee_delta_root: "netted:fee:delta:root:settlement:001".to_string(),
                quote_price_root: "quote:price:root:low-fee-settlement:001".to_string(),
                receipt_bytes: 49_152,
                storage_keys_touched: 4_096,
                gross_micro_fee: 3,
                quote_nonce: 1,
            })
            .expect("devnet quote proposes");
        let _epochner = state
            .attest_settlement_quote(SettlementAttestationInput {
                quote_id: quote_id.clone(),
                role: SettlementAttestationRole::SettlementEpochner,
                committee_id: "committee:pq-settlement-epochners:devnet:01".to_string(),
                signer_set_root: "signer:set:root:settlement-epochners:01".to_string(),
                attested_settlement_root: "settlement:root:attested:settlement:001".to_string(),
                attested_receipt_root: "receipt:batch:root:settlement:001".to_string(),
                attested_storage_root: "storage:root:aggregate:settlement:after".to_string(),
                pq_public_key_digest: "pq-key:digest:settlement-epochner:001".to_string(),
                pq_signature_root: "pq-signature:root:settlement-epochner:001".to_string(),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                quorum_weight_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
                attestation_nonce: 1,
            })
            .expect("devnet epochner attests");
        let _verifier = state
            .attest_settlement_quote(SettlementAttestationInput {
                quote_id: quote_id.clone(),
                role: SettlementAttestationRole::ReceiptVerifier,
                committee_id: "committee:pq-settlement-verifiers:devnet:01".to_string(),
                signer_set_root: "signer:set:root:settlement-verifiers:01".to_string(),
                attested_settlement_root: "settlement:root:attested:settlement:001".to_string(),
                attested_receipt_root: "receipt:batch:root:settlement:001".to_string(),
                attested_storage_root: "storage:root:aggregate:settlement:after".to_string(),
                pq_public_key_digest: "pq-key:digest:settlement-verifier:001".to_string(),
                pq_signature_root: "pq-signature:root:settlement-verifier:001".to_string(),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                quorum_weight_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
                attestation_nonce: 2,
            })
            .expect("devnet verifier attests");
        let batch_id = state
            .finalize_fast_settlement_batch(FastSettlementBatchInput {
                epoch_id: epoch_id.clone(),
                quote_ids: vec![quote_id],
                operator_commitment: "operator:commitment:fast-settlement:001".to_string(),
                settlement_lane_root: "settlement:lane:root:fast-settlement:001".to_string(),
                aggregate_receipt_root: "receipt:aggregate:root:fast-settlement:001".to_string(),
                aggregate_storage_root: "storage:aggregate:root:fast-settlement:001".to_string(),
                aggregate_settlement_fee_ledger_root:
                    "fee-ledger:aggregate:root:fast-settlement:001".to_string(),
                batch_nonce: 1,
            })
            .expect("devnet fast batch finalizes");
        let track_id = state
            .open_settlement_track(SettlementTrackInput {
                batch_id,
                epoch_id,
                settlement_lane_root: "settlement:lane:root:fast-settlement:001".to_string(),
                pre_settlement_root: "settlement:root:before:settlement:001".to_string(),
                post_settlement_root: "settlement:root:after:settlement:001".to_string(),
                receipt_count: 1,
                net_micro_fee: 2,
                rebate_micro_fee: 1,
                track_nonce: 1,
            })
            .expect("devnet settlement track opens");
        let _ledger = state
            .append_settlement_fee_ledger_entry(SettlementFeeLedgerEntryInput {
                settlement_track_id: track_id,
                contract_commitment: "contract:commitment:private-dex-settlement".to_string(),
                payer_note_commitment: "note:commitment:settlement-fee-payer:001".to_string(),
                settlement_rebate_note_commitment: "note:commitment:settlement-rebate:001"
                    .to_string(),
                fee_delta_commitment_root: "fee:delta:commitment:root:settlement:001".to_string(),
                accounting_delta_root: "accounting:delta:root:settlement:001".to_string(),
                receipt_count: 1,
                storage_keys_touched: 4_096,
                gross_micro_fee: 3,
                net_micro_fee: 2,
                rebate_micro_fee: 1,
                ledger_nonce: 1,
            })
            .expect("devnet ledger appends");
        state
    }

    pub fn advance_height(&mut self, new_height: u64) -> Result<String> {
        if new_height < self.current_height {
            return Err("new height cannot be below current height".to_string());
        }
        self.current_height = new_height;
        self.current_epoch = self.current_height / 512;
        self.expire_stale_records();
        self.recompute_roots();
        Ok(self.state_root())
    }

    pub fn open_settlement_epoch(&mut self, input: SettlementEpochInput) -> Result<String> {
        require_non_empty("source_namespace_root", &input.source_namespace_root)?;
        require_non_empty("target_namespace_root", &input.target_namespace_root)?;
        require_non_empty(
            "eligible_contract_set_root",
            &input.eligible_contract_set_root,
        )?;
        require_non_empty(
            "settlement_committee_root",
            &input.settlement_committee_root,
        )?;
        require_non_empty(
            "liquidity_reserve_set_root",
            &input.liquidity_reserve_set_root,
        )?;
        require_non_empty("pq_policy_root", &input.pq_policy_root)?;
        if input.target_receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("target receipt bytes exceed settlement batch limit".to_string());
        }
        if input.target_storage_keys > self.config.max_storage_keys_per_receipt {
            return Err("target storage keys exceed settlement receipt limit".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set size below settlement minimum".to_string());
        }
        let epoch_id = settlement_epoch_id(
            input.lane,
            &input.source_namespace_root,
            &input.target_namespace_root,
            &input.settlement_committee_root,
            input.epoch_nonce,
        );
        if self.settlement_epochs.contains_key(&epoch_id) {
            return Err("settlement epoch already exists".to_string());
        }
        let epoch = SettlementEpoch {
            epoch_id: epoch_id.clone(),
            lane: input.lane,
            status: SettlementEpochStatus::AcceptingReceipts,
            source_namespace_root: input.source_namespace_root,
            target_namespace_root: input.target_namespace_root,
            eligible_contract_set_root: input.eligible_contract_set_root,
            settlement_committee_root: input.settlement_committee_root,
            liquidity_reserve_set_root: input.liquidity_reserve_set_root,
            target_receipt_bytes: input.target_receipt_bytes,
            target_storage_keys: input.target_storage_keys,
            min_settlement_micro_fee: input
                .min_settlement_micro_fee
                .max(self.config.min_micro_fee),
            privacy_set_size: input.privacy_set_size,
            pq_policy_root: input.pq_policy_root,
            opened_height: self.current_height,
            instruction_deadline_height: self
                .current_height
                .saturating_add(self.config.settlement_window_blocks),
            fast_instruction_deadline_height: self
                .current_height
                .saturating_add(self.config.settlement_window_blocks)
                .saturating_add(self.config.fast_settlement_blocks),
        };
        self.settlement_epochs.insert(epoch_id.clone(), epoch);
        self.counters.settlement_epochs_opened =
            self.counters.settlement_epochs_opened.saturating_add(1);
        self.recompute_roots();
        Ok(epoch_id)
    }

    pub fn register_settlement_netting_set(
        &mut self,
        input: SettlementNettingSetInput,
    ) -> Result<String> {
        self.ensure_epoch_accepts_settlements(&input.epoch_id)?;
        require_non_empty(
            "source_contract_commitment",
            &input.source_contract_commitment,
        )?;
        require_non_empty(
            "target_contract_commitment",
            &input.target_contract_commitment,
        )?;
        require_non_empty("source_storage_root", &input.source_storage_root)?;
        require_non_empty("target_storage_root", &input.target_storage_root)?;
        require_non_empty("fee_asset_commitment", &input.fee_asset_commitment)?;
        require_non_empty("liquidity_reserve_root", &input.liquidity_reserve_root)?;
        if input.max_hops_from_source == 0
            || input.max_hops_from_source > self.config.max_netting_set_hops
        {
            return Err("settlement netting_set hop count exceeds settlement policy".to_string());
        }
        if input.netting_set_weight_bps > MAX_BPS {
            return Err("settlement netting_set weight exceeds MAX_BPS".to_string());
        }
        if self.settlement_netting_sets_for_epoch(&input.epoch_id)
            >= self.config.max_settlement_netting_sets
        {
            return Err("settlement netting_set limit reached".to_string());
        }
        let netting_set_id = settlement_netting_set_id(
            &input.epoch_id,
            input.netting_set_kind,
            &input.source_contract_commitment,
            &input.target_contract_commitment,
            input.netting_set_nonce,
        );
        if self.settlement_netting_sets.contains_key(&netting_set_id) {
            return Err("settlement netting_set already exists".to_string());
        }
        let netting_set = SettlementNettingSet {
            netting_set_id: netting_set_id.clone(),
            epoch_id: input.epoch_id,
            netting_set_kind: input.netting_set_kind,
            source_contract_commitment: input.source_contract_commitment,
            target_contract_commitment: input.target_contract_commitment,
            source_storage_root: input.source_storage_root,
            target_storage_root: input.target_storage_root,
            fee_asset_commitment: input.fee_asset_commitment,
            liquidity_reserve_root: input.liquidity_reserve_root,
            max_hops_from_source: input.max_hops_from_source,
            netting_set_weight_bps: input.netting_set_weight_bps,
            opened_height: self.current_height,
        };
        self.settlement_netting_sets
            .insert(netting_set_id.clone(), netting_set);
        self.counters.settlement_netting_sets_registered = self
            .counters
            .settlement_netting_sets_registered
            .saturating_add(1);
        self.recompute_roots();
        Ok(netting_set_id)
    }

    pub fn submit_sealed_settlement_receipt(
        &mut self,
        input: SealedSettlementReceiptInput,
    ) -> Result<String> {
        let lane = self.ensure_epoch_accepts_receipts(&input.epoch_id)?;
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("payer_note_commitment", &input.payer_note_commitment)?;
        require_non_empty("sealed_receipt_root", &input.sealed_receipt_root)?;
        require_non_empty(
            "encrypted_storage_delta_root",
            &input.encrypted_storage_delta_root,
        )?;
        require_non_empty("settlement_reserve_root", &input.settlement_reserve_root)?;
        require_non_empty("replay_nullifier_root", &input.replay_nullifier_root)?;
        if self
            .consumed_replay_nullifier_roots
            .contains(&input.replay_nullifier_root)
        {
            self.counters.duplicate_receipts_rejected =
                self.counters.duplicate_receipts_rejected.saturating_add(1);
            return Err("replay nullifier already consumed".to_string());
        }
        if input.receipt_bytes_upper_bound > self.config.max_receipt_bytes_per_batch {
            return Err("receipt bytes exceed settlement limit".to_string());
        }
        if input.storage_keys_upper_bound > self.config.max_storage_keys_per_receipt {
            return Err("storage keys exceed settlement receipt limit".to_string());
        }
        let receipt_id = sealed_settlement_receipt_id(
            &input.epoch_id,
            &input.contract_commitment,
            &input.sealed_receipt_root,
            input.receipt_nonce,
        );
        if self.sealed_receipts.contains_key(&receipt_id) {
            self.counters.duplicate_receipts_rejected =
                self.counters.duplicate_receipts_rejected.saturating_add(1);
            return Err("sealed settlement receipt already exists".to_string());
        }
        let quoted_micro_fee = estimate_settlement_micro_fee(
            &self.config,
            lane,
            input.max_micro_fee,
            input.receipt_bytes_upper_bound,
            1,
        );
        let receipt = SealedSettlementReceipt {
            receipt_id: receipt_id.clone(),
            epoch_id: input.epoch_id.clone(),
            status: SealedSettlementReceiptStatus::ReplayLocked,
            contract_commitment: input.contract_commitment,
            payer_note_commitment: input.payer_note_commitment,
            sealed_receipt_root: input.sealed_receipt_root,
            encrypted_storage_delta_root: input.encrypted_storage_delta_root,
            settlement_reserve_root: input.settlement_reserve_root,
            replay_nullifier_root: input.replay_nullifier_root.clone(),
            quoted_micro_fee,
            max_micro_fee: input.max_micro_fee,
            receipt_bytes_upper_bound: input.receipt_bytes_upper_bound,
            storage_keys_upper_bound: input.storage_keys_upper_bound,
            submitted_height: self.current_height,
            expires_height: self
                .current_height
                .saturating_add(self.config.replay_window_blocks),
        };
        let replay_lock_id = replay_lock_id(
            &input.epoch_id,
            &receipt_id,
            &input.replay_nullifier_root,
            input.receipt_nonce,
        );
        let lock = ReplayLock {
            replay_lock_id: replay_lock_id.clone(),
            epoch_id: input.epoch_id,
            receipt_id: receipt_id.clone(),
            replay_nullifier_root: input.replay_nullifier_root.clone(),
            status: ReplayLockStatus::Armed,
            reserved_height: self.current_height,
            expires_height: self
                .current_height
                .saturating_add(self.config.replay_window_blocks),
        };
        self.consumed_replay_nullifier_roots
            .insert(input.replay_nullifier_root);
        self.sealed_receipts.insert(receipt_id.clone(), receipt);
        self.replay_locks.insert(replay_lock_id, lock);
        self.counters.sealed_receipts_submitted =
            self.counters.sealed_receipts_submitted.saturating_add(1);
        self.counters.replay_locks_consumed = self.counters.replay_locks_consumed.saturating_add(1);
        self.counters.total_receipt_bytes_settled = self
            .counters
            .total_receipt_bytes_settled
            .saturating_add(input.receipt_bytes_upper_bound);
        self.counters.total_storage_keys_settled = self
            .counters
            .total_storage_keys_settled
            .saturating_add(input.storage_keys_upper_bound);
        self.recompute_roots();
        Ok(receipt_id)
    }

    pub fn bind_netting_instruction(&mut self, input: NettingInstructionInput) -> Result<String> {
        self.ensure_epoch_exists(&input.epoch_id)?;
        require_non_empty(
            "aggregate_position_commitment_root",
            &input.aggregate_position_commitment_root,
        )?;
        require_non_empty("aggregate_fee_delta_root", &input.aggregate_fee_delta_root)?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("privacy_witness_root", &input.privacy_witness_root)?;
        if input.receipt_ids.is_empty() {
            return Err("netting instruction requires at least one receipt".to_string());
        }
        if input.settlement_netting_set_ids.is_empty() {
            return Err(
                "netting instruction requires at least one settlement netting_set".to_string(),
            );
        }
        if self.instructions_for_epoch(&input.epoch_id) >= self.config.max_instructions_per_epoch {
            return Err("netting instruction limit reached".to_string());
        }
        for receipt_id in &input.receipt_ids {
            let receipt = self
                .sealed_receipts
                .get(receipt_id)
                .ok_or_else(|| "unknown sealed settlement receipt".to_string())?;
            if receipt.epoch_id != input.epoch_id {
                return Err("sealed settlement receipt belongs to a different epoch".to_string());
            }
            if !receipt.status.routable() {
                return Err("sealed settlement receipt is not routable".to_string());
            }
        }
        for netting_set_id in &input.settlement_netting_set_ids {
            let netting_set = self
                .settlement_netting_sets
                .get(netting_set_id)
                .ok_or_else(|| "unknown settlement netting_set".to_string())?;
            if netting_set.epoch_id != input.epoch_id {
                return Err("settlement netting_set belongs to a different epoch".to_string());
            }
        }
        let instruction_id = netting_instruction_id(
            &input.epoch_id,
            &input.aggregate_position_commitment_root,
            &input.aggregate_fee_delta_root,
            input.instruction_nonce,
        );
        if self.netting_instructions.contains_key(&instruction_id) {
            return Err("netting instruction already exists".to_string());
        }
        for receipt_id in &input.receipt_ids {
            if let Some(receipt) = self.sealed_receipts.get_mut(receipt_id) {
                receipt.status = SealedSettlementReceiptStatus::InstructionBound;
            }
        }
        if let Some(epoch) = self.settlement_epochs.get_mut(&input.epoch_id) {
            epoch.status = SettlementEpochStatus::Routing;
        }
        let instruction = NettingInstruction {
            instruction_id: instruction_id.clone(),
            epoch_id: input.epoch_id,
            status: NettingInstructionStatus::SettlementLocked,
            receipt_ids: input.receipt_ids,
            settlement_netting_set_ids: input.settlement_netting_set_ids,
            aggregate_position_commitment_root: input.aggregate_position_commitment_root,
            aggregate_fee_delta_root: input.aggregate_fee_delta_root,
            settlement_lane_root: input.settlement_lane_root,
            privacy_witness_root: input.privacy_witness_root,
            created_height: self.current_height,
        };
        self.netting_instructions
            .insert(instruction_id.clone(), instruction);
        self.counters.netting_instructions_bound =
            self.counters.netting_instructions_bound.saturating_add(1);
        self.recompute_roots();
        Ok(instruction_id)
    }

    pub fn register_liquidity_reserve(&mut self, input: LiquidityReserveInput) -> Result<String> {
        self.ensure_epoch_exists(&input.epoch_id)?;
        require_non_empty("sponsor_commitment", &input.sponsor_commitment)?;
        require_non_empty(
            "liquidity_commitment_root",
            &input.liquidity_commitment_root,
        )?;
        require_non_empty("low_fee_curve_root", &input.low_fee_curve_root)?;
        require_non_empty("rebate_commitment_root", &input.rebate_commitment_root)?;
        let netting_set = self
            .settlement_netting_sets
            .get(&input.settlement_netting_set_id)
            .ok_or_else(|| "unknown settlement netting_set".to_string())?;
        if netting_set.epoch_id != input.epoch_id {
            return Err("liquidity reserve netting_set belongs to a different epoch".to_string());
        }
        if input.expires_height <= self.current_height {
            return Err("liquidity reserve must expire in the future".to_string());
        }
        let reserve_id = liquidity_reserve_id(
            &input.epoch_id,
            &input.settlement_netting_set_id,
            &input.sponsor_commitment,
            input.reserve_nonce,
        );
        if self.liquidity_reserves.contains_key(&reserve_id) {
            return Err("liquidity reserve already exists".to_string());
        }
        let reserve = LiquidityReserve {
            reserve_id: reserve_id.clone(),
            epoch_id: input.epoch_id,
            settlement_netting_set_id: input.settlement_netting_set_id,
            sponsor_commitment: input.sponsor_commitment,
            liquidity_commitment_root: input.liquidity_commitment_root,
            low_fee_curve_root: input.low_fee_curve_root,
            rebate_commitment_root: input.rebate_commitment_root,
            available_liquidity_bucket: input.available_liquidity_bucket,
            opened_height: self.current_height,
            expires_height: input.expires_height,
        };
        self.liquidity_reserves.insert(reserve_id.clone(), reserve);
        self.counters.liquidity_reserves_registered = self
            .counters
            .liquidity_reserves_registered
            .saturating_add(1);
        self.recompute_roots();
        Ok(reserve_id)
    }

    pub fn propose_settlement_quote(&mut self, input: SettlementQuoteInput) -> Result<String> {
        let lane = self.ensure_epoch_exists(&input.epoch_id)?;
        require_non_empty("pre_storage_root", &input.pre_storage_root)?;
        require_non_empty("post_storage_root", &input.post_storage_root)?;
        require_non_empty(
            "sealed_settlement_receipt_batch_root",
            &input.sealed_settlement_receipt_batch_root,
        )?;
        require_non_empty("netted_fee_delta_root", &input.netted_fee_delta_root)?;
        require_non_empty("quote_price_root", &input.quote_price_root)?;
        let instruction = self
            .netting_instructions
            .get(&input.instruction_id)
            .ok_or_else(|| "unknown netting instruction".to_string())?;
        if instruction.epoch_id != input.epoch_id {
            return Err("netting instruction belongs to a different epoch".to_string());
        }
        if input.liquidity_reserve_ids.is_empty() {
            return Err("settlement quote requires liquidity reserve coverage".to_string());
        }
        if self.quotes_for_epoch(&input.epoch_id) >= self.config.max_quotes_per_epoch {
            return Err("settlement quote limit reached".to_string());
        }
        if input.receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("settlement quote receipt bytes exceed batch limit".to_string());
        }
        if input.storage_keys_touched > self.config.max_storage_keys_per_receipt {
            return Err("settlement quote storage keys exceed receipt limit".to_string());
        }
        for reserve_id in &input.liquidity_reserve_ids {
            let reserve = self
                .liquidity_reserves
                .get(reserve_id)
                .ok_or_else(|| "unknown liquidity reserve".to_string())?;
            if reserve.epoch_id != input.epoch_id {
                return Err("liquidity reserve belongs to a different epoch".to_string());
            }
            if reserve.expires_height <= self.current_height {
                return Err("liquidity reserve is expired".to_string());
            }
        }
        let quote_id = settlement_quote_id(
            &input.epoch_id,
            &input.instruction_id,
            &input.netted_fee_delta_root,
            input.quote_nonce,
        );
        if self.settlement_quotes.contains_key(&quote_id) {
            return Err("settlement quote already exists".to_string());
        }
        let netting_hop_count = instruction.settlement_netting_set_ids.len() as u8;
        let estimated_net_micro_fee = estimate_settlement_micro_fee(
            &self.config,
            lane,
            input.gross_micro_fee,
            input.receipt_bytes,
            netting_hop_count.max(1),
        );
        let estimated_rebate_micro_fee = input
            .gross_micro_fee
            .saturating_sub(estimated_net_micro_fee)
            .max(bps(
                input.gross_micro_fee,
                self.config.settlement_rebate_bps,
            ));
        for receipt_id in &instruction.receipt_ids {
            if let Some(receipt) = self.sealed_receipts.get_mut(receipt_id) {
                receipt.status = SealedSettlementReceiptStatus::Quoted;
                receipt.quoted_micro_fee = estimated_net_micro_fee;
            }
        }
        if let Some(instruction) = self.netting_instructions.get_mut(&input.instruction_id) {
            instruction.status = NettingInstructionStatus::QuoteReady;
        }
        if let Some(epoch) = self.settlement_epochs.get_mut(&input.epoch_id) {
            epoch.status = SettlementEpochStatus::Quoting;
        }
        let quote = SettlementQuote {
            quote_id: quote_id.clone(),
            epoch_id: input.epoch_id,
            instruction_id: input.instruction_id,
            status: SettlementQuoteStatus::LiquidityChecked,
            liquidity_reserve_ids: input.liquidity_reserve_ids,
            pre_storage_root: input.pre_storage_root,
            post_storage_root: input.post_storage_root,
            sealed_settlement_receipt_batch_root: input.sealed_settlement_receipt_batch_root,
            netted_fee_delta_root: input.netted_fee_delta_root,
            quote_price_root: input.quote_price_root,
            receipt_bytes: input.receipt_bytes,
            storage_keys_touched: input.storage_keys_touched,
            gross_micro_fee: input.gross_micro_fee,
            estimated_net_micro_fee,
            estimated_rebate_micro_fee,
            proposed_height: self.current_height,
        };
        self.settlement_quotes.insert(quote_id.clone(), quote);
        self.counters.settlement_quotes_proposed =
            self.counters.settlement_quotes_proposed.saturating_add(1);
        self.counters.gross_micro_fees_quoted = self
            .counters
            .gross_micro_fees_quoted
            .saturating_add(input.gross_micro_fee);
        self.recompute_roots();
        Ok(quote_id)
    }

    pub fn attest_settlement_quote(&mut self, input: SettlementAttestationInput) -> Result<String> {
        require_non_empty("committee_id", &input.committee_id)?;
        require_non_empty("signer_set_root", &input.signer_set_root)?;
        require_non_empty("attested_settlement_root", &input.attested_settlement_root)?;
        require_non_empty("attested_receipt_root", &input.attested_receipt_root)?;
        require_non_empty("attested_storage_root", &input.attested_storage_root)?;
        require_non_empty("pq_public_key_digest", &input.pq_public_key_digest)?;
        require_non_empty("pq_signature_root", &input.pq_signature_root)?;
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("settlement attestation below minimum PQ security bits".to_string());
        }
        if input.quorum_weight_bps > MAX_BPS {
            return Err("settlement attestation quorum exceeds MAX_BPS".to_string());
        }
        let quote = self
            .settlement_quotes
            .get_mut(&input.quote_id)
            .ok_or_else(|| "unknown settlement quote".to_string())?;
        if !quote.status.settlement_ready() {
            return Err("settlement quote is not ready for attestation".to_string());
        }
        let attestation_id = settlement_attestation_id(
            &input.quote_id,
            &input.committee_id,
            input.role,
            input.attestation_nonce,
        );
        if self.settlement_attestations.contains_key(&attestation_id) {
            return Err("settlement attestation already exists".to_string());
        }
        quote.status = match input.role {
            SettlementAttestationRole::SettlementEpochner
            | SettlementAttestationRole::NettingExecutor
            | SettlementAttestationRole::LiquidityAuditor => {
                SettlementQuoteStatus::ExecutorAttested
            }
            SettlementAttestationRole::ReceiptVerifier
            | SettlementAttestationRole::PrivacySetAuditor
            | SettlementAttestationRole::Watchtower => SettlementQuoteStatus::VerifierAttested,
        };
        let attestation = SettlementAttestation {
            attestation_id: attestation_id.clone(),
            quote_id: input.quote_id.clone(),
            role: input.role,
            status: SettlementAttestationStatus::Verified,
            committee_id: input.committee_id,
            signer_set_root: input.signer_set_root,
            attested_settlement_root: input.attested_settlement_root,
            attested_receipt_root: input.attested_receipt_root,
            attested_storage_root: input.attested_storage_root,
            pq_public_key_digest: input.pq_public_key_digest,
            pq_signature_root: input.pq_signature_root,
            pq_security_bits: input.pq_security_bits,
            quorum_weight_bps: input.quorum_weight_bps,
            attested_height: self.current_height,
            expires_height: self
                .current_height
                .saturating_add(self.config.replay_window_blocks),
        };
        self.settlement_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.settlement_attestations_recorded = self
            .counters
            .settlement_attestations_recorded
            .saturating_add(1);
        self.refresh_quote_quorum(&input.quote_id);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn finalize_fast_settlement_batch(
        &mut self,
        input: FastSettlementBatchInput,
    ) -> Result<String> {
        self.ensure_epoch_exists(&input.epoch_id)?;
        require_non_empty("operator_commitment", &input.operator_commitment)?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("aggregate_receipt_root", &input.aggregate_receipt_root)?;
        require_non_empty("aggregate_storage_root", &input.aggregate_storage_root)?;
        require_non_empty(
            "aggregate_settlement_fee_ledger_root",
            &input.aggregate_settlement_fee_ledger_root,
        )?;
        if input.quote_ids.is_empty() {
            return Err("fast settlement batch requires quotes".to_string());
        }
        if input.quote_ids.len() > self.config.max_batch_matches {
            return Err("fast settlement batch quote limit exceeded".to_string());
        }
        let mut total_receipt_bytes = 0u64;
        let mut total_storage_keys = 0u64;
        let mut total_net_micro_fee = 0u64;
        for quote_id in &input.quote_ids {
            let quote = self
                .settlement_quotes
                .get(quote_id)
                .ok_or_else(|| "unknown settlement quote".to_string())?;
            if quote.epoch_id != input.epoch_id {
                return Err("settlement quote belongs to a different epoch".to_string());
            }
            if !matches!(
                quote.status,
                SettlementQuoteStatus::QuorumReady
                    | SettlementQuoteStatus::ExecutorAttested
                    | SettlementQuoteStatus::VerifierAttested
            ) {
                return Err("settlement quote lacks PQ quorum".to_string());
            }
            total_receipt_bytes = total_receipt_bytes.saturating_add(quote.receipt_bytes);
            total_storage_keys = total_storage_keys.saturating_add(quote.storage_keys_touched);
            total_net_micro_fee = total_net_micro_fee.saturating_add(quote.estimated_net_micro_fee);
        }
        if total_receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("fast settlement batch exceeds receipt byte limit".to_string());
        }
        let batch_id = fast_settlement_batch_id(
            &input.operator_commitment,
            &input.settlement_lane_root,
            self.current_height,
            input.batch_nonce,
        );
        if self.fast_batches.contains_key(&batch_id) {
            return Err("fast settlement batch already exists".to_string());
        }
        for quote_id in &input.quote_ids {
            if let Some(quote) = self.settlement_quotes.get_mut(quote_id) {
                quote.status = SettlementQuoteStatus::Included;
            }
            if let Some(instruction_id) = self
                .settlement_quotes
                .get(quote_id)
                .map(|quote| quote.instruction_id.clone())
            {
                if let Some(instruction) = self.netting_instructions.get_mut(&instruction_id) {
                    instruction.status = NettingInstructionStatus::FullyNetted;
                    for receipt_id in &instruction.receipt_ids {
                        if let Some(receipt) = self.sealed_receipts.get_mut(receipt_id) {
                            receipt.status = SealedSettlementReceiptStatus::Netted;
                        }
                    }
                }
            }
        }
        if let Some(epoch) = self.settlement_epochs.get_mut(&input.epoch_id) {
            epoch.status = SettlementEpochStatus::FastSettling;
        }
        let batch = FastSettlementBatch {
            batch_id: batch_id.clone(),
            epoch_id: input.epoch_id,
            quote_ids: input.quote_ids,
            status: FastSettlementBatchStatus::FastFinal,
            operator_commitment: input.operator_commitment,
            settlement_lane_root: input.settlement_lane_root,
            aggregate_receipt_root: input.aggregate_receipt_root,
            aggregate_storage_root: input.aggregate_storage_root,
            aggregate_settlement_fee_ledger_root: input.aggregate_settlement_fee_ledger_root,
            total_receipt_bytes,
            total_storage_keys,
            total_net_micro_fee,
            finalized_height: self.current_height,
        };
        self.fast_batches.insert(batch_id.clone(), batch);
        self.counters.fast_batches_finalized =
            self.counters.fast_batches_finalized.saturating_add(1);
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn open_settlement_track(&mut self, input: SettlementTrackInput) -> Result<String> {
        self.ensure_epoch_exists(&input.epoch_id)?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("pre_settlement_root", &input.pre_settlement_root)?;
        require_non_empty("post_settlement_root", &input.post_settlement_root)?;
        let batch = self
            .fast_batches
            .get(&input.batch_id)
            .ok_or_else(|| "unknown fast settlement batch".to_string())?;
        if batch.epoch_id != input.epoch_id {
            return Err("fast settlement batch belongs to a different epoch".to_string());
        }
        let settlement_track_id = settlement_track_id(
            &input.batch_id,
            &input.settlement_lane_root,
            &input.post_settlement_root,
            input.track_nonce,
        );
        if self.settlement_tracks.contains_key(&settlement_track_id) {
            return Err("settlement track already exists".to_string());
        }
        let track = SettlementTrack {
            settlement_track_id: settlement_track_id.clone(),
            batch_id: input.batch_id.clone(),
            epoch_id: input.epoch_id.clone(),
            settlement_lane_root: input.settlement_lane_root,
            pre_settlement_root: input.pre_settlement_root,
            post_settlement_root: input.post_settlement_root,
            status: SettlementTrackStatus::FastFinal,
            receipt_count: input.receipt_count,
            net_micro_fee: input.net_micro_fee,
            rebate_micro_fee: input.rebate_micro_fee,
            opened_height: self.current_height,
        };
        if let Some(batch) = self.fast_batches.get_mut(&input.batch_id) {
            batch.status = FastSettlementBatchStatus::Settled;
        }
        if let Some(epoch) = self.settlement_epochs.get_mut(&input.epoch_id) {
            epoch.status = SettlementEpochStatus::Settled;
        }
        self.settlement_tracks
            .insert(settlement_track_id.clone(), track);
        self.counters.settlement_tracks_opened =
            self.counters.settlement_tracks_opened.saturating_add(1);
        self.counters.receipts_settled = self
            .counters
            .receipts_settled
            .saturating_add(input.receipt_count);
        self.counters.net_micro_fees_settled = self
            .counters
            .net_micro_fees_settled
            .saturating_add(input.net_micro_fee);
        self.counters.rebate_micro_fees_returned = self
            .counters
            .rebate_micro_fees_returned
            .saturating_add(input.rebate_micro_fee);
        self.recompute_roots();
        Ok(settlement_track_id)
    }

    pub fn append_settlement_fee_ledger_entry(
        &mut self,
        input: SettlementFeeLedgerEntryInput,
    ) -> Result<String> {
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("payer_note_commitment", &input.payer_note_commitment)?;
        require_non_empty(
            "settlement_rebate_note_commitment",
            &input.settlement_rebate_note_commitment,
        )?;
        require_non_empty(
            "fee_delta_commitment_root",
            &input.fee_delta_commitment_root,
        )?;
        require_non_empty("accounting_delta_root", &input.accounting_delta_root)?;
        if !self
            .settlement_tracks
            .contains_key(&input.settlement_track_id)
        {
            return Err("unknown settlement track".to_string());
        }
        let ledger_entry_id = settlement_fee_ledger_entry_id(
            &input.settlement_track_id,
            &input.contract_commitment,
            &input.fee_delta_commitment_root,
            input.ledger_nonce,
        );
        if self
            .settlement_fee_ledger_entries
            .contains_key(&ledger_entry_id)
        {
            return Err("fee ledger entry already exists".to_string());
        }
        let entry = SettlementFeeLedgerEntry {
            ledger_entry_id: ledger_entry_id.clone(),
            settlement_track_id: input.settlement_track_id,
            contract_commitment: input.contract_commitment,
            payer_note_commitment: input.payer_note_commitment,
            settlement_rebate_note_commitment: input.settlement_rebate_note_commitment,
            fee_delta_commitment_root: input.fee_delta_commitment_root,
            accounting_delta_root: input.accounting_delta_root,
            receipt_count: input.receipt_count,
            storage_keys_touched: input.storage_keys_touched,
            gross_micro_fee: input.gross_micro_fee,
            net_micro_fee: input.net_micro_fee,
            rebate_micro_fee: input.rebate_micro_fee,
            appended_height: self.current_height,
        };
        self.settlement_fee_ledger_entries
            .insert(ledger_entry_id.clone(), entry);
        self.counters.settlement_fee_ledger_entries_appended = self
            .counters
            .settlement_fee_ledger_entries_appended
            .saturating_add(1);
        self.recompute_roots();
        Ok(ledger_entry_id)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            settlement_epoch_root: merkle_record_root(
                SETTLEMENT_EPOCH_SCHEME,
                self.settlement_epochs
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            settlement_netting_set_root: merkle_record_root(
                SETTLEMENT_NETTING_SET_SCHEME,
                self.settlement_netting_sets
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            sealed_settlement_receipt_root: merkle_record_root(
                SETTLED_RECEIPT_SCHEME,
                self.sealed_receipts
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            netting_instruction_root: merkle_record_root(
                SETTLEMENT_INSTRUCTION_SCHEME,
                self.netting_instructions
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            liquidity_reserve_root: merkle_record_root(
                LIQUIDITY_RESERVE_SCHEME,
                self.liquidity_reserves
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            settlement_quote_root: merkle_record_root(
                SETTLEMENT_QUOTE_SCHEME,
                self.settlement_quotes
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            settlement_attestation_root: merkle_record_root(
                SETTLEMENT_ATTESTATION_SCHEME,
                self.settlement_attestations
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            settlement_batch_root: merkle_record_root(
                SETTLEMENT_BATCH_SCHEME,
                self.fast_batches
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            replay_lock_root: merkle_record_root(
                REPLAY_LOCK_SCHEME,
                self.replay_locks
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            settlement_track_root: merkle_record_root(
                FINALITY_TRACK_SCHEME,
                self.settlement_tracks
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            settlement_fee_ledger_root: merkle_record_root(
                SETTLEMENT_FEE_LEDGER_SCHEME,
                self.settlement_fee_ledger_entries
                    .values()
                    .map(|record| record.root())
                    .collect(),
            ),
            policy_root: self.policy_root(),
            public_record_root: String::new(),
        };
        roots.public_record_root = payload_root(
            PUBLIC_RECORD_ROOT_SCHEME,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "height": self.current_height,
                "epoch": self.current_epoch,
                "roots_without_public_record_root": {
                    "config_root": roots.config_root,
                    "counters_root": roots.counters_root,
                    "settlement_epoch_root": roots.settlement_epoch_root,
                    "settlement_netting_set_root": roots.settlement_netting_set_root,
                    "sealed_settlement_receipt_root": roots.sealed_settlement_receipt_root,
                    "netting_instruction_root": roots.netting_instruction_root,
                    "liquidity_reserve_root": roots.liquidity_reserve_root,
                    "settlement_quote_root": roots.settlement_quote_root,
                    "settlement_attestation_root": roots.settlement_attestation_root,
                    "settlement_batch_root": roots.settlement_batch_root,
                    "replay_lock_root": roots.replay_lock_root,
                    "settlement_track_root": roots.settlement_track_root,
                    "settlement_fee_ledger_root": roots.settlement_fee_ledger_root,
                    "policy_root": roots.policy_root,
                },
            }),
        );
        roots
    }

    pub fn recompute_roots(&mut self) {
        self.roots = self.roots();
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "height": self.current_height,
            "epoch": self.current_epoch,
            "roots": self.roots().public_record(),
        }))
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "fee_asset_id": self.config.fee_asset_id,
            "height": self.current_height,
            "epoch": self.current_epoch,
            "state_root": self.state_root(),
            "roots_only": true,
            "roots": roots.public_record(),
            "privacy_policy": {
                "roots_only_public_records": self.config.require_roots_only_public_records,
                "sealed_receipt_payloads_redacted": true,
                "encrypted_storage_deltas_redacted": true,
                "contract_identity_commitments_only": true,
                "settlement_reserves_commitment_only": true,
                "liquidity_amounts_bucketed": true,
                "pq_attestation_roots_only": true,
                "replay_nullifier_roots_only": true,
                "settlement_fee_ledger_commitments_only": true,
            },
        })
    }

    fn ensure_epoch_exists(&self, epoch_id: &str) -> Result<SettlementLane> {
        self.settlement_epochs
            .get(epoch_id)
            .map(|epoch| epoch.lane)
            .ok_or_else(|| "unknown settlement epoch".to_string())
    }

    fn ensure_epoch_accepts_receipts(&self, epoch_id: &str) -> Result<SettlementLane> {
        let epoch = self
            .settlement_epochs
            .get(epoch_id)
            .ok_or_else(|| "unknown settlement epoch".to_string())?;
        if !epoch.status.accepts_receipts() {
            return Err("settlement epoch is not accepting receipts".to_string());
        }
        if self.current_height > epoch.instruction_deadline_height {
            return Err("settlement epoch settlement window closed".to_string());
        }
        Ok(epoch.lane)
    }

    fn ensure_epoch_accepts_settlements(&self, epoch_id: &str) -> Result<SettlementLane> {
        let epoch = self
            .settlement_epochs
            .get(epoch_id)
            .ok_or_else(|| "unknown settlement epoch".to_string())?;
        if !epoch.status.active() {
            return Err("settlement epoch is not active".to_string());
        }
        if self.current_height > epoch.fast_instruction_deadline_height {
            return Err("settlement epoch fast settlement window closed".to_string());
        }
        Ok(epoch.lane)
    }

    fn settlement_netting_sets_for_epoch(&self, epoch_id: &str) -> usize {
        self.settlement_netting_sets
            .values()
            .filter(|netting_set| netting_set.epoch_id == epoch_id)
            .count()
    }

    fn instructions_for_epoch(&self, epoch_id: &str) -> usize {
        self.netting_instructions
            .values()
            .filter(|instruction| instruction.epoch_id == epoch_id)
            .count()
    }

    fn quotes_for_epoch(&self, epoch_id: &str) -> usize {
        self.settlement_quotes
            .values()
            .filter(|quote| quote.epoch_id == epoch_id)
            .count()
    }

    fn refresh_quote_quorum(&mut self, quote_id: &str) {
        let quorum_weight = self
            .settlement_attestations
            .values()
            .filter(|attestation| {
                attestation.quote_id == quote_id
                    && matches!(
                        attestation.status,
                        SettlementAttestationStatus::Verified
                            | SettlementAttestationStatus::Aggregated
                    )
            })
            .fold(0u64, |acc, attestation| {
                acc.saturating_add(attestation.quorum_weight_bps)
            });
        if quorum_weight >= self.config.fast_finality_quorum_bps {
            if let Some(quote) = self.settlement_quotes.get_mut(quote_id) {
                quote.status = SettlementQuoteStatus::QuorumReady;
            }
            for attestation in self.settlement_attestations.values_mut() {
                if attestation.quote_id == quote_id
                    && matches!(attestation.status, SettlementAttestationStatus::Verified)
                {
                    attestation.status = SettlementAttestationStatus::Aggregated;
                }
            }
        }
    }

    fn policy_root(&self) -> String {
        payload_root(
            POLICY_ROOT_SCHEME,
            &json!({
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "target_privacy_set_size": self.config.target_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "max_netting_set_hops": self.config.max_netting_set_hops,
                "quorum_bps": self.config.quorum_bps,
                "fast_finality_quorum_bps": self.config.fast_finality_quorum_bps,
                "prefer_low_fee_settlements": self.config.prefer_low_fee_settlements,
                "prefer_fast_receipt_settlement": self.config.prefer_fast_receipt_settlement,
                "require_pq_attestations": self.config.require_pq_attestations,
                "require_replay_locks": self.config.require_replay_locks,
            }),
        )
    }

    fn expire_stale_records(&mut self) {
        for epoch in self.settlement_epochs.values_mut() {
            if epoch.status.active() && self.current_height > epoch.fast_instruction_deadline_height
            {
                epoch.status = SettlementEpochStatus::Expired;
            }
        }
        for receipt in self.sealed_receipts.values_mut() {
            if receipt.status.routable() && self.current_height > receipt.expires_height {
                receipt.status = SealedSettlementReceiptStatus::Expired;
            }
        }
        for instruction in self.netting_instructions.values_mut() {
            if matches!(
                instruction.status,
                NettingInstructionStatus::Pending
                    | NettingInstructionStatus::SettlementLocked
                    | NettingInstructionStatus::QuoteReady
            ) && self
                .current_height
                .saturating_sub(instruction.created_height)
                > self.config.replay_window_blocks
            {
                instruction.status = NettingInstructionStatus::Expired;
            }
        }
        for reserve in self.liquidity_reserves.values_mut() {
            if self.current_height > reserve.expires_height {
                reserve.available_liquidity_bucket = 0;
            }
        }
        for attestation in self.settlement_attestations.values_mut() {
            if matches!(
                attestation.status,
                SettlementAttestationStatus::Pending | SettlementAttestationStatus::Verified
            ) && self.current_height > attestation.expires_height
            {
                attestation.status = SettlementAttestationStatus::Expired;
            }
        }
        for lock in self.replay_locks.values_mut() {
            if matches!(
                lock.status,
                ReplayLockStatus::Reserved | ReplayLockStatus::Armed
            ) && self.current_height > lock.expires_height
            {
                lock.status = ReplayLockStatus::Expired;
            }
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn settlement_epoch_id(
    lane: SettlementLane,
    source_namespace_root: &str,
    target_namespace_root: &str,
    settlement_committee_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:PLAN-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(source_namespace_root),
            HashPart::Str(target_namespace_root),
            HashPart::Str(settlement_committee_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn settlement_netting_set_id(
    epoch_id: &str,
    netting_set_kind: SettlementNettingSetKind,
    source_contract_commitment: &str,
    target_contract_commitment: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:EDGE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(epoch_id),
            HashPart::Str(netting_set_kind.as_str()),
            HashPart::Str(source_contract_commitment),
            HashPart::Str(target_contract_commitment),
            HashPart::U64(nonce),
        ],
    )
}

pub fn sealed_settlement_receipt_id(
    epoch_id: &str,
    contract_commitment: &str,
    sealed_receipt_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:RECEIPT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(epoch_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(sealed_receipt_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn netting_instruction_id(
    epoch_id: &str,
    aggregate_position_commitment_root: &str,
    aggregate_fee_delta_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:INTENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(epoch_id),
            HashPart::Str(aggregate_position_commitment_root),
            HashPart::Str(aggregate_fee_delta_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn liquidity_reserve_id(
    epoch_id: &str,
    settlement_netting_set_id: &str,
    sponsor_commitment: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:LIQUIDITY-RESERVE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(epoch_id),
            HashPart::Str(settlement_netting_set_id),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(nonce),
        ],
    )
}

pub fn settlement_quote_id(
    epoch_id: &str,
    instruction_id: &str,
    netted_fee_delta_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:QUOTE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(epoch_id),
            HashPart::Str(instruction_id),
            HashPart::Str(netted_fee_delta_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn settlement_attestation_id(
    quote_id: &str,
    committee_id: &str,
    role: SettlementAttestationRole,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(quote_id),
            HashPart::Str(committee_id),
            HashPart::Str(role.as_str()),
            HashPart::U64(nonce),
        ],
    )
}

pub fn replay_lock_id(
    epoch_id: &str,
    receipt_id: &str,
    replay_nullifier_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:REPLAY-GUARD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(epoch_id),
            HashPart::Str(receipt_id),
            HashPart::Str(replay_nullifier_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn fast_settlement_batch_id(
    operator_commitment: &str,
    settlement_lane_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_commitment),
            HashPart::Str(settlement_lane_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

pub fn settlement_track_id(
    batch_id: &str,
    settlement_lane_root: &str,
    post_settlement_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:SETTLEMENT-TRACK-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_lane_root),
            HashPart::Str(post_settlement_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn settlement_fee_ledger_entry_id(
    settlement_track_id: &str,
    contract_commitment: &str,
    fee_delta_commitment_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:FEE-LEDGER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(settlement_track_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(fee_delta_commitment_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn estimate_settlement_micro_fee(
    config: &Config,
    lane: SettlementLane,
    max_micro_fee: u64,
    receipt_bytes: u64,
    settlement_hops: u8,
) -> u64 {
    let byte_component = receipt_bytes.saturating_add(4095) / 4096;
    let priority_discount = lane.priority_weight() / 1_600;
    let hop_component =
        u64::from(settlement_hops.saturating_sub(1)).saturating_mul(config.base_micro_fee);
    let hop_rebate = bps(
        hop_component.saturating_add(max_micro_fee),
        config.netting_compression_rebate_bps,
    );
    let mut fee = max_micro_fee
        .max(config.base_micro_fee)
        .saturating_add(byte_component)
        .saturating_add(hop_component)
        .saturating_add(config.settlement_operator_fee_bps)
        .saturating_add(config.congestion_fee_bps)
        .saturating_sub(priority_discount)
        .saturating_sub(hop_rebate);
    fee = fee.saturating_sub(bps(fee, config.settlement_rebate_bps));
    fee.max(config.min_micro_fee)
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:PAYLOAD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-SETTLEMENT:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    if records.is_empty() {
        payload_root(domain, &json!({ "empty": true }))
    } else {
        merkle_root(domain, records)
    }
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn string_list_root(domain: &str, values: &[String]) -> String {
    payload_root(domain, &json!({ "values": values }))
}

fn merkle_record_root(domain: &str, leaves: Vec<String>) -> String {
    if leaves.is_empty() {
        payload_root(domain, &json!({ "empty": true }))
    } else {
        let values = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
        merkle_root(domain, &values)
    }
}

fn bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must be non-empty"))
    } else {
        Ok(())
    }
}
