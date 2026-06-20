use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStorageReceiptFeeClearingRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedStorageReceiptFeeClearingRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_CLEARING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-storage-receipt-fee-clearing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_CLEARING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CLEARING_SUITE: &str = "pq-confidential-contract-sealed-storage-receipt-fee-clearing-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-storage-receipt-fee-clearing-public-record-v1";
pub const CLEARING_EPOCH_SCHEME: &str = "sealed-storage-receipt-clearing-epoch-root-v1";
pub const SEALED_RECEIPT_ORDER_SCHEME: &str = "sealed-storage-receipt-clearing-order-root-v1";
pub const RECEIPT_MATCH_SCHEME: &str = "sealed-storage-receipt-clearing-match-root-v1";
pub const PQ_CLEARING_ATTESTATION_SCHEME: &str = "pq-storage-receipt-clearing-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "storage-receipt-clearing-replay-nullifier-root-v1";
pub const FAST_CLEARING_BATCH_SCHEME: &str = "fast-storage-receipt-clearing-batch-root-v1";
pub const CONTRACT_ACCOUNTING_SCHEME: &str = "confidential-contract-clearing-accounting-root-v1";
pub const FEE_POOL_SCHEME: &str = "low-fee-clearing-liquidity-pool-root-v1";
pub const POLICY_ROOT_SCHEME: &str = "clearing-privacy-pq-policy-root-v1";
pub const PUBLIC_RECORD_ROOT_SCHEME: &str = "storage-receipt-clearing-roots-only-public-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_889_024;
pub const DEVNET_EPOCH: u64 = 11_502;
pub const DEFAULT_CLEARING_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 2;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 160;
pub const DEFAULT_ACCOUNTING_EPOCH_BLOCKS: u64 = 360;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_MICRO_FEE: u64 = 1;
pub const DEFAULT_BASE_MICRO_FEE: u64 = 2;
pub const DEFAULT_MAX_SEALED_ORDERS_PER_EPOCH: usize = 18_432;
pub const DEFAULT_MAX_MATCHES_PER_BATCH: usize = 6_144;
pub const DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH: u64 = 10_485_760;
pub const DEFAULT_MAX_STORAGE_KEYS_PER_ORDER: u64 = 131_072;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 2;
pub const DEFAULT_CLEARING_REBATE_BPS: u64 = 14;
pub const DEFAULT_CONGESTION_FEE_BPS: u64 = 7;
pub const DEFAULT_LIQUIDITY_DISCOUNT_BPS: u64 = 5;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_FAST_FINALITY_QUORUM_BPS: u64 = 8_250;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingLane {
    DefiExecution,
    LendingRisk,
    BridgeSettlement,
    OracleCache,
    GovernanceVault,
    AccountRecovery,
    EmergencyRetention,
    BatchMaintenance,
}

impl ClearingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefiExecution => "defi_execution",
            Self::LendingRisk => "lending_risk",
            Self::BridgeSettlement => "bridge_settlement",
            Self::OracleCache => "oracle_cache",
            Self::GovernanceVault => "governance_vault",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyRetention => "emergency_retention",
            Self::BatchMaintenance => "batch_maintenance",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyRetention => 10_000,
            Self::AccountRecovery => 9_700,
            Self::BridgeSettlement => 9_300,
            Self::OracleCache => 8_950,
            Self::LendingRisk => 8_650,
            Self::DefiExecution => 8_400,
            Self::GovernanceVault => 8_050,
            Self::BatchMaintenance => 7_600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingEpochStatus {
    Announced,
    AcceptingSealedOrders,
    Matching,
    PqAttested,
    FastSettling,
    Settled,
    Cancelled,
    Expired,
}

impl ClearingEpochStatus {
    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Announced | Self::AcceptingSealedOrders)
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::AcceptingSealedOrders
                | Self::Matching
                | Self::PqAttested
                | Self::FastSettling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedOrderStatus {
    Sealed,
    ReplayGuarded,
    Matchable,
    Matched,
    Settled,
    Repriced,
    Refunded,
    DuplicateRejected,
    Expired,
}

impl SealedOrderStatus {
    pub fn matchable(self) -> bool {
        matches!(self, Self::ReplayGuarded | Self::Matchable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchStatus {
    Proposed,
    FeeCleared,
    ExecutorAttested,
    VerifierAttested,
    QuorumReady,
    Included,
    Challenged,
    Rejected,
}

impl MatchStatus {
    pub fn settlement_ready(self) -> bool {
        matches!(
            self,
            Self::ExecutorAttested | Self::VerifierAttested | Self::QuorumReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    ClearingExecutor,
    ReceiptVerifier,
    Watchtower,
    FeePoolAuditor,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClearingExecutor => "clearing_executor",
            Self::ReceiptVerifier => "receipt_verifier",
            Self::Watchtower => "watchtower",
            Self::FeePoolAuditor => "fee_pool_auditor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Verified,
    Aggregated,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Reserved,
    Armed,
    Consumed,
    DuplicateRejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Queued,
    PqQuorum,
    FastFinal,
    Settled,
    Repriced,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeePoolStatus {
    Open,
    Netting,
    Locked,
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
    pub hash_suite: String,
    pub clearing_suite: String,
    pub roots_only_public_record_suite: String,
    pub clearing_window_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub replay_window_blocks: u64,
    pub accounting_epoch_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_micro_fee: u64,
    pub base_micro_fee: u64,
    pub max_sealed_orders_per_epoch: usize,
    pub max_matches_per_batch: usize,
    pub max_receipt_bytes_per_batch: u64,
    pub max_storage_keys_per_order: u64,
    pub operator_fee_bps: u64,
    pub clearing_rebate_bps: u64,
    pub congestion_fee_bps: u64,
    pub liquidity_discount_bps: u64,
    pub quorum_bps: u64,
    pub fast_finality_quorum_bps: u64,
    pub require_roots_only_public_records: bool,
    pub require_replay_nullifier: bool,
    pub require_pq_attestation: bool,
    pub prefer_low_fee_clearing: bool,
    pub prefer_fast_receipt_settlement: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            clearing_suite: CLEARING_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            clearing_window_blocks: DEFAULT_CLEARING_WINDOW_BLOCKS,
            fast_settlement_blocks: DEFAULT_FAST_SETTLEMENT_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            accounting_epoch_blocks: DEFAULT_ACCOUNTING_EPOCH_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_micro_fee: DEFAULT_MIN_MICRO_FEE,
            base_micro_fee: DEFAULT_BASE_MICRO_FEE,
            max_sealed_orders_per_epoch: DEFAULT_MAX_SEALED_ORDERS_PER_EPOCH,
            max_matches_per_batch: DEFAULT_MAX_MATCHES_PER_BATCH,
            max_receipt_bytes_per_batch: DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH,
            max_storage_keys_per_order: DEFAULT_MAX_STORAGE_KEYS_PER_ORDER,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            clearing_rebate_bps: DEFAULT_CLEARING_REBATE_BPS,
            congestion_fee_bps: DEFAULT_CONGESTION_FEE_BPS,
            liquidity_discount_bps: DEFAULT_LIQUIDITY_DISCOUNT_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            fast_finality_quorum_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
            require_roots_only_public_records: true,
            require_replay_nullifier: true,
            require_pq_attestation: true,
            prefer_low_fee_clearing: true,
            prefer_fast_receipt_settlement: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported sealed storage receipt fee clearing protocol".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported sealed storage receipt fee clearing schema".to_string());
        }
        if self.clearing_window_blocks == 0 || self.fast_settlement_blocks == 0 {
            return Err("clearing and fast settlement windows must be non-zero".to_string());
        }
        if self.replay_window_blocks < self.clearing_window_blocks {
            return Err("replay window must cover the clearing window".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set bounds are invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("post-quantum security floor is too low".to_string());
        }
        if self.max_sealed_orders_per_epoch == 0 || self.max_matches_per_batch == 0 {
            return Err("clearing capacity limits must be non-zero".to_string());
        }
        if self.operator_fee_bps > MAX_BPS
            || self.clearing_rebate_bps > MAX_BPS
            || self.congestion_fee_bps > MAX_BPS
            || self.liquidity_discount_bps > MAX_BPS
            || self.quorum_bps > MAX_BPS
            || self.fast_finality_quorum_bps > MAX_BPS
        {
            return Err("basis point value exceeds MAX_BPS".to_string());
        }
        if self.fast_finality_quorum_bps < self.quorum_bps {
            return Err("fast finality quorum cannot be below base quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("config serializes")
    }

    pub fn root(&self) -> String {
        root_from_value("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub next_epoch_index: u64,
    pub next_order_index: u64,
    pub next_match_index: u64,
    pub next_attestation_index: u64,
    pub next_batch_index: u64,
    pub next_accounting_index: u64,
    pub clearing_epochs_opened: u64,
    pub sealed_orders_submitted: u64,
    pub replay_nullifiers_reserved: u64,
    pub duplicate_nullifiers_rejected: u64,
    pub receipt_matches_proposed: u64,
    pub receipt_matches_cleared: u64,
    pub pq_attestations: u64,
    pub fast_batches_finalized: u64,
    pub accounting_entries: u64,
    pub total_receipt_bytes_cleared: u64,
    pub total_storage_keys_cleared: u64,
    pub total_fee_micro_units: u128,
    pub total_operator_micro_units: u128,
    pub total_rebate_micro_units: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_epoch_index: 1,
            next_order_index: 1,
            next_match_index: 1,
            next_attestation_index: 1,
            next_batch_index: 1,
            next_accounting_index: 1,
            clearing_epochs_opened: 0,
            sealed_orders_submitted: 0,
            replay_nullifiers_reserved: 0,
            duplicate_nullifiers_rejected: 0,
            receipt_matches_proposed: 0,
            receipt_matches_cleared: 0,
            pq_attestations: 0,
            fast_batches_finalized: 0,
            accounting_entries: 0,
            total_receipt_bytes_cleared: 0,
            total_storage_keys_cleared: 0,
            total_fee_micro_units: 0,
            total_operator_micro_units: 0,
            total_rebate_micro_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("counters serialize")
    }

    pub fn root(&self) -> String {
        root_from_value("COUNTERS", &self.public_record())
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub clearing_epoch_root: String,
    pub sealed_receipt_order_root: String,
    pub receipt_match_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
    pub fast_clearing_batch_root: String,
    pub contract_accounting_root: String,
    pub fee_pool_root: String,
    pub policy_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("roots serialize")
    }

    pub fn root(&self) -> String {
        root_from_value("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ClearingEpochInput {
    pub lane: ClearingLane,
    pub storage_namespace_root: String,
    pub eligible_contract_set_root: String,
    pub fee_pool_root: String,
    pub target_receipt_bytes: u64,
    pub target_storage_keys: u64,
    pub min_clearing_micro_fee: u64,
    pub pq_policy_root: String,
    pub epoch_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ClearingEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub lane: ClearingLane,
    pub start_height: u64,
    pub order_end_height: u64,
    pub fast_settlement_deadline_height: u64,
    pub status: ClearingEpochStatus,
    pub storage_namespace_root: String,
    pub eligible_contract_set_root: String,
    pub fee_pool_root: String,
    pub target_receipt_bytes: u64,
    pub target_storage_keys: u64,
    pub min_clearing_micro_fee: u64,
    pub privacy_set_size: u64,
    pub pq_policy_root: String,
}

impl ClearingEpoch {
    pub fn from_input(
        epoch_index: u64,
        height: u64,
        config: &Config,
        input: ClearingEpochInput,
    ) -> Result<Self> {
        require_non_empty("storage_namespace_root", &input.storage_namespace_root)?;
        require_non_empty(
            "eligible_contract_set_root",
            &input.eligible_contract_set_root,
        )?;
        require_non_empty("fee_pool_root", &input.fee_pool_root)?;
        require_non_empty("pq_policy_root", &input.pq_policy_root)?;
        let epoch_id = deterministic_id(
            "CLEARING-EPOCH-ID",
            &[
                HashPart::Str(input.lane.as_str()),
                HashPart::Str(&input.storage_namespace_root),
                HashPart::Str(&input.eligible_contract_set_root),
                HashPart::U64(epoch_index),
                HashPart::U64(input.epoch_nonce),
            ],
        );
        Ok(Self {
            epoch_id,
            epoch_index,
            lane: input.lane,
            start_height: height,
            order_end_height: height.saturating_add(config.clearing_window_blocks),
            fast_settlement_deadline_height: height
                .saturating_add(config.clearing_window_blocks)
                .saturating_add(config.fast_settlement_blocks),
            status: ClearingEpochStatus::AcceptingSealedOrders,
            storage_namespace_root: input.storage_namespace_root,
            eligible_contract_set_root: input.eligible_contract_set_root,
            fee_pool_root: input.fee_pool_root,
            target_receipt_bytes: input.target_receipt_bytes,
            target_storage_keys: input.target_storage_keys,
            min_clearing_micro_fee: input.min_clearing_micro_fee.max(config.min_micro_fee),
            privacy_set_size: input
                .target_receipt_bytes
                .saturating_mul(input.target_storage_keys.max(1))
                .max(config.min_privacy_set_size),
            pq_policy_root: input.pq_policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "order_end_height": self.order_end_height,
            "fast_settlement_deadline_height": self.fast_settlement_deadline_height,
            "status": self.status,
            "storage_namespace_root": self.storage_namespace_root,
            "eligible_contract_set_root": self.eligible_contract_set_root,
            "fee_pool_root": self.fee_pool_root,
            "target_receipt_bytes": self.target_receipt_bytes,
            "target_storage_keys": self.target_storage_keys,
            "min_clearing_micro_fee": self.min_clearing_micro_fee,
            "privacy_set_size": self.privacy_set_size,
            "pq_policy_root": self.pq_policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedReceiptOrderInput {
    pub epoch_id: String,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub sealed_receipt_root: String,
    pub encrypted_storage_delta_root: String,
    pub max_micro_fee: u64,
    pub receipt_bytes_upper_bound: u64,
    pub storage_keys_upper_bound: u64,
    pub replay_nullifier_root: String,
    pub settlement_hint_root: String,
    pub order_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedReceiptOrder {
    pub order_id: String,
    pub order_index: u64,
    pub epoch_id: String,
    pub contract_commitment: String,
    pub payer_note_commitment: String,
    pub sealed_receipt_root: String,
    pub encrypted_storage_delta_root: String,
    pub max_micro_fee: u64,
    pub quoted_micro_fee: u64,
    pub receipt_bytes_upper_bound: u64,
    pub storage_keys_upper_bound: u64,
    pub privacy_set_size: u64,
    pub replay_nullifier_root: String,
    pub settlement_hint_root: String,
    pub status: SealedOrderStatus,
    pub expires_height: u64,
}

impl SealedReceiptOrder {
    pub fn from_input(
        order_index: u64,
        epoch: &ClearingEpoch,
        config: &Config,
        input: SealedReceiptOrderInput,
    ) -> Result<Self> {
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("payer_note_commitment", &input.payer_note_commitment)?;
        require_non_empty("sealed_receipt_root", &input.sealed_receipt_root)?;
        require_non_empty(
            "encrypted_storage_delta_root",
            &input.encrypted_storage_delta_root,
        )?;
        require_non_empty("replay_nullifier_root", &input.replay_nullifier_root)?;
        require_non_empty("settlement_hint_root", &input.settlement_hint_root)?;
        if input.max_micro_fee < epoch.min_clearing_micro_fee {
            return Err("sealed receipt order below clearing fee floor".to_string());
        }
        if input.storage_keys_upper_bound > config.max_storage_keys_per_order {
            return Err("sealed receipt order exceeds storage key bound".to_string());
        }
        let privacy_set_size = input
            .receipt_bytes_upper_bound
            .saturating_mul(input.storage_keys_upper_bound.max(1))
            .max(config.min_privacy_set_size);
        let quoted_micro_fee =
            estimate_clearing_micro_fee(config, epoch.lane, input.max_micro_fee, privacy_set_size);
        Ok(Self {
            order_id: deterministic_id(
                "SEALED-RECEIPT-CLEARING-ORDER-ID",
                &[
                    HashPart::Str(&input.epoch_id),
                    HashPart::Str(&input.contract_commitment),
                    HashPart::Str(&input.sealed_receipt_root),
                    HashPart::U64(input.order_nonce),
                ],
            ),
            order_index,
            epoch_id: input.epoch_id,
            contract_commitment: input.contract_commitment,
            payer_note_commitment: input.payer_note_commitment,
            sealed_receipt_root: input.sealed_receipt_root,
            encrypted_storage_delta_root: input.encrypted_storage_delta_root,
            max_micro_fee: input.max_micro_fee,
            quoted_micro_fee,
            receipt_bytes_upper_bound: input.receipt_bytes_upper_bound,
            storage_keys_upper_bound: input.storage_keys_upper_bound,
            privacy_set_size,
            replay_nullifier_root: input.replay_nullifier_root,
            settlement_hint_root: input.settlement_hint_root,
            status: SealedOrderStatus::ReplayGuarded,
            expires_height: epoch.fast_settlement_deadline_height,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("sealed receipt order serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReceiptMatchInput {
    pub epoch_id: String,
    pub order_ids: Vec<String>,
    pub fee_pool_id: String,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub matched_receipt_root: String,
    pub clearing_price_root: String,
    pub accounting_delta_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub match_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReceiptClearingMatch {
    pub match_id: String,
    pub match_index: u64,
    pub epoch_id: String,
    pub order_ids: Vec<String>,
    pub fee_pool_id: String,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub matched_receipt_root: String,
    pub clearing_price_root: String,
    pub accounting_delta_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub clearing_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub status: MatchStatus,
    pub executor_attestation_id: Option<String>,
    pub verifier_attestation_id: Option<String>,
}

impl ReceiptClearingMatch {
    pub fn from_input(
        match_index: u64,
        config: &Config,
        orders: &[SealedReceiptOrder],
        input: ReceiptMatchInput,
    ) -> Result<Self> {
        if input.order_ids.is_empty() {
            return Err("clearing match requires at least one sealed order".to_string());
        }
        require_non_empty("fee_pool_id", &input.fee_pool_id)?;
        require_non_empty("pre_storage_root", &input.pre_storage_root)?;
        require_non_empty("post_storage_root", &input.post_storage_root)?;
        require_non_empty("matched_receipt_root", &input.matched_receipt_root)?;
        require_non_empty("clearing_price_root", &input.clearing_price_root)?;
        require_non_empty("accounting_delta_root", &input.accounting_delta_root)?;
        let quoted_sum = orders.iter().fold(0_u64, |sum, order| {
            sum.saturating_add(order.quoted_micro_fee)
        });
        let byte_floor = config
            .base_micro_fee
            .saturating_mul(input.receipt_bytes.max(1));
        let gross = quoted_sum.max(byte_floor).max(config.min_micro_fee);
        let clearing_micro_fee = gross
            .saturating_add(bps(gross, config.congestion_fee_bps))
            .saturating_sub(bps(gross, config.liquidity_discount_bps))
            .max(config.min_micro_fee);
        let rebate_micro_fee = bps(clearing_micro_fee, config.clearing_rebate_bps);
        Ok(Self {
            match_id: deterministic_id(
                "RECEIPT-CLEARING-MATCH-ID",
                &[
                    HashPart::Str(&input.epoch_id),
                    HashPart::Str(&root_from_strings("MATCH-ORDER-SET", &input.order_ids)),
                    HashPart::Str(&input.post_storage_root),
                    HashPart::U64(input.match_nonce),
                ],
            ),
            match_index,
            epoch_id: input.epoch_id,
            order_ids: input.order_ids,
            fee_pool_id: input.fee_pool_id,
            pre_storage_root: input.pre_storage_root,
            post_storage_root: input.post_storage_root,
            matched_receipt_root: input.matched_receipt_root,
            clearing_price_root: input.clearing_price_root,
            accounting_delta_root: input.accounting_delta_root,
            receipt_bytes: input.receipt_bytes,
            storage_keys_touched: input.storage_keys_touched,
            clearing_micro_fee,
            rebate_micro_fee,
            status: MatchStatus::FeeCleared,
            executor_attestation_id: None,
            verifier_attestation_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("receipt clearing match serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqClearingAttestationInput {
    pub match_id: String,
    pub role: AttestationRole,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_receipt_root: String,
    pub attested_storage_root: String,
    pub pq_public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub attestation_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqClearingAttestation {
    pub attestation_id: String,
    pub attestation_index: u64,
    pub match_id: String,
    pub role: AttestationRole,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_receipt_root: String,
    pub attested_storage_root: String,
    pub pq_public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub status: AttestationStatus,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl PqClearingAttestation {
    pub fn from_input(
        attestation_index: u64,
        height: u64,
        config: &Config,
        clearing_match: &ReceiptClearingMatch,
        input: PqClearingAttestationInput,
    ) -> Result<Self> {
        require_non_empty("committee_id", &input.committee_id)?;
        require_non_empty("signer_set_root", &input.signer_set_root)?;
        require_non_empty("attested_receipt_root", &input.attested_receipt_root)?;
        require_non_empty("attested_storage_root", &input.attested_storage_root)?;
        require_non_empty("pq_public_key_digest", &input.pq_public_key_digest)?;
        require_non_empty("pq_signature_root", &input.pq_signature_root)?;
        if clearing_match.matched_receipt_root != input.attested_receipt_root {
            return Err("PQ clearing attestation receipt root mismatch".to_string());
        }
        if clearing_match.post_storage_root != input.attested_storage_root {
            return Err("PQ clearing attestation storage root mismatch".to_string());
        }
        if input.pq_security_bits < config.min_pq_security_bits {
            return Err("PQ clearing attestation security below runtime floor".to_string());
        }
        if input.quorum_weight_bps > MAX_BPS {
            return Err("PQ clearing attestation quorum exceeds 100%".to_string());
        }
        let status = if input.quorum_weight_bps >= config.fast_finality_quorum_bps {
            AttestationStatus::Aggregated
        } else if input.quorum_weight_bps >= config.quorum_bps {
            AttestationStatus::Verified
        } else {
            AttestationStatus::Pending
        };
        Ok(Self {
            attestation_id: deterministic_id(
                "PQ-CLEARING-ATTESTATION-ID",
                &[
                    HashPart::Str(&input.match_id),
                    HashPart::Str(input.role.as_str()),
                    HashPart::Str(&input.committee_id),
                    HashPart::U64(input.attestation_nonce),
                ],
            ),
            attestation_index,
            match_id: input.match_id,
            role: input.role,
            committee_id: input.committee_id,
            signer_set_root: input.signer_set_root,
            attested_receipt_root: input.attested_receipt_root,
            attested_storage_root: input.attested_storage_root,
            pq_public_key_digest: input.pq_public_key_digest,
            pq_signature_root: input.pq_signature_root,
            pq_security_bits: input.pq_security_bits,
            quorum_weight_bps: input.quorum_weight_bps,
            status,
            issued_height: height,
            expires_height: height.saturating_add(config.replay_window_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("PQ clearing attestation serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayNullifier {
    pub nullifier_root: String,
    pub epoch_id: String,
    pub order_id: String,
    pub contract_commitment: String,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub status: NullifierStatus,
    pub consumed_by_batch_id: Option<String>,
}

impl ReplayNullifier {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("replay nullifier serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeePool {
    pub fee_pool_id: String,
    pub lane: ClearingLane,
    pub status: FeePoolStatus,
    pub liquidity_commitment_root: String,
    pub low_fee_curve_root: String,
    pub operator_set_root: String,
    pub opening_balance_commitment: String,
    pub closing_balance_commitment: String,
    pub netted_fee_micro_units: u128,
    pub rebate_micro_units: u128,
}

impl FeePool {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("fee pool serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeePoolInput {
    pub lane: ClearingLane,
    pub liquidity_commitment_root: String,
    pub low_fee_curve_root: String,
    pub operator_set_root: String,
    pub opening_balance_commitment: String,
    pub pool_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FastClearingBatch {
    pub batch_id: String,
    pub batch_index: u64,
    pub epoch_id: String,
    pub match_ids: Vec<String>,
    pub order_ids: Vec<String>,
    pub consumed_nullifier_roots: Vec<String>,
    pub status: BatchStatus,
    pub batch_storage_root_before: String,
    pub batch_storage_root_after: String,
    pub batch_receipt_root: String,
    pub batch_accounting_root: String,
    pub aggregated_pq_attestation_root: String,
    pub fee_pool_root: String,
    pub total_receipt_bytes: u64,
    pub total_storage_keys: u64,
    pub total_fee_micro_units: u128,
    pub operator_fee_micro_units: u128,
    pub rebate_micro_units: u128,
    pub settled_height: u64,
}

impl FastClearingBatch {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("fast clearing batch serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ContractAccountingEntry {
    pub accounting_id: String,
    pub accounting_index: u64,
    pub batch_id: String,
    pub contract_commitment: String,
    pub debit_note_commitment: String,
    pub rebate_note_commitment: String,
    pub accounting_epoch: u64,
    pub receipt_count: u64,
    pub storage_keys_touched: u64,
    pub net_micro_fee: u64,
    pub accounting_root_before: String,
    pub accounting_root_after: String,
}

impl ContractAccountingEntry {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("contract accounting entry serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AccountingEntryInput {
    pub batch_id: String,
    pub contract_commitment: String,
    pub debit_note_commitment: String,
    pub rebate_note_commitment: String,
    pub receipt_count: u64,
    pub storage_keys_touched: u64,
    pub net_micro_fee: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub current_epoch: u64,
    pub clearing_epochs: BTreeMap<String, ClearingEpoch>,
    pub sealed_orders: BTreeMap<String, SealedReceiptOrder>,
    pub receipt_matches: BTreeMap<String, ReceiptClearingMatch>,
    pub pq_attestations: BTreeMap<String, PqClearingAttestation>,
    pub replay_nullifiers: BTreeMap<String, ReplayNullifier>,
    pub fast_batches: BTreeMap<String, FastClearingBatch>,
    pub accounting_entries: BTreeMap<String, ContractAccountingEntry>,
    pub fee_pools: BTreeMap<String, FeePool>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::new(),
            current_height: DEVNET_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            clearing_epochs: BTreeMap::new(),
            sealed_orders: BTreeMap::new(),
            receipt_matches: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            replay_nullifiers: BTreeMap::new(),
            fast_batches: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            fee_pools: BTreeMap::new(),
        })
    }

    pub fn open_fee_pool(&mut self, input: FeePoolInput) -> Result<String> {
        require_non_empty(
            "liquidity_commitment_root",
            &input.liquidity_commitment_root,
        )?;
        require_non_empty("low_fee_curve_root", &input.low_fee_curve_root)?;
        require_non_empty("operator_set_root", &input.operator_set_root)?;
        require_non_empty(
            "opening_balance_commitment",
            &input.opening_balance_commitment,
        )?;
        let fee_pool_id = deterministic_id(
            "CLEARING-FEE-POOL-ID",
            &[
                HashPart::Str(input.lane.as_str()),
                HashPart::Str(&input.liquidity_commitment_root),
                HashPart::U64(input.pool_nonce),
            ],
        );
        let pool = FeePool {
            fee_pool_id: fee_pool_id.clone(),
            lane: input.lane,
            status: FeePoolStatus::Open,
            liquidity_commitment_root: input.liquidity_commitment_root,
            low_fee_curve_root: input.low_fee_curve_root,
            operator_set_root: input.operator_set_root,
            opening_balance_commitment: input.opening_balance_commitment.clone(),
            closing_balance_commitment: input.opening_balance_commitment,
            netted_fee_micro_units: 0,
            rebate_micro_units: 0,
        };
        self.fee_pools.insert(fee_pool_id.clone(), pool);
        Ok(fee_pool_id)
    }

    pub fn open_clearing_epoch(&mut self, input: ClearingEpochInput) -> Result<String> {
        let epoch = ClearingEpoch::from_input(
            self.counters.next_epoch_index,
            self.current_height,
            &self.config,
            input,
        )?;
        let epoch_id = epoch.epoch_id.clone();
        self.clearing_epochs.insert(epoch_id.clone(), epoch);
        self.counters.next_epoch_index += 1;
        self.counters.clearing_epochs_opened += 1;
        Ok(epoch_id)
    }

    pub fn submit_sealed_receipt_order(
        &mut self,
        input: SealedReceiptOrderInput,
    ) -> Result<String> {
        let epoch = self
            .clearing_epochs
            .get(&input.epoch_id)
            .ok_or_else(|| "unknown clearing epoch".to_string())?;
        if !epoch.status.accepts_orders() {
            return Err("clearing epoch is not accepting sealed receipt orders".to_string());
        }
        if self.orders_in_epoch(&input.epoch_id) >= self.config.max_sealed_orders_per_epoch {
            return Err("clearing epoch sealed order capacity reached".to_string());
        }
        if self
            .replay_nullifiers
            .contains_key(&input.replay_nullifier_root)
        {
            self.counters.duplicate_nullifiers_rejected += 1;
            return Err("duplicate clearing replay nullifier".to_string());
        }
        let order = SealedReceiptOrder::from_input(
            self.counters.next_order_index,
            epoch,
            &self.config,
            input,
        )?;
        let order_id = order.order_id.clone();
        let replay = ReplayNullifier {
            nullifier_root: order.replay_nullifier_root.clone(),
            epoch_id: order.epoch_id.clone(),
            order_id: order_id.clone(),
            contract_commitment: order.contract_commitment.clone(),
            reserved_height: self.current_height,
            expires_height: self
                .current_height
                .saturating_add(self.config.replay_window_blocks),
            status: NullifierStatus::Armed,
            consumed_by_batch_id: None,
        };
        self.replay_nullifiers
            .insert(replay.nullifier_root.clone(), replay);
        self.sealed_orders.insert(order_id.clone(), order);
        self.counters.next_order_index += 1;
        self.counters.sealed_orders_submitted += 1;
        self.counters.replay_nullifiers_reserved += 1;
        Ok(order_id)
    }

    pub fn propose_receipt_match(&mut self, input: ReceiptMatchInput) -> Result<String> {
        self.ensure_epoch_exists(&input.epoch_id)?;
        if input.order_ids.len() > self.config.max_matches_per_batch {
            return Err("receipt match exceeds configured match order limit".to_string());
        }
        if !self.fee_pools.contains_key(&input.fee_pool_id) {
            return Err("receipt match references unknown fee pool".to_string());
        }
        let mut orders = Vec::new();
        for order_id in &input.order_ids {
            let order = self
                .sealed_orders
                .get(order_id)
                .ok_or_else(|| format!("unknown sealed receipt order {order_id}"))?;
            if order.epoch_id != input.epoch_id {
                return Err("receipt match contains order from another epoch".to_string());
            }
            if !order.status.matchable() {
                return Err("receipt match contains non-matchable sealed order".to_string());
            }
            if input.receipt_bytes > order.receipt_bytes_upper_bound {
                return Err("receipt match exceeds sealed order byte bound".to_string());
            }
            if input.storage_keys_touched > order.storage_keys_upper_bound {
                return Err("receipt match exceeds sealed order storage key bound".to_string());
            }
            orders.push(order.clone());
        }
        let clearing_match = ReceiptClearingMatch::from_input(
            self.counters.next_match_index,
            &self.config,
            &orders,
            input,
        )?;
        let match_id = clearing_match.match_id.clone();
        for order_id in &clearing_match.order_ids {
            if let Some(order) = self.sealed_orders.get_mut(order_id) {
                order.status = SealedOrderStatus::Matched;
            }
        }
        if let Some(epoch) = self.clearing_epochs.get_mut(&clearing_match.epoch_id) {
            epoch.status = ClearingEpochStatus::Matching;
        }
        self.receipt_matches
            .insert(match_id.clone(), clearing_match);
        self.counters.next_match_index += 1;
        self.counters.receipt_matches_proposed += 1;
        Ok(match_id)
    }

    pub fn attest_receipt_match(&mut self, input: PqClearingAttestationInput) -> Result<String> {
        let clearing_match = self
            .receipt_matches
            .get(&input.match_id)
            .ok_or_else(|| "unknown receipt clearing match".to_string())?;
        let attestation = PqClearingAttestation::from_input(
            self.counters.next_attestation_index,
            self.current_height,
            &self.config,
            clearing_match,
            input,
        )?;
        let attestation_id = attestation.attestation_id.clone();
        let role = attestation.role;
        let match_id = attestation.match_id.clone();
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        if let Some(clearing_match) = self.receipt_matches.get_mut(&match_id) {
            match role {
                AttestationRole::ClearingExecutor => {
                    clearing_match.executor_attestation_id = Some(attestation_id.clone());
                    clearing_match.status = MatchStatus::ExecutorAttested;
                }
                AttestationRole::ReceiptVerifier | AttestationRole::Watchtower => {
                    clearing_match.verifier_attestation_id = Some(attestation_id.clone());
                    clearing_match.status = MatchStatus::VerifierAttested;
                }
                AttestationRole::FeePoolAuditor => {}
            }
            if clearing_match.executor_attestation_id.is_some()
                && clearing_match.verifier_attestation_id.is_some()
            {
                clearing_match.status = MatchStatus::QuorumReady;
            }
        }
        self.counters.next_attestation_index += 1;
        self.counters.pq_attestations += 1;
        Ok(attestation_id)
    }

    pub fn finalize_fast_clearing_batch(
        &mut self,
        epoch_id: impl Into<String>,
        match_ids: Vec<String>,
    ) -> Result<String> {
        let epoch_id = epoch_id.into();
        self.ensure_epoch_exists(&epoch_id)?;
        if match_ids.is_empty() {
            return Err("fast clearing batch cannot be empty".to_string());
        }
        if match_ids.len() > self.config.max_matches_per_batch {
            return Err("fast clearing batch exceeds match limit".to_string());
        }
        let mut order_ids = BTreeSet::new();
        let mut consumed_nullifier_roots = BTreeSet::new();
        let mut before_roots = Vec::new();
        let mut after_roots = Vec::new();
        let mut receipt_roots = Vec::new();
        let mut accounting_roots = Vec::new();
        let mut attestation_roots = Vec::new();
        let mut fee_pool_ids = BTreeSet::new();
        let mut total_receipt_bytes = 0_u64;
        let mut total_storage_keys = 0_u64;
        let mut total_fee_micro_units = 0_u128;
        let mut rebate_micro_units = 0_u128;

        for match_id in &match_ids {
            let clearing_match = self
                .receipt_matches
                .get(match_id)
                .ok_or_else(|| format!("unknown receipt clearing match {match_id}"))?;
            if clearing_match.epoch_id != epoch_id {
                return Err("fast clearing batch contains match from another epoch".to_string());
            }
            if !clearing_match.status.settlement_ready() {
                return Err("fast clearing batch contains match without PQ quorum".to_string());
            }
            total_receipt_bytes = total_receipt_bytes.saturating_add(clearing_match.receipt_bytes);
            total_storage_keys =
                total_storage_keys.saturating_add(clearing_match.storage_keys_touched);
            total_fee_micro_units =
                total_fee_micro_units.saturating_add(clearing_match.clearing_micro_fee as u128);
            rebate_micro_units =
                rebate_micro_units.saturating_add(clearing_match.rebate_micro_fee as u128);
            before_roots.push(clearing_match.pre_storage_root.clone());
            after_roots.push(clearing_match.post_storage_root.clone());
            receipt_roots.push(clearing_match.matched_receipt_root.clone());
            accounting_roots.push(clearing_match.accounting_delta_root.clone());
            fee_pool_ids.insert(clearing_match.fee_pool_id.clone());
            for order_id in &clearing_match.order_ids {
                order_ids.insert(order_id.clone());
                let order = self
                    .sealed_orders
                    .get(order_id)
                    .ok_or_else(|| "clearing match references unknown order".to_string())?;
                consumed_nullifier_roots.insert(order.replay_nullifier_root.clone());
            }
            if let Some(id) = &clearing_match.executor_attestation_id {
                if let Some(attestation) = self.pq_attestations.get(id) {
                    attestation_roots.push(record_root(
                        PQ_CLEARING_ATTESTATION_SCHEME,
                        &attestation.public_record(),
                    ));
                }
            }
            if let Some(id) = &clearing_match.verifier_attestation_id {
                if let Some(attestation) = self.pq_attestations.get(id) {
                    attestation_roots.push(record_root(
                        PQ_CLEARING_ATTESTATION_SCHEME,
                        &attestation.public_record(),
                    ));
                }
            }
        }
        if total_receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("fast clearing batch exceeds receipt byte limit".to_string());
        }

        let operator_fee_micro_units = (total_fee_micro_units
            .saturating_mul(self.config.operator_fee_bps as u128))
            / (MAX_BPS as u128);
        let batch_id = deterministic_id(
            "FAST-RECEIPT-CLEARING-BATCH-ID",
            &[
                HashPart::Str(&epoch_id),
                HashPart::Str(&root_from_strings("FAST-CLEARING-MATCH-SET", &match_ids)),
                HashPart::U64(self.counters.next_batch_index),
            ],
        );
        let fee_pool_root = root_from_strings(
            "FAST-CLEARING-FEE-POOL-SET",
            &fee_pool_ids.iter().cloned().collect::<Vec<_>>(),
        );
        let batch = FastClearingBatch {
            batch_id: batch_id.clone(),
            batch_index: self.counters.next_batch_index,
            epoch_id: epoch_id.clone(),
            match_ids: match_ids.clone(),
            order_ids: order_ids.iter().cloned().collect(),
            consumed_nullifier_roots: consumed_nullifier_roots.iter().cloned().collect(),
            status: BatchStatus::Settled,
            batch_storage_root_before: root_from_strings("CLEARING-BATCH-BEFORE", &before_roots),
            batch_storage_root_after: root_from_strings("CLEARING-BATCH-AFTER", &after_roots),
            batch_receipt_root: root_from_strings("CLEARING-BATCH-RECEIPTS", &receipt_roots),
            batch_accounting_root: root_from_strings(
                "CLEARING-BATCH-ACCOUNTING",
                &accounting_roots,
            ),
            aggregated_pq_attestation_root: root_from_strings(
                "CLEARING-BATCH-PQ-ATTESTATIONS",
                &attestation_roots,
            ),
            fee_pool_root,
            total_receipt_bytes,
            total_storage_keys,
            total_fee_micro_units,
            operator_fee_micro_units,
            rebate_micro_units,
            settled_height: self.current_height,
        };
        for match_id in &match_ids {
            if let Some(clearing_match) = self.receipt_matches.get_mut(match_id) {
                clearing_match.status = MatchStatus::Included;
            }
        }
        for order_id in &order_ids {
            if let Some(order) = self.sealed_orders.get_mut(order_id) {
                order.status = SealedOrderStatus::Settled;
            }
        }
        for nullifier in &consumed_nullifier_roots {
            if let Some(replay) = self.replay_nullifiers.get_mut(nullifier) {
                replay.status = NullifierStatus::Consumed;
                replay.consumed_by_batch_id = Some(batch_id.clone());
            }
        }
        for fee_pool_id in &fee_pool_ids {
            if let Some(pool) = self.fee_pools.get_mut(fee_pool_id) {
                pool.status = FeePoolStatus::Settled;
                pool.netted_fee_micro_units = pool
                    .netted_fee_micro_units
                    .saturating_add(total_fee_micro_units);
                pool.rebate_micro_units =
                    pool.rebate_micro_units.saturating_add(rebate_micro_units);
                pool.closing_balance_commitment = root_from_value(
                    "FEE-POOL-CLOSING-BALANCE",
                    &json!({
                        "fee_pool_id": pool.fee_pool_id,
                        "netted_fee_micro_units": pool.netted_fee_micro_units,
                        "rebate_micro_units": pool.rebate_micro_units,
                    }),
                );
            }
        }
        if let Some(epoch) = self.clearing_epochs.get_mut(&epoch_id) {
            epoch.status = ClearingEpochStatus::Settled;
        }
        self.fast_batches.insert(batch_id.clone(), batch);
        self.counters.next_batch_index += 1;
        self.counters.fast_batches_finalized += 1;
        self.counters.receipt_matches_cleared = self
            .counters
            .receipt_matches_cleared
            .saturating_add(match_ids.len() as u64);
        self.counters.total_receipt_bytes_cleared = self
            .counters
            .total_receipt_bytes_cleared
            .saturating_add(total_receipt_bytes);
        self.counters.total_storage_keys_cleared = self
            .counters
            .total_storage_keys_cleared
            .saturating_add(total_storage_keys);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(total_fee_micro_units);
        self.counters.total_operator_micro_units = self
            .counters
            .total_operator_micro_units
            .saturating_add(operator_fee_micro_units);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(rebate_micro_units);
        Ok(batch_id)
    }

    pub fn append_accounting_entry(&mut self, input: AccountingEntryInput) -> Result<String> {
        let batch = self
            .fast_batches
            .get(&input.batch_id)
            .ok_or_else(|| "unknown fast clearing batch".to_string())?;
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("debit_note_commitment", &input.debit_note_commitment)?;
        require_non_empty("rebate_note_commitment", &input.rebate_note_commitment)?;
        let accounting_id = deterministic_id(
            "CONTRACT-CLEARING-ACCOUNTING-ID",
            &[
                HashPart::Str(&input.batch_id),
                HashPart::Str(&input.contract_commitment),
                HashPart::U64(self.counters.next_accounting_index),
            ],
        );
        let accounting_root_before = self.roots().contract_accounting_root;
        let entry = ContractAccountingEntry {
            accounting_id: accounting_id.clone(),
            accounting_index: self.counters.next_accounting_index,
            batch_id: input.batch_id.clone(),
            contract_commitment: input.contract_commitment,
            debit_note_commitment: input.debit_note_commitment,
            rebate_note_commitment: input.rebate_note_commitment,
            accounting_epoch: self.current_height / self.config.accounting_epoch_blocks.max(1),
            receipt_count: input.receipt_count,
            storage_keys_touched: input.storage_keys_touched,
            net_micro_fee: input.net_micro_fee,
            accounting_root_before,
            accounting_root_after: root_from_value(
                "CONTRACT-ACCOUNTING-AFTER",
                &json!({
                    "accounting_id": accounting_id,
                    "batch_root": record_root(FAST_CLEARING_BATCH_SCHEME, &batch.public_record()),
                    "receipt_count": input.receipt_count,
                    "storage_keys_touched": input.storage_keys_touched,
                    "net_micro_fee": input.net_micro_fee,
                }),
            ),
        };
        let accounting_id = entry.accounting_id.clone();
        self.accounting_entries.insert(accounting_id.clone(), entry);
        self.counters.next_accounting_index += 1;
        self.counters.accounting_entries += 1;
        Ok(accounting_id)
    }

    pub fn advance_height(&mut self, new_height: u64) -> Result<()> {
        if new_height < self.current_height {
            return Err("cannot rewind clearing runtime height".to_string());
        }
        self.current_height = new_height;
        self.current_epoch = new_height / self.config.clearing_window_blocks.max(1);
        self.expire_old_records();
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            clearing_epoch_root: merkle_record_root(
                CLEARING_EPOCH_SCHEME,
                self.clearing_epochs
                    .values()
                    .map(|record| record_root(CLEARING_EPOCH_SCHEME, &record.public_record()))
                    .collect(),
            ),
            sealed_receipt_order_root: merkle_record_root(
                SEALED_RECEIPT_ORDER_SCHEME,
                self.sealed_orders
                    .values()
                    .map(|record| record_root(SEALED_RECEIPT_ORDER_SCHEME, &record.public_record()))
                    .collect(),
            ),
            receipt_match_root: merkle_record_root(
                RECEIPT_MATCH_SCHEME,
                self.receipt_matches
                    .values()
                    .map(|record| record_root(RECEIPT_MATCH_SCHEME, &record.public_record()))
                    .collect(),
            ),
            pq_attestation_root: merkle_record_root(
                PQ_CLEARING_ATTESTATION_SCHEME,
                self.pq_attestations
                    .values()
                    .map(|record| {
                        record_root(PQ_CLEARING_ATTESTATION_SCHEME, &record.public_record())
                    })
                    .collect(),
            ),
            replay_nullifier_root: merkle_record_root(
                REPLAY_NULLIFIER_SCHEME,
                self.replay_nullifiers
                    .values()
                    .map(|record| record_root(REPLAY_NULLIFIER_SCHEME, &record.public_record()))
                    .collect(),
            ),
            fast_clearing_batch_root: merkle_record_root(
                FAST_CLEARING_BATCH_SCHEME,
                self.fast_batches
                    .values()
                    .map(|record| record_root(FAST_CLEARING_BATCH_SCHEME, &record.public_record()))
                    .collect(),
            ),
            contract_accounting_root: merkle_record_root(
                CONTRACT_ACCOUNTING_SCHEME,
                self.accounting_entries
                    .values()
                    .map(|record| record_root(CONTRACT_ACCOUNTING_SCHEME, &record.public_record()))
                    .collect(),
            ),
            fee_pool_root: merkle_record_root(
                FEE_POOL_SCHEME,
                self.fee_pools
                    .values()
                    .map(|record| record_root(FEE_POOL_SCHEME, &record.public_record()))
                    .collect(),
            ),
            policy_root: self.policy_root(),
            public_record_root: String::new(),
        };
        roots.public_record_root = root_from_value(
            PUBLIC_RECORD_ROOT_SCHEME,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "height": self.current_height,
                "epoch": self.current_epoch,
                "roots_without_public_record_root": {
                    "config_root": roots.config_root,
                    "counters_root": roots.counters_root,
                    "clearing_epoch_root": roots.clearing_epoch_root,
                    "sealed_receipt_order_root": roots.sealed_receipt_order_root,
                    "receipt_match_root": roots.receipt_match_root,
                    "pq_attestation_root": roots.pq_attestation_root,
                    "replay_nullifier_root": roots.replay_nullifier_root,
                    "fast_clearing_batch_root": roots.fast_clearing_batch_root,
                    "contract_accounting_root": roots.contract_accounting_root,
                    "fee_pool_root": roots.fee_pool_root,
                    "policy_root": roots.policy_root,
                }
            }),
        );
        roots
    }

    pub fn state_root(&self) -> String {
        root_from_value(
            "STATE",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "height": self.current_height,
                "epoch": self.current_epoch,
                "roots": self.roots().public_record(),
            }),
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "height": self.current_height,
            "epoch": self.current_epoch,
            "state_root": self.state_root(),
            "roots": roots.public_record(),
            "privacy_policy": {
                "roots_only_public_records": self.config.require_roots_only_public_records,
                "sealed_receipt_payloads_redacted": true,
                "contract_identity_commitments_only": true,
                "encrypted_storage_deltas_redacted": true,
                "fee_pool_balances_commitment_only": true,
                "pq_attestation_roots_only": true,
                "replay_nullifier_roots_only": true,
            },
        })
    }

    fn ensure_epoch_exists(&self, epoch_id: &str) -> Result<()> {
        self.clearing_epochs
            .get(epoch_id)
            .map(|_| ())
            .ok_or_else(|| "unknown clearing epoch".to_string())
    }

    fn orders_in_epoch(&self, epoch_id: &str) -> usize {
        self.sealed_orders
            .values()
            .filter(|order| order.epoch_id == epoch_id)
            .count()
    }

    fn policy_root(&self) -> String {
        root_from_value(
            POLICY_ROOT_SCHEME,
            &json!({
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "target_privacy_set_size": self.config.target_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "quorum_bps": self.config.quorum_bps,
                "fast_finality_quorum_bps": self.config.fast_finality_quorum_bps,
                "low_fee_clearing": self.config.prefer_low_fee_clearing,
                "fast_receipt_settlement": self.config.prefer_fast_receipt_settlement,
            }),
        )
    }

    fn expire_old_records(&mut self) {
        for epoch in self.clearing_epochs.values_mut() {
            if epoch.status.active() && self.current_height > epoch.fast_settlement_deadline_height
            {
                epoch.status = ClearingEpochStatus::Expired;
            }
        }
        for order in self.sealed_orders.values_mut() {
            if order.status.matchable() && self.current_height > order.expires_height {
                order.status = SealedOrderStatus::Expired;
            }
        }
        for nullifier in self.replay_nullifiers.values_mut() {
            if matches!(
                nullifier.status,
                NullifierStatus::Reserved | NullifierStatus::Armed
            ) && self.current_height > nullifier.expires_height
            {
                nullifier.status = NullifierStatus::Expired;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if matches!(
                attestation.status,
                AttestationStatus::Pending | AttestationStatus::Verified
            ) && self.current_height > attestation.expires_height
            {
                attestation.status = AttestationStatus::Expired;
            }
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::devnet()).expect("devnet clearing config is valid");
    let fee_pool_id = state
        .open_fee_pool(FeePoolInput {
            lane: ClearingLane::DefiExecution,
            liquidity_commitment_root: "fee-pool:liquidity:root:defi-clearing".to_string(),
            low_fee_curve_root: "fee-pool:curve:root:low-latency".to_string(),
            operator_set_root: "operator:set:root:pq-clearing-devnet".to_string(),
            opening_balance_commitment: "balance:commitment:fee-pool:opening".to_string(),
            pool_nonce: 1,
        })
        .expect("devnet fee pool opens");
    let epoch_id = state
        .open_clearing_epoch(ClearingEpochInput {
            lane: ClearingLane::DefiExecution,
            storage_namespace_root: "storage:namespace:root:confidential-contracts".to_string(),
            eligible_contract_set_root: "contract:set:root:private-defi-clearing".to_string(),
            fee_pool_root: record_root(
                FEE_POOL_SCHEME,
                &state
                    .fee_pools
                    .get(&fee_pool_id)
                    .expect("fee pool exists")
                    .public_record(),
            ),
            target_receipt_bytes: 524_288,
            target_storage_keys: 65_536,
            min_clearing_micro_fee: 1,
            pq_policy_root: state.policy_root(),
            epoch_nonce: 1,
        })
        .expect("devnet clearing epoch opens");
    let order_id = state
        .submit_sealed_receipt_order(SealedReceiptOrderInput {
            epoch_id: epoch_id.clone(),
            contract_commitment: "contract:commitment:private-dex-router".to_string(),
            payer_note_commitment: "note:commitment:receipt-fee-payer:001".to_string(),
            sealed_receipt_root: "sealed:receipt:root:ml-kem:001".to_string(),
            encrypted_storage_delta_root: "encrypted:storage-delta:root:001".to_string(),
            max_micro_fee: 3,
            receipt_bytes_upper_bound: 131_072,
            storage_keys_upper_bound: 16_384,
            replay_nullifier_root: "nullifier:root:clearing-order:001".to_string(),
            settlement_hint_root: "settlement:hint:root:fast-path:001".to_string(),
            order_nonce: 1,
        })
        .expect("devnet sealed receipt order accepted");
    let match_id = state
        .propose_receipt_match(ReceiptMatchInput {
            epoch_id: epoch_id.clone(),
            order_ids: vec![order_id.clone()],
            fee_pool_id: fee_pool_id.clone(),
            pre_storage_root: "storage:root:before:private-dex-router".to_string(),
            post_storage_root: "storage:root:after:private-dex-router".to_string(),
            matched_receipt_root: "matched:receipt:root:private-dex-router:001".to_string(),
            clearing_price_root: "clearing:price:root:low-fee:001".to_string(),
            accounting_delta_root: "accounting:delta:root:cleared-fee:001".to_string(),
            receipt_bytes: 65_536,
            storage_keys_touched: 8_192,
            match_nonce: 1,
        })
        .expect("devnet receipt match proposed");
    let _executor = state
        .attest_receipt_match(PqClearingAttestationInput {
            match_id: match_id.clone(),
            role: AttestationRole::ClearingExecutor,
            committee_id: "committee:pq-clearing-executors:devnet:01".to_string(),
            signer_set_root: "signer:set:root:clearing-executors:01".to_string(),
            attested_receipt_root: "matched:receipt:root:private-dex-router:001".to_string(),
            attested_storage_root: "storage:root:after:private-dex-router".to_string(),
            pq_public_key_digest: "pq-key:digest:clearing-executor:001".to_string(),
            pq_signature_root: "pq-signature:root:clearing-executor:001".to_string(),
            pq_security_bits: 256,
            quorum_weight_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
            attestation_nonce: 1,
        })
        .expect("devnet executor attests");
    let _verifier = state
        .attest_receipt_match(PqClearingAttestationInput {
            match_id: match_id.clone(),
            role: AttestationRole::ReceiptVerifier,
            committee_id: "committee:pq-receipt-verifiers:devnet:01".to_string(),
            signer_set_root: "signer:set:root:receipt-verifiers:01".to_string(),
            attested_receipt_root: "matched:receipt:root:private-dex-router:001".to_string(),
            attested_storage_root: "storage:root:after:private-dex-router".to_string(),
            pq_public_key_digest: "pq-key:digest:receipt-verifier:001".to_string(),
            pq_signature_root: "pq-signature:root:receipt-verifier:001".to_string(),
            pq_security_bits: 256,
            quorum_weight_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
            attestation_nonce: 2,
        })
        .expect("devnet verifier attests");
    let batch_id = state
        .finalize_fast_clearing_batch(epoch_id, vec![match_id])
        .expect("devnet fast clearing batch finalizes");
    let _accounting = state
        .append_accounting_entry(AccountingEntryInput {
            batch_id,
            contract_commitment: "contract:commitment:private-dex-router".to_string(),
            debit_note_commitment: "note:commitment:debit:private-dex-router".to_string(),
            rebate_note_commitment: "note:commitment:rebate:private-dex-router".to_string(),
            receipt_count: 1,
            storage_keys_touched: 8_192,
            net_micro_fee: 2,
        })
        .expect("devnet accounting appends");
    state
}

fn estimate_clearing_micro_fee(
    config: &Config,
    lane: ClearingLane,
    max_micro_fee: u64,
    privacy_set_size: u64,
) -> u64 {
    let priority_component = lane.priority_weight().saturating_mul(config.base_micro_fee) / MAX_BPS;
    let privacy_discount = if privacy_set_size >= config.target_privacy_set_size {
        bps(max_micro_fee, config.liquidity_discount_bps)
    } else {
        0
    };
    max_micro_fee
        .saturating_add(priority_component)
        .saturating_sub(privacy_discount)
        .max(config.min_micro_fee)
}

fn bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn root_from_value(domain: &str, value: &Value) -> String {
    domain_hash(
        CLEARING_SUITE,
        &[HashPart::Str(domain), HashPart::Json(value)],
        32,
    )
}

fn record_root(domain: &str, value: &Value) -> String {
    root_from_value(domain, value)
}

fn root_from_strings(domain: &str, values: &[String]) -> String {
    root_from_value(domain, &json!({ "domain": domain, "values": values }))
}

fn merkle_record_root(domain: &str, leaves: Vec<String>) -> String {
    if leaves.is_empty() {
        root_from_value(domain, &json!({"empty": true}))
    } else {
        let values = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
        merkle_root(domain, &values)
    }
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must be non-empty"))
    } else {
        Ok(())
    }
}
