use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-storage-receipt-fee-netting-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const NETTING_SUITE: &str = "pq-confidential-contract-sealed-storage-receipt-fee-netting-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-storage-receipt-fee-netting-public-record-v1";
pub const NETTING_CYCLE_SCHEME: &str = "sealed-storage-receipt-fee-netting-cycle-root-v1";
pub const SEALED_RECEIPT_LEG_SCHEME: &str = "sealed-storage-receipt-fee-netting-leg-root-v1";
pub const NETTABLE_POSITION_SCHEME: &str = "confidential-contract-nettable-position-root-v1";
pub const NETTING_MATCH_SCHEME: &str = "sealed-storage-receipt-fee-netting-match-root-v1";
pub const PQ_NETTING_ATTESTATION_SCHEME: &str = "pq-storage-receipt-netting-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "storage-receipt-netting-replay-nullifier-root-v1";
pub const FAST_NETTING_BATCH_SCHEME: &str = "fast-storage-receipt-netting-batch-root-v1";
pub const CONTRACT_ACCOUNTING_SCHEME: &str = "confidential-contract-netting-accounting-root-v1";
pub const FEE_DELTA_SCHEME: &str = "low-fee-netting-delta-root-v1";
pub const POLICY_ROOT_SCHEME: &str = "netting-privacy-pq-policy-root-v1";
pub const PUBLIC_RECORD_ROOT_SCHEME: &str = "storage-receipt-netting-roots-only-public-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_942_784;
pub const DEVNET_EPOCH: u64 = 11_607;
pub const DEFAULT_NETTING_WINDOW_BLOCKS: u64 = 16;
pub const DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 2;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_ACCOUNTING_EPOCH_BLOCKS: u64 = 320;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_MICRO_FEE: u64 = 1;
pub const DEFAULT_BASE_MICRO_FEE: u64 = 2;
pub const DEFAULT_MAX_LEGS_PER_CYCLE: usize = 24_576;
pub const DEFAULT_MAX_POSITIONS_PER_CYCLE: usize = 16_384;
pub const DEFAULT_MAX_MATCHES_PER_BATCH: usize = 8_192;
pub const DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH: u64 = 12_582_912;
pub const DEFAULT_MAX_STORAGE_KEYS_PER_LEG: u64 = 196_608;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 2;
pub const DEFAULT_NETTING_REBATE_BPS: u64 = 18;
pub const DEFAULT_CONGESTION_FEE_BPS: u64 = 5;
pub const DEFAULT_BALANCE_DISCOUNT_BPS: u64 = 9;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_FAST_FINALITY_QUORUM_BPS: u64 = 8_350;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingLane {
    DefiExecution,
    LendingCollateral,
    BridgeSettlement,
    OracleCache,
    GovernanceVault,
    AccountRecovery,
    EmergencyRetention,
    BatchMaintenance,
    ContractPayroll,
    CrossShardStorage,
}

impl NettingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefiExecution => "defi_execution",
            Self::LendingCollateral => "lending_collateral",
            Self::BridgeSettlement => "bridge_settlement",
            Self::OracleCache => "oracle_cache",
            Self::GovernanceVault => "governance_vault",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyRetention => "emergency_retention",
            Self::BatchMaintenance => "batch_maintenance",
            Self::ContractPayroll => "contract_payroll",
            Self::CrossShardStorage => "cross_shard_storage",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyRetention => 10_000,
            Self::AccountRecovery => 9_750,
            Self::BridgeSettlement => 9_400,
            Self::CrossShardStorage => 9_050,
            Self::OracleCache => 8_950,
            Self::LendingCollateral => 8_700,
            Self::DefiExecution => 8_500,
            Self::ContractPayroll => 8_250,
            Self::GovernanceVault => 8_000,
            Self::BatchMaintenance => 7_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingCycleStatus {
    Announced,
    AcceptingSealedLegs,
    Positioning,
    Netting,
    PqAttested,
    FastSettling,
    Settled,
    Cancelled,
    Expired,
}

impl NettingCycleStatus {
    pub fn accepts_legs(self) -> bool {
        matches!(self, Self::Announced | Self::AcceptingSealedLegs)
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::AcceptingSealedLegs
                | Self::Positioning
                | Self::Netting
                | Self::PqAttested
                | Self::FastSettling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLegDirection {
    Debit,
    Credit,
    Rebate,
    Liability,
}

impl ReceiptLegDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debit => "debit",
            Self::Credit => "credit",
            Self::Rebate => "rebate",
            Self::Liability => "liability",
        }
    }

    pub fn sign(self) -> i8 {
        match self {
            Self::Debit | Self::Liability => -1,
            Self::Credit | Self::Rebate => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedReceiptLegStatus {
    Sealed,
    ReplayGuarded,
    PositionBound,
    Nettable,
    Netted,
    Settled,
    Repriced,
    Refunded,
    DuplicateRejected,
    Expired,
}

impl SealedReceiptLegStatus {
    pub fn nettable(self) -> bool {
        matches!(
            self,
            Self::ReplayGuarded | Self::PositionBound | Self::Nettable
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Pending,
    Balanced,
    PartiallyNetted,
    FullyNetted,
    DustRefund,
    Challenged,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingMatchStatus {
    Proposed,
    FeeDeltaBound,
    ExecutorAttested,
    VerifierAttested,
    QuorumReady,
    Included,
    Challenged,
    Rejected,
}

impl NettingMatchStatus {
    pub fn settlement_ready(self) -> bool {
        matches!(
            self,
            Self::FeeDeltaBound
                | Self::ExecutorAttested
                | Self::VerifierAttested
                | Self::QuorumReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    NettingExecutor,
    ReceiptVerifier,
    Watchtower,
    FeeDeltaAuditor,
    PrivacySetAuditor,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NettingExecutor => "netting_executor",
            Self::ReceiptVerifier => "receipt_verifier",
            Self::Watchtower => "watchtower",
            Self::FeeDeltaAuditor => "fee_delta_auditor",
            Self::PrivacySetAuditor => "privacy_set_auditor",
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
pub enum NettingBatchStatus {
    Queued,
    PqQuorum,
    FastFinal,
    Settled,
    Repriced,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub netting_suite: String,
    pub roots_only_public_record_suite: String,
    pub netting_window_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub replay_window_blocks: u64,
    pub accounting_epoch_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_micro_fee: u64,
    pub base_micro_fee: u64,
    pub max_legs_per_cycle: usize,
    pub max_positions_per_cycle: usize,
    pub max_matches_per_batch: usize,
    pub max_receipt_bytes_per_batch: u64,
    pub max_storage_keys_per_leg: u64,
    pub operator_fee_bps: u64,
    pub netting_rebate_bps: u64,
    pub congestion_fee_bps: u64,
    pub balance_discount_bps: u64,
    pub quorum_bps: u64,
    pub fast_finality_quorum_bps: u64,
    pub require_roots_only_public_records: bool,
    pub require_replay_nullifier: bool,
    pub require_pq_attestation: bool,
    pub prefer_low_fee_netting: bool,
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
            netting_suite: NETTING_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            netting_window_blocks: DEFAULT_NETTING_WINDOW_BLOCKS,
            fast_settlement_blocks: DEFAULT_FAST_SETTLEMENT_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            accounting_epoch_blocks: DEFAULT_ACCOUNTING_EPOCH_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_micro_fee: DEFAULT_MIN_MICRO_FEE,
            base_micro_fee: DEFAULT_BASE_MICRO_FEE,
            max_legs_per_cycle: DEFAULT_MAX_LEGS_PER_CYCLE,
            max_positions_per_cycle: DEFAULT_MAX_POSITIONS_PER_CYCLE,
            max_matches_per_batch: DEFAULT_MAX_MATCHES_PER_BATCH,
            max_receipt_bytes_per_batch: DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH,
            max_storage_keys_per_leg: DEFAULT_MAX_STORAGE_KEYS_PER_LEG,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            netting_rebate_bps: DEFAULT_NETTING_REBATE_BPS,
            congestion_fee_bps: DEFAULT_CONGESTION_FEE_BPS,
            balance_discount_bps: DEFAULT_BALANCE_DISCOUNT_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            fast_finality_quorum_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
            require_roots_only_public_records: true,
            require_replay_nullifier: true,
            require_pq_attestation: true,
            prefer_low_fee_netting: true,
            prefer_fast_receipt_settlement: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported sealed storage receipt fee netting protocol".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported sealed storage receipt fee netting schema".to_string());
        }
        if self.netting_window_blocks == 0 || self.fast_settlement_blocks == 0 {
            return Err("netting and settlement windows must be non-zero".to_string());
        }
        if self.replay_window_blocks < self.netting_window_blocks {
            return Err("replay window must cover the netting window".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set bounds are invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("post-quantum security floor is too low".to_string());
        }
        if self.min_micro_fee == 0 || self.base_micro_fee < self.min_micro_fee {
            return Err("fee floor is invalid".to_string());
        }
        if self.max_legs_per_cycle == 0
            || self.max_positions_per_cycle == 0
            || self.max_matches_per_batch == 0
        {
            return Err("netting capacity limits must be non-zero".to_string());
        }
        if self.operator_fee_bps > MAX_BPS
            || self.netting_rebate_bps > MAX_BPS
            || self.congestion_fee_bps > MAX_BPS
            || self.balance_discount_bps > MAX_BPS
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
        payload_root("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub next_cycle_index: u64,
    pub next_leg_index: u64,
    pub next_position_index: u64,
    pub next_match_index: u64,
    pub next_attestation_index: u64,
    pub next_batch_index: u64,
    pub cycles_opened: u64,
    pub sealed_legs_submitted: u64,
    pub nettable_positions_created: u64,
    pub pq_attestations: u64,
    pub duplicate_nullifiers_rejected: u64,
    pub netting_matches_created: u64,
    pub batches_finalized: u64,
    pub legs_netted: u64,
    pub legs_refunded: u64,
    pub total_receipt_bytes_settled: u64,
    pub total_fee_micro_units: u128,
    pub total_net_savings_micro_units: u128,
    pub total_rebate_micro_units: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_cycle_index: 1,
            next_leg_index: 1,
            next_position_index: 1,
            next_match_index: 1,
            next_attestation_index: 1,
            next_batch_index: 1,
            cycles_opened: 0,
            sealed_legs_submitted: 0,
            nettable_positions_created: 0,
            pq_attestations: 0,
            duplicate_nullifiers_rejected: 0,
            netting_matches_created: 0,
            batches_finalized: 0,
            legs_netted: 0,
            legs_refunded: 0,
            total_receipt_bytes_settled: 0,
            total_fee_micro_units: 0,
            total_net_savings_micro_units: 0,
            total_rebate_micro_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("counters serialize")
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
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
    pub netting_cycle_root: String,
    pub sealed_receipt_leg_root: String,
    pub nettable_position_root: String,
    pub netting_match_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
    pub fast_batch_root: String,
    pub accounting_root: String,
    pub fee_delta_root: String,
    pub policy_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("roots serialize")
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettingCycleInput {
    pub lane: NettingLane,
    pub storage_namespace_root: String,
    pub participant_set_root: String,
    pub eligible_contract_set_root: String,
    pub capacity_receipt_bytes: u64,
    pub capacity_storage_keys: u64,
    pub fee_policy_root: String,
    pub pq_policy_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettingCycle {
    pub cycle_id: String,
    pub cycle_index: u64,
    pub lane: NettingLane,
    pub start_height: u64,
    pub close_height: u64,
    pub settlement_deadline_height: u64,
    pub status: NettingCycleStatus,
    pub storage_namespace_root: String,
    pub participant_set_root: String,
    pub eligible_contract_set_root: String,
    pub capacity_receipt_bytes: u64,
    pub capacity_storage_keys: u64,
    pub privacy_set_size: u64,
    pub fee_policy_root: String,
    pub pq_policy_root: String,
}

impl NettingCycle {
    pub fn from_input(
        cycle_index: u64,
        height: u64,
        config: &Config,
        input: NettingCycleInput,
    ) -> Result<Self> {
        require_non_empty("storage_namespace_root", &input.storage_namespace_root)?;
        require_non_empty("participant_set_root", &input.participant_set_root)?;
        require_non_empty(
            "eligible_contract_set_root",
            &input.eligible_contract_set_root,
        )?;
        require_non_empty("fee_policy_root", &input.fee_policy_root)?;
        require_non_empty("pq_policy_root", &input.pq_policy_root)?;
        let cycle_id = netting_cycle_id(
            input.lane,
            &input.storage_namespace_root,
            &input.participant_set_root,
            cycle_index,
        );
        Ok(Self {
            cycle_id,
            cycle_index,
            lane: input.lane,
            start_height: height,
            close_height: height.saturating_add(config.netting_window_blocks),
            settlement_deadline_height: height
                .saturating_add(config.netting_window_blocks)
                .saturating_add(config.fast_settlement_blocks),
            status: NettingCycleStatus::AcceptingSealedLegs,
            storage_namespace_root: input.storage_namespace_root,
            participant_set_root: input.participant_set_root,
            eligible_contract_set_root: input.eligible_contract_set_root,
            capacity_receipt_bytes: input.capacity_receipt_bytes,
            capacity_storage_keys: input.capacity_storage_keys,
            privacy_set_size: input
                .capacity_storage_keys
                .saturating_mul(input.capacity_receipt_bytes.max(1))
                .max(config.min_privacy_set_size),
            fee_policy_root: input.fee_policy_root,
            pq_policy_root: input.pq_policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cycle_id": self.cycle_id,
            "cycle_index": self.cycle_index,
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "close_height": self.close_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "status": self.status,
            "storage_namespace_root": self.storage_namespace_root,
            "participant_set_root": self.participant_set_root,
            "eligible_contract_set_root": self.eligible_contract_set_root,
            "capacity_receipt_bytes": self.capacity_receipt_bytes,
            "capacity_storage_keys": self.capacity_storage_keys,
            "privacy_set_size": self.privacy_set_size,
            "fee_policy_root": self.fee_policy_root,
            "pq_policy_root": self.pq_policy_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("NETTING_CYCLE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedReceiptLegInput {
    pub cycle_id: String,
    pub contract_commitment: String,
    pub counterparty_commitment: String,
    pub direction: ReceiptLegDirection,
    pub sealed_receipt_root: String,
    pub encrypted_fee_delta_root: String,
    pub max_micro_fee: u64,
    pub receipt_bytes: u64,
    pub storage_keys: u64,
    pub replay_nullifier_root: String,
    pub pq_commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedReceiptLeg {
    pub leg_id: String,
    pub leg_index: u64,
    pub cycle_id: String,
    pub contract_commitment: String,
    pub counterparty_commitment: String,
    pub direction: ReceiptLegDirection,
    pub sealed_receipt_root: String,
    pub encrypted_fee_delta_root: String,
    pub estimated_micro_fee: u64,
    pub receipt_bytes: u64,
    pub storage_keys: u64,
    pub replay_nullifier_root: String,
    pub pq_commitment_root: String,
    pub status: SealedReceiptLegStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl SealedReceiptLeg {
    pub fn from_input(
        leg_index: u64,
        height: u64,
        cycle: &NettingCycle,
        config: &Config,
        input: SealedReceiptLegInput,
    ) -> Result<Self> {
        if input.cycle_id != cycle.cycle_id {
            return Err("sealed leg targets a different netting cycle".to_string());
        }
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("counterparty_commitment", &input.counterparty_commitment)?;
        require_non_empty("sealed_receipt_root", &input.sealed_receipt_root)?;
        require_non_empty("encrypted_fee_delta_root", &input.encrypted_fee_delta_root)?;
        require_non_empty("replay_nullifier_root", &input.replay_nullifier_root)?;
        require_non_empty("pq_commitment_root", &input.pq_commitment_root)?;
        if input.storage_keys > config.max_storage_keys_per_leg {
            return Err("sealed receipt leg exceeds storage key limit".to_string());
        }
        let leg_id = sealed_receipt_leg_id(
            &input.cycle_id,
            &input.contract_commitment,
            &input.sealed_receipt_root,
            leg_index,
        );
        let estimated_micro_fee = estimate_netting_fee_micro_units(
            config,
            cycle.lane,
            input.max_micro_fee,
            input.receipt_bytes,
        );
        Ok(Self {
            leg_id,
            leg_index,
            cycle_id: input.cycle_id,
            contract_commitment: input.contract_commitment,
            counterparty_commitment: input.counterparty_commitment,
            direction: input.direction,
            sealed_receipt_root: input.sealed_receipt_root,
            encrypted_fee_delta_root: input.encrypted_fee_delta_root,
            estimated_micro_fee,
            receipt_bytes: input.receipt_bytes,
            storage_keys: input.storage_keys,
            replay_nullifier_root: input.replay_nullifier_root,
            pq_commitment_root: input.pq_commitment_root,
            status: SealedReceiptLegStatus::ReplayGuarded,
            submitted_height: height,
            expires_height: height.saturating_add(config.replay_window_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "leg_id": self.leg_id,
            "leg_index": self.leg_index,
            "cycle_id": self.cycle_id,
            "contract_commitment": self.contract_commitment,
            "counterparty_commitment": self.counterparty_commitment,
            "direction": self.direction.as_str(),
            "sealed_receipt_root": self.sealed_receipt_root,
            "encrypted_fee_delta_root": self.encrypted_fee_delta_root,
            "estimated_micro_fee": self.estimated_micro_fee,
            "receipt_bytes": self.receipt_bytes,
            "storage_keys": self.storage_keys,
            "replay_nullifier_root": self.replay_nullifier_root,
            "pq_commitment_root": self.pq_commitment_root,
            "status": self.status,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SEALED_RECEIPT_LEG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettablePositionInput {
    pub cycle_id: String,
    pub contract_commitment: String,
    pub position_commitment_root: String,
    pub debit_leg_root: String,
    pub credit_leg_root: String,
    pub encrypted_net_amount_root: String,
    pub privacy_bucket_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettablePosition {
    pub position_id: String,
    pub position_index: u64,
    pub cycle_id: String,
    pub contract_commitment: String,
    pub position_commitment_root: String,
    pub debit_leg_root: String,
    pub credit_leg_root: String,
    pub encrypted_net_amount_root: String,
    pub privacy_bucket_root: String,
    pub status: PositionStatus,
    pub created_height: u64,
}

impl NettablePosition {
    pub fn from_input(
        position_index: u64,
        height: u64,
        input: NettablePositionInput,
    ) -> Result<Self> {
        require_non_empty("cycle_id", &input.cycle_id)?;
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("position_commitment_root", &input.position_commitment_root)?;
        require_non_empty("debit_leg_root", &input.debit_leg_root)?;
        require_non_empty("credit_leg_root", &input.credit_leg_root)?;
        require_non_empty(
            "encrypted_net_amount_root",
            &input.encrypted_net_amount_root,
        )?;
        require_non_empty("privacy_bucket_root", &input.privacy_bucket_root)?;
        let position_id = nettable_position_id(
            &input.cycle_id,
            &input.contract_commitment,
            &input.position_commitment_root,
            position_index,
        );
        Ok(Self {
            position_id,
            position_index,
            cycle_id: input.cycle_id,
            contract_commitment: input.contract_commitment,
            position_commitment_root: input.position_commitment_root,
            debit_leg_root: input.debit_leg_root,
            credit_leg_root: input.credit_leg_root,
            encrypted_net_amount_root: input.encrypted_net_amount_root,
            privacy_bucket_root: input.privacy_bucket_root,
            status: PositionStatus::Pending,
            created_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "position_index": self.position_index,
            "cycle_id": self.cycle_id,
            "contract_commitment": self.contract_commitment,
            "position_commitment_root": self.position_commitment_root,
            "debit_leg_root": self.debit_leg_root,
            "credit_leg_root": self.credit_leg_root,
            "encrypted_net_amount_root": self.encrypted_net_amount_root,
            "privacy_bucket_root": self.privacy_bucket_root,
            "status": self.status,
            "created_height": self.created_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("NETTABLE_POSITION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettingMatchInput {
    pub cycle_id: String,
    pub position_ids: Vec<String>,
    pub matched_leg_ids: Vec<String>,
    pub aggregate_fee_delta_root: String,
    pub balanced_storage_delta_root: String,
    pub settlement_lane_root: String,
    pub pq_witness_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NettingMatch {
    pub match_id: String,
    pub match_index: u64,
    pub cycle_id: String,
    pub position_ids: Vec<String>,
    pub matched_leg_ids: Vec<String>,
    pub aggregate_fee_delta_root: String,
    pub balanced_storage_delta_root: String,
    pub settlement_lane_root: String,
    pub pq_witness_root: String,
    pub status: NettingMatchStatus,
    pub estimated_gross_micro_fee: u64,
    pub estimated_net_micro_fee: u64,
    pub estimated_savings_micro_fee: u64,
    pub receipt_bytes: u64,
    pub created_height: u64,
}

impl NettingMatch {
    pub fn from_input(
        match_index: u64,
        height: u64,
        config: &Config,
        gross_micro_fee: u64,
        receipt_bytes: u64,
        input: NettingMatchInput,
    ) -> Result<Self> {
        require_non_empty("cycle_id", &input.cycle_id)?;
        require_non_empty("aggregate_fee_delta_root", &input.aggregate_fee_delta_root)?;
        require_non_empty(
            "balanced_storage_delta_root",
            &input.balanced_storage_delta_root,
        )?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("pq_witness_root", &input.pq_witness_root)?;
        if input.position_ids.is_empty() || input.matched_leg_ids.is_empty() {
            return Err("netting match requires positions and sealed legs".to_string());
        }
        let match_id = netting_match_id(
            &input.cycle_id,
            &input.aggregate_fee_delta_root,
            &input.settlement_lane_root,
            match_index,
        );
        let discount = gross_micro_fee.saturating_mul(config.balance_discount_bps) / MAX_BPS;
        let rebate = gross_micro_fee.saturating_mul(config.netting_rebate_bps) / MAX_BPS;
        let estimated_net_micro_fee = gross_micro_fee
            .saturating_sub(discount)
            .saturating_sub(rebate)
            .max(config.min_micro_fee);
        Ok(Self {
            match_id,
            match_index,
            cycle_id: input.cycle_id,
            position_ids: input.position_ids,
            matched_leg_ids: input.matched_leg_ids,
            aggregate_fee_delta_root: input.aggregate_fee_delta_root,
            balanced_storage_delta_root: input.balanced_storage_delta_root,
            settlement_lane_root: input.settlement_lane_root,
            pq_witness_root: input.pq_witness_root,
            status: NettingMatchStatus::FeeDeltaBound,
            estimated_gross_micro_fee: gross_micro_fee,
            estimated_net_micro_fee,
            estimated_savings_micro_fee: gross_micro_fee.saturating_sub(estimated_net_micro_fee),
            receipt_bytes,
            created_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "match_id": self.match_id,
            "match_index": self.match_index,
            "cycle_id": self.cycle_id,
            "position_ids": self.position_ids,
            "matched_leg_ids": self.matched_leg_ids,
            "aggregate_fee_delta_root": self.aggregate_fee_delta_root,
            "balanced_storage_delta_root": self.balanced_storage_delta_root,
            "settlement_lane_root": self.settlement_lane_root,
            "pq_witness_root": self.pq_witness_root,
            "status": self.status,
            "estimated_gross_micro_fee": self.estimated_gross_micro_fee,
            "estimated_net_micro_fee": self.estimated_net_micro_fee,
            "estimated_savings_micro_fee": self.estimated_savings_micro_fee,
            "receipt_bytes": self.receipt_bytes,
            "created_height": self.created_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("NETTING_MATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqNettingAttestationInput {
    pub match_id: String,
    pub committee_id: String,
    pub role: AttestationRole,
    pub attestation_root: String,
    pub aggregate_signature_root: String,
    pub signer_set_root: String,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqNettingAttestation {
    pub attestation_id: String,
    pub attestation_index: u64,
    pub match_id: String,
    pub committee_id: String,
    pub role: AttestationRole,
    pub attestation_root: String,
    pub aggregate_signature_root: String,
    pub signer_set_root: String,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub status: AttestationStatus,
    pub verified_height: u64,
}

impl PqNettingAttestation {
    pub fn from_input(
        attestation_index: u64,
        height: u64,
        config: &Config,
        input: PqNettingAttestationInput,
    ) -> Result<Self> {
        require_non_empty("match_id", &input.match_id)?;
        require_non_empty("committee_id", &input.committee_id)?;
        require_non_empty("attestation_root", &input.attestation_root)?;
        require_non_empty("aggregate_signature_root", &input.aggregate_signature_root)?;
        require_non_empty("signer_set_root", &input.signer_set_root)?;
        if input.pq_security_bits < config.min_pq_security_bits {
            return Err("post-quantum attestation security is below policy".to_string());
        }
        if input.quorum_bps < config.quorum_bps || input.quorum_bps > MAX_BPS {
            return Err("attestation quorum is outside policy".to_string());
        }
        let attestation_id = pq_netting_attestation_id(
            &input.match_id,
            &input.committee_id,
            input.role,
            attestation_index,
        );
        Ok(Self {
            attestation_id,
            attestation_index,
            match_id: input.match_id,
            committee_id: input.committee_id,
            role: input.role,
            attestation_root: input.attestation_root,
            aggregate_signature_root: input.aggregate_signature_root,
            signer_set_root: input.signer_set_root,
            pq_security_bits: input.pq_security_bits,
            quorum_bps: input.quorum_bps,
            status: AttestationStatus::Verified,
            verified_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attestation_index": self.attestation_index,
            "match_id": self.match_id,
            "committee_id": self.committee_id,
            "role": self.role.as_str(),
            "attestation_root": self.attestation_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "signer_set_root": self.signer_set_root,
            "pq_security_bits": self.pq_security_bits,
            "quorum_bps": self.quorum_bps,
            "status": self.status,
            "verified_height": self.verified_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PQ_NETTING_ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FastNettingBatchInput {
    pub operator_commitment: String,
    pub settlement_lane_root: String,
    pub match_ids: Vec<String>,
    pub netted_position_root: String,
    pub fee_delta_root: String,
    pub accounting_root: String,
    pub final_storage_root: String,
    pub batch_signature_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FastNettingBatch {
    pub batch_id: String,
    pub batch_index: u64,
    pub operator_commitment: String,
    pub settlement_lane_root: String,
    pub match_ids: Vec<String>,
    pub netted_position_root: String,
    pub fee_delta_root: String,
    pub accounting_root: String,
    pub final_storage_root: String,
    pub batch_signature_root: String,
    pub total_net_micro_fee: u64,
    pub total_savings_micro_fee: u64,
    pub total_receipt_bytes: u64,
    pub status: NettingBatchStatus,
    pub settled_height: u64,
}

impl FastNettingBatch {
    pub fn from_input(
        batch_index: u64,
        height: u64,
        total_net_micro_fee: u64,
        total_savings_micro_fee: u64,
        total_receipt_bytes: u64,
        input: FastNettingBatchInput,
    ) -> Result<Self> {
        require_non_empty("operator_commitment", &input.operator_commitment)?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("netted_position_root", &input.netted_position_root)?;
        require_non_empty("fee_delta_root", &input.fee_delta_root)?;
        require_non_empty("accounting_root", &input.accounting_root)?;
        require_non_empty("final_storage_root", &input.final_storage_root)?;
        require_non_empty("batch_signature_root", &input.batch_signature_root)?;
        if input.match_ids.is_empty() {
            return Err("fast netting batch requires at least one match".to_string());
        }
        let batch_id = fast_netting_batch_id(
            &input.operator_commitment,
            &input.settlement_lane_root,
            height,
            batch_index,
        );
        Ok(Self {
            batch_id,
            batch_index,
            operator_commitment: input.operator_commitment,
            settlement_lane_root: input.settlement_lane_root,
            match_ids: input.match_ids,
            netted_position_root: input.netted_position_root,
            fee_delta_root: input.fee_delta_root,
            accounting_root: input.accounting_root,
            final_storage_root: input.final_storage_root,
            batch_signature_root: input.batch_signature_root,
            total_net_micro_fee,
            total_savings_micro_fee,
            total_receipt_bytes,
            status: NettingBatchStatus::FastFinal,
            settled_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "batch_index": self.batch_index,
            "operator_commitment": self.operator_commitment,
            "settlement_lane_root": self.settlement_lane_root,
            "match_ids": self.match_ids,
            "netted_position_root": self.netted_position_root,
            "fee_delta_root": self.fee_delta_root,
            "accounting_root": self.accounting_root,
            "final_storage_root": self.final_storage_root,
            "batch_signature_root": self.batch_signature_root,
            "total_net_micro_fee": self.total_net_micro_fee,
            "total_savings_micro_fee": self.total_savings_micro_fee,
            "total_receipt_bytes": self.total_receipt_bytes,
            "status": self.status,
            "settled_height": self.settled_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FAST_NETTING_BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub netting_cycles: BTreeMap<String, NettingCycle>,
    pub sealed_receipt_legs: BTreeMap<String, SealedReceiptLeg>,
    pub nettable_positions: BTreeMap<String, NettablePosition>,
    pub netting_matches: BTreeMap<String, NettingMatch>,
    pub pq_attestations: BTreeMap<String, PqNettingAttestation>,
    pub fast_batches: BTreeMap<String, FastNettingBatch>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub accounting_roots: BTreeMap<String, String>,
    pub fee_delta_roots: BTreeMap<String, String>,
    pub policy_roots: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            counters: Counters::new(),
            roots: Roots::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            netting_cycles: BTreeMap::new(),
            sealed_receipt_legs: BTreeMap::new(),
            nettable_positions: BTreeMap::new(),
            netting_matches: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            fast_batches: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            accounting_roots: BTreeMap::new(),
            fee_delta_roots: BTreeMap::new(),
            policy_roots: BTreeSet::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        if self.roots.public_record_root.is_empty() {
            return Err("state roots have not been computed".to_string());
        }
        Ok(())
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("cannot move netting runtime height backwards".to_string());
        }
        self.height = height;
        self.epoch = self.height / self.config.accounting_epoch_blocks.max(1);
        self.expire_stale_records();
        self.recompute_roots();
        Ok(())
    }

    pub fn open_cycle(&mut self, input: NettingCycleInput) -> Result<String> {
        self.config.validate()?;
        if self.netting_cycles.len() >= self.config.max_positions_per_cycle {
            return Err("netting cycle registry capacity exhausted".to_string());
        }
        let cycle_index = self.counters.next_cycle_index;
        let cycle = NettingCycle::from_input(cycle_index, self.height, &self.config, input)?;
        let cycle_id = cycle.cycle_id.clone();
        self.policy_roots.insert(cycle.fee_policy_root.clone());
        self.policy_roots.insert(cycle.pq_policy_root.clone());
        self.netting_cycles.insert(cycle_id.clone(), cycle);
        self.counters.next_cycle_index = self.counters.next_cycle_index.saturating_add(1);
        self.counters.cycles_opened = self.counters.cycles_opened.saturating_add(1);
        self.recompute_roots();
        Ok(cycle_id)
    }

    pub fn submit_sealed_leg(&mut self, input: SealedReceiptLegInput) -> Result<String> {
        self.config.validate()?;
        let cycle = self
            .netting_cycles
            .get(&input.cycle_id)
            .ok_or_else(|| "netting cycle not found".to_string())?;
        if !cycle.status.accepts_legs() || self.height > cycle.close_height {
            return Err("netting cycle is not accepting sealed legs".to_string());
        }
        if self.sealed_receipt_legs.len() >= self.config.max_legs_per_cycle {
            return Err("sealed receipt leg capacity exhausted".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&input.replay_nullifier_root)
        {
            self.counters.duplicate_nullifiers_rejected = self
                .counters
                .duplicate_nullifiers_rejected
                .saturating_add(1);
            self.recompute_roots();
            return Err("duplicate sealed receipt replay nullifier".to_string());
        }
        let nullifier = input.replay_nullifier_root.clone();
        let leg_index = self.counters.next_leg_index;
        let leg = SealedReceiptLeg::from_input(leg_index, self.height, cycle, &self.config, input)?;
        let leg_id = leg.leg_id.clone();
        self.consumed_nullifier_roots.insert(nullifier);
        self.sealed_receipt_legs.insert(leg_id.clone(), leg);
        self.counters.next_leg_index = self.counters.next_leg_index.saturating_add(1);
        self.counters.sealed_legs_submitted = self.counters.sealed_legs_submitted.saturating_add(1);
        self.recompute_roots();
        Ok(leg_id)
    }

    pub fn bind_position(&mut self, input: NettablePositionInput) -> Result<String> {
        self.config.validate()?;
        if !self.netting_cycles.contains_key(&input.cycle_id) {
            return Err("netting cycle not found".to_string());
        }
        if self.nettable_positions.len() >= self.config.max_positions_per_cycle {
            return Err("nettable position capacity exhausted".to_string());
        }
        let position_index = self.counters.next_position_index;
        let position = NettablePosition::from_input(position_index, self.height, input)?;
        let position_id = position.position_id.clone();
        self.nettable_positions
            .insert(position_id.clone(), position);
        self.counters.next_position_index = self.counters.next_position_index.saturating_add(1);
        self.counters.nettable_positions_created =
            self.counters.nettable_positions_created.saturating_add(1);
        self.recompute_roots();
        Ok(position_id)
    }

    pub fn create_match(&mut self, input: NettingMatchInput) -> Result<String> {
        self.config.validate()?;
        if self.netting_matches.len() >= self.config.max_matches_per_batch {
            return Err("netting match capacity exhausted".to_string());
        }
        let mut gross_micro_fee = 0u64;
        let mut receipt_bytes = 0u64;
        for leg_id in &input.matched_leg_ids {
            let leg = self
                .sealed_receipt_legs
                .get(leg_id)
                .ok_or_else(|| format!("sealed receipt leg not found: {leg_id}"))?;
            if !leg.status.nettable() {
                return Err(format!("sealed receipt leg is not nettable: {leg_id}"));
            }
            gross_micro_fee = gross_micro_fee.saturating_add(leg.estimated_micro_fee);
            receipt_bytes = receipt_bytes.saturating_add(leg.receipt_bytes);
        }
        if receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("netting match exceeds receipt byte limit".to_string());
        }
        for position_id in &input.position_ids {
            if !self.nettable_positions.contains_key(position_id) {
                return Err(format!("nettable position not found: {position_id}"));
            }
        }
        let match_index = self.counters.next_match_index;
        let netting_match = NettingMatch::from_input(
            match_index,
            self.height,
            &self.config,
            gross_micro_fee,
            receipt_bytes,
            input,
        )?;
        let match_id = netting_match.match_id.clone();
        for leg_id in &netting_match.matched_leg_ids {
            if let Some(leg) = self.sealed_receipt_legs.get_mut(leg_id) {
                leg.status = SealedReceiptLegStatus::Netted;
            }
        }
        for position_id in &netting_match.position_ids {
            if let Some(position) = self.nettable_positions.get_mut(position_id) {
                position.status = PositionStatus::PartiallyNetted;
            }
        }
        self.fee_delta_roots.insert(
            match_id.clone(),
            netting_match.aggregate_fee_delta_root.clone(),
        );
        self.netting_matches.insert(match_id.clone(), netting_match);
        self.counters.next_match_index = self.counters.next_match_index.saturating_add(1);
        self.counters.netting_matches_created =
            self.counters.netting_matches_created.saturating_add(1);
        self.recompute_roots();
        Ok(match_id)
    }

    pub fn attest_match(&mut self, input: PqNettingAttestationInput) -> Result<String> {
        self.config.validate()?;
        let netting_match = self
            .netting_matches
            .get_mut(&input.match_id)
            .ok_or_else(|| "netting match not found".to_string())?;
        if !netting_match.status.settlement_ready() {
            return Err("netting match is not ready for attestation".to_string());
        }
        let attestation_index = self.counters.next_attestation_index;
        let attestation =
            PqNettingAttestation::from_input(attestation_index, self.height, &self.config, input)?;
        match attestation.role {
            AttestationRole::NettingExecutor => {
                netting_match.status = NettingMatchStatus::ExecutorAttested;
            }
            AttestationRole::ReceiptVerifier
            | AttestationRole::FeeDeltaAuditor
            | AttestationRole::PrivacySetAuditor => {
                netting_match.status = NettingMatchStatus::VerifierAttested;
            }
            AttestationRole::Watchtower => {
                netting_match.status = NettingMatchStatus::QuorumReady;
            }
        }
        let attestation_id = attestation.attestation_id.clone();
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.next_attestation_index =
            self.counters.next_attestation_index.saturating_add(1);
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn finalize_batch(&mut self, input: FastNettingBatchInput) -> Result<String> {
        self.config.validate()?;
        if input.match_ids.len() > self.config.max_matches_per_batch {
            return Err("fast batch exceeds match count limit".to_string());
        }
        let mut total_net_micro_fee = 0u64;
        let mut total_savings_micro_fee = 0u64;
        let mut total_receipt_bytes = 0u64;
        for match_id in &input.match_ids {
            let netting_match = self
                .netting_matches
                .get(match_id)
                .ok_or_else(|| format!("netting match not found: {match_id}"))?;
            if !netting_match.status.settlement_ready() {
                return Err(format!("netting match is not settlement ready: {match_id}"));
            }
            total_net_micro_fee =
                total_net_micro_fee.saturating_add(netting_match.estimated_net_micro_fee);
            total_savings_micro_fee =
                total_savings_micro_fee.saturating_add(netting_match.estimated_savings_micro_fee);
            total_receipt_bytes = total_receipt_bytes.saturating_add(netting_match.receipt_bytes);
        }
        if total_receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("fast batch exceeds receipt byte limit".to_string());
        }
        let batch_index = self.counters.next_batch_index;
        let batch = FastNettingBatch::from_input(
            batch_index,
            self.height,
            total_net_micro_fee,
            total_savings_micro_fee,
            total_receipt_bytes,
            input,
        )?;
        let batch_id = batch.batch_id.clone();
        for match_id in &batch.match_ids {
            if let Some(netting_match) = self.netting_matches.get_mut(match_id) {
                netting_match.status = NettingMatchStatus::Included;
                for leg_id in &netting_match.matched_leg_ids {
                    if let Some(leg) = self.sealed_receipt_legs.get_mut(leg_id) {
                        leg.status = SealedReceiptLegStatus::Settled;
                    }
                }
                for position_id in &netting_match.position_ids {
                    if let Some(position) = self.nettable_positions.get_mut(position_id) {
                        position.status = PositionStatus::FullyNetted;
                    }
                }
            }
        }
        self.accounting_roots
            .insert(batch_id.clone(), batch.accounting_root.clone());
        self.fee_delta_roots
            .insert(batch_id.clone(), batch.fee_delta_root.clone());
        self.fast_batches.insert(batch_id.clone(), batch);
        self.counters.next_batch_index = self.counters.next_batch_index.saturating_add(1);
        self.counters.batches_finalized = self.counters.batches_finalized.saturating_add(1);
        self.counters.legs_netted = self
            .counters
            .legs_netted
            .saturating_add(total_receipt_bytes);
        self.counters.total_receipt_bytes_settled = self
            .counters
            .total_receipt_bytes_settled
            .saturating_add(total_receipt_bytes);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(total_net_micro_fee as u128);
        self.counters.total_net_savings_micro_units = self
            .counters
            .total_net_savings_micro_units
            .saturating_add(total_savings_micro_fee as u128);
        self.counters.total_rebate_micro_units =
            self.counters.total_rebate_micro_units.saturating_add(
                (total_net_micro_fee.saturating_mul(self.config.netting_rebate_bps) / MAX_BPS)
                    as u128,
            );
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "fee_asset_id": self.config.fee_asset_id,
            "height": self.height,
            "epoch": self.epoch,
            "roots_only": true,
            "roots": self.roots.public_record(),
            "counters_root": self.roots.counters_root,
            "netting_cycle_root": self.roots.netting_cycle_root,
            "sealed_receipt_leg_root": self.roots.sealed_receipt_leg_root,
            "nettable_position_root": self.roots.nettable_position_root,
            "netting_match_root": self.roots.netting_match_root,
            "pq_attestation_root": self.roots.pq_attestation_root,
            "replay_nullifier_root": self.roots.replay_nullifier_root,
            "fast_batch_root": self.roots.fast_batch_root,
            "accounting_root": self.roots.accounting_root,
            "fee_delta_root": self.roots.fee_delta_root,
            "policy_root": self.roots.policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn recompute_roots(&mut self) {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            netting_cycle_root: record_root(
                NETTING_CYCLE_SCHEME,
                &self
                    .netting_cycles
                    .values()
                    .map(NettingCycle::public_record)
                    .collect::<Vec<_>>(),
            ),
            sealed_receipt_leg_root: record_root(
                SEALED_RECEIPT_LEG_SCHEME,
                &self
                    .sealed_receipt_legs
                    .values()
                    .map(SealedReceiptLeg::public_record)
                    .collect::<Vec<_>>(),
            ),
            nettable_position_root: record_root(
                NETTABLE_POSITION_SCHEME,
                &self
                    .nettable_positions
                    .values()
                    .map(NettablePosition::public_record)
                    .collect::<Vec<_>>(),
            ),
            netting_match_root: record_root(
                NETTING_MATCH_SCHEME,
                &self
                    .netting_matches
                    .values()
                    .map(NettingMatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: record_root(
                PQ_NETTING_ATTESTATION_SCHEME,
                &self
                    .pq_attestations
                    .values()
                    .map(PqNettingAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            replay_nullifier_root: record_root(
                REPLAY_NULLIFIER_SCHEME,
                &self
                    .consumed_nullifier_roots
                    .iter()
                    .map(|root| json!({ "nullifier_root": root }))
                    .collect::<Vec<_>>(),
            ),
            fast_batch_root: record_root(
                FAST_NETTING_BATCH_SCHEME,
                &self
                    .fast_batches
                    .values()
                    .map(FastNettingBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            accounting_root: record_root(
                CONTRACT_ACCOUNTING_SCHEME,
                &self
                    .accounting_roots
                    .iter()
                    .map(|(batch_id, accounting_root)| {
                        json!({
                            "batch_id": batch_id,
                            "accounting_root": accounting_root,
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            fee_delta_root: record_root(
                FEE_DELTA_SCHEME,
                &self
                    .fee_delta_roots
                    .iter()
                    .map(|(owner_id, fee_delta_root)| {
                        json!({
                            "owner_id": owner_id,
                            "fee_delta_root": fee_delta_root,
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            policy_root: record_root(
                POLICY_ROOT_SCHEME,
                &self
                    .policy_roots
                    .iter()
                    .map(|root| json!({ "policy_root": root }))
                    .collect::<Vec<_>>(),
            ),
            public_record_root: String::new(),
        };
        roots.public_record_root = payload_root(
            PUBLIC_RECORD_ROOT_SCHEME,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "height": self.height,
                "epoch": self.epoch,
                "roots_without_public_record_root": {
                    "config_root": roots.config_root,
                    "counters_root": roots.counters_root,
                    "netting_cycle_root": roots.netting_cycle_root,
                    "sealed_receipt_leg_root": roots.sealed_receipt_leg_root,
                    "nettable_position_root": roots.nettable_position_root,
                    "netting_match_root": roots.netting_match_root,
                    "pq_attestation_root": roots.pq_attestation_root,
                    "replay_nullifier_root": roots.replay_nullifier_root,
                    "fast_batch_root": roots.fast_batch_root,
                    "accounting_root": roots.accounting_root,
                    "fee_delta_root": roots.fee_delta_root,
                    "policy_root": roots.policy_root,
                },
            }),
        );
        self.roots = roots;
    }

    fn expire_stale_records(&mut self) {
        for cycle in self.netting_cycles.values_mut() {
            if cycle.status.active() && self.height > cycle.settlement_deadline_height {
                cycle.status = NettingCycleStatus::Expired;
            }
        }
        for leg in self.sealed_receipt_legs.values_mut() {
            if matches!(
                leg.status,
                SealedReceiptLegStatus::Sealed
                    | SealedReceiptLegStatus::ReplayGuarded
                    | SealedReceiptLegStatus::PositionBound
                    | SealedReceiptLegStatus::Nettable
            ) && self.height > leg.expires_height
            {
                leg.status = SealedReceiptLegStatus::Expired;
            }
        }
        for position in self.nettable_positions.values_mut() {
            if matches!(position.status, PositionStatus::Pending) {
                let age = self.height.saturating_sub(position.created_height);
                if age > self.config.replay_window_blocks {
                    position.status = PositionStatus::Expired;
                }
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

pub fn netting_cycle_id(
    lane: NettingLane,
    storage_namespace_root: &str,
    participant_set_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING:CYCLE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(storage_namespace_root),
            HashPart::Str(participant_set_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn sealed_receipt_leg_id(
    cycle_id: &str,
    contract_commitment: &str,
    sealed_receipt_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING:LEG-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cycle_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(sealed_receipt_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn nettable_position_id(
    cycle_id: &str,
    contract_commitment: &str,
    position_commitment_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING:POSITION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cycle_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(position_commitment_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn netting_match_id(
    cycle_id: &str,
    aggregate_fee_delta_root: &str,
    settlement_lane_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING:MATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(cycle_id),
            HashPart::Str(aggregate_fee_delta_root),
            HashPart::Str(settlement_lane_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_netting_attestation_id(
    match_id: &str,
    committee_id: &str,
    role: AttestationRole,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING:ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(match_id),
            HashPart::Str(committee_id),
            HashPart::Str(role.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn fast_netting_batch_id(
    operator_commitment: &str,
    settlement_lane_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING:BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_commitment),
            HashPart::Str(settlement_lane_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn estimate_netting_fee_micro_units(
    config: &Config,
    lane: NettingLane,
    max_micro_fee: u64,
    receipt_bytes: u64,
) -> u64 {
    let byte_component = receipt_bytes.saturating_add(2047) / 2048;
    let priority_discount = lane.priority_weight() / 1_500;
    let mut fee = max_micro_fee
        .max(config.base_micro_fee)
        .saturating_add(byte_component)
        .saturating_add(config.operator_fee_bps)
        .saturating_add(config.congestion_fee_bps)
        .saturating_sub(priority_discount);
    fee = fee.saturating_sub(fee.saturating_mul(config.netting_rebate_bps) / MAX_BPS);
    fee.max(config.min_micro_fee)
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING:PAYLOAD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
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

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}
