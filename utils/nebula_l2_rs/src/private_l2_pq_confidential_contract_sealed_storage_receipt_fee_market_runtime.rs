use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStorageReceiptFeeMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedStorageReceiptFeeMarketRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-storage-receipt-fee-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const STORAGE_RECEIPT_FEE_MARKET_SUITE: &str =
    "sealed-confidential-smart-contract-storage-receipt-fee-market-v1";
pub const PQ_EXECUTOR_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-storage-executor-attestation-v1";
pub const PQ_VERIFIER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-storage-verifier-attestation-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-public-record-storage-receipt-fee-market-v1";
pub const MARKET_WINDOW_SCHEME: &str = "sealed-storage-receipt-market-window-root-v1";
pub const PRIVATE_BID_SCHEME: &str = "private-storage-receipt-fee-bid-root-v1";
pub const TRANSITION_COMMITMENT_SCHEME: &str = "encrypted-storage-transition-commitment-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-storage-receipt-executor-verifier-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "storage-receipt-replay-nullifier-root-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str = "low-fee-storage-receipt-settlement-batch-root-v1";
pub const SUBSCRIPTION_ROOT_SCHEME: &str = "storage-receipt-contract-subscription-root-v1";
pub const ACCOUNTING_ROOT_SCHEME: &str = "storage-receipt-accounting-root-v1";
pub const REBATE_ROOT_SCHEME: &str = "storage-rent-rebate-accounting-root-v1";
pub const PUBLIC_RECORD_ROOT_SCHEME: &str = "storage-receipt-roots-only-public-record-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_702_144;
pub const DEVNET_EPOCH: u64 = 11_137;
pub const DEFAULT_MARKET_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 192;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_SUBSCRIPTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_ACCOUNTING_EPOCH_BLOCKS: u64 = 360;
pub const DEFAULT_REBATE_EPOCH_BLOCKS: u64 = 7_200;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_RECEIPT_MICRO_FEE: u64 = 2;
pub const DEFAULT_MIN_RECEIPT_MICRO_FEE: u64 = 1;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 9;
pub const DEFAULT_RENT_REBATE_BPS: u64 = 6_500;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 10;
pub const DEFAULT_MAX_BIDS_PER_WINDOW: usize = 16_384;
pub const DEFAULT_MAX_COMMITMENTS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH: u64 = 12_582_912;
pub const DEFAULT_MAX_STORAGE_KEYS_PER_RECEIPT: u64 = 65_536;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRICT_QUORUM_BPS: u64 = 8_000;
pub const MICRO_UNIT: u64 = 1_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageReceiptDomain {
    DexPool,
    LendingVault,
    PerpsMargin,
    OptionsVault,
    StableSwap,
    BridgeAdapter,
    OracleCache,
    GovernanceVault,
    AccountRecovery,
    EmergencyRetention,
}

impl StorageReceiptDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DexPool => "dex_pool",
            Self::LendingVault => "lending_vault",
            Self::PerpsMargin => "perps_margin",
            Self::OptionsVault => "options_vault",
            Self::StableSwap => "stable_swap",
            Self::BridgeAdapter => "bridge_adapter",
            Self::OracleCache => "oracle_cache",
            Self::GovernanceVault => "governance_vault",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyRetention => "emergency_retention",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyRetention => 10_000,
            Self::AccountRecovery => 9_700,
            Self::BridgeAdapter => 9_300,
            Self::OracleCache => 8_900,
            Self::GovernanceVault => 8_700,
            Self::PerpsMargin => 8_450,
            Self::OptionsVault => 8_250,
            Self::LendingVault => 8_050,
            Self::DexPool => 7_900,
            Self::StableSwap => 7_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageTransitionKind {
    SlotWrite,
    SlotClear,
    RentTopUp,
    RentRebate,
    SubscriptionDebit,
    AccountingCheckpoint,
    DefiSettlement,
    LiquidationGuard,
    OracleRefresh,
    EmergencyPin,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketWindowStatus {
    Announced,
    CommitOpen,
    PqAttested,
    BatchReady,
    Settling,
    Settled,
    Cancelled,
    Expired,
}

impl MarketWindowStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::CommitOpen
                | Self::PqAttested
                | Self::BatchReady
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    ReplayGuarded,
    PqCommitted,
    BatchQueued,
    Accepted,
    Repriced,
    Outbid,
    Refunded,
    DuplicateRejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Proposed,
    ExecutorSealed,
    VerifierSealed,
    QuorumSigned,
    Included,
    Challenged,
    Rejected,
}

impl CommitmentStatus {
    pub fn can_batch(self) -> bool {
        matches!(
            self,
            Self::ExecutorSealed | Self::VerifierSealed | Self::QuorumSigned
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    Executor,
    Verifier,
    Watchtower,
    StorageOracle,
    RebateAuditor,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executor => "executor",
            Self::Verifier => "verifier",
            Self::Watchtower => "watchtower",
            Self::StorageOracle => "storage_oracle",
            Self::RebateAuditor => "rebate_auditor",
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
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    Reserved,
    Armed,
    Consumed,
    DuplicateRejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Attested,
    Settling,
    Settled,
    Repriced,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    Grace,
    Suspended,
    Cancelled,
    Expired,
}

impl SubscriptionStatus {
    pub fn chargeable(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Queued,
    Netted,
    Paid,
    ClawedBack,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub market_window_blocks: u64,
    pub replay_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub subscription_epoch_blocks: u64,
    pub accounting_epoch_blocks: u64,
    pub rebate_epoch_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_receipt_micro_fee: u64,
    pub min_receipt_micro_fee: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub rent_rebate_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub max_bids_per_window: usize,
    pub max_commitments_per_batch: usize,
    pub max_receipt_bytes_per_batch: u64,
    pub max_storage_keys_per_receipt: u64,
    pub quorum_bps: u64,
    pub strict_quorum_bps: u64,
    pub roots_only_public_records: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            market_window_blocks: DEFAULT_MARKET_WINDOW_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            subscription_epoch_blocks: DEFAULT_SUBSCRIPTION_EPOCH_BLOCKS,
            accounting_epoch_blocks: DEFAULT_ACCOUNTING_EPOCH_BLOCKS,
            rebate_epoch_blocks: DEFAULT_REBATE_EPOCH_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_receipt_micro_fee: DEFAULT_BASE_RECEIPT_MICRO_FEE,
            min_receipt_micro_fee: DEFAULT_MIN_RECEIPT_MICRO_FEE,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            rent_rebate_bps: DEFAULT_RENT_REBATE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            max_bids_per_window: DEFAULT_MAX_BIDS_PER_WINDOW,
            max_commitments_per_batch: DEFAULT_MAX_COMMITMENTS_PER_BATCH,
            max_receipt_bytes_per_batch: DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH,
            max_storage_keys_per_receipt: DEFAULT_MAX_STORAGE_KEYS_PER_RECEIPT,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strict_quorum_bps: DEFAULT_STRICT_QUORUM_BPS,
            roots_only_public_records: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.market_window_blocks == 0 {
            return Err("market window must be non-zero".to_string());
        }
        if self.batch_window_blocks == 0 {
            return Err("batch window must be non-zero".to_string());
        }
        if self.replay_window_blocks < self.market_window_blocks {
            return Err("replay window must cover at least one market window".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set bounds are invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security bits must be at least 192".to_string());
        }
        if self.operator_fee_bps
            + self.batch_rebate_bps
            + self.congestion_surcharge_bps
            + self.rent_rebate_bps
            > MAX_BPS
        {
            return Err("fee shares exceed 100%".to_string());
        }
        if self.quorum_bps > MAX_BPS || self.strict_quorum_bps > MAX_BPS {
            return Err("quorum bps exceeds 100%".to_string());
        }
        if self.strict_quorum_bps < self.quorum_bps {
            return Err("strict quorum cannot be below base quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "market_window_blocks": self.market_window_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "subscription_epoch_blocks": self.subscription_epoch_blocks,
            "accounting_epoch_blocks": self.accounting_epoch_blocks,
            "rebate_epoch_blocks": self.rebate_epoch_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "base_receipt_micro_fee": self.base_receipt_micro_fee,
            "min_receipt_micro_fee": self.min_receipt_micro_fee,
            "operator_fee_bps": self.operator_fee_bps,
            "batch_rebate_bps": self.batch_rebate_bps,
            "rent_rebate_bps": self.rent_rebate_bps,
            "congestion_surcharge_bps": self.congestion_surcharge_bps,
            "max_bids_per_window": self.max_bids_per_window,
            "max_commitments_per_batch": self.max_commitments_per_batch,
            "max_receipt_bytes_per_batch": self.max_receipt_bytes_per_batch,
            "max_storage_keys_per_receipt": self.max_storage_keys_per_receipt,
            "quorum_bps": self.quorum_bps,
            "strict_quorum_bps": self.strict_quorum_bps,
            "roots_only_public_records": self.roots_only_public_records,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub market_windows: u64,
    pub private_bids: u64,
    pub transition_commitments: u64,
    pub pq_attestations: u64,
    pub replay_nullifiers: u64,
    pub settlement_batches: u64,
    pub subscriptions: u64,
    pub accounting_entries: u64,
    pub rent_rebates: u64,
    pub accepted_bids: u64,
    pub rejected_replays: u64,
    pub settled_batches: u64,
    pub micro_fees_charged: u64,
    pub micro_fees_rebated: u64,
    pub storage_bytes_settled: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub market_window_root: String,
    pub private_bid_root: String,
    pub transition_commitment_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
    pub settlement_batch_root: String,
    pub subscription_root: String,
    pub accounting_root: String,
    pub rebate_root: String,
    pub counters_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "market_window_root": self.market_window_root,
            "private_bid_root": self.private_bid_root,
            "transition_commitment_root": self.transition_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "settlement_batch_root": self.settlement_batch_root,
            "subscription_root": self.subscription_root,
            "accounting_root": self.accounting_root,
            "rebate_root": self.rebate_root,
            "counters_root": self.counters_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MarketWindow {
    pub window_id: String,
    pub domain: StorageReceiptDomain,
    pub start_height: u64,
    pub end_height: u64,
    pub settlement_height: u64,
    pub status: MarketWindowStatus,
    pub storage_namespace_root: String,
    pub contract_set_root: String,
    pub min_private_bid_micro_fee: u64,
    pub target_receipt_bytes: u64,
    pub target_storage_keys: u64,
    pub privacy_set_size: u64,
    pub fee_pressure_bps: u64,
    pub batch_rebate_bps: u64,
    pub rent_rebate_bps: u64,
    pub pq_policy_root: String,
}

impl MarketWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "domain": self.domain.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "settlement_height": self.settlement_height,
            "status": self.status,
            "storage_namespace_root": self.storage_namespace_root,
            "contract_set_root": self.contract_set_root,
            "min_private_bid_micro_fee": self.min_private_bid_micro_fee,
            "target_receipt_bytes": self.target_receipt_bytes,
            "target_storage_keys": self.target_storage_keys,
            "privacy_set_size": self.privacy_set_size,
            "fee_pressure_bps": self.fee_pressure_bps,
            "batch_rebate_bps": self.batch_rebate_bps,
            "rent_rebate_bps": self.rent_rebate_bps,
            "pq_policy_root": self.pq_policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateStorageReceiptFeeBid {
    pub bid_id: String,
    pub window_id: String,
    pub contract_commitment: String,
    pub bidder_note_commitment: String,
    pub fee_asset_id: String,
    pub sealed_fee_bid_commitment: String,
    pub max_micro_fee_per_receipt: u64,
    pub max_total_micro_fee: u64,
    pub storage_keys_upper_bound: u64,
    pub receipt_bytes_upper_bound: u64,
    pub privacy_set_size: u64,
    pub replay_nullifier: String,
    pub bid_status: BidStatus,
    pub subscription_id: Option<String>,
    pub rent_rebate_hint_root: String,
}

impl PrivateStorageReceiptFeeBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "window_id": self.window_id,
            "contract_commitment": self.contract_commitment,
            "bidder_note_commitment": self.bidder_note_commitment,
            "fee_asset_id": self.fee_asset_id,
            "sealed_fee_bid_commitment": self.sealed_fee_bid_commitment,
            "max_micro_fee_per_receipt": self.max_micro_fee_per_receipt,
            "max_total_micro_fee": self.max_total_micro_fee,
            "storage_keys_upper_bound": self.storage_keys_upper_bound,
            "receipt_bytes_upper_bound": self.receipt_bytes_upper_bound,
            "privacy_set_size": self.privacy_set_size,
            "replay_nullifier": self.replay_nullifier,
            "bid_status": self.bid_status,
            "subscription_id": self.subscription_id,
            "rent_rebate_hint_root": self.rent_rebate_hint_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedStorageTransitionCommitment {
    pub commitment_id: String,
    pub window_id: String,
    pub bid_id: String,
    pub transition_kind: StorageTransitionKind,
    pub encrypted_transition_root: String,
    pub encrypted_receipt_root: String,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub contract_accounting_delta_root: String,
    pub subscription_delta_root: String,
    pub rent_rebate_delta_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub vm_step_count: u64,
    pub status: CommitmentStatus,
    pub executor_attestation_id: Option<String>,
    pub verifier_attestation_id: Option<String>,
}

impl EncryptedStorageTransitionCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "window_id": self.window_id,
            "bid_id": self.bid_id,
            "transition_kind": self.transition_kind,
            "encrypted_transition_root": self.encrypted_transition_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "pre_storage_root": self.pre_storage_root,
            "post_storage_root": self.post_storage_root,
            "contract_accounting_delta_root": self.contract_accounting_delta_root,
            "subscription_delta_root": self.subscription_delta_root,
            "rent_rebate_delta_root": self.rent_rebate_delta_root,
            "receipt_bytes": self.receipt_bytes,
            "storage_keys_touched": self.storage_keys_touched,
            "vm_step_count": self.vm_step_count,
            "status": self.status,
            "executor_attestation_id": self.executor_attestation_id,
            "verifier_attestation_id": self.verifier_attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqExecutorVerifierAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub role: AttestationRole,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_transition_root: String,
    pub attested_receipt_root: String,
    pub public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub status: AttestationStatus,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl PqExecutorVerifierAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "commitment_id": self.commitment_id,
            "role": self.role.as_str(),
            "committee_id": self.committee_id,
            "signer_set_root": self.signer_set_root,
            "attested_transition_root": self.attested_transition_root,
            "attested_receipt_root": self.attested_receipt_root,
            "public_key_digest": self.public_key_digest,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "status": self.status,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayNullifier {
    pub nullifier: String,
    pub window_id: String,
    pub bid_id: String,
    pub contract_commitment: String,
    pub reserved_height: u64,
    pub expires_height: u64,
    pub status: ReplayStatus,
    pub consumed_by_batch_id: Option<String>,
}

impl ReplayNullifier {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "window_id": self.window_id,
            "bid_id": self.bid_id,
            "contract_commitment": self.contract_commitment,
            "reserved_height": self.reserved_height,
            "expires_height": self.expires_height,
            "status": self.status,
            "consumed_by_batch_id": self.consumed_by_batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeSettlementBatch {
    pub batch_id: String,
    pub window_id: String,
    pub status: BatchStatus,
    pub commitment_ids: Vec<String>,
    pub accepted_bid_ids: Vec<String>,
    pub consumed_nullifiers: Vec<String>,
    pub batch_storage_root_before: String,
    pub batch_storage_root_after: String,
    pub batch_receipt_root: String,
    pub batch_accounting_root: String,
    pub batch_subscription_root: String,
    pub batch_rebate_root: String,
    pub aggregated_pq_attestation_root: String,
    pub total_receipt_bytes: u64,
    pub total_storage_keys: u64,
    pub total_micro_fees: u64,
    pub operator_micro_fee: u64,
    pub rebate_micro_credit: u64,
    pub settlement_height: u64,
}

impl LowFeeSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "window_id": self.window_id,
            "status": self.status,
            "commitment_ids": self.commitment_ids,
            "accepted_bid_ids": self.accepted_bid_ids,
            "consumed_nullifiers": self.consumed_nullifiers,
            "batch_storage_root_before": self.batch_storage_root_before,
            "batch_storage_root_after": self.batch_storage_root_after,
            "batch_receipt_root": self.batch_receipt_root,
            "batch_accounting_root": self.batch_accounting_root,
            "batch_subscription_root": self.batch_subscription_root,
            "batch_rebate_root": self.batch_rebate_root,
            "aggregated_pq_attestation_root": self.aggregated_pq_attestation_root,
            "total_receipt_bytes": self.total_receipt_bytes,
            "total_storage_keys": self.total_storage_keys,
            "total_micro_fees": self.total_micro_fees,
            "operator_micro_fee": self.operator_micro_fee,
            "rebate_micro_credit": self.rebate_micro_credit,
            "settlement_height": self.settlement_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContractSubscription {
    pub subscription_id: String,
    pub contract_commitment: String,
    pub sponsor_note_commitment: String,
    pub domain: StorageReceiptDomain,
    pub status: SubscriptionStatus,
    pub prepaid_micro_balance_commitment: String,
    pub subscription_accounting_root: String,
    pub receipt_allowance_per_epoch: u64,
    pub storage_key_allowance_per_epoch: u64,
    pub last_charged_height: u64,
    pub expires_height: u64,
}

impl ContractSubscription {
    pub fn public_record(&self) -> Value {
        json!({
            "subscription_id": self.subscription_id,
            "contract_commitment": self.contract_commitment,
            "sponsor_note_commitment": self.sponsor_note_commitment,
            "domain": self.domain.as_str(),
            "status": self.status,
            "prepaid_micro_balance_commitment": self.prepaid_micro_balance_commitment,
            "subscription_accounting_root": self.subscription_accounting_root,
            "receipt_allowance_per_epoch": self.receipt_allowance_per_epoch,
            "storage_key_allowance_per_epoch": self.storage_key_allowance_per_epoch,
            "last_charged_height": self.last_charged_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountingEntry {
    pub entry_id: String,
    pub batch_id: String,
    pub contract_commitment: String,
    pub subscription_id: Option<String>,
    pub accounting_epoch: u64,
    pub debit_micro_fee_commitment: String,
    pub credit_micro_rebate_commitment: String,
    pub net_micro_fee: u64,
    pub receipt_count: u64,
    pub storage_keys_touched: u64,
    pub accounting_root_before: String,
    pub accounting_root_after: String,
}

impl AccountingEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "batch_id": self.batch_id,
            "contract_commitment": self.contract_commitment,
            "subscription_id": self.subscription_id,
            "accounting_epoch": self.accounting_epoch,
            "debit_micro_fee_commitment": self.debit_micro_fee_commitment,
            "credit_micro_rebate_commitment": self.credit_micro_rebate_commitment,
            "net_micro_fee": self.net_micro_fee,
            "receipt_count": self.receipt_count,
            "storage_keys_touched": self.storage_keys_touched,
            "accounting_root_before": self.accounting_root_before,
            "accounting_root_after": self.accounting_root_after,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageRentRebate {
    pub rebate_id: String,
    pub contract_commitment: String,
    pub batch_id: String,
    pub rebate_epoch: u64,
    pub rebate_status: RebateStatus,
    pub eligible_storage_key_root: String,
    pub cleared_storage_key_root: String,
    pub rebate_note_commitment: String,
    pub rent_paid_micro_commitment: String,
    pub rebate_micro_credit: u64,
    pub privacy_set_size: u64,
    pub auditor_attestation_id: Option<String>,
}

impl StorageRentRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "contract_commitment": self.contract_commitment,
            "batch_id": self.batch_id,
            "rebate_epoch": self.rebate_epoch,
            "rebate_status": self.rebate_status,
            "eligible_storage_key_root": self.eligible_storage_key_root,
            "cleared_storage_key_root": self.cleared_storage_key_root,
            "rebate_note_commitment": self.rebate_note_commitment,
            "rent_paid_micro_commitment": self.rent_paid_micro_commitment,
            "rebate_micro_credit": self.rebate_micro_credit,
            "privacy_set_size": self.privacy_set_size,
            "auditor_attestation_id": self.auditor_attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateBidInput {
    pub window_id: String,
    pub contract_commitment: String,
    pub bidder_note_commitment: String,
    pub sealed_fee_bid_commitment: String,
    pub max_micro_fee_per_receipt: u64,
    pub max_total_micro_fee: u64,
    pub storage_keys_upper_bound: u64,
    pub receipt_bytes_upper_bound: u64,
    pub replay_nullifier: String,
    pub subscription_id: Option<String>,
    pub rent_rebate_hint_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransitionCommitmentInput {
    pub window_id: String,
    pub bid_id: String,
    pub transition_kind: StorageTransitionKind,
    pub encrypted_transition_root: String,
    pub encrypted_receipt_root: String,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub contract_accounting_delta_root: String,
    pub subscription_delta_root: String,
    pub rent_rebate_delta_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub vm_step_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttestationInput {
    pub commitment_id: String,
    pub role: AttestationRole,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_transition_root: String,
    pub attested_receipt_root: String,
    pub public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub issued_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubscriptionInput {
    pub contract_commitment: String,
    pub sponsor_note_commitment: String,
    pub domain: StorageReceiptDomain,
    pub prepaid_micro_balance_commitment: String,
    pub subscription_accounting_root: String,
    pub receipt_allowance_per_epoch: u64,
    pub storage_key_allowance_per_epoch: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateInput {
    pub contract_commitment: String,
    pub batch_id: String,
    pub rebate_epoch: u64,
    pub eligible_storage_key_root: String,
    pub cleared_storage_key_root: String,
    pub rebate_note_commitment: String,
    pub rent_paid_micro_commitment: String,
    pub rebate_micro_credit: u64,
    pub privacy_set_size: u64,
    pub auditor_attestation_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub current_epoch: u64,
    pub market_windows: BTreeMap<String, MarketWindow>,
    pub private_bids: BTreeMap<String, PrivateStorageReceiptFeeBid>,
    pub transition_commitments: BTreeMap<String, EncryptedStorageTransitionCommitment>,
    pub pq_attestations: BTreeMap<String, PqExecutorVerifierAttestation>,
    pub replay_nullifiers: BTreeMap<String, ReplayNullifier>,
    pub settlement_batches: BTreeMap<String, LowFeeSettlementBatch>,
    pub subscriptions: BTreeMap<String, ContractSubscription>,
    pub accounting_entries: BTreeMap<String, AccountingEntry>,
    pub rent_rebates: BTreeMap<String, StorageRentRebate>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: DEVNET_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            market_windows: BTreeMap::new(),
            private_bids: BTreeMap::new(),
            transition_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            replay_nullifiers: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            rent_rebates: BTreeMap::new(),
        })
    }

    pub fn open_market_window(
        &mut self,
        domain: StorageReceiptDomain,
        storage_namespace_root: impl Into<String>,
        contract_set_root: impl Into<String>,
        target_receipt_bytes: u64,
        target_storage_keys: u64,
    ) -> Result<String> {
        let start_height = self.current_height;
        let end_height = start_height + self.config.market_window_blocks;
        let settlement_height = end_height + self.config.batch_window_blocks;
        let window_id = deterministic_id(
            "WINDOW-ID",
            &[
                HashPart::Str(domain.as_str()),
                HashPart::U64(start_height),
                HashPart::U64(self.counters.market_windows + 1),
            ],
        );
        let window = MarketWindow {
            window_id: window_id.clone(),
            domain,
            start_height,
            end_height,
            settlement_height,
            status: MarketWindowStatus::CommitOpen,
            storage_namespace_root: storage_namespace_root.into(),
            contract_set_root: contract_set_root.into(),
            min_private_bid_micro_fee: self.config.min_receipt_micro_fee,
            target_receipt_bytes,
            target_storage_keys,
            privacy_set_size: self.config.target_privacy_set_size,
            fee_pressure_bps: self.config.congestion_surcharge_bps,
            batch_rebate_bps: self.config.batch_rebate_bps,
            rent_rebate_bps: self.config.rent_rebate_bps,
            pq_policy_root: root_from_value(
                "PQ-POLICY",
                &json!({
                    "min_pq_security_bits": self.config.min_pq_security_bits,
                    "executor_suite": PQ_EXECUTOR_ATTESTATION_SUITE,
                    "verifier_suite": PQ_VERIFIER_ATTESTATION_SUITE,
                }),
            ),
        };
        self.market_windows.insert(window_id.clone(), window);
        self.counters.market_windows += 1;
        Ok(window_id)
    }

    pub fn submit_private_bid(&mut self, input: PrivateBidInput) -> Result<String> {
        self.ensure_window_accepts_bids(&input.window_id)?;
        if self.replay_nullifiers.contains_key(&input.replay_nullifier) {
            self.counters.rejected_replays += 1;
            return Err("duplicate replay nullifier".to_string());
        }
        if input.max_micro_fee_per_receipt < self.config.min_receipt_micro_fee {
            return Err("private bid below minimum storage receipt fee".to_string());
        }
        if input.storage_keys_upper_bound > self.config.max_storage_keys_per_receipt {
            return Err("storage key bound exceeds configured maximum".to_string());
        }
        if input.privacy_set_size_hint() < self.config.min_privacy_set_size {
            return Err("private bid privacy set is too small".to_string());
        }
        let bid_id = deterministic_id(
            "PRIVATE-STORAGE-RECEIPT-BID-ID",
            &[
                HashPart::Str(&input.window_id),
                HashPart::Str(&input.contract_commitment),
                HashPart::Str(&input.replay_nullifier),
                HashPart::U64(self.counters.private_bids + 1),
            ],
        );
        let bid = PrivateStorageReceiptFeeBid {
            bid_id: bid_id.clone(),
            window_id: input.window_id.clone(),
            contract_commitment: input.contract_commitment.clone(),
            bidder_note_commitment: input.bidder_note_commitment,
            fee_asset_id: self.config.fee_asset_id.clone(),
            sealed_fee_bid_commitment: input.sealed_fee_bid_commitment,
            max_micro_fee_per_receipt: input.max_micro_fee_per_receipt,
            max_total_micro_fee: input.max_total_micro_fee,
            storage_keys_upper_bound: input.storage_keys_upper_bound,
            receipt_bytes_upper_bound: input.receipt_bytes_upper_bound,
            privacy_set_size: self.config.target_privacy_set_size,
            replay_nullifier: input.replay_nullifier.clone(),
            bid_status: BidStatus::ReplayGuarded,
            subscription_id: input.subscription_id,
            rent_rebate_hint_root: input.rent_rebate_hint_root,
        };
        let nullifier = ReplayNullifier {
            nullifier: input.replay_nullifier.clone(),
            window_id: input.window_id,
            bid_id: bid_id.clone(),
            contract_commitment: input.contract_commitment,
            reserved_height: self.current_height,
            expires_height: self.current_height + self.config.replay_window_blocks,
            status: ReplayStatus::Armed,
            consumed_by_batch_id: None,
        };
        self.private_bids.insert(bid_id.clone(), bid);
        self.replay_nullifiers
            .insert(input.replay_nullifier, nullifier);
        self.counters.private_bids += 1;
        self.counters.replay_nullifiers += 1;
        Ok(bid_id)
    }

    pub fn commit_storage_transition(
        &mut self,
        input: TransitionCommitmentInput,
    ) -> Result<String> {
        let bid = self
            .private_bids
            .get(&input.bid_id)
            .ok_or_else(|| "unknown private bid".to_string())?;
        if bid.window_id != input.window_id {
            return Err("transition commitment window mismatch".to_string());
        }
        if input.receipt_bytes > bid.receipt_bytes_upper_bound {
            return Err("transition receipt bytes exceed private bid bound".to_string());
        }
        if input.storage_keys_touched > bid.storage_keys_upper_bound {
            return Err("transition storage keys exceed private bid bound".to_string());
        }
        let commitment_id = deterministic_id(
            "STORAGE-TRANSITION-COMMITMENT-ID",
            &[
                HashPart::Str(&input.window_id),
                HashPart::Str(&input.bid_id),
                HashPart::Str(&input.encrypted_transition_root),
                HashPart::U64(self.counters.transition_commitments + 1),
            ],
        );
        let commitment = EncryptedStorageTransitionCommitment {
            commitment_id: commitment_id.clone(),
            window_id: input.window_id,
            bid_id: input.bid_id.clone(),
            transition_kind: input.transition_kind,
            encrypted_transition_root: input.encrypted_transition_root,
            encrypted_receipt_root: input.encrypted_receipt_root,
            pre_storage_root: input.pre_storage_root,
            post_storage_root: input.post_storage_root,
            contract_accounting_delta_root: input.contract_accounting_delta_root,
            subscription_delta_root: input.subscription_delta_root,
            rent_rebate_delta_root: input.rent_rebate_delta_root,
            receipt_bytes: input.receipt_bytes,
            storage_keys_touched: input.storage_keys_touched,
            vm_step_count: input.vm_step_count,
            status: CommitmentStatus::Proposed,
            executor_attestation_id: None,
            verifier_attestation_id: None,
        };
        self.transition_commitments
            .insert(commitment_id.clone(), commitment);
        self.counters.transition_commitments += 1;
        if let Some(bid) = self.private_bids.get_mut(&input.bid_id) {
            bid.bid_status = BidStatus::PqCommitted;
        }
        Ok(commitment_id)
    }

    pub fn attest_transition(&mut self, input: AttestationInput) -> Result<String> {
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("attestation below configured PQ security floor".to_string());
        }
        if input.quorum_weight_bps > MAX_BPS {
            return Err("attestation quorum exceeds 100%".to_string());
        }
        let commitment = self
            .transition_commitments
            .get(&input.commitment_id)
            .ok_or_else(|| "unknown transition commitment".to_string())?;
        if commitment.encrypted_transition_root != input.attested_transition_root {
            return Err("attestation transition root mismatch".to_string());
        }
        if commitment.encrypted_receipt_root != input.attested_receipt_root {
            return Err("attestation receipt root mismatch".to_string());
        }
        let attestation_id = deterministic_id(
            "PQ-STORAGE-RECEIPT-ATTESTATION-ID",
            &[
                HashPart::Str(&input.commitment_id),
                HashPart::Str(input.role.as_str()),
                HashPart::Str(&input.committee_id),
                HashPart::U64(self.counters.pq_attestations + 1),
            ],
        );
        let status = if input.quorum_weight_bps >= self.config.strict_quorum_bps {
            AttestationStatus::Aggregated
        } else if input.quorum_weight_bps >= self.config.quorum_bps {
            AttestationStatus::Verified
        } else {
            AttestationStatus::Pending
        };
        let attestation = PqExecutorVerifierAttestation {
            attestation_id: attestation_id.clone(),
            commitment_id: input.commitment_id.clone(),
            role: input.role,
            committee_id: input.committee_id,
            signer_set_root: input.signer_set_root,
            attested_transition_root: input.attested_transition_root,
            attested_receipt_root: input.attested_receipt_root,
            public_key_digest: input.public_key_digest,
            pq_signature_root: input.pq_signature_root,
            pq_security_bits: input.pq_security_bits,
            quorum_weight_bps: input.quorum_weight_bps,
            status,
            issued_height: input.issued_height,
            expires_height: input.expires_height,
        };
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_attestations += 1;
        if let Some(commitment) = self.transition_commitments.get_mut(&input.commitment_id) {
            match input.role {
                AttestationRole::Executor => {
                    commitment.executor_attestation_id = Some(attestation_id.clone());
                    commitment.status = CommitmentStatus::ExecutorSealed;
                }
                AttestationRole::Verifier | AttestationRole::Watchtower => {
                    commitment.verifier_attestation_id = Some(attestation_id.clone());
                    commitment.status = CommitmentStatus::VerifierSealed;
                }
                AttestationRole::StorageOracle | AttestationRole::RebateAuditor => {}
            }
            if commitment.executor_attestation_id.is_some()
                && commitment.verifier_attestation_id.is_some()
            {
                commitment.status = CommitmentStatus::QuorumSigned;
            }
        }
        Ok(attestation_id)
    }

    pub fn open_subscription(&mut self, input: SubscriptionInput) -> Result<String> {
        if input.receipt_allowance_per_epoch == 0 || input.storage_key_allowance_per_epoch == 0 {
            return Err("subscription allowances must be non-zero".to_string());
        }
        let subscription_id = deterministic_id(
            "STORAGE-RECEIPT-SUBSCRIPTION-ID",
            &[
                HashPart::Str(&input.contract_commitment),
                HashPart::Str(&input.sponsor_note_commitment),
                HashPart::U64(self.counters.subscriptions + 1),
            ],
        );
        let subscription = ContractSubscription {
            subscription_id: subscription_id.clone(),
            contract_commitment: input.contract_commitment,
            sponsor_note_commitment: input.sponsor_note_commitment,
            domain: input.domain,
            status: SubscriptionStatus::Active,
            prepaid_micro_balance_commitment: input.prepaid_micro_balance_commitment,
            subscription_accounting_root: input.subscription_accounting_root,
            receipt_allowance_per_epoch: input.receipt_allowance_per_epoch,
            storage_key_allowance_per_epoch: input.storage_key_allowance_per_epoch,
            last_charged_height: self.current_height,
            expires_height: input.expires_height,
        };
        self.subscriptions
            .insert(subscription_id.clone(), subscription);
        self.counters.subscriptions += 1;
        Ok(subscription_id)
    }

    pub fn queue_rent_rebate(&mut self, input: RebateInput) -> Result<String> {
        if !self.settlement_batches.contains_key(&input.batch_id) {
            return Err("rebate references unknown settlement batch".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("rebate privacy set below configured floor".to_string());
        }
        let rebate_id = deterministic_id(
            "STORAGE-RENT-REBATE-ID",
            &[
                HashPart::Str(&input.contract_commitment),
                HashPart::Str(&input.batch_id),
                HashPart::U64(input.rebate_epoch),
                HashPart::U64(self.counters.rent_rebates + 1),
            ],
        );
        let rebate = StorageRentRebate {
            rebate_id: rebate_id.clone(),
            contract_commitment: input.contract_commitment,
            batch_id: input.batch_id,
            rebate_epoch: input.rebate_epoch,
            rebate_status: RebateStatus::Queued,
            eligible_storage_key_root: input.eligible_storage_key_root,
            cleared_storage_key_root: input.cleared_storage_key_root,
            rebate_note_commitment: input.rebate_note_commitment,
            rent_paid_micro_commitment: input.rent_paid_micro_commitment,
            rebate_micro_credit: input.rebate_micro_credit,
            privacy_set_size: input.privacy_set_size,
            auditor_attestation_id: input.auditor_attestation_id,
        };
        self.counters.micro_fees_rebated += rebate.rebate_micro_credit;
        self.rent_rebates.insert(rebate_id.clone(), rebate);
        self.counters.rent_rebates += 1;
        Ok(rebate_id)
    }

    pub fn build_low_fee_settlement_batch(
        &mut self,
        window_id: impl Into<String>,
        commitment_ids: Vec<String>,
    ) -> Result<String> {
        let window_id = window_id.into();
        self.ensure_window_exists(&window_id)?;
        if commitment_ids.is_empty() {
            return Err("settlement batch cannot be empty".to_string());
        }
        if commitment_ids.len() > self.config.max_commitments_per_batch {
            return Err("settlement batch exceeds commitment limit".to_string());
        }
        let mut accepted_bid_ids = BTreeSet::new();
        let mut consumed_nullifiers = BTreeSet::new();
        let mut total_receipt_bytes = 0_u64;
        let mut total_storage_keys = 0_u64;
        let mut fee_quote = 0_u64;
        let mut before_roots = Vec::new();
        let mut after_roots = Vec::new();
        let mut receipt_roots = Vec::new();
        let mut accounting_roots = Vec::new();
        let mut subscription_roots = Vec::new();
        let mut rebate_roots = Vec::new();
        let mut attestation_roots = Vec::new();

        for commitment_id in &commitment_ids {
            let commitment = self
                .transition_commitments
                .get(commitment_id)
                .ok_or_else(|| format!("unknown transition commitment {commitment_id}"))?;
            if commitment.window_id != window_id {
                return Err("batch contains commitment from another window".to_string());
            }
            if !commitment.status.can_batch() {
                return Err("batch contains commitment without usable PQ attestations".to_string());
            }
            let bid = self
                .private_bids
                .get(&commitment.bid_id)
                .ok_or_else(|| "commitment references unknown bid".to_string())?;
            total_receipt_bytes = total_receipt_bytes.saturating_add(commitment.receipt_bytes);
            total_storage_keys = total_storage_keys.saturating_add(commitment.storage_keys_touched);
            fee_quote = fee_quote.saturating_add(
                bid.max_micro_fee_per_receipt
                    .saturating_mul(commitment.storage_keys_touched.max(1)),
            );
            accepted_bid_ids.insert(commitment.bid_id.clone());
            consumed_nullifiers.insert(bid.replay_nullifier.clone());
            before_roots.push(commitment.pre_storage_root.clone());
            after_roots.push(commitment.post_storage_root.clone());
            receipt_roots.push(commitment.encrypted_receipt_root.clone());
            accounting_roots.push(commitment.contract_accounting_delta_root.clone());
            subscription_roots.push(commitment.subscription_delta_root.clone());
            rebate_roots.push(commitment.rent_rebate_delta_root.clone());
            if let Some(id) = &commitment.executor_attestation_id {
                if let Some(attestation) = self.pq_attestations.get(id) {
                    attestation_roots.push(record_root(
                        PQ_ATTESTATION_SCHEME,
                        &attestation.public_record(),
                    ));
                }
            }
            if let Some(id) = &commitment.verifier_attestation_id {
                if let Some(attestation) = self.pq_attestations.get(id) {
                    attestation_roots.push(record_root(
                        PQ_ATTESTATION_SCHEME,
                        &attestation.public_record(),
                    ));
                }
            }
        }

        if total_receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("settlement batch exceeds receipt byte limit".to_string());
        }

        let total_micro_fees = self.price_batch_fee(fee_quote, total_receipt_bytes);
        let operator_micro_fee = bps(total_micro_fees, self.config.operator_fee_bps);
        let rebate_micro_credit = bps(total_micro_fees, self.config.batch_rebate_bps);
        let batch_id = deterministic_id(
            "LOW-FEE-STORAGE-RECEIPT-BATCH-ID",
            &[
                HashPart::Str(&window_id),
                HashPart::Str(&root_from_strings("BATCH-COMMITMENT-SET", &commitment_ids)),
                HashPart::U64(self.counters.settlement_batches + 1),
            ],
        );
        let batch = LowFeeSettlementBatch {
            batch_id: batch_id.clone(),
            window_id: window_id.clone(),
            status: BatchStatus::Settled,
            commitment_ids: commitment_ids.clone(),
            accepted_bid_ids: accepted_bid_ids.iter().cloned().collect(),
            consumed_nullifiers: consumed_nullifiers.iter().cloned().collect(),
            batch_storage_root_before: root_from_strings("BATCH-STORAGE-BEFORE", &before_roots),
            batch_storage_root_after: root_from_strings("BATCH-STORAGE-AFTER", &after_roots),
            batch_receipt_root: root_from_strings("BATCH-RECEIPTS", &receipt_roots),
            batch_accounting_root: root_from_strings("BATCH-ACCOUNTING", &accounting_roots),
            batch_subscription_root: root_from_strings("BATCH-SUBSCRIPTIONS", &subscription_roots),
            batch_rebate_root: root_from_strings("BATCH-REBATES", &rebate_roots),
            aggregated_pq_attestation_root: root_from_strings(
                "BATCH-PQ-ATTESTATIONS",
                &attestation_roots,
            ),
            total_receipt_bytes,
            total_storage_keys,
            total_micro_fees,
            operator_micro_fee,
            rebate_micro_credit,
            settlement_height: self.current_height,
        };

        for bid_id in &accepted_bid_ids {
            if let Some(bid) = self.private_bids.get_mut(bid_id) {
                bid.bid_status = BidStatus::Accepted;
            }
        }
        for commitment_id in &commitment_ids {
            if let Some(commitment) = self.transition_commitments.get_mut(commitment_id) {
                commitment.status = CommitmentStatus::Included;
            }
        }
        for nullifier in &consumed_nullifiers {
            if let Some(replay) = self.replay_nullifiers.get_mut(nullifier) {
                replay.status = ReplayStatus::Consumed;
                replay.consumed_by_batch_id = Some(batch_id.clone());
            }
        }
        if let Some(window) = self.market_windows.get_mut(&window_id) {
            window.status = MarketWindowStatus::Settled;
        }
        self.counters.accepted_bids += accepted_bid_ids.len() as u64;
        self.counters.settled_batches += 1;
        self.counters.storage_bytes_settled = self
            .counters
            .storage_bytes_settled
            .saturating_add(total_receipt_bytes);
        self.counters.micro_fees_charged = self
            .counters
            .micro_fees_charged
            .saturating_add(total_micro_fees);
        self.counters.micro_fees_rebated = self
            .counters
            .micro_fees_rebated
            .saturating_add(rebate_micro_credit);
        self.settlement_batches.insert(batch_id.clone(), batch);
        self.counters.settlement_batches += 1;
        Ok(batch_id)
    }

    pub fn append_accounting_entry(
        &mut self,
        batch_id: impl Into<String>,
        contract_commitment: impl Into<String>,
        subscription_id: Option<String>,
        receipt_count: u64,
        storage_keys_touched: u64,
    ) -> Result<String> {
        let batch_id = batch_id.into();
        let batch = self
            .settlement_batches
            .get(&batch_id)
            .ok_or_else(|| "unknown settlement batch".to_string())?;
        let contract_commitment = contract_commitment.into();
        let accounting_epoch = self.current_height / self.config.accounting_epoch_blocks.max(1);
        let net_micro_fee = self
            .config
            .base_receipt_micro_fee
            .saturating_mul(receipt_count.max(1))
            .saturating_mul(storage_keys_touched.max(1));
        let entry_id = deterministic_id(
            "STORAGE-RECEIPT-ACCOUNTING-ENTRY-ID",
            &[
                HashPart::Str(&batch_id),
                HashPart::Str(&contract_commitment),
                HashPart::U64(self.counters.accounting_entries + 1),
            ],
        );
        let entry = AccountingEntry {
            entry_id: entry_id.clone(),
            batch_id,
            contract_commitment,
            subscription_id,
            accounting_epoch,
            debit_micro_fee_commitment: root_from_value(
                "ACCOUNTING-DEBIT",
                &json!({
                    "batch_root": record_root(SETTLEMENT_BATCH_SCHEME, &batch.public_record()),
                    "net_micro_fee": net_micro_fee,
                }),
            ),
            credit_micro_rebate_commitment: root_from_value(
                "ACCOUNTING-CREDIT",
                &json!({
                    "batch_rebate_root": batch.batch_rebate_root,
                    "rebate_micro_credit": batch.rebate_micro_credit,
                }),
            ),
            net_micro_fee,
            receipt_count,
            storage_keys_touched,
            accounting_root_before: self.roots().accounting_root,
            accounting_root_after: root_from_value(
                "ACCOUNTING-AFTER",
                &json!({
                    "entry_id": entry_id,
                    "batch_id": batch.batch_id,
                    "net_micro_fee": net_micro_fee,
                }),
            ),
        };
        let entry_id = entry.entry_id.clone();
        self.accounting_entries.insert(entry_id.clone(), entry);
        self.counters.accounting_entries += 1;
        Ok(entry_id)
    }

    pub fn advance_height(&mut self, new_height: u64) -> Result<()> {
        if new_height < self.current_height {
            return Err("cannot rewind runtime height".to_string());
        }
        self.current_height = new_height;
        self.current_epoch = new_height / self.config.market_window_blocks.max(1);
        self.expire_old_records();
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: root_from_value("CONFIG", &self.config.public_record()),
            market_window_root: merkle_record_root(
                MARKET_WINDOW_SCHEME,
                self.market_windows
                    .values()
                    .map(|record| record_root(MARKET_WINDOW_SCHEME, &record.public_record()))
                    .collect(),
            ),
            private_bid_root: merkle_record_root(
                PRIVATE_BID_SCHEME,
                self.private_bids
                    .values()
                    .map(|record| record_root(PRIVATE_BID_SCHEME, &record.public_record()))
                    .collect(),
            ),
            transition_commitment_root: merkle_record_root(
                TRANSITION_COMMITMENT_SCHEME,
                self.transition_commitments
                    .values()
                    .map(|record| {
                        record_root(TRANSITION_COMMITMENT_SCHEME, &record.public_record())
                    })
                    .collect(),
            ),
            pq_attestation_root: merkle_record_root(
                PQ_ATTESTATION_SCHEME,
                self.pq_attestations
                    .values()
                    .map(|record| record_root(PQ_ATTESTATION_SCHEME, &record.public_record()))
                    .collect(),
            ),
            replay_nullifier_root: merkle_record_root(
                REPLAY_NULLIFIER_SCHEME,
                self.replay_nullifiers
                    .values()
                    .map(|record| record_root(REPLAY_NULLIFIER_SCHEME, &record.public_record()))
                    .collect(),
            ),
            settlement_batch_root: merkle_record_root(
                SETTLEMENT_BATCH_SCHEME,
                self.settlement_batches
                    .values()
                    .map(|record| record_root(SETTLEMENT_BATCH_SCHEME, &record.public_record()))
                    .collect(),
            ),
            subscription_root: merkle_record_root(
                SUBSCRIPTION_ROOT_SCHEME,
                self.subscriptions
                    .values()
                    .map(|record| record_root(SUBSCRIPTION_ROOT_SCHEME, &record.public_record()))
                    .collect(),
            ),
            accounting_root: merkle_record_root(
                ACCOUNTING_ROOT_SCHEME,
                self.accounting_entries
                    .values()
                    .map(|record| record_root(ACCOUNTING_ROOT_SCHEME, &record.public_record()))
                    .collect(),
            ),
            rebate_root: merkle_record_root(
                REBATE_ROOT_SCHEME,
                self.rent_rebates
                    .values()
                    .map(|record| record_root(REBATE_ROOT_SCHEME, &record.public_record()))
                    .collect(),
            ),
            counters_root: root_from_value("COUNTERS", &self.counters.public_record()),
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
                    "market_window_root": roots.market_window_root,
                    "private_bid_root": roots.private_bid_root,
                    "transition_commitment_root": roots.transition_commitment_root,
                    "pq_attestation_root": roots.pq_attestation_root,
                    "replay_nullifier_root": roots.replay_nullifier_root,
                    "settlement_batch_root": roots.settlement_batch_root,
                    "subscription_root": roots.subscription_root,
                    "accounting_root": roots.accounting_root,
                    "rebate_root": roots.rebate_root,
                    "counters_root": roots.counters_root,
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
            "counters": self.counters.public_record(),
            "privacy_policy": {
                "roots_only_public_records": self.config.roots_only_public_records,
                "private_bid_payloads_redacted": true,
                "encrypted_transition_payloads_redacted": true,
                "receipt_contents_redacted": true,
                "contract_identity_commitments_only": true,
                "pq_attestation_roots_only": true,
            },
        })
    }

    fn ensure_window_exists(&self, window_id: &str) -> Result<()> {
        self.market_windows
            .get(window_id)
            .map(|_| ())
            .ok_or_else(|| "unknown market window".to_string())
    }

    fn ensure_window_accepts_bids(&self, window_id: &str) -> Result<()> {
        let window = self
            .market_windows
            .get(window_id)
            .ok_or_else(|| "unknown market window".to_string())?;
        if !matches!(
            window.status,
            MarketWindowStatus::Announced | MarketWindowStatus::CommitOpen
        ) {
            return Err("market window is not accepting private bids".to_string());
        }
        let bids_in_window = self
            .private_bids
            .values()
            .filter(|bid| bid.window_id == window_id)
            .count();
        if bids_in_window >= self.config.max_bids_per_window {
            return Err("market window bid capacity reached".to_string());
        }
        Ok(())
    }

    fn price_batch_fee(&self, quoted_micro_fee: u64, receipt_bytes: u64) -> u64 {
        let byte_floor = self
            .config
            .base_receipt_micro_fee
            .saturating_mul(receipt_bytes.max(1));
        let gross = quoted_micro_fee.max(byte_floor);
        let surcharge = bps(gross, self.config.congestion_surcharge_bps);
        gross
            .saturating_add(surcharge)
            .saturating_sub(bps(gross, self.config.batch_rebate_bps))
            .max(self.config.min_receipt_micro_fee)
    }

    fn expire_old_records(&mut self) {
        for window in self.market_windows.values_mut() {
            if window.status.active() && self.current_height > window.settlement_height {
                window.status = MarketWindowStatus::Expired;
            }
        }
        for nullifier in self.replay_nullifiers.values_mut() {
            if matches!(
                nullifier.status,
                ReplayStatus::Reserved | ReplayStatus::Armed
            ) && self.current_height > nullifier.expires_height
            {
                nullifier.status = ReplayStatus::Expired;
            }
        }
        for subscription in self.subscriptions.values_mut() {
            if subscription.status.chargeable() && self.current_height > subscription.expires_height
            {
                subscription.status = SubscriptionStatus::Expired;
            }
        }
    }
}

impl PrivateBidInput {
    fn privacy_set_size_hint(&self) -> u64 {
        self.storage_keys_upper_bound
            .saturating_mul(self.receipt_bytes_upper_bound.max(1))
            .max(DEFAULT_MIN_PRIVACY_SET_SIZE)
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default()).expect("devnet storage receipt config is valid");
    let subscription_id = state
        .open_subscription(SubscriptionInput {
            contract_commitment: "contract:commitment:confidential-dex-vault".to_string(),
            sponsor_note_commitment: "note:commitment:subscription-sponsor-001".to_string(),
            domain: StorageReceiptDomain::DexPool,
            prepaid_micro_balance_commitment: "balance:commitment:prepaid:8m".to_string(),
            subscription_accounting_root: "subscription:accounting:root:genesis".to_string(),
            receipt_allowance_per_epoch: 262_144,
            storage_key_allowance_per_epoch: 1_048_576,
            expires_height: DEVNET_HEIGHT + DEFAULT_SUBSCRIPTION_EPOCH_BLOCKS * 4,
        })
        .expect("devnet subscription opens");
    let window_id = state
        .open_market_window(
            StorageReceiptDomain::DexPool,
            "storage:namespace:root:confidential-defi",
            "contract:set:root:blue-chip-private-defi",
            1_048_576,
            262_144,
        )
        .expect("devnet market opens");
    let bid_id = state
        .submit_private_bid(PrivateBidInput {
            window_id: window_id.clone(),
            contract_commitment: "contract:commitment:confidential-dex-vault".to_string(),
            bidder_note_commitment: "note:commitment:bidder-fee-note-001".to_string(),
            sealed_fee_bid_commitment: "sealed:fee-bid:ml-kem:ciphertext-root-001".to_string(),
            max_micro_fee_per_receipt: 3,
            max_total_micro_fee: 750_000,
            storage_keys_upper_bound: 65_536,
            receipt_bytes_upper_bound: 262_144,
            replay_nullifier: "nullifier:storage-receipt:bid:001".to_string(),
            subscription_id: Some(subscription_id),
            rent_rebate_hint_root: "rebate:hint:root:dex-cleared-slots".to_string(),
        })
        .expect("devnet private bid accepted");
    let commitment_id = state
        .commit_storage_transition(TransitionCommitmentInput {
            window_id: window_id.clone(),
            bid_id: bid_id.clone(),
            transition_kind: StorageTransitionKind::DefiSettlement,
            encrypted_transition_root: "encrypted:transition:root:swap-netting-001".to_string(),
            encrypted_receipt_root: "encrypted:receipt:root:storage-settlement-001".to_string(),
            pre_storage_root: "storage:root:before:confidential-dex".to_string(),
            post_storage_root: "storage:root:after:confidential-dex".to_string(),
            contract_accounting_delta_root: "accounting:delta:root:fees-001".to_string(),
            subscription_delta_root: "subscription:delta:root:debit-001".to_string(),
            rent_rebate_delta_root: "rebate:delta:root:slot-clear-001".to_string(),
            receipt_bytes: 131_072,
            storage_keys_touched: 16_384,
            vm_step_count: 4_800_000,
        })
        .expect("devnet transition committed");
    let _executor_attestation = state
        .attest_transition(AttestationInput {
            commitment_id: commitment_id.clone(),
            role: AttestationRole::Executor,
            committee_id: "committee:pq-executors:devnet:01".to_string(),
            signer_set_root: "signer:set:root:executor:devnet:01".to_string(),
            attested_transition_root: "encrypted:transition:root:swap-netting-001".to_string(),
            attested_receipt_root: "encrypted:receipt:root:storage-settlement-001".to_string(),
            public_key_digest: "pq-key:digest:executor:001".to_string(),
            pq_signature_root: "pq-signature:root:executor:001".to_string(),
            pq_security_bits: 256,
            quorum_weight_bps: DEFAULT_STRICT_QUORUM_BPS,
            issued_height: DEVNET_HEIGHT,
            expires_height: DEVNET_HEIGHT + DEFAULT_REPLAY_WINDOW_BLOCKS,
        })
        .expect("devnet executor attests");
    let _verifier_attestation = state
        .attest_transition(AttestationInput {
            commitment_id: commitment_id.clone(),
            role: AttestationRole::Verifier,
            committee_id: "committee:pq-verifiers:devnet:01".to_string(),
            signer_set_root: "signer:set:root:verifier:devnet:01".to_string(),
            attested_transition_root: "encrypted:transition:root:swap-netting-001".to_string(),
            attested_receipt_root: "encrypted:receipt:root:storage-settlement-001".to_string(),
            public_key_digest: "pq-key:digest:verifier:001".to_string(),
            pq_signature_root: "pq-signature:root:verifier:001".to_string(),
            pq_security_bits: 256,
            quorum_weight_bps: DEFAULT_STRICT_QUORUM_BPS,
            issued_height: DEVNET_HEIGHT,
            expires_height: DEVNET_HEIGHT + DEFAULT_REPLAY_WINDOW_BLOCKS,
        })
        .expect("devnet verifier attests");
    let batch_id = state
        .build_low_fee_settlement_batch(window_id, vec![commitment_id])
        .expect("devnet batch settles");
    let _accounting_entry = state
        .append_accounting_entry(
            batch_id.clone(),
            "contract:commitment:confidential-dex-vault",
            state
                .private_bids
                .get(&bid_id)
                .and_then(|bid| bid.subscription_id.clone()),
            1,
            16_384,
        )
        .expect("devnet accounting entry appends");
    state
}

fn bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn root_from_value(domain: &str, value: &Value) -> String {
    domain_hash(
        STORAGE_RECEIPT_FEE_MARKET_SUITE,
        &[HashPart::Str(domain), HashPart::Json(value)],
        32,
    )
}

fn record_root(domain: &str, value: &Value) -> String {
    root_from_value(domain, value)
}

fn root_from_strings(domain: &str, values: &[String]) -> String {
    let record = json!({
        "domain": domain,
        "values": values,
    });
    root_from_value(domain, &record)
}

fn merkle_record_root(domain: &str, leaves: Vec<String>) -> String {
    if leaves.is_empty() {
        root_from_value(domain, &json!({"empty": true}))
    } else {
        let values = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
        merkle_root(domain, &values)
    }
}
