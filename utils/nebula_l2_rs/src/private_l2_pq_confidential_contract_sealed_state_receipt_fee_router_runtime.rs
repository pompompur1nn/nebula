use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStateReceiptFeeRouterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedStateReceiptFeeRouterRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STATE_RECEIPT_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-state-receipt-fee-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STATE_RECEIPT_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_STATE_RECEIPT_FEE_ROUTER_SUITE: &str =
    "sealed-confidential-smart-contract-state-receipt-fee-router-v1";
pub const PRIVATE_STATE_RECEIPT_FEE_BID_SUITE: &str = "private-state-receipt-fee-bid-commitment-v1";
pub const ENCRYPTED_STATE_TRANSITION_COMMITMENT_SUITE: &str =
    "ml-kem-encrypted-state-transition-commitment-v1";
pub const PQ_EXECUTOR_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-contract-executor-attestation-v1";
pub const PQ_VERIFIER_ATTESTATION_SUITE: &str =
    "Falcon-1024+SPHINCS+-SHAKE-256f-contract-verifier-attestation-v1";
pub const REPLAY_NULLIFIER_SUITE: &str = "sealed-state-receipt-replay-nullifier-set-v1";
pub const LOW_FEE_SETTLEMENT_BATCH_SUITE: &str =
    "low-fee-confidential-state-receipt-settlement-batch-v1";
pub const SUBSCRIPTION_ACCOUNTING_SUITE: &str =
    "confidential-contract-subscription-accounting-root-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-public-contract-state-receipt-router-record-v1";
pub const BID_SCHEME: &str = "sealed-state-receipt-private-fee-bid-root-v1";
pub const TRANSITION_SCHEME: &str = "encrypted-state-transition-commitment-root-v1";
pub const EXECUTOR_ATTESTATION_SCHEME: &str = "pq-executor-attestation-root-v1";
pub const VERIFIER_ATTESTATION_SCHEME: &str = "pq-verifier-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "state-receipt-replay-nullifier-root-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str = "low-fee-state-receipt-settlement-batch-root-v1";
pub const SUBSCRIPTION_SCHEME: &str = "contract-subscription-accounting-root-v1";
pub const ACCOUNTING_LEDGER_SCHEME: &str = "contract-accounting-ledger-root-v1";
pub const PUBLIC_SNAPSHOT_SCHEME: &str = "state-receipt-router-public-snapshot-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_392_704;
pub const DEVNET_EPOCH: u64 = 10_532;
pub const DEFAULT_RECEIPT_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_SUBSCRIPTION_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_BIDS_PER_WINDOW: usize = 16_384;
pub const DEFAULT_MAX_TRANSITIONS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH: u64 = 8_388_608;
pub const DEFAULT_BASE_RECEIPT_MICRO_FEE: u64 = 6;
pub const DEFAULT_MIN_RECEIPT_MICRO_FEE: u64 = 1;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 7;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 10;
pub const DEFAULT_SUBSCRIPTION_DISCOUNT_BPS: u64 = 120;
pub const DEFAULT_VERIFIER_REWARD_BPS: u64 = 25;
pub const DEFAULT_EXECUTOR_BOND_MICRO_UNITS: u64 = 1_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    DefiSwap,
    LendingPool,
    VaultStrategy,
    PerpetualMargin,
    OptionsVault,
    OracleSettlement,
    GovernanceExecution,
    AccountRecovery,
    BridgeReceipt,
    EmergencyControl,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefiSwap => "defi_swap",
            Self::LendingPool => "lending_pool",
            Self::VaultStrategy => "vault_strategy",
            Self::PerpetualMargin => "perpetual_margin",
            Self::OptionsVault => "options_vault",
            Self::OracleSettlement => "oracle_settlement",
            Self::GovernanceExecution => "governance_execution",
            Self::AccountRecovery => "account_recovery",
            Self::BridgeReceipt => "bridge_receipt",
            Self::EmergencyControl => "emergency_control",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyControl => 10_000,
            Self::AccountRecovery => 9_650,
            Self::BridgeReceipt => 9_300,
            Self::OracleSettlement => 8_950,
            Self::PerpetualMargin => 8_700,
            Self::LendingPool => 8_450,
            Self::VaultStrategy => 8_250,
            Self::OptionsVault => 8_000,
            Self::DefiSwap => 7_750,
            Self::GovernanceExecution => 6_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptClass {
    StateWrite,
    StateReadProof,
    LiquidityMutation,
    CollateralMutation,
    OracleCheckpoint,
    CrossContractCall,
    SubscriptionDebit,
    FeeRebate,
    UpgradeReceipt,
    EmergencyReceipt,
}

impl ReceiptClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateWrite => "state_write",
            Self::StateReadProof => "state_read_proof",
            Self::LiquidityMutation => "liquidity_mutation",
            Self::CollateralMutation => "collateral_mutation",
            Self::OracleCheckpoint => "oracle_checkpoint",
            Self::CrossContractCall => "cross_contract_call",
            Self::SubscriptionDebit => "subscription_debit",
            Self::FeeRebate => "fee_rebate",
            Self::UpgradeReceipt => "upgrade_receipt",
            Self::EmergencyReceipt => "emergency_receipt",
        }
    }

    pub fn fee_weight(self) -> u64 {
        match self {
            Self::EmergencyReceipt => 4,
            Self::FeeRebate => 4,
            Self::SubscriptionDebit => 5,
            Self::StateReadProof => 6,
            Self::OracleCheckpoint => 7,
            Self::StateWrite => 8,
            Self::CrossContractCall => 9,
            Self::LiquidityMutation => 10,
            Self::CollateralMutation => 11,
            Self::UpgradeReceipt => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    ReplayReserved,
    TransitionLinked,
    ExecutorAttested,
    VerifierAttested,
    BatchQueued,
    Accepted,
    Repriced,
    Refunded,
    DuplicateRejected,
    Expired,
}

impl BidStatus {
    pub fn pending(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::ReplayReserved
                | Self::TransitionLinked
                | Self::ExecutorAttested
                | Self::VerifierAttested
                | Self::BatchQueued
                | Self::Repriced
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Refunded | Self::DuplicateRejected | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionStatus {
    Encrypted,
    NullifierBound,
    ExecutorSigned,
    VerifierSigned,
    Included,
    Settled,
    Challenged,
    Rejected,
}

impl TransitionStatus {
    pub fn admissible(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::NullifierBound
                | Self::ExecutorSigned
                | Self::VerifierSigned
                | Self::Included
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    Executor,
    Verifier,
    Watchtower,
    SubscriptionAuditor,
    FeeAccountant,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executor => "executor",
            Self::Verifier => "verifier",
            Self::Watchtower => "watchtower",
            Self::SubscriptionAuditor => "subscription_auditor",
            Self::FeeAccountant => "fee_accountant",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Authenticated,
    QuorumSigned,
    Applied,
    Challenged,
    Rejected,
}

impl AttestationStatus {
    pub fn accepted(self) -> bool {
        matches!(
            self,
            Self::Authenticated | Self::QuorumSigned | Self::Applied
        )
    }
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
    Open,
    Sealed,
    ExecutorQuorum,
    VerifierQuorum,
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
    pub fn billable(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingEntryKind {
    Debit,
    Credit,
    Rebate,
    SponsorTopUp,
    VerifierReward,
    ExecutorReward,
    Slash,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub router_suite: String,
    pub private_fee_bid_suite: String,
    pub encrypted_transition_suite: String,
    pub pq_executor_attestation_suite: String,
    pub pq_verifier_attestation_suite: String,
    pub replay_nullifier_suite: String,
    pub low_fee_settlement_batch_suite: String,
    pub subscription_accounting_suite: String,
    pub roots_only_public_record_suite: String,
    pub receipt_window_blocks: u64,
    pub replay_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub subscription_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_bids_per_window: usize,
    pub max_transitions_per_batch: usize,
    pub max_receipt_bytes_per_batch: u64,
    pub base_receipt_micro_fee: u64,
    pub min_receipt_micro_fee: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub subscription_discount_bps: u64,
    pub verifier_reward_bps: u64,
    pub executor_bond_micro_units: u64,
    pub require_roots_only_public_records: bool,
    pub require_replay_nullifier: bool,
    pub require_executor_attestation: bool,
    pub require_verifier_attestation: bool,
    pub allow_subscription_sponsorship: bool,
    pub allow_low_fee_batch_repricing: bool,
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
            router_suite: SEALED_STATE_RECEIPT_FEE_ROUTER_SUITE.to_string(),
            private_fee_bid_suite: PRIVATE_STATE_RECEIPT_FEE_BID_SUITE.to_string(),
            encrypted_transition_suite: ENCRYPTED_STATE_TRANSITION_COMMITMENT_SUITE.to_string(),
            pq_executor_attestation_suite: PQ_EXECUTOR_ATTESTATION_SUITE.to_string(),
            pq_verifier_attestation_suite: PQ_VERIFIER_ATTESTATION_SUITE.to_string(),
            replay_nullifier_suite: REPLAY_NULLIFIER_SUITE.to_string(),
            low_fee_settlement_batch_suite: LOW_FEE_SETTLEMENT_BATCH_SUITE.to_string(),
            subscription_accounting_suite: SUBSCRIPTION_ACCOUNTING_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            receipt_window_blocks: DEFAULT_RECEIPT_WINDOW_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            subscription_window_blocks: DEFAULT_SUBSCRIPTION_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_bids_per_window: DEFAULT_MAX_BIDS_PER_WINDOW,
            max_transitions_per_batch: DEFAULT_MAX_TRANSITIONS_PER_BATCH,
            max_receipt_bytes_per_batch: DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH,
            base_receipt_micro_fee: DEFAULT_BASE_RECEIPT_MICRO_FEE,
            min_receipt_micro_fee: DEFAULT_MIN_RECEIPT_MICRO_FEE,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            subscription_discount_bps: DEFAULT_SUBSCRIPTION_DISCOUNT_BPS,
            verifier_reward_bps: DEFAULT_VERIFIER_REWARD_BPS,
            executor_bond_micro_units: DEFAULT_EXECUTOR_BOND_MICRO_UNITS,
            require_roots_only_public_records: true,
            require_replay_nullifier: true,
            require_executor_attestation: true,
            require_verifier_attestation: true,
            allow_subscription_sponsorship: true,
            allow_low_fee_batch_repricing: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported sealed state receipt fee router protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported sealed state receipt fee router schema version".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("post-quantum security floor is too low".to_string());
        }
        if self.min_privacy_set_size < 65_536 {
            return Err("privacy set floor is too low for sealed state receipts".to_string());
        }
        if self.max_bids_per_window == 0 {
            return Err("max_bids_per_window must be non-zero".to_string());
        }
        if self.max_transitions_per_batch == 0 {
            return Err("max_transitions_per_batch must be non-zero".to_string());
        }
        if self.operator_fee_bps > MAX_BPS
            || self.batch_rebate_bps > MAX_BPS
            || self.congestion_surcharge_bps > MAX_BPS
            || self.subscription_discount_bps > MAX_BPS
            || self.verifier_reward_bps > MAX_BPS
        {
            return Err("basis point value exceeds MAX_BPS".to_string());
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub next_bid_index: u64,
    pub next_transition_index: u64,
    pub next_executor_attestation_index: u64,
    pub next_verifier_attestation_index: u64,
    pub next_nullifier_index: u64,
    pub next_batch_index: u64,
    pub next_subscription_index: u64,
    pub next_accounting_entry_index: u64,
    pub bids_submitted: u64,
    pub bids_accepted: u64,
    pub bids_repriced: u64,
    pub duplicate_bids_rejected: u64,
    pub transitions_committed: u64,
    pub transitions_settled: u64,
    pub executor_attestations: u64,
    pub verifier_attestations: u64,
    pub nullifiers_consumed: u64,
    pub batches_settled: u64,
    pub subscription_debits: u64,
    pub total_fee_micro_units: u128,
    pub total_rebate_micro_units: u128,
    pub total_executor_reward_micro_units: u128,
    pub total_verifier_reward_micro_units: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_bid_index: 1,
            next_transition_index: 1,
            next_executor_attestation_index: 1,
            next_verifier_attestation_index: 1,
            next_nullifier_index: 1,
            next_batch_index: 1,
            next_subscription_index: 1,
            next_accounting_entry_index: 1,
            bids_submitted: 0,
            bids_accepted: 0,
            bids_repriced: 0,
            duplicate_bids_rejected: 0,
            transitions_committed: 0,
            transitions_settled: 0,
            executor_attestations: 0,
            verifier_attestations: 0,
            nullifiers_consumed: 0,
            batches_settled: 0,
            subscription_debits: 0,
            total_fee_micro_units: 0,
            total_rebate_micro_units: 0,
            total_executor_reward_micro_units: 0,
            total_verifier_reward_micro_units: 0,
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
    pub private_fee_bid_root: String,
    pub encrypted_transition_root: String,
    pub executor_attestation_root: String,
    pub verifier_attestation_root: String,
    pub replay_nullifier_root: String,
    pub low_fee_batch_root: String,
    pub subscription_root: String,
    pub accounting_ledger_root: String,
    pub public_snapshot_root: String,
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
pub struct PrivateStateReceiptFeeBidInput {
    pub contract_id: String,
    pub bidder_commitment: String,
    pub domain: ContractDomain,
    pub receipt_class: ReceiptClass,
    pub sealed_fee_bid_root: String,
    pub encrypted_receipt_payload_root: String,
    pub max_fee_micro_units: u64,
    pub receipt_count: u64,
    pub receipt_bytes: u64,
    pub privacy_set_size: u64,
    pub desired_settlement_height: u64,
    pub subscription_id: Option<String>,
    pub replay_nullifier_root: String,
    pub bid_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateStateReceiptFeeBid {
    pub bid_id: String,
    pub bid_index: u64,
    pub contract_id: String,
    pub bidder_commitment: String,
    pub domain: ContractDomain,
    pub receipt_class: ReceiptClass,
    pub sealed_fee_bid_root: String,
    pub encrypted_receipt_payload_root: String,
    pub max_fee_micro_units: u64,
    pub quoted_fee_micro_units: u64,
    pub receipt_count: u64,
    pub receipt_bytes: u64,
    pub privacy_set_size: u64,
    pub desired_settlement_height: u64,
    pub subscription_id: Option<String>,
    pub replay_nullifier_root: String,
    pub status: BidStatus,
    pub created_height: u64,
    pub expires_height: u64,
}

impl PrivateStateReceiptFeeBid {
    pub fn from_input(
        index: u64,
        height: u64,
        config: &Config,
        input: PrivateStateReceiptFeeBidInput,
    ) -> Result<Self> {
        if input.contract_id.is_empty() {
            return Err("contract_id is required".to_string());
        }
        if input.bidder_commitment.is_empty() {
            return Err("bidder commitment is required".to_string());
        }
        if input.sealed_fee_bid_root.is_empty()
            || input.encrypted_receipt_payload_root.is_empty()
            || input.replay_nullifier_root.is_empty()
        {
            return Err("sealed bid, encrypted payload, and replay roots are required".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("privacy set too small for state receipt fee bid".to_string());
        }
        if input.receipt_bytes > config.max_receipt_bytes_per_batch {
            return Err("receipt bytes exceed batch limit".to_string());
        }
        let quoted_fee_micro_units = estimate_receipt_fee_micro_units(
            config,
            input.domain,
            input.receipt_class,
            input.receipt_count,
            input.receipt_bytes,
            input.subscription_id.is_some(),
        );
        if input.max_fee_micro_units < quoted_fee_micro_units {
            return Err("sealed bid is below quoted low-fee route".to_string());
        }
        let bid_id = private_state_receipt_fee_bid_id(
            &input.contract_id,
            &input.bidder_commitment,
            &input.sealed_fee_bid_root,
            input.bid_nonce,
        );
        Ok(Self {
            bid_id,
            bid_index: index,
            contract_id: input.contract_id,
            bidder_commitment: input.bidder_commitment,
            domain: input.domain,
            receipt_class: input.receipt_class,
            sealed_fee_bid_root: input.sealed_fee_bid_root,
            encrypted_receipt_payload_root: input.encrypted_receipt_payload_root,
            max_fee_micro_units: input.max_fee_micro_units,
            quoted_fee_micro_units,
            receipt_count: input.receipt_count,
            receipt_bytes: input.receipt_bytes,
            privacy_set_size: input.privacy_set_size,
            desired_settlement_height: input.desired_settlement_height,
            subscription_id: input.subscription_id,
            replay_nullifier_root: input.replay_nullifier_root,
            status: BidStatus::Sealed,
            created_height: height,
            expires_height: height.saturating_add(config.receipt_window_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("private state receipt fee bid serializes")
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE_STATE_RECEIPT_FEE_BID", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedStateTransitionCommitmentInput {
    pub bid_id: String,
    pub contract_id: String,
    pub pre_state_root: String,
    pub post_state_commitment_root: String,
    pub encrypted_state_delta_root: String,
    pub receipt_commitment_root: String,
    pub callgraph_commitment_root: String,
    pub witness_bundle_root: String,
    pub replay_nullifier_root: String,
    pub transition_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedStateTransitionCommitment {
    pub transition_id: String,
    pub transition_index: u64,
    pub bid_id: String,
    pub contract_id: String,
    pub pre_state_root: String,
    pub post_state_commitment_root: String,
    pub encrypted_state_delta_root: String,
    pub receipt_commitment_root: String,
    pub callgraph_commitment_root: String,
    pub witness_bundle_root: String,
    pub replay_nullifier_root: String,
    pub status: TransitionStatus,
    pub created_height: u64,
}

impl EncryptedStateTransitionCommitment {
    pub fn from_input(
        index: u64,
        height: u64,
        input: EncryptedStateTransitionCommitmentInput,
    ) -> Result<Self> {
        require_non_empty("bid_id", &input.bid_id)?;
        require_non_empty("contract_id", &input.contract_id)?;
        require_non_empty("pre_state_root", &input.pre_state_root)?;
        require_non_empty(
            "post_state_commitment_root",
            &input.post_state_commitment_root,
        )?;
        require_non_empty(
            "encrypted_state_delta_root",
            &input.encrypted_state_delta_root,
        )?;
        require_non_empty("receipt_commitment_root", &input.receipt_commitment_root)?;
        require_non_empty("witness_bundle_root", &input.witness_bundle_root)?;
        require_non_empty("replay_nullifier_root", &input.replay_nullifier_root)?;
        let transition_id = encrypted_state_transition_commitment_id(
            &input.bid_id,
            &input.contract_id,
            &input.post_state_commitment_root,
            input.transition_nonce,
        );
        Ok(Self {
            transition_id,
            transition_index: index,
            bid_id: input.bid_id,
            contract_id: input.contract_id,
            pre_state_root: input.pre_state_root,
            post_state_commitment_root: input.post_state_commitment_root,
            encrypted_state_delta_root: input.encrypted_state_delta_root,
            receipt_commitment_root: input.receipt_commitment_root,
            callgraph_commitment_root: input.callgraph_commitment_root,
            witness_bundle_root: input.witness_bundle_root,
            replay_nullifier_root: input.replay_nullifier_root,
            status: TransitionStatus::Encrypted,
            created_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("encrypted state transition serializes")
    }

    pub fn root(&self) -> String {
        payload_root(
            "ENCRYPTED_STATE_TRANSITION_COMMITMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqAttestationInput {
    pub transition_id: String,
    pub attestor_commitment: String,
    pub role: AttestationRole,
    pub attested_state_root: String,
    pub attested_receipt_root: String,
    pub signature_root: String,
    pub public_key_root: String,
    pub security_bits: u16,
    pub stake_weight: u64,
    pub attestation_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqAttestation {
    pub attestation_id: String,
    pub attestation_index: u64,
    pub transition_id: String,
    pub attestor_commitment: String,
    pub role: AttestationRole,
    pub attested_state_root: String,
    pub attested_receipt_root: String,
    pub signature_root: String,
    pub public_key_root: String,
    pub security_bits: u16,
    pub stake_weight: u64,
    pub status: AttestationStatus,
    pub created_height: u64,
}

impl PqAttestation {
    pub fn from_input(
        index: u64,
        height: u64,
        config: &Config,
        input: PqAttestationInput,
    ) -> Result<Self> {
        require_non_empty("transition_id", &input.transition_id)?;
        require_non_empty("attestor_commitment", &input.attestor_commitment)?;
        require_non_empty("attested_state_root", &input.attested_state_root)?;
        require_non_empty("attested_receipt_root", &input.attested_receipt_root)?;
        require_non_empty("signature_root", &input.signature_root)?;
        require_non_empty("public_key_root", &input.public_key_root)?;
        if input.security_bits < config.min_pq_security_bits {
            return Err("attestation does not meet post-quantum security floor".to_string());
        }
        if input.stake_weight == 0 {
            return Err("attestation stake weight must be non-zero".to_string());
        }
        let attestation_id = pq_attestation_id(
            &input.transition_id,
            &input.attestor_commitment,
            input.role,
            input.attestation_nonce,
        );
        Ok(Self {
            attestation_id,
            attestation_index: index,
            transition_id: input.transition_id,
            attestor_commitment: input.attestor_commitment,
            role: input.role,
            attested_state_root: input.attested_state_root,
            attested_receipt_root: input.attested_receipt_root,
            signature_root: input.signature_root,
            public_key_root: input.public_key_root,
            security_bits: input.security_bits,
            stake_weight: input.stake_weight,
            status: AttestationStatus::Authenticated,
            created_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("pq attestation serializes")
    }

    pub fn root(&self) -> String {
        payload_root("PQ_ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayNullifierInput {
    pub bid_id: String,
    pub transition_id: String,
    pub nullifier_root: String,
    pub membership_witness_root: String,
    pub epoch: u64,
    pub expires_height: u64,
    pub nullifier_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayNullifier {
    pub nullifier_id: String,
    pub nullifier_index: u64,
    pub bid_id: String,
    pub transition_id: String,
    pub nullifier_root: String,
    pub membership_witness_root: String,
    pub epoch: u64,
    pub status: NullifierStatus,
    pub created_height: u64,
    pub expires_height: u64,
}

impl ReplayNullifier {
    pub fn from_input(index: u64, height: u64, input: ReplayNullifierInput) -> Result<Self> {
        require_non_empty("bid_id", &input.bid_id)?;
        require_non_empty("transition_id", &input.transition_id)?;
        require_non_empty("nullifier_root", &input.nullifier_root)?;
        require_non_empty("membership_witness_root", &input.membership_witness_root)?;
        if input.expires_height <= height {
            return Err("replay nullifier expiry must be in the future".to_string());
        }
        let nullifier_id = replay_nullifier_id(
            &input.bid_id,
            &input.transition_id,
            &input.nullifier_root,
            input.nullifier_nonce,
        );
        Ok(Self {
            nullifier_id,
            nullifier_index: index,
            bid_id: input.bid_id,
            transition_id: input.transition_id,
            nullifier_root: input.nullifier_root,
            membership_witness_root: input.membership_witness_root,
            epoch: input.epoch,
            status: NullifierStatus::Reserved,
            created_height: height,
            expires_height: input.expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("replay nullifier serializes")
    }

    pub fn root(&self) -> String {
        payload_root("REPLAY_NULLIFIER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeSettlementBatchInput {
    pub operator_commitment: String,
    pub settlement_lane_root: String,
    pub transition_ids: Vec<String>,
    pub receipt_batch_root: String,
    pub fee_distribution_root: String,
    pub subscription_debit_root: String,
    pub aggregate_executor_attestation_root: String,
    pub aggregate_verifier_attestation_root: String,
    pub total_fee_micro_units: u128,
    pub total_rebate_micro_units: u128,
    pub batch_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeSettlementBatch {
    pub batch_id: String,
    pub batch_index: u64,
    pub operator_commitment: String,
    pub settlement_lane_root: String,
    pub transition_ids: Vec<String>,
    pub receipt_batch_root: String,
    pub fee_distribution_root: String,
    pub subscription_debit_root: String,
    pub aggregate_executor_attestation_root: String,
    pub aggregate_verifier_attestation_root: String,
    pub total_fee_micro_units: u128,
    pub total_rebate_micro_units: u128,
    pub status: BatchStatus,
    pub created_height: u64,
    pub settled_height: Option<u64>,
}

impl LowFeeSettlementBatch {
    pub fn from_input(
        index: u64,
        height: u64,
        config: &Config,
        input: LowFeeSettlementBatchInput,
    ) -> Result<Self> {
        require_non_empty("operator_commitment", &input.operator_commitment)?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("receipt_batch_root", &input.receipt_batch_root)?;
        require_non_empty("fee_distribution_root", &input.fee_distribution_root)?;
        require_non_empty("subscription_debit_root", &input.subscription_debit_root)?;
        require_non_empty(
            "aggregate_executor_attestation_root",
            &input.aggregate_executor_attestation_root,
        )?;
        require_non_empty(
            "aggregate_verifier_attestation_root",
            &input.aggregate_verifier_attestation_root,
        )?;
        if input.transition_ids.is_empty() {
            return Err("settlement batch must contain at least one transition".to_string());
        }
        if input.transition_ids.len() > config.max_transitions_per_batch {
            return Err("settlement batch exceeds transition limit".to_string());
        }
        let batch_id = low_fee_settlement_batch_id(
            &input.operator_commitment,
            &input.settlement_lane_root,
            height,
            input.batch_nonce,
        );
        Ok(Self {
            batch_id,
            batch_index: index,
            operator_commitment: input.operator_commitment,
            settlement_lane_root: input.settlement_lane_root,
            transition_ids: input.transition_ids,
            receipt_batch_root: input.receipt_batch_root,
            fee_distribution_root: input.fee_distribution_root,
            subscription_debit_root: input.subscription_debit_root,
            aggregate_executor_attestation_root: input.aggregate_executor_attestation_root,
            aggregate_verifier_attestation_root: input.aggregate_verifier_attestation_root,
            total_fee_micro_units: input.total_fee_micro_units,
            total_rebate_micro_units: input.total_rebate_micro_units,
            status: BatchStatus::Open,
            created_height: height,
            settled_height: None,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("low-fee settlement batch serializes")
    }

    pub fn root(&self) -> String {
        payload_root("LOW_FEE_SETTLEMENT_BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ContractSubscriptionInput {
    pub contract_id: String,
    pub subscriber_commitment: String,
    pub sponsor_commitment: Option<String>,
    pub accounting_root: String,
    pub prepaid_fee_root: String,
    pub max_debit_micro_units_per_window: u64,
    pub discount_bps: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub subscription_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ContractSubscription {
    pub subscription_id: String,
    pub subscription_index: u64,
    pub contract_id: String,
    pub subscriber_commitment: String,
    pub sponsor_commitment: Option<String>,
    pub accounting_root: String,
    pub prepaid_fee_root: String,
    pub max_debit_micro_units_per_window: u64,
    pub discount_bps: u64,
    pub status: SubscriptionStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub debited_micro_units: u128,
    pub credited_micro_units: u128,
}

impl ContractSubscription {
    pub fn from_input(
        index: u64,
        config: &Config,
        input: ContractSubscriptionInput,
    ) -> Result<Self> {
        require_non_empty("contract_id", &input.contract_id)?;
        require_non_empty("subscriber_commitment", &input.subscriber_commitment)?;
        require_non_empty("accounting_root", &input.accounting_root)?;
        require_non_empty("prepaid_fee_root", &input.prepaid_fee_root)?;
        if input.end_height <= input.start_height {
            return Err("subscription end height must be after start height".to_string());
        }
        if input.discount_bps > config.subscription_discount_bps {
            return Err("subscription discount exceeds configured cap".to_string());
        }
        if input.sponsor_commitment.is_some() && !config.allow_subscription_sponsorship {
            return Err("subscription sponsorship is disabled".to_string());
        }
        let subscription_id = contract_subscription_id(
            &input.contract_id,
            &input.subscriber_commitment,
            &input.accounting_root,
            input.subscription_nonce,
        );
        Ok(Self {
            subscription_id,
            subscription_index: index,
            contract_id: input.contract_id,
            subscriber_commitment: input.subscriber_commitment,
            sponsor_commitment: input.sponsor_commitment,
            accounting_root: input.accounting_root,
            prepaid_fee_root: input.prepaid_fee_root,
            max_debit_micro_units_per_window: input.max_debit_micro_units_per_window,
            discount_bps: input.discount_bps,
            status: SubscriptionStatus::Active,
            start_height: input.start_height,
            end_height: input.end_height,
            debited_micro_units: 0,
            credited_micro_units: 0,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("contract subscription serializes")
    }

    pub fn root(&self) -> String {
        payload_root("CONTRACT_SUBSCRIPTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AccountingEntryInput {
    pub subscription_id: Option<String>,
    pub contract_id: String,
    pub batch_id: Option<String>,
    pub bid_id: Option<String>,
    pub kind: AccountingEntryKind,
    pub amount_micro_units: u128,
    pub balance_root_after: String,
    pub memo_commitment_root: String,
    pub entry_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AccountingEntry {
    pub entry_id: String,
    pub entry_index: u64,
    pub subscription_id: Option<String>,
    pub contract_id: String,
    pub batch_id: Option<String>,
    pub bid_id: Option<String>,
    pub kind: AccountingEntryKind,
    pub amount_micro_units: u128,
    pub balance_root_after: String,
    pub memo_commitment_root: String,
    pub created_height: u64,
}

impl AccountingEntry {
    pub fn from_input(index: u64, height: u64, input: AccountingEntryInput) -> Result<Self> {
        require_non_empty("contract_id", &input.contract_id)?;
        require_non_empty("balance_root_after", &input.balance_root_after)?;
        require_non_empty("memo_commitment_root", &input.memo_commitment_root)?;
        if input.amount_micro_units == 0 {
            return Err("accounting entry amount must be non-zero".to_string());
        }
        let entry_id = accounting_entry_id(
            &input.contract_id,
            input.subscription_id.as_deref().unwrap_or("none"),
            &input.balance_root_after,
            input.entry_nonce,
        );
        Ok(Self {
            entry_id,
            entry_index: index,
            subscription_id: input.subscription_id,
            contract_id: input.contract_id,
            batch_id: input.batch_id,
            bid_id: input.bid_id,
            kind: input.kind,
            amount_micro_units: input.amount_micro_units,
            balance_root_after: input.balance_root_after,
            memo_commitment_root: input.memo_commitment_root,
            created_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("accounting entry serializes")
    }

    pub fn root(&self) -> String {
        payload_root("ACCOUNTING_ENTRY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub private_fee_bids: BTreeMap<String, PrivateStateReceiptFeeBid>,
    pub encrypted_transitions: BTreeMap<String, EncryptedStateTransitionCommitment>,
    pub executor_attestations: BTreeMap<String, PqAttestation>,
    pub verifier_attestations: BTreeMap<String, PqAttestation>,
    pub replay_nullifiers: BTreeMap<String, ReplayNullifier>,
    pub low_fee_batches: BTreeMap<String, LowFeeSettlementBatch>,
    pub contract_subscriptions: BTreeMap<String, ContractSubscription>,
    pub accounting_entries: BTreeMap<String, AccountingEntry>,
    pub consumed_nullifier_roots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::new(),
            roots: Roots::default(),
            height,
            epoch,
            private_fee_bids: BTreeMap::new(),
            encrypted_transitions: BTreeMap::new(),
            executor_attestations: BTreeMap::new(),
            verifier_attestations: BTreeMap::new(),
            replay_nullifiers: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            contract_subscriptions: BTreeMap::new(),
            accounting_entries: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH)
            .expect("devnet sealed state receipt router config is valid")
    }

    pub fn submit_private_fee_bid(
        &mut self,
        input: PrivateStateReceiptFeeBidInput,
    ) -> Result<String> {
        if self.private_fee_bids.len() >= self.config.max_bids_per_window {
            return Err("fee bid window is full".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&input.replay_nullifier_root)
        {
            self.counters.duplicate_bids_rejected =
                self.counters.duplicate_bids_rejected.saturating_add(1);
            return Err("replay nullifier root has already been consumed".to_string());
        }
        let bid = PrivateStateReceiptFeeBid::from_input(
            self.counters.next_bid_index,
            self.height,
            &self.config,
            input,
        )?;
        let bid_id = bid.bid_id.clone();
        if self.private_fee_bids.contains_key(&bid_id) {
            self.counters.duplicate_bids_rejected =
                self.counters.duplicate_bids_rejected.saturating_add(1);
            return Err("duplicate private state receipt fee bid".to_string());
        }
        self.counters.next_bid_index = self.counters.next_bid_index.saturating_add(1);
        self.counters.bids_submitted = self.counters.bids_submitted.saturating_add(1);
        self.private_fee_bids.insert(bid_id.clone(), bid);
        self.recompute_roots();
        Ok(bid_id)
    }

    pub fn commit_encrypted_transition(
        &mut self,
        input: EncryptedStateTransitionCommitmentInput,
    ) -> Result<String> {
        let bid = self
            .private_fee_bids
            .get_mut(&input.bid_id)
            .ok_or_else(|| "unknown fee bid for encrypted transition".to_string())?;
        if !bid.status.pending() {
            return Err("fee bid is not accepting transition commitments".to_string());
        }
        if bid.contract_id != input.contract_id {
            return Err("transition contract does not match fee bid contract".to_string());
        }
        if bid.replay_nullifier_root != input.replay_nullifier_root {
            return Err("transition replay root does not match fee bid replay root".to_string());
        }
        let transition = EncryptedStateTransitionCommitment::from_input(
            self.counters.next_transition_index,
            self.height,
            input,
        )?;
        let transition_id = transition.transition_id.clone();
        if self.encrypted_transitions.contains_key(&transition_id) {
            return Err("duplicate encrypted state transition commitment".to_string());
        }
        bid.status = BidStatus::TransitionLinked;
        self.counters.next_transition_index = self.counters.next_transition_index.saturating_add(1);
        self.counters.transitions_committed = self.counters.transitions_committed.saturating_add(1);
        self.encrypted_transitions
            .insert(transition_id.clone(), transition);
        self.recompute_roots();
        Ok(transition_id)
    }

    pub fn reserve_replay_nullifier(&mut self, input: ReplayNullifierInput) -> Result<String> {
        if self
            .consumed_nullifier_roots
            .contains(&input.nullifier_root)
        {
            return Err("replay nullifier root already consumed".to_string());
        }
        let transition = self
            .encrypted_transitions
            .get_mut(&input.transition_id)
            .ok_or_else(|| "unknown transition for replay nullifier".to_string())?;
        if transition.bid_id != input.bid_id {
            return Err("nullifier bid does not match transition bid".to_string());
        }
        let nullifier =
            ReplayNullifier::from_input(self.counters.next_nullifier_index, self.height, input)?;
        let nullifier_id = nullifier.nullifier_id.clone();
        if self.replay_nullifiers.contains_key(&nullifier_id) {
            return Err("duplicate replay nullifier".to_string());
        }
        transition.status = TransitionStatus::NullifierBound;
        self.counters.next_nullifier_index = self.counters.next_nullifier_index.saturating_add(1);
        self.replay_nullifiers
            .insert(nullifier_id.clone(), nullifier);
        self.recompute_roots();
        Ok(nullifier_id)
    }

    pub fn record_executor_attestation(&mut self, input: PqAttestationInput) -> Result<String> {
        if input.role != AttestationRole::Executor {
            return Err("executor attestation must use executor role".to_string());
        }
        let transition = self
            .encrypted_transitions
            .get_mut(&input.transition_id)
            .ok_or_else(|| "unknown transition for executor attestation".to_string())?;
        let attestation = PqAttestation::from_input(
            self.counters.next_executor_attestation_index,
            self.height,
            &self.config,
            input,
        )?;
        let attestation_id = attestation.attestation_id.clone();
        if self.executor_attestations.contains_key(&attestation_id) {
            return Err("duplicate executor attestation".to_string());
        }
        transition.status = TransitionStatus::ExecutorSigned;
        self.counters.next_executor_attestation_index = self
            .counters
            .next_executor_attestation_index
            .saturating_add(1);
        self.counters.executor_attestations = self.counters.executor_attestations.saturating_add(1);
        self.executor_attestations
            .insert(attestation_id.clone(), attestation);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn record_verifier_attestation(&mut self, input: PqAttestationInput) -> Result<String> {
        if input.role != AttestationRole::Verifier {
            return Err("verifier attestation must use verifier role".to_string());
        }
        let transition = self
            .encrypted_transitions
            .get_mut(&input.transition_id)
            .ok_or_else(|| "unknown transition for verifier attestation".to_string())?;
        let attestation = PqAttestation::from_input(
            self.counters.next_verifier_attestation_index,
            self.height,
            &self.config,
            input,
        )?;
        let attestation_id = attestation.attestation_id.clone();
        if self.verifier_attestations.contains_key(&attestation_id) {
            return Err("duplicate verifier attestation".to_string());
        }
        transition.status = TransitionStatus::VerifierSigned;
        self.counters.next_verifier_attestation_index = self
            .counters
            .next_verifier_attestation_index
            .saturating_add(1);
        self.counters.verifier_attestations = self.counters.verifier_attestations.saturating_add(1);
        self.verifier_attestations
            .insert(attestation_id.clone(), attestation);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn open_contract_subscription(
        &mut self,
        input: ContractSubscriptionInput,
    ) -> Result<String> {
        let subscription = ContractSubscription::from_input(
            self.counters.next_subscription_index,
            &self.config,
            input,
        )?;
        let subscription_id = subscription.subscription_id.clone();
        if self.contract_subscriptions.contains_key(&subscription_id) {
            return Err("duplicate contract subscription".to_string());
        }
        self.counters.next_subscription_index =
            self.counters.next_subscription_index.saturating_add(1);
        self.contract_subscriptions
            .insert(subscription_id.clone(), subscription);
        self.recompute_roots();
        Ok(subscription_id)
    }

    pub fn append_accounting_entry(&mut self, input: AccountingEntryInput) -> Result<String> {
        if let Some(subscription_id) = input.subscription_id.as_deref() {
            let subscription = self
                .contract_subscriptions
                .get_mut(subscription_id)
                .ok_or_else(|| "unknown subscription for accounting entry".to_string())?;
            if !subscription.status.billable() {
                return Err("subscription is not billable".to_string());
            }
            match input.kind {
                AccountingEntryKind::Debit => {
                    let next = subscription
                        .debited_micro_units
                        .saturating_add(input.amount_micro_units);
                    if next
                        > subscription.max_debit_micro_units_per_window as u128
                            * self.config.subscription_window_blocks as u128
                    {
                        return Err("subscription debit exceeds accounting window cap".to_string());
                    }
                    subscription.debited_micro_units = next;
                    self.counters.subscription_debits =
                        self.counters.subscription_debits.saturating_add(1);
                }
                AccountingEntryKind::Credit
                | AccountingEntryKind::Rebate
                | AccountingEntryKind::SponsorTopUp => {
                    subscription.credited_micro_units = subscription
                        .credited_micro_units
                        .saturating_add(input.amount_micro_units);
                }
                _ => {}
            }
        }
        let entry = AccountingEntry::from_input(
            self.counters.next_accounting_entry_index,
            self.height,
            input,
        )?;
        let entry_id = entry.entry_id.clone();
        if self.accounting_entries.contains_key(&entry_id) {
            return Err("duplicate accounting entry".to_string());
        }
        match entry.kind {
            AccountingEntryKind::Debit => {
                self.counters.total_fee_micro_units = self
                    .counters
                    .total_fee_micro_units
                    .saturating_add(entry.amount_micro_units);
            }
            AccountingEntryKind::Rebate => {
                self.counters.total_rebate_micro_units = self
                    .counters
                    .total_rebate_micro_units
                    .saturating_add(entry.amount_micro_units);
            }
            AccountingEntryKind::ExecutorReward => {
                self.counters.total_executor_reward_micro_units = self
                    .counters
                    .total_executor_reward_micro_units
                    .saturating_add(entry.amount_micro_units);
            }
            AccountingEntryKind::VerifierReward => {
                self.counters.total_verifier_reward_micro_units = self
                    .counters
                    .total_verifier_reward_micro_units
                    .saturating_add(entry.amount_micro_units);
            }
            _ => {}
        }
        self.counters.next_accounting_entry_index =
            self.counters.next_accounting_entry_index.saturating_add(1);
        self.accounting_entries.insert(entry_id.clone(), entry);
        self.recompute_roots();
        Ok(entry_id)
    }

    pub fn queue_low_fee_settlement_batch(
        &mut self,
        input: LowFeeSettlementBatchInput,
    ) -> Result<String> {
        for transition_id in &input.transition_ids {
            let transition = self
                .encrypted_transitions
                .get(transition_id)
                .ok_or_else(|| {
                    format!("unknown transition in settlement batch: {transition_id}")
                })?;
            if !transition.status.admissible() {
                return Err(format!(
                    "transition is not batch-admissible: {transition_id}"
                ));
            }
        }
        let batch = LowFeeSettlementBatch::from_input(
            self.counters.next_batch_index,
            self.height,
            &self.config,
            input,
        )?;
        let batch_id = batch.batch_id.clone();
        if self.low_fee_batches.contains_key(&batch_id) {
            return Err("duplicate low-fee settlement batch".to_string());
        }
        for transition_id in &batch.transition_ids {
            if let Some(transition) = self.encrypted_transitions.get_mut(transition_id) {
                transition.status = TransitionStatus::Included;
            }
        }
        self.counters.next_batch_index = self.counters.next_batch_index.saturating_add(1);
        self.low_fee_batches.insert(batch_id.clone(), batch);
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn settle_low_fee_batch(&mut self, batch_id: &str) -> Result<()> {
        let batch = self
            .low_fee_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown settlement batch".to_string())?;
        if matches!(batch.status, BatchStatus::Settled | BatchStatus::Cancelled) {
            return Err("settlement batch is already terminal".to_string());
        }
        batch.status = BatchStatus::Settled;
        batch.settled_height = Some(self.height);
        self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(batch.total_fee_micro_units);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(batch.total_rebate_micro_units);
        for transition_id in &batch.transition_ids {
            if let Some(transition) = self.encrypted_transitions.get_mut(transition_id) {
                transition.status = TransitionStatus::Settled;
                self.counters.transitions_settled =
                    self.counters.transitions_settled.saturating_add(1);
                self.consumed_nullifier_roots
                    .insert(transition.replay_nullifier_root.clone());
            }
        }
        for bid in self.private_fee_bids.values_mut() {
            if batch.transition_ids.iter().any(|transition_id| {
                self.encrypted_transitions
                    .get(transition_id)
                    .map(|transition| transition.bid_id.as_str() == bid.bid_id.as_str())
                    .unwrap_or(false)
            }) {
                bid.status = BidStatus::Accepted;
                self.counters.bids_accepted = self.counters.bids_accepted.saturating_add(1);
            }
        }
        for nullifier in self.replay_nullifiers.values_mut() {
            if batch
                .transition_ids
                .iter()
                .any(|transition_id| transition_id == &nullifier.transition_id)
            {
                nullifier.status = NullifierStatus::Consumed;
                self.counters.nullifiers_consumed =
                    self.counters.nullifiers_consumed.saturating_add(1);
            }
        }
        self.recompute_roots();
        Ok(())
    }

    pub fn advance_height(&mut self, next_height: u64) -> Result<()> {
        if next_height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = next_height;
        self.expire_stale_records();
        self.recompute_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "fee_asset_id": self.config.fee_asset_id,
            "height": self.height,
            "epoch": self.epoch,
            "roots_only_public_record_suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "roots": self.roots.public_record(),
        }))
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            private_fee_bid_root: record_root(
                BID_SCHEME,
                &self
                    .private_fee_bids
                    .values()
                    .map(PrivateStateReceiptFeeBid::public_record)
                    .collect::<Vec<_>>(),
            ),
            encrypted_transition_root: record_root(
                TRANSITION_SCHEME,
                &self
                    .encrypted_transitions
                    .values()
                    .map(EncryptedStateTransitionCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            executor_attestation_root: record_root(
                EXECUTOR_ATTESTATION_SCHEME,
                &self
                    .executor_attestations
                    .values()
                    .map(PqAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            verifier_attestation_root: record_root(
                VERIFIER_ATTESTATION_SCHEME,
                &self
                    .verifier_attestations
                    .values()
                    .map(PqAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            replay_nullifier_root: record_root(
                REPLAY_NULLIFIER_SCHEME,
                &self
                    .replay_nullifiers
                    .values()
                    .map(ReplayNullifier::public_record)
                    .collect::<Vec<_>>(),
            ),
            low_fee_batch_root: record_root(
                SETTLEMENT_BATCH_SCHEME,
                &self
                    .low_fee_batches
                    .values()
                    .map(LowFeeSettlementBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            subscription_root: record_root(
                SUBSCRIPTION_SCHEME,
                &self
                    .contract_subscriptions
                    .values()
                    .map(ContractSubscription::public_record)
                    .collect::<Vec<_>>(),
            ),
            accounting_ledger_root: record_root(
                ACCOUNTING_LEDGER_SCHEME,
                &self
                    .accounting_entries
                    .values()
                    .map(AccountingEntry::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_snapshot_root: record_root(
                PUBLIC_SNAPSHOT_SCHEME,
                &[json!({
                    "height": self.height,
                    "epoch": self.epoch,
                    "bid_count": self.private_fee_bids.len(),
                    "transition_count": self.encrypted_transitions.len(),
                    "batch_count": self.low_fee_batches.len(),
                    "subscription_count": self.contract_subscriptions.len(),
                    "consumed_nullifier_count": self.consumed_nullifier_roots.len(),
                })],
            ),
        };
    }

    fn expire_stale_records(&mut self) {
        for bid in self.private_fee_bids.values_mut() {
            if bid.status.pending() && self.height > bid.expires_height {
                bid.status = BidStatus::Expired;
            }
        }
        for nullifier in self.replay_nullifiers.values_mut() {
            if matches!(
                nullifier.status,
                NullifierStatus::Reserved | NullifierStatus::Armed
            ) && self.height > nullifier.expires_height
            {
                nullifier.status = NullifierStatus::Expired;
            }
        }
        for subscription in self.contract_subscriptions.values_mut() {
            if subscription.status.billable() && self.height > subscription.end_height {
                subscription.status = SubscriptionStatus::Expired;
            }
        }
    }
}

pub fn private_state_receipt_fee_bid_id(
    contract_id: &str,
    bidder_commitment: &str,
    sealed_fee_bid_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:BID-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(contract_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_fee_bid_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn encrypted_state_transition_commitment_id(
    bid_id: &str,
    contract_id: &str,
    post_state_commitment_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:TRANSITION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(bid_id),
            HashPart::Str(contract_id),
            HashPart::Str(post_state_commitment_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_attestation_id(
    transition_id: &str,
    attestor_commitment: &str,
    role: AttestationRole,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(transition_id),
            HashPart::Str(attestor_commitment),
            HashPart::Str(role.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn replay_nullifier_id(
    bid_id: &str,
    transition_id: &str,
    nullifier_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:NULLIFIER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(bid_id),
            HashPart::Str(transition_id),
            HashPart::Str(nullifier_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn low_fee_settlement_batch_id(
    operator_commitment: &str,
    settlement_lane_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:BATCH-ID",
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

pub fn contract_subscription_id(
    contract_id: &str,
    subscriber_commitment: &str,
    accounting_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:SUBSCRIPTION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(contract_id),
            HashPart::Str(subscriber_commitment),
            HashPart::Str(accounting_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn accounting_entry_id(
    contract_id: &str,
    subscription_id: &str,
    balance_root_after: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:ACCOUNTING-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(contract_id),
            HashPart::Str(subscription_id),
            HashPart::Str(balance_root_after),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:DETERMINISTIC-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn estimate_receipt_fee_micro_units(
    config: &Config,
    domain: ContractDomain,
    receipt_class: ReceiptClass,
    receipt_count: u64,
    receipt_bytes: u64,
    subscription_discount: bool,
) -> u64 {
    let count_component = receipt_count
        .max(1)
        .saturating_mul(config.base_receipt_micro_fee)
        .saturating_mul(receipt_class.fee_weight());
    let byte_component = receipt_bytes.saturating_add(511) / 512;
    let priority_discount = domain.priority_weight() / 1_000;
    let mut fee = count_component
        .saturating_add(byte_component)
        .saturating_add(config.operator_fee_bps)
        .saturating_add(config.congestion_surcharge_bps)
        .saturating_sub(priority_discount);
    let rebate = fee.saturating_mul(config.batch_rebate_bps) / MAX_BPS;
    fee = fee.saturating_sub(rebate);
    if subscription_discount {
        fee = fee.saturating_sub(fee.saturating_mul(config.subscription_discount_bps) / MAX_BPS);
    }
    fee.max(config.min_receipt_micro_fee)
}

pub fn verifier_reward_micro_units(config: &Config, fee_micro_units: u64) -> u64 {
    fee_micro_units.saturating_mul(config.verifier_reward_bps) / MAX_BPS
}

pub fn executor_bond_required_micro_units(config: &Config, transition_count: usize) -> u64 {
    config
        .executor_bond_micro_units
        .saturating_mul(transition_count.max(1) as u64)
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:PAYLOAD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-RECEIPT-FEE-ROUTER:STATE-ROOT",
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

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}
