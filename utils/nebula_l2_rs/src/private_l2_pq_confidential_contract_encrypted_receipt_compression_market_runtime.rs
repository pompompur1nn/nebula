use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractEncryptedReceiptCompressionMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> =
    PrivateL2PqConfidentialContractEncryptedReceiptCompressionMarketRuntimeResult<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_RECEIPT_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-encrypted-receipt-compression-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_RECEIPT_COMPRESSION_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_RECEIPT_SUITE: &str =
    "ML-KEM-1024+XWing-confidential-contract-encrypted-receipt-v1";
pub const RECEIPT_COMPRESSION_SUITE: &str =
    "pq-confidential-contract-receipt-compression-market-v1";
pub const PQ_COMPRESSOR_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-receipt-compressor-attestation-v1";
pub const BIDDER_COMMITMENT_SUITE: &str = "sealed-private-receipt-compression-bidder-commitment-v1";
pub const NAMESPACE_RENT_CREDIT_SUITE: &str = "private-contract-receipt-namespace-rent-credit-v1";
pub const LOW_FEE_REWARD_SUITE: &str = "low-fee-encrypted-receipt-compression-reward-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "privacy-budgeted-redacted-receipt-compression-market-summary-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "operator-safe-encrypted-receipt-compression-market-summary-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_240_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_744_000;
pub const DEVNET_EPOCH: u64 = 14_400;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_TARGET_COMPRESSION_RATIO_BPS: u64 = 2_200;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 7;
pub const DEFAULT_TARGET_REWARD_BPS: u64 = 6;
pub const DEFAULT_RENT_CREDIT_REBATE_BPS: u64 = 1_800;
pub const DEFAULT_MARKET_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REWARD_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_EVIDENCE_WINDOW_BLOCKS: u64 = 288;
pub const DEFAULT_MAX_MARKETS: usize = 262_144;
pub const DEFAULT_MAX_RECEIPTS: usize = 4_194_304;
pub const DEFAULT_MAX_BIDS: usize = 4_194_304;
pub const DEFAULT_MAX_COMPRESSORS: usize = 131_072;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_RENT_CREDITS: usize = 2_097_152;
pub const DEFAULT_MAX_REWARDS: usize = 2_097_152;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptMarketKind {
    PrivateCallTrace,
    ConfidentialEventLog,
    FheExecutionReceipt,
    CrossContractCallback,
    TokenTransferReceipt,
    DefiSettlementReceipt,
    BridgeMessageReceipt,
    GovernanceReceipt,
    EmergencyEscapeReceipt,
}

impl ReceiptMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCallTrace => "private_call_trace",
            Self::ConfidentialEventLog => "confidential_event_log",
            Self::FheExecutionReceipt => "fhe_execution_receipt",
            Self::CrossContractCallback => "cross_contract_callback",
            Self::TokenTransferReceipt => "token_transfer_receipt",
            Self::DefiSettlementReceipt => "defi_settlement_receipt",
            Self::BridgeMessageReceipt => "bridge_message_receipt",
            Self::GovernanceReceipt => "governance_receipt",
            Self::EmergencyEscapeReceipt => "emergency_escape_receipt",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscapeReceipt => 10_000,
            Self::BridgeMessageReceipt => 9_400,
            Self::DefiSettlementReceipt => 9_100,
            Self::FheExecutionReceipt => 8_800,
            Self::CrossContractCallback => 8_500,
            Self::TokenTransferReceipt => 8_200,
            Self::PrivateCallTrace => 7_900,
            Self::ConfidentialEventLog => 7_600,
            Self::GovernanceReceipt => 7_300,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Open,
    Warm,
    Saturated,
    Settling,
    Suspended,
    Retired,
}

impl MarketStatus {
    pub fn accepts_receipts(self) -> bool {
        matches!(self, Self::Open | Self::Warm | Self::Saturated)
    }

    pub fn accepts_bids(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Warm | Self::Saturated | Self::Settling
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Warm => "warm",
            Self::Saturated => "saturated",
            Self::Settling => "settling",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Submitted,
    Encrypted,
    BidMatched,
    Compressing,
    Compressed,
    Attested,
    Settled,
    Disclosed,
    Expired,
    Slashed,
}

impl ReceiptStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Encrypted
                | Self::BidMatched
                | Self::Compressing
                | Self::Compressed
                | Self::Attested
        )
    }

    pub fn compressed(self) -> bool {
        matches!(self, Self::Compressed | Self::Attested | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionMode {
    DictionaryDelta,
    ReceiptMerklePatch,
    EventTopicDedup,
    FheCiphertextPack,
    CrossContractTraceFold,
    RecursiveReceiptRollup,
    EmergencyMinimal,
}

impl CompressionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DictionaryDelta => "dictionary_delta",
            Self::ReceiptMerklePatch => "receipt_merkle_patch",
            Self::EventTopicDedup => "event_topic_dedup",
            Self::FheCiphertextPack => "fhe_ciphertext_pack",
            Self::CrossContractTraceFold => "cross_contract_trace_fold",
            Self::RecursiveReceiptRollup => "recursive_receipt_rollup",
            Self::EmergencyMinimal => "emergency_minimal",
        }
    }

    pub fn expected_ratio_bps(self) -> u64 {
        match self {
            Self::DictionaryDelta => 2_600,
            Self::ReceiptMerklePatch => 2_900,
            Self::EventTopicDedup => 3_200,
            Self::FheCiphertextPack => 3_600,
            Self::CrossContractTraceFold => 2_400,
            Self::RecursiveReceiptRollup => 1_900,
            Self::EmergencyMinimal => 5_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Selected,
    Filled,
    Expired,
    Cancelled,
    Disputed,
    Slashed,
}

impl BidStatus {
    pub fn selectable(self) -> bool {
        matches!(self, Self::Posted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressorStatus {
    Active,
    Throttled,
    Probation,
    Paused,
    Quarantined,
    Slashed,
    Retired,
}

impl CompressorStatus {
    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::Probation)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    CompressionCorrectness,
    ReceiptInclusion,
    PrivacyBudget,
    NamespaceRent,
    LowFeeReward,
    RedactionSafety,
    OperatorSummary,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompressionCorrectness => "compression_correctness",
            Self::ReceiptInclusion => "receipt_inclusion",
            Self::PrivacyBudget => "privacy_budget",
            Self::NamespaceRent => "namespace_rent",
            Self::LowFeeReward => "low_fee_reward",
            Self::RedactionSafety => "redaction_safety",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Challenged,
    Expired,
    Slashed,
}

impl AttestationStatus {
    pub fn valid(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RentCreditStatus {
    Reserved,
    Earned,
    Applied,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardStatus {
    Open,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyTier {
    Standard,
    High,
    AuditorOnly,
    EmergencyRedacted,
}

impl PrivacyTier {
    pub fn min_set_size(self) -> u64 {
        match self {
            Self::Standard => DEFAULT_MIN_PRIVACY_SET_SIZE,
            Self::High => DEFAULT_TARGET_PRIVACY_SET_SIZE,
            Self::AuditorOnly => DEFAULT_TARGET_PRIVACY_SET_SIZE * 2,
            Self::EmergencyRedacted => DEFAULT_MIN_PRIVACY_SET_SIZE / 2,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub mode: RuntimeMode,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub target_compression_ratio_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_reward_bps: u64,
    pub rent_credit_rebate_bps: u64,
    pub market_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub reward_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub evidence_window_blocks: u64,
    pub max_markets: usize,
    pub max_receipts: usize,
    pub max_bids: usize,
    pub max_compressors: usize,
    pub max_attestations: usize,
    pub max_rent_credits: usize,
    pub max_rewards: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
    pub require_pq_attestation: bool,
    pub require_namespace_rent_credit: bool,
    pub allow_low_fee_rewarding: bool,
    pub allow_selective_disclosure: bool,
    pub allow_emergency_minimal_compression: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            mode: RuntimeMode::Devnet,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            target_compression_ratio_bps: DEFAULT_TARGET_COMPRESSION_RATIO_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_reward_bps: DEFAULT_TARGET_REWARD_BPS,
            rent_credit_rebate_bps: DEFAULT_RENT_CREDIT_REBATE_BPS,
            market_ttl_blocks: DEFAULT_MARKET_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            reward_ttl_blocks: DEFAULT_REWARD_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            evidence_window_blocks: DEFAULT_EVIDENCE_WINDOW_BLOCKS,
            max_markets: DEFAULT_MAX_MARKETS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_bids: DEFAULT_MAX_BIDS,
            max_compressors: DEFAULT_MAX_COMPRESSORS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_rent_credits: DEFAULT_MAX_RENT_CREDITS,
            max_rewards: DEFAULT_MAX_REWARDS,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            require_pq_attestation: true,
            require_namespace_rent_credit: true,
            allow_low_fee_rewarding: true,
            allow_selective_disclosure: true,
            allow_emergency_minimal_compression: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_encrypted_receipt_compression_market_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "mode": self.mode.as_str(),
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "target_compression_ratio_bps": self.target_compression_ratio_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_reward_bps": self.target_reward_bps,
            "rent_credit_rebate_bps": self.rent_credit_rebate_bps,
            "market_ttl_blocks": self.market_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "reward_ttl_blocks": self.reward_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "evidence_window_blocks": self.evidence_window_blocks,
            "max_markets": self.max_markets,
            "max_receipts": self.max_receipts,
            "max_bids": self.max_bids,
            "max_compressors": self.max_compressors,
            "max_attestations": self.max_attestations,
            "max_rent_credits": self.max_rent_credits,
            "max_rewards": self.max_rewards,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_operator_summaries": self.max_operator_summaries,
            "require_pq_attestation": self.require_pq_attestation,
            "require_namespace_rent_credit": self.require_namespace_rent_credit,
            "allow_low_fee_rewarding": self.allow_low_fee_rewarding,
            "allow_selective_disclosure": self.allow_selective_disclosure,
            "allow_emergency_minimal_compression": self.allow_emergency_minimal_compression
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub markets: usize,
    pub open_markets: usize,
    pub receipts: usize,
    pub live_receipts: usize,
    pub compressed_receipts: usize,
    pub bids: usize,
    pub selectable_bids: usize,
    pub compressors: usize,
    pub active_compressors: usize,
    pub attestations: usize,
    pub accepted_attestations: usize,
    pub rent_credits: usize,
    pub applied_rent_credits: usize,
    pub low_fee_rewards: usize,
    pub settled_rewards: usize,
    pub redaction_budgets: usize,
    pub operator_summaries: usize,
    pub total_original_bytes: u128,
    pub total_compressed_bytes: u128,
    pub total_fee_saved_piconero: u128,
    pub total_rewards_piconero: u128,
}

impl Counters {
    pub fn compression_ratio_bps(&self) -> u64 {
        if self.total_original_bytes == 0 {
            return MAX_BPS;
        }
        ((self.total_compressed_bytes.saturating_mul(MAX_BPS as u128)) / self.total_original_bytes)
            as u64
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub market_root: String,
    pub receipt_root: String,
    pub bid_root: String,
    pub compressor_root: String,
    pub attestation_root: String,
    pub rent_credit_root: String,
    pub reward_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub namespace_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("config"),
            counters_root: empty_root("counters"),
            market_root: empty_root("markets"),
            receipt_root: empty_root("receipts"),
            bid_root: empty_root("bids"),
            compressor_root: empty_root("compressors"),
            attestation_root: empty_root("attestations"),
            rent_credit_root: empty_root("rent-credits"),
            reward_root: empty_root("rewards"),
            redaction_budget_root: empty_root("redaction-budgets"),
            operator_summary_root: empty_root("operator-summaries"),
            namespace_root: empty_root("namespaces"),
            state_root: empty_root("state"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionMarket {
    pub market_id: String,
    pub kind: ReceiptMarketKind,
    pub status: MarketStatus,
    pub contract_namespace: String,
    pub contract_commitment: String,
    pub shard_id: u16,
    pub epoch: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub target_privacy_set_size: u64,
    pub target_compression_ratio_bps: u64,
    pub max_user_fee_bps: u64,
    pub reward_pool_piconero: u128,
    pub rent_credit_pool_piconero: u128,
    pub receipt_count: u64,
    pub compressed_receipt_count: u64,
    pub namespace_root: String,
    pub policy_root: String,
}

impl CompressionMarket {
    pub fn new(
        market_id: impl Into<String>,
        kind: ReceiptMarketKind,
        contract_namespace: impl Into<String>,
        contract_commitment: impl Into<String>,
        shard_id: u16,
        epoch: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let market_id = market_id.into();
        let namespace = contract_namespace.into();
        Self {
            market_id,
            kind,
            status: MarketStatus::Open,
            contract_namespace: namespace.clone(),
            contract_commitment: contract_commitment.into(),
            shard_id,
            epoch,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            target_privacy_set_size: kind.priority_weight().saturating_mul(128),
            target_compression_ratio_bps: DEFAULT_TARGET_COMPRESSION_RATIO_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            reward_pool_piconero: 0,
            rent_credit_pool_piconero: 0,
            receipt_count: 0,
            compressed_receipt_count: 0,
            namespace_root: sample_root("namespace", &namespace),
            policy_root: sample_root("market-policy", &kind.as_str()),
        }
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.accepts_receipts() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_market",
            "market_id": self.market_id,
            "market_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "contract_namespace": self.contract_namespace,
            "contract_commitment": self.contract_commitment,
            "shard_id": self.shard_id,
            "epoch": self.epoch,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "target_privacy_set_size": self.target_privacy_set_size,
            "target_compression_ratio_bps": self.target_compression_ratio_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "reward_pool_piconero": self.reward_pool_piconero.to_string(),
            "rent_credit_pool_piconero": self.rent_credit_pool_piconero.to_string(),
            "receipt_count": self.receipt_count,
            "compressed_receipt_count": self.compressed_receipt_count,
            "namespace_root": self.namespace_root,
            "policy_root": self.policy_root
        })
    }

    pub fn root(&self) -> String {
        deterministic_record_root("market", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedContractReceipt {
    pub receipt_id: String,
    pub market_id: String,
    pub status: ReceiptStatus,
    pub privacy_tier: PrivacyTier,
    pub contract_namespace: String,
    pub contract_commitment: String,
    pub caller_commitment: String,
    pub call_nonce_commitment: String,
    pub encrypted_receipt_root: String,
    pub event_topic_root: String,
    pub state_access_root: String,
    pub nullifier_root: String,
    pub inclusion_witness_root: String,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub max_fee_piconero: u128,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub compression_mode: CompressionMode,
    pub selected_bid_id: Option<String>,
    pub compressor_id: Option<String>,
    pub attestation_id: Option<String>,
}

impl EncryptedContractReceipt {
    pub fn compression_ratio_bps(&self) -> u64 {
        if self.original_bytes == 0 {
            return MAX_BPS;
        }
        self.compressed_bytes.saturating_mul(MAX_BPS) / self.original_bytes
    }

    pub fn estimated_fee_saved_piconero(&self, base_fee_per_byte: u128) -> u128 {
        self.original_bytes
            .saturating_sub(self.compressed_bytes)
            .into()
            .saturating_mul(base_fee_per_byte)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_contract_receipt",
            "receipt_id": self.receipt_id,
            "market_id": self.market_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "privacy_tier": format!("{:?}", self.privacy_tier).to_lowercase(),
            "contract_namespace": self.contract_namespace,
            "contract_commitment": self.contract_commitment,
            "caller_commitment": redacted_operator(&self.caller_commitment),
            "call_nonce_commitment": self.call_nonce_commitment,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "event_topic_root": self.event_topic_root,
            "state_access_root": self.state_access_root,
            "nullifier_root": self.nullifier_root,
            "inclusion_witness_root": self.inclusion_witness_root,
            "original_bytes": self.original_bytes,
            "compressed_bytes": self.compressed_bytes,
            "compression_ratio_bps": self.compression_ratio_bps(),
            "max_fee_piconero": self.max_fee_piconero.to_string(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "compression_mode": self.compression_mode.as_str(),
            "selected_bid_id": self.selected_bid_id,
            "compressor_id": self.compressor_id.as_ref().map(|id| redacted_operator(id)),
            "attestation_id": self.attestation_id
        })
    }

    pub fn root(&self) -> String {
        deterministic_record_root("receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BidderCommitment {
    pub bid_id: String,
    pub market_id: String,
    pub receipt_id: Option<String>,
    pub bidder_id: String,
    pub status: BidStatus,
    pub compression_mode: CompressionMode,
    pub bid_commitment_root: String,
    pub sealed_fee_commitment: String,
    pub max_fee_piconero: u128,
    pub min_savings_bps: u64,
    pub promised_ratio_bps: u64,
    pub pq_key_commitment: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl BidderCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bidder_commitment",
            "bid_id": self.bid_id,
            "market_id": self.market_id,
            "receipt_id": self.receipt_id,
            "bidder_id": redacted_operator(&self.bidder_id),
            "status": format!("{:?}", self.status).to_lowercase(),
            "compression_mode": self.compression_mode.as_str(),
            "bid_commitment_root": self.bid_commitment_root,
            "sealed_fee_commitment": self.sealed_fee_commitment,
            "max_fee_piconero": self.max_fee_piconero.to_string(),
            "min_savings_bps": self.min_savings_bps,
            "promised_ratio_bps": self.promised_ratio_bps,
            "pq_key_commitment": self.pq_key_commitment,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        deterministic_record_root("bid", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressorOperator {
    pub compressor_id: String,
    pub status: CompressorStatus,
    pub operator_commitment: String,
    pub pq_identity_root: String,
    pub stake_piconero: u128,
    pub min_pq_security_bits: u16,
    pub accepted_modes: BTreeSet<CompressionMode>,
    pub served_namespaces: BTreeSet<String>,
    pub receipts_compressed: u64,
    pub bytes_saved: u128,
    pub rewards_earned_piconero: u128,
    pub slashing_count: u64,
    pub last_attested_height: u64,
}

impl CompressorOperator {
    pub fn active_for(&self, mode: CompressionMode, namespace: &str) -> bool {
        self.status.accepts_work()
            && self.accepted_modes.contains(&mode)
            && (self.served_namespaces.is_empty() || self.served_namespaces.contains(namespace))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compressor_operator",
            "compressor_id": redacted_operator(&self.compressor_id),
            "status": format!("{:?}", self.status).to_lowercase(),
            "operator_commitment": self.operator_commitment,
            "pq_identity_root": self.pq_identity_root,
            "stake_piconero": self.stake_piconero.to_string(),
            "min_pq_security_bits": self.min_pq_security_bits,
            "accepted_modes": self.accepted_modes.iter().map(|mode| mode.as_str()).collect::<Vec<_>>(),
            "served_namespace_count": self.served_namespaces.len(),
            "receipts_compressed": self.receipts_compressed,
            "bytes_saved": self.bytes_saved.to_string(),
            "rewards_earned_piconero": self.rewards_earned_piconero.to_string(),
            "slashing_count": self.slashing_count,
            "last_attested_height": self.last_attested_height
        })
    }

    pub fn root(&self) -> String {
        deterministic_record_root("compressor", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCompressorAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub market_id: String,
    pub receipt_id: String,
    pub compressor_id: String,
    pub bid_id: Option<String>,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub preimage_policy_root: String,
    pub compressed_receipt_root: String,
    pub compression_ratio_bps: u64,
    pub privacy_set_size: u64,
    pub fee_saved_piconero: u128,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqCompressorAttestation {
    pub fn meets_privacy_floor(&self, config: &Config) -> bool {
        self.privacy_set_size >= config.min_privacy_set_size
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_compressor_attestation",
            "attestation_id": self.attestation_id,
            "attestation_kind": self.kind.as_str(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "market_id": self.market_id,
            "receipt_id": self.receipt_id,
            "compressor_id": redacted_operator(&self.compressor_id),
            "bid_id": self.bid_id,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "preimage_policy_root": self.preimage_policy_root,
            "compressed_receipt_root": self.compressed_receipt_root,
            "compression_ratio_bps": self.compression_ratio_bps,
            "privacy_set_size": self.privacy_set_size,
            "fee_saved_piconero": self.fee_saved_piconero.to_string(),
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        deterministic_record_root("attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NamespaceRentCredit {
    pub credit_id: String,
    pub market_id: String,
    pub contract_namespace: String,
    pub operator_id: String,
    pub status: RentCreditStatus,
    pub receipt_id: Option<String>,
    pub namespace_root: String,
    pub rented_bytes_before: u64,
    pub rented_bytes_after: u64,
    pub credit_piconero: u128,
    pub rebate_bps: u64,
    pub earned_at_height: u64,
    pub expires_at_height: u64,
}

impl NamespaceRentCredit {
    pub fn bytes_reduced(&self) -> u64 {
        self.rented_bytes_before
            .saturating_sub(self.rented_bytes_after)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "namespace_rent_credit",
            "credit_id": self.credit_id,
            "market_id": self.market_id,
            "contract_namespace": self.contract_namespace,
            "operator_id": redacted_operator(&self.operator_id),
            "status": format!("{:?}", self.status).to_lowercase(),
            "receipt_id": self.receipt_id,
            "namespace_root": self.namespace_root,
            "rented_bytes_before": self.rented_bytes_before,
            "rented_bytes_after": self.rented_bytes_after,
            "bytes_reduced": self.bytes_reduced(),
            "credit_piconero": self.credit_piconero.to_string(),
            "rebate_bps": self.rebate_bps,
            "earned_at_height": self.earned_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        deterministic_record_root("rent-credit", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub market_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub status: AttestationStatus,
    pub allowed_fields: BTreeSet<String>,
    pub consumed_fields: BTreeSet<String>,
    pub max_redacted_receipts: u64,
    pub redacted_receipts: u64,
    pub privacy_floor: u64,
    pub budget_root: String,
}

impl RedactionBudget {
    pub fn remaining_receipts(&self) -> u64 {
        self.max_redacted_receipts
            .saturating_sub(self.redacted_receipts)
    }

    pub fn allows_field(&self, field: &str) -> bool {
        self.allowed_fields.contains(field) && !self.consumed_fields.contains(field)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "redaction_budget",
            "budget_id": self.budget_id,
            "market_id": self.market_id,
            "operator_id": redacted_operator(&self.operator_id),
            "epoch": self.epoch,
            "status": format!("{:?}", self.status).to_lowercase(),
            "allowed_fields": self.allowed_fields.iter().cloned().collect::<Vec<_>>(),
            "consumed_fields": self.consumed_fields.iter().cloned().collect::<Vec<_>>(),
            "max_redacted_receipts": self.max_redacted_receipts,
            "redacted_receipts": self.redacted_receipts,
            "remaining_receipts": self.remaining_receipts(),
            "privacy_floor": self.privacy_floor,
            "budget_root": self.budget_root
        })
    }

    pub fn root(&self) -> String {
        deterministic_record_root("redaction-budget", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCompressionReward {
    pub reward_id: String,
    pub market_id: String,
    pub receipt_id: String,
    pub compressor_id: String,
    pub attestation_id: String,
    pub status: RewardStatus,
    pub fee_saved_piconero: u128,
    pub reward_piconero: u128,
    pub reward_bps: u64,
    pub rent_credit_id: Option<String>,
    pub settled_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeCompressionReward {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_compression_reward",
            "reward_id": self.reward_id,
            "market_id": self.market_id,
            "receipt_id": self.receipt_id,
            "compressor_id": redacted_operator(&self.compressor_id),
            "attestation_id": self.attestation_id,
            "status": format!("{:?}", self.status).to_lowercase(),
            "fee_saved_piconero": self.fee_saved_piconero.to_string(),
            "reward_piconero": self.reward_piconero.to_string(),
            "reward_bps": self.reward_bps,
            "rent_credit_id": self.rent_credit_id,
            "settled_at_height": self.settled_at_height,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn root(&self) -> String {
        deterministic_record_root("reward", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub market_count: u64,
    pub receipt_count: u64,
    pub compressed_receipt_count: u64,
    pub attestation_count: u64,
    pub rejected_attestation_count: u64,
    pub total_bytes_saved: u128,
    pub total_fee_saved_piconero: u128,
    pub total_rewards_piconero: u128,
    pub rent_credits_piconero: u128,
    pub redaction_budget_root: String,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_summary",
            "summary_id": self.summary_id,
            "operator_id": redacted_operator(&self.operator_id),
            "epoch": self.epoch,
            "market_count": self.market_count,
            "receipt_count": self.receipt_count,
            "compressed_receipt_count": self.compressed_receipt_count,
            "attestation_count": self.attestation_count,
            "rejected_attestation_count": self.rejected_attestation_count,
            "total_bytes_saved": self.total_bytes_saved.to_string(),
            "total_fee_saved_piconero": self.total_fee_saved_piconero.to_string(),
            "total_rewards_piconero": self.total_rewards_piconero.to_string(),
            "rent_credits_piconero": self.rent_credits_piconero.to_string(),
            "redaction_budget_root": self.redaction_budget_root,
            "summary_root": self.summary_root
        })
    }

    pub fn root(&self) -> String {
        deterministic_record_root("operator-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub roots: Roots,
    pub counters: Counters,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub markets: BTreeMap<String, CompressionMarket>,
    pub receipts: BTreeMap<String, EncryptedContractReceipt>,
    pub bids: BTreeMap<String, BidderCommitment>,
    pub compressors: BTreeMap<String, CompressorOperator>,
    pub attestations: BTreeMap<String, PqCompressorAttestation>,
    pub rent_credits: BTreeMap<String, NamespaceRentCredit>,
    pub rewards: BTreeMap<String, LowFeeCompressionReward>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            roots: Roots::empty(),
            counters: Counters::default(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            markets: BTreeMap::new(),
            receipts: BTreeMap::new(),
            bids: BTreeMap::new(),
            compressors: BTreeMap::new(),
            attestations: BTreeMap::new(),
            rent_credits: BTreeMap::new(),
            rewards: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let namespace = "confidential.swap.receipts";
        let market_id = state
            .open_market(
                ReceiptMarketKind::DefiSettlementReceipt,
                namespace,
                sample_root("contract", namespace),
                3,
            )
            .expect("devnet market opens");
        let compressor_id = state
            .register_compressor(
                "devnet-receipt-compressor-alpha",
                75_000_000_000,
                [
                    CompressionMode::DictionaryDelta,
                    CompressionMode::CrossContractTraceFold,
                    CompressionMode::RecursiveReceiptRollup,
                ],
                [namespace.to_string()],
            )
            .expect("devnet compressor registers");
        let receipt_id = state
            .submit_receipt(
                &market_id,
                PrivacyTier::High,
                "caller-commitment-devnet-alpha",
                48_000,
                9_600,
                120_000,
                CompressionMode::CrossContractTraceFold,
            )
            .expect("devnet receipt submits");
        let bid_id = state
            .post_bid(
                &market_id,
                Some(receipt_id.clone()),
                "sealed-bidder-devnet-alpha",
                CompressionMode::CrossContractTraceFold,
                96_000,
                4_000,
                2_400,
            )
            .expect("devnet bid posts");
        let attestation_id = state
            .accept_compression(&receipt_id, &bid_id, &compressor_id, 9_100)
            .expect("devnet compression accepted");
        let credit_id = state
            .grant_namespace_rent_credit(
                &market_id,
                namespace,
                &compressor_id,
                Some(receipt_id.clone()),
                96_000,
                57_600,
            )
            .expect("devnet rent credit");
        state
            .settle_low_fee_reward(&receipt_id, &attestation_id, Some(credit_id))
            .expect("devnet reward settles");
        state
            .open_redaction_budget(
                &market_id,
                &compressor_id,
                ["compressor_id", "caller_commitment", "fee_saved_piconero"],
                24,
            )
            .expect("devnet redaction budget opens");
        state
            .summarize_operator(&compressor_id)
            .expect("devnet operator summary");
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let namespace = "confidential.dao.receipts";
        let market_id = state
            .open_market(
                ReceiptMarketKind::GovernanceReceipt,
                namespace,
                sample_root("contract", namespace),
                5,
            )
            .expect("demo market opens");
        let compressor_id = state
            .register_compressor(
                "demo-governance-receipt-compressor",
                55_000_000_000,
                [
                    CompressionMode::EventTopicDedup,
                    CompressionMode::ReceiptMerklePatch,
                ],
                [namespace.to_string()],
            )
            .expect("demo compressor registers");
        let receipt_id = state
            .submit_receipt(
                &market_id,
                PrivacyTier::AuditorOnly,
                "caller-commitment-demo-dao",
                32_768,
                8_192,
                90_000,
                CompressionMode::EventTopicDedup,
            )
            .expect("demo receipt submits");
        let bid_id = state
            .post_bid(
                &market_id,
                Some(receipt_id.clone()),
                "sealed-bidder-demo-dao",
                CompressionMode::EventTopicDedup,
                72_000,
                3_500,
                3_200,
            )
            .expect("demo bid posts");
        let attestation_id = state
            .accept_compression(&receipt_id, &bid_id, &compressor_id, 10_200)
            .expect("demo compression accepted");
        state
            .settle_low_fee_reward(&receipt_id, &attestation_id, None)
            .expect("demo reward settles");
        state
            .summarize_operator(&compressor_id)
            .expect("demo operator summary");
        state.refresh_roots();
        state
    }

    pub fn open_market(
        &mut self,
        kind: ReceiptMarketKind,
        contract_namespace: impl Into<String>,
        contract_commitment: impl Into<String>,
        shard_id: u16,
    ) -> Result<String> {
        ensure!(
            self.markets.len() < self.config.max_markets,
            "compression market capacity exceeded"
        );
        let namespace = contract_namespace.into();
        let record = json!({
            "kind": kind.as_str(),
            "namespace": namespace,
            "shard_id": shard_id,
            "height": self.l2_height,
            "epoch": self.epoch
        });
        let market_id = deterministic_id("market", self.markets.len() as u64 + 1, &record);
        let mut market = CompressionMarket::new(
            market_id.clone(),
            kind,
            namespace,
            contract_commitment,
            shard_id,
            self.epoch,
            self.l2_height,
            self.config.market_ttl_blocks,
        );
        market.target_privacy_set_size = self
            .config
            .target_privacy_set_size
            .max(kind.priority_weight() * 128);
        market.target_compression_ratio_bps = self.config.target_compression_ratio_bps;
        market.max_user_fee_bps = self.config.max_user_fee_bps;
        self.markets.insert(market_id.clone(), market);
        self.refresh_roots();
        Ok(market_id)
    }

    pub fn submit_receipt(
        &mut self,
        market_id: &str,
        privacy_tier: PrivacyTier,
        caller_commitment: impl Into<String>,
        original_bytes: u64,
        compressed_bytes: u64,
        max_fee_piconero: u128,
        compression_mode: CompressionMode,
    ) -> Result<String> {
        ensure!(
            self.receipts.len() < self.config.max_receipts,
            "encrypted receipt capacity exceeded"
        );
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| format!("unknown market {market_id}"))?;
        ensure!(
            market.is_live_at(self.l2_height),
            "market {market_id} is not accepting receipts"
        );
        ensure!(original_bytes > 0, "receipt must have original bytes");
        ensure!(
            compressed_bytes <= original_bytes,
            "compressed receipt cannot exceed original size"
        );
        ensure!(
            privacy_tier.min_set_size() >= self.config.min_privacy_set_size / 2,
            "privacy tier below runtime floor"
        );
        let caller_commitment = caller_commitment.into();
        let seed = format!("{market_id}:{caller_commitment}:{original_bytes}:{compressed_bytes}");
        let record = json!({
            "market_id": market_id,
            "caller_commitment": caller_commitment,
            "original_bytes": original_bytes,
            "compressed_bytes": compressed_bytes,
            "height": self.l2_height
        });
        let receipt_id = deterministic_id("receipt", self.receipts.len() as u64 + 1, &record);
        let receipt = EncryptedContractReceipt {
            receipt_id: receipt_id.clone(),
            market_id: market_id.to_string(),
            status: ReceiptStatus::Encrypted,
            privacy_tier,
            contract_namespace: market.contract_namespace.clone(),
            contract_commitment: market.contract_commitment.clone(),
            caller_commitment,
            call_nonce_commitment: sample_root("call-nonce", &seed),
            encrypted_receipt_root: sample_root("encrypted-receipt", &seed),
            event_topic_root: sample_root("event-topics", &seed),
            state_access_root: sample_root("state-access", &seed),
            nullifier_root: sample_root("nullifiers", &seed),
            inclusion_witness_root: sample_root("inclusion-witness", &seed),
            original_bytes,
            compressed_bytes,
            max_fee_piconero,
            created_at_height: self.l2_height,
            expires_at_height: self
                .l2_height
                .saturating_add(self.config.receipt_ttl_blocks),
            compression_mode,
            selected_bid_id: None,
            compressor_id: None,
            attestation_id: None,
        };
        self.receipts.insert(receipt_id.clone(), receipt);
        if let Some(market) = self.markets.get_mut(market_id) {
            market.receipt_count = market.receipt_count.saturating_add(1);
            market.reward_pool_piconero =
                market.reward_pool_piconero.saturating_add(max_fee_piconero);
        }
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn post_bid(
        &mut self,
        market_id: &str,
        receipt_id: Option<String>,
        bidder_id: impl Into<String>,
        compression_mode: CompressionMode,
        max_fee_piconero: u128,
        min_savings_bps: u64,
        promised_ratio_bps: u64,
    ) -> Result<String> {
        ensure!(
            self.bids.len() < self.config.max_bids,
            "bid capacity exceeded"
        );
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| format!("unknown market {market_id}"))?;
        ensure!(
            market.status.accepts_bids(),
            "market {market_id} does not accept bids"
        );
        if let Some(receipt_id) = receipt_id.as_ref() {
            ensure!(
                self.receipts.contains_key(receipt_id),
                "unknown receipt {receipt_id}"
            );
        }
        ensure!(min_savings_bps <= MAX_BPS, "min savings bps out of range");
        ensure!(
            promised_ratio_bps <= MAX_BPS,
            "promised ratio bps out of range"
        );
        let bidder_id = bidder_id.into();
        let record = json!({
            "market_id": market_id,
            "receipt_id": receipt_id,
            "bidder_id": bidder_id,
            "mode": compression_mode.as_str(),
            "height": self.l2_height
        });
        let bid_id = deterministic_id("bid", self.bids.len() as u64 + 1, &record);
        let seed = format!("{market_id}:{bid_id}:{bidder_id}");
        let bid = BidderCommitment {
            bid_id: bid_id.clone(),
            market_id: market_id.to_string(),
            receipt_id,
            bidder_id,
            status: BidStatus::Posted,
            compression_mode,
            bid_commitment_root: sample_root("bid-commitment", &seed),
            sealed_fee_commitment: sample_root("sealed-fee", &seed),
            max_fee_piconero,
            min_savings_bps,
            promised_ratio_bps,
            pq_key_commitment: sample_root("bidder-pq-key", &seed),
            posted_at_height: self.l2_height,
            expires_at_height: self.l2_height.saturating_add(self.config.bid_ttl_blocks),
        };
        self.bids.insert(bid_id.clone(), bid);
        self.refresh_roots();
        Ok(bid_id)
    }

    pub fn register_compressor<I, M>(
        &mut self,
        compressor_id: impl Into<String>,
        stake_piconero: u128,
        accepted_modes: I,
        served_namespaces: M,
    ) -> Result<String>
    where
        I: IntoIterator<Item = CompressionMode>,
        M: IntoIterator<Item = String>,
    {
        ensure!(
            self.compressors.len() < self.config.max_compressors,
            "compressor capacity exceeded"
        );
        let compressor_id = compressor_id.into();
        ensure!(
            !self.compressors.contains_key(&compressor_id),
            "compressor {compressor_id} already registered"
        );
        let accepted_modes = accepted_modes.into_iter().collect::<BTreeSet<_>>();
        ensure!(
            !accepted_modes.is_empty(),
            "compressor must accept at least one mode"
        );
        let served_namespaces = served_namespaces.into_iter().collect::<BTreeSet<_>>();
        let seed = format!("{compressor_id}:{stake_piconero}");
        let compressor = CompressorOperator {
            compressor_id: compressor_id.clone(),
            status: CompressorStatus::Active,
            operator_commitment: sample_root("operator", &seed),
            pq_identity_root: sample_root("pq-identity", &seed),
            stake_piconero,
            min_pq_security_bits: self.config.min_pq_security_bits,
            accepted_modes,
            served_namespaces,
            receipts_compressed: 0,
            bytes_saved: 0,
            rewards_earned_piconero: 0,
            slashing_count: 0,
            last_attested_height: self.l2_height,
        };
        self.compressors.insert(compressor_id.clone(), compressor);
        self.refresh_roots();
        Ok(compressor_id)
    }

    pub fn accept_compression(
        &mut self,
        receipt_id: &str,
        bid_id: &str,
        compressor_id: &str,
        base_fee_per_byte: u128,
    ) -> Result<String> {
        ensure!(
            self.attestations.len() < self.config.max_attestations,
            "attestation capacity exceeded"
        );
        let receipt = self
            .receipts
            .get(receipt_id)
            .ok_or_else(|| format!("unknown receipt {receipt_id}"))?
            .clone();
        let bid = self
            .bids
            .get(bid_id)
            .ok_or_else(|| format!("unknown bid {bid_id}"))?
            .clone();
        let market = self
            .markets
            .get(&receipt.market_id)
            .ok_or_else(|| format!("unknown market {}", receipt.market_id))?
            .clone();
        let compressor = self
            .compressors
            .get(compressor_id)
            .ok_or_else(|| format!("unknown compressor {compressor_id}"))?
            .clone();
        ensure!(bid.status.selectable(), "bid {bid_id} is not selectable");
        ensure!(
            bid.compression_mode == receipt.compression_mode,
            "bid mode does not match receipt mode"
        );
        ensure!(
            compressor.active_for(receipt.compression_mode, &receipt.contract_namespace),
            "compressor {compressor_id} cannot serve receipt namespace or mode"
        );
        ensure!(
            receipt.compression_ratio_bps()
                <= market
                    .target_compression_ratio_bps
                    .max(bid.promised_ratio_bps),
            "receipt compression ratio misses market target"
        );
        let fee_saved = receipt.estimated_fee_saved_piconero(base_fee_per_byte);
        let record = json!({
            "receipt_id": receipt_id,
            "bid_id": bid_id,
            "compressor_id": compressor_id,
            "fee_saved": fee_saved.to_string(),
            "height": self.l2_height
        });
        let attestation_id =
            deterministic_id("attestation", self.attestations.len() as u64 + 1, &record);
        let seed = format!("{receipt_id}:{bid_id}:{compressor_id}");
        let attestation = PqCompressorAttestation {
            attestation_id: attestation_id.clone(),
            kind: AttestationKind::CompressionCorrectness,
            status: AttestationStatus::Accepted,
            market_id: receipt.market_id.clone(),
            receipt_id: receipt_id.to_string(),
            compressor_id: compressor_id.to_string(),
            bid_id: Some(bid_id.to_string()),
            pq_signature_root: sample_root("pq-compressor-signature", &seed),
            transcript_root: sample_root("compression-transcript", &seed),
            preimage_policy_root: sample_root("preimage-policy", &seed),
            compressed_receipt_root: sample_root("compressed-receipt", &seed),
            compression_ratio_bps: receipt.compression_ratio_bps(),
            privacy_set_size: receipt
                .privacy_tier
                .min_set_size()
                .max(market.target_privacy_set_size),
            fee_saved_piconero: fee_saved,
            attested_at_height: self.l2_height,
            expires_at_height: self
                .l2_height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        ensure!(
            attestation.meets_privacy_floor(&self.config),
            "attestation privacy set below floor"
        );
        if let Some(receipt) = self.receipts.get_mut(receipt_id) {
            receipt.status = ReceiptStatus::Attested;
            receipt.selected_bid_id = Some(bid_id.to_string());
            receipt.compressor_id = Some(compressor_id.to_string());
            receipt.attestation_id = Some(attestation_id.clone());
        }
        if let Some(bid) = self.bids.get_mut(bid_id) {
            bid.status = BidStatus::Filled;
            bid.receipt_id = Some(receipt_id.to_string());
        }
        if let Some(market) = self.markets.get_mut(&receipt.market_id) {
            market.compressed_receipt_count = market.compressed_receipt_count.saturating_add(1);
        }
        if let Some(compressor) = self.compressors.get_mut(compressor_id) {
            compressor.receipts_compressed = compressor.receipts_compressed.saturating_add(1);
            compressor.bytes_saved = compressor.bytes_saved.saturating_add(
                receipt
                    .original_bytes
                    .saturating_sub(receipt.compressed_bytes)
                    .into(),
            );
            compressor.last_attested_height = self.l2_height;
        }
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn grant_namespace_rent_credit(
        &mut self,
        market_id: &str,
        contract_namespace: &str,
        operator_id: &str,
        receipt_id: Option<String>,
        rented_bytes_before: u64,
        rented_bytes_after: u64,
    ) -> Result<String> {
        ensure!(
            self.rent_credits.len() < self.config.max_rent_credits,
            "rent credit capacity exceeded"
        );
        ensure!(
            self.markets.contains_key(market_id),
            "unknown market {market_id}"
        );
        ensure!(
            rented_bytes_after <= rented_bytes_before,
            "rent credit cannot increase rented bytes"
        );
        let bytes_reduced = rented_bytes_before.saturating_sub(rented_bytes_after);
        let credit_piconero = (bytes_reduced as u128)
            .saturating_mul(self.config.rent_credit_rebate_bps as u128)
            / MAX_BPS as u128;
        let record = json!({
            "market_id": market_id,
            "namespace": contract_namespace,
            "operator_id": operator_id,
            "bytes_reduced": bytes_reduced,
            "height": self.l2_height
        });
        let credit_id =
            deterministic_id("rent-credit", self.rent_credits.len() as u64 + 1, &record);
        let credit = NamespaceRentCredit {
            credit_id: credit_id.clone(),
            market_id: market_id.to_string(),
            contract_namespace: contract_namespace.to_string(),
            operator_id: operator_id.to_string(),
            status: RentCreditStatus::Earned,
            receipt_id,
            namespace_root: sample_root("namespace-rent-credit", contract_namespace),
            rented_bytes_before,
            rented_bytes_after,
            credit_piconero,
            rebate_bps: self.config.rent_credit_rebate_bps,
            earned_at_height: self.l2_height,
            expires_at_height: self.l2_height.saturating_add(self.config.reward_ttl_blocks),
        };
        if let Some(market) = self.markets.get_mut(market_id) {
            market.rent_credit_pool_piconero = market
                .rent_credit_pool_piconero
                .saturating_add(credit_piconero);
        }
        self.rent_credits.insert(credit_id.clone(), credit);
        self.refresh_roots();
        Ok(credit_id)
    }

    pub fn settle_low_fee_reward(
        &mut self,
        receipt_id: &str,
        attestation_id: &str,
        rent_credit_id: Option<String>,
    ) -> Result<String> {
        ensure!(
            self.rewards.len() < self.config.max_rewards,
            "reward capacity exceeded"
        );
        let receipt = self
            .receipts
            .get(receipt_id)
            .ok_or_else(|| format!("unknown receipt {receipt_id}"))?
            .clone();
        let attestation = self
            .attestations
            .get(attestation_id)
            .ok_or_else(|| format!("unknown attestation {attestation_id}"))?
            .clone();
        ensure!(
            attestation.status.valid(),
            "attestation {attestation_id} is not accepted"
        );
        let reward_piconero = attestation
            .fee_saved_piconero
            .saturating_mul(self.config.target_reward_bps as u128)
            / MAX_BPS as u128;
        let record = json!({
            "receipt_id": receipt_id,
            "attestation_id": attestation_id,
            "compressor_id": attestation.compressor_id,
            "height": self.l2_height
        });
        let reward_id = deterministic_id("reward", self.rewards.len() as u64 + 1, &record);
        let reward = LowFeeCompressionReward {
            reward_id: reward_id.clone(),
            market_id: receipt.market_id.clone(),
            receipt_id: receipt_id.to_string(),
            compressor_id: attestation.compressor_id.clone(),
            attestation_id: attestation_id.to_string(),
            status: RewardStatus::Settled,
            fee_saved_piconero: attestation.fee_saved_piconero,
            reward_piconero,
            reward_bps: self.config.target_reward_bps,
            rent_credit_id: rent_credit_id.clone(),
            settled_at_height: self.l2_height,
            expires_at_height: self.l2_height.saturating_add(self.config.reward_ttl_blocks),
        };
        if let Some(receipt) = self.receipts.get_mut(receipt_id) {
            receipt.status = ReceiptStatus::Settled;
        }
        if let Some(compressor) = self.compressors.get_mut(&attestation.compressor_id) {
            compressor.rewards_earned_piconero = compressor
                .rewards_earned_piconero
                .saturating_add(reward_piconero);
        }
        if let Some(credit_id) = rent_credit_id {
            if let Some(credit) = self.rent_credits.get_mut(&credit_id) {
                credit.status = RentCreditStatus::Applied;
            }
        }
        self.rewards.insert(reward_id.clone(), reward);
        self.refresh_roots();
        Ok(reward_id)
    }

    pub fn open_redaction_budget<I>(
        &mut self,
        market_id: &str,
        operator_id: &str,
        allowed_fields: I,
        max_redacted_receipts: u64,
    ) -> Result<String>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity exceeded"
        );
        ensure!(
            self.markets.contains_key(market_id),
            "unknown market {market_id}"
        );
        let allowed_fields = allowed_fields
            .into_iter()
            .map(|field| field.as_ref().to_string())
            .collect::<BTreeSet<_>>();
        let record = json!({
            "market_id": market_id,
            "operator_id": operator_id,
            "epoch": self.epoch,
            "allowed_fields": allowed_fields.iter().cloned().collect::<Vec<_>>()
        });
        let budget_id = deterministic_id(
            "redaction-budget",
            self.redaction_budgets.len() as u64 + 1,
            &record,
        );
        let budget = RedactionBudget {
            budget_id: budget_id.clone(),
            market_id: market_id.to_string(),
            operator_id: operator_id.to_string(),
            epoch: self.epoch,
            status: AttestationStatus::Accepted,
            allowed_fields,
            consumed_fields: BTreeSet::new(),
            max_redacted_receipts,
            redacted_receipts: 0,
            privacy_floor: self.config.min_privacy_set_size,
            budget_root: sample_root("redaction-budget", &budget_id),
        };
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn summarize_operator(&mut self, operator_id: &str) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity exceeded"
        );
        ensure!(
            self.compressors.contains_key(operator_id),
            "unknown operator {operator_id}"
        );
        let receipt_count = self
            .receipts
            .values()
            .filter(|receipt| receipt.compressor_id.as_deref() == Some(operator_id))
            .count() as u64;
        let compressed_receipt_count = self
            .receipts
            .values()
            .filter(|receipt| {
                receipt.compressor_id.as_deref() == Some(operator_id) && receipt.status.compressed()
            })
            .count() as u64;
        let attestation_count = self
            .attestations
            .values()
            .filter(|attestation| attestation.compressor_id == operator_id)
            .count() as u64;
        let rejected_attestation_count = self
            .attestations
            .values()
            .filter(|attestation| {
                attestation.compressor_id == operator_id
                    && !matches!(attestation.status, AttestationStatus::Accepted)
            })
            .count() as u64;
        let total_fee_saved_piconero = self
            .attestations
            .values()
            .filter(|attestation| attestation.compressor_id == operator_id)
            .map(|attestation| attestation.fee_saved_piconero)
            .sum();
        let total_rewards_piconero = self
            .rewards
            .values()
            .filter(|reward| reward.compressor_id == operator_id)
            .map(|reward| reward.reward_piconero)
            .sum();
        let rent_credits_piconero = self
            .rent_credits
            .values()
            .filter(|credit| credit.operator_id == operator_id)
            .map(|credit| credit.credit_piconero)
            .sum();
        let total_bytes_saved = self
            .receipts
            .values()
            .filter(|receipt| receipt.compressor_id.as_deref() == Some(operator_id))
            .map(|receipt| {
                receipt
                    .original_bytes
                    .saturating_sub(receipt.compressed_bytes) as u128
            })
            .sum();
        let record = json!({
            "operator_id": operator_id,
            "epoch": self.epoch,
            "receipt_count": receipt_count,
            "attestation_count": attestation_count
        });
        let summary_id = deterministic_id(
            "operator-summary",
            self.operator_summaries.len() as u64 + 1,
            &record,
        );
        let budget_records = self
            .redaction_budgets
            .values()
            .filter(|budget| budget.operator_id == operator_id)
            .map(RedactionBudget::public_record)
            .collect::<Vec<_>>();
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_id: operator_id.to_string(),
            epoch: self.epoch,
            market_count: self.markets.len() as u64,
            receipt_count,
            compressed_receipt_count,
            attestation_count,
            rejected_attestation_count,
            total_bytes_saved,
            total_fee_saved_piconero,
            total_rewards_piconero,
            rent_credits_piconero,
            redaction_budget_root: public_record_root(
                "operator-redaction-budgets",
                &budget_records,
            ),
            summary_root: sample_root("operator-summary", &summary_id),
        };
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn derive_counters(&self) -> Counters {
        Counters {
            markets: self.markets.len(),
            open_markets: self
                .markets
                .values()
                .filter(|market| market.status.accepts_receipts())
                .count(),
            receipts: self.receipts.len(),
            live_receipts: self
                .receipts
                .values()
                .filter(|receipt| receipt.status.live())
                .count(),
            compressed_receipts: self
                .receipts
                .values()
                .filter(|receipt| receipt.status.compressed())
                .count(),
            bids: self.bids.len(),
            selectable_bids: self
                .bids
                .values()
                .filter(|bid| bid.status.selectable())
                .count(),
            compressors: self.compressors.len(),
            active_compressors: self
                .compressors
                .values()
                .filter(|compressor| compressor.status.accepts_work())
                .count(),
            attestations: self.attestations.len(),
            accepted_attestations: self
                .attestations
                .values()
                .filter(|attestation| attestation.status.valid())
                .count(),
            rent_credits: self.rent_credits.len(),
            applied_rent_credits: self
                .rent_credits
                .values()
                .filter(|credit| matches!(credit.status, RentCreditStatus::Applied))
                .count(),
            low_fee_rewards: self.rewards.len(),
            settled_rewards: self
                .rewards
                .values()
                .filter(|reward| matches!(reward.status, RewardStatus::Settled))
                .count(),
            redaction_budgets: self.redaction_budgets.len(),
            operator_summaries: self.operator_summaries.len(),
            total_original_bytes: self
                .receipts
                .values()
                .map(|receipt| receipt.original_bytes as u128)
                .sum(),
            total_compressed_bytes: self
                .receipts
                .values()
                .map(|receipt| receipt.compressed_bytes as u128)
                .sum(),
            total_fee_saved_piconero: self
                .attestations
                .values()
                .map(|attestation| attestation.fee_saved_piconero)
                .sum(),
            total_rewards_piconero: self
                .rewards
                .values()
                .map(|reward| reward.reward_piconero)
                .sum(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_encrypted_receipt_compression_market_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "encrypted_receipt_suite": ENCRYPTED_RECEIPT_SUITE,
            "receipt_compression_suite": RECEIPT_COMPRESSION_SUITE,
            "pq_compressor_attestation_suite": PQ_COMPRESSOR_ATTESTATION_SUITE,
            "bidder_commitment_suite": BIDDER_COMMITMENT_SUITE,
            "namespace_rent_credit_suite": NAMESPACE_RENT_CREDIT_SUITE,
            "low_fee_reward_suite": LOW_FEE_REWARD_SUITE,
            "redaction_budget_suite": REDACTION_BUDGET_SUITE,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "counters_root": self.roots.counters_root,
                "market_root": self.roots.market_root,
                "receipt_root": self.roots.receipt_root,
                "bid_root": self.roots.bid_root,
                "compressor_root": self.roots.compressor_root,
                "attestation_root": self.roots.attestation_root,
                "rent_credit_root": self.roots.rent_credit_root,
                "reward_root": self.roots.reward_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "operator_summary_root": self.roots.operator_summary_root,
                "namespace_root": self.roots.namespace_root
            }
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["roots"]["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.derive_counters();
        self.roots.config_root = deterministic_record_root("config", &self.config.public_record());
        self.roots.counters_root =
            deterministic_record_root("counters", &self.counters.public_record());
        self.roots.market_root = public_record_root(
            "markets",
            &values_record(&self.markets, CompressionMarket::public_record),
        );
        self.roots.receipt_root = public_record_root(
            "receipts",
            &values_record(&self.receipts, EncryptedContractReceipt::public_record),
        );
        self.roots.bid_root = public_record_root(
            "bids",
            &values_record(&self.bids, BidderCommitment::public_record),
        );
        self.roots.compressor_root = public_record_root(
            "compressors",
            &values_record(&self.compressors, CompressorOperator::public_record),
        );
        self.roots.attestation_root = public_record_root(
            "attestations",
            &values_record(&self.attestations, PqCompressorAttestation::public_record),
        );
        self.roots.rent_credit_root = public_record_root(
            "rent-credits",
            &values_record(&self.rent_credits, NamespaceRentCredit::public_record),
        );
        self.roots.reward_root = public_record_root(
            "rewards",
            &values_record(&self.rewards, LowFeeCompressionReward::public_record),
        );
        self.roots.redaction_budget_root = public_record_root(
            "redaction-budgets",
            &values_record(&self.redaction_budgets, RedactionBudget::public_record),
        );
        self.roots.operator_summary_root = public_record_root(
            "operator-summaries",
            &values_record(&self.operator_summaries, OperatorSummary::public_record),
        );
        let namespace_records = self
            .markets
            .values()
            .map(|market| {
                json!({
                    "namespace": market.contract_namespace,
                    "namespace_root": market.namespace_root,
                    "market_id": market.market_id
                })
            })
            .collect::<Vec<_>>();
        self.roots.namespace_root = public_record_root("namespaces", &namespace_records);
        self.roots.state_root = self.state_root();
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

pub fn deterministic_id(domain: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-RECEIPT-COMPRESSION-MARKET:{domain}-ID"
        ),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        20,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-RECEIPT-COMPRESSION-MARKET:{domain}-ROOT"
        ),
        records,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-RECEIPT-COMPRESSION-MARKET:{domain}"
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-RECEIPT-COMPRESSION-MARKET:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

fn values_record<T, F>(records: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    records.values().map(public_record).collect()
}

fn sample_root(domain: &str, seed: &str) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-RECEIPT-COMPRESSION-MARKET:SAMPLE:{domain}"
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(seed)],
        32,
    )
}

fn redacted_operator(operator_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-RECEIPT-COMPRESSION-MARKET:REDACTED-OPERATOR",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(operator_id)],
        16,
    )
}
