use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialProofFeeSwapVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-proof-fee-swap-vault-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-proof-fee-swap-vault-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT: u64 =
    928_000;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_VAULTS:
    usize = 262_144;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_SWAP_INTENTS:
    usize = 4_194_304;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_FEE_BUCKETS:
    usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_QUOTES:
    usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_BATCHES:
    usize = 524_288;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_RECEIPTS:
    usize = 4_194_304;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_REBATES:
    usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 256;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_TARGET_PRIVACY_SET:
    u64 = 4_096;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_SWAP_FEE_BPS:
    u64 = 18;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_PROTOCOL_FEE_BPS:
    u64 = 3;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_TARGET_REBATE_BPS:
    u64 = 8;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS:
    u64 = 360;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS:
    u64 = 40;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultKind {
    ConstantProduct,
    StableSwap,
    ConcentratedRange,
    ProofFeeAccumulator,
    RoutingTreasury,
    RebateSink,
}

impl VaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::StableSwap => "stable_swap",
            Self::ConcentratedRange => "concentrated_range",
            Self::ProofFeeAccumulator => "proof_fee_accumulator",
            Self::RoutingTreasury => "routing_treasury",
            Self::RebateSink => "rebate_sink",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Open,
    Paused,
    Rebalancing,
    Draining,
    Closed,
}

impl VaultStatus {
    pub fn accepts_flow(self) -> bool {
        matches!(self, Self::Open | Self::Rebalancing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapSide {
    BaseToQuote,
    QuoteToBase,
    MultiHop,
}

impl SwapSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseToQuote => "base_to_quote",
            Self::QuoteToBase => "quote_to_base",
            Self::MultiHop => "multi_hop",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapIntentStatus {
    Pending,
    Quoted,
    Batched,
    Cleared,
    RebateQueued,
    Settled,
    Expired,
    Rejected,
}

impl SwapIntentStatus {
    pub fn is_pending(self) -> bool {
        matches!(self, Self::Pending | Self::Quoted)
    }

    pub fn can_batch(self) -> bool {
        matches!(self, Self::Pending | Self::Quoted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeBucketStatus {
    Open,
    Reserved,
    Consumed,
    RebatePending,
    Refunded,
    Exhausted,
    Frozen,
}

impl FeeBucketStatus {
    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Open | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqQuoteVerdict {
    Accept,
    Reprice,
    ReduceSize,
    Delay,
    Reject,
}

impl PqQuoteVerdict {
    pub fn allows_clearing(self) -> bool {
        matches!(self, Self::Accept | Self::Reprice | Self::ReduceSize)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailSeverity {
    Info,
    Low,
    Medium,
    High,
    Halt,
}

impl GuardrailSeverity {
    pub fn blocks_flow(self) -> bool {
        matches!(self, Self::High | Self::Halt)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingBatchStatus {
    Proposed,
    PqAttested,
    Clearing,
    Cleared,
    RebateSettled,
    Disputed,
    Cancelled,
}

impl ClearingBatchStatus {
    pub fn can_settle(self) -> bool {
        matches!(self, Self::PqAttested | Self::Clearing | Self::Cleared)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Nettable,
    SettledPrivately,
    Refunded,
    DonatedToVault,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    VaultRegistered,
    FeeBucketOpened,
    SwapIntentAccepted,
    QuoteAttested,
    GuardrailEvaluated,
    BatchCleared,
    RebateSettled,
    OperatorSummaryPublished,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultRegistered => "vault_registered",
            Self::FeeBucketOpened => "fee_bucket_opened",
            Self::SwapIntentAccepted => "swap_intent_accepted",
            Self::QuoteAttested => "quote_attested",
            Self::GuardrailEvaluated => "guardrail_evaluated",
            Self::BatchCleared => "batch_cleared",
            Self::RebateSettled => "rebate_settled",
            Self::OperatorSummaryPublished => "operator_summary_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub max_vaults: usize,
    pub max_swap_intents: usize,
    pub max_fee_buckets: usize,
    pub max_quote_attestations: usize,
    pub max_clearing_batches: usize,
    pub max_settlement_receipts: usize,
    pub max_rebate_settlements: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_swap_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub intent_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub require_private_fee_settlement: bool,
    pub require_pq_quote_attestation: bool,
    pub allow_fee_credit_rebates: bool,
    pub low_fee_mode: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_HASH_SUITE
                    .to_string(),
            pq_suite: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_PQ_SUITE
                .to_string(),
            max_vaults:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_VAULTS,
            max_swap_intents:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_SWAP_INTENTS,
            max_fee_buckets:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_FEE_BUCKETS,
            max_quote_attestations:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_QUOTES,
            max_clearing_batches:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_BATCHES,
            max_settlement_receipts:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebate_settlements:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_REBATES,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set_size:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_TARGET_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_swap_fee_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MAX_SWAP_FEE_BPS,
            protocol_fee_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_PROTOCOL_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            intent_ttl_blocks:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            quote_ttl_blocks:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            require_private_fee_settlement: true,
            require_pq_quote_attestation: true,
            allow_fee_credit_rebates: true,
            low_fee_mode: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        required("protocol_version", &self.protocol_version)?;
        if self.protocol_version
            != PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_PROTOCOL_VERSION
        {
            return Err("proof-fee swap vault protocol version mismatch".to_string());
        }
        required("chain_id", &self.chain_id)?;
        required("hash_suite", &self.hash_suite)?;
        required("pq_suite", &self.pq_suite)?;
        require(self.max_vaults > 0, "max_vaults must be positive")?;
        require(
            self.max_swap_intents > 0,
            "max_swap_intents must be positive",
        )?;
        require(self.max_fee_buckets > 0, "max_fee_buckets must be positive")?;
        require(
            self.max_quote_attestations > 0,
            "max_quote_attestations must be positive",
        )?;
        require(
            self.max_clearing_batches > 0,
            "max_clearing_batches must be positive",
        )?;
        require(
            self.max_settlement_receipts > 0,
            "max_settlement_receipts must be positive",
        )?;
        require(
            self.max_rebate_settlements > 0,
            "max_rebate_settlements must be positive",
        )?;
        require(
            self.min_privacy_set_size > 0,
            "min_privacy_set_size must be positive",
        )?;
        require(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set cannot be below minimum",
        )?;
        require(
            self.min_pq_security_bits >= 128,
            "minimum PQ security must be at least 128 bits",
        )?;
        require_bps("max_swap_fee_bps", self.max_swap_fee_bps)?;
        require_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require(
            self.protocol_fee_bps <= self.max_swap_fee_bps,
            "protocol fee cannot exceed max swap fee",
        )?;
        require(
            self.target_rebate_bps <= self.max_swap_fee_bps,
            "target rebate cannot exceed max swap fee",
        )?;
        require(
            self.intent_ttl_blocks > 0,
            "intent_ttl_blocks must be positive",
        )?;
        require(
            self.quote_ttl_blocks > 0,
            "quote_ttl_blocks must be positive",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "max_vaults": self.max_vaults,
            "max_swap_intents": self.max_swap_intents,
            "max_fee_buckets": self.max_fee_buckets,
            "max_quote_attestations": self.max_quote_attestations,
            "max_clearing_batches": self.max_clearing_batches,
            "max_settlement_receipts": self.max_settlement_receipts,
            "max_rebate_settlements": self.max_rebate_settlements,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_swap_fee_bps": self.max_swap_fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "require_private_fee_settlement": self.require_private_fee_settlement,
            "require_pq_quote_attestation": self.require_pq_quote_attestation,
            "allow_fee_credit_rebates": self.allow_fee_credit_rebates,
            "low_fee_mode": self.low_fee_mode,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub swap_intents: u64,
    pub fee_buckets: u64,
    pub quote_attestations: u64,
    pub guardrails: u64,
    pub clearing_batches: u64,
    pub settlement_receipts: u64,
    pub rebate_settlements: u64,
    pub operator_summaries: u64,
    pub private_fee_settlements: u64,
    pub low_fee_savings_atomic_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "vaults": self.vaults,
            "swap_intents": self.swap_intents,
            "fee_buckets": self.fee_buckets,
            "quote_attestations": self.quote_attestations,
            "guardrails": self.guardrails,
            "clearing_batches": self.clearing_batches,
            "settlement_receipts": self.settlement_receipts,
            "rebate_settlements": self.rebate_settlements,
            "operator_summaries": self.operator_summaries,
            "private_fee_settlements": self.private_fee_settlements,
            "low_fee_savings_atomic_units": self.low_fee_savings_atomic_units.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub swap_intent_root: String,
    pub fee_bucket_root: String,
    pub quote_attestation_root: String,
    pub guardrail_root: String,
    pub clearing_batch_root: String,
    pub settlement_receipt_root: String,
    pub rebate_settlement_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "vault_root": self.vault_root,
            "swap_intent_root": self.swap_intent_root,
            "fee_bucket_root": self.fee_bucket_root,
            "quote_attestation_root": self.quote_attestation_root,
            "guardrail_root": self.guardrail_root,
            "clearing_batch_root": self.clearing_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_settlement_root": self.rebate_settlement_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialProofFeeVault {
    pub vault_id: String,
    pub label: String,
    pub kind: VaultKind,
    pub status: VaultStatus,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub lp_note_root: String,
    pub reserve_commitment_root: String,
    pub fee_credit_bucket_root: String,
    pub routing_policy_root: String,
    pub min_trade_atomic_units: u128,
    pub max_trade_atomic_units: u128,
    pub available_liquidity_atomic_units: u128,
    pub locked_liquidity_atomic_units: u128,
    pub max_swap_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub low_fee_priority: u8,
    pub created_height: u64,
    pub updated_height: u64,
}

impl ConfidentialProofFeeVault {
    pub fn new(
        label: impl Into<String>,
        kind: VaultKind,
        base_asset_commitment: impl Into<String>,
        quote_asset_commitment: impl Into<String>,
        max_swap_fee_bps: u64,
    ) -> Self {
        let mut vault = Self {
            vault_id: String::new(),
            label: label.into(),
            kind,
            status: VaultStatus::Open,
            base_asset_commitment: base_asset_commitment.into(),
            quote_asset_commitment: quote_asset_commitment.into(),
            lp_note_root: empty_root("LP-NOTES"),
            reserve_commitment_root: empty_root("RESERVES"),
            fee_credit_bucket_root: empty_root("FEE-BUCKETS"),
            routing_policy_root: empty_root("ROUTING-POLICY"),
            min_trade_atomic_units: 10_000,
            max_trade_atomic_units: 75_000_000_000,
            available_liquidity_atomic_units: 9_000_000_000_000,
            locked_liquidity_atomic_units: 0,
            max_swap_fee_bps,
            protocol_fee_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_PROTOCOL_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            privacy_set_size:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_TARGET_PRIVACY_SET,
            pq_security_bits:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_priority: 10,
            created_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT,
            updated_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT,
        };
        vault.vault_id = id_from_record("VAULT-ID", &vault.public_record_without_id());
        vault
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        required("vault_id", &self.vault_id)?;
        required("label", &self.label)?;
        required("base_asset_commitment", &self.base_asset_commitment)?;
        required("quote_asset_commitment", &self.quote_asset_commitment)?;
        require_root("lp_note_root", &self.lp_note_root)?;
        require_root("reserve_commitment_root", &self.reserve_commitment_root)?;
        require_root("fee_credit_bucket_root", &self.fee_credit_bucket_root)?;
        require_root("routing_policy_root", &self.routing_policy_root)?;
        require(
            self.status.accepts_flow() || self.locked_liquidity_atomic_units == 0,
            "paused vaults cannot carry newly locked liquidity",
        )?;
        require(
            self.min_trade_atomic_units <= self.max_trade_atomic_units,
            "vault minimum trade exceeds maximum trade",
        )?;
        require(
            self.max_trade_atomic_units <= self.available_liquidity_atomic_units,
            "vault maximum trade exceeds available liquidity",
        )?;
        require_bps("vault max_swap_fee_bps", self.max_swap_fee_bps)?;
        require_bps("vault protocol_fee_bps", self.protocol_fee_bps)?;
        require_bps("vault target_rebate_bps", self.target_rebate_bps)?;
        require(
            self.max_swap_fee_bps <= config.max_swap_fee_bps,
            "vault fee exceeds runtime low-fee cap",
        )?;
        require(
            self.protocol_fee_bps <= self.max_swap_fee_bps,
            "vault protocol fee exceeds vault fee",
        )?;
        require(
            self.target_rebate_bps <= self.max_swap_fee_bps,
            "vault target rebate exceeds vault fee",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "vault privacy set below runtime minimum",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "vault PQ security below runtime minimum",
        )?;
        Ok(())
    }

    pub fn fee_quote_atomic_units(&self, notional_atomic_units: u128) -> u128 {
        notional_atomic_units.saturating_mul(self.max_swap_fee_bps as u128)
            / PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_MAX_BPS as u128
    }

    pub fn rebate_quote_atomic_units(&self, notional_atomic_units: u128) -> u128 {
        notional_atomic_units.saturating_mul(self.target_rebate_bps as u128)
            / PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_MAX_BPS as u128
    }

    pub fn can_fill(&self, amount_atomic_units: u128) -> bool {
        self.status.accepts_flow()
            && amount_atomic_units >= self.min_trade_atomic_units
            && amount_atomic_units <= self.max_trade_atomic_units
            && amount_atomic_units <= self.available_liquidity_atomic_units
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "label": self.label,
            "kind": self.kind,
            "status": self.status,
            "base_asset_commitment": self.base_asset_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "lp_note_root": self.lp_note_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "fee_credit_bucket_root": self.fee_credit_bucket_root,
            "routing_policy_root": self.routing_policy_root,
            "min_trade_atomic_units": self.min_trade_atomic_units.to_string(),
            "max_trade_atomic_units": self.max_trade_atomic_units.to_string(),
            "available_liquidity_atomic_units": self.available_liquidity_atomic_units.to_string(),
            "locked_liquidity_atomic_units": self.locked_liquidity_atomic_units.to_string(),
            "max_swap_fee_bps": self.max_swap_fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "low_fee_priority": self.low_fee_priority,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["vault_id"] = json!(self.vault_id);
        record
    }

    pub fn state_root(&self) -> String {
        root_from_record("VAULT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwapIntent {
    pub intent_id: String,
    pub vault_id: String,
    pub side: SwapSide,
    pub status: SwapIntentStatus,
    pub input_note_commitment: String,
    pub output_note_commitment: String,
    pub trader_view_tag: String,
    pub route_commitment: String,
    pub amount_commitment: String,
    pub amount_upper_bound_atomic_units: u128,
    pub max_fee_atomic_units: u128,
    pub quoted_fee_atomic_units: u128,
    pub expected_rebate_atomic_units: u128,
    pub slippage_bps: u64,
    pub proof_fee_nullifier: String,
    pub fee_bucket_id: String,
    pub quote_attestation_id: String,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl SwapIntent {
    pub fn new(
        vault: &ConfidentialProofFeeVault,
        side: SwapSide,
        input_note_commitment: impl Into<String>,
        output_note_commitment: impl Into<String>,
        amount_upper_bound_atomic_units: u128,
    ) -> Self {
        let quoted_fee_atomic_units = vault.fee_quote_atomic_units(amount_upper_bound_atomic_units);
        let expected_rebate_atomic_units =
            vault.rebate_quote_atomic_units(amount_upper_bound_atomic_units);
        let mut intent = Self {
            intent_id: String::new(),
            vault_id: vault.vault_id.clone(),
            side,
            status: SwapIntentStatus::Pending,
            input_note_commitment: input_note_commitment.into(),
            output_note_commitment: output_note_commitment.into(),
            trader_view_tag: deterministic_tag("TRADER-VIEW", &vault.vault_id),
            route_commitment: root_from_strings("ROUTE", &[vault.vault_id.as_str(), side.as_str()]),
            amount_commitment: root_from_strings(
                "AMOUNT",
                &[&amount_upper_bound_atomic_units.to_string()],
            ),
            amount_upper_bound_atomic_units,
            max_fee_atomic_units: quoted_fee_atomic_units.saturating_add(500),
            quoted_fee_atomic_units,
            expected_rebate_atomic_units,
            slippage_bps: 35,
            proof_fee_nullifier: deterministic_tag("PROOF-FEE-NULLIFIER", &vault.vault_id),
            fee_bucket_id: String::new(),
            quote_attestation_id: String::new(),
            privacy_set_size: vault.privacy_set_size,
            created_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT + 1,
            expires_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT
                    + PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
        };
        intent.intent_id = id_from_record("SWAP-INTENT-ID", &intent.public_record_without_id());
        intent
    }

    pub fn validate(&self, config: &Config, vault_ids: &BTreeSet<String>) -> Result<()> {
        required("intent_id", &self.intent_id)?;
        required("vault_id", &self.vault_id)?;
        require(
            vault_ids.contains(&self.vault_id),
            "swap intent references unknown vault",
        )?;
        required("input_note_commitment", &self.input_note_commitment)?;
        required("output_note_commitment", &self.output_note_commitment)?;
        required("trader_view_tag", &self.trader_view_tag)?;
        require_root("route_commitment", &self.route_commitment)?;
        require_root("amount_commitment", &self.amount_commitment)?;
        required("proof_fee_nullifier", &self.proof_fee_nullifier)?;
        require(
            self.amount_upper_bound_atomic_units > 0,
            "swap intent amount must be positive",
        )?;
        require(
            self.quoted_fee_atomic_units <= self.max_fee_atomic_units,
            "quoted proof fee exceeds user cap",
        )?;
        require_bps("swap slippage_bps", self.slippage_bps)?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "swap intent privacy set below runtime minimum",
        )?;
        require(
            self.expires_height > self.created_height,
            "swap intent expiry must be after creation",
        )?;
        Ok(())
    }

    pub fn attach_fee_bucket(&mut self, bucket_id: impl Into<String>) {
        self.fee_bucket_id = bucket_id.into();
    }

    pub fn attach_quote(&mut self, quote_attestation_id: impl Into<String>) {
        self.quote_attestation_id = quote_attestation_id.into();
        self.status = SwapIntentStatus::Quoted;
    }

    pub fn mark_batched(&mut self) {
        self.status = SwapIntentStatus::Batched;
    }

    pub fn mark_settled(&mut self) {
        self.status = SwapIntentStatus::Settled;
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "side": self.side,
            "status": self.status,
            "input_note_commitment": self.input_note_commitment,
            "output_note_commitment": self.output_note_commitment,
            "trader_view_tag": self.trader_view_tag,
            "route_commitment": self.route_commitment,
            "amount_commitment": self.amount_commitment,
            "amount_upper_bound_atomic_units": self.amount_upper_bound_atomic_units.to_string(),
            "max_fee_atomic_units": self.max_fee_atomic_units.to_string(),
            "quoted_fee_atomic_units": self.quoted_fee_atomic_units.to_string(),
            "expected_rebate_atomic_units": self.expected_rebate_atomic_units.to_string(),
            "slippage_bps": self.slippage_bps,
            "proof_fee_nullifier": self.proof_fee_nullifier,
            "fee_bucket_id": self.fee_bucket_id,
            "quote_attestation_id": self.quote_attestation_id,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["intent_id"] = json!(self.intent_id);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditBucket {
    pub bucket_id: String,
    pub owner_view_tag: String,
    pub vault_id: String,
    pub status: FeeBucketStatus,
    pub private_credit_commitment: String,
    pub reserved_credit_atomic_units: u128,
    pub consumed_credit_atomic_units: u128,
    pub rebate_credit_atomic_units: u128,
    pub settlement_note_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl FeeCreditBucket {
    pub fn new(
        vault_id: impl Into<String>,
        owner_view_tag: impl Into<String>,
        credit: u128,
    ) -> Self {
        let vault_id = vault_id.into();
        let owner_view_tag = owner_view_tag.into();
        let mut bucket = Self {
            bucket_id: String::new(),
            owner_view_tag,
            vault_id,
            status: FeeBucketStatus::Open,
            private_credit_commitment: root_from_strings("FEE-CREDIT", &[&credit.to_string()]),
            reserved_credit_atomic_units: credit,
            consumed_credit_atomic_units: 0,
            rebate_credit_atomic_units: 0,
            settlement_note_root: empty_root("FEE-SETTLEMENT-NOTES"),
            nullifier_root: empty_root("FEE-NULLIFIERS"),
            privacy_set_size:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_TARGET_PRIVACY_SET,
            created_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT + 1,
            updated_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT + 1,
        };
        bucket.bucket_id = id_from_record("FEE-BUCKET-ID", &bucket.public_record_without_id());
        bucket
    }

    pub fn consume(&mut self, amount: u128) -> Result<()> {
        require(self.status.can_reserve(), "fee bucket is not reservable")?;
        require(
            self.available_credit_atomic_units() >= amount,
            "fee bucket credit is insufficient",
        )?;
        self.consumed_credit_atomic_units =
            self.consumed_credit_atomic_units.saturating_add(amount);
        if self.available_credit_atomic_units() == 0 {
            self.status = FeeBucketStatus::Exhausted;
        } else {
            self.status = FeeBucketStatus::Consumed;
        }
        Ok(())
    }

    pub fn queue_rebate(&mut self, amount: u128) {
        self.rebate_credit_atomic_units = self.rebate_credit_atomic_units.saturating_add(amount);
        self.status = FeeBucketStatus::RebatePending;
    }

    pub fn available_credit_atomic_units(&self) -> u128 {
        self.reserved_credit_atomic_units
            .saturating_sub(self.consumed_credit_atomic_units)
    }

    pub fn validate(&self, config: &Config, vault_ids: &BTreeSet<String>) -> Result<()> {
        required("bucket_id", &self.bucket_id)?;
        required("owner_view_tag", &self.owner_view_tag)?;
        required("vault_id", &self.vault_id)?;
        require(
            vault_ids.contains(&self.vault_id),
            "fee bucket references unknown vault",
        )?;
        require_root("private_credit_commitment", &self.private_credit_commitment)?;
        require_root("settlement_note_root", &self.settlement_note_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require(
            self.consumed_credit_atomic_units <= self.reserved_credit_atomic_units,
            "fee bucket consumed credit exceeds reserve",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "fee bucket privacy set below runtime minimum",
        )?;
        Ok(())
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "owner_view_tag": self.owner_view_tag,
            "vault_id": self.vault_id,
            "status": self.status,
            "private_credit_commitment": self.private_credit_commitment,
            "reserved_credit_atomic_units": self.reserved_credit_atomic_units.to_string(),
            "consumed_credit_atomic_units": self.consumed_credit_atomic_units.to_string(),
            "rebate_credit_atomic_units": self.rebate_credit_atomic_units.to_string(),
            "settlement_note_root": self.settlement_note_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["bucket_id"] = json!(self.bucket_id);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqQuoteAttestation {
    pub attestation_id: String,
    pub quote_id: String,
    pub vault_id: String,
    pub intent_id: String,
    pub attestor_key_id: String,
    pub verdict: PqQuoteVerdict,
    pub quote_price_commitment: String,
    pub fee_schedule_root: String,
    pub reserve_state_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub quote_fee_atomic_units: u128,
    pub valid_from_height: u64,
    pub expires_height: u64,
}

impl PqQuoteAttestation {
    pub fn new(vault: &ConfidentialProofFeeVault, intent: &SwapIntent) -> Self {
        let mut attestation = Self {
            attestation_id: String::new(),
            quote_id: deterministic_tag("QUOTE", &intent.intent_id),
            vault_id: vault.vault_id.clone(),
            intent_id: intent.intent_id.clone(),
            attestor_key_id: deterministic_tag("PQ-ATTESTOR", &vault.vault_id),
            verdict: PqQuoteVerdict::Accept,
            quote_price_commitment: root_from_strings(
                "QUOTE-PRICE",
                &[&vault.vault_id, &intent.amount_upper_bound_atomic_units.to_string()],
            ),
            fee_schedule_root: root_from_strings(
                "FEE-SCHEDULE",
                &[&vault.max_swap_fee_bps.to_string(), &vault.target_rebate_bps.to_string()],
            ),
            reserve_state_root: vault.reserve_commitment_root.clone(),
            signature_root: root_from_strings("PQ-SIGNATURE", &[&intent.intent_id]),
            transcript_root: root_from_strings("PQ-QUOTE-TRANSCRIPT", &[&intent.intent_id]),
            pq_security_bits: vault.pq_security_bits,
            quote_fee_atomic_units: intent.quoted_fee_atomic_units,
            valid_from_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT + 2,
            expires_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT
                    + PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
        };
        attestation.attestation_id = id_from_record(
            "PQ-QUOTE-ATTESTATION-ID",
            &attestation.public_record_without_id(),
        );
        attestation
    }

    pub fn validate(
        &self,
        config: &Config,
        vault_ids: &BTreeSet<String>,
        intent_ids: &BTreeSet<String>,
    ) -> Result<()> {
        required("attestation_id", &self.attestation_id)?;
        required("quote_id", &self.quote_id)?;
        required("vault_id", &self.vault_id)?;
        required("intent_id", &self.intent_id)?;
        require(
            vault_ids.contains(&self.vault_id),
            "quote attestation references unknown vault",
        )?;
        require(
            intent_ids.contains(&self.intent_id),
            "quote attestation references unknown intent",
        )?;
        required("attestor_key_id", &self.attestor_key_id)?;
        require_root("quote_price_commitment", &self.quote_price_commitment)?;
        require_root("fee_schedule_root", &self.fee_schedule_root)?;
        require_root("reserve_state_root", &self.reserve_state_root)?;
        require_root("signature_root", &self.signature_root)?;
        require_root("transcript_root", &self.transcript_root)?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "quote attestation PQ security below runtime minimum",
        )?;
        require(
            self.expires_height > self.valid_from_height,
            "quote attestation expiry must be after valid_from",
        )?;
        Ok(())
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "vault_id": self.vault_id,
            "intent_id": self.intent_id,
            "attestor_key_id": self.attestor_key_id,
            "verdict": self.verdict,
            "quote_price_commitment": self.quote_price_commitment,
            "fee_schedule_root": self.fee_schedule_root,
            "reserve_state_root": self.reserve_state_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "quote_fee_atomic_units": self.quote_fee_atomic_units.to_string(),
            "valid_from_height": self.valid_from_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["attestation_id"] = json!(self.attestation_id);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityGuardrail {
    pub guardrail_id: String,
    pub vault_id: String,
    pub label: String,
    pub severity: GuardrailSeverity,
    pub min_reserve_ratio_bps: u64,
    pub max_trade_share_bps: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub pause_on_pq_degradation: bool,
    pub observed_reserve_ratio_bps: u64,
    pub observed_trade_share_bps: u64,
    pub observed_fee_bps: u64,
    pub observed_privacy_set_size: u64,
    pub evaluated_height: u64,
}

impl LiquidityGuardrail {
    pub fn new(vault: &ConfidentialProofFeeVault, label: impl Into<String>) -> Self {
        let mut guardrail = Self {
            guardrail_id: String::new(),
            vault_id: vault.vault_id.clone(),
            label: label.into(),
            severity: GuardrailSeverity::Low,
            min_reserve_ratio_bps: 7_000,
            max_trade_share_bps: 1_250,
            max_fee_bps: vault.max_swap_fee_bps,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            pause_on_pq_degradation: true,
            observed_reserve_ratio_bps: 9_250,
            observed_trade_share_bps: 320,
            observed_fee_bps: vault.max_swap_fee_bps,
            observed_privacy_set_size: vault.privacy_set_size,
            evaluated_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT + 2,
        };
        guardrail.guardrail_id =
            id_from_record("GUARDRAIL-ID", &guardrail.public_record_without_id());
        guardrail
    }

    pub fn evaluate(&mut self) -> GuardrailSeverity {
        self.severity = if self.observed_fee_bps > self.max_fee_bps
            || self.observed_trade_share_bps > self.max_trade_share_bps
        {
            GuardrailSeverity::High
        } else if self.observed_reserve_ratio_bps < self.min_reserve_ratio_bps {
            GuardrailSeverity::Medium
        } else if self.observed_privacy_set_size < self.min_privacy_set_size {
            GuardrailSeverity::Low
        } else {
            GuardrailSeverity::Info
        };
        self.severity
    }

    pub fn validate(&self, vault_ids: &BTreeSet<String>) -> Result<()> {
        required("guardrail_id", &self.guardrail_id)?;
        required("vault_id", &self.vault_id)?;
        require(
            vault_ids.contains(&self.vault_id),
            "liquidity guardrail references unknown vault",
        )?;
        required("label", &self.label)?;
        require_bps("min_reserve_ratio_bps", self.min_reserve_ratio_bps)?;
        require_bps("max_trade_share_bps", self.max_trade_share_bps)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require_bps(
            "observed_reserve_ratio_bps",
            self.observed_reserve_ratio_bps,
        )?;
        require_bps("observed_trade_share_bps", self.observed_trade_share_bps)?;
        require_bps("observed_fee_bps", self.observed_fee_bps)?;
        require(
            !self.severity.blocks_flow() || self.pause_on_pq_degradation,
            "blocking guardrail must be configured to pause degraded flow",
        )?;
        Ok(())
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "label": self.label,
            "severity": self.severity,
            "min_reserve_ratio_bps": self.min_reserve_ratio_bps,
            "max_trade_share_bps": self.max_trade_share_bps,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pause_on_pq_degradation": self.pause_on_pq_degradation,
            "observed_reserve_ratio_bps": self.observed_reserve_ratio_bps,
            "observed_trade_share_bps": self.observed_trade_share_bps,
            "observed_fee_bps": self.observed_fee_bps,
            "observed_privacy_set_size": self.observed_privacy_set_size,
            "evaluated_height": self.evaluated_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["guardrail_id"] = json!(self.guardrail_id);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingBatch {
    pub batch_id: String,
    pub status: ClearingBatchStatus,
    pub coordinator_id: String,
    pub vault_ids: Vec<String>,
    pub intent_ids: Vec<String>,
    pub fee_bucket_ids: Vec<String>,
    pub quote_attestation_ids: Vec<String>,
    pub input_note_root: String,
    pub output_note_root: String,
    pub private_fee_settlement_root: String,
    pub rebate_root: String,
    pub nullifier_root: String,
    pub total_notional_atomic_units: u128,
    pub total_fee_atomic_units: u128,
    pub total_rebate_atomic_units: u128,
    pub low_fee_savings_atomic_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub proposed_height: u64,
    pub cleared_height: u64,
}

impl ClearingBatch {
    pub fn new(
        coordinator_id: impl Into<String>,
        intents: &[SwapIntent],
        quotes: &[PqQuoteAttestation],
        buckets: &[FeeCreditBucket],
    ) -> Self {
        let intent_ids: Vec<String> = intents
            .iter()
            .map(|intent| intent.intent_id.clone())
            .collect();
        let vault_ids: Vec<String> = intents
            .iter()
            .map(|intent| intent.vault_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let fee_bucket_ids: Vec<String> = buckets
            .iter()
            .map(|bucket| bucket.bucket_id.clone())
            .collect();
        let quote_attestation_ids: Vec<String> = quotes
            .iter()
            .map(|quote| quote.attestation_id.clone())
            .collect();
        let total_notional_atomic_units = intents
            .iter()
            .map(|intent| intent.amount_upper_bound_atomic_units)
            .sum();
        let total_fee_atomic_units = intents
            .iter()
            .map(|intent| intent.quoted_fee_atomic_units)
            .sum();
        let total_rebate_atomic_units = intents
            .iter()
            .map(|intent| intent.expected_rebate_atomic_units)
            .sum();
        let mut batch = Self {
            batch_id: String::new(),
            status: ClearingBatchStatus::PqAttested,
            coordinator_id: coordinator_id.into(),
            vault_ids,
            intent_ids,
            fee_bucket_ids,
            quote_attestation_ids,
            input_note_root: public_record_root(
                "BATCH-INPUT-NOTES",
                &intents
                    .iter()
                    .map(|intent| json!(intent.input_note_commitment))
                    .collect::<Vec<_>>(),
            ),
            output_note_root: public_record_root(
                "BATCH-OUTPUT-NOTES",
                &intents
                    .iter()
                    .map(|intent| json!(intent.output_note_commitment))
                    .collect::<Vec<_>>(),
            ),
            private_fee_settlement_root: public_record_root(
                "BATCH-PRIVATE-FEES",
                &buckets
                    .iter()
                    .map(FeeCreditBucket::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: empty_root("BATCH-REBATES"),
            nullifier_root: public_record_root(
                "BATCH-NULLIFIERS",
                &intents
                    .iter()
                    .map(|intent| json!(intent.proof_fee_nullifier))
                    .collect::<Vec<_>>(),
            ),
            total_notional_atomic_units,
            total_fee_atomic_units,
            total_rebate_atomic_units,
            low_fee_savings_atomic_units: total_fee_atomic_units / 3,
            privacy_set_size:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_TARGET_PRIVACY_SET,
            pq_security_bits:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            proposed_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT + 3,
            cleared_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT + 4,
        };
        batch.batch_id = id_from_record("CLEARING-BATCH-ID", &batch.public_record_without_id());
        batch
    }

    pub fn validate(
        &self,
        config: &Config,
        vault_ids: &BTreeSet<String>,
        intent_ids: &BTreeSet<String>,
        bucket_ids: &BTreeSet<String>,
        quote_ids: &BTreeSet<String>,
    ) -> Result<()> {
        required("batch_id", &self.batch_id)?;
        required("coordinator_id", &self.coordinator_id)?;
        require(
            !self.intent_ids.is_empty(),
            "clearing batch must contain intents",
        )?;
        require(
            self.intent_ids.len() <= config.max_swap_intents,
            "clearing batch exceeds swap intent capacity",
        )?;
        for vault_id in &self.vault_ids {
            require(
                vault_ids.contains(vault_id),
                "clearing batch references unknown vault",
            )?;
        }
        for intent_id in &self.intent_ids {
            require(
                intent_ids.contains(intent_id),
                "clearing batch references unknown intent",
            )?;
        }
        for bucket_id in &self.fee_bucket_ids {
            require(
                bucket_ids.contains(bucket_id),
                "clearing batch references unknown fee bucket",
            )?;
        }
        for quote_id in &self.quote_attestation_ids {
            require(
                quote_ids.contains(quote_id),
                "clearing batch references unknown quote",
            )?;
        }
        require_root("input_note_root", &self.input_note_root)?;
        require_root("output_note_root", &self.output_note_root)?;
        require_root(
            "private_fee_settlement_root",
            &self.private_fee_settlement_root,
        )?;
        require_root("rebate_root", &self.rebate_root)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require(
            self.total_fee_atomic_units <= self.total_notional_atomic_units,
            "clearing batch fee exceeds notional",
        )?;
        require(
            self.total_rebate_atomic_units <= self.total_fee_atomic_units,
            "clearing batch rebate exceeds fee",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "clearing batch privacy set below runtime minimum",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "clearing batch PQ security below runtime minimum",
        )?;
        require(
            self.cleared_height >= self.proposed_height,
            "clearing height must not precede proposal",
        )?;
        Ok(())
    }

    pub fn mark_cleared(&mut self) {
        self.status = ClearingBatchStatus::Cleared;
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "status": self.status,
            "coordinator_id": self.coordinator_id,
            "vault_ids": self.vault_ids,
            "intent_ids": self.intent_ids,
            "fee_bucket_ids": self.fee_bucket_ids,
            "quote_attestation_ids": self.quote_attestation_ids,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "private_fee_settlement_root": self.private_fee_settlement_root,
            "rebate_root": self.rebate_root,
            "nullifier_root": self.nullifier_root,
            "total_notional_atomic_units": self.total_notional_atomic_units.to_string(),
            "total_fee_atomic_units": self.total_fee_atomic_units.to_string(),
            "total_rebate_atomic_units": self.total_rebate_atomic_units.to_string(),
            "low_fee_savings_atomic_units": self.low_fee_savings_atomic_units.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "proposed_height": self.proposed_height,
            "cleared_height": self.cleared_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["batch_id"] = json!(self.batch_id);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateSettlement {
    pub rebate_id: String,
    pub batch_id: String,
    pub fee_bucket_id: String,
    pub owner_view_tag: String,
    pub status: RebateStatus,
    pub rebate_note_commitment: String,
    pub encrypted_rebate_payload_root: String,
    pub rebate_atomic_units: u128,
    pub privacy_set_size: u64,
    pub settled_height: u64,
}

impl RebateSettlement {
    pub fn new(batch: &ClearingBatch, bucket: &FeeCreditBucket, amount: u128) -> Self {
        let mut rebate = Self {
            rebate_id: String::new(),
            batch_id: batch.batch_id.clone(),
            fee_bucket_id: bucket.bucket_id.clone(),
            owner_view_tag: bucket.owner_view_tag.clone(),
            status: RebateStatus::SettledPrivately,
            rebate_note_commitment: root_from_strings(
                "REBATE-NOTE",
                &[&batch.batch_id, &bucket.bucket_id, &amount.to_string()],
            ),
            encrypted_rebate_payload_root: root_from_strings(
                "REBATE-PAYLOAD",
                &[&bucket.owner_view_tag, &amount.to_string()],
            ),
            rebate_atomic_units: amount,
            privacy_set_size: batch.privacy_set_size,
            settled_height: batch.cleared_height + 1,
        };
        rebate.rebate_id = id_from_record("REBATE-ID", &rebate.public_record_without_id());
        rebate
    }

    pub fn validate(
        &self,
        config: &Config,
        batch_ids: &BTreeSet<String>,
        bucket_ids: &BTreeSet<String>,
    ) -> Result<()> {
        required("rebate_id", &self.rebate_id)?;
        required("batch_id", &self.batch_id)?;
        require(
            batch_ids.contains(&self.batch_id),
            "rebate references unknown batch",
        )?;
        required("fee_bucket_id", &self.fee_bucket_id)?;
        require(
            bucket_ids.contains(&self.fee_bucket_id),
            "rebate references unknown fee bucket",
        )?;
        required("owner_view_tag", &self.owner_view_tag)?;
        require_root("rebate_note_commitment", &self.rebate_note_commitment)?;
        require_root(
            "encrypted_rebate_payload_root",
            &self.encrypted_rebate_payload_root,
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "rebate privacy set below runtime minimum",
        )?;
        Ok(())
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "fee_bucket_id": self.fee_bucket_id,
            "owner_view_tag": self.owner_view_tag,
            "status": self.status,
            "rebate_note_commitment": self.rebate_note_commitment,
            "encrypted_rebate_payload_root": self.encrypted_rebate_payload_root,
            "rebate_atomic_units": self.rebate_atomic_units.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "settled_height": self.settled_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["rebate_id"] = json!(self.rebate_id);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub kind: ReceiptKind,
    pub subject_id: String,
    pub batch_id: String,
    pub vault_id: String,
    pub private_fee_settlement_root: String,
    pub public_audit_hint: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub emitted_height: u64,
}

impl SettlementReceipt {
    pub fn new(
        kind: ReceiptKind,
        subject_id: impl Into<String>,
        batch_id: impl Into<String>,
        vault_id: impl Into<String>,
        private_fee_settlement_root: impl Into<String>,
        state_root_before: impl Into<String>,
        state_root_after: impl Into<String>,
    ) -> Self {
        let subject_id = subject_id.into();
        let mut receipt = Self {
            receipt_id: String::new(),
            kind,
            subject_id: subject_id.clone(),
            batch_id: batch_id.into(),
            vault_id: vault_id.into(),
            private_fee_settlement_root: private_fee_settlement_root.into(),
            public_audit_hint: deterministic_tag(kind.as_str(), &subject_id),
            state_root_before: state_root_before.into(),
            state_root_after: state_root_after.into(),
            emitted_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT + 5,
        };
        receipt.receipt_id = id_from_record("RECEIPT-ID", &receipt.public_record_without_id());
        receipt
    }

    pub fn validate(&self) -> Result<()> {
        required("receipt_id", &self.receipt_id)?;
        required("subject_id", &self.subject_id)?;
        required("batch_id", &self.batch_id)?;
        required("vault_id", &self.vault_id)?;
        require_root(
            "private_fee_settlement_root",
            &self.private_fee_settlement_root,
        )?;
        required("public_audit_hint", &self.public_audit_hint)?;
        require_root("state_root_before", &self.state_root_before)?;
        require_root("state_root_after", &self.state_root_after)?;
        Ok(())
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "kind": self.kind,
            "subject_id": self.subject_id,
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "private_fee_settlement_root": self.private_fee_settlement_root,
            "public_audit_hint": self.public_audit_hint,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "emitted_height": self.emitted_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["receipt_id"] = json!(self.receipt_id);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub batch_ids: Vec<String>,
    pub vault_ids: Vec<String>,
    pub private_fee_settlement_root: String,
    pub clearing_root: String,
    pub rebate_root: String,
    pub total_batches: u64,
    pub total_swaps: u64,
    pub total_fees_atomic_units: u128,
    pub total_rebates_atomic_units: u128,
    pub low_fee_savings_atomic_units: u128,
    pub pq_security_floor_bits: u16,
    pub published_height: u64,
}

impl OperatorSummary {
    pub fn new(operator_id: impl Into<String>, batches: &[ClearingBatch]) -> Self {
        let operator_id = operator_id.into();
        let batch_ids: Vec<String> = batches.iter().map(|batch| batch.batch_id.clone()).collect();
        let vault_ids: Vec<String> = batches
            .iter()
            .flat_map(|batch| batch.vault_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let total_swaps = batches
            .iter()
            .map(|batch| batch.intent_ids.len() as u64)
            .sum();
        let total_fees_atomic_units = batches
            .iter()
            .map(|batch| batch.total_fee_atomic_units)
            .sum();
        let total_rebates_atomic_units = batches
            .iter()
            .map(|batch| batch.total_rebate_atomic_units)
            .sum();
        let low_fee_savings_atomic_units = batches
            .iter()
            .map(|batch| batch.low_fee_savings_atomic_units)
            .sum();
        let mut summary = Self {
            summary_id: String::new(),
            operator_id,
            batch_ids,
            vault_ids,
            private_fee_settlement_root: public_record_root(
                "SUMMARY-PRIVATE-FEES",
                &batches
                    .iter()
                    .map(|batch| json!(batch.private_fee_settlement_root))
                    .collect::<Vec<_>>(),
            ),
            clearing_root: public_record_root(
                "SUMMARY-CLEARING",
                &batches
                    .iter()
                    .map(ClearingBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: public_record_root(
                "SUMMARY-REBATES",
                &batches
                    .iter()
                    .map(|batch| json!(batch.rebate_root))
                    .collect::<Vec<_>>(),
            ),
            total_batches: batches.len() as u64,
            total_swaps,
            total_fees_atomic_units,
            total_rebates_atomic_units,
            low_fee_savings_atomic_units,
            pq_security_floor_bits: batches
                .iter()
                .map(|batch| batch.pq_security_bits)
                .min()
                .unwrap_or(
                    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
                ),
            published_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_DEVNET_HEIGHT + 6,
        };
        summary.summary_id =
            id_from_record("OPERATOR-SUMMARY-ID", &summary.public_record_without_id());
        summary
    }

    pub fn validate(
        &self,
        batch_ids: &BTreeSet<String>,
        vault_ids: &BTreeSet<String>,
    ) -> Result<()> {
        required("summary_id", &self.summary_id)?;
        required("operator_id", &self.operator_id)?;
        for batch_id in &self.batch_ids {
            require(
                batch_ids.contains(batch_id),
                "operator summary references unknown batch",
            )?;
        }
        for vault_id in &self.vault_ids {
            require(
                vault_ids.contains(vault_id),
                "operator summary references unknown vault",
            )?;
        }
        require_root(
            "private_fee_settlement_root",
            &self.private_fee_settlement_root,
        )?;
        require_root("clearing_root", &self.clearing_root)?;
        require_root("rebate_root", &self.rebate_root)?;
        require(
            self.total_rebates_atomic_units <= self.total_fees_atomic_units,
            "operator summary rebates exceed fees",
        )?;
        Ok(())
    }

    fn public_record_without_id(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "batch_ids": self.batch_ids,
            "vault_ids": self.vault_ids,
            "private_fee_settlement_root": self.private_fee_settlement_root,
            "clearing_root": self.clearing_root,
            "rebate_root": self.rebate_root,
            "total_batches": self.total_batches,
            "total_swaps": self.total_swaps,
            "total_fees_atomic_units": self.total_fees_atomic_units.to_string(),
            "total_rebates_atomic_units": self.total_rebates_atomic_units.to_string(),
            "low_fee_savings_atomic_units": self.low_fee_savings_atomic_units.to_string(),
            "pq_security_floor_bits": self.pq_security_floor_bits,
            "published_height": self.published_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_id();
        record["summary_id"] = json!(self.summary_id);
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub vaults: Vec<ConfidentialProofFeeVault>,
    pub swap_intents: Vec<SwapIntent>,
    pub fee_buckets: Vec<FeeCreditBucket>,
    pub quote_attestations: Vec<PqQuoteAttestation>,
    pub liquidity_guardrails: Vec<LiquidityGuardrail>,
    pub clearing_batches: Vec<ClearingBatch>,
    pub settlement_receipts: Vec<SettlementReceipt>,
    pub rebate_settlements: Vec<RebateSettlement>,
    pub operator_summaries: Vec<OperatorSummary>,
    pub consumed_nullifiers: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            vaults: Vec::new(),
            swap_intents: Vec::new(),
            fee_buckets: Vec::new(),
            quote_attestations: Vec::new(),
            liquidity_guardrails: Vec::new(),
            clearing_batches: Vec::new(),
            settlement_receipts: Vec::new(),
            rebate_settlements: Vec::new(),
            operator_summaries: Vec::new(),
            consumed_nullifiers: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        demo()
    }

    pub fn push_vault(&mut self, vault: ConfidentialProofFeeVault) -> Result<String> {
        require(
            self.vaults.len() < self.config.max_vaults,
            "runtime vault capacity exceeded",
        )?;
        vault.validate(&self.config)?;
        let vault_id = vault.vault_id.clone();
        self.vaults.push(vault);
        self.refresh_roots();
        Ok(vault_id)
    }

    pub fn open_fee_bucket(&mut self, bucket: FeeCreditBucket) -> Result<String> {
        require(
            self.fee_buckets.len() < self.config.max_fee_buckets,
            "runtime fee bucket capacity exceeded",
        )?;
        let vault_ids = self.vault_id_set();
        bucket.validate(&self.config, &vault_ids)?;
        let bucket_id = bucket.bucket_id.clone();
        self.fee_buckets.push(bucket);
        self.refresh_roots();
        Ok(bucket_id)
    }

    pub fn accept_swap_intent(&mut self, intent: SwapIntent) -> Result<String> {
        require(
            self.swap_intents.len() < self.config.max_swap_intents,
            "runtime swap intent capacity exceeded",
        )?;
        let vault_ids = self.vault_id_set();
        intent.validate(&self.config, &vault_ids)?;
        require(
            !self
                .consumed_nullifiers
                .contains(&intent.proof_fee_nullifier),
            "proof-fee nullifier already consumed",
        )?;
        let intent_id = intent.intent_id.clone();
        self.swap_intents.push(intent);
        self.refresh_roots();
        Ok(intent_id)
    }

    pub fn attest_quote(&mut self, attestation: PqQuoteAttestation) -> Result<String> {
        require(
            self.quote_attestations.len() < self.config.max_quote_attestations,
            "runtime quote attestation capacity exceeded",
        )?;
        let vault_ids = self.vault_id_set();
        let intent_ids = self.intent_id_set();
        attestation.validate(&self.config, &vault_ids, &intent_ids)?;
        let attestation_id = attestation.attestation_id.clone();
        if let Some(intent) = self
            .swap_intents
            .iter_mut()
            .find(|intent| intent.intent_id == attestation.intent_id)
        {
            intent.attach_quote(attestation_id.clone());
        }
        self.quote_attestations.push(attestation);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn add_guardrail(&mut self, mut guardrail: LiquidityGuardrail) -> Result<String> {
        let vault_ids = self.vault_id_set();
        guardrail.evaluate();
        guardrail.validate(&vault_ids)?;
        let guardrail_id = guardrail.guardrail_id.clone();
        self.liquidity_guardrails.push(guardrail);
        self.refresh_roots();
        Ok(guardrail_id)
    }

    pub fn clear_batch(&mut self, mut batch: ClearingBatch) -> Result<String> {
        require(
            self.clearing_batches.len() < self.config.max_clearing_batches,
            "runtime clearing batch capacity exceeded",
        )?;
        let vault_ids = self.vault_id_set();
        let intent_ids = self.intent_id_set();
        let bucket_ids = self.bucket_id_set();
        let quote_ids = self.quote_id_set();
        batch.validate(
            &self.config,
            &vault_ids,
            &intent_ids,
            &bucket_ids,
            &quote_ids,
        )?;
        batch.mark_cleared();
        let batch_id = batch.batch_id.clone();
        for intent in &mut self.swap_intents {
            if batch.intent_ids.contains(&intent.intent_id) {
                intent.mark_settled();
                self.consumed_nullifiers
                    .push(intent.proof_fee_nullifier.clone());
            }
        }
        for bucket in &mut self.fee_buckets {
            if batch.fee_bucket_ids.contains(&bucket.bucket_id) {
                bucket
                    .consume(batch.total_fee_atomic_units / batch.fee_bucket_ids.len() as u128)?;
                bucket.queue_rebate(
                    batch.total_rebate_atomic_units / batch.fee_bucket_ids.len() as u128,
                );
            }
        }
        self.clearing_batches.push(batch);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn settle_rebate(&mut self, rebate: RebateSettlement) -> Result<String> {
        require(
            self.rebate_settlements.len() < self.config.max_rebate_settlements,
            "runtime rebate settlement capacity exceeded",
        )?;
        let batch_ids = self.batch_id_set();
        let bucket_ids = self.bucket_id_set();
        rebate.validate(&self.config, &batch_ids, &bucket_ids)?;
        let rebate_id = rebate.rebate_id.clone();
        self.rebate_settlements.push(rebate);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn publish_receipt(&mut self, receipt: SettlementReceipt) -> Result<String> {
        require(
            self.settlement_receipts.len() < self.config.max_settlement_receipts,
            "runtime settlement receipt capacity exceeded",
        )?;
        receipt.validate()?;
        let receipt_id = receipt.receipt_id.clone();
        self.settlement_receipts.push(receipt);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn publish_operator_summary(&mut self, summary: OperatorSummary) -> Result<String> {
        let batch_ids = self.batch_id_set();
        let vault_ids = self.vault_id_set();
        summary.validate(&batch_ids, &vault_ids)?;
        let summary_id = summary.summary_id.clone();
        self.operator_summaries.push(summary);
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(
            self.vaults.len() <= self.config.max_vaults,
            "runtime has too many vaults",
        )?;
        require(
            self.swap_intents.len() <= self.config.max_swap_intents,
            "runtime has too many swap intents",
        )?;
        require(
            self.fee_buckets.len() <= self.config.max_fee_buckets,
            "runtime has too many fee buckets",
        )?;
        require(
            self.quote_attestations.len() <= self.config.max_quote_attestations,
            "runtime has too many quote attestations",
        )?;
        require(
            self.clearing_batches.len() <= self.config.max_clearing_batches,
            "runtime has too many clearing batches",
        )?;
        require(
            self.settlement_receipts.len() <= self.config.max_settlement_receipts,
            "runtime has too many settlement receipts",
        )?;
        require(
            self.rebate_settlements.len() <= self.config.max_rebate_settlements,
            "runtime has too many rebate settlements",
        )?;
        let vault_ids = self.vault_id_set();
        let intent_ids = self.intent_id_set();
        let bucket_ids = self.bucket_id_set();
        let quote_ids = self.quote_id_set();
        let batch_ids = self.batch_id_set();
        require(
            vault_ids.len() == self.vaults.len(),
            "runtime has duplicate vault ids",
        )?;
        require(
            intent_ids.len() == self.swap_intents.len(),
            "runtime has duplicate intent ids",
        )?;
        require(
            bucket_ids.len() == self.fee_buckets.len(),
            "runtime has duplicate fee bucket ids",
        )?;
        require(
            quote_ids.len() == self.quote_attestations.len(),
            "runtime has duplicate quote attestation ids",
        )?;
        require(
            batch_ids.len() == self.clearing_batches.len(),
            "runtime has duplicate clearing batch ids",
        )?;
        for vault in &self.vaults {
            vault.validate(&self.config)?;
        }
        for intent in &self.swap_intents {
            intent.validate(&self.config, &vault_ids)?;
        }
        for bucket in &self.fee_buckets {
            bucket.validate(&self.config, &vault_ids)?;
        }
        for quote in &self.quote_attestations {
            quote.validate(&self.config, &vault_ids, &intent_ids)?;
        }
        for guardrail in &self.liquidity_guardrails {
            guardrail.validate(&vault_ids)?;
        }
        for batch in &self.clearing_batches {
            batch.validate(
                &self.config,
                &vault_ids,
                &intent_ids,
                &bucket_ids,
                &quote_ids,
            )?;
        }
        for receipt in &self.settlement_receipts {
            receipt.validate()?;
        }
        for rebate in &self.rebate_settlements {
            rebate.validate(&self.config, &batch_ids, &bucket_ids)?;
        }
        for summary in &self.operator_summaries {
            summary.validate(&batch_ids, &vault_ids)?;
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.state_root(),
            vault_root: public_record_root(
                "VAULTS",
                &self
                    .vaults
                    .iter()
                    .map(ConfidentialProofFeeVault::public_record)
                    .collect::<Vec<_>>(),
            ),
            swap_intent_root: public_record_root(
                "SWAP-INTENTS",
                &self
                    .swap_intents
                    .iter()
                    .map(SwapIntent::public_record)
                    .collect::<Vec<_>>(),
            ),
            fee_bucket_root: public_record_root(
                "FEE-BUCKETS",
                &self
                    .fee_buckets
                    .iter()
                    .map(FeeCreditBucket::public_record)
                    .collect::<Vec<_>>(),
            ),
            quote_attestation_root: public_record_root(
                "PQ-QUOTE-ATTESTATIONS",
                &self
                    .quote_attestations
                    .iter()
                    .map(PqQuoteAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            guardrail_root: public_record_root(
                "LIQUIDITY-GUARDRAILS",
                &self
                    .liquidity_guardrails
                    .iter()
                    .map(LiquidityGuardrail::public_record)
                    .collect::<Vec<_>>(),
            ),
            clearing_batch_root: public_record_root(
                "CLEARING-BATCHES",
                &self
                    .clearing_batches
                    .iter()
                    .map(ClearingBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_receipt_root: public_record_root(
                "SETTLEMENT-RECEIPTS",
                &self
                    .settlement_receipts
                    .iter()
                    .map(SettlementReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_settlement_root: public_record_root(
                "REBATE-SETTLEMENTS",
                &self
                    .rebate_settlements
                    .iter()
                    .map(RebateSettlement::public_record)
                    .collect::<Vec<_>>(),
            ),
            operator_summary_root: public_record_root(
                "OPERATOR-SUMMARIES",
                &self
                    .operator_summaries
                    .iter()
                    .map(OperatorSummary::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_root: public_record_root(
                "CONSUMED-NULLIFIERS",
                &self
                    .consumed_nullifiers
                    .iter()
                    .map(|nullifier| json!(nullifier))
                    .collect::<Vec<_>>(),
            ),
            counters_root: root_from_record("COUNTERS", &self.counters().public_record()),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&self.public_record_without_roots_state(&roots));
        roots
    }

    pub fn counters(&self) -> Counters {
        Counters {
            vaults: self.vaults.len() as u64,
            swap_intents: self.swap_intents.len() as u64,
            fee_buckets: self.fee_buckets.len() as u64,
            quote_attestations: self.quote_attestations.len() as u64,
            guardrails: self.liquidity_guardrails.len() as u64,
            clearing_batches: self.clearing_batches.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            rebate_settlements: self.rebate_settlements.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            private_fee_settlements: self
                .clearing_batches
                .iter()
                .filter(|batch| !batch.private_fee_settlement_root.is_empty())
                .count() as u64,
            low_fee_savings_atomic_units: self
                .clearing_batches
                .iter()
                .map(|batch| batch.low_fee_savings_atomic_units)
                .sum(),
        }
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.counters();
        self.roots = self.roots();
    }

    pub fn public_record_without_state_root(&self) -> Value {
        self.public_record_without_roots_state(&self.roots())
    }

    fn public_record_without_roots_state(&self, roots: &Roots) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "roots": roots.public_record_without_state_root(),
            "counters": self.counters().public_record(),
            "vaults": sorted_records(self.vaults.iter().map(ConfidentialProofFeeVault::public_record).collect()),
            "swap_intents": sorted_records(self.swap_intents.iter().map(SwapIntent::public_record).collect()),
            "fee_buckets": sorted_records(self.fee_buckets.iter().map(FeeCreditBucket::public_record).collect()),
            "quote_attestations": sorted_records(self.quote_attestations.iter().map(PqQuoteAttestation::public_record).collect()),
            "liquidity_guardrails": sorted_records(self.liquidity_guardrails.iter().map(LiquidityGuardrail::public_record).collect()),
            "clearing_batches": sorted_records(self.clearing_batches.iter().map(ClearingBatch::public_record).collect()),
            "settlement_receipts": sorted_records(self.settlement_receipts.iter().map(SettlementReceipt::public_record).collect()),
            "rebate_settlements": sorted_records(self.rebate_settlements.iter().map(RebateSettlement::public_record).collect()),
            "operator_summaries": sorted_records(self.operator_summaries.iter().map(OperatorSummary::public_record).collect()),
            "consumed_nullifiers": self.consumed_nullifiers,
            "metadata": self.metadata,
        })
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_roots_state(&roots);
        record["state_root"] = json!(roots.state_root);
        record["roots"] = roots.public_record();
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn vault_id_set(&self) -> BTreeSet<String> {
        self.vaults
            .iter()
            .map(|vault| vault.vault_id.clone())
            .collect()
    }

    fn intent_id_set(&self) -> BTreeSet<String> {
        self.swap_intents
            .iter()
            .map(|intent| intent.intent_id.clone())
            .collect()
    }

    fn bucket_id_set(&self) -> BTreeSet<String> {
        self.fee_buckets
            .iter()
            .map(|bucket| bucket.bucket_id.clone())
            .collect()
    }

    fn quote_id_set(&self) -> BTreeSet<String> {
        self.quote_attestations
            .iter()
            .map(|quote| quote.attestation_id.clone())
            .collect()
    }

    fn batch_id_set(&self) -> BTreeSet<String> {
        self.clearing_batches
            .iter()
            .map(|batch| batch.batch_id.clone())
            .collect()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::new(Config::devnet());
    state.metadata.insert(
        "runtime_family".to_string(),
        "private_l2_low_fee_pq_confidential_proof_fee_swap_vault".to_string(),
    );
    state.metadata.insert(
        "priority".to_string(),
        "low_fees_defi_swaps_vaults_pq_attestations_private_fee_settlement".to_string(),
    );

    let mut xmr_usdc = ConfidentialProofFeeVault::new(
        "devnet-xmr-usdc-low-fee-proof-vault",
        VaultKind::StableSwap,
        deterministic_tag("ASSET", "xmr"),
        deterministic_tag("ASSET", "usdc"),
        12,
    );
    xmr_usdc.available_liquidity_atomic_units = 12_500_000_000_000;
    xmr_usdc.low_fee_priority = 10;

    let mut xmr_dnr = ConfidentialProofFeeVault::new(
        "devnet-xmr-dnr-routing-vault",
        VaultKind::ConstantProduct,
        deterministic_tag("ASSET", "xmr"),
        deterministic_tag("ASSET", "dnr"),
        15,
    );
    xmr_dnr.available_liquidity_atomic_units = 8_250_000_000_000;
    xmr_dnr.low_fee_priority = 9;

    let _ = state.push_vault(xmr_usdc.clone());
    let _ = state.push_vault(xmr_dnr.clone());

    let bucket_a = FeeCreditBucket::new(
        xmr_usdc.vault_id.clone(),
        deterministic_tag("OWNER", "alice-view"),
        25_000_000,
    );
    let bucket_b = FeeCreditBucket::new(
        xmr_dnr.vault_id.clone(),
        deterministic_tag("OWNER", "bob-view"),
        18_000_000,
    );
    let _ = state.open_fee_bucket(bucket_a.clone());
    let _ = state.open_fee_bucket(bucket_b.clone());

    let mut intent_a = SwapIntent::new(
        &xmr_usdc,
        SwapSide::BaseToQuote,
        deterministic_tag("INPUT-NOTE", "alice-xmr"),
        deterministic_tag("OUTPUT-NOTE", "alice-usdc"),
        6_000_000_000,
    );
    intent_a.attach_fee_bucket(bucket_a.bucket_id.clone());

    let mut intent_b = SwapIntent::new(
        &xmr_dnr,
        SwapSide::QuoteToBase,
        deterministic_tag("INPUT-NOTE", "bob-dnr"),
        deterministic_tag("OUTPUT-NOTE", "bob-xmr"),
        4_500_000_000,
    );
    intent_b.attach_fee_bucket(bucket_b.bucket_id.clone());

    let _ = state.accept_swap_intent(intent_a.clone());
    let _ = state.accept_swap_intent(intent_b.clone());

    let quote_a = PqQuoteAttestation::new(&xmr_usdc, &intent_a);
    let quote_b = PqQuoteAttestation::new(&xmr_dnr, &intent_b);
    let _ = state.attest_quote(quote_a.clone());
    let _ = state.attest_quote(quote_b.clone());

    let _ = state.add_guardrail(LiquidityGuardrail::new(&xmr_usdc, "xmr-usdc-low-fee-band"));
    let _ = state.add_guardrail(LiquidityGuardrail::new(&xmr_dnr, "xmr-dnr-routing-band"));

    let mut batch = ClearingBatch::new(
        deterministic_tag("COORDINATOR", "devnet-proof-fee-clearer"),
        &[intent_a.clone(), intent_b.clone()],
        &[quote_a.clone(), quote_b.clone()],
        &[bucket_a.clone(), bucket_b.clone()],
    );
    batch.rebate_root = public_record_root(
        "DEVNET-REBATES",
        &[
            json!(intent_a.expected_rebate_atomic_units.to_string()),
            json!(intent_b.expected_rebate_atomic_units.to_string()),
        ],
    );
    let state_root_before = state.state_root();
    let _ = state.clear_batch(batch.clone());

    let stored_batch = state
        .clearing_batches
        .last()
        .cloned()
        .unwrap_or_else(|| batch.clone());
    let rebate_a = RebateSettlement::new(
        &stored_batch,
        &bucket_a,
        intent_a.expected_rebate_atomic_units,
    );
    let rebate_b = RebateSettlement::new(
        &stored_batch,
        &bucket_b,
        intent_b.expected_rebate_atomic_units,
    );
    let _ = state.settle_rebate(rebate_a);
    let _ = state.settle_rebate(rebate_b);

    let state_root_after = state.state_root();
    let receipt = SettlementReceipt::new(
        ReceiptKind::BatchCleared,
        stored_batch.batch_id.clone(),
        stored_batch.batch_id.clone(),
        xmr_usdc.vault_id.clone(),
        stored_batch.private_fee_settlement_root.clone(),
        state_root_before,
        state_root_after,
    );
    let _ = state.publish_receipt(receipt);

    let summary = OperatorSummary::new(
        deterministic_tag("OPERATOR", "devnet-low-fee-vault-operator"),
        &[stored_batch],
    );
    let _ = state.publish_operator_summary(summary);
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let mut records = records.to_vec();
    records.sort_by_key(canonical_json);
    merkle_root(domain, &records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE", record)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn root_from_strings(domain: &str, parts: &[&str]) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&json!(parts.len())),
            HashPart::Str(&canonical_json(&json!(parts))),
        ],
        32,
    )
}

pub fn id_from_record(domain: &str, record: &Value) -> String {
    root_from_record(domain, record)
}

pub fn deterministic_tag(domain: &str, label: &str) -> String {
    root_from_strings(domain, &[label])
}

pub fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

fn sorted_records(records: Vec<Value>) -> Vec<Value> {
    let mut records = records;
    records.sort_by_key(canonical_json);
    records
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn required(field: &str, value: &str) -> Result<()> {
    require(!value.trim().is_empty(), &format!("{field} is required"))
}

fn require_root(field: &str, value: &str) -> Result<()> {
    required(field, value)?;
    require(
        value.len() >= 16,
        &format!("{field} must be a deterministic root or commitment"),
    )
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    require(
        value <= PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_MAX_BPS,
        &format!("{field} exceeds bps denominator"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_fixture_validates_and_has_stable_root() {
        let state = State::devnet();
        state.validate().expect("devnet should validate");
        assert_eq!(state.state_root(), state.state_root());
        assert_eq!(
            state.public_record()["protocol_version"],
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_PROOF_FEE_SWAP_VAULT_RUNTIME_PROTOCOL_VERSION
        );
    }

    #[test]
    fn low_fee_vault_quotes_fee_and_rebate() {
        let vault = ConfidentialProofFeeVault::new(
            "test-vault",
            VaultKind::StableSwap,
            deterministic_tag("ASSET", "base"),
            deterministic_tag("ASSET", "quote"),
            10,
        );
        assert_eq!(vault.fee_quote_atomic_units(1_000_000), 1_000);
        assert!(
            vault.rebate_quote_atomic_units(1_000_000) <= vault.fee_quote_atomic_units(1_000_000)
        );
    }
}
