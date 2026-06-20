use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-private-parallel-intent-execution-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_INTENT_SUITE: &str = "sealed-private-parallel-intent-root-v1";
pub const DEPENDENCY_WITNESS_SUITE: &str = "private-intent-dependency-witness-root-v1";
pub const PQ_PREAUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-intent-preauth-v1";
pub const PARALLEL_BATCH_SUITE: &str = "private-parallel-intent-execution-batch-root-v1";
pub const RECEIPT_SUITE: &str = "private-parallel-intent-execution-receipt-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "private-parallel-intent-low-fee-rebate-root-v1";
pub const PRIVACY_ACCOUNTING_SUITE: &str = "private-parallel-intent-privacy-accounting-root-v1";
pub const SLASHING_SUITE: &str = "private-parallel-intent-witness-slashing-root-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 1_980_000;
pub const DEFAULT_DEVNET_EPOCH: u64 = 24_576;
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_PREAUTH_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 6;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 4;
pub const DEFAULT_MAX_LANES: usize = 4_096;
pub const DEFAULT_MAX_INTENTS: usize = 8_388_608;
pub const DEFAULT_MAX_WITNESSES: usize = 16_777_216;
pub const DEFAULT_MAX_PREAUTHS: usize = 8_388_608;
pub const DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_PRIVACY_ACCOUNTS: usize = 4_194_304;
pub const DEFAULT_MAX_SLASHES: usize = 1_048_576;
pub const DEFAULT_MAX_INTENTS_PER_BATCH: usize = 16_384;
pub const DEFAULT_MAX_WITNESSES_PER_INTENT: usize = 64;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_BATCH_MS: u64 = 420;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_LANE_OPERATOR_REBATE_BPS: u64 = 2;
pub const DEFAULT_CONFLICTING_WITNESS_SLASH_BPS: u64 = 4_000;
pub const DEFAULT_STALE_EXECUTION_SLASH_BPS: u64 = 1_500;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateExecutionLane {
    UltraFastDefi,
    ConfidentialTransfer,
    ShieldedContractCall,
    TokenRuntime,
    Lending,
    Perpetuals,
    Vault,
    Oracle,
    MoneroBridge,
    Paymaster,
    BackgroundProof,
    Emergency,
}

impl PrivateExecutionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraFastDefi => "ultra_fast_defi",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::ShieldedContractCall => "shielded_contract_call",
            Self::TokenRuntime => "token_runtime",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Vault => "vault",
            Self::Oracle => "oracle",
            Self::MoneroBridge => "monero_bridge",
            Self::Paymaster => "paymaster",
            Self::BackgroundProof => "background_proof",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::MoneroBridge => 9_800,
            Self::Perpetuals => 9_500,
            Self::UltraFastDefi => 9_300,
            Self::Lending => 9_000,
            Self::Vault => 8_800,
            Self::ShieldedContractCall => 8_500,
            Self::ConfidentialTransfer => 8_300,
            Self::TokenRuntime => 8_100,
            Self::Paymaster => 7_900,
            Self::Oracle => 7_700,
            Self::BackgroundProof => 6_500,
        }
    }

    pub fn latency_sensitive(self) -> bool {
        matches!(
            self,
            Self::Emergency | Self::MoneroBridge | Self::Perpetuals | Self::UltraFastDefi
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    PrivateCall,
    ConfidentialTransfer,
    TokenMint,
    TokenBurn,
    DefiSwap,
    AddLiquidity,
    RemoveLiquidity,
    Borrow,
    Repay,
    Liquidation,
    VaultDeposit,
    VaultRedeem,
    OracleRead,
    GovernanceAction,
    BridgeLock,
    BridgeRelease,
    PaymasterSponsor,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCall => "private_call",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::DefiSwap => "defi_swap",
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::Liquidation => "liquidation",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultRedeem => "vault_redeem",
            Self::OracleRead => "oracle_read",
            Self::GovernanceAction => "governance_action",
            Self::BridgeLock => "bridge_lock",
            Self::BridgeRelease => "bridge_release",
            Self::PaymasterSponsor => "paymaster_sponsor",
        }
    }

    pub fn mutates_private_state(self) -> bool {
        !matches!(self, Self::OracleRead)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    WitnessLocked,
    PqPreauthorized,
    Ready,
    Batched,
    Executed,
    Receipted,
    Expired,
    Rejected,
    Slashed,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::WitnessLocked => "witness_locked",
            Self::PqPreauthorized => "pq_preauthorized",
            Self::Ready => "ready",
            Self::Batched => "batched",
            Self::Executed => "executed",
            Self::Receipted => "receipted",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_witnesses(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::WitnessLocked | Self::PqPreauthorized
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessKind {
    ReadSet,
    WriteSet,
    NullifierSet,
    ContractDependency,
    LiquidityDependency,
    OracleDependency,
    BridgeFinality,
    PaymasterAllowance,
    ProofHint,
    PrivacySet,
}

impl WitnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadSet => "read_set",
            Self::WriteSet => "write_set",
            Self::NullifierSet => "nullifier_set",
            Self::ContractDependency => "contract_dependency",
            Self::LiquidityDependency => "liquidity_dependency",
            Self::OracleDependency => "oracle_dependency",
            Self::BridgeFinality => "bridge_finality",
            Self::PaymasterAllowance => "paymaster_allowance",
            Self::ProofHint => "proof_hint",
            Self::PrivacySet => "privacy_set",
        }
    }

    pub fn conflict_scope(self) -> &'static str {
        match self {
            Self::ReadSet | Self::ProofHint | Self::PrivacySet => "advisory",
            Self::WriteSet | Self::NullifierSet => "exclusive",
            Self::ContractDependency
            | Self::LiquidityDependency
            | Self::OracleDependency
            | Self::BridgeFinality
            | Self::PaymasterAllowance => "dependency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStatus {
    Open,
    Satisfied,
    Conflicting,
    BypassedByProof,
    Expired,
    Slashed,
}

impl WitnessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Satisfied => "satisfied",
            Self::Conflicting => "conflicting",
            Self::BypassedByProof => "bypassed_by_proof",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreauthStatus {
    Pending,
    Verified,
    BoundToBatch,
    Consumed,
    Expired,
    Revoked,
    Rejected,
}

impl PreauthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::BoundToBatch => "bound_to_batch",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    WitnessChecked,
    Executing,
    Executed,
    Receipted,
    Finalized,
    Expired,
    Rejected,
    Slashed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::WitnessChecked => "witness_checked",
            Self::Executing => "executing",
            Self::Executed => "executed",
            Self::Receipted => "receipted",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Posted,
    RebateReserved,
    Finalized,
    Challenged,
    Slashed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::RebateReserved => "rebate_reserved",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Claimable,
    Paid,
    Forfeited,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Claimable => "claimable",
            Self::Paid => "paid",
            Self::Forfeited => "forfeited",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyStatus {
    Accruing,
    Satisfied,
    Deficient,
    Penalized,
}

impl PrivacyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Satisfied => "satisfied",
            Self::Deficient => "deficient",
            Self::Penalized => "penalized",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashKind {
    ConflictingWitness,
    StaleExecution,
    InvalidPqPreauthorization,
    PrivacySetDeficiency,
    ReceiptMismatch,
    DuplicateNullifier,
}

impl SlashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConflictingWitness => "conflicting_witness",
            Self::StaleExecution => "stale_execution",
            Self::InvalidPqPreauthorization => "invalid_pq_preauthorization",
            Self::PrivacySetDeficiency => "privacy_set_deficiency",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::DuplicateNullifier => "duplicate_nullifier",
        }
    }

    pub fn default_bps(self) -> u64 {
        match self {
            Self::ConflictingWitness | Self::DuplicateNullifier => {
                DEFAULT_CONFLICTING_WITNESS_SLASH_BPS
            }
            Self::StaleExecution => DEFAULT_STALE_EXECUTION_SLASH_BPS,
            Self::InvalidPqPreauthorization => 2_500,
            Self::PrivacySetDeficiency => 1_000,
            Self::ReceiptMismatch => 3_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub sealed_intent_suite: String,
    pub dependency_witness_suite: String,
    pub pq_preauth_suite: String,
    pub parallel_batch_suite: String,
    pub receipt_suite: String,
    pub low_fee_rebate_suite: String,
    pub privacy_accounting_suite: String,
    pub slashing_suite: String,
    pub intent_ttl_blocks: u64,
    pub preauth_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub max_lanes: usize,
    pub max_intents: usize,
    pub max_witnesses: usize,
    pub max_preauths: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_privacy_accounts: usize,
    pub max_slashes: usize,
    pub max_intents_per_batch: usize,
    pub max_witnesses_per_intent: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_batch_ms: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub lane_operator_rebate_bps: u64,
    pub conflicting_witness_slash_bps: u64,
    pub stale_execution_slash_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            sealed_intent_suite: SEALED_INTENT_SUITE.to_string(),
            dependency_witness_suite: DEPENDENCY_WITNESS_SUITE.to_string(),
            pq_preauth_suite: PQ_PREAUTH_SUITE.to_string(),
            parallel_batch_suite: PARALLEL_BATCH_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            privacy_accounting_suite: PRIVACY_ACCOUNTING_SUITE.to_string(),
            slashing_suite: SLASHING_SUITE.to_string(),
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            preauth_ttl_blocks: DEFAULT_PREAUTH_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            max_lanes: DEFAULT_MAX_LANES,
            max_intents: DEFAULT_MAX_INTENTS,
            max_witnesses: DEFAULT_MAX_WITNESSES,
            max_preauths: DEFAULT_MAX_PREAUTHS,
            max_batches: DEFAULT_MAX_BATCHES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_privacy_accounts: DEFAULT_MAX_PRIVACY_ACCOUNTS,
            max_slashes: DEFAULT_MAX_SLASHES,
            max_intents_per_batch: DEFAULT_MAX_INTENTS_PER_BATCH,
            max_witnesses_per_intent: DEFAULT_MAX_WITNESSES_PER_INTENT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_batch_ms: DEFAULT_TARGET_BATCH_MS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            lane_operator_rebate_bps: DEFAULT_LANE_OPERATOR_REBATE_BPS,
            conflicting_witness_slash_bps: DEFAULT_CONFLICTING_WITNESS_SLASH_BPS,
            stale_execution_slash_bps: DEFAULT_STALE_EXECUTION_SLASH_BPS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("chain_id", &self.chain_id),
            ("protocol_version", &self.protocol_version),
            ("l2_network", &self.l2_network),
            ("monero_network", &self.monero_network),
            ("fee_asset_id", &self.fee_asset_id),
            ("hash_suite", &self.hash_suite),
            ("sealed_intent_suite", &self.sealed_intent_suite),
            ("dependency_witness_suite", &self.dependency_witness_suite),
            ("pq_preauth_suite", &self.pq_preauth_suite),
            ("parallel_batch_suite", &self.parallel_batch_suite),
            ("receipt_suite", &self.receipt_suite),
            ("low_fee_rebate_suite", &self.low_fee_rebate_suite),
            ("privacy_accounting_suite", &self.privacy_accounting_suite),
            ("slashing_suite", &self.slashing_suite),
        ] {
            ensure_non_empty(name, value)?;
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("private parallel intent runtime schema version mismatch".to_string());
        }
        if self.intent_ttl_blocks == 0
            || self.preauth_ttl_blocks == 0
            || self.batch_ttl_blocks == 0
            || self.receipt_finality_blocks == 0
            || self.target_batch_ms == 0
            || self.min_pq_security_bits == 0
        {
            return Err("private parallel intent runtime positive thresholds required".to_string());
        }
        if self.max_lanes == 0
            || self.max_intents == 0
            || self.max_witnesses == 0
            || self.max_preauths == 0
            || self.max_batches == 0
            || self.max_receipts == 0
            || self.max_rebates == 0
            || self.max_privacy_accounts == 0
            || self.max_slashes == 0
            || self.max_intents_per_batch == 0
            || self.max_witnesses_per_intent == 0
        {
            return Err("private parallel intent runtime capacities must be positive".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("private parallel intent privacy set thresholds are invalid".to_string());
        }
        for (name, value) in [
            ("max_user_fee_bps", self.max_user_fee_bps),
            ("target_rebate_bps", self.target_rebate_bps),
            ("lane_operator_rebate_bps", self.lane_operator_rebate_bps),
            (
                "conflicting_witness_slash_bps",
                self.conflicting_witness_slash_bps,
            ),
            ("stale_execution_slash_bps", self.stale_execution_slash_bps),
        ] {
            if value > MAX_BPS {
                return Err(format!("{name} cannot exceed 100%"));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "sealed_intent_suite": self.sealed_intent_suite,
            "dependency_witness_suite": self.dependency_witness_suite,
            "pq_preauth_suite": self.pq_preauth_suite,
            "parallel_batch_suite": self.parallel_batch_suite,
            "receipt_suite": self.receipt_suite,
            "low_fee_rebate_suite": self.low_fee_rebate_suite,
            "privacy_accounting_suite": self.privacy_accounting_suite,
            "slashing_suite": self.slashing_suite,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "preauth_ttl_blocks": self.preauth_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "max_lanes": self.max_lanes,
            "max_intents": self.max_intents,
            "max_witnesses": self.max_witnesses,
            "max_preauths": self.max_preauths,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_privacy_accounts": self.max_privacy_accounts,
            "max_slashes": self.max_slashes,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_witnesses_per_intent": self.max_witnesses_per_intent,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_batch_ms": self.target_batch_ms,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "lane_operator_rebate_bps": self.lane_operator_rebate_bps,
            "conflicting_witness_slash_bps": self.conflicting_witness_slash_bps,
            "stale_execution_slash_bps": self.stale_execution_slash_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_opened: u64,
    pub intents_sealed: u64,
    pub witnesses_registered: u64,
    pub preauths_verified: u64,
    pub batches_built: u64,
    pub batches_executed: u64,
    pub receipts_posted: u64,
    pub rebates_reserved: u64,
    pub privacy_accounts_updated: u64,
    pub slashes_recorded: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes_opened": self.lanes_opened,
            "intents_sealed": self.intents_sealed,
            "witnesses_registered": self.witnesses_registered,
            "preauths_verified": self.preauths_verified,
            "batches_built": self.batches_built,
            "batches_executed": self.batches_executed,
            "receipts_posted": self.receipts_posted,
            "rebates_reserved": self.rebates_reserved,
            "privacy_accounts_updated": self.privacy_accounts_updated,
            "slashes_recorded": self.slashes_recorded,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub lane_root: String,
    pub intent_root: String,
    pub witness_root: String,
    pub preauth_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_account_root: String,
    pub slash_root: String,
    pub operator_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_root": self.lane_root,
            "intent_root": self.intent_root,
            "witness_root": self.witness_root,
            "preauth_root": self.preauth_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_account_root": self.privacy_account_root,
            "slash_root": self.slash_root,
            "operator_root": self.operator_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneOpenRequest {
    pub lane: PrivateExecutionLane,
    pub lane_operator_commitment: String,
    pub admission_root: String,
    pub privacy_pool_root: String,
    pub max_parallelism: u64,
    pub fee_cap_bps: u64,
    pub opened_at_height: u64,
}

impl LaneOpenRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_operator_commitment": self.lane_operator_commitment,
            "admission_root": self.admission_root,
            "privacy_pool_root": self.privacy_pool_root,
            "max_parallelism": self.max_parallelism,
            "fee_cap_bps": self.fee_cap_bps,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateLaneRecord {
    pub lane_id: String,
    pub request: LaneOpenRequest,
    pub active_intents: BTreeSet<String>,
    pub committed_batches: BTreeSet<String>,
    pub status: String,
}

impl PrivateLaneRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "request": self.request.public_record(),
            "active_intents": self.active_intents,
            "committed_batches": self.committed_batches,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedIntentRequest {
    pub lane_id: String,
    pub lane: PrivateExecutionLane,
    pub intent_kind: IntentKind,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub sealed_payload_root: String,
    pub encrypted_call_root: String,
    pub nullifier_root: String,
    pub dependency_root: String,
    pub witness_commitment_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub expiry_height: u64,
    pub submitted_at_height: u64,
}

impl SealedIntentRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "intent_kind": self.intent_kind.as_str(),
            "sender_commitment": self.sender_commitment,
            "contract_commitment": self.contract_commitment,
            "sealed_payload_root": self.sealed_payload_root,
            "encrypted_call_root": self.encrypted_call_root,
            "nullifier_root": self.nullifier_root,
            "dependency_root": self.dependency_root,
            "witness_commitment_root": self.witness_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "expiry_height": self.expiry_height,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedIntentRecord {
    pub intent_id: String,
    pub request: SealedIntentRequest,
    pub witness_ids: BTreeSet<String>,
    pub preauth_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub status: IntentStatus,
    pub status_height: u64,
}

impl SealedIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "request": self.request.public_record(),
            "witness_ids": self.witness_ids,
            "preauth_id": self.preauth_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "status_height": self.status_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessCommitmentRequest {
    pub intent_id: String,
    pub witness_kind: WitnessKind,
    pub dependency_key_root: String,
    pub witness_root: String,
    pub expected_state_root: String,
    pub conflict_salt_root: String,
    pub provider_commitment: String,
    pub valid_after_height: u64,
    pub expires_at_height: u64,
}

impl WitnessCommitmentRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "witness_kind": self.witness_kind.as_str(),
            "dependency_key_root": self.dependency_key_root,
            "witness_root": self.witness_root,
            "expected_state_root": self.expected_state_root,
            "conflict_salt_root": self.conflict_salt_root,
            "provider_commitment": self.provider_commitment,
            "valid_after_height": self.valid_after_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessCommitmentRecord {
    pub witness_id: String,
    pub request: WitnessCommitmentRequest,
    pub status: WitnessStatus,
    pub conflicting_witness_id: Option<String>,
    pub status_height: u64,
}

impl WitnessCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "conflicting_witness_id": self.conflicting_witness_id,
            "status_height": self.status_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPreauthorizationRequest {
    pub intent_id: String,
    pub authorizer_commitment: String,
    pub pq_key_root: String,
    pub pq_signature_root: String,
    pub session_ciphertext_root: String,
    pub witness_root: String,
    pub security_bits: u16,
    pub expires_at_height: u64,
}

impl PqPreauthorizationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "authorizer_commitment": self.authorizer_commitment,
            "pq_key_root": self.pq_key_root,
            "pq_signature_root": self.pq_signature_root,
            "session_ciphertext_root": self.session_ciphertext_root,
            "witness_root": self.witness_root,
            "security_bits": self.security_bits,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPreauthorizationRecord {
    pub preauth_id: String,
    pub request: PqPreauthorizationRequest,
    pub status: PreauthStatus,
    pub status_height: u64,
}

impl PqPreauthorizationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "preauth_id": self.preauth_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "status_height": self.status_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParallelBatchRequest {
    pub lane_id: String,
    pub lane: PrivateExecutionLane,
    pub builder_commitment: String,
    pub intent_ids: Vec<String>,
    pub dependency_root: String,
    pub witness_root: String,
    pub preauth_root: String,
    pub privacy_account_root: String,
    pub proposed_state_root: String,
    pub max_fee_bps: u64,
    pub target_execution_ms: u64,
    pub expires_at_height: u64,
}

impl ParallelBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "builder_commitment": self.builder_commitment,
            "intent_ids": self.intent_ids,
            "dependency_root": self.dependency_root,
            "witness_root": self.witness_root,
            "preauth_root": self.preauth_root,
            "privacy_account_root": self.privacy_account_root,
            "proposed_state_root": self.proposed_state_root,
            "max_fee_bps": self.max_fee_bps,
            "target_execution_ms": self.target_execution_ms,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParallelBatchRecord {
    pub batch_id: String,
    pub request: ParallelBatchRequest,
    pub execution_root: Option<String>,
    pub receipt_id: Option<String>,
    pub status: BatchStatus,
    pub status_height: u64,
}

impl ParallelBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "execution_root": self.execution_root,
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "status_height": self.status_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceiptRequest {
    pub batch_id: String,
    pub publisher_commitment: String,
    pub execution_trace_root: String,
    pub new_private_state_root: String,
    pub nullifier_root: String,
    pub output_commitment_root: String,
    pub recursive_proof_root: String,
    pub fee_root: String,
    pub privacy_account_root: String,
    pub executed_at_height: u64,
}

impl ExecutionReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "publisher_commitment": self.publisher_commitment,
            "execution_trace_root": self.execution_trace_root,
            "new_private_state_root": self.new_private_state_root,
            "nullifier_root": self.nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "recursive_proof_root": self.recursive_proof_root,
            "fee_root": self.fee_root,
            "privacy_account_root": self.privacy_account_root,
            "executed_at_height": self.executed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceiptRecord {
    pub receipt_id: String,
    pub request: ExecutionReceiptRequest,
    pub rebate_ids: BTreeSet<String>,
    pub status: ReceiptStatus,
    pub finalizes_at_height: u64,
}

impl ExecutionReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "rebate_ids": self.rebate_ids,
            "status": self.status.as_str(),
            "finalizes_at_height": self.finalizes_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebateRequest {
    pub receipt_id: String,
    pub intent_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub paid_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_bps: u64,
    pub claim_root: String,
}

impl LowFeeRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_asset_id": self.rebate_asset_id,
            "paid_fee_bps": self.paid_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "rebate_bps": self.rebate_bps,
            "claim_root": self.claim_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebateRecord {
    pub rebate_id: String,
    pub request: LowFeeRebateRequest,
    pub status: RebateStatus,
    pub status_height: u64,
}

impl LowFeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "status_height": self.status_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyAccountingRequest {
    pub subject_commitment: String,
    pub lane_id: String,
    pub anonymity_set_root: String,
    pub privacy_budget_root: String,
    pub observed_set_size: u64,
    pub target_set_size: u64,
    pub spent_units: u64,
    pub credited_units: u64,
    pub accounting_height: u64,
}

impl PrivacyAccountingRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "subject_commitment": self.subject_commitment,
            "lane_id": self.lane_id,
            "anonymity_set_root": self.anonymity_set_root,
            "privacy_budget_root": self.privacy_budget_root,
            "observed_set_size": self.observed_set_size,
            "target_set_size": self.target_set_size,
            "spent_units": self.spent_units,
            "credited_units": self.credited_units,
            "accounting_height": self.accounting_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyAccountingRecord {
    pub account_id: String,
    pub request: PrivacyAccountingRequest,
    pub status: PrivacyStatus,
    pub status_height: u64,
}

impl PrivacyAccountingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "status_height": self.status_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashRequest {
    pub slash_kind: SlashKind,
    pub accused_commitment: String,
    pub evidence_root: String,
    pub related_intent_id: Option<String>,
    pub related_witness_id: Option<String>,
    pub related_batch_id: Option<String>,
    pub reporter_commitment: String,
    pub slash_bps: u64,
    pub reported_at_height: u64,
}

impl SlashRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_kind": self.slash_kind.as_str(),
            "accused_commitment": self.accused_commitment,
            "evidence_root": self.evidence_root,
            "related_intent_id": self.related_intent_id,
            "related_witness_id": self.related_witness_id,
            "related_batch_id": self.related_batch_id,
            "reporter_commitment": self.reporter_commitment,
            "slash_bps": self.slash_bps,
            "reported_at_height": self.reported_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashRecord {
    pub slash_id: String,
    pub request: SlashRequest,
    pub adjudicated: bool,
    pub applied_height: Option<u64>,
}

impl SlashRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "request": self.request.public_record(),
            "adjudicated": self.adjudicated,
            "applied_height": self.applied_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub counters: Counters,
    pub lanes: BTreeMap<String, PrivateLaneRecord>,
    pub intents: BTreeMap<String, SealedIntentRecord>,
    pub witnesses: BTreeMap<String, WitnessCommitmentRecord>,
    pub preauthorizations: BTreeMap<String, PqPreauthorizationRecord>,
    pub batches: BTreeMap<String, ParallelBatchRecord>,
    pub receipts: BTreeMap<String, ExecutionReceiptRecord>,
    pub rebates: BTreeMap<String, LowFeeRebateRecord>,
    pub privacy_accounts: BTreeMap<String, PrivacyAccountingRecord>,
    pub slashes: BTreeMap<String, SlashRecord>,
    pub lane_operators: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut lane_operators = BTreeSet::new();
        lane_operators.insert(deterministic_root("operator", "devnet-private-intent-0", 0));
        lane_operators.insert(deterministic_root("operator", "devnet-private-intent-1", 1));
        lane_operators.insert(deterministic_root("operator", "devnet-private-intent-2", 2));

        Self {
            config: Config::devnet(),
            current_height: DEFAULT_DEVNET_HEIGHT,
            current_epoch: DEFAULT_DEVNET_EPOCH,
            counters: Counters::default(),
            lanes: BTreeMap::new(),
            intents: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            preauthorizations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_accounts: BTreeMap::new(),
            slashes: BTreeMap::new(),
            lane_operators,
        }
    }

    pub fn with_config(config: Config, current_height: u64, current_epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_height,
            current_epoch,
            counters: Counters::default(),
            lanes: BTreeMap::new(),
            intents: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            preauthorizations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_accounts: BTreeMap::new(),
            slashes: BTreeMap::new(),
            lane_operators: BTreeSet::new(),
        })
    }

    pub fn advance_height(&mut self, new_height: u64) -> Result<()> {
        if new_height < self.current_height {
            return Err("private parallel intent height cannot move backward".to_string());
        }
        self.current_height = new_height;
        self.expire_stale_records();
        Ok(())
    }

    pub fn open_lane(&mut self, request: LaneOpenRequest) -> Result<String> {
        self.ensure_capacity(self.lanes.len(), self.config.max_lanes, "lanes")?;
        ensure_root(
            "lane operator commitment",
            &request.lane_operator_commitment,
        )?;
        ensure_root("lane admission root", &request.admission_root)?;
        ensure_root("lane privacy pool root", &request.privacy_pool_root)?;
        ensure_positive("max_parallelism", request.max_parallelism)?;
        ensure_bps("fee_cap_bps", request.fee_cap_bps)?;
        if request.fee_cap_bps > self.config.max_user_fee_bps {
            return Err("private lane fee cap exceeds runtime maximum".to_string());
        }

        let lane_id = deterministic_id(
            "lane",
            self.counters.lanes_opened + 1,
            &request.public_record(),
        );
        if self.lanes.contains_key(&lane_id) {
            return Err("private lane already exists".to_string());
        }
        self.lane_operators
            .insert(request.lane_operator_commitment.clone());
        self.lanes.insert(
            lane_id.clone(),
            PrivateLaneRecord {
                lane_id: lane_id.clone(),
                request,
                active_intents: BTreeSet::new(),
                committed_batches: BTreeSet::new(),
                status: "open".to_string(),
            },
        );
        self.counters.lanes_opened += 1;
        Ok(lane_id)
    }

    pub fn submit_sealed_intent(&mut self, mut request: SealedIntentRequest) -> Result<String> {
        self.ensure_capacity(self.intents.len(), self.config.max_intents, "intents")?;
        self.ensure_lane(&request.lane_id)?;
        ensure_root("sender commitment", &request.sender_commitment)?;
        ensure_root("contract commitment", &request.contract_commitment)?;
        ensure_root("sealed payload root", &request.sealed_payload_root)?;
        ensure_root("encrypted call root", &request.encrypted_call_root)?;
        ensure_root("nullifier root", &request.nullifier_root)?;
        ensure_root("dependency root", &request.dependency_root)?;
        ensure_root("witness commitment root", &request.witness_commitment_root)?;
        ensure_bps("max_fee_bps", request.max_fee_bps)?;
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("sealed private intent fee exceeds runtime maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("sealed private intent privacy set is too small".to_string());
        }
        if request.submitted_at_height == 0 {
            request.submitted_at_height = self.current_height;
        }
        if request.expiry_height == 0 {
            request.expiry_height = request.submitted_at_height + self.config.intent_ttl_blocks;
        }
        if request.expiry_height <= self.current_height {
            return Err("sealed private intent expiry is stale".to_string());
        }

        let intent_id = deterministic_id(
            "sealed-intent",
            self.counters.intents_sealed + 1,
            &request.public_record(),
        );
        if self.intents.contains_key(&intent_id) {
            return Err("sealed private intent already exists".to_string());
        }
        self.intents.insert(
            intent_id.clone(),
            SealedIntentRecord {
                intent_id: intent_id.clone(),
                request: request.clone(),
                witness_ids: BTreeSet::new(),
                preauth_id: None,
                batch_id: None,
                receipt_id: None,
                status: IntentStatus::Sealed,
                status_height: self.current_height,
            },
        );
        if let Some(lane) = self.lanes.get_mut(&request.lane_id) {
            lane.active_intents.insert(intent_id.clone());
        }
        self.counters.intents_sealed += 1;
        Ok(intent_id)
    }

    pub fn register_witness_commitment(
        &mut self,
        request: WitnessCommitmentRequest,
    ) -> Result<String> {
        self.ensure_capacity(self.witnesses.len(), self.config.max_witnesses, "witnesses")?;
        ensure_root("dependency key root", &request.dependency_key_root)?;
        ensure_root("witness root", &request.witness_root)?;
        ensure_root("expected state root", &request.expected_state_root)?;
        ensure_root("conflict salt root", &request.conflict_salt_root)?;
        ensure_root("provider commitment", &request.provider_commitment)?;
        if request.expires_at_height <= self.current_height {
            return Err("private intent witness commitment is stale".to_string());
        }

        let witness_count = self
            .intents
            .get(&request.intent_id)
            .ok_or_else(|| "sealed private intent not found for witness".to_string())?
            .witness_ids
            .len();
        if witness_count >= self.config.max_witnesses_per_intent {
            return Err("sealed private intent witness limit exceeded".to_string());
        }
        if !self
            .intents
            .get(&request.intent_id)
            .expect("checked above")
            .status
            .accepts_witnesses()
        {
            return Err("sealed private intent no longer accepts witnesses".to_string());
        }

        let conflicting_witness_id = self.find_conflicting_witness(&request);
        let status = if conflicting_witness_id.is_some() {
            WitnessStatus::Conflicting
        } else {
            WitnessStatus::Open
        };
        let witness_id = deterministic_id(
            "witness",
            self.counters.witnesses_registered + 1,
            &request.public_record(),
        );
        self.witnesses.insert(
            witness_id.clone(),
            WitnessCommitmentRecord {
                witness_id: witness_id.clone(),
                request: request.clone(),
                status,
                conflicting_witness_id: conflicting_witness_id.clone(),
                status_height: self.current_height,
            },
        );
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.witness_ids.insert(witness_id.clone());
            intent.status = if conflicting_witness_id.is_some() {
                IntentStatus::Rejected
            } else {
                IntentStatus::WitnessLocked
            };
            intent.status_height = self.current_height;
        }
        if let Some(conflict) = conflicting_witness_id {
            let slash_request = SlashRequest {
                slash_kind: SlashKind::ConflictingWitness,
                accused_commitment: request.provider_commitment,
                evidence_root: payload_root(
                    "PRIVATE-PARALLEL-INTENT-CONFLICTING-WITNESS-EVIDENCE",
                    &json!({ "witness_id": witness_id, "conflicting_witness_id": conflict }),
                ),
                related_intent_id: Some(request.intent_id),
                related_witness_id: Some(conflict),
                related_batch_id: None,
                reporter_commitment: deterministic_root("reporter", "conflict-detector", 0),
                slash_bps: self.config.conflicting_witness_slash_bps,
                reported_at_height: self.current_height,
            };
            self.record_slash(slash_request)?;
        }
        self.counters.witnesses_registered += 1;
        Ok(witness_id)
    }

    pub fn satisfy_witness(&mut self, witness_id: &str, proof_root: &str) -> Result<()> {
        ensure_root("witness satisfaction proof root", proof_root)?;
        let witness = self
            .witnesses
            .get_mut(witness_id)
            .ok_or_else(|| "private intent witness not found".to_string())?;
        if witness.status != WitnessStatus::Open {
            return Err("private intent witness is not open".to_string());
        }
        witness.status = WitnessStatus::Satisfied;
        witness.status_height = self.current_height;
        self.refresh_intent_readiness(&witness.request.intent_id)?;
        Ok(())
    }

    pub fn verify_pq_preauthorization(
        &mut self,
        mut request: PqPreauthorizationRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            self.preauthorizations.len(),
            self.config.max_preauths,
            "preauthorizations",
        )?;
        ensure_root("authorizer commitment", &request.authorizer_commitment)?;
        ensure_root("pq key root", &request.pq_key_root)?;
        ensure_root("pq signature root", &request.pq_signature_root)?;
        ensure_root("session ciphertext root", &request.session_ciphertext_root)?;
        ensure_root("preauthorization witness root", &request.witness_root)?;
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("private intent PQ preauthorization security is too low".to_string());
        }
        if request.expires_at_height == 0 {
            request.expires_at_height = self.current_height + self.config.preauth_ttl_blocks;
        }
        if request.expires_at_height <= self.current_height {
            return Err("private intent PQ preauthorization is stale".to_string());
        }
        let intent = self
            .intents
            .get_mut(&request.intent_id)
            .ok_or_else(|| "sealed private intent not found for PQ preauthorization".to_string())?;
        if matches!(
            intent.status,
            IntentStatus::Batched
                | IntentStatus::Executed
                | IntentStatus::Receipted
                | IntentStatus::Expired
                | IntentStatus::Rejected
                | IntentStatus::Slashed
        ) {
            return Err("sealed private intent cannot accept PQ preauthorization".to_string());
        }

        let preauth_id = deterministic_id(
            "pq-preauthorization",
            self.counters.preauths_verified + 1,
            &request.public_record(),
        );
        self.preauthorizations.insert(
            preauth_id.clone(),
            PqPreauthorizationRecord {
                preauth_id: preauth_id.clone(),
                request: request.clone(),
                status: PreauthStatus::Verified,
                status_height: self.current_height,
            },
        );
        intent.preauth_id = Some(preauth_id.clone());
        intent.status = IntentStatus::PqPreauthorized;
        intent.status_height = self.current_height;
        self.counters.preauths_verified += 1;
        self.refresh_intent_readiness(&request.intent_id)?;
        Ok(preauth_id)
    }

    pub fn build_parallel_batch(&mut self, request: ParallelBatchRequest) -> Result<String> {
        self.ensure_capacity(self.batches.len(), self.config.max_batches, "batches")?;
        self.ensure_lane(&request.lane_id)?;
        ensure_root("batch builder commitment", &request.builder_commitment)?;
        ensure_root("batch dependency root", &request.dependency_root)?;
        ensure_root("batch witness root", &request.witness_root)?;
        ensure_root("batch preauthorization root", &request.preauth_root)?;
        ensure_root("batch privacy account root", &request.privacy_account_root)?;
        ensure_root("batch proposed state root", &request.proposed_state_root)?;
        ensure_bps("batch max_fee_bps", request.max_fee_bps)?;
        ensure_positive("target_execution_ms", request.target_execution_ms)?;
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("private parallel batch fee exceeds runtime maximum".to_string());
        }
        if request.intent_ids.is_empty() {
            return Err("private parallel batch must include at least one intent".to_string());
        }
        if request.intent_ids.len() > self.config.max_intents_per_batch {
            return Err("private parallel batch intent limit exceeded".to_string());
        }
        if request.expires_at_height <= self.current_height {
            return Err("private parallel batch expiry is stale".to_string());
        }

        let mut unique = BTreeSet::new();
        for intent_id in &request.intent_ids {
            if !unique.insert(intent_id.clone()) {
                return Err("private parallel batch contains duplicate intents".to_string());
            }
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("sealed private intent {intent_id} not found"))?;
            if intent.request.lane_id != request.lane_id {
                return Err("private parallel batch mixes lane ids".to_string());
            }
            if intent.request.lane != request.lane {
                return Err("private parallel batch mixes execution lanes".to_string());
            }
            if intent.status != IntentStatus::Ready {
                return Err(format!("sealed private intent {intent_id} is not ready"));
            }
            self.ensure_intent_witnesses_satisfied(intent_id)?;
        }

        let batch_id = deterministic_id(
            "parallel-batch",
            self.counters.batches_built + 1,
            &request.public_record(),
        );
        self.batches.insert(
            batch_id.clone(),
            ParallelBatchRecord {
                batch_id: batch_id.clone(),
                request: request.clone(),
                execution_root: None,
                receipt_id: None,
                status: BatchStatus::WitnessChecked,
                status_height: self.current_height,
            },
        );
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.batch_id = Some(batch_id.clone());
                intent.status = IntentStatus::Batched;
                intent.status_height = self.current_height;
            }
            if let Some(preauth_id) = self
                .intents
                .get(intent_id)
                .and_then(|i| i.preauth_id.clone())
            {
                if let Some(preauth) = self.preauthorizations.get_mut(&preauth_id) {
                    preauth.status = PreauthStatus::BoundToBatch;
                    preauth.status_height = self.current_height;
                }
            }
        }
        if let Some(lane) = self.lanes.get_mut(&request.lane_id) {
            lane.committed_batches.insert(batch_id.clone());
        }
        self.counters.batches_built += 1;
        Ok(batch_id)
    }

    pub fn execute_batch(&mut self, batch_id: &str, execution_root: &str) -> Result<()> {
        ensure_root("parallel execution root", execution_root)?;
        let intent_ids = {
            let batch = self
                .batches
                .get_mut(batch_id)
                .ok_or_else(|| "private parallel batch not found".to_string())?;
            if batch.status != BatchStatus::WitnessChecked && batch.status != BatchStatus::Executing
            {
                return Err("private parallel batch is not executable".to_string());
            }
            if batch.request.expires_at_height <= self.current_height {
                batch.status = BatchStatus::Expired;
                return Err("private parallel batch expired before execution".to_string());
            }
            batch.execution_root = Some(execution_root.to_string());
            batch.status = BatchStatus::Executed;
            batch.status_height = self.current_height;
            batch.request.intent_ids.clone()
        };

        for intent_id in intent_ids {
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.status = IntentStatus::Executed;
                intent.status_height = self.current_height;
            }
            if let Some(preauth_id) = self
                .intents
                .get(&intent_id)
                .and_then(|i| i.preauth_id.clone())
            {
                if let Some(preauth) = self.preauthorizations.get_mut(&preauth_id) {
                    preauth.status = PreauthStatus::Consumed;
                    preauth.status_height = self.current_height;
                }
            }
        }
        self.counters.batches_executed += 1;
        Ok(())
    }

    pub fn post_execution_receipt(&mut self, request: ExecutionReceiptRequest) -> Result<String> {
        self.ensure_capacity(self.receipts.len(), self.config.max_receipts, "receipts")?;
        ensure_root(
            "receipt publisher commitment",
            &request.publisher_commitment,
        )?;
        ensure_root("execution trace root", &request.execution_trace_root)?;
        ensure_root("new private state root", &request.new_private_state_root)?;
        ensure_root("receipt nullifier root", &request.nullifier_root)?;
        ensure_root("output commitment root", &request.output_commitment_root)?;
        ensure_root("recursive proof root", &request.recursive_proof_root)?;
        ensure_root("receipt fee root", &request.fee_root)?;
        ensure_root(
            "receipt privacy account root",
            &request.privacy_account_root,
        )?;
        if request.executed_at_height > self.current_height {
            return Err("private parallel receipt cannot execute in the future".to_string());
        }

        let intent_ids = {
            let batch = self
                .batches
                .get_mut(&request.batch_id)
                .ok_or_else(|| "private parallel batch not found for receipt".to_string())?;
            if batch.status != BatchStatus::Executed {
                return Err("private parallel batch has not executed".to_string());
            }
            batch.status = BatchStatus::Receipted;
            batch.status_height = self.current_height;
            batch.request.intent_ids.clone()
        };
        let receipt_id = deterministic_id(
            "receipt",
            self.counters.receipts_posted + 1,
            &request.public_record(),
        );
        self.receipts.insert(
            receipt_id.clone(),
            ExecutionReceiptRecord {
                receipt_id: receipt_id.clone(),
                request: request.clone(),
                rebate_ids: BTreeSet::new(),
                status: ReceiptStatus::Posted,
                finalizes_at_height: self.current_height + self.config.receipt_finality_blocks,
            },
        );
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.receipt_id = Some(receipt_id.clone());
        }
        for intent_id in intent_ids {
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.receipt_id = Some(receipt_id.clone());
                intent.status = IntentStatus::Receipted;
                intent.status_height = self.current_height;
            }
        }
        self.counters.receipts_posted += 1;
        Ok(receipt_id)
    }

    pub fn reserve_low_fee_rebate(&mut self, request: LowFeeRebateRequest) -> Result<String> {
        self.ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebates")?;
        ensure_non_empty("rebate asset id", &request.rebate_asset_id)?;
        ensure_root(
            "rebate beneficiary commitment",
            &request.beneficiary_commitment,
        )?;
        ensure_root("rebate claim root", &request.claim_root)?;
        ensure_bps("paid_fee_bps", request.paid_fee_bps)?;
        ensure_bps("target_fee_bps", request.target_fee_bps)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("private parallel intent rebate exceeds target".to_string());
        }
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("private parallel receipt not found for rebate".to_string());
        }
        if !self.intents.contains_key(&request.intent_id) {
            return Err("sealed private intent not found for rebate".to_string());
        }

        let rebate_id = deterministic_id(
            "rebate",
            self.counters.rebates_reserved + 1,
            &request.public_record(),
        );
        self.rebates.insert(
            rebate_id.clone(),
            LowFeeRebateRecord {
                rebate_id: rebate_id.clone(),
                request: request.clone(),
                status: RebateStatus::Reserved,
                status_height: self.current_height,
            },
        );
        if let Some(receipt) = self.receipts.get_mut(&request.receipt_id) {
            receipt.rebate_ids.insert(rebate_id.clone());
            receipt.status = ReceiptStatus::RebateReserved;
        }
        self.counters.rebates_reserved += 1;
        Ok(rebate_id)
    }

    pub fn update_privacy_accounting(
        &mut self,
        request: PrivacyAccountingRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            self.privacy_accounts.len(),
            self.config.max_privacy_accounts,
            "privacy accounts",
        )?;
        self.ensure_lane(&request.lane_id)?;
        ensure_root("privacy subject commitment", &request.subject_commitment)?;
        ensure_root("anonymity set root", &request.anonymity_set_root)?;
        ensure_root("privacy budget root", &request.privacy_budget_root)?;
        ensure_positive("observed_set_size", request.observed_set_size)?;
        ensure_positive("target_set_size", request.target_set_size)?;

        let status = if request.observed_set_size >= request.target_set_size
            && request.observed_set_size >= self.config.min_privacy_set_size
        {
            PrivacyStatus::Satisfied
        } else if request.observed_set_size < self.config.min_privacy_set_size {
            PrivacyStatus::Deficient
        } else {
            PrivacyStatus::Accruing
        };
        let account_id = deterministic_id(
            "privacy-account",
            self.counters.privacy_accounts_updated + 1,
            &request.public_record(),
        );
        self.privacy_accounts.insert(
            account_id.clone(),
            PrivacyAccountingRecord {
                account_id: account_id.clone(),
                request: request.clone(),
                status,
                status_height: self.current_height,
            },
        );
        if status == PrivacyStatus::Deficient {
            let slash_request = SlashRequest {
                slash_kind: SlashKind::PrivacySetDeficiency,
                accused_commitment: request.subject_commitment,
                evidence_root: payload_root(
                    "PRIVATE-PARALLEL-INTENT-PRIVACY-DEFICIENCY-EVIDENCE",
                    &request.public_record(),
                ),
                related_intent_id: None,
                related_witness_id: None,
                related_batch_id: None,
                reporter_commitment: deterministic_root("reporter", "privacy-accounting", 0),
                slash_bps: SlashKind::PrivacySetDeficiency.default_bps(),
                reported_at_height: self.current_height,
            };
            self.record_slash(slash_request)?;
        }
        self.counters.privacy_accounts_updated += 1;
        Ok(account_id)
    }

    pub fn record_slash(&mut self, mut request: SlashRequest) -> Result<String> {
        self.ensure_capacity(self.slashes.len(), self.config.max_slashes, "slashes")?;
        ensure_root("slash accused commitment", &request.accused_commitment)?;
        ensure_root("slash evidence root", &request.evidence_root)?;
        ensure_root("slash reporter commitment", &request.reporter_commitment)?;
        if request.slash_bps == 0 {
            request.slash_bps = request.slash_kind.default_bps();
        }
        ensure_bps("slash_bps", request.slash_bps)?;
        let slash_id = deterministic_id(
            "slash",
            self.counters.slashes_recorded + 1,
            &request.public_record(),
        );
        self.slashes.insert(
            slash_id.clone(),
            SlashRecord {
                slash_id: slash_id.clone(),
                request,
                adjudicated: false,
                applied_height: None,
            },
        );
        self.counters.slashes_recorded += 1;
        Ok(slash_id)
    }

    pub fn apply_slash(&mut self, slash_id: &str) -> Result<()> {
        let slash = self
            .slashes
            .get_mut(slash_id)
            .ok_or_else(|| "private parallel intent slash not found".to_string())?;
        slash.adjudicated = true;
        slash.applied_height = Some(self.current_height);
        if let Some(intent_id) = &slash.request.related_intent_id {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Slashed;
                intent.status_height = self.current_height;
            }
        }
        if let Some(witness_id) = &slash.request.related_witness_id {
            if let Some(witness) = self.witnesses.get_mut(witness_id) {
                witness.status = WitnessStatus::Slashed;
                witness.status_height = self.current_height;
            }
        }
        if let Some(batch_id) = &slash.request.related_batch_id {
            if let Some(batch) = self.batches.get_mut(batch_id) {
                batch.status = BatchStatus::Slashed;
                batch.status_height = self.current_height;
            }
        }
        Ok(())
    }

    pub fn finalize_receipts(&mut self) -> usize {
        let mut finalized = 0usize;
        for receipt in self.receipts.values_mut() {
            if matches!(
                receipt.status,
                ReceiptStatus::Posted | ReceiptStatus::RebateReserved
            ) && receipt.finalizes_at_height <= self.current_height
            {
                receipt.status = ReceiptStatus::Finalized;
                finalized += 1;
            }
        }
        for batch in self.batches.values_mut() {
            if batch.status == BatchStatus::Receipted {
                if let Some(receipt_id) = &batch.receipt_id {
                    if self
                        .receipts
                        .get(receipt_id)
                        .map(|receipt| receipt.status == ReceiptStatus::Finalized)
                        .unwrap_or(false)
                    {
                        batch.status = BatchStatus::Finalized;
                        batch.status_height = self.current_height;
                    }
                }
            }
        }
        finalized
    }

    pub fn roots(&self) -> Roots {
        let lane_root = map_root(
            "PRIVATE-PARALLEL-INTENT-LANES",
            &self.lanes,
            PrivateLaneRecord::public_record,
        );
        let intent_root = map_root(
            "PRIVATE-PARALLEL-INTENT-SEALED-INTENTS",
            &self.intents,
            SealedIntentRecord::public_record,
        );
        let witness_root = map_root(
            "PRIVATE-PARALLEL-INTENT-WITNESSES",
            &self.witnesses,
            WitnessCommitmentRecord::public_record,
        );
        let preauth_root = map_root(
            "PRIVATE-PARALLEL-INTENT-PREAUTHS",
            &self.preauthorizations,
            PqPreauthorizationRecord::public_record,
        );
        let batch_root = map_root(
            "PRIVATE-PARALLEL-INTENT-BATCHES",
            &self.batches,
            ParallelBatchRecord::public_record,
        );
        let receipt_root = map_root(
            "PRIVATE-PARALLEL-INTENT-RECEIPTS",
            &self.receipts,
            ExecutionReceiptRecord::public_record,
        );
        let rebate_root = map_root(
            "PRIVATE-PARALLEL-INTENT-REBATES",
            &self.rebates,
            LowFeeRebateRecord::public_record,
        );
        let privacy_account_root = map_root(
            "PRIVATE-PARALLEL-INTENT-PRIVACY-ACCOUNTS",
            &self.privacy_accounts,
            PrivacyAccountingRecord::public_record,
        );
        let slash_root = map_root(
            "PRIVATE-PARALLEL-INTENT-SLASHES",
            &self.slashes,
            SlashRecord::public_record,
        );
        let operator_root = set_root(
            "PRIVATE-PARALLEL-INTENT-LANE-OPERATORS",
            &self.lane_operators,
        );
        let state_root = state_root_from_record(&self.public_record_without_state_root_with_roots(
            &lane_root,
            &intent_root,
            &witness_root,
            &preauth_root,
            &batch_root,
            &receipt_root,
            &rebate_root,
            &privacy_account_root,
            &slash_root,
            &operator_root,
        ));
        Roots {
            lane_root,
            intent_root,
            witness_root,
            preauth_root,
            batch_root,
            receipt_root,
            rebate_root,
            privacy_account_root,
            slash_root,
            operator_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots_without_state_root();
        self.public_record_without_state_root_with_roots(
            &roots.0, &roots.1, &roots.2, &roots.3, &roots.4, &roots.5, &roots.6, &roots.7,
            &roots.8, &roots.9,
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root_with_roots(
            &roots.lane_root,
            &roots.intent_root,
            &roots.witness_root,
            &roots.preauth_root,
            &roots.batch_root,
            &roots.receipt_root,
            &roots.rebate_root,
            &roots.privacy_account_root,
            &roots.slash_root,
            &roots.operator_root,
        );
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(roots.state_root));
            object.insert("roots".to_string(), roots.public_record());
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            return Err(format!(
                "private parallel intent runtime {label} capacity exceeded"
            ));
        }
        Ok(())
    }

    fn ensure_lane(&self, lane_id: &str) -> Result<()> {
        ensure_non_empty("lane_id", lane_id)?;
        if !self.lanes.contains_key(lane_id) {
            return Err("private execution lane not found".to_string());
        }
        Ok(())
    }

    fn ensure_intent_witnesses_satisfied(&self, intent_id: &str) -> Result<()> {
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| "sealed private intent not found".to_string())?;
        for witness_id in &intent.witness_ids {
            let witness = self
                .witnesses
                .get(witness_id)
                .ok_or_else(|| "private intent witness missing".to_string())?;
            if witness.status != WitnessStatus::Satisfied
                && witness.status != WitnessStatus::BypassedByProof
            {
                return Err("sealed private intent has unsatisfied witnesses".to_string());
            }
        }
        Ok(())
    }

    fn refresh_intent_readiness(&mut self, intent_id: &str) -> Result<()> {
        let ready = {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| "sealed private intent not found".to_string())?;
            intent.preauth_id.is_some()
                && !intent.witness_ids.is_empty()
                && intent.witness_ids.iter().all(|witness_id| {
                    self.witnesses
                        .get(witness_id)
                        .map(|witness| {
                            witness.status == WitnessStatus::Satisfied
                                || witness.status == WitnessStatus::BypassedByProof
                        })
                        .unwrap_or(false)
                })
        };
        if ready {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Ready;
                intent.status_height = self.current_height;
            }
        }
        Ok(())
    }

    fn find_conflicting_witness(&self, request: &WitnessCommitmentRequest) -> Option<String> {
        if request.witness_kind.conflict_scope() == "advisory" {
            return None;
        }
        self.witnesses
            .iter()
            .find(|(_, witness)| {
                witness.request.intent_id != request.intent_id
                    && witness.request.dependency_key_root == request.dependency_key_root
                    && witness.request.witness_kind.conflict_scope()
                        == request.witness_kind.conflict_scope()
                    && witness.request.conflict_salt_root != request.conflict_salt_root
                    && matches!(
                        witness.status,
                        WitnessStatus::Open
                            | WitnessStatus::Satisfied
                            | WitnessStatus::BypassedByProof
                    )
            })
            .map(|(witness_id, _)| witness_id.clone())
    }

    fn expire_stale_records(&mut self) {
        for intent in self.intents.values_mut() {
            if matches!(
                intent.status,
                IntentStatus::Sealed
                    | IntentStatus::WitnessLocked
                    | IntentStatus::PqPreauthorized
                    | IntentStatus::Ready
            ) && intent.request.expiry_height <= self.current_height
            {
                intent.status = IntentStatus::Expired;
                intent.status_height = self.current_height;
            }
        }
        for witness in self.witnesses.values_mut() {
            if matches!(
                witness.status,
                WitnessStatus::Open | WitnessStatus::Satisfied
            ) && witness.request.expires_at_height <= self.current_height
            {
                witness.status = WitnessStatus::Expired;
                witness.status_height = self.current_height;
            }
        }
        for preauth in self.preauthorizations.values_mut() {
            if matches!(
                preauth.status,
                PreauthStatus::Pending | PreauthStatus::Verified | PreauthStatus::BoundToBatch
            ) && preauth.request.expires_at_height <= self.current_height
            {
                preauth.status = PreauthStatus::Expired;
                preauth.status_height = self.current_height;
            }
        }
        let mut stale_batches = Vec::new();
        for (batch_id, batch) in self.batches.iter_mut() {
            if matches!(
                batch.status,
                BatchStatus::Proposed | BatchStatus::WitnessChecked | BatchStatus::Executing
            ) && batch.request.expires_at_height <= self.current_height
            {
                batch.status = BatchStatus::Expired;
                batch.status_height = self.current_height;
                stale_batches.push(batch_id.clone());
            }
        }
        for batch_id in stale_batches {
            let evidence_root = payload_root(
                "PRIVATE-PARALLEL-INTENT-STALE-BATCH-EVIDENCE",
                &json!({ "batch_id": batch_id, "height": self.current_height }),
            );
            let request = SlashRequest {
                slash_kind: SlashKind::StaleExecution,
                accused_commitment: deterministic_root("batch", &batch_id, self.current_height),
                evidence_root,
                related_intent_id: None,
                related_witness_id: None,
                related_batch_id: Some(batch_id),
                reporter_commitment: deterministic_root("reporter", "stale-execution", 0),
                slash_bps: self.config.stale_execution_slash_bps,
                reported_at_height: self.current_height,
            };
            let _ = self.record_slash(request);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn public_record_without_state_root_with_roots(
        &self,
        lane_root: &str,
        intent_root: &str,
        witness_root: &str,
        preauth_root: &str,
        batch_root: &str,
        receipt_root: &str,
        rebate_root: &str,
        privacy_account_root: &str,
        slash_root: &str,
        operator_root: &str,
    ) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "counters": self.counters.public_record(),
            "lane_root": lane_root,
            "intent_root": intent_root,
            "witness_root": witness_root,
            "preauth_root": preauth_root,
            "batch_root": batch_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "privacy_account_root": privacy_account_root,
            "slash_root": slash_root,
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
    ) {
        (
            map_root(
                "PRIVATE-PARALLEL-INTENT-LANES",
                &self.lanes,
                PrivateLaneRecord::public_record,
            ),
            map_root(
                "PRIVATE-PARALLEL-INTENT-SEALED-INTENTS",
                &self.intents,
                SealedIntentRecord::public_record,
            ),
            map_root(
                "PRIVATE-PARALLEL-INTENT-WITNESSES",
                &self.witnesses,
                WitnessCommitmentRecord::public_record,
            ),
            map_root(
                "PRIVATE-PARALLEL-INTENT-PREAUTHS",
                &self.preauthorizations,
                PqPreauthorizationRecord::public_record,
            ),
            map_root(
                "PRIVATE-PARALLEL-INTENT-BATCHES",
                &self.batches,
                ParallelBatchRecord::public_record,
            ),
            map_root(
                "PRIVATE-PARALLEL-INTENT-RECEIPTS",
                &self.receipts,
                ExecutionReceiptRecord::public_record,
            ),
            map_root(
                "PRIVATE-PARALLEL-INTENT-REBATES",
                &self.rebates,
                LowFeeRebateRecord::public_record,
            ),
            map_root(
                "PRIVATE-PARALLEL-INTENT-PRIVACY-ACCOUNTS",
                &self.privacy_accounts,
                PrivacyAccountingRecord::public_record,
            ),
            map_root(
                "PRIVATE-PARALLEL-INTENT-SLASHES",
                &self.slashes,
                SlashRecord::public_record,
            ),
            set_root(
                "PRIVATE-PARALLEL-INTENT-LANE-OPERATORS",
                &self.lane_operators,
            ),
        )
    }
}

pub fn deterministic_root(label: &str, subject: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PARALLEL-INTENT-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn deterministic_id(label: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PARALLEL-INTENT-DETERMINISTIC-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
            HashPart::Json(record),
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

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("PRIVATE-L2-FAST-PRIVATE-PARALLEL-INTENT-STATE-ROOT", record)
}

fn public_records_from_map<T, F>(map: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(public_record).collect()
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    public_record_root(domain, &public_records_from_map(map, public_record))
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|item| Value::String(item.clone()))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
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

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} cannot exceed 100%"));
    }
    Ok(())
}
