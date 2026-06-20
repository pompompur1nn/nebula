use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeCrossContractCallMarketRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-cross-contract-call-market-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SEALED_CALL_SCHEME: &str =
    "ml-kem-1024+zk-sealed-cross-contract-call-intent-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SOLVER_QUOTE_SCHEME: &str =
    "roots-only-low-fee-cross-contract-solver-quote-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEPENDENCY_PROOF_SCHEME: &str =
    "zk-cross-contract-call-dependency-proof-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_BUNDLE_SCHEME: &str =
    "low-fee-private-cross-contract-call-bundle-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_PQ_SOLVER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256s-solver-attestation-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SETTLEMENT_SCHEME: &str =
    "zk-pq-private-cross-contract-call-settlement-batch-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_RECEIPT_SCHEME: &str =
    "roots-only-private-cross-contract-call-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEVNET_HEIGHT: u64 = 428_000;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 30;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 14;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_INTENTS: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_QUOTES: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_DEPENDENCY_PROOFS:
    usize = 2_097_152;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_BUNDLE_CALLS: usize =
    1_024;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    512;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_BUNDLE_PRIVACY_SET_SIZE:
    u64 = 4_096;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS: u64 =
    22;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_TARGET_LATENCY_MS: u64 =
    450;
pub const PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossContractCallKind {
    ConfidentialInvoke,
    MultiCall,
    AtomicSwap,
    TokenMint,
    TokenBurn,
    TokenTransfer,
    AmmSwap,
    LendingSupply,
    LendingBorrow,
    VaultDeposit,
    VaultWithdraw,
    OracleReadThenCall,
    Callback,
    SettlementHook,
}

impl CrossContractCallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialInvoke => "confidential_invoke",
            Self::MultiCall => "multi_call",
            Self::AtomicSwap => "atomic_swap",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::TokenTransfer => "token_transfer",
            Self::AmmSwap => "amm_swap",
            Self::LendingSupply => "lending_supply",
            Self::LendingBorrow => "lending_borrow",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultWithdraw => "vault_withdraw",
            Self::OracleReadThenCall => "oracle_read_then_call",
            Self::Callback => "callback",
            Self::SettlementHook => "settlement_hook",
        }
    }

    pub fn composability_weight(self) -> u64 {
        match self {
            Self::SettlementHook => 9_700,
            Self::AtomicSwap | Self::AmmSwap => 9_100,
            Self::LendingBorrow | Self::VaultWithdraw => 8_500,
            Self::MultiCall | Self::OracleReadThenCall => 8_000,
            Self::ConfidentialInvoke | Self::Callback => 7_200,
            Self::TokenMint | Self::TokenBurn | Self::TokenTransfer => 6_800,
            Self::LendingSupply | Self::VaultDeposit => 6_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    ReadAfterWrite,
    WriteAfterRead,
    WriteAfterWrite,
    NullifierOrdering,
    AssetConservation,
    OracleFreshness,
    CallbackOrdering,
    SolverRouteOrdering,
    FeeSponsorPrepay,
    SettlementBarrier,
}

impl DependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadAfterWrite => "read_after_write",
            Self::WriteAfterRead => "write_after_read",
            Self::WriteAfterWrite => "write_after_write",
            Self::NullifierOrdering => "nullifier_ordering",
            Self::AssetConservation => "asset_conservation",
            Self::OracleFreshness => "oracle_freshness",
            Self::CallbackOrdering => "callback_ordering",
            Self::SolverRouteOrdering => "solver_route_ordering",
            Self::FeeSponsorPrepay => "fee_sponsor_prepay",
            Self::SettlementBarrier => "settlement_barrier",
        }
    }

    pub fn strict(self) -> bool {
        matches!(
            self,
            Self::WriteAfterWrite
                | Self::NullifierOrdering
                | Self::AssetConservation
                | Self::SolverRouteOrdering
                | Self::SettlementBarrier
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    DependencyProved,
    Quoted,
    Bundled,
    Settled,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::DependencyProved => "dependency_proved",
            Self::Quoted => "quoted",
            Self::Bundled => "bundled",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn marketable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::DependencyProved | Self::Quoted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Selected,
    Settled,
    Rejected,
    Expired,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Built,
    ExecutionReady,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::ExecutionReady => "execution_ready",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub sealed_call_scheme: String,
    pub solver_quote_scheme: String,
    pub dependency_proof_scheme: String,
    pub bundle_scheme: String,
    pub pq_solver_attestation_scheme: String,
    pub settlement_scheme: String,
    pub receipt_scheme: String,
    pub intent_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub max_intents: usize,
    pub max_quotes: usize,
    pub max_dependency_proofs: usize,
    pub max_bundle_calls: usize,
    pub min_privacy_set_size: u64,
    pub bundle_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub target_latency_ms: u64,
    pub require_pq_solver_attestations: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_HASH_SUITE
                .to_string(),
            sealed_call_scheme:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SEALED_CALL_SCHEME
                    .to_string(),
            solver_quote_scheme:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SOLVER_QUOTE_SCHEME
                    .to_string(),
            dependency_proof_scheme:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEPENDENCY_PROOF_SCHEME
                    .to_string(),
            bundle_scheme: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_BUNDLE_SCHEME
                .to_string(),
            pq_solver_attestation_scheme:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_PQ_SOLVER_ATTESTATION_SCHEME
                    .to_string(),
            settlement_scheme:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SETTLEMENT_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            intent_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            quote_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            bundle_ttl_blocks:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_BUNDLE_TTL_BLOCKS,
            max_intents: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_INTENTS,
            max_quotes: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_QUOTES,
            max_dependency_proofs:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_DEPENDENCY_PROOFS,
            max_bundle_calls:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_BUNDLE_CALLS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            bundle_privacy_set_size:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_BUNDLE_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS,
            target_latency_ms:
                PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_TARGET_LATENCY_MS,
            require_pq_solver_attestations: true,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<()> {
        require_non_empty(&self.protocol_version, "protocol version")?;
        require_non_empty(&self.chain_id, "chain id")?;
        if self.chain_id != CHAIN_ID {
            return Err("cross-contract call market chain id mismatch".to_string());
        }
        if self.schema_version
            != PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SCHEMA_VERSION
        {
            return Err("cross-contract call market schema version mismatch".to_string());
        }
        if self.intent_ttl_blocks == 0
            || self.quote_ttl_blocks == 0
            || self.bundle_ttl_blocks == 0
            || self.max_intents == 0
            || self.max_quotes == 0
            || self.max_dependency_proofs == 0
            || self.max_bundle_calls == 0
        {
            return Err(
                "cross-contract call market windows and capacities must be positive".to_string(),
            );
        }
        if self.min_privacy_set_size == 0
            || self.bundle_privacy_set_size < self.min_privacy_set_size
            || self.min_pq_security_bits < 192
        {
            return Err("cross-contract call market privacy or PQ floors are invalid".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_MAX_BPS
            || self.max_solver_fee_bps
                > PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_MAX_BPS
        {
            return Err("cross-contract call market fee caps exceed bps denominator".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_call_market_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "sealed_call_scheme": self.sealed_call_scheme,
            "solver_quote_scheme": self.solver_quote_scheme,
            "dependency_proof_scheme": self.dependency_proof_scheme,
            "bundle_scheme": self.bundle_scheme,
            "pq_solver_attestation_scheme": self.pq_solver_attestation_scheme,
            "settlement_scheme": self.settlement_scheme,
            "receipt_scheme": self.receipt_scheme,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "max_intents": self.max_intents,
            "max_quotes": self.max_quotes,
            "max_dependency_proofs": self.max_dependency_proofs,
            "max_bundle_calls": self.max_bundle_calls,
            "min_privacy_set_size": self.min_privacy_set_size,
            "bundle_privacy_set_size": self.bundle_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "target_latency_ms": self.target_latency_ms,
            "require_pq_solver_attestations": self.require_pq_solver_attestations,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_intent_nonce: u64,
    pub next_quote_nonce: u64,
    pub next_dependency_proof_nonce: u64,
    pub next_attestation_nonce: u64,
    pub next_bundle_nonce: u64,
    pub next_settlement_nonce: u64,
    pub next_receipt_nonce: u64,
    pub intents_submitted: u64,
    pub quotes_posted: u64,
    pub dependency_proofs_recorded: u64,
    pub pq_solver_attestations_recorded: u64,
    pub bundles_built: u64,
    pub settlement_batches_published: u64,
    pub receipts_published: u64,
    pub intents_settled: u64,
    pub total_fee_bps_committed: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_call_market_counters",
            "next_intent_nonce": self.next_intent_nonce,
            "next_quote_nonce": self.next_quote_nonce,
            "next_dependency_proof_nonce": self.next_dependency_proof_nonce,
            "next_attestation_nonce": self.next_attestation_nonce,
            "next_bundle_nonce": self.next_bundle_nonce,
            "next_settlement_nonce": self.next_settlement_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "intents_submitted": self.intents_submitted,
            "quotes_posted": self.quotes_posted,
            "dependency_proofs_recorded": self.dependency_proofs_recorded,
            "pq_solver_attestations_recorded": self.pq_solver_attestations_recorded,
            "bundles_built": self.bundles_built,
            "settlement_batches_published": self.settlement_batches_published,
            "receipts_published": self.receipts_published,
            "intents_settled": self.intents_settled,
            "total_fee_bps_committed": self.total_fee_bps_committed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPrivateCrossContractCallIntentRequest {
    pub call_kind: CrossContractCallKind,
    pub account_commitment: String,
    pub contract_call_graph_root: String,
    pub sealed_calldata_root: String,
    pub encrypted_witness_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub asset_flow_root: String,
    pub callback_root: String,
    pub nullifier_root: String,
    pub fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub target_latency_ms: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitPrivateCrossContractCallIntentRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<()> {
        require_root(&self.account_commitment, "account commitment")?;
        require_root(&self.contract_call_graph_root, "contract call graph root")?;
        require_root(&self.sealed_calldata_root, "sealed calldata root")?;
        require_root(&self.encrypted_witness_root, "encrypted witness root")?;
        require_root(&self.read_set_root, "read set root")?;
        require_root(&self.write_set_root, "write set root")?;
        require_root(&self.asset_flow_root, "asset flow root")?;
        require_root(&self.callback_root, "callback root")?;
        require_root(&self.nullifier_root, "nullifier root")?;
        require_root(&self.fee_sponsor_root, "fee sponsor root")?;
        require_root(&self.pq_authorization_root, "PQ authorization root")?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("cross-contract call intent fee cap exceeds low-fee policy".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("cross-contract call intent privacy set below policy".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("cross-contract call intent PQ security below policy".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height
            || self.expires_at_height - self.submitted_at_height > config.intent_ttl_blocks
        {
            return Err("cross-contract call intent ttl is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "call_kind": self.call_kind.as_str(),
            "account_commitment": self.account_commitment,
            "contract_call_graph_root": self.contract_call_graph_root,
            "sealed_calldata_root": self.sealed_calldata_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "asset_flow_root": self.asset_flow_root,
            "callback_root": self.callback_root,
            "nullifier_root": self.nullifier_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "target_latency_ms": self.target_latency_ms,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostSolverQuoteRequest {
    pub intent_ids: Vec<String>,
    pub solver_commitment: String,
    pub route_commitment_root: String,
    pub execution_plan_root: String,
    pub expected_output_root: String,
    pub fee_quote_bps: u64,
    pub latency_ms: u64,
    pub privacy_set_size: u64,
    pub pq_quote_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl PostSolverQuoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_ids": self.intent_ids,
            "solver_commitment": self.solver_commitment,
            "route_commitment_root": self.route_commitment_root,
            "execution_plan_root": self.execution_plan_root,
            "expected_output_root": self.expected_output_root,
            "fee_quote_bps": self.fee_quote_bps,
            "latency_ms": self.latency_ms,
            "privacy_set_size": self.privacy_set_size,
            "pq_quote_root": self.pq_quote_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordDependencyProofRequest {
    pub predecessor_intent_id: String,
    pub successor_intent_id: String,
    pub dependency_kind: DependencyKind,
    pub resource_commitment: String,
    pub dependency_proof_root: String,
    pub witness_root: String,
    pub pq_authorization_root: String,
    pub proved_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordPqSolverAttestationRequest {
    pub quote_id: String,
    pub solver_commitment: String,
    pub attestation_root: String,
    pub signature_bundle_root: String,
    pub key_epoch_root: String,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildLowFeeCallBundleRequest {
    pub intent_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub dependency_proof_ids: Vec<String>,
    pub pq_attestation_ids: Vec<String>,
    pub aggregate_call_graph_root: String,
    pub aggregate_dependency_root: String,
    pub aggregate_witness_root: String,
    pub aggregate_fee_root: String,
    pub aggregate_pq_attestation_root: String,
    pub bundle_execution_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub built_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSettlementBatchRequest {
    pub bundle_id: String,
    pub recursive_proof_root: String,
    pub settlement_tx_root: String,
    pub public_input_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub output_commitment_root: String,
    pub consumed_nullifier_root: String,
    pub fee_settlement_root: String,
    pub pq_transcript_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishReceiptRequest {
    pub settlement_batch_id: String,
    pub finalized_at_height: Option<u64>,
    pub receipt_note_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossContractCallIntentRecord {
    pub intent_id: String,
    pub request: SubmitPrivateCrossContractCallIntentRequest,
    pub status: IntentStatus,
    pub selected_quote_id: Option<String>,
    pub bundle_id: Option<String>,
}

impl PrivateCrossContractCallIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_call_intent",
            "intent_id": self.intent_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "selected_quote_id": self.selected_quote_id,
            "bundle_id": self.bundle_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverQuoteRecord {
    pub quote_id: String,
    pub request: PostSolverQuoteRequest,
    pub score: u128,
    pub status: QuoteStatus,
    pub pq_attestation_id: Option<String>,
}

impl SolverQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_solver_quote",
            "quote_id": self.quote_id,
            "request": self.request.public_record(),
            "score": self.score.to_string(),
            "status": self.status.as_str(),
            "pq_attestation_id": self.pq_attestation_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyProofRecord {
    pub dependency_proof_id: String,
    pub request: RecordDependencyProofRequest,
    pub strict_ordering: bool,
}

impl DependencyProofRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_dependency_proof",
            "dependency_proof_id": self.dependency_proof_id,
            "predecessor_intent_id": self.request.predecessor_intent_id,
            "successor_intent_id": self.request.successor_intent_id,
            "dependency_kind": self.request.dependency_kind.as_str(),
            "resource_commitment": self.request.resource_commitment,
            "dependency_proof_root": self.request.dependency_proof_root,
            "witness_root": self.request.witness_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "strict_ordering": self.strict_ordering,
            "proved_at_height": self.request.proved_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSolverAttestationRecord {
    pub attestation_id: String,
    pub request: RecordPqSolverAttestationRequest,
}

impl PqSolverAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_pq_solver_attestation",
            "attestation_id": self.attestation_id,
            "quote_id": self.request.quote_id,
            "solver_commitment": self.request.solver_commitment,
            "attestation_root": self.request.attestation_root,
            "signature_bundle_root": self.request.signature_bundle_root,
            "key_epoch_root": self.request.key_epoch_root,
            "pq_security_bits": self.request.pq_security_bits,
            "attested_at_height": self.request.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeCallBundleRecord {
    pub bundle_id: String,
    pub request: BuildLowFeeCallBundleRequest,
    pub selected_quote_id: String,
    pub settlement_deadline_height: u64,
    pub status: BundleStatus,
    pub settlement_batch_id: Option<String>,
}

impl LowFeeCallBundleRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_call_bundle",
            "bundle_id": self.bundle_id,
            "request": self.request,
            "selected_quote_id": self.selected_quote_id,
            "settlement_deadline_height": self.settlement_deadline_height,
            "status": self.status.as_str(),
            "settlement_batch_id": self.settlement_batch_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatchRecord {
    pub settlement_batch_id: String,
    pub request: PublishSettlementBatchRequest,
    pub receipt_id: Option<String>,
}

impl SettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_settlement_batch",
            "settlement_batch_id": self.settlement_batch_id,
            "request": self.request,
            "receipt_id": self.receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub settlement_batch_id: String,
    pub status: ReceiptStatus,
    pub state_root_after: String,
    pub receipt_note_root: String,
    pub published_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_receipt",
            "receipt_id": self.receipt_id,
            "settlement_batch_id": self.settlement_batch_id,
            "status": self.status.as_str(),
            "state_root_after": self.state_root_after,
            "receipt_note_root": self.receipt_note_root,
            "published_at_height": self.published_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub intent_root: String,
    pub quote_root: String,
    pub dependency_proof_root: String,
    pub pq_attestation_root: String,
    pub bundle_root: String,
    pub settlement_batch_root: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "intent_root": self.intent_root,
            "quote_root": self.quote_root,
            "dependency_proof_root": self.dependency_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "bundle_root": self.bundle_root,
            "settlement_batch_root": self.settlement_batch_root,
            "receipt_root": self.receipt_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub intents: BTreeMap<String, PrivateCrossContractCallIntentRecord>,
    pub quotes: BTreeMap<String, SolverQuoteRecord>,
    pub dependency_proofs: BTreeMap<String, DependencyProofRecord>,
    pub pq_attestations: BTreeMap<String, PqSolverAttestationRecord>,
    pub bundles: BTreeMap<String, LowFeeCallBundleRecord>,
    pub settlement_batches: BTreeMap<String, SettlementBatchRecord>,
    pub receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

pub type Runtime = State;

impl State {
    pub fn devnet() -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEVNET_HEIGHT,
            runtime_root: private_l2_low_fee_cross_contract_call_market_payload_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-DEVNET-RUNTIME",
                &json!({ "chain_id": CHAIN_ID }),
            ),
            intents: BTreeMap::new(),
            quotes: BTreeMap::new(),
            dependency_proofs: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            bundles: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn submit_private_cross_contract_call_intent(
        &mut self,
        request: SubmitPrivateCrossContractCallIntentRequest,
    ) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<PrivateCrossContractCallIntentRecord>
    {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.intents.len() >= self.config.max_intents {
            return Err("cross-contract call intent lane is full".to_string());
        }
        if self.consumed_nullifiers.contains(&request.nullifier_root) {
            self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
            return Err("cross-contract call intent nullifier already consumed".to_string());
        }
        let intent_id =
            private_cross_contract_call_intent_id(&request, self.counters.next_intent_nonce);
        let record = PrivateCrossContractCallIntentRecord {
            intent_id: intent_id.clone(),
            request,
            status: IntentStatus::Submitted,
            selected_quote_id: None,
            bundle_id: None,
        };
        self.current_height = self.current_height.max(record.request.submitted_at_height);
        self.counters.next_intent_nonce = self.counters.next_intent_nonce.saturating_add(1);
        self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
        self.publish_public_record("intent", &intent_id, record.public_record());
        self.intents.insert(intent_id, record.clone());
        Ok(record)
    }

    pub fn post_solver_quote(
        &mut self,
        request: PostSolverQuoteRequest,
    ) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<SolverQuoteRecord> {
        self.config.validate()?;
        ensure_unique(&request.intent_ids, "quote intent id")?;
        if self.quotes.len() >= self.config.max_quotes {
            return Err("cross-contract call quote lane is full".to_string());
        }
        if request.intent_ids.is_empty() {
            return Err("solver quote must cover at least one intent".to_string());
        }
        require_root(&request.solver_commitment, "solver commitment")?;
        require_root(&request.route_commitment_root, "route commitment root")?;
        require_root(&request.execution_plan_root, "execution plan root")?;
        require_root(&request.expected_output_root, "expected output root")?;
        require_root(&request.pq_quote_root, "PQ quote root")?;
        if request.fee_quote_bps > self.config.max_solver_fee_bps {
            return Err("solver quote fee exceeds low-fee cap".to_string());
        }
        if request.expires_at_height <= request.posted_at_height
            || request.expires_at_height - request.posted_at_height > self.config.quote_ttl_blocks
        {
            return Err("solver quote ttl is invalid".to_string());
        }
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("unknown quoted intent: {intent_id}"))?;
            if !intent.status.marketable() {
                return Err(format!("intent is not quoteable: {intent_id}"));
            }
            if request.privacy_set_size < intent.request.privacy_set_size {
                return Err("solver quote privacy set cannot be below covered intent".to_string());
            }
        }
        let score = solver_quote_score(&request);
        let quote_id = solver_quote_id(&request, score, self.counters.next_quote_nonce);
        let record = SolverQuoteRecord {
            quote_id: quote_id.clone(),
            request,
            score,
            status: QuoteStatus::Posted,
            pq_attestation_id: None,
        };
        for intent_id in &record.request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Quoted;
            }
        }
        self.current_height = self.current_height.max(record.request.posted_at_height);
        self.counters.next_quote_nonce = self.counters.next_quote_nonce.saturating_add(1);
        self.counters.quotes_posted = self.counters.quotes_posted.saturating_add(1);
        self.counters.total_fee_bps_committed = self
            .counters
            .total_fee_bps_committed
            .saturating_add(record.request.fee_quote_bps);
        self.refresh_intent_records(&record.request.intent_ids);
        self.publish_public_record("solver_quote", &quote_id, record.public_record());
        self.quotes.insert(quote_id, record.clone());
        Ok(record)
    }

    pub fn record_dependency_proof(
        &mut self,
        request: RecordDependencyProofRequest,
    ) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<DependencyProofRecord> {
        self.config.validate()?;
        require_root(&request.resource_commitment, "resource commitment")?;
        require_root(&request.dependency_proof_root, "dependency proof root")?;
        require_root(&request.witness_root, "dependency witness root")?;
        require_root(
            &request.pq_authorization_root,
            "dependency PQ authorization root",
        )?;
        if self.dependency_proofs.len() >= self.config.max_dependency_proofs {
            return Err("cross-contract call dependency proof lane is full".to_string());
        }
        if request.predecessor_intent_id == request.successor_intent_id {
            return Err("dependency proof cannot self-reference".to_string());
        }
        for intent_id in [&request.predecessor_intent_id, &request.successor_intent_id] {
            if !self.intents.contains_key(intent_id) {
                return Err(format!(
                    "dependency proof references unknown intent: {intent_id}"
                ));
            }
        }
        let strict_ordering = request.dependency_kind.strict();
        let record = DependencyProofRecord {
            dependency_proof_id: dependency_proof_id(
                &request,
                strict_ordering,
                self.counters.next_dependency_proof_nonce,
            ),
            request,
            strict_ordering,
        };
        if would_create_cycle(&self.dependency_proofs, &record) {
            return Err("dependency proof would create a cyclic call graph".to_string());
        }
        for intent_id in [
            &record.request.predecessor_intent_id,
            &record.request.successor_intent_id,
        ] {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::DependencyProved;
            }
        }
        self.current_height = self.current_height.max(record.request.proved_at_height);
        self.counters.next_dependency_proof_nonce =
            self.counters.next_dependency_proof_nonce.saturating_add(1);
        self.counters.dependency_proofs_recorded =
            self.counters.dependency_proofs_recorded.saturating_add(1);
        let proof_id = record.dependency_proof_id.clone();
        self.refresh_intent_records(&[
            record.request.predecessor_intent_id.clone(),
            record.request.successor_intent_id.clone(),
        ]);
        self.publish_public_record("dependency_proof", &proof_id, record.public_record());
        self.dependency_proofs.insert(proof_id, record.clone());
        Ok(record)
    }

    pub fn record_pq_solver_attestation(
        &mut self,
        request: RecordPqSolverAttestationRequest,
    ) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<PqSolverAttestationRecord> {
        self.config.validate()?;
        require_root(&request.solver_commitment, "solver commitment")?;
        require_root(&request.attestation_root, "attestation root")?;
        require_root(&request.signature_bundle_root, "signature bundle root")?;
        require_root(&request.key_epoch_root, "key epoch root")?;
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("solver attestation PQ security below policy".to_string());
        }
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| "solver attestation references unknown quote".to_string())?;
        if quote.request.solver_commitment != request.solver_commitment {
            return Err("solver attestation commitment does not match quote".to_string());
        }
        let attestation_id =
            pq_solver_attestation_id(&request, self.counters.next_attestation_nonce);
        quote.pq_attestation_id = Some(attestation_id.clone());
        let record = PqSolverAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
        };
        self.current_height = self.current_height.max(record.request.attested_at_height);
        self.counters.next_attestation_nonce =
            self.counters.next_attestation_nonce.saturating_add(1);
        self.counters.pq_solver_attestations_recorded = self
            .counters
            .pq_solver_attestations_recorded
            .saturating_add(1);
        self.publish_public_record(
            "pq_solver_attestation",
            &attestation_id,
            record.public_record(),
        );
        let quote_record = self
            .quotes
            .get(&record.request.quote_id)
            .map(|quote| (quote.quote_id.clone(), quote.public_record()));
        if let Some((quote_id, public_record)) = quote_record {
            self.publish_public_record("solver_quote", &quote_id, public_record);
        }
        self.pq_attestations.insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn build_low_fee_call_bundle(
        &mut self,
        request: BuildLowFeeCallBundleRequest,
    ) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<LowFeeCallBundleRecord> {
        self.config.validate()?;
        ensure_unique(&request.intent_ids, "bundle intent id")?;
        ensure_unique(&request.quote_ids, "bundle quote id")?;
        ensure_unique(&request.dependency_proof_ids, "bundle dependency proof id")?;
        ensure_unique(&request.pq_attestation_ids, "bundle PQ attestation id")?;
        if request.intent_ids.is_empty() || request.intent_ids.len() > self.config.max_bundle_calls
        {
            return Err("low-fee call bundle has invalid intent count".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("low-fee call bundle exceeds user fee cap".to_string());
        }
        if request.privacy_set_size < self.config.bundle_privacy_set_size {
            return Err("low-fee call bundle privacy set below batch target".to_string());
        }
        require_root(
            &request.aggregate_call_graph_root,
            "aggregate call graph root",
        )?;
        require_root(
            &request.aggregate_dependency_root,
            "aggregate dependency root",
        )?;
        require_root(&request.aggregate_witness_root, "aggregate witness root")?;
        require_root(&request.aggregate_fee_root, "aggregate fee root")?;
        require_root(
            &request.aggregate_pq_attestation_root,
            "aggregate PQ attestation root",
        )?;
        require_root(&request.bundle_execution_root, "bundle execution root")?;
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("unknown bundle intent: {intent_id}"))?;
            if !intent.status.marketable() {
                return Err(format!("intent is not bundleable: {intent_id}"));
            }
        }
        let quote_records = request
            .quote_ids
            .iter()
            .map(|quote_id| {
                self.quotes
                    .get(quote_id)
                    .ok_or_else(|| format!("unknown bundle quote: {quote_id}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let selected_quote = quote_records
            .iter()
            .filter(|quote| covers_all(&quote.request.intent_ids, &request.intent_ids))
            .max_by_key(|quote| quote.score)
            .ok_or_else(|| "no solver quote covers every bundle intent".to_string())?;
        if self.config.require_pq_solver_attestations {
            let attestation_id = selected_quote
                .pq_attestation_id
                .as_ref()
                .ok_or_else(|| "selected quote is missing PQ solver attestation".to_string())?;
            if !request.pq_attestation_ids.contains(attestation_id) {
                return Err("bundle does not include selected quote PQ attestation".to_string());
            }
        }
        for proof_id in &request.dependency_proof_ids {
            if !self.dependency_proofs.contains_key(proof_id) {
                return Err(format!("unknown dependency proof: {proof_id}"));
            }
        }
        for attestation_id in &request.pq_attestation_ids {
            if !self.pq_attestations.contains_key(attestation_id) {
                return Err(format!("unknown PQ solver attestation: {attestation_id}"));
            }
        }
        let selected_quote_id = selected_quote.quote_id.clone();
        let bundle_id = low_fee_call_bundle_id(
            &request,
            &selected_quote_id,
            self.counters.next_bundle_nonce,
        );
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Bundled;
                intent.selected_quote_id = Some(selected_quote_id.clone());
                intent.bundle_id = Some(bundle_id.clone());
            }
        }
        for quote_id in &request.quote_ids {
            if let Some(quote) = self.quotes.get_mut(quote_id) {
                quote.status = if *quote_id == selected_quote_id {
                    QuoteStatus::Selected
                } else {
                    QuoteStatus::Rejected
                };
            }
        }
        let record = LowFeeCallBundleRecord {
            bundle_id: bundle_id.clone(),
            settlement_deadline_height: request.built_at_height + self.config.bundle_ttl_blocks,
            request,
            selected_quote_id,
            status: BundleStatus::SettlementReady,
            settlement_batch_id: None,
        };
        self.current_height = self.current_height.max(record.request.built_at_height);
        self.counters.next_bundle_nonce = self.counters.next_bundle_nonce.saturating_add(1);
        self.counters.bundles_built = self.counters.bundles_built.saturating_add(1);
        self.refresh_intent_records(&record.request.intent_ids);
        self.refresh_quote_records(&record.request.quote_ids);
        self.publish_public_record("low_fee_call_bundle", &bundle_id, record.public_record());
        self.bundles.insert(bundle_id, record.clone());
        Ok(record)
    }

    pub fn publish_settlement_batch(
        &mut self,
        request: PublishSettlementBatchRequest,
    ) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<SettlementBatchRecord> {
        self.config.validate()?;
        require_root(&request.recursive_proof_root, "recursive proof root")?;
        require_root(&request.settlement_tx_root, "settlement tx root")?;
        require_root(&request.public_input_root, "public input root")?;
        require_root(&request.state_root_before, "state root before")?;
        require_root(&request.state_root_after, "state root after")?;
        require_root(&request.output_commitment_root, "output commitment root")?;
        require_root(&request.consumed_nullifier_root, "consumed nullifier root")?;
        require_root(&request.fee_settlement_root, "fee settlement root")?;
        require_root(&request.pq_transcript_root, "PQ transcript root")?;
        if request.settled_fee_bps > self.config.max_user_fee_bps {
            return Err("settlement batch fee exceeds low-fee cap".to_string());
        }
        let batch = self
            .bundles
            .get(&request.bundle_id)
            .cloned()
            .ok_or_else(|| "settlement references unknown call bundle".to_string())?;
        if !batch.status.can_settle() {
            return Err("call bundle is not settlement ready".to_string());
        }
        if request.settled_at_height > batch.settlement_deadline_height {
            return Err("call bundle settlement deadline elapsed".to_string());
        }
        if request.state_root_before != self.state_root() {
            return Err("settlement state root before does not match runtime".to_string());
        }
        let settlement_batch_id =
            settlement_batch_id(&request, self.counters.next_settlement_nonce);
        for intent_id in &batch.request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
                self.consumed_nullifiers
                    .insert(intent.request.nullifier_root.clone());
            }
        }
        if let Some(quote) = self.quotes.get_mut(&batch.selected_quote_id) {
            quote.status = QuoteStatus::Settled;
        }
        if let Some(bundle) = self.bundles.get_mut(&request.bundle_id) {
            bundle.status = BundleStatus::Settled;
            bundle.settlement_batch_id = Some(settlement_batch_id.clone());
        }
        self.runtime_root = request.state_root_after.clone();
        self.current_height = self.current_height.max(request.settled_at_height);
        self.counters.next_settlement_nonce = self.counters.next_settlement_nonce.saturating_add(1);
        self.counters.settlement_batches_published =
            self.counters.settlement_batches_published.saturating_add(1);
        self.counters.intents_settled = self
            .counters
            .intents_settled
            .saturating_add(batch.request.intent_ids.len() as u64);
        let record = SettlementBatchRecord {
            settlement_batch_id: settlement_batch_id.clone(),
            request,
            receipt_id: None,
        };
        self.refresh_intent_records(&batch.request.intent_ids);
        self.refresh_quote_records(&batch.request.quote_ids);
        self.publish_public_record(
            "settlement_batch",
            &settlement_batch_id,
            record.public_record(),
        );
        self.settlement_batches
            .insert(settlement_batch_id, record.clone());
        Ok(record)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishReceiptRequest,
    ) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<SettlementReceiptRecord> {
        self.config.validate()?;
        require_root(&request.receipt_note_root, "receipt note root")?;
        let settlement = self
            .settlement_batches
            .get(&request.settlement_batch_id)
            .cloned()
            .ok_or_else(|| "receipt references unknown settlement batch".to_string())?;
        let receipt_id = settlement_receipt_id(&request, self.counters.next_receipt_nonce);
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            settlement_batch_id: request.settlement_batch_id.clone(),
            status: if request.finalized_at_height.is_some() {
                ReceiptStatus::Finalized
            } else {
                ReceiptStatus::Published
            },
            state_root_after: settlement.request.state_root_after,
            receipt_note_root: request.receipt_note_root,
            published_at_height: self.current_height,
            finalized_at_height: request.finalized_at_height,
        };
        if let Some(settlement) = self
            .settlement_batches
            .get_mut(&request.settlement_batch_id)
        {
            settlement.receipt_id = Some(receipt_id.clone());
        }
        self.counters.next_receipt_nonce = self.counters.next_receipt_nonce.saturating_add(1);
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        self.publish_public_record("receipt", &receipt_id, record.public_record());
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: private_l2_low_fee_cross_contract_call_market_payload_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-CONFIG",
                &self.config.public_record(),
            ),
            intent_root: private_l2_low_fee_cross_contract_call_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-INTENT",
                self.intents
                    .values()
                    .map(PrivateCrossContractCallIntentRecord::public_record)
                    .collect(),
            ),
            quote_root: private_l2_low_fee_cross_contract_call_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-QUOTE",
                self.quotes
                    .values()
                    .map(SolverQuoteRecord::public_record)
                    .collect(),
            ),
            dependency_proof_root: private_l2_low_fee_cross_contract_call_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-DEPENDENCY",
                self.dependency_proofs
                    .values()
                    .map(DependencyProofRecord::public_record)
                    .collect(),
            ),
            pq_attestation_root: private_l2_low_fee_cross_contract_call_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-PQ-ATTESTATION",
                self.pq_attestations
                    .values()
                    .map(PqSolverAttestationRecord::public_record)
                    .collect(),
            ),
            bundle_root: private_l2_low_fee_cross_contract_call_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-BUNDLE",
                self.bundles
                    .values()
                    .map(LowFeeCallBundleRecord::public_record)
                    .collect(),
            ),
            settlement_batch_root: private_l2_low_fee_cross_contract_call_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-SETTLEMENT",
                self.settlement_batches
                    .values()
                    .map(SettlementBatchRecord::public_record)
                    .collect(),
            ),
            receipt_root: private_l2_low_fee_cross_contract_call_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-RECEIPT",
                self.receipts
                    .values()
                    .map(SettlementReceiptRecord::public_record)
                    .collect(),
            ),
            nullifier_root: private_l2_low_fee_cross_contract_call_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-NULLIFIER",
                self.consumed_nullifiers
                    .iter()
                    .map(|nullifier| json!({ "nullifier_root": nullifier }))
                    .collect(),
            ),
            public_record_root: private_l2_low_fee_cross_contract_call_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-PUBLIC-RECORD",
                self.public_records.values().cloned().collect(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_cross_contract_call_market_runtime",
            "protocol_version": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_HASH_SUITE,
            "sealed_call_scheme": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SEALED_CALL_SCHEME,
            "solver_quote_scheme": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SOLVER_QUOTE_SCHEME,
            "dependency_proof_scheme": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEPENDENCY_PROOF_SCHEME,
            "bundle_scheme": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_BUNDLE_SCHEME,
            "pq_solver_attestation_scheme": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_PQ_SOLVER_ATTESTATION_SCHEME,
            "settlement_scheme": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_SETTLEMENT_SCHEME,
            "receipt_scheme": PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_RECEIPT_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "roots": self.roots().public_record(),
            "privacy_boundary": "public records expose roots, commitments, statuses, and counters only",
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": private_l2_low_fee_cross_contract_call_market_state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_low_fee_cross_contract_call_market_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: Value) {
        let record_id = public_record_id(record_kind, subject_id, &payload);
        self.public_records.insert(
            record_id,
            roots_only_payload(record_kind, subject_id, &payload),
        );
    }

    fn refresh_intent_records(&mut self, intent_ids: &[String]) {
        let updates = intent_ids
            .iter()
            .filter_map(|intent_id| {
                self.intents
                    .get(intent_id)
                    .map(|intent| (intent.intent_id.clone(), intent.public_record()))
            })
            .collect::<Vec<_>>();
        for (intent_id, record) in updates {
            self.publish_public_record("intent", &intent_id, record);
        }
    }

    fn refresh_quote_records(&mut self, quote_ids: &[String]) {
        let updates = quote_ids
            .iter()
            .filter_map(|quote_id| {
                self.quotes
                    .get(quote_id)
                    .map(|quote| (quote.quote_id.clone(), quote.public_record()))
            })
            .collect::<Vec<_>>();
        for (quote_id, record) in updates {
            self.publish_public_record("solver_quote", &quote_id, record);
        }
    }
}

pub fn private_l2_low_fee_cross_contract_call_market_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_l2_low_fee_cross_contract_call_market_state_root_from_record(
    record: &Value,
) -> String {
    private_l2_low_fee_cross_contract_call_market_payload_root(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-STATE",
        record,
    )
}

pub fn private_l2_low_fee_cross_contract_call_market_merkle_root(
    domain: &str,
    leaves: Vec<Value>,
) -> String {
    merkle_root(domain, &leaves)
}

pub fn private_cross_contract_call_intent_id(
    request: &SubmitPrivateCrossContractCallIntentRequest,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(request.call_kind.as_str()),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.contract_call_graph_root),
            HashPart::Str(&request.sealed_calldata_root),
            HashPart::Str(&request.nullifier_root),
        ],
        32,
    )
}

pub fn solver_quote_id(request: &PostSolverQuoteRequest, score: u128, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-SOLVER-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.solver_commitment),
            HashPart::Str(&intent_id_root(&request.intent_ids)),
            HashPart::Str(&request.route_commitment_root),
            HashPart::Str(&request.execution_plan_root),
            HashPart::Int(score as i128),
        ],
        32,
    )
}

pub fn dependency_proof_id(
    request: &RecordDependencyProofRequest,
    strict_ordering: bool,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-DEPENDENCY-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.predecessor_intent_id),
            HashPart::Str(&request.successor_intent_id),
            HashPart::Str(request.dependency_kind.as_str()),
            HashPart::Str(&request.resource_commitment),
            HashPart::Str(&request.dependency_proof_root),
            HashPart::Int(strict_ordering as i128),
        ],
        32,
    )
}

pub fn pq_solver_attestation_id(request: &RecordPqSolverAttestationRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-PQ-SOLVER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.quote_id),
            HashPart::Str(&request.solver_commitment),
            HashPart::Str(&request.attestation_root),
            HashPart::Str(&request.signature_bundle_root),
        ],
        32,
    )
}

pub fn low_fee_call_bundle_id(
    request: &BuildLowFeeCallBundleRequest,
    selected_quote_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&intent_id_root(&request.intent_ids)),
            HashPart::Str(&intent_id_root(&request.quote_ids)),
            HashPart::Str(selected_quote_id),
            HashPart::Str(&request.aggregate_call_graph_root),
            HashPart::Str(&request.bundle_execution_root),
            HashPart::Int(request.built_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_batch_id(request: &PublishSettlementBatchRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.bundle_id),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.state_root_before),
            HashPart::Str(&request.state_root_after),
            HashPart::Int(request.settled_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &PublishReceiptRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.settlement_batch_id),
            HashPart::Str(&request.receipt_note_root),
        ],
        32,
    )
}

fn solver_quote_score(request: &PostSolverQuoteRequest) -> u128 {
    let latency_bonus =
        PRIVATE_L2_LOW_FEE_CROSS_CONTRACT_CALL_MARKET_RUNTIME_DEFAULT_TARGET_LATENCY_MS
            .saturating_sub(request.latency_ms) as u128
            * 1_000_000;
    let composability_bonus = request.intent_ids.len() as u128 * 10_000_000;
    let fee_penalty = request.fee_quote_bps as u128 * 100_000;
    composability_bonus
        .saturating_add(latency_bonus)
        .saturating_sub(fee_penalty)
}

fn intent_id_root(ids: &[String]) -> String {
    merkle_root(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-ID-LIST",
        &ids.iter().map(|id| json!(id)).collect::<Vec<_>>(),
    )
}

fn covers_all(haystack: &[String], needles: &[String]) -> bool {
    let haystack = haystack.iter().collect::<BTreeSet<_>>();
    needles.iter().all(|needle| haystack.contains(needle))
}

fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn roots_only_payload(record_kind: &str, subject_id: &str, payload: &Value) -> Value {
    json!({
        "kind": "private_l2_low_fee_cross_contract_call_market_roots_only_payload",
        "chain_id": CHAIN_ID,
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": private_l2_low_fee_cross_contract_call_market_payload_root(
            "PRIVATE-L2-LOW-FEE-CROSS-CONTRACT-CALL-MARKET-ROOTS-ONLY-PAYLOAD",
            payload,
        ),
    })
}

fn require_non_empty(
    value: &str,
    label: &str,
) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(
    value: &str,
    label: &str,
) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<()> {
    require_non_empty(value, label)?;
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn ensure_unique(
    values: &[String],
    label: &str,
) -> PrivateL2LowFeeCrossContractCallMarketRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("duplicate {label}: {value}"));
        }
    }
    Ok(())
}

fn would_create_cycle(
    edges: &BTreeMap<String, DependencyProofRecord>,
    candidate: &DependencyProofRecord,
) -> bool {
    let mut stack = vec![candidate.request.successor_intent_id.clone()];
    let mut visited = BTreeSet::new();
    while let Some(current) = stack.pop() {
        if current == candidate.request.predecessor_intent_id {
            return true;
        }
        if !visited.insert(current.clone()) {
            continue;
        }
        for edge in edges.values() {
            if edge.request.predecessor_intent_id == current {
                stack.push(edge.request.successor_intent_id.clone());
            }
        }
    }
    false
}
