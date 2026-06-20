use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2CrossContractIntentSettlementBusResult<T> = Result<T, String>;

pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_PROTOCOL_VERSION: &str =
    "nebula-private-l2-cross-contract-intent-settlement-bus-v1";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEVNET_HEIGHT: u64 = 512;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_INTENT_SCHEME: &str =
    "encrypted-cross-contract-private-intent-v1";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEPENDENCY_SCHEME: &str =
    "private-intent-dependency-graph-edge-v1";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_SOLVER_SCHEME: &str =
    "sealed-solver-settlement-commitment-v1";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_PQ_AUTH_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_LOW_FEE_SPONSOR_SCHEME: &str =
    "low-fee-cross-contract-intent-sponsor-root-v1";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_RECEIPT_SCHEME: &str =
    "batched-roots-only-private-intent-settlement-receipt-v1";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_STATE_SCHEME: &str =
    "cross-contract-private-intent-state-root-v1";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_LOW_FEE_LANE: &str =
    "private-l2-cross-contract-intent-settlement";
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_BATCH_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_FINALITY_BLOCKS: u64 = 12;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MAX_INTENTS_PER_BATCH: usize = 96;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MAX_EDGES_PER_BATCH: usize = 256;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MAX_SOLVERS_PER_BATCH: usize = 24;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_DEFI_PRIVACY_SET_SIZE: u64 = 512;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MAX_FEE_MICRO_UNITS: u64 = 1_500;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_SPONSORED_FEE_MICRO_UNITS: u64 =
    800;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_000;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_PENDING_INTENTS: usize = 262_144;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_DEPENDENCY_EDGES: usize = 524_288;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_SOLVER_COMMITMENTS: usize = 131_072;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_BATCHES: usize = 131_072;
pub const PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_RECEIPTS: usize = 131_072;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractIntentKind {
    ShieldedCall,
    MultiContractSwap,
    PrivateTokenTransfer,
    PrivateTokenMint,
    PrivateTokenBurn,
    ConfidentialAmmSwap,
    ConfidentialAmmLiquidity,
    PrivateLendingSupply,
    PrivateLendingBorrow,
    PrivateLendingRepay,
    PrivateVaultDeposit,
    PrivateVaultWithdraw,
    SettlementHook,
    Callback,
    Custom(String),
}

impl ContractIntentKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::ShieldedCall => "shielded_call".to_string(),
            Self::MultiContractSwap => "multi_contract_swap".to_string(),
            Self::PrivateTokenTransfer => "private_token_transfer".to_string(),
            Self::PrivateTokenMint => "private_token_mint".to_string(),
            Self::PrivateTokenBurn => "private_token_burn".to_string(),
            Self::ConfidentialAmmSwap => "confidential_amm_swap".to_string(),
            Self::ConfidentialAmmLiquidity => "confidential_amm_liquidity".to_string(),
            Self::PrivateLendingSupply => "private_lending_supply".to_string(),
            Self::PrivateLendingBorrow => "private_lending_borrow".to_string(),
            Self::PrivateLendingRepay => "private_lending_repay".to_string(),
            Self::PrivateVaultDeposit => "private_vault_deposit".to_string(),
            Self::PrivateVaultWithdraw => "private_vault_withdraw".to_string(),
            Self::SettlementHook => "settlement_hook".to_string(),
            Self::Callback => "callback".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn defi(&self) -> bool {
        matches!(
            self,
            Self::MultiContractSwap
                | Self::ConfidentialAmmSwap
                | Self::ConfidentialAmmLiquidity
                | Self::PrivateLendingSupply
                | Self::PrivateLendingBorrow
                | Self::PrivateLendingRepay
                | Self::PrivateVaultDeposit
                | Self::PrivateVaultWithdraw
        )
    }

    pub fn default_priority_weight(&self) -> u64 {
        match self {
            Self::SettlementHook => 9_600,
            Self::PrivateLendingRepay => 9_000,
            Self::MultiContractSwap | Self::ConfidentialAmmSwap => 8_700,
            Self::PrivateLendingBorrow => 8_300,
            Self::ConfidentialAmmLiquidity
            | Self::PrivateVaultDeposit
            | Self::PrivateVaultWithdraw => 7_700,
            Self::ShieldedCall | Self::Callback => 7_200,
            Self::PrivateTokenTransfer | Self::PrivateTokenMint | Self::PrivateTokenBurn => 6_800,
            Self::PrivateLendingSupply => 6_400,
            Self::Custom(_) => 6_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentDependencyKind {
    ReadAfterWrite,
    WriteAfterRead,
    WriteAfterWrite,
    AssetConservation,
    NullifierOrdering,
    OracleFreshness,
    CallbackOrdering,
    SolverRouteOrdering,
    FeeSponsorPrepay,
    SettlementBarrier,
}

impl IntentDependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadAfterWrite => "read_after_write",
            Self::WriteAfterRead => "write_after_read",
            Self::WriteAfterWrite => "write_after_write",
            Self::AssetConservation => "asset_conservation",
            Self::NullifierOrdering => "nullifier_ordering",
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
                | Self::AssetConservation
                | Self::NullifierOrdering
                | Self::SolverRouteOrdering
                | Self::SettlementBarrier
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentSettlementStatus {
    Pending,
    GraphLinked,
    SolverCommitted,
    Batched,
    Proving,
    Proven,
    Settled,
    Failed,
    Expired,
    Cancelled,
    Challenged,
}

impl IntentSettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::GraphLinked => "graph_linked",
            Self::SolverCommitted => "solver_committed",
            Self::Batched => "batched",
            Self::Proving => "proving",
            Self::Proven => "proven",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::GraphLinked | Self::SolverCommitted
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Failed | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub hash_suite: String,
    pub intent_scheme: String,
    pub dependency_scheme: String,
    pub solver_scheme: String,
    pub pq_auth_scheme: String,
    pub low_fee_sponsor_scheme: String,
    pub receipt_scheme: String,
    pub state_scheme: String,
    pub intent_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub finality_blocks: u64,
    pub max_intents_per_batch: usize,
    pub max_edges_per_batch: usize,
    pub max_solvers_per_batch: usize,
    pub min_privacy_set_size: u64,
    pub defi_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_micro_units: u64,
    pub sponsored_fee_micro_units: u64,
    pub sponsor_rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_L2_NETWORK
                .to_string(),
            monero_network: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MONERO_NETWORK
                .to_string(),
            fee_asset_id: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_FEE_ASSET_ID
                .to_string(),
            low_fee_lane: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_LOW_FEE_LANE
                .to_string(),
            hash_suite: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_HASH_SUITE.to_string(),
            intent_scheme: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_INTENT_SCHEME
                .to_string(),
            dependency_scheme: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEPENDENCY_SCHEME
                .to_string(),
            solver_scheme: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_SOLVER_SCHEME
                .to_string(),
            pq_auth_scheme: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_PQ_AUTH_SCHEME
                .to_string(),
            low_fee_sponsor_scheme:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_LOW_FEE_SPONSOR_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_RECEIPT_SCHEME
                .to_string(),
            state_scheme: PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_STATE_SCHEME.to_string(),
            intent_ttl_blocks:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_INTENT_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_BATCH_TTL_BLOCKS,
            finality_blocks:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_FINALITY_BLOCKS,
            max_intents_per_batch:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MAX_INTENTS_PER_BATCH,
            max_edges_per_batch:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MAX_EDGES_PER_BATCH,
            max_solvers_per_batch:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MAX_SOLVERS_PER_BATCH,
            min_privacy_set_size:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MIN_PRIVACY_SET_SIZE,
            defi_privacy_set_size:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_DEFI_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_micro_units:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_MAX_FEE_MICRO_UNITS,
            sponsored_fee_micro_units:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_SPONSORED_FEE_MICRO_UNITS,
            sponsor_rebate_bps:
                PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_DEFAULT_SPONSOR_REBATE_BPS,
        }
    }

    pub fn validate(&self) -> PrivateL2CrossContractIntentSettlementBusResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_non_empty(&self.l2_network, "l2 network")?;
        ensure_non_empty(&self.monero_network, "monero network")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_non_empty(&self.low_fee_lane, "low fee lane")?;
        ensure_non_empty(&self.hash_suite, "hash suite")?;
        ensure_non_empty(&self.intent_scheme, "intent scheme")?;
        ensure_non_empty(&self.dependency_scheme, "dependency scheme")?;
        ensure_non_empty(&self.solver_scheme, "solver scheme")?;
        ensure_non_empty(&self.pq_auth_scheme, "pq auth scheme")?;
        ensure_non_empty(&self.low_fee_sponsor_scheme, "low fee sponsor scheme")?;
        ensure_non_empty(&self.receipt_scheme, "receipt scheme")?;
        ensure_non_empty(&self.state_scheme, "state scheme")?;
        if self.schema_version == 0
            || self.intent_ttl_blocks == 0
            || self.batch_ttl_blocks == 0
            || self.finality_blocks == 0
        {
            return Err("schema version and settlement windows must be non-zero".to_string());
        }
        if self.max_intents_per_batch == 0
            || self.max_edges_per_batch == 0
            || self.max_solvers_per_batch == 0
        {
            return Err("batch limits must be non-zero".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.defi_privacy_set_size < self.min_privacy_set_size
            || self.min_pq_security_bits == 0
        {
            return Err("privacy and pq security floors are invalid".to_string());
        }
        if self.max_fee_micro_units == 0
            || self.sponsored_fee_micro_units > self.max_fee_micro_units
            || self.sponsor_rebate_bps > PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_BPS
        {
            return Err("low-fee sponsor policy is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_cross_contract_intent_settlement_bus_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "hash_suite": self.hash_suite,
            "intent_scheme": self.intent_scheme,
            "dependency_scheme": self.dependency_scheme,
            "solver_scheme": self.solver_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "low_fee_sponsor_scheme": self.low_fee_sponsor_scheme,
            "receipt_scheme": self.receipt_scheme,
            "state_scheme": self.state_scheme,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "finality_blocks": self.finality_blocks,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_edges_per_batch": self.max_edges_per_batch,
            "max_solvers_per_batch": self.max_solvers_per_batch,
            "min_privacy_set_size": self.min_privacy_set_size,
            "defi_privacy_set_size": self.defi_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_micro_units": self.max_fee_micro_units,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub intents_submitted: u64,
    pub dependency_edges_linked: u64,
    pub solver_commitments_posted: u64,
    pub batches_built: u64,
    pub batches_settled: u64,
    pub receipts_published: u64,
    pub replay_rejections: u64,
    pub privacy_floor_rejections: u64,
    pub pq_security_rejections: u64,
    pub total_sponsored_fee_micro_units: u64,
    pub total_settled_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "intents_submitted": self.intents_submitted,
            "dependency_edges_linked": self.dependency_edges_linked,
            "solver_commitments_posted": self.solver_commitments_posted,
            "batches_built": self.batches_built,
            "batches_settled": self.batches_settled,
            "receipts_published": self.receipts_published,
            "replay_rejections": self.replay_rejections,
            "privacy_floor_rejections": self.privacy_floor_rejections,
            "pq_security_rejections": self.pq_security_rejections,
            "total_sponsored_fee_micro_units": self.total_sponsored_fee_micro_units,
            "total_settled_fee_micro_units": self.total_settled_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEncryptedIntentRequest {
    pub intent_kind: ContractIntentKind,
    pub account_commitment: String,
    pub contract_commitment_root: String,
    pub encrypted_intent_root: String,
    pub encrypted_witness_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub asset_flow_root: String,
    pub callback_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub replay_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_micro_units: u64,
    pub priority_weight: Option<u64>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitEncryptedIntentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2CrossContractIntentSettlementBusResult<()> {
        ensure_non_empty(&self.account_commitment, "account commitment")?;
        ensure_non_empty(&self.contract_commitment_root, "contract commitment root")?;
        ensure_non_empty(&self.encrypted_intent_root, "encrypted intent root")?;
        ensure_non_empty(&self.encrypted_witness_root, "encrypted witness root")?;
        ensure_non_empty(&self.read_set_root, "read set root")?;
        ensure_non_empty(&self.write_set_root, "write set root")?;
        ensure_non_empty(&self.asset_flow_root, "asset flow root")?;
        ensure_non_empty(&self.callback_root, "callback root")?;
        ensure_non_empty(&self.pq_authorization_root, "pq authorization root")?;
        ensure_non_empty(&self.low_fee_sponsor_root, "low-fee sponsor root")?;
        ensure_non_empty(&self.replay_nullifier, "replay nullifier")?;
        let privacy_floor = if self.intent_kind.defi() {
            config.defi_privacy_set_size
        } else {
            config.min_privacy_set_size
        };
        if self.privacy_set_size < privacy_floor {
            return Err(format!(
                "privacy set {} is below required {}",
                self.privacy_set_size, privacy_floor
            ));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "pq security bits {} below required {}",
                self.pq_security_bits, config.min_pq_security_bits
            ));
        }
        if self.max_fee_micro_units == 0 || self.max_fee_micro_units > config.max_fee_micro_units {
            return Err("intent fee cap exceeds low-fee lane policy".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("intent expiry must follow submission height".to_string());
        }
        if self.expires_at_height - self.submitted_at_height > config.intent_ttl_blocks {
            return Err("intent ttl exceeds policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkDependencyEdgeRequest {
    pub predecessor_intent_id: String,
    pub successor_intent_id: String,
    pub dependency_kind: IntentDependencyKind,
    pub resource_commitment: String,
    pub read_root: String,
    pub write_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub pq_authorization_root: String,
    pub strict_ordering: bool,
    pub linked_at_height: u64,
}

impl LinkDependencyEdgeRequest {
    pub fn validate(&self) -> PrivateL2CrossContractIntentSettlementBusResult<()> {
        ensure_non_empty(&self.predecessor_intent_id, "predecessor intent id")?;
        ensure_non_empty(&self.successor_intent_id, "successor intent id")?;
        ensure_non_empty(&self.resource_commitment, "resource commitment")?;
        ensure_non_empty(&self.read_root, "dependency read root")?;
        ensure_non_empty(&self.write_root, "dependency write root")?;
        ensure_non_empty(&self.nullifier_root, "dependency nullifier root")?;
        ensure_non_empty(&self.proof_root, "dependency proof root")?;
        ensure_non_empty(
            &self.pq_authorization_root,
            "dependency pq authorization root",
        )?;
        if self.predecessor_intent_id == self.successor_intent_id {
            return Err("dependency edge cannot point to the same intent".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostSolverCommitmentRequest {
    pub intent_ids: Vec<String>,
    pub solver_commitment: String,
    pub route_commitment_root: String,
    pub fill_commitment_root: String,
    pub constraint_satisfaction_root: String,
    pub solver_pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub posted_at_height: u64,
}

impl PostSolverCommitmentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2CrossContractIntentSettlementBusResult<()> {
        if self.intent_ids.is_empty() {
            return Err("solver commitment requires at least one intent".to_string());
        }
        if self.intent_ids.len() > config.max_intents_per_batch {
            return Err("solver commitment exceeds max intent count".to_string());
        }
        ensure_unique(&self.intent_ids, "solver intent id")?;
        ensure_non_empty(&self.solver_commitment, "solver commitment")?;
        ensure_non_empty(&self.route_commitment_root, "route commitment root")?;
        ensure_non_empty(&self.fill_commitment_root, "fill commitment root")?;
        ensure_non_empty(
            &self.constraint_satisfaction_root,
            "constraint satisfaction root",
        )?;
        ensure_non_empty(
            &self.solver_pq_authorization_root,
            "solver pq authorization root",
        )?;
        ensure_non_empty(&self.low_fee_sponsor_root, "low-fee sponsor root")?;
        if self.max_fee_micro_units == 0 || self.max_fee_micro_units > config.max_fee_micro_units {
            return Err("solver fee cap exceeds lane policy".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("solver privacy set is below policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSettlementBatchRequest {
    pub intent_ids: Vec<String>,
    pub solver_commitment_ids: Vec<String>,
    pub aggregate_dependency_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_low_fee_sponsor_root: String,
    pub batch_witness_root: String,
    pub batch_proof_request_root: String,
    pub state_root_before: String,
    pub min_privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub built_at_height: u64,
}

impl BuildSettlementBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2CrossContractIntentSettlementBusResult<()> {
        if self.intent_ids.is_empty() {
            return Err("settlement batch requires at least one intent".to_string());
        }
        if self.intent_ids.len() > config.max_intents_per_batch {
            return Err("settlement batch exceeds max intent count".to_string());
        }
        if self.solver_commitment_ids.len() > config.max_solvers_per_batch {
            return Err("settlement batch exceeds max solver commitments".to_string());
        }
        ensure_unique(&self.intent_ids, "batch intent id")?;
        ensure_unique(&self.solver_commitment_ids, "batch solver commitment id")?;
        ensure_non_empty(&self.aggregate_dependency_root, "aggregate dependency root")?;
        ensure_non_empty(
            &self.aggregate_pq_authorization_root,
            "aggregate pq authorization root",
        )?;
        ensure_non_empty(
            &self.aggregate_low_fee_sponsor_root,
            "aggregate low-fee sponsor root",
        )?;
        ensure_non_empty(&self.batch_witness_root, "batch witness root")?;
        ensure_non_empty(&self.batch_proof_request_root, "batch proof request root")?;
        ensure_non_empty(&self.state_root_before, "state root before")?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("batch privacy set is below policy".to_string());
        }
        if self.max_fee_micro_units == 0 || self.max_fee_micro_units > config.max_fee_micro_units {
            return Err("batch fee cap exceeds low-fee lane policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub recursive_proof_root: String,
    pub settlement_tx_root: String,
    pub public_input_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub output_commitment_root: String,
    pub consumed_nullifier_root: String,
    pub fee_settlement_root: String,
    pub pq_transcript_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub settled_fee_micro_units: u64,
    pub settled_at_height: u64,
    pub status: IntentSettlementStatus,
}

impl SettleBatchRequest {
    pub fn validate(&self) -> PrivateL2CrossContractIntentSettlementBusResult<()> {
        ensure_non_empty(&self.batch_id, "batch id")?;
        ensure_non_empty(&self.recursive_proof_root, "recursive proof root")?;
        ensure_non_empty(&self.settlement_tx_root, "settlement tx root")?;
        ensure_non_empty(&self.public_input_root, "public input root")?;
        ensure_non_empty(&self.state_root_before, "state root before")?;
        ensure_non_empty(&self.state_root_after, "state root after")?;
        ensure_non_empty(&self.output_commitment_root, "output commitment root")?;
        ensure_non_empty(&self.consumed_nullifier_root, "consumed nullifier root")?;
        ensure_non_empty(&self.fee_settlement_root, "fee settlement root")?;
        ensure_non_empty(&self.pq_transcript_root, "pq transcript root")?;
        ensure_non_empty(
            &self.low_fee_sponsor_receipt_root,
            "low-fee sponsor receipt root",
        )?;
        if !matches!(
            self.status,
            IntentSettlementStatus::Settled | IntentSettlementStatus::Failed
        ) {
            return Err("settlement status must be settled or failed".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedContractIntentRecord {
    pub intent_id: String,
    pub intent_kind: ContractIntentKind,
    pub account_commitment: String,
    pub contract_commitment_root: String,
    pub encrypted_intent_root: String,
    pub encrypted_witness_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub asset_flow_root: String,
    pub callback_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub replay_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_micro_units: u64,
    pub priority_weight: u64,
    pub status: IntentSettlementStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedContractIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "intent_kind": self.intent_kind.as_str(),
            "account_commitment": self.account_commitment,
            "contract_commitment_root": self.contract_commitment_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "asset_flow_root": self.asset_flow_root,
            "callback_root": self.callback_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "replay_nullifier": self.replay_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_micro_units": self.max_fee_micro_units,
            "priority_weight": self.priority_weight,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_boundary": "roots_and_commitments_only_no_plaintext_intent_accounts_or_calldata",
        })
    }

    pub fn root(&self) -> String {
        private_l2_cross_contract_intent_settlement_bus_payload_root(
            "ENCRYPTED-CONTRACT-INTENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyGraphEdgeRecord {
    pub edge_id: String,
    pub predecessor_intent_id: String,
    pub successor_intent_id: String,
    pub dependency_kind: IntentDependencyKind,
    pub resource_commitment: String,
    pub read_root: String,
    pub write_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub pq_authorization_root: String,
    pub strict_ordering: bool,
    pub linked_at_height: u64,
}

impl DependencyGraphEdgeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "edge_id": self.edge_id,
            "predecessor_intent_id": self.predecessor_intent_id,
            "successor_intent_id": self.successor_intent_id,
            "dependency_kind": self.dependency_kind.as_str(),
            "resource_commitment": self.resource_commitment,
            "read_root": self.read_root,
            "write_root": self.write_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "strict_ordering": self.strict_ordering,
            "linked_at_height": self.linked_at_height,
        })
    }

    pub fn root(&self) -> String {
        private_l2_cross_contract_intent_settlement_bus_payload_root(
            "DEPENDENCY-GRAPH-EDGE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitmentRecord {
    pub solver_commitment_id: String,
    pub intent_ids: Vec<String>,
    pub solver_commitment: String,
    pub route_commitment_root: String,
    pub fill_commitment_root: String,
    pub constraint_satisfaction_root: String,
    pub solver_pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub posted_at_height: u64,
}

impl SolverCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "solver_commitment_id": self.solver_commitment_id,
            "intent_count": self.intent_ids.len(),
            "intent_root": merkle_root(
                "PRIVATE-L2-CROSS-CONTRACT-INTENT-SOLVER-INTENT-IDS",
                &self.intent_ids.iter().map(|id| Value::String(id.clone())).collect::<Vec<_>>()
            ),
            "solver_commitment": self.solver_commitment,
            "route_commitment_root": self.route_commitment_root,
            "fill_commitment_root": self.fill_commitment_root,
            "constraint_satisfaction_root": self.constraint_satisfaction_root,
            "solver_pq_authorization_root": self.solver_pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "posted_at_height": self.posted_at_height,
        })
    }

    pub fn root(&self) -> String {
        private_l2_cross_contract_intent_settlement_bus_payload_root(
            "SOLVER-COMMITMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatchRecord {
    pub batch_id: String,
    pub intent_ids: Vec<String>,
    pub solver_commitment_ids: Vec<String>,
    pub intent_root: String,
    pub dependency_edge_root: String,
    pub solver_commitment_root: String,
    pub aggregate_dependency_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_low_fee_sponsor_root: String,
    pub batch_witness_root: String,
    pub batch_proof_request_root: String,
    pub state_root_before: String,
    pub min_privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub status: IntentSettlementStatus,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl SettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "intent_count": self.intent_ids.len(),
            "solver_commitment_count": self.solver_commitment_ids.len(),
            "intent_root": self.intent_root,
            "dependency_edge_root": self.dependency_edge_root,
            "solver_commitment_root": self.solver_commitment_root,
            "aggregate_dependency_root": self.aggregate_dependency_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "aggregate_low_fee_sponsor_root": self.aggregate_low_fee_sponsor_root,
            "batch_witness_root": self.batch_witness_root,
            "batch_proof_request_root": self.batch_proof_request_root,
            "state_root_before": self.state_root_before,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_micro_units": self.max_fee_micro_units,
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        private_l2_cross_contract_intent_settlement_bus_payload_root(
            "SETTLEMENT-BATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchedSettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub recursive_proof_root: String,
    pub settlement_tx_root: String,
    pub public_input_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub output_commitment_root: String,
    pub consumed_nullifier_root: String,
    pub fee_settlement_root: String,
    pub pq_transcript_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub settled_fee_micro_units: u64,
    pub settled_at_height: u64,
    pub finality_height: u64,
    pub status: IntentSettlementStatus,
}

impl BatchedSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "recursive_proof_root": self.recursive_proof_root,
            "settlement_tx_root": self.settlement_tx_root,
            "public_input_root": self.public_input_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "output_commitment_root": self.output_commitment_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "fee_settlement_root": self.fee_settlement_root,
            "pq_transcript_root": self.pq_transcript_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "settled_fee_micro_units": self.settled_fee_micro_units,
            "settled_at_height": self.settled_at_height,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
            "privacy_boundary": "batched_receipt_exposes_roots_only",
        })
    }

    pub fn root(&self) -> String {
        private_l2_cross_contract_intent_settlement_bus_payload_root(
            "BATCHED-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub intent_root: String,
    pub dependency_edge_root: String,
    pub solver_commitment_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub replay_nullifier_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_root": self.intent_root,
            "dependency_edge_root": self.dependency_edge_root,
            "solver_commitment_root": self.solver_commitment_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn root(&self) -> String {
        private_l2_cross_contract_intent_settlement_bus_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub intents: BTreeMap<String, EncryptedContractIntentRecord>,
    pub dependency_edges: BTreeMap<String, DependencyGraphEdgeRecord>,
    pub solver_commitments: BTreeMap<String, SolverCommitmentRecord>,
    pub batches: BTreeMap<String, SettlementBatchRecord>,
    pub receipts: BTreeMap<String, BatchedSettlementReceipt>,
    pub replay_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2CrossContractIntentSettlementBusResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            intents: BTreeMap::new(),
            dependency_edges: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
        })
    }

    pub fn submit_encrypted_intent(
        &mut self,
        request: SubmitEncryptedIntentRequest,
    ) -> PrivateL2CrossContractIntentSettlementBusResult<String> {
        request.validate(&self.config).map_err(|err| {
            if err.contains("privacy") {
                self.counters.privacy_floor_rejections =
                    self.counters.privacy_floor_rejections.saturating_add(1);
            }
            if err.contains("pq security") {
                self.counters.pq_security_rejections =
                    self.counters.pq_security_rejections.saturating_add(1);
            }
            err
        })?;
        if self.intents.len() >= PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_PENDING_INTENTS
        {
            return Err("cross-contract intent bus is at capacity".to_string());
        }
        if self.replay_nullifiers.contains(&request.replay_nullifier) {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("replay nullifier already observed".to_string());
        }
        let nonce = self.counters.intents_submitted;
        let intent_id = encrypted_intent_id(&request, nonce);
        let priority_weight = request
            .priority_weight
            .unwrap_or_else(|| request.intent_kind.default_priority_weight());
        let record = EncryptedContractIntentRecord {
            intent_id: intent_id.clone(),
            intent_kind: request.intent_kind,
            account_commitment: request.account_commitment,
            contract_commitment_root: request.contract_commitment_root,
            encrypted_intent_root: request.encrypted_intent_root,
            encrypted_witness_root: request.encrypted_witness_root,
            read_set_root: request.read_set_root,
            write_set_root: request.write_set_root,
            asset_flow_root: request.asset_flow_root,
            callback_root: request.callback_root,
            pq_authorization_root: request.pq_authorization_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            replay_nullifier: request.replay_nullifier.clone(),
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_micro_units: request.max_fee_micro_units,
            priority_weight,
            status: IntentSettlementStatus::Pending,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
        };
        self.replay_nullifiers.insert(request.replay_nullifier);
        self.intents.insert(intent_id.clone(), record);
        self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
        Ok(intent_id)
    }

    pub fn link_dependency_edge(
        &mut self,
        request: LinkDependencyEdgeRequest,
    ) -> PrivateL2CrossContractIntentSettlementBusResult<String> {
        request.validate()?;
        if self.dependency_edges.len()
            >= PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_DEPENDENCY_EDGES
        {
            return Err("dependency edge lane is at capacity".to_string());
        }
        let predecessor = self
            .intents
            .get(&request.predecessor_intent_id)
            .ok_or_else(|| {
                format!(
                    "unknown predecessor intent: {}",
                    request.predecessor_intent_id
                )
            })?;
        let successor = self
            .intents
            .get(&request.successor_intent_id)
            .ok_or_else(|| format!("unknown successor intent: {}", request.successor_intent_id))?;
        if predecessor.status.terminal() || successor.status.terminal() {
            return Err("cannot link terminal intents".to_string());
        }
        let strict_ordering = request.strict_ordering || request.dependency_kind.strict();
        let nonce = self.counters.dependency_edges_linked;
        let edge_id = dependency_edge_id(&request, strict_ordering, nonce);
        let edge = DependencyGraphEdgeRecord {
            edge_id: edge_id.clone(),
            predecessor_intent_id: request.predecessor_intent_id,
            successor_intent_id: request.successor_intent_id,
            dependency_kind: request.dependency_kind,
            resource_commitment: request.resource_commitment,
            read_root: request.read_root,
            write_root: request.write_root,
            nullifier_root: request.nullifier_root,
            proof_root: request.proof_root,
            pq_authorization_root: request.pq_authorization_root,
            strict_ordering,
            linked_at_height: request.linked_at_height,
        };
        if would_create_cycle(&self.dependency_edges, &edge) {
            return Err("dependency edge would create a cycle".to_string());
        }
        if let Some(intent) = self.intents.get_mut(&edge.predecessor_intent_id) {
            intent.status = IntentSettlementStatus::GraphLinked;
        }
        if let Some(intent) = self.intents.get_mut(&edge.successor_intent_id) {
            intent.status = IntentSettlementStatus::GraphLinked;
        }
        self.dependency_edges.insert(edge_id.clone(), edge);
        self.counters.dependency_edges_linked =
            self.counters.dependency_edges_linked.saturating_add(1);
        Ok(edge_id)
    }

    pub fn post_solver_commitment(
        &mut self,
        request: PostSolverCommitmentRequest,
    ) -> PrivateL2CrossContractIntentSettlementBusResult<String> {
        request.validate(&self.config)?;
        if self.solver_commitments.len()
            >= PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_SOLVER_COMMITMENTS
        {
            return Err("solver commitment lane is at capacity".to_string());
        }
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("unknown solver intent: {intent_id}"))?;
            if !intent.status.open() {
                return Err(format!(
                    "intent {intent_id} is not open for solver commitment"
                ));
            }
            if request.privacy_set_size < intent.privacy_set_size {
                return Err("solver privacy set cannot be below intent privacy set".to_string());
            }
        }
        let commitment_id = solver_commitment_id(&request, self.counters.solver_commitments_posted);
        let record = SolverCommitmentRecord {
            solver_commitment_id: commitment_id.clone(),
            intent_ids: request.intent_ids,
            solver_commitment: request.solver_commitment,
            route_commitment_root: request.route_commitment_root,
            fill_commitment_root: request.fill_commitment_root,
            constraint_satisfaction_root: request.constraint_satisfaction_root,
            solver_pq_authorization_root: request.solver_pq_authorization_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            max_fee_micro_units: request.max_fee_micro_units,
            privacy_set_size: request.privacy_set_size,
            posted_at_height: request.posted_at_height,
        };
        for intent_id in &record.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentSettlementStatus::SolverCommitted;
            }
        }
        self.solver_commitments
            .insert(commitment_id.clone(), record);
        self.counters.solver_commitments_posted =
            self.counters.solver_commitments_posted.saturating_add(1);
        Ok(commitment_id)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildSettlementBatchRequest,
    ) -> PrivateL2CrossContractIntentSettlementBusResult<String> {
        request.validate(&self.config)?;
        if self.batches.len() >= PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_BATCHES {
            return Err("settlement batch lane is at capacity".to_string());
        }
        let intent_set = request.intent_ids.iter().cloned().collect::<BTreeSet<_>>();
        let intents = request
            .intent_ids
            .iter()
            .map(|id| {
                self.intents
                    .get(id)
                    .ok_or_else(|| format!("unknown batch intent: {id}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if intents.iter().any(|intent| !intent.status.open()) {
            return Err("batch can only include open intents".to_string());
        }
        let solver_records = request
            .solver_commitment_ids
            .iter()
            .map(|id| {
                self.solver_commitments
                    .get(id)
                    .ok_or_else(|| format!("unknown solver commitment: {id}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for solver in &solver_records {
            if solver
                .intent_ids
                .iter()
                .any(|intent_id| !intent_set.contains(intent_id))
            {
                return Err("solver commitment references an intent outside the batch".to_string());
            }
        }
        let edge_records = self
            .dependency_edges
            .values()
            .filter(|edge| {
                intent_set.contains(&edge.predecessor_intent_id)
                    && intent_set.contains(&edge.successor_intent_id)
            })
            .collect::<Vec<_>>();
        if edge_records.len() > self.config.max_edges_per_batch {
            return Err("batch exceeds dependency edge limit".to_string());
        }
        let intent_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-BATCH-INTENTS",
            &intents
                .iter()
                .map(|intent| intent.public_record())
                .collect::<Vec<_>>(),
        );
        let dependency_edge_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-BATCH-EDGES",
            &edge_records
                .iter()
                .map(|edge| edge.public_record())
                .collect::<Vec<_>>(),
        );
        let solver_commitment_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-BATCH-SOLVERS",
            &solver_records
                .iter()
                .map(|solver| solver.public_record())
                .collect::<Vec<_>>(),
        );
        let batch_id = settlement_batch_id(
            &intent_root,
            &dependency_edge_root,
            &solver_commitment_root,
            request.built_at_height,
            self.counters.batches_built,
        );
        let batch = SettlementBatchRecord {
            batch_id: batch_id.clone(),
            intent_ids: request.intent_ids,
            solver_commitment_ids: request.solver_commitment_ids,
            intent_root,
            dependency_edge_root,
            solver_commitment_root,
            aggregate_dependency_root: request.aggregate_dependency_root,
            aggregate_pq_authorization_root: request.aggregate_pq_authorization_root,
            aggregate_low_fee_sponsor_root: request.aggregate_low_fee_sponsor_root,
            batch_witness_root: request.batch_witness_root,
            batch_proof_request_root: request.batch_proof_request_root,
            state_root_before: request.state_root_before,
            min_privacy_set_size: request.min_privacy_set_size,
            max_fee_micro_units: request.max_fee_micro_units,
            status: IntentSettlementStatus::Batched,
            built_at_height: request.built_at_height,
            expires_at_height: request.built_at_height + self.config.batch_ttl_blocks,
        };
        for intent_id in &batch.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentSettlementStatus::Batched;
            }
        }
        self.batches.insert(batch_id.clone(), batch);
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        Ok(batch_id)
    }

    pub fn settle_batch(
        &mut self,
        request: SettleBatchRequest,
    ) -> PrivateL2CrossContractIntentSettlementBusResult<String> {
        request.validate()?;
        if self.receipts.len() >= PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_MAX_RECEIPTS {
            return Err("receipt lane is at capacity".to_string());
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| format!("unknown settlement batch: {}", request.batch_id))?;
        if batch.status.terminal() {
            return Err("batch is already terminal".to_string());
        }
        if batch.state_root_before != request.state_root_before {
            return Err("settlement state root before does not match batch".to_string());
        }
        batch.status = request.status;
        let receipt_id = batched_settlement_receipt_id(
            &request.batch_id,
            &request.settlement_tx_root,
            &request.recursive_proof_root,
            request.settled_at_height,
            self.counters.receipts_published,
        );
        let receipt = BatchedSettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id.clone(),
            recursive_proof_root: request.recursive_proof_root,
            settlement_tx_root: request.settlement_tx_root,
            public_input_root: request.public_input_root,
            state_root_before: request.state_root_before,
            state_root_after: request.state_root_after,
            output_commitment_root: request.output_commitment_root,
            consumed_nullifier_root: request.consumed_nullifier_root,
            fee_settlement_root: request.fee_settlement_root,
            pq_transcript_root: request.pq_transcript_root,
            low_fee_sponsor_receipt_root: request.low_fee_sponsor_receipt_root,
            settled_fee_micro_units: request.settled_fee_micro_units,
            settled_at_height: request.settled_at_height,
            finality_height: request.settled_at_height + self.config.finality_blocks,
            status: request.status,
        };
        if let Some(batch) = self.batches.get(&receipt.batch_id) {
            for intent_id in &batch.intent_ids {
                if let Some(intent) = self.intents.get_mut(intent_id) {
                    intent.status = request.status;
                }
            }
        }
        self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        self.counters.total_settled_fee_micro_units = self
            .counters
            .total_settled_fee_micro_units
            .saturating_add(request.settled_fee_micro_units);
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn roots(&self) -> Roots {
        let intent_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-ROOT",
            &self
                .intents
                .values()
                .map(EncryptedContractIntentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let dependency_edge_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-DEPENDENCY-ROOT",
            &self
                .dependency_edges
                .values()
                .map(DependencyGraphEdgeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let solver_commitment_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-SOLVER-ROOT",
            &self
                .solver_commitments
                .values()
                .map(SolverCommitmentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let batch_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-BATCH-ROOT",
            &self
                .batches
                .values()
                .map(SettlementBatchRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-RECEIPT-ROOT",
            &self
                .receipts
                .values()
                .map(BatchedSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let replay_nullifier_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-REPLAY-NULLIFIER-ROOT",
            &self
                .replay_nullifiers
                .iter()
                .map(|nullifier| Value::String(nullifier.clone()))
                .collect::<Vec<_>>(),
        );
        let pq_authorization_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-PQ-AUTH-ROOT",
            &self
                .intents
                .values()
                .map(|intent| Value::String(intent.pq_authorization_root.clone()))
                .chain(
                    self.dependency_edges
                        .values()
                        .map(|edge| Value::String(edge.pq_authorization_root.clone())),
                )
                .chain(
                    self.solver_commitments
                        .values()
                        .map(|solver| Value::String(solver.solver_pq_authorization_root.clone())),
                )
                .collect::<Vec<_>>(),
        );
        let low_fee_sponsor_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-LOW-FEE-SPONSOR-ROOT",
            &self
                .intents
                .values()
                .map(|intent| Value::String(intent.low_fee_sponsor_root.clone()))
                .chain(
                    self.solver_commitments
                        .values()
                        .map(|solver| Value::String(solver.low_fee_sponsor_root.clone())),
                )
                .collect::<Vec<_>>(),
        );
        let public_record_root = merkle_root(
            "PRIVATE-L2-CROSS-CONTRACT-INTENT-PUBLIC-RECORD-ROOT",
            &self
                .public_records_without_state_root()
                .into_iter()
                .map(|(_, record)| record)
                .collect::<Vec<_>>(),
        );
        Roots {
            intent_root,
            dependency_edge_root,
            solver_commitment_root,
            batch_root,
            receipt_root,
            replay_nullifier_root,
            pq_authorization_root,
            low_fee_sponsor_root,
            public_record_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root(),
            "privacy_boundary": "state_public_record_exposes_roots_and_commitments_only",
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_cross_contract_intent_settlement_bus_hash(
            "STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&self.roots().public_record()),
            ],
        )
    }

    fn public_records_without_state_root(&self) -> BTreeMap<String, Value> {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        records.insert("counters".to_string(), self.counters.public_record());
        for intent in self.intents.values() {
            records.insert(
                format!("intent:{}", intent.intent_id),
                intent.public_record(),
            );
        }
        for edge in self.dependency_edges.values() {
            records.insert(format!("edge:{}", edge.edge_id), edge.public_record());
        }
        for solver in self.solver_commitments.values() {
            records.insert(
                format!("solver:{}", solver.solver_commitment_id),
                solver.public_record(),
            );
        }
        for batch in self.batches.values() {
            records.insert(format!("batch:{}", batch.batch_id), batch.public_record());
        }
        for receipt in self.receipts.values() {
            records.insert(
                format!("receipt:{}", receipt.receipt_id),
                receipt.public_record(),
            );
        }
        records
    }
}

pub fn private_l2_cross_contract_intent_settlement_bus_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_cross_contract_intent_settlement_bus_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    private_l2_cross_contract_intent_settlement_bus_hash(domain, &[HashPart::Json(payload)])
}

pub fn private_l2_cross_contract_intent_settlement_bus_hash(
    domain: &str,
    parts: &[HashPart<'_>],
) -> String {
    domain_hash(
        &format!(
            "{}:{domain}",
            PRIVATE_L2_CROSS_CONTRACT_INTENT_SETTLEMENT_BUS_PROTOCOL_VERSION
        ),
        parts,
        32,
    )
}

pub fn encrypted_intent_id(request: &SubmitEncryptedIntentRequest, nonce: u64) -> String {
    private_l2_cross_contract_intent_settlement_bus_hash(
        "ENCRYPTED-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.intent_kind.as_str()),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.contract_commitment_root),
            HashPart::Str(&request.encrypted_intent_root),
            HashPart::Str(&request.replay_nullifier),
        ],
    )
}

pub fn dependency_edge_id(
    request: &LinkDependencyEdgeRequest,
    strict_ordering: bool,
    nonce: u64,
) -> String {
    private_l2_cross_contract_intent_settlement_bus_hash(
        "DEPENDENCY-EDGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.predecessor_intent_id),
            HashPart::Str(&request.successor_intent_id),
            HashPart::Str(request.dependency_kind.as_str()),
            HashPart::Str(&request.resource_commitment),
            HashPart::Int(strict_ordering as i128),
        ],
    )
}

pub fn solver_commitment_id(request: &PostSolverCommitmentRequest, nonce: u64) -> String {
    private_l2_cross_contract_intent_settlement_bus_hash(
        "SOLVER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.solver_commitment),
            HashPart::Str(&request.route_commitment_root),
            HashPart::Str(&request.fill_commitment_root),
            HashPart::Str(&request.constraint_satisfaction_root),
        ],
    )
}

pub fn settlement_batch_id(
    intent_root: &str,
    dependency_edge_root: &str,
    solver_commitment_root: &str,
    built_at_height: u64,
    nonce: u64,
) -> String {
    private_l2_cross_contract_intent_settlement_bus_hash(
        "SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(intent_root),
            HashPart::Str(dependency_edge_root),
            HashPart::Str(solver_commitment_root),
            HashPart::Int(built_at_height as i128),
        ],
    )
}

pub fn batched_settlement_receipt_id(
    batch_id: &str,
    settlement_tx_root: &str,
    recursive_proof_root: &str,
    settled_at_height: u64,
    nonce: u64,
) -> String {
    private_l2_cross_contract_intent_settlement_bus_hash(
        "BATCHED-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_tx_root),
            HashPart::Str(recursive_proof_root),
            HashPart::Int(settled_at_height as i128),
        ],
    )
}

fn ensure_non_empty(
    value: &str,
    label: &str,
) -> PrivateL2CrossContractIntentSettlementBusResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_unique(
    values: &[String],
    label: &str,
) -> PrivateL2CrossContractIntentSettlementBusResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("duplicate {label}: {value}"));
        }
    }
    Ok(())
}

fn would_create_cycle(
    edges: &BTreeMap<String, DependencyGraphEdgeRecord>,
    candidate: &DependencyGraphEdgeRecord,
) -> bool {
    let mut stack = vec![candidate.successor_intent_id.clone()];
    let mut visited = BTreeSet::new();
    while let Some(current) = stack.pop() {
        if current == candidate.predecessor_intent_id {
            return true;
        }
        if !visited.insert(current.clone()) {
            continue;
        }
        for edge in edges.values() {
            if edge.predecessor_intent_id == current {
                stack.push(edge.successor_intent_id.clone());
            }
        }
    }
    false
}
