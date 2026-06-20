use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ZkContractComposabilitySettlementResult<T> = Result<T, String>;

pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_PROTOCOL_VERSION: &str =
    "nebula-private-l2-zk-contract-composability-settlement-v1";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEVNET_HEIGHT: u64 = 512;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_HASH_SCHEME: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_ZK_VM_SCHEME: &str =
    "nebula-private-l2-composable-zkvm-v1";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_RECURSION_SCHEME: &str =
    "fri-folded-private-contract-dag-settlement-v1";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_PQ_AUTH_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_CALL_COMMITMENT_SCHEME: &str =
    "roots-only-private-contract-call-commitment-v1";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEPENDENCY_SCHEME: &str =
    "private-contract-dag-dependency-root-v1";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_BATCH_SCHEME: &str =
    "atomic-private-contract-settlement-batch-v1";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_SPONSOR_SCHEME: &str =
    "low-fee-private-zk-call-sponsor-root-v1";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_RECEIPT_SCHEME: &str =
    "roots-only-final-private-contract-settlement-receipt-v1";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_NULLIFIER_SCHEME: &str =
    "private-composable-call-replay-nullifier-v1";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_LOW_FEE_LANE: &str =
    "private-l2-zk-contract-composability";
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_BATCH_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_CALL_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_FINALITY_BLOCKS: u64 = 12;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MAX_CALLS_PER_BATCH: usize = 64;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MAX_DEPENDENCIES_PER_BATCH:
    usize = 192;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_DEFI_PRIVACY_SET_SIZE: u64 = 512;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_TARGET_VERIFY_MICROS: u64 =
    12_000;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MAX_FEE_MICRO_UNITS: u64 = 1_800;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_SPONSORED_FEE_MICRO_UNITS: u64 =
    900;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_000;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_PENDING_CALLS: usize = 262_144;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_DEPENDENCY_EDGES: usize = 524_288;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_BATCHES: usize = 131_072;
pub const PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_RECEIPTS: usize = 131_072;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateContractCallKind {
    ShieldedContract,
    PrivateTokenTransfer,
    PrivateTokenMint,
    PrivateTokenBurn,
    ConfidentialAmmSwap,
    ConfidentialAmmLiquidity,
    PrivateLendingSupply,
    PrivateLendingBorrow,
    PrivateLendingRepay,
    PrivateLendingWithdraw,
    PrivatePerpOpen,
    PrivatePerpClose,
    PrivateOptionsExercise,
    PrivateVaultDeposit,
    PrivateVaultWithdraw,
    OracleRead,
    Callback,
    SettlementHook,
    Custom(String),
}

impl PrivateContractCallKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::ShieldedContract => "shielded_contract".to_string(),
            Self::PrivateTokenTransfer => "private_token_transfer".to_string(),
            Self::PrivateTokenMint => "private_token_mint".to_string(),
            Self::PrivateTokenBurn => "private_token_burn".to_string(),
            Self::ConfidentialAmmSwap => "confidential_amm_swap".to_string(),
            Self::ConfidentialAmmLiquidity => "confidential_amm_liquidity".to_string(),
            Self::PrivateLendingSupply => "private_lending_supply".to_string(),
            Self::PrivateLendingBorrow => "private_lending_borrow".to_string(),
            Self::PrivateLendingRepay => "private_lending_repay".to_string(),
            Self::PrivateLendingWithdraw => "private_lending_withdraw".to_string(),
            Self::PrivatePerpOpen => "private_perp_open".to_string(),
            Self::PrivatePerpClose => "private_perp_close".to_string(),
            Self::PrivateOptionsExercise => "private_options_exercise".to_string(),
            Self::PrivateVaultDeposit => "private_vault_deposit".to_string(),
            Self::PrivateVaultWithdraw => "private_vault_withdraw".to_string(),
            Self::OracleRead => "oracle_read".to_string(),
            Self::Callback => "callback".to_string(),
            Self::SettlementHook => "settlement_hook".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn defi(self: &Self) -> bool {
        matches!(
            self,
            Self::ConfidentialAmmSwap
                | Self::ConfidentialAmmLiquidity
                | Self::PrivateLendingSupply
                | Self::PrivateLendingBorrow
                | Self::PrivateLendingRepay
                | Self::PrivateLendingWithdraw
                | Self::PrivatePerpOpen
                | Self::PrivatePerpClose
                | Self::PrivateOptionsExercise
                | Self::PrivateVaultDeposit
                | Self::PrivateVaultWithdraw
        )
    }

    pub fn default_priority_weight(&self) -> u64 {
        match self {
            Self::SettlementHook => 9_600,
            Self::PrivatePerpClose | Self::PrivateLendingRepay | Self::PrivateLendingWithdraw => {
                9_000
            }
            Self::ConfidentialAmmSwap | Self::PrivateLendingBorrow | Self::PrivateLendingSupply => {
                8_400
            }
            Self::PrivatePerpOpen | Self::PrivateOptionsExercise => 8_100,
            Self::ConfidentialAmmLiquidity
            | Self::PrivateVaultDeposit
            | Self::PrivateVaultWithdraw => 7_700,
            Self::ShieldedContract | Self::Callback => 7_300,
            Self::PrivateTokenTransfer | Self::PrivateTokenMint | Self::PrivateTokenBurn => 6_800,
            Self::OracleRead => 6_000,
            Self::Custom(_) => 6_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    ReadAfterWrite,
    WriteAfterRead,
    WriteAfterWrite,
    AssetConservation,
    NullifierOrdering,
    OracleFreshness,
    CallbackOrdering,
    FeeSponsorPrepay,
    SettlementBarrier,
}

impl DependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadAfterWrite => "read_after_write",
            Self::WriteAfterRead => "write_after_read",
            Self::WriteAfterWrite => "write_after_write",
            Self::AssetConservation => "asset_conservation",
            Self::NullifierOrdering => "nullifier_ordering",
            Self::OracleFreshness => "oracle_freshness",
            Self::CallbackOrdering => "callback_ordering",
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
                | Self::SettlementBarrier
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    GraphLinked,
    Batched,
    Proving,
    Proven,
    Settled,
    Failed,
    Expired,
    Cancelled,
    Challenged,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::GraphLinked => "graph_linked",
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
        matches!(self, Self::Pending | Self::GraphLinked)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Failed | Self::Expired | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub hash_scheme: String,
    pub zk_vm_scheme: String,
    pub recursion_scheme: String,
    pub pq_auth_scheme: String,
    pub call_commitment_scheme: String,
    pub dependency_scheme: String,
    pub batch_scheme: String,
    pub sponsor_scheme: String,
    pub receipt_scheme: String,
    pub nullifier_scheme: String,
    pub batch_ttl_blocks: u64,
    pub call_ttl_blocks: u64,
    pub finality_blocks: u64,
    pub max_calls_per_batch: usize,
    pub max_dependencies_per_batch: usize,
    pub min_privacy_set_size: u64,
    pub defi_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_verify_micros: u64,
    pub max_fee_micro_units: u64,
    pub sponsored_fee_micro_units: u64,
    pub sponsor_rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_L2_NETWORK
                .to_string(),
            monero_network: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MONERO_NETWORK
                .to_string(),
            fee_asset_id: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_FEE_ASSET_ID
                .to_string(),
            low_fee_lane: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_LOW_FEE_LANE
                .to_string(),
            hash_scheme: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_HASH_SCHEME.to_string(),
            zk_vm_scheme: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_ZK_VM_SCHEME.to_string(),
            recursion_scheme: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_RECURSION_SCHEME
                .to_string(),
            pq_auth_scheme: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_PQ_AUTH_SCHEME
                .to_string(),
            call_commitment_scheme:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_CALL_COMMITMENT_SCHEME.to_string(),
            dependency_scheme: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEPENDENCY_SCHEME
                .to_string(),
            batch_scheme: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_BATCH_SCHEME.to_string(),
            sponsor_scheme: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_SPONSOR_SCHEME
                .to_string(),
            receipt_scheme: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_RECEIPT_SCHEME
                .to_string(),
            nullifier_scheme: PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_NULLIFIER_SCHEME
                .to_string(),
            batch_ttl_blocks:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_BATCH_TTL_BLOCKS,
            call_ttl_blocks:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_CALL_TTL_BLOCKS,
            finality_blocks:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_FINALITY_BLOCKS,
            max_calls_per_batch:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MAX_CALLS_PER_BATCH,
            max_dependencies_per_batch:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MAX_DEPENDENCIES_PER_BATCH,
            min_privacy_set_size:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MIN_PRIVACY_SET_SIZE,
            defi_privacy_set_size:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_DEFI_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_verify_micros:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_TARGET_VERIFY_MICROS,
            max_fee_micro_units:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MAX_FEE_MICRO_UNITS,
            sponsored_fee_micro_units:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_SPONSORED_FEE_MICRO_UNITS,
            sponsor_rebate_bps:
                PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_SPONSOR_REBATE_BPS,
        }
    }

    pub fn validate(&self) -> PrivateL2ZkContractComposabilitySettlementResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_non_empty(&self.l2_network, "l2 network")?;
        ensure_non_empty(&self.monero_network, "monero network")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_non_empty(&self.low_fee_lane, "low fee lane")?;
        ensure_non_empty(&self.hash_scheme, "hash scheme")?;
        ensure_non_empty(&self.zk_vm_scheme, "zk vm scheme")?;
        ensure_non_empty(&self.recursion_scheme, "recursion scheme")?;
        ensure_non_empty(&self.pq_auth_scheme, "pq auth scheme")?;
        ensure_non_empty(&self.call_commitment_scheme, "call commitment scheme")?;
        ensure_non_empty(&self.dependency_scheme, "dependency scheme")?;
        ensure_non_empty(&self.batch_scheme, "batch scheme")?;
        ensure_non_empty(&self.sponsor_scheme, "sponsor scheme")?;
        ensure_non_empty(&self.receipt_scheme, "receipt scheme")?;
        ensure_non_empty(&self.nullifier_scheme, "nullifier scheme")?;
        if self.schema_version == 0 {
            return Err("schema version must be non-zero".to_string());
        }
        if self.batch_ttl_blocks == 0 || self.call_ttl_blocks == 0 || self.finality_blocks == 0 {
            return Err("ttl and finality windows must be non-zero".to_string());
        }
        if self.max_calls_per_batch == 0
            || self.max_calls_per_batch
                > PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_DEFAULT_MAX_CALLS_PER_BATCH
        {
            return Err("max calls per batch is outside supported bounds".to_string());
        }
        if self.max_dependencies_per_batch == 0 {
            return Err("max dependencies per batch must be non-zero".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.defi_privacy_set_size < self.min_privacy_set_size
            || self.min_pq_security_bits == 0
        {
            return Err("privacy and pq security floors are invalid".to_string());
        }
        if self.max_fee_micro_units == 0
            || self.sponsored_fee_micro_units > self.max_fee_micro_units
            || self.sponsor_rebate_bps > PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_BPS
        {
            return Err("fee sponsorship policy is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "hash_scheme": self.hash_scheme,
            "zk_vm_scheme": self.zk_vm_scheme,
            "recursion_scheme": self.recursion_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "call_commitment_scheme": self.call_commitment_scheme,
            "dependency_scheme": self.dependency_scheme,
            "batch_scheme": self.batch_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "receipt_scheme": self.receipt_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "call_ttl_blocks": self.call_ttl_blocks,
            "finality_blocks": self.finality_blocks,
            "max_calls_per_batch": self.max_calls_per_batch,
            "max_dependencies_per_batch": self.max_dependencies_per_batch,
            "min_privacy_set_size": self.min_privacy_set_size,
            "defi_privacy_set_size": self.defi_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_verify_micros": self.target_verify_micros,
            "max_fee_micro_units": self.max_fee_micro_units,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub calls_submitted: u64,
    pub dependencies_linked: u64,
    pub graphs_built: u64,
    pub batches_built: u64,
    pub batches_settled: u64,
    pub sponsor_receipts: u64,
    pub final_receipts: u64,
    pub replay_rejections: u64,
    pub privacy_floor_rejections: u64,
    pub pq_security_rejections: u64,
    pub total_sponsored_fee_micro_units: u64,
    pub total_settled_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "calls_submitted": self.calls_submitted,
            "dependencies_linked": self.dependencies_linked,
            "graphs_built": self.graphs_built,
            "batches_built": self.batches_built,
            "batches_settled": self.batches_settled,
            "sponsor_receipts": self.sponsor_receipts,
            "final_receipts": self.final_receipts,
            "replay_rejections": self.replay_rejections,
            "privacy_floor_rejections": self.privacy_floor_rejections,
            "pq_security_rejections": self.pq_security_rejections,
            "total_sponsored_fee_micro_units": self.total_sponsored_fee_micro_units,
            "total_settled_fee_micro_units": self.total_settled_fee_micro_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitCallRequest {
    pub call_kind: PrivateContractCallKind,
    pub contract_commitment: String,
    pub selector_commitment: String,
    pub encrypted_calldata_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub state_read_root: String,
    pub state_write_root: String,
    pub callback_root: String,
    pub proof_request_root: String,
    pub pq_auth_root: String,
    pub pq_key_committee_root: String,
    pub fee_quote_root: String,
    pub sponsor_policy_root: String,
    pub replay_nullifier: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_micro_units: u64,
    pub priority_weight: Option<u64>,
    pub expires_at_height: u64,
    pub submitted_at_height: u64,
}

impl SubmitCallRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ZkContractComposabilitySettlementResult<()> {
        ensure_non_empty(&self.contract_commitment, "contract commitment")?;
        ensure_non_empty(&self.selector_commitment, "selector commitment")?;
        ensure_non_empty(&self.encrypted_calldata_root, "encrypted calldata root")?;
        ensure_non_empty(&self.input_note_root, "input note root")?;
        ensure_non_empty(&self.output_note_root, "output note root")?;
        ensure_non_empty(&self.state_read_root, "state read root")?;
        ensure_non_empty(&self.state_write_root, "state write root")?;
        ensure_non_empty(&self.callback_root, "callback root")?;
        ensure_non_empty(&self.proof_request_root, "proof request root")?;
        ensure_non_empty(&self.pq_auth_root, "pq auth root")?;
        ensure_non_empty(&self.pq_key_committee_root, "pq key committee root")?;
        ensure_non_empty(&self.fee_quote_root, "fee quote root")?;
        ensure_non_empty(&self.sponsor_policy_root, "sponsor policy root")?;
        ensure_non_empty(&self.replay_nullifier, "replay nullifier")?;
        let privacy_floor = if self.call_kind.defi() {
            config.defi_privacy_set_size
        } else {
            config.min_privacy_set_size
        };
        if self.min_privacy_set_size < privacy_floor {
            return Err(format!(
                "privacy set floor {} is below required {}",
                self.min_privacy_set_size, privacy_floor
            ));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "pq security bits {} below required {}",
                self.pq_security_bits, config.min_pq_security_bits
            ));
        }
        if self.max_fee_micro_units == 0 || self.max_fee_micro_units > config.max_fee_micro_units {
            return Err("max fee exceeds lane cap".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("call expiry must be after submission height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkDependencyRequest {
    pub predecessor_call_id: String,
    pub successor_call_id: String,
    pub dependency_kind: DependencyKind,
    pub resource_commitment: String,
    pub read_root: String,
    pub write_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub pq_auth_root: String,
    pub strict_ordering: bool,
    pub linked_at_height: u64,
}

impl LinkDependencyRequest {
    pub fn validate(&self) -> PrivateL2ZkContractComposabilitySettlementResult<()> {
        ensure_non_empty(&self.predecessor_call_id, "predecessor call id")?;
        ensure_non_empty(&self.successor_call_id, "successor call id")?;
        ensure_non_empty(&self.resource_commitment, "resource commitment")?;
        ensure_non_empty(&self.read_root, "dependency read root")?;
        ensure_non_empty(&self.write_root, "dependency write root")?;
        ensure_non_empty(&self.nullifier_root, "dependency nullifier root")?;
        ensure_non_empty(&self.proof_root, "dependency proof root")?;
        ensure_non_empty(&self.pq_auth_root, "dependency pq auth root")?;
        if self.predecessor_call_id == self.successor_call_id {
            return Err("dependency cannot point to the same call".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildBatchRequest {
    pub call_ids: Vec<String>,
    pub sponsor_commitment: String,
    pub sponsor_budget_root: String,
    pub fee_asset_id: String,
    pub low_fee_policy_root: String,
    pub batch_proof_request_root: String,
    pub pq_batch_auth_root: String,
    pub aggregator_commitment: String,
    pub min_privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub build_at_height: u64,
}

impl BuildBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ZkContractComposabilitySettlementResult<()> {
        if self.call_ids.is_empty() {
            return Err("batch must include at least one call".to_string());
        }
        if self.call_ids.len() > config.max_calls_per_batch {
            return Err("batch exceeds max call count".to_string());
        }
        ensure_unique(&self.call_ids, "batch call id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&self.sponsor_budget_root, "sponsor budget root")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_non_empty(&self.low_fee_policy_root, "low fee policy root")?;
        ensure_non_empty(&self.batch_proof_request_root, "batch proof request root")?;
        ensure_non_empty(&self.pq_batch_auth_root, "pq batch auth root")?;
        ensure_non_empty(&self.aggregator_commitment, "aggregator commitment")?;
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("batch privacy set floor is below lane minimum".to_string());
        }
        if self.max_fee_micro_units == 0 || self.max_fee_micro_units > config.max_fee_micro_units {
            return Err("batch fee cap exceeds lane cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub recursive_proof_root: String,
    pub public_input_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub output_commitment_root: String,
    pub nullifier_root: String,
    pub fee_settlement_root: String,
    pub pq_transcript_root: String,
    pub verifier_key_root: String,
    pub sponsor_receipt_root: String,
    pub settled_fee_micro_units: u64,
    pub settled_at_height: u64,
    pub status: SettlementStatus,
}

impl SettleBatchRequest {
    pub fn validate(&self) -> PrivateL2ZkContractComposabilitySettlementResult<()> {
        ensure_non_empty(&self.batch_id, "batch id")?;
        ensure_non_empty(&self.recursive_proof_root, "recursive proof root")?;
        ensure_non_empty(&self.public_input_root, "public input root")?;
        ensure_non_empty(&self.state_root_before, "state root before")?;
        ensure_non_empty(&self.state_root_after, "state root after")?;
        ensure_non_empty(&self.output_commitment_root, "output commitment root")?;
        ensure_non_empty(&self.nullifier_root, "nullifier root")?;
        ensure_non_empty(&self.fee_settlement_root, "fee settlement root")?;
        ensure_non_empty(&self.pq_transcript_root, "pq transcript root")?;
        ensure_non_empty(&self.verifier_key_root, "verifier key root")?;
        ensure_non_empty(&self.sponsor_receipt_root, "sponsor receipt root")?;
        if !matches!(
            self.status,
            SettlementStatus::Settled | SettlementStatus::Failed
        ) {
            return Err("settlement request status must be settled or failed".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateContractCallRecord {
    pub call_id: String,
    pub call_kind: PrivateContractCallKind,
    pub contract_commitment: String,
    pub selector_commitment: String,
    pub encrypted_calldata_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub state_read_root: String,
    pub state_write_root: String,
    pub callback_root: String,
    pub proof_request_root: String,
    pub pq_auth_root: String,
    pub pq_key_committee_root: String,
    pub fee_quote_root: String,
    pub sponsor_policy_root: String,
    pub replay_nullifier: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_micro_units: u64,
    pub priority_weight: u64,
    pub status: SettlementStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateContractCallRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "call_kind": self.call_kind.as_str(),
            "contract_commitment": self.contract_commitment,
            "selector_commitment": self.selector_commitment,
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "state_read_root": self.state_read_root,
            "state_write_root": self.state_write_root,
            "callback_root": self.callback_root,
            "proof_request_root": self.proof_request_root,
            "pq_auth_root": self.pq_auth_root,
            "pq_key_committee_root": self.pq_key_committee_root,
            "fee_quote_root": self.fee_quote_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "replay_nullifier": self.replay_nullifier,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_micro_units": self.max_fee_micro_units,
            "priority_weight": self.priority_weight,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_boundary": "roots_and_commitments_only_no_plaintext_accounts_or_calldata",
        })
    }

    pub fn root(&self) -> String {
        lane_root("CALL-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyEdgeRecord {
    pub edge_id: String,
    pub predecessor_call_id: String,
    pub successor_call_id: String,
    pub dependency_kind: DependencyKind,
    pub resource_commitment: String,
    pub read_root: String,
    pub write_root: String,
    pub nullifier_root: String,
    pub proof_root: String,
    pub pq_auth_root: String,
    pub strict_ordering: bool,
    pub linked_at_height: u64,
}

impl DependencyEdgeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "edge_id": self.edge_id,
            "predecessor_call_id": self.predecessor_call_id,
            "successor_call_id": self.successor_call_id,
            "dependency_kind": self.dependency_kind.as_str(),
            "resource_commitment": self.resource_commitment,
            "read_root": self.read_root,
            "write_root": self.write_root,
            "nullifier_root": self.nullifier_root,
            "proof_root": self.proof_root,
            "pq_auth_root": self.pq_auth_root,
            "strict_ordering": self.strict_ordering,
            "linked_at_height": self.linked_at_height,
        })
    }

    pub fn root(&self) -> String {
        lane_root("DEPENDENCY-EDGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyDagRecord {
    pub dag_id: String,
    pub call_ids: Vec<String>,
    pub edge_ids: Vec<String>,
    pub call_root: String,
    pub edge_root: String,
    pub adjacency_root: String,
    pub topological_order_root: String,
    pub nullifier_root: String,
    pub pq_auth_root: String,
    pub min_privacy_set_size: u64,
    pub max_pq_security_floor_bits: u16,
    pub built_at_height: u64,
}

impl DependencyDagRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "dag_id": self.dag_id,
            "call_root": self.call_root,
            "edge_root": self.edge_root,
            "adjacency_root": self.adjacency_root,
            "topological_order_root": self.topological_order_root,
            "nullifier_root": self.nullifier_root,
            "pq_auth_root": self.pq_auth_root,
            "call_count": self.call_ids.len(),
            "edge_count": self.edge_ids.len(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_pq_security_floor_bits": self.max_pq_security_floor_bits,
            "built_at_height": self.built_at_height,
        })
    }

    pub fn root(&self) -> String {
        lane_root("DEPENDENCY-DAG", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeSponsorReceipt {
    pub sponsor_receipt_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub sponsor_budget_root: String,
    pub low_fee_policy_root: String,
    pub fee_asset_id: String,
    pub sponsored_fee_micro_units: u64,
    pub rebate_bps: u64,
    pub rebate_commitment_root: String,
    pub pq_auth_root: String,
    pub issued_at_height: u64,
}

impl FeeSponsorReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_receipt_id": self.sponsor_receipt_id,
            "batch_id": self.batch_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_budget_root": self.sponsor_budget_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "fee_asset_id": self.fee_asset_id,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "rebate_commitment_root": self.rebate_commitment_root,
            "pq_auth_root": self.pq_auth_root,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn root(&self) -> String {
        lane_root("FEE-SPONSOR-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicSettlementBatchRecord {
    pub batch_id: String,
    pub dag_id: String,
    pub call_ids: Vec<String>,
    pub dependency_edge_ids: Vec<String>,
    pub call_root: String,
    pub dependency_root: String,
    pub dag_root: String,
    pub sponsor_receipt_root: String,
    pub batch_proof_request_root: String,
    pub pq_batch_auth_root: String,
    pub aggregator_commitment: String,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub pq_security_floor_bits: u16,
    pub max_fee_micro_units: u64,
    pub status: SettlementStatus,
    pub build_at_height: u64,
    pub expires_at_height: u64,
}

impl AtomicSettlementBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "dag_id": self.dag_id,
            "call_count": self.call_ids.len(),
            "dependency_edge_count": self.dependency_edge_ids.len(),
            "call_root": self.call_root,
            "dependency_root": self.dependency_root,
            "dag_root": self.dag_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "batch_proof_request_root": self.batch_proof_request_root,
            "pq_batch_auth_root": self.pq_batch_auth_root,
            "aggregator_commitment": self.aggregator_commitment,
            "low_fee_lane": self.low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_floor_bits": self.pq_security_floor_bits,
            "max_fee_micro_units": self.max_fee_micro_units,
            "status": self.status.as_str(),
            "build_at_height": self.build_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        lane_root("ATOMIC-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalSettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub dag_id: String,
    pub recursive_proof_root: String,
    pub public_input_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub output_commitment_root: String,
    pub nullifier_root: String,
    pub fee_settlement_root: String,
    pub pq_transcript_root: String,
    pub verifier_key_root: String,
    pub sponsor_receipt_root: String,
    pub settled_fee_micro_units: u64,
    pub settled_at_height: u64,
    pub finality_height: u64,
    pub status: SettlementStatus,
}

impl FinalSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "dag_id": self.dag_id,
            "recursive_proof_root": self.recursive_proof_root,
            "public_input_root": self.public_input_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "output_commitment_root": self.output_commitment_root,
            "nullifier_root": self.nullifier_root,
            "fee_settlement_root": self.fee_settlement_root,
            "pq_transcript_root": self.pq_transcript_root,
            "verifier_key_root": self.verifier_key_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "settled_fee_micro_units": self.settled_fee_micro_units,
            "settled_at_height": self.settled_at_height,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
            "privacy_boundary": "final_receipt_exposes_roots_only",
        })
    }

    pub fn root(&self) -> String {
        lane_root("FINAL-SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub call_root: String,
    pub dependency_edge_root: String,
    pub dag_root: String,
    pub batch_root: String,
    pub sponsor_receipt_root: String,
    pub final_receipt_root: String,
    pub replay_nullifier_root: String,
    pub pq_auth_root: String,
    pub low_fee_sponsor_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "call_root": self.call_root,
            "dependency_edge_root": self.dependency_edge_root,
            "dag_root": self.dag_root,
            "batch_root": self.batch_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "final_receipt_root": self.final_receipt_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "pq_auth_root": self.pq_auth_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub calls: BTreeMap<String, PrivateContractCallRecord>,
    pub dependency_edges: BTreeMap<String, DependencyEdgeRecord>,
    pub dags: BTreeMap<String, DependencyDagRecord>,
    pub batches: BTreeMap<String, AtomicSettlementBatchRecord>,
    pub sponsor_receipts: BTreeMap<String, FeeSponsorReceipt>,
    pub final_receipts: BTreeMap<String, FinalSettlementReceipt>,
    pub replay_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2ZkContractComposabilitySettlementResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            calls: BTreeMap::new(),
            dependency_edges: BTreeMap::new(),
            dags: BTreeMap::new(),
            batches: BTreeMap::new(),
            sponsor_receipts: BTreeMap::new(),
            final_receipts: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
        })
    }

    pub fn submit_call(
        &mut self,
        request: SubmitCallRequest,
    ) -> PrivateL2ZkContractComposabilitySettlementResult<String> {
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
        if self.calls.len() >= PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_PENDING_CALLS {
            return Err("private call lane is at capacity".to_string());
        }
        if self.replay_nullifiers.contains(&request.replay_nullifier) {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("replay nullifier already observed".to_string());
        }
        let nonce = self.counters.calls_submitted;
        let call_id = call_id(&request, nonce);
        let priority_weight = request
            .priority_weight
            .unwrap_or_else(|| request.call_kind.default_priority_weight());
        let record = PrivateContractCallRecord {
            call_id: call_id.clone(),
            call_kind: request.call_kind,
            contract_commitment: request.contract_commitment,
            selector_commitment: request.selector_commitment,
            encrypted_calldata_root: request.encrypted_calldata_root,
            input_note_root: request.input_note_root,
            output_note_root: request.output_note_root,
            state_read_root: request.state_read_root,
            state_write_root: request.state_write_root,
            callback_root: request.callback_root,
            proof_request_root: request.proof_request_root,
            pq_auth_root: request.pq_auth_root,
            pq_key_committee_root: request.pq_key_committee_root,
            fee_quote_root: request.fee_quote_root,
            sponsor_policy_root: request.sponsor_policy_root,
            replay_nullifier: request.replay_nullifier.clone(),
            min_privacy_set_size: request.min_privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_micro_units: request.max_fee_micro_units,
            priority_weight,
            status: SettlementStatus::Pending,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
        };
        self.replay_nullifiers.insert(request.replay_nullifier);
        self.calls.insert(call_id.clone(), record);
        self.counters.calls_submitted = self.counters.calls_submitted.saturating_add(1);
        Ok(call_id)
    }

    pub fn link_dependency(
        &mut self,
        request: LinkDependencyRequest,
    ) -> PrivateL2ZkContractComposabilitySettlementResult<String> {
        request.validate()?;
        if self.dependency_edges.len()
            >= PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_DEPENDENCY_EDGES
        {
            return Err("dependency edge lane is at capacity".to_string());
        }
        let predecessor = self
            .calls
            .get(&request.predecessor_call_id)
            .ok_or_else(|| format!("unknown predecessor call: {}", request.predecessor_call_id))?;
        let successor = self
            .calls
            .get(&request.successor_call_id)
            .ok_or_else(|| format!("unknown successor call: {}", request.successor_call_id))?;
        if predecessor.status.terminal() || successor.status.terminal() {
            return Err("cannot link terminal calls".to_string());
        }
        let strict_ordering = request.strict_ordering || request.dependency_kind.strict();
        let nonce = self.counters.dependencies_linked;
        let edge_id = dependency_edge_id(&request, strict_ordering, nonce);
        let edge = DependencyEdgeRecord {
            edge_id: edge_id.clone(),
            predecessor_call_id: request.predecessor_call_id,
            successor_call_id: request.successor_call_id,
            dependency_kind: request.dependency_kind,
            resource_commitment: request.resource_commitment,
            read_root: request.read_root,
            write_root: request.write_root,
            nullifier_root: request.nullifier_root,
            proof_root: request.proof_root,
            pq_auth_root: request.pq_auth_root,
            strict_ordering,
            linked_at_height: request.linked_at_height,
        };
        if would_create_cycle(&self.dependency_edges, &edge) {
            return Err("dependency would create a cycle".to_string());
        }
        if let Some(call) = self.calls.get_mut(&edge.predecessor_call_id) {
            call.status = SettlementStatus::GraphLinked;
        }
        if let Some(call) = self.calls.get_mut(&edge.successor_call_id) {
            call.status = SettlementStatus::GraphLinked;
        }
        self.dependency_edges.insert(edge_id.clone(), edge);
        self.counters.dependencies_linked = self.counters.dependencies_linked.saturating_add(1);
        Ok(edge_id)
    }

    pub fn build_graph(
        &mut self,
        call_ids: Vec<String>,
        built_at_height: u64,
    ) -> PrivateL2ZkContractComposabilitySettlementResult<String> {
        if call_ids.is_empty() {
            return Err("graph must include at least one call".to_string());
        }
        if call_ids.len() > self.config.max_calls_per_batch {
            return Err("graph exceeds max calls per batch".to_string());
        }
        ensure_unique(&call_ids, "graph call id")?;
        let call_set = call_ids.iter().cloned().collect::<BTreeSet<_>>();
        let calls = call_ids
            .iter()
            .map(|id| {
                self.calls
                    .get(id)
                    .ok_or_else(|| format!("unknown graph call: {id}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if calls.iter().any(|call| !call.status.open()) {
            return Err("graph can only include pending or graph-linked calls".to_string());
        }
        let edge_ids = self
            .dependency_edges
            .values()
            .filter(|edge| {
                call_set.contains(&edge.predecessor_call_id)
                    && call_set.contains(&edge.successor_call_id)
            })
            .map(|edge| edge.edge_id.clone())
            .collect::<Vec<_>>();
        if edge_ids.len() > self.config.max_dependencies_per_batch {
            return Err("graph exceeds dependency limit".to_string());
        }
        let call_records = calls
            .iter()
            .map(|call| call.public_record())
            .collect::<Vec<_>>();
        let edge_records = edge_ids
            .iter()
            .filter_map(|id| self.dependency_edges.get(id))
            .map(DependencyEdgeRecord::public_record)
            .collect::<Vec<_>>();
        let adjacency = adjacency_record(&edge_records);
        let order = topological_order(&call_ids, &edge_ids, &self.dependency_edges)?;
        let pq_auths = calls
            .iter()
            .map(|call| Value::String(call.pq_auth_root.clone()))
            .collect::<Vec<_>>();
        let nullifiers = calls
            .iter()
            .map(|call| Value::String(call.replay_nullifier.clone()))
            .collect::<Vec<_>>();
        let min_privacy_set_size = calls
            .iter()
            .map(|call| call.min_privacy_set_size)
            .min()
            .unwrap_or(self.config.min_privacy_set_size);
        let max_pq_security_floor_bits = calls
            .iter()
            .map(|call| call.pq_security_bits)
            .min()
            .unwrap_or(self.config.min_pq_security_bits);
        let call_root = merkle_root("PRIVATE-L2-ZK-COMPOSABILITY-CALLS", &call_records);
        let edge_root = merkle_root("PRIVATE-L2-ZK-COMPOSABILITY-EDGES", &edge_records);
        let adjacency_root = lane_root("DAG-ADJACENCY", &adjacency);
        let topological_order_root = merkle_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-TOPOLOGICAL-ORDER",
            &order
                .iter()
                .map(|id| Value::String(id.clone()))
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root("PRIVATE-L2-ZK-COMPOSABILITY-NULLIFIERS", &nullifiers);
        let pq_auth_root = merkle_root("PRIVATE-L2-ZK-COMPOSABILITY-PQ-AUTH", &pq_auths);
        let dag_id = dag_id(
            &call_root,
            &edge_root,
            &topological_order_root,
            built_at_height,
            self.counters.graphs_built,
        );
        let dag = DependencyDagRecord {
            dag_id: dag_id.clone(),
            call_ids,
            edge_ids,
            call_root,
            edge_root,
            adjacency_root,
            topological_order_root,
            nullifier_root,
            pq_auth_root,
            min_privacy_set_size,
            max_pq_security_floor_bits,
            built_at_height,
        };
        self.dags.insert(dag_id.clone(), dag);
        self.counters.graphs_built = self.counters.graphs_built.saturating_add(1);
        Ok(dag_id)
    }

    pub fn build_batch(
        &mut self,
        request: BuildBatchRequest,
    ) -> PrivateL2ZkContractComposabilitySettlementResult<String> {
        request.validate(&self.config)?;
        if self.batches.len() >= PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_BATCHES {
            return Err("batch lane is at capacity".to_string());
        }
        let dag_id = self.build_graph(request.call_ids.clone(), request.build_at_height)?;
        let dag = self
            .dags
            .get(&dag_id)
            .ok_or_else(|| format!("missing graph after build: {dag_id}"))?
            .clone();
        if dag.min_privacy_set_size < request.min_privacy_set_size {
            return Err("batch request privacy floor exceeds graph floor".to_string());
        }
        if dag.max_pq_security_floor_bits < self.config.min_pq_security_bits {
            self.counters.pq_security_rejections =
                self.counters.pq_security_rejections.saturating_add(1);
            return Err("graph pq security floor below config".to_string());
        }
        let sponsor_receipt_id = sponsor_receipt_id(
            &dag_id,
            &request.sponsor_commitment,
            &request.sponsor_budget_root,
            request.build_at_height,
            self.counters.sponsor_receipts,
        );
        let sponsored_fee_micro_units = request
            .max_fee_micro_units
            .min(self.config.sponsored_fee_micro_units)
            .saturating_mul(dag.call_ids.len() as u64);
        let rebate_commitment_root = lane_hash(
            "SPONSOR-REBATE-COMMITMENT-ROOT",
            &[
                HashPart::Str(&sponsor_receipt_id),
                HashPart::Str(&request.low_fee_policy_root),
                HashPart::Int(sponsored_fee_micro_units as i128),
            ],
        );
        let sponsor_receipt = FeeSponsorReceipt {
            sponsor_receipt_id: sponsor_receipt_id.clone(),
            batch_id: dag_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            sponsor_budget_root: request.sponsor_budget_root,
            low_fee_policy_root: request.low_fee_policy_root,
            fee_asset_id: request.fee_asset_id.clone(),
            sponsored_fee_micro_units,
            rebate_bps: self.config.sponsor_rebate_bps,
            rebate_commitment_root,
            pq_auth_root: request.pq_batch_auth_root.clone(),
            issued_at_height: request.build_at_height,
        };
        let sponsor_receipt_root = sponsor_receipt.root();
        let batch_id = batch_id(
            &dag_id,
            &dag.root(),
            &sponsor_receipt_root,
            request.build_at_height,
            self.counters.batches_built,
        );
        let batch = AtomicSettlementBatchRecord {
            batch_id: batch_id.clone(),
            dag_id: dag_id.clone(),
            call_ids: dag.call_ids.clone(),
            dependency_edge_ids: dag.edge_ids.clone(),
            call_root: dag.call_root.clone(),
            dependency_root: dag.edge_root.clone(),
            dag_root: dag.root(),
            sponsor_receipt_root,
            batch_proof_request_root: request.batch_proof_request_root,
            pq_batch_auth_root: request.pq_batch_auth_root,
            aggregator_commitment: request.aggregator_commitment,
            low_fee_lane: self.config.low_fee_lane.clone(),
            fee_asset_id: request.fee_asset_id,
            min_privacy_set_size: dag.min_privacy_set_size,
            pq_security_floor_bits: dag.max_pq_security_floor_bits,
            max_fee_micro_units: request.max_fee_micro_units,
            status: SettlementStatus::Batched,
            build_at_height: request.build_at_height,
            expires_at_height: request
                .build_at_height
                .saturating_add(self.config.batch_ttl_blocks),
        };
        for call_id in &batch.call_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = SettlementStatus::Batched;
            }
        }
        self.sponsor_receipts
            .insert(sponsor_receipt_id, sponsor_receipt);
        self.batches.insert(batch_id.clone(), batch);
        self.counters.sponsor_receipts = self.counters.sponsor_receipts.saturating_add(1);
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        self.counters.total_sponsored_fee_micro_units = self
            .counters
            .total_sponsored_fee_micro_units
            .saturating_add(sponsored_fee_micro_units);
        Ok(batch_id)
    }

    pub fn settle_batch(
        &mut self,
        request: SettleBatchRequest,
    ) -> PrivateL2ZkContractComposabilitySettlementResult<String> {
        request.validate()?;
        if self.final_receipts.len() >= PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_MAX_RECEIPTS
        {
            return Err("final receipt lane is at capacity".to_string());
        }
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| format!("unknown batch: {}", request.batch_id))?
            .clone();
        if batch.status.terminal() {
            return Err("batch already terminal".to_string());
        }
        if request.settled_at_height > batch.expires_at_height
            && request.status != SettlementStatus::Failed
        {
            return Err("batch expired before settlement".to_string());
        }
        let receipt_id = final_receipt_id(
            &request.batch_id,
            &request.recursive_proof_root,
            &request.state_root_after,
            request.settled_at_height,
            self.counters.final_receipts,
        );
        let receipt = FinalSettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id.clone(),
            dag_id: batch.dag_id.clone(),
            recursive_proof_root: request.recursive_proof_root,
            public_input_root: request.public_input_root,
            state_root_before: request.state_root_before,
            state_root_after: request.state_root_after,
            output_commitment_root: request.output_commitment_root,
            nullifier_root: request.nullifier_root,
            fee_settlement_root: request.fee_settlement_root,
            pq_transcript_root: request.pq_transcript_root,
            verifier_key_root: request.verifier_key_root,
            sponsor_receipt_root: request.sponsor_receipt_root,
            settled_fee_micro_units: request.settled_fee_micro_units,
            settled_at_height: request.settled_at_height,
            finality_height: request
                .settled_at_height
                .saturating_add(self.config.finality_blocks),
            status: request.status,
        };
        if let Some(batch_mut) = self.batches.get_mut(&request.batch_id) {
            batch_mut.status = request.status;
        }
        for call_id in &batch.call_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = request.status;
            }
        }
        self.final_receipts.insert(receipt_id.clone(), receipt);
        self.counters.final_receipts = self.counters.final_receipts.saturating_add(1);
        self.counters.total_settled_fee_micro_units = self
            .counters
            .total_settled_fee_micro_units
            .saturating_add(request.settled_fee_micro_units);
        if request.status == SettlementStatus::Settled {
            self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        }
        Ok(receipt_id)
    }

    pub fn roots(&self) -> Roots {
        let call_root = record_map_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-CALL-MAP",
            &self.calls,
            PrivateContractCallRecord::public_record,
        );
        let dependency_edge_root = record_map_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-DEPENDENCY-MAP",
            &self.dependency_edges,
            DependencyEdgeRecord::public_record,
        );
        let dag_root = record_map_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-DAG-MAP",
            &self.dags,
            DependencyDagRecord::public_record,
        );
        let batch_root = record_map_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-BATCH-MAP",
            &self.batches,
            AtomicSettlementBatchRecord::public_record,
        );
        let sponsor_receipt_root = record_map_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-SPONSOR-RECEIPT-MAP",
            &self.sponsor_receipts,
            FeeSponsorReceipt::public_record,
        );
        let final_receipt_root = record_map_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-FINAL-RECEIPT-MAP",
            &self.final_receipts,
            FinalSettlementReceipt::public_record,
        );
        let replay_nullifier_root = merkle_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-REPLAY-NULLIFIERS",
            &self
                .replay_nullifiers
                .iter()
                .map(|value| Value::String(value.clone()))
                .collect::<Vec<_>>(),
        );
        let pq_auth_root = merkle_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-PQ-AUTH-ROOTS",
            &self
                .calls
                .values()
                .map(|call| Value::String(call.pq_auth_root.clone()))
                .chain(
                    self.dependency_edges
                        .values()
                        .map(|edge| Value::String(edge.pq_auth_root.clone())),
                )
                .chain(
                    self.sponsor_receipts
                        .values()
                        .map(|receipt| Value::String(receipt.pq_auth_root.clone())),
                )
                .collect::<Vec<_>>(),
        );
        let low_fee_sponsor_root = record_map_root(
            "PRIVATE-L2-ZK-COMPOSABILITY-LOW-FEE-SPONSORS",
            &self.sponsor_receipts,
            FeeSponsorReceipt::public_record,
        );
        let public_record_root = lane_root(
            "PUBLIC-RECORD-SUMMARY",
            &json!({
                "config": self.config.public_record(),
                "counters": self.counters.public_record(),
                "call_root": call_root,
                "dependency_edge_root": dependency_edge_root,
                "dag_root": dag_root,
                "batch_root": batch_root,
                "sponsor_receipt_root": sponsor_receipt_root,
                "final_receipt_root": final_receipt_root,
            }),
        );
        Roots {
            call_root,
            dependency_edge_root,
            dag_root,
            batch_root,
            sponsor_receipt_root,
            final_receipt_root,
            replay_nullifier_root,
            pq_auth_root,
            low_fee_sponsor_root,
            public_record_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PRIVATE_L2_ZK_CONTRACT_COMPOSABILITY_SETTLEMENT_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.root(),
            "counters": self.counters.public_record(),
            "privacy_boundary": {
                "accounts": "commitments_only",
                "calldata": "encrypted_calldata_root_only",
                "state": "read_write_roots_only",
                "fees": "low_fee_sponsor_roots_only",
                "auth": "pq_auth_roots_only"
            }
        })
    }

    pub fn state_root(&self) -> String {
        lane_root("STATE", &self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
}

pub fn devnet() -> PrivateL2ZkContractComposabilitySettlementResult<State> {
    State::devnet()
}

pub fn call_id(request: &SubmitCallRequest, nonce: u64) -> String {
    lane_hash(
        "CALL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.contract_commitment),
            HashPart::Str(&request.selector_commitment),
            HashPart::Str(&request.encrypted_calldata_root),
            HashPart::Str(&request.replay_nullifier),
            HashPart::Int(request.submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn dependency_edge_id(
    request: &LinkDependencyRequest,
    strict_ordering: bool,
    nonce: u64,
) -> String {
    lane_hash(
        "DEPENDENCY-EDGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.predecessor_call_id),
            HashPart::Str(&request.successor_call_id),
            HashPart::Str(request.dependency_kind.as_str()),
            HashPart::Str(&request.resource_commitment),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(if strict_ordering { "strict" } else { "soft" }),
            HashPart::Int(request.linked_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn dag_id(
    call_root: &str,
    edge_root: &str,
    topological_order_root: &str,
    built_at_height: u64,
    nonce: u64,
) -> String {
    lane_hash(
        "DAG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(call_root),
            HashPart::Str(edge_root),
            HashPart::Str(topological_order_root),
            HashPart::Int(built_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn sponsor_receipt_id(
    dag_id: &str,
    sponsor_commitment: &str,
    sponsor_budget_root: &str,
    issued_at_height: u64,
    nonce: u64,
) -> String {
    lane_hash(
        "SPONSOR-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dag_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(sponsor_budget_root),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn batch_id(
    dag_id: &str,
    dag_root: &str,
    sponsor_receipt_root: &str,
    build_at_height: u64,
    nonce: u64,
) -> String {
    lane_hash(
        "BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(dag_id),
            HashPart::Str(dag_root),
            HashPart::Str(sponsor_receipt_root),
            HashPart::Int(build_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn final_receipt_id(
    batch_id: &str,
    recursive_proof_root: &str,
    state_root_after: &str,
    settled_at_height: u64,
    nonce: u64,
) -> String {
    lane_hash(
        "FINAL-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(recursive_proof_root),
            HashPart::Str(state_root_after),
            HashPart::Int(settled_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

pub fn lane_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-ZK-CONTRACT-COMPOSABILITY-SETTLEMENT-{domain}"),
        parts,
        32,
    )
}

pub fn lane_root(domain: &str, record: &Value) -> String {
    lane_hash(domain, &[HashPart::Json(record)])
}

fn record_map_root<T, F>(domain: &str, records: &BTreeMap<String, T>, record_fn: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = records
        .iter()
        .map(|(id, record)| {
            json!({
                "id": id,
                "record": record_fn(record),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(
    value: &str,
    label: &str,
) -> PrivateL2ZkContractComposabilitySettlementResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_unique(
    values: &[String],
    label: &str,
) -> PrivateL2ZkContractComposabilitySettlementResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("duplicate {label}: {value}"));
        }
    }
    Ok(())
}

fn adjacency_record(edge_records: &[Value]) -> Value {
    let mut adjacency = BTreeMap::<String, Vec<String>>::new();
    for record in edge_records {
        let predecessor = record
            .get("predecessor_call_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let successor = record
            .get("successor_call_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        adjacency.entry(predecessor).or_default().push(successor);
    }
    json!(adjacency)
}

fn would_create_cycle(
    existing: &BTreeMap<String, DependencyEdgeRecord>,
    candidate: &DependencyEdgeRecord,
) -> bool {
    let mut adjacency = existing
        .values()
        .map(|edge| {
            (
                edge.predecessor_call_id.clone(),
                edge.successor_call_id.clone(),
            )
        })
        .collect::<Vec<_>>();
    adjacency.push((
        candidate.predecessor_call_id.clone(),
        candidate.successor_call_id.clone(),
    ));
    reaches(
        &adjacency,
        &candidate.successor_call_id,
        &candidate.predecessor_call_id,
        &mut BTreeSet::new(),
    )
}

fn reaches(
    adjacency: &[(String, String)],
    current: &str,
    target: &str,
    visited: &mut BTreeSet<String>,
) -> bool {
    if current == target {
        return true;
    }
    if !visited.insert(current.to_string()) {
        return false;
    }
    adjacency
        .iter()
        .any(|(from, to)| from == current && reaches(adjacency, to, target, visited))
}

fn topological_order(
    call_ids: &[String],
    edge_ids: &[String],
    edges: &BTreeMap<String, DependencyEdgeRecord>,
) -> PrivateL2ZkContractComposabilitySettlementResult<Vec<String>> {
    let mut indegree = call_ids
        .iter()
        .map(|id| (id.clone(), 0_u64))
        .collect::<BTreeMap<_, _>>();
    let mut outgoing = call_ids
        .iter()
        .map(|id| (id.clone(), Vec::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    for edge_id in edge_ids {
        let edge = edges
            .get(edge_id)
            .ok_or_else(|| format!("unknown dependency edge in graph: {edge_id}"))?;
        if !indegree.contains_key(&edge.predecessor_call_id)
            || !indegree.contains_key(&edge.successor_call_id)
        {
            continue;
        }
        outgoing
            .entry(edge.predecessor_call_id.clone())
            .or_default()
            .push(edge.successor_call_id.clone());
        let entry = indegree.entry(edge.successor_call_id.clone()).or_default();
        *entry = entry.saturating_add(1);
    }
    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(call_ids.len());
    while let Some(next) = ready.iter().next().cloned() {
        ready.remove(&next);
        order.push(next.clone());
        for successor in outgoing.get(&next).cloned().unwrap_or_default() {
            if let Some(degree) = indegree.get_mut(&successor) {
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    ready.insert(successor);
                }
            }
        }
    }
    if order.len() != call_ids.len() {
        return Err("dependency graph contains a cycle".to_string());
    }
    Ok(order)
}
