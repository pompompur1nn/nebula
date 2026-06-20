use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateLiquidityNettingPoolResult<T> = Result<T, String>;

pub const PRIVATE_LIQUIDITY_NETTING_POOL_PROTOCOL_VERSION: &str =
    "nebula-private-liquidity-netting-pool-v1";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_INTENT_COMMITMENT_SCHEME: &str =
    "zk-shielded-swap-intent-commitment-v1";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_SOLVER_COMMITMENT_SCHEME: &str =
    "ml-dsa-87-solver-liquidity-commitment-v1";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_BATCH_PROOF_SCHEME: &str =
    "zk-private-batch-netting-proof-v1";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_REBATE_PROOF_SCHEME: &str = "zk-low-fee-rebate-note-v1";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-pool-operator-attestation-v1";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_HEIGHT: u64 = 320;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_XMR_ASSET_ID: &str = "xmr-devnet";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_STABLE_ASSET_ID: &str = "dusd-devnet";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_LOW_FEE_LANE: &str =
    "devnet-private-liquidity-low-fee";
pub const PRIVATE_LIQUIDITY_NETTING_POOL_MAX_BPS: u64 = 10_000;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_BUCKET_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_BATCH_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_SOLVER_TTL_BLOCKS: u64 = 1_440;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 2;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_REBATE_TTL_BLOCKS: u64 = 240;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_INTENTS_PER_BUCKET: usize = 16_384;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_SOLVERS_PER_BUCKET: usize = 512;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_BATCH_INTENTS: usize = 1_024;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_BATCH_SOLVERS: usize = 128;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_NETTING_IMBALANCE_BPS: u64 = 350;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_CORRELATION_BPS: u64 = 4_000;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_BRIDGE_SHARE_BPS: u64 = 5_500;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_SURPLUS_REBATE_BPS: u64 = 5_000;
pub const PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MIN_BATCH_PRIVACY_SET: u64 = 32;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityFlowKind {
    ShieldedSwap,
    MoneroBridgeIn,
    MoneroBridgeOut,
    CrossPairRebalance,
    ContractSettlement,
    Custom(String),
}

impl LiquidityFlowKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::ShieldedSwap => "shielded_swap".to_string(),
            Self::MoneroBridgeIn => "monero_bridge_in".to_string(),
            Self::MoneroBridgeOut => "monero_bridge_out".to_string(),
            Self::CrossPairRebalance => "cross_pair_rebalance".to_string(),
            Self::ContractSettlement => "contract_settlement".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn is_bridge(&self) -> bool {
        matches!(self, Self::MoneroBridgeIn | Self::MoneroBridgeOut)
    }

    pub fn default_privacy_weight(&self) -> u64 {
        match self {
            Self::ShieldedSwap => 120,
            Self::MoneroBridgeIn => 180,
            Self::MoneroBridgeOut => 220,
            Self::CrossPairRebalance => 90,
            Self::ContractSettlement => 160,
            Self::Custom(_) => 200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentDirection {
    ExactIn,
    ExactOut,
    TwoSided,
    BridgeMint,
    BridgeBurn,
}

impl IntentDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExactIn => "exact_in",
            Self::ExactOut => "exact_out",
            Self::TwoSided => "two_sided",
            Self::BridgeMint => "bridge_mint",
            Self::BridgeBurn => "bridge_burn",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentCommitmentStatus {
    Pending,
    Bucketed,
    SolverReserved,
    Netted,
    Settled,
    Cancelled,
    Expired,
    Rejected,
    Challenged,
}

impl IntentCommitmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Bucketed => "bucketed",
            Self::SolverReserved => "solver_reserved",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }

    pub fn active(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Bucketed | Self::SolverReserved | Self::Netted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Sealed,
    Netting,
    Settling,
    Settled,
    Paused,
    Expired,
    Disputed,
}

impl BucketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Netting => "netting",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn accepts_intents(&self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    Draft,
    Posted,
    Eligible,
    Selected,
    PartiallyFilled,
    Filled,
    Slashed,
    Expired,
    Revoked,
}

impl SolverCommitmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Posted => "posted",
            Self::Eligible => "eligible",
            Self::Selected => "selected",
            Self::PartiallyFilled => "partially_filled",
            Self::Filled => "filled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(&self) -> bool {
        matches!(
            self,
            Self::Posted | Self::Eligible | Self::Selected | Self::PartiallyFilled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingBatchStatus {
    Open,
    Proving,
    Proven,
    Posted,
    Settling,
    Settled,
    Disputed,
    Expired,
    Reverted,
}

impl NettingBatchStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proving => "proving",
            Self::Proven => "proven",
            Self::Posted => "posted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Reverted => "reverted",
        }
    }

    pub fn settlement_ready(&self) -> bool {
        matches!(self, Self::Proven | Self::Posted | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    Expired,
    Forfeited,
}

impl RebateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Forfeited => "forfeited",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLimitStatus {
    Monitoring,
    Warning,
    Constrained,
    Halted,
    Cleared,
}

impl RiskLimitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Monitoring => "monitoring",
            Self::Warning => "warning",
            Self::Constrained => "constrained",
            Self::Halted => "halted",
            Self::Cleared => "cleared",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRootStatus {
    Draft,
    Posted,
    Anchored,
    Finalized,
    Disputed,
    Replaced,
}

impl SettlementRootStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Posted => "posted",
            Self::Anchored => "anchored",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Replaced => "replaced",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityNettingPoolConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub low_fee_lane_id: String,
    pub epoch_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub solver_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub max_intents_per_bucket: usize,
    pub max_solvers_per_bucket: usize,
    pub max_batch_intents: usize,
    pub max_batch_solvers: usize,
    pub max_netting_imbalance_bps: u64,
    pub max_correlation_bps: u64,
    pub max_bridge_share_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub surplus_rebate_bps: u64,
    pub min_batch_privacy_set: u64,
    pub intent_commitment_scheme: String,
    pub solver_commitment_scheme: String,
    pub batch_proof_scheme: String,
    pub rebate_proof_scheme: String,
    pub pq_authorization_scheme: String,
}

impl Default for PrivateLiquidityNettingPoolConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_LIQUIDITY_NETTING_POOL_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_LIQUIDITY_NETTING_POOL_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_FEE_ASSET_ID.to_string(),
            low_fee_lane_id: PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_LOW_FEE_LANE.to_string(),
            epoch_blocks: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_EPOCH_BLOCKS,
            bucket_ttl_blocks: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_BUCKET_TTL_BLOCKS,
            batch_ttl_blocks: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_BATCH_TTL_BLOCKS,
            solver_ttl_blocks: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_SOLVER_TTL_BLOCKS,
            settlement_delay_blocks: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            rebate_ttl_blocks: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_REBATE_TTL_BLOCKS,
            min_pq_security_bits: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_intents_per_bucket: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_INTENTS_PER_BUCKET,
            max_solvers_per_bucket: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_SOLVERS_PER_BUCKET,
            max_batch_intents: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_BATCH_INTENTS,
            max_batch_solvers: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_BATCH_SOLVERS,
            max_netting_imbalance_bps:
                PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_NETTING_IMBALANCE_BPS,
            max_correlation_bps: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_CORRELATION_BPS,
            max_bridge_share_bps: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_BRIDGE_SHARE_BPS,
            low_fee_rebate_bps: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_LOW_FEE_REBATE_BPS,
            surplus_rebate_bps: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_SURPLUS_REBATE_BPS,
            min_batch_privacy_set: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MIN_BATCH_PRIVACY_SET,
            intent_commitment_scheme: PRIVATE_LIQUIDITY_NETTING_POOL_INTENT_COMMITMENT_SCHEME
                .to_string(),
            solver_commitment_scheme: PRIVATE_LIQUIDITY_NETTING_POOL_SOLVER_COMMITMENT_SCHEME
                .to_string(),
            batch_proof_scheme: PRIVATE_LIQUIDITY_NETTING_POOL_BATCH_PROOF_SCHEME.to_string(),
            rebate_proof_scheme: PRIVATE_LIQUIDITY_NETTING_POOL_REBATE_PROOF_SCHEME.to_string(),
            pq_authorization_scheme: PRIVATE_LIQUIDITY_NETTING_POOL_PQ_AUTH_SCHEME.to_string(),
        }
    }
}

impl PrivateLiquidityNettingPoolConfig {
    pub fn validate(&self) -> PrivateLiquidityNettingPoolResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("low_fee_lane_id", &self.low_fee_lane_id)?;
        require_non_zero("epoch_blocks", self.epoch_blocks)?;
        require_non_zero("bucket_ttl_blocks", self.bucket_ttl_blocks)?;
        require_non_zero("batch_ttl_blocks", self.batch_ttl_blocks)?;
        require_non_zero("solver_ttl_blocks", self.solver_ttl_blocks)?;
        require_non_zero("rebate_ttl_blocks", self.rebate_ttl_blocks)?;
        require_non_zero("min_pq_security_bits", self.min_pq_security_bits as u64)?;
        require_non_zero("max_intents_per_bucket", self.max_intents_per_bucket as u64)?;
        require_non_zero("max_solvers_per_bucket", self.max_solvers_per_bucket as u64)?;
        require_non_zero("max_batch_intents", self.max_batch_intents as u64)?;
        require_non_zero("max_batch_solvers", self.max_batch_solvers as u64)?;
        require_bps("max_netting_imbalance_bps", self.max_netting_imbalance_bps)?;
        require_bps("max_correlation_bps", self.max_correlation_bps)?;
        require_bps("max_bridge_share_bps", self.max_bridge_share_bps)?;
        require_bps("low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        require_bps("surplus_rebate_bps", self.surplus_rebate_bps)?;
        require_non_zero("min_batch_privacy_set", self.min_batch_privacy_set)?;
        require_non_empty("intent_commitment_scheme", &self.intent_commitment_scheme)?;
        require_non_empty("solver_commitment_scheme", &self.solver_commitment_scheme)?;
        require_non_empty("batch_proof_scheme", &self.batch_proof_scheme)?;
        require_non_empty("rebate_proof_scheme", &self.rebate_proof_scheme)?;
        require_non_empty("pq_authorization_scheme", &self.pq_authorization_scheme)?;
        if self.max_batch_intents > self.max_intents_per_bucket {
            return Err("max_batch_intents cannot exceed max_intents_per_bucket".to_string());
        }
        if self.max_batch_solvers > self.max_solvers_per_bucket {
            return Err("max_batch_solvers cannot exceed max_solvers_per_bucket".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "epoch_blocks": self.epoch_blocks,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "solver_ttl_blocks": self.solver_ttl_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_intents_per_bucket": self.max_intents_per_bucket,
            "max_solvers_per_bucket": self.max_solvers_per_bucket,
            "max_batch_intents": self.max_batch_intents,
            "max_batch_solvers": self.max_batch_solvers,
            "max_netting_imbalance_bps": self.max_netting_imbalance_bps,
            "max_correlation_bps": self.max_correlation_bps,
            "max_bridge_share_bps": self.max_bridge_share_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "surplus_rebate_bps": self.surplus_rebate_bps,
            "min_batch_privacy_set": self.min_batch_privacy_set,
            "intent_commitment_scheme": self.intent_commitment_scheme,
            "solver_commitment_scheme": self.solver_commitment_scheme,
            "batch_proof_scheme": self.batch_proof_scheme,
            "rebate_proof_scheme": self.rebate_proof_scheme,
            "pq_authorization_scheme": self.pq_authorization_scheme,
        })
    }

    pub fn commitment(&self) -> String {
        private_liquidity_netting_pool_payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPairBucket {
    pub bucket_id: String,
    pub epoch: u64,
    pub pair_key: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub flow_kind: LiquidityFlowKind,
    pub status: BucketStatus,
    pub opened_height: u64,
    pub seal_height: u64,
    pub expires_height: u64,
    pub amount_bucket_log2: u8,
    pub min_privacy_set: u64,
    pub intent_count: u64,
    pub solver_count: u64,
    pub gross_base_commitment: String,
    pub gross_quote_commitment: String,
    pub net_base_commitment: String,
    pub net_quote_commitment: String,
    pub bridge_share_bps: u64,
    pub correlation_score_bps: u64,
    pub low_fee_lane_id: String,
    pub metadata_commitment: String,
}

impl TokenPairBucket {
    pub fn devnet(
        bucket_id: &str,
        base_asset_id: &str,
        quote_asset_id: &str,
        flow_kind: LiquidityFlowKind,
        opened_height: u64,
    ) -> Self {
        let pair_key = canonical_pair_key(base_asset_id, quote_asset_id);
        Self {
            bucket_id: bucket_id.to_string(),
            epoch: opened_height / PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_EPOCH_BLOCKS,
            pair_key,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            flow_kind,
            status: BucketStatus::Open,
            opened_height,
            seal_height: opened_height + PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_BUCKET_TTL_BLOCKS,
            expires_height: opened_height
                + PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_BUCKET_TTL_BLOCKS
                + PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_BATCH_TTL_BLOCKS,
            amount_bucket_log2: 16,
            min_privacy_set: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MIN_BATCH_PRIVACY_SET,
            intent_count: 0,
            solver_count: 0,
            gross_base_commitment: devnet_commitment("bucket-gross-base", bucket_id),
            gross_quote_commitment: devnet_commitment("bucket-gross-quote", bucket_id),
            net_base_commitment: devnet_commitment("bucket-net-base", bucket_id),
            net_quote_commitment: devnet_commitment("bucket-net-quote", bucket_id),
            bridge_share_bps: 0,
            correlation_score_bps: 0,
            low_fee_lane_id: PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_LOW_FEE_LANE.to_string(),
            metadata_commitment: devnet_commitment("bucket-metadata", bucket_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch": self.epoch,
            "pair_key": self.pair_key,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "flow_kind": self.flow_kind.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "seal_height": self.seal_height,
            "expires_height": self.expires_height,
            "amount_bucket_log2": self.amount_bucket_log2,
            "min_privacy_set": self.min_privacy_set,
            "intent_count": self.intent_count,
            "solver_count": self.solver_count,
            "gross_base_commitment": self.gross_base_commitment,
            "gross_quote_commitment": self.gross_quote_commitment,
            "net_base_commitment": self.net_base_commitment,
            "net_quote_commitment": self.net_quote_commitment,
            "bridge_share_bps": self.bridge_share_bps,
            "correlation_score_bps": self.correlation_score_bps,
            "low_fee_lane_id": self.low_fee_lane_id,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn commitment(&self) -> String {
        private_liquidity_netting_pool_payload_root("TOKEN-PAIR-BUCKET", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidityNettingPoolResult<String> {
        require_non_empty("bucket_id", &self.bucket_id)?;
        require_non_empty("pair_key", &self.pair_key)?;
        require_non_empty("base_asset_id", &self.base_asset_id)?;
        require_non_empty("quote_asset_id", &self.quote_asset_id)?;
        if self.base_asset_id == self.quote_asset_id {
            return Err("token pair bucket assets must differ".to_string());
        }
        if self.pair_key != canonical_pair_key(&self.base_asset_id, &self.quote_asset_id) {
            return Err("token pair bucket pair_key is not canonical".to_string());
        }
        if self.seal_height <= self.opened_height {
            return Err("token pair bucket seal_height must exceed opened_height".to_string());
        }
        if self.expires_height <= self.seal_height {
            return Err("token pair bucket expires_height must exceed seal_height".to_string());
        }
        require_non_zero("amount_bucket_log2", self.amount_bucket_log2 as u64)?;
        require_non_zero("min_privacy_set", self.min_privacy_set)?;
        require_bps("bridge_share_bps", self.bridge_share_bps)?;
        require_bps("correlation_score_bps", self.correlation_score_bps)?;
        require_non_empty("low_fee_lane_id", &self.low_fee_lane_id)?;
        require_commitment("gross_base_commitment", &self.gross_base_commitment)?;
        require_commitment("gross_quote_commitment", &self.gross_quote_commitment)?;
        require_commitment("net_base_commitment", &self.net_base_commitment)?;
        require_commitment("net_quote_commitment", &self.net_quote_commitment)?;
        require_commitment("metadata_commitment", &self.metadata_commitment)?;
        Ok(self.commitment())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentCommitment {
    pub intent_id: String,
    pub bucket_id: String,
    pub owner_nullifier: String,
    pub commitment: String,
    pub encrypted_payload_root: String,
    pub flow_kind: LiquidityFlowKind,
    pub direction: IntentDirection,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub amount_bucket: u64,
    pub limit_price_commitment: String,
    pub route_hint_commitment: String,
    pub bridge_note_commitment: Option<String>,
    pub monero_view_tag_root: Option<String>,
    pub max_fee_units: u64,
    pub low_fee_eligible: bool,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: IntentCommitmentStatus,
    pub privacy_weight: u64,
    pub pq_authorization_root: String,
}

impl IntentCommitment {
    pub fn devnet_swap(
        intent_id: &str,
        bucket_id: &str,
        base_asset_id: &str,
        quote_asset_id: &str,
        amount_bucket: u64,
        height: u64,
    ) -> Self {
        Self {
            intent_id: intent_id.to_string(),
            bucket_id: bucket_id.to_string(),
            owner_nullifier: devnet_commitment("owner-nullifier", intent_id),
            commitment: devnet_commitment("intent", intent_id),
            encrypted_payload_root: devnet_commitment("intent-payload", intent_id),
            flow_kind: LiquidityFlowKind::ShieldedSwap,
            direction: IntentDirection::ExactIn,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            amount_bucket,
            limit_price_commitment: devnet_commitment("limit-price", intent_id),
            route_hint_commitment: devnet_commitment("route-hint", intent_id),
            bridge_note_commitment: None,
            monero_view_tag_root: None,
            max_fee_units: 25,
            low_fee_eligible: true,
            submitted_height: height,
            expires_height: height + 48,
            status: IntentCommitmentStatus::Bucketed,
            privacy_weight: LiquidityFlowKind::ShieldedSwap.default_privacy_weight(),
            pq_authorization_root: devnet_commitment("intent-pq-auth", intent_id),
        }
    }

    pub fn devnet_bridge_out(
        intent_id: &str,
        bucket_id: &str,
        amount_bucket: u64,
        height: u64,
    ) -> Self {
        Self {
            intent_id: intent_id.to_string(),
            bucket_id: bucket_id.to_string(),
            owner_nullifier: devnet_commitment("owner-nullifier", intent_id),
            commitment: devnet_commitment("bridge-intent", intent_id),
            encrypted_payload_root: devnet_commitment("bridge-payload", intent_id),
            flow_kind: LiquidityFlowKind::MoneroBridgeOut,
            direction: IntentDirection::BridgeBurn,
            base_asset_id: PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID.to_string(),
            quote_asset_id: PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_XMR_ASSET_ID.to_string(),
            amount_bucket,
            limit_price_commitment: devnet_commitment("bridge-price", intent_id),
            route_hint_commitment: devnet_commitment("bridge-route", intent_id),
            bridge_note_commitment: Some(devnet_commitment("bridge-note", intent_id)),
            monero_view_tag_root: Some(devnet_commitment("monero-view-tags", intent_id)),
            max_fee_units: 40,
            low_fee_eligible: true,
            submitted_height: height,
            expires_height: height + 64,
            status: IntentCommitmentStatus::Bucketed,
            privacy_weight: LiquidityFlowKind::MoneroBridgeOut.default_privacy_weight(),
            pq_authorization_root: devnet_commitment("intent-pq-auth", intent_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "bucket_id": self.bucket_id,
            "owner_nullifier": self.owner_nullifier,
            "commitment": self.commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "flow_kind": self.flow_kind.as_str(),
            "direction": self.direction.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "amount_bucket": self.amount_bucket,
            "limit_price_commitment": self.limit_price_commitment,
            "route_hint_commitment": self.route_hint_commitment,
            "bridge_note_commitment": self.bridge_note_commitment,
            "monero_view_tag_root": self.monero_view_tag_root,
            "max_fee_units": self.max_fee_units,
            "low_fee_eligible": self.low_fee_eligible,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "privacy_weight": self.privacy_weight,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }

    pub fn root(&self) -> String {
        private_liquidity_netting_pool_payload_root("INTENT-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidityNettingPoolResult<String> {
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("bucket_id", &self.bucket_id)?;
        require_commitment("owner_nullifier", &self.owner_nullifier)?;
        require_commitment("commitment", &self.commitment)?;
        require_commitment("encrypted_payload_root", &self.encrypted_payload_root)?;
        require_non_empty("base_asset_id", &self.base_asset_id)?;
        require_non_empty("quote_asset_id", &self.quote_asset_id)?;
        if self.base_asset_id == self.quote_asset_id && !self.flow_kind.is_bridge() {
            return Err("non-bridge intent assets must differ".to_string());
        }
        require_non_zero("amount_bucket", self.amount_bucket)?;
        require_commitment("limit_price_commitment", &self.limit_price_commitment)?;
        require_commitment("route_hint_commitment", &self.route_hint_commitment)?;
        if self.flow_kind.is_bridge() && self.bridge_note_commitment.is_none() {
            return Err("bridge intent requires bridge_note_commitment".to_string());
        }
        if let Some(commitment) = &self.bridge_note_commitment {
            require_commitment("bridge_note_commitment", commitment)?;
        }
        if let Some(root) = &self.monero_view_tag_root {
            require_commitment("monero_view_tag_root", root)?;
        }
        if self.expires_height <= self.submitted_height {
            return Err("intent expires_height must exceed submitted_height".to_string());
        }
        require_non_zero("privacy_weight", self.privacy_weight)?;
        require_commitment("pq_authorization_root", &self.pq_authorization_root)?;
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverLiquidityCommitment {
    pub solver_id: String,
    pub commitment_id: String,
    pub bucket_id: String,
    pub pair_key: String,
    pub status: SolverCommitmentStatus,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub available_base_commitment: String,
    pub available_quote_commitment: String,
    pub min_fill_commitment: String,
    pub price_curve_commitment: String,
    pub fee_quote_commitment: String,
    pub inventory_nullifier_root: String,
    pub pq_signature_root: String,
    pub bond_units: u64,
    pub low_fee_capacity_units: u64,
    pub max_bridge_exposure_bps: u64,
    pub posted_height: u64,
    pub expires_height: u64,
}

impl SolverLiquidityCommitment {
    pub fn devnet(
        solver_id: &str,
        commitment_id: &str,
        bucket_id: &str,
        base_asset_id: &str,
        quote_asset_id: &str,
        height: u64,
    ) -> Self {
        Self {
            solver_id: solver_id.to_string(),
            commitment_id: commitment_id.to_string(),
            bucket_id: bucket_id.to_string(),
            pair_key: canonical_pair_key(base_asset_id, quote_asset_id),
            status: SolverCommitmentStatus::Eligible,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            available_base_commitment: devnet_commitment("solver-base", commitment_id),
            available_quote_commitment: devnet_commitment("solver-quote", commitment_id),
            min_fill_commitment: devnet_commitment("solver-min-fill", commitment_id),
            price_curve_commitment: devnet_commitment("solver-price-curve", commitment_id),
            fee_quote_commitment: devnet_commitment("solver-fee-quote", commitment_id),
            inventory_nullifier_root: devnet_commitment("solver-inventory", commitment_id),
            pq_signature_root: devnet_commitment("solver-pq-sig", commitment_id),
            bond_units: 500_000,
            low_fee_capacity_units: 100_000,
            max_bridge_exposure_bps: 3_000,
            posted_height: height,
            expires_height: height + PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_SOLVER_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "solver_id": self.solver_id,
            "commitment_id": self.commitment_id,
            "bucket_id": self.bucket_id,
            "pair_key": self.pair_key,
            "status": self.status.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "available_base_commitment": self.available_base_commitment,
            "available_quote_commitment": self.available_quote_commitment,
            "min_fill_commitment": self.min_fill_commitment,
            "price_curve_commitment": self.price_curve_commitment,
            "fee_quote_commitment": self.fee_quote_commitment,
            "inventory_nullifier_root": self.inventory_nullifier_root,
            "pq_signature_root": self.pq_signature_root,
            "bond_units": self.bond_units,
            "low_fee_capacity_units": self.low_fee_capacity_units,
            "max_bridge_exposure_bps": self.max_bridge_exposure_bps,
            "posted_height": self.posted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        private_liquidity_netting_pool_payload_root("SOLVER-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidityNettingPoolResult<String> {
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("commitment_id", &self.commitment_id)?;
        require_non_empty("bucket_id", &self.bucket_id)?;
        require_non_empty("pair_key", &self.pair_key)?;
        require_non_empty("base_asset_id", &self.base_asset_id)?;
        require_non_empty("quote_asset_id", &self.quote_asset_id)?;
        if self.pair_key != canonical_pair_key(&self.base_asset_id, &self.quote_asset_id) {
            return Err("solver commitment pair_key is not canonical".to_string());
        }
        require_commitment("available_base_commitment", &self.available_base_commitment)?;
        require_commitment(
            "available_quote_commitment",
            &self.available_quote_commitment,
        )?;
        require_commitment("min_fill_commitment", &self.min_fill_commitment)?;
        require_commitment("price_curve_commitment", &self.price_curve_commitment)?;
        require_commitment("fee_quote_commitment", &self.fee_quote_commitment)?;
        require_commitment("inventory_nullifier_root", &self.inventory_nullifier_root)?;
        require_commitment("pq_signature_root", &self.pq_signature_root)?;
        require_non_zero("bond_units", self.bond_units)?;
        require_bps("max_bridge_exposure_bps", self.max_bridge_exposure_bps)?;
        if self.expires_height <= self.posted_height {
            return Err("solver commitment expires_height must exceed posted_height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiCorrelationRiskLimit {
    pub limit_id: String,
    pub pair_key: String,
    pub status: RiskLimitStatus,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_correlation_bps: u64,
    pub observed_correlation_bps: u64,
    pub max_bridge_share_bps: u64,
    pub observed_bridge_share_bps: u64,
    pub imbalance_bps: u64,
    pub stress_root: String,
    pub mitigation_root: String,
}

impl AntiCorrelationRiskLimit {
    pub fn devnet(limit_id: &str, pair_key: &str, height: u64) -> Self {
        Self {
            limit_id: limit_id.to_string(),
            pair_key: pair_key.to_string(),
            status: RiskLimitStatus::Monitoring,
            window_start_height: height,
            window_end_height: height + 120,
            max_correlation_bps: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_CORRELATION_BPS,
            observed_correlation_bps: 1_200,
            max_bridge_share_bps: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_MAX_BRIDGE_SHARE_BPS,
            observed_bridge_share_bps: 2_000,
            imbalance_bps: 75,
            stress_root: devnet_commitment("risk-stress", limit_id),
            mitigation_root: devnet_commitment("risk-mitigation", limit_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "limit_id": self.limit_id,
            "pair_key": self.pair_key,
            "status": self.status.as_str(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_correlation_bps": self.max_correlation_bps,
            "observed_correlation_bps": self.observed_correlation_bps,
            "max_bridge_share_bps": self.max_bridge_share_bps,
            "observed_bridge_share_bps": self.observed_bridge_share_bps,
            "imbalance_bps": self.imbalance_bps,
            "stress_root": self.stress_root,
            "mitigation_root": self.mitigation_root,
        })
    }

    pub fn root(&self) -> String {
        private_liquidity_netting_pool_payload_root(
            "ANTI-CORRELATION-RISK-LIMIT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityNettingPoolResult<String> {
        require_non_empty("limit_id", &self.limit_id)?;
        require_non_empty("pair_key", &self.pair_key)?;
        if self.window_end_height <= self.window_start_height {
            return Err("risk limit window_end_height must exceed window_start_height".to_string());
        }
        require_bps("max_correlation_bps", self.max_correlation_bps)?;
        require_bps("observed_correlation_bps", self.observed_correlation_bps)?;
        require_bps("max_bridge_share_bps", self.max_bridge_share_bps)?;
        require_bps("observed_bridge_share_bps", self.observed_bridge_share_bps)?;
        require_bps("imbalance_bps", self.imbalance_bps)?;
        require_commitment("stress_root", &self.stress_root)?;
        require_commitment("mitigation_root", &self.mitigation_root)?;
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchNettingProof {
    pub proof_id: String,
    pub batch_id: String,
    pub bucket_id: String,
    pub status: NettingBatchStatus,
    pub proof_scheme: String,
    pub input_intent_root: String,
    pub solver_commitment_root: String,
    pub netted_transfer_root: String,
    pub surplus_distribution_root: String,
    pub nullifier_root: String,
    pub bridge_flow_root: String,
    pub risk_limit_root: String,
    pub proof_commitment: String,
    pub verifier_key_root: String,
    pub privacy_set_size: u64,
    pub netting_imbalance_bps: u64,
    pub prover_id: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl BatchNettingProof {
    pub fn devnet(
        proof_id: &str,
        batch_id: &str,
        bucket_id: &str,
        input_intent_root: String,
        solver_commitment_root: String,
        risk_limit_root: String,
        height: u64,
    ) -> Self {
        Self {
            proof_id: proof_id.to_string(),
            batch_id: batch_id.to_string(),
            bucket_id: bucket_id.to_string(),
            status: NettingBatchStatus::Proven,
            proof_scheme: PRIVATE_LIQUIDITY_NETTING_POOL_BATCH_PROOF_SCHEME.to_string(),
            input_intent_root,
            solver_commitment_root,
            netted_transfer_root: devnet_commitment("netted-transfer", batch_id),
            surplus_distribution_root: devnet_commitment("surplus-distribution", batch_id),
            nullifier_root: devnet_commitment("batch-nullifiers", batch_id),
            bridge_flow_root: devnet_commitment("bridge-flow", batch_id),
            risk_limit_root,
            proof_commitment: devnet_commitment("batch-proof", proof_id),
            verifier_key_root: devnet_commitment("verifier-key", proof_id),
            privacy_set_size: 64,
            netting_imbalance_bps: 80,
            prover_id: "devnet-pq-prover-1".to_string(),
            created_height: height,
            expires_height: height + PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_BATCH_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "batch_id": self.batch_id,
            "bucket_id": self.bucket_id,
            "status": self.status.as_str(),
            "proof_scheme": self.proof_scheme,
            "input_intent_root": self.input_intent_root,
            "solver_commitment_root": self.solver_commitment_root,
            "netted_transfer_root": self.netted_transfer_root,
            "surplus_distribution_root": self.surplus_distribution_root,
            "nullifier_root": self.nullifier_root,
            "bridge_flow_root": self.bridge_flow_root,
            "risk_limit_root": self.risk_limit_root,
            "proof_commitment": self.proof_commitment,
            "verifier_key_root": self.verifier_key_root,
            "privacy_set_size": self.privacy_set_size,
            "netting_imbalance_bps": self.netting_imbalance_bps,
            "prover_id": self.prover_id,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        private_liquidity_netting_pool_payload_root("BATCH-NETTING-PROOF", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidityNettingPoolResult<String> {
        require_non_empty("proof_id", &self.proof_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("bucket_id", &self.bucket_id)?;
        require_non_empty("proof_scheme", &self.proof_scheme)?;
        require_commitment("input_intent_root", &self.input_intent_root)?;
        require_commitment("solver_commitment_root", &self.solver_commitment_root)?;
        require_commitment("netted_transfer_root", &self.netted_transfer_root)?;
        require_commitment("surplus_distribution_root", &self.surplus_distribution_root)?;
        require_commitment("nullifier_root", &self.nullifier_root)?;
        require_commitment("bridge_flow_root", &self.bridge_flow_root)?;
        require_commitment("risk_limit_root", &self.risk_limit_root)?;
        require_commitment("proof_commitment", &self.proof_commitment)?;
        require_commitment("verifier_key_root", &self.verifier_key_root)?;
        require_non_zero("privacy_set_size", self.privacy_set_size)?;
        require_bps("netting_imbalance_bps", self.netting_imbalance_bps)?;
        require_non_empty("prover_id", &self.prover_id)?;
        if self.expires_height <= self.created_height {
            return Err("batch proof expires_height must exceed created_height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebateNote {
    pub rebate_id: String,
    pub batch_id: String,
    pub recipient_nullifier: String,
    pub asset_id: String,
    pub status: RebateStatus,
    pub rebate_commitment: String,
    pub rebate_amount_bucket: u64,
    pub low_fee_rebate_bps: u64,
    pub surplus_rebate_bps: u64,
    pub proof_root: String,
    pub claim_nullifier: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl FeeRebateNote {
    pub fn devnet(rebate_id: &str, batch_id: &str, recipient_label: &str, height: u64) -> Self {
        Self {
            rebate_id: rebate_id.to_string(),
            batch_id: batch_id.to_string(),
            recipient_nullifier: devnet_commitment("rebate-recipient", recipient_label),
            asset_id: PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_FEE_ASSET_ID.to_string(),
            status: RebateStatus::Claimable,
            rebate_commitment: devnet_commitment("rebate", rebate_id),
            rebate_amount_bucket: 4,
            low_fee_rebate_bps: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_LOW_FEE_REBATE_BPS,
            surplus_rebate_bps: PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_SURPLUS_REBATE_BPS,
            proof_root: devnet_commitment("rebate-proof", rebate_id),
            claim_nullifier: devnet_commitment("rebate-claim", rebate_id),
            created_height: height,
            expires_height: height + PRIVATE_LIQUIDITY_NETTING_POOL_DEFAULT_REBATE_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "recipient_nullifier": self.recipient_nullifier,
            "asset_id": self.asset_id,
            "status": self.status.as_str(),
            "rebate_commitment": self.rebate_commitment,
            "rebate_amount_bucket": self.rebate_amount_bucket,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "surplus_rebate_bps": self.surplus_rebate_bps,
            "proof_root": self.proof_root,
            "claim_nullifier": self.claim_nullifier,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        private_liquidity_netting_pool_payload_root("FEE-REBATE-NOTE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateLiquidityNettingPoolResult<String> {
        require_non_empty("rebate_id", &self.rebate_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_commitment("recipient_nullifier", &self.recipient_nullifier)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_commitment("rebate_commitment", &self.rebate_commitment)?;
        require_non_zero("rebate_amount_bucket", self.rebate_amount_bucket)?;
        require_bps("low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        require_bps("surplus_rebate_bps", self.surplus_rebate_bps)?;
        require_commitment("proof_root", &self.proof_root)?;
        require_commitment("claim_nullifier", &self.claim_nullifier)?;
        if self.expires_height <= self.created_height {
            return Err("rebate expires_height must exceed created_height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSettlementRoot {
    pub settlement_id: String,
    pub batch_id: String,
    pub status: SettlementRootStatus,
    pub settlement_height: u64,
    pub intent_root: String,
    pub solver_root: String,
    pub proof_root: String,
    pub rebate_root: String,
    pub debit_root: String,
    pub credit_root: String,
    pub nullifier_root: String,
    pub bridge_anchor_root: String,
    pub state_delta_root: String,
    pub low_fee_cost_units: u64,
    pub compressed_fee_units: u64,
    pub anchor_tx_id: Option<String>,
}

impl LowFeeSettlementRoot {
    pub fn devnet(
        settlement_id: &str,
        batch_id: &str,
        intent_root: String,
        solver_root: String,
        proof_root: String,
        rebate_root: String,
        height: u64,
    ) -> Self {
        Self {
            settlement_id: settlement_id.to_string(),
            batch_id: batch_id.to_string(),
            status: SettlementRootStatus::Posted,
            settlement_height: height,
            intent_root,
            solver_root,
            proof_root,
            rebate_root,
            debit_root: devnet_commitment("settlement-debits", settlement_id),
            credit_root: devnet_commitment("settlement-credits", settlement_id),
            nullifier_root: devnet_commitment("settlement-nullifiers", settlement_id),
            bridge_anchor_root: devnet_commitment("settlement-bridge-anchor", settlement_id),
            state_delta_root: devnet_commitment("settlement-state-delta", settlement_id),
            low_fee_cost_units: 180,
            compressed_fee_units: 24,
            anchor_tx_id: Some("devnet-anchor-private-liquidity-netting-1".to_string()),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "settlement_height": self.settlement_height,
            "intent_root": self.intent_root,
            "solver_root": self.solver_root,
            "proof_root": self.proof_root,
            "rebate_root": self.rebate_root,
            "debit_root": self.debit_root,
            "credit_root": self.credit_root,
            "nullifier_root": self.nullifier_root,
            "bridge_anchor_root": self.bridge_anchor_root,
            "state_delta_root": self.state_delta_root,
            "low_fee_cost_units": self.low_fee_cost_units,
            "compressed_fee_units": self.compressed_fee_units,
            "anchor_tx_id": self.anchor_tx_id,
        })
    }

    pub fn root(&self) -> String {
        private_liquidity_netting_pool_payload_root(
            "LOW-FEE-SETTLEMENT-ROOT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PrivateLiquidityNettingPoolResult<String> {
        require_non_empty("settlement_id", &self.settlement_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_commitment("intent_root", &self.intent_root)?;
        require_commitment("solver_root", &self.solver_root)?;
        require_commitment("proof_root", &self.proof_root)?;
        require_commitment("rebate_root", &self.rebate_root)?;
        require_commitment("debit_root", &self.debit_root)?;
        require_commitment("credit_root", &self.credit_root)?;
        require_commitment("nullifier_root", &self.nullifier_root)?;
        require_commitment("bridge_anchor_root", &self.bridge_anchor_root)?;
        require_commitment("state_delta_root", &self.state_delta_root)?;
        if self.compressed_fee_units > self.low_fee_cost_units {
            return Err("compressed_fee_units cannot exceed low_fee_cost_units".to_string());
        }
        if let Some(anchor_tx_id) = &self.anchor_tx_id {
            require_non_empty("anchor_tx_id", anchor_tx_id)?;
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityNettingPoolRoots {
    pub config_root: String,
    pub bucket_root: String,
    pub intent_root: String,
    pub solver_root: String,
    pub proof_root: String,
    pub rebate_root: String,
    pub risk_root: String,
    pub settlement_root: String,
}

impl PrivateLiquidityNettingPoolRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bucket_root": self.bucket_root,
            "intent_root": self.intent_root,
            "solver_root": self.solver_root,
            "proof_root": self.proof_root,
            "rebate_root": self.rebate_root,
            "risk_root": self.risk_root,
            "settlement_root": self.settlement_root,
        })
    }

    pub fn root(&self) -> String {
        private_liquidity_netting_pool_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityNettingPoolCounters {
    pub buckets: usize,
    pub open_buckets: usize,
    pub intents: usize,
    pub active_intents: usize,
    pub solver_commitments: usize,
    pub usable_solver_commitments: usize,
    pub batch_proofs: usize,
    pub settlement_ready_batches: usize,
    pub rebates: usize,
    pub claimable_rebates: usize,
    pub risk_limits: usize,
    pub constrained_risk_limits: usize,
    pub settlement_roots: usize,
}

impl PrivateLiquidityNettingPoolCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "buckets": self.buckets,
            "open_buckets": self.open_buckets,
            "intents": self.intents,
            "active_intents": self.active_intents,
            "solver_commitments": self.solver_commitments,
            "usable_solver_commitments": self.usable_solver_commitments,
            "batch_proofs": self.batch_proofs,
            "settlement_ready_batches": self.settlement_ready_batches,
            "rebates": self.rebates,
            "claimable_rebates": self.claimable_rebates,
            "risk_limits": self.risk_limits,
            "constrained_risk_limits": self.constrained_risk_limits,
            "settlement_roots": self.settlement_roots,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidityNettingPoolState {
    pub config: PrivateLiquidityNettingPoolConfig,
    pub height: u64,
    pub buckets: BTreeMap<String, TokenPairBucket>,
    pub intents: BTreeMap<String, IntentCommitment>,
    pub solver_commitments: BTreeMap<String, SolverLiquidityCommitment>,
    pub batch_proofs: BTreeMap<String, BatchNettingProof>,
    pub fee_rebates: BTreeMap<String, FeeRebateNote>,
    pub risk_limits: BTreeMap<String, AntiCorrelationRiskLimit>,
    pub settlement_roots: BTreeMap<String, LowFeeSettlementRoot>,
    pub bucket_intent_index: BTreeMap<String, BTreeSet<String>>,
    pub bucket_solver_index: BTreeMap<String, BTreeSet<String>>,
}

impl Default for PrivateLiquidityNettingPoolState {
    fn default() -> Self {
        Self {
            config: PrivateLiquidityNettingPoolConfig::default(),
            height: 0,
            buckets: BTreeMap::new(),
            intents: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            batch_proofs: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            risk_limits: BTreeMap::new(),
            settlement_roots: BTreeMap::new(),
            bucket_intent_index: BTreeMap::new(),
            bucket_solver_index: BTreeMap::new(),
        }
    }
}

impl PrivateLiquidityNettingPoolState {
    pub fn new(
        config: PrivateLiquidityNettingPoolConfig,
    ) -> PrivateLiquidityNettingPoolResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> PrivateLiquidityNettingPoolResult<Self> {
        let mut state = Self::default();
        state.set_height(PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_HEIGHT);

        let swap_bucket = TokenPairBucket::devnet(
            "devnet-bucket-wxmr-dusd-1",
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID,
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_STABLE_ASSET_ID,
            LiquidityFlowKind::ShieldedSwap,
            state.height,
        );
        let bridge_bucket = TokenPairBucket::devnet(
            "devnet-bucket-wxmr-xmr-out-1",
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID,
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_XMR_ASSET_ID,
            LiquidityFlowKind::MoneroBridgeOut,
            state.height,
        );
        state.upsert_bucket(swap_bucket)?;
        state.upsert_bucket(bridge_bucket)?;

        state.upsert_intent(IntentCommitment::devnet_swap(
            "devnet-intent-swap-1",
            "devnet-bucket-wxmr-dusd-1",
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID,
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_STABLE_ASSET_ID,
            12,
            state.height,
        ))?;
        state.upsert_intent(IntentCommitment::devnet_swap(
            "devnet-intent-swap-2",
            "devnet-bucket-wxmr-dusd-1",
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID,
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_STABLE_ASSET_ID,
            14,
            state.height,
        ))?;
        state.upsert_intent(IntentCommitment::devnet_bridge_out(
            "devnet-intent-bridge-out-1",
            "devnet-bucket-wxmr-xmr-out-1",
            10,
            state.height,
        ))?;

        state.upsert_solver_commitment(SolverLiquidityCommitment::devnet(
            "devnet-solver-1",
            "devnet-solver-commitment-1",
            "devnet-bucket-wxmr-dusd-1",
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID,
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_STABLE_ASSET_ID,
            state.height,
        ))?;
        state.upsert_solver_commitment(SolverLiquidityCommitment::devnet(
            "devnet-solver-bridge-1",
            "devnet-solver-commitment-bridge-1",
            "devnet-bucket-wxmr-xmr-out-1",
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID,
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_XMR_ASSET_ID,
            state.height,
        ))?;

        let swap_pair_key = canonical_pair_key(
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID,
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_STABLE_ASSET_ID,
        );
        state.upsert_risk_limit(AntiCorrelationRiskLimit::devnet(
            "devnet-risk-wxmr-dusd-1",
            &swap_pair_key,
            state.height,
        ))?;
        let bridge_pair_key = canonical_pair_key(
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_WXMR_ASSET_ID,
            PRIVATE_LIQUIDITY_NETTING_POOL_DEVNET_XMR_ASSET_ID,
        );
        state.upsert_risk_limit(AntiCorrelationRiskLimit::devnet(
            "devnet-risk-wxmr-xmr-1",
            &bridge_pair_key,
            state.height,
        ))?;

        let intent_root = state.intent_root();
        let solver_root = state.solver_root();
        let risk_root = state.risk_root();
        state.upsert_batch_proof(BatchNettingProof::devnet(
            "devnet-proof-wxmr-dusd-1",
            "devnet-batch-wxmr-dusd-1",
            "devnet-bucket-wxmr-dusd-1",
            intent_root.clone(),
            solver_root.clone(),
            risk_root.clone(),
            state.height + 2,
        ))?;
        state.upsert_fee_rebate(FeeRebateNote::devnet(
            "devnet-rebate-1",
            "devnet-batch-wxmr-dusd-1",
            "alice",
            state.height + 2,
        ))?;
        let proof_root = state.proof_root();
        let rebate_root = state.rebate_root();
        state.upsert_settlement_root(LowFeeSettlementRoot::devnet(
            "devnet-settlement-wxmr-dusd-1",
            "devnet-batch-wxmr-dusd-1",
            intent_root,
            solver_root,
            proof_root,
            rebate_root,
            state.height + 4,
        ))?;

        state.recompute_bucket_counters();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn upsert_bucket(
        &mut self,
        bucket: TokenPairBucket,
    ) -> PrivateLiquidityNettingPoolResult<String> {
        let root = bucket.validate()?;
        self.bucket_intent_index
            .entry(bucket.bucket_id.clone())
            .or_default();
        self.bucket_solver_index
            .entry(bucket.bucket_id.clone())
            .or_default();
        self.buckets.insert(bucket.bucket_id.clone(), bucket);
        Ok(root)
    }

    pub fn upsert_intent(
        &mut self,
        intent: IntentCommitment,
    ) -> PrivateLiquidityNettingPoolResult<String> {
        let root = intent.validate()?;
        let bucket = self
            .buckets
            .get(&intent.bucket_id)
            .ok_or_else(|| format!("intent references unknown bucket {}", intent.bucket_id))?;
        if canonical_pair_key(&intent.base_asset_id, &intent.quote_asset_id) != bucket.pair_key {
            return Err("intent pair does not match bucket pair".to_string());
        }
        let bucket_intents = self
            .bucket_intent_index
            .entry(intent.bucket_id.clone())
            .or_default();
        if !self.intents.contains_key(&intent.intent_id)
            && bucket_intents.len() >= self.config.max_intents_per_bucket
        {
            return Err("bucket intent capacity exceeded".to_string());
        }
        bucket_intents.insert(intent.intent_id.clone());
        self.intents.insert(intent.intent_id.clone(), intent);
        self.recompute_bucket_counters();
        Ok(root)
    }

    pub fn upsert_solver_commitment(
        &mut self,
        solver: SolverLiquidityCommitment,
    ) -> PrivateLiquidityNettingPoolResult<String> {
        let root = solver.validate()?;
        let bucket = self.buckets.get(&solver.bucket_id).ok_or_else(|| {
            format!(
                "solver commitment references unknown bucket {}",
                solver.bucket_id
            )
        })?;
        if solver.pair_key != bucket.pair_key {
            return Err("solver commitment pair does not match bucket pair".to_string());
        }
        let bucket_solvers = self
            .bucket_solver_index
            .entry(solver.bucket_id.clone())
            .or_default();
        if !self.solver_commitments.contains_key(&solver.commitment_id)
            && bucket_solvers.len() >= self.config.max_solvers_per_bucket
        {
            return Err("bucket solver capacity exceeded".to_string());
        }
        bucket_solvers.insert(solver.commitment_id.clone());
        self.solver_commitments
            .insert(solver.commitment_id.clone(), solver);
        self.recompute_bucket_counters();
        Ok(root)
    }

    pub fn upsert_batch_proof(
        &mut self,
        proof: BatchNettingProof,
    ) -> PrivateLiquidityNettingPoolResult<String> {
        let root = proof.validate()?;
        if !self.buckets.contains_key(&proof.bucket_id) {
            return Err(format!(
                "batch proof references unknown bucket {}",
                proof.bucket_id
            ));
        }
        if proof.privacy_set_size < self.config.min_batch_privacy_set {
            return Err("batch proof privacy set is below configured minimum".to_string());
        }
        if proof.netting_imbalance_bps > self.config.max_netting_imbalance_bps {
            return Err("batch proof netting imbalance exceeds configured limit".to_string());
        }
        self.batch_proofs.insert(proof.proof_id.clone(), proof);
        Ok(root)
    }

    pub fn upsert_fee_rebate(
        &mut self,
        rebate: FeeRebateNote,
    ) -> PrivateLiquidityNettingPoolResult<String> {
        let root = rebate.validate()?;
        self.fee_rebates.insert(rebate.rebate_id.clone(), rebate);
        Ok(root)
    }

    pub fn upsert_risk_limit(
        &mut self,
        risk_limit: AntiCorrelationRiskLimit,
    ) -> PrivateLiquidityNettingPoolResult<String> {
        let root = risk_limit.validate()?;
        if risk_limit.observed_correlation_bps > risk_limit.max_correlation_bps
            && matches!(risk_limit.status, RiskLimitStatus::Cleared)
        {
            return Err("cleared risk limit cannot exceed max correlation".to_string());
        }
        if risk_limit.observed_bridge_share_bps > risk_limit.max_bridge_share_bps
            && matches!(risk_limit.status, RiskLimitStatus::Cleared)
        {
            return Err("cleared risk limit cannot exceed max bridge share".to_string());
        }
        self.risk_limits
            .insert(risk_limit.limit_id.clone(), risk_limit);
        Ok(root)
    }

    pub fn upsert_settlement_root(
        &mut self,
        settlement: LowFeeSettlementRoot,
    ) -> PrivateLiquidityNettingPoolResult<String> {
        let root = settlement.validate()?;
        self.settlement_roots
            .insert(settlement.settlement_id.clone(), settlement);
        Ok(root)
    }

    pub fn roots(&self) -> PrivateLiquidityNettingPoolRoots {
        PrivateLiquidityNettingPoolRoots {
            config_root: self.config.commitment(),
            bucket_root: self.bucket_root(),
            intent_root: self.intent_root(),
            solver_root: self.solver_root(),
            proof_root: self.proof_root(),
            rebate_root: self.rebate_root(),
            risk_root: self.risk_root(),
            settlement_root: self.settlement_root_records(),
        }
    }

    pub fn counters(&self) -> PrivateLiquidityNettingPoolCounters {
        PrivateLiquidityNettingPoolCounters {
            buckets: self.buckets.len(),
            open_buckets: self
                .buckets
                .values()
                .filter(|bucket| bucket.status.accepts_intents())
                .count(),
            intents: self.intents.len(),
            active_intents: self
                .intents
                .values()
                .filter(|intent| intent.status.active())
                .count(),
            solver_commitments: self.solver_commitments.len(),
            usable_solver_commitments: self
                .solver_commitments
                .values()
                .filter(|solver| solver.status.usable())
                .count(),
            batch_proofs: self.batch_proofs.len(),
            settlement_ready_batches: self
                .batch_proofs
                .values()
                .filter(|proof| proof.status.settlement_ready())
                .count(),
            rebates: self.fee_rebates.len(),
            claimable_rebates: self
                .fee_rebates
                .values()
                .filter(|rebate| matches!(rebate.status, RebateStatus::Claimable))
                .count(),
            risk_limits: self.risk_limits.len(),
            constrained_risk_limits: self
                .risk_limits
                .values()
                .filter(|limit| {
                    matches!(
                        limit.status,
                        RiskLimitStatus::Constrained | RiskLimitStatus::Halted
                    )
                })
                .count(),
            settlement_roots: self.settlement_roots.len(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "hash_suite": PRIVATE_LIQUIDITY_NETTING_POOL_HASH_SUITE,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let record = json!({
            "height": self.height,
            "config_root": self.config.commitment(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        });
        private_liquidity_netting_pool_payload_root("STATE", &record)
    }

    pub fn validate(&self) -> PrivateLiquidityNettingPoolResult<String> {
        self.config.validate()?;
        for bucket in self.buckets.values() {
            bucket.validate()?;
            if bucket.bridge_share_bps > self.config.max_bridge_share_bps {
                return Err(format!(
                    "bucket {} exceeds bridge share limit",
                    bucket.bucket_id
                ));
            }
            if bucket.correlation_score_bps > self.config.max_correlation_bps {
                return Err(format!(
                    "bucket {} exceeds correlation limit",
                    bucket.bucket_id
                ));
            }
        }
        for intent in self.intents.values() {
            intent.validate()?;
            let bucket = self
                .buckets
                .get(&intent.bucket_id)
                .ok_or_else(|| format!("intent {} references missing bucket", intent.intent_id))?;
            if canonical_pair_key(&intent.base_asset_id, &intent.quote_asset_id) != bucket.pair_key
            {
                return Err(format!(
                    "intent {} pair does not match bucket",
                    intent.intent_id
                ));
            }
        }
        for solver in self.solver_commitments.values() {
            solver.validate()?;
            let bucket = self.buckets.get(&solver.bucket_id).ok_or_else(|| {
                format!(
                    "solver commitment {} references missing bucket",
                    solver.commitment_id
                )
            })?;
            if solver.pair_key != bucket.pair_key {
                return Err(format!(
                    "solver commitment {} pair does not match bucket",
                    solver.commitment_id
                ));
            }
        }
        for proof in self.batch_proofs.values() {
            proof.validate()?;
            if proof.privacy_set_size < self.config.min_batch_privacy_set {
                return Err(format!(
                    "proof {} privacy set below minimum",
                    proof.proof_id
                ));
            }
            if proof.netting_imbalance_bps > self.config.max_netting_imbalance_bps {
                return Err(format!("proof {} imbalance exceeds limit", proof.proof_id));
            }
        }
        for rebate in self.fee_rebates.values() {
            rebate.validate()?;
        }
        for risk_limit in self.risk_limits.values() {
            risk_limit.validate()?;
            if risk_limit.max_correlation_bps > self.config.max_correlation_bps {
                return Err(format!(
                    "risk limit {} exceeds configured max correlation",
                    risk_limit.limit_id
                ));
            }
            if risk_limit.max_bridge_share_bps > self.config.max_bridge_share_bps {
                return Err(format!(
                    "risk limit {} exceeds configured max bridge share",
                    risk_limit.limit_id
                ));
            }
        }
        for settlement in self.settlement_roots.values() {
            settlement.validate()?;
        }
        self.validate_indexes()?;
        Ok(self.state_root())
    }

    pub fn bucket_root(&self) -> String {
        merkle_root(
            "PRIVATE-LIQUIDITY-NETTING-POOL:BUCKETS",
            &map_records(&self.buckets, |bucket| bucket.public_record()),
        )
    }

    pub fn intent_root(&self) -> String {
        merkle_root(
            "PRIVATE-LIQUIDITY-NETTING-POOL:INTENTS",
            &map_records(&self.intents, |intent| intent.public_record()),
        )
    }

    pub fn solver_root(&self) -> String {
        merkle_root(
            "PRIVATE-LIQUIDITY-NETTING-POOL:SOLVERS",
            &map_records(&self.solver_commitments, |solver| solver.public_record()),
        )
    }

    pub fn proof_root(&self) -> String {
        merkle_root(
            "PRIVATE-LIQUIDITY-NETTING-POOL:PROOFS",
            &map_records(&self.batch_proofs, |proof| proof.public_record()),
        )
    }

    pub fn rebate_root(&self) -> String {
        merkle_root(
            "PRIVATE-LIQUIDITY-NETTING-POOL:REBATES",
            &map_records(&self.fee_rebates, |rebate| rebate.public_record()),
        )
    }

    pub fn risk_root(&self) -> String {
        merkle_root(
            "PRIVATE-LIQUIDITY-NETTING-POOL:RISK-LIMITS",
            &map_records(&self.risk_limits, |risk| risk.public_record()),
        )
    }

    pub fn settlement_root_records(&self) -> String {
        merkle_root(
            "PRIVATE-LIQUIDITY-NETTING-POOL:SETTLEMENT-ROOTS",
            &map_records(&self.settlement_roots, |settlement| {
                settlement.public_record()
            }),
        )
    }

    fn recompute_bucket_counters(&mut self) {
        for bucket in self.buckets.values_mut() {
            bucket.intent_count = self
                .bucket_intent_index
                .get(&bucket.bucket_id)
                .map(BTreeSet::len)
                .unwrap_or_default() as u64;
            bucket.solver_count = self
                .bucket_solver_index
                .get(&bucket.bucket_id)
                .map(BTreeSet::len)
                .unwrap_or_default() as u64;
            let bridge_intents = self
                .bucket_intent_index
                .get(&bucket.bucket_id)
                .map(|ids| {
                    ids.iter()
                        .filter_map(|id| self.intents.get(id))
                        .filter(|intent| intent.flow_kind.is_bridge())
                        .count()
                })
                .unwrap_or_default() as u64;
            bucket.bridge_share_bps = ratio_bps(bridge_intents, bucket.intent_count);
        }
    }

    fn validate_indexes(&self) -> PrivateLiquidityNettingPoolResult<()> {
        for (bucket_id, intent_ids) in &self.bucket_intent_index {
            if !self.buckets.contains_key(bucket_id) {
                return Err(format!(
                    "intent index references missing bucket {bucket_id}"
                ));
            }
            if intent_ids.len() > self.config.max_intents_per_bucket {
                return Err(format!(
                    "intent index capacity exceeded for bucket {bucket_id}"
                ));
            }
            for intent_id in intent_ids {
                let intent = self
                    .intents
                    .get(intent_id)
                    .ok_or_else(|| format!("intent index references missing intent {intent_id}"))?;
                if &intent.bucket_id != bucket_id {
                    return Err(format!("intent index mismatch for intent {intent_id}"));
                }
            }
        }
        for (bucket_id, solver_ids) in &self.bucket_solver_index {
            if !self.buckets.contains_key(bucket_id) {
                return Err(format!(
                    "solver index references missing bucket {bucket_id}"
                ));
            }
            if solver_ids.len() > self.config.max_solvers_per_bucket {
                return Err(format!(
                    "solver index capacity exceeded for bucket {bucket_id}"
                ));
            }
            for solver_id in solver_ids {
                let solver = self.solver_commitments.get(solver_id).ok_or_else(|| {
                    format!("solver index references missing solver commitment {solver_id}")
                })?;
                if &solver.bucket_id != bucket_id {
                    return Err(format!(
                        "solver index mismatch for solver commitment {solver_id}"
                    ));
                }
            }
        }
        Ok(())
    }
}

pub fn canonical_pair_key(base_asset_id: &str, quote_asset_id: &str) -> String {
    if base_asset_id <= quote_asset_id {
        format!("{base_asset_id}/{quote_asset_id}")
    } else {
        format!("{quote_asset_id}/{base_asset_id}")
    }
}

pub fn private_liquidity_netting_pool_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-LIQUIDITY-NETTING-POOL:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn private_liquidity_netting_pool_devnet(
) -> PrivateLiquidityNettingPoolResult<PrivateLiquidityNettingPoolState> {
    PrivateLiquidityNettingPoolState::devnet()
}

fn map_records<T, F>(map: &BTreeMap<String, T>, mut record: F) -> Vec<Value>
where
    F: FnMut(&T) -> Value,
{
    map.iter()
        .map(|(key, value)| json!({"id": key, "record": record(value)}))
        .collect()
}

fn require_non_empty(field: &str, value: &str) -> PrivateLiquidityNettingPoolResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_non_zero(field: &str, value: u64) -> PrivateLiquidityNettingPoolResult<()> {
    if value == 0 {
        Err(format!("{field} must be non-zero"))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> PrivateLiquidityNettingPoolResult<()> {
    if value > PRIVATE_LIQUIDITY_NETTING_POOL_MAX_BPS {
        Err(format!(
            "{field} exceeds {} bps",
            PRIVATE_LIQUIDITY_NETTING_POOL_MAX_BPS
        ))
    } else {
        Ok(())
    }
}

fn require_commitment(field: &str, value: &str) -> PrivateLiquidityNettingPoolResult<()> {
    require_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} commitment is too short"));
    }
    Ok(())
}

fn devnet_commitment(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("PRIVATE-LIQUIDITY-NETTING-POOL:DEVNET:{domain}"),
        &[HashPart::Str(label)],
        32,
    )
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(PRIVATE_LIQUIDITY_NETTING_POOL_MAX_BPS) / denominator
    }
}
