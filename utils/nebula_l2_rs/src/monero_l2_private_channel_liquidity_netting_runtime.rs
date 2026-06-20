use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PrivateChannelLiquidityNettingRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-private-channel-liquidity-netting-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_HEIGHT: u64 = 214_000;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_CHANNEL_BOOK: &str =
    "devnet-monero-l2-private-channel-book";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_LIQUIDITY_POOL: &str =
    "devnet-monero-l2-private-liquidity-pool";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_CHANNEL_UPDATE_SCHEME: &str =
    "roots-only-monero-l2-private-channel-update-v1";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_PQ_COMMITMENT_SCHEME: &str =
    "ml-dsa-87-channel-state-commitment-root-v1";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_REBALANCE_BATCH_SCHEME: &str =
    "private-channel-liquidity-rebalance-batch-root-v1";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DISPUTE_WINDOW_SCHEME: &str =
    "private-channel-dispute-window-root-v1";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_LOW_FEE_SPONSOR_SCHEME: &str =
    "low-fee-private-channel-sponsor-receipt-root-v1";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_FAST_SETTLEMENT_SCHEME: &str =
    "fast-private-channel-settlement-receipt-root-v1";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_NULLIFIER_SCHEME: &str =
    "private-channel-liquidity-nullifier-root-v1";
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_UPDATE_TTL_BLOCKS: u64 = 32;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 48;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 =
    96;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 =
    6;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    4_096;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE:
    u64 = 8_192;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    192;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 =
    256;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 24;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 6;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 =
    7_500;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MAX_NET_IMBALANCE_BPS: u64 =
    175;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_UPDATES: usize = 262_144;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_COMMITMENTS: usize = 262_144;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_BATCHES: usize = 131_072;
pub const MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_RECEIPTS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelUpdateKind {
    Open,
    Pay,
    Receive,
    AddLiquidity,
    RemoveLiquidity,
    CooperativeClose,
    ForceClose,
}

impl ChannelUpdateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Pay => "pay",
            Self::Receive => "receive",
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::CooperativeClose => "cooperative_close",
            Self::ForceClose => "force_close",
        }
    }

    pub fn closes_channel(self) -> bool {
        matches!(self, Self::CooperativeClose | Self::ForceClose)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelUpdateStatus {
    Proposed,
    PqCommitted,
    Netted,
    Settled,
    Disputed,
    Expired,
    Rejected,
}

impl ChannelUpdateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PqCommitted => "pq_committed",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Proposed | Self::PqCommitted | Self::Netted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceBatchStatus {
    Open,
    Sealed,
    SettlementReady,
    FastSettled,
    Settled,
    Disputed,
    Expired,
}

impl RebalanceBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::SettlementReady => "settlement_ready",
            Self::FastSettled => "fast_settled",
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
pub enum DisputeStatus {
    Open,
    Challenged,
    Resolved,
    Expired,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Challenged => "challenged",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Failed,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub channel_book: String,
    pub liquidity_pool: String,
    pub hash_suite: String,
    pub channel_update_scheme: String,
    pub pq_commitment_scheme: String,
    pub rebalance_batch_scheme: String,
    pub dispute_window_scheme: String,
    pub low_fee_sponsor_scheme: String,
    pub fast_settlement_scheme: String,
    pub nullifier_scheme: String,
    pub genesis_height: u64,
    pub update_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub dispute_window_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_net_imbalance_bps: u64,
    pub roots_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_SCHEMA_VERSION,
            monero_network:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            l2_network: MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            channel_book:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_CHANNEL_BOOK
                    .to_string(),
            liquidity_pool:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_LIQUIDITY_POOL
                    .to_string(),
            hash_suite: MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_HASH_SUITE
                .to_string(),
            channel_update_scheme:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_CHANNEL_UPDATE_SCHEME
                    .to_string(),
            pq_commitment_scheme:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_PQ_COMMITMENT_SCHEME
                    .to_string(),
            rebalance_batch_scheme:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_REBALANCE_BATCH_SCHEME
                    .to_string(),
            dispute_window_scheme:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DISPUTE_WINDOW_SCHEME
                    .to_string(),
            low_fee_sponsor_scheme:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_LOW_FEE_SPONSOR_SCHEME
                    .to_string(),
            fast_settlement_scheme:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_FAST_SETTLEMENT_SCHEME
                    .to_string(),
            nullifier_scheme:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_NULLIFIER_SCHEME.to_string(),
            genesis_height: MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_HEIGHT,
            update_ttl_blocks:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_UPDATE_TTL_BLOCKS,
            batch_ttl_blocks:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            dispute_window_blocks:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS,
            fast_settlement_blocks:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_FAST_SETTLEMENT_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_LOW_FEE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            max_net_imbalance_bps:
                MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEFAULT_MAX_NET_IMBALANCE_BPS,
            roots_only: true,
        }
    }

    pub fn validate(&self) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("config chain id does not match runtime chain id".to_string());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported private channel liquidity netting protocol".to_string());
        }
        if !self.roots_only {
            return Err(
                "private channel liquidity netting requires roots-only privacy".to_string(),
            );
        }
        if self.monero_network.is_empty()
            || self.l2_network.is_empty()
            || self.channel_book.is_empty()
            || self.liquidity_pool.is_empty()
            || self.hash_suite.is_empty()
            || self.channel_update_scheme.is_empty()
            || self.pq_commitment_scheme.is_empty()
            || self.rebalance_batch_scheme.is_empty()
            || self.dispute_window_scheme.is_empty()
            || self.low_fee_sponsor_scheme.is_empty()
            || self.fast_settlement_scheme.is_empty()
            || self.nullifier_scheme.is_empty()
        {
            return Err("private channel liquidity netting labels cannot be empty".to_string());
        }
        if self.update_ttl_blocks == 0
            || self.batch_ttl_blocks == 0
            || self.dispute_window_blocks == 0
            || self.fast_settlement_blocks == 0
            || self.min_privacy_set_size == 0
        {
            return Err("private channel liquidity netting windows must be positive".to_string());
        }
        if self.min_batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch privacy set must cover channel update privacy set".to_string());
        }
        if self.min_pq_security_bits < 128
            || self.target_pq_security_bits < self.min_pq_security_bits
        {
            return Err("invalid post-quantum security bit policy".to_string());
        }
        if self.low_fee_bps > self.max_user_fee_bps
            || self.max_user_fee_bps > MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_BPS
            || self.sponsor_cover_bps > MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_BPS
            || self.max_net_imbalance_bps
                > MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_BPS
        {
            return Err("private channel liquidity netting bps policy is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_liquidity_netting_runtime_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "channel_book": self.channel_book,
            "liquidity_pool": self.liquidity_pool,
            "hash_suite": self.hash_suite,
            "channel_update_scheme": self.channel_update_scheme,
            "pq_commitment_scheme": self.pq_commitment_scheme,
            "rebalance_batch_scheme": self.rebalance_batch_scheme,
            "dispute_window_scheme": self.dispute_window_scheme,
            "low_fee_sponsor_scheme": self.low_fee_sponsor_scheme,
            "fast_settlement_scheme": self.fast_settlement_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "genesis_height": self.genesis_height,
            "update_ttl_blocks": self.update_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "dispute_window_blocks": self.dispute_window_blocks,
            "fast_settlement_blocks": self.fast_settlement_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "max_net_imbalance_bps": self.max_net_imbalance_bps,
            "privacy": "roots_only",
            "roots_only": self.roots_only,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub channel_updates: u64,
    pub pq_commitments: u64,
    pub rebalance_batches: u64,
    pub dispute_windows: u64,
    pub sponsor_receipts: u64,
    pub fast_settlement_receipts: u64,
    pub settled_batches: u64,
    pub disputed_batches: u64,
    pub replay_rejections: u64,
    pub pq_rejections: u64,
    pub fee_rejections: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_liquidity_netting_runtime_counters",
            "channel_updates": self.channel_updates,
            "pq_commitments": self.pq_commitments,
            "rebalance_batches": self.rebalance_batches,
            "dispute_windows": self.dispute_windows,
            "sponsor_receipts": self.sponsor_receipts,
            "fast_settlement_receipts": self.fast_settlement_receipts,
            "settled_batches": self.settled_batches,
            "disputed_batches": self.disputed_batches,
            "replay_rejections": self.replay_rejections,
            "pq_rejections": self.pq_rejections,
            "fee_rejections": self.fee_rejections,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitChannelUpdateRequest {
    pub channel_id: String,
    pub update_kind: ChannelUpdateKind,
    pub prior_state_root: String,
    pub proposed_state_root: String,
    pub balance_delta_root: String,
    pub liquidity_delta_root: String,
    pub fee_commitment_root: String,
    pub route_hint_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub nullifier: String,
    pub replay_fence: String,
    pub submitted_at_height: u64,
    pub client_nonce: String,
}

impl SubmitChannelUpdateRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
        require_non_empty("channel id", &self.channel_id)?;
        require_root("prior state root", &self.prior_state_root)?;
        require_root("proposed state root", &self.proposed_state_root)?;
        require_root("balance delta root", &self.balance_delta_root)?;
        require_root("liquidity delta root", &self.liquidity_delta_root)?;
        require_root("fee commitment root", &self.fee_commitment_root)?;
        require_root("route hint root", &self.route_hint_root)?;
        require_root("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("nullifier", &self.nullifier)?;
        require_non_empty("replay fence", &self.replay_fence)?;
        require_non_empty("client nonce", &self.client_nonce)?;
        require_privacy_set(config, self.privacy_set_size, false)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("channel update fee cap exceeds configured maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqStateCommitmentRequest {
    pub update_id: String,
    pub state_commitment_root: String,
    pub signer_set_root: String,
    pub pq_signature_root: String,
    pub pq_transcript_root: String,
    pub pq_security_bits: u16,
    pub committed_at_height: u64,
    pub commitment_nonce: String,
}

impl PqStateCommitmentRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
        require_non_empty("update id", &self.update_id)?;
        require_root("state commitment root", &self.state_commitment_root)?;
        require_root("signer set root", &self.signer_set_root)?;
        require_root("PQ signature root", &self.pq_signature_root)?;
        require_root("PQ transcript root", &self.pq_transcript_root)?;
        require_non_empty("commitment nonce", &self.commitment_nonce)?;
        require_pq_security(config, self.pq_security_bits)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildRebalanceBatchRequest {
    pub batch_label: String,
    pub update_ids: Vec<String>,
    pub solver_id: String,
    pub netted_channel_root: String,
    pub net_liquidity_delta_root: String,
    pub fee_plan_root: String,
    pub sponsor_plan_root: String,
    pub settlement_plan_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub net_imbalance_bps: u64,
    pub sealed_at_height: u64,
    pub batch_nonce: String,
}

impl BuildRebalanceBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
        require_non_empty("batch label", &self.batch_label)?;
        require_non_empty("solver id", &self.solver_id)?;
        require_root("netted channel root", &self.netted_channel_root)?;
        require_root("net liquidity delta root", &self.net_liquidity_delta_root)?;
        require_root("fee plan root", &self.fee_plan_root)?;
        require_root("sponsor plan root", &self.sponsor_plan_root)?;
        require_root("settlement plan root", &self.settlement_plan_root)?;
        require_root("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("batch nonce", &self.batch_nonce)?;
        require_privacy_set(config, self.privacy_set_size, true)?;
        if self.update_ids.is_empty() {
            return Err("rebalance batch must include channel updates".to_string());
        }
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("rebalance batch fee exceeds configured maximum".to_string());
        }
        if self.net_imbalance_bps > config.max_net_imbalance_bps {
            return Err("rebalance batch net imbalance exceeds configured maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenDisputeWindowRequest {
    pub batch_id: String,
    pub challenge_root: String,
    pub challenger_set_root: String,
    pub evidence_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub dispute_nonce: String,
}

impl OpenDisputeWindowRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_root("challenge root", &self.challenge_root)?;
        require_root("challenger set root", &self.challenger_set_root)?;
        require_root("evidence root", &self.evidence_root)?;
        require_root("PQ signature root", &self.pq_signature_root)?;
        require_non_empty("dispute nonce", &self.dispute_nonce)?;
        require_pq_security(config, self.pq_security_bits)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReceiptRequest {
    pub batch_id: String,
    pub sponsor_id: String,
    pub sponsor_receipt_root: String,
    pub fee_subsidy_root: String,
    pub beneficiary_set_root: String,
    pub covered_fee_bps: u64,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub published_at_height: u64,
    pub receipt_nonce: String,
}

impl SponsorReceiptRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_non_empty("sponsor id", &self.sponsor_id)?;
        require_root("sponsor receipt root", &self.sponsor_receipt_root)?;
        require_root("fee subsidy root", &self.fee_subsidy_root)?;
        require_root("beneficiary set root", &self.beneficiary_set_root)?;
        require_root("PQ signature root", &self.pq_signature_root)?;
        require_non_empty("receipt nonce", &self.receipt_nonce)?;
        require_pq_security(config, self.pq_security_bits)?;
        if self.covered_fee_bps < config.low_fee_bps
            || self.covered_fee_bps > config.sponsor_cover_bps
        {
            return Err(
                "sponsor receipt coverage is outside configured low-fee policy".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastSettlementReceiptRequest {
    pub batch_id: String,
    pub sponsor_receipt_id: Option<String>,
    pub settlement_receipt_root: String,
    pub settlement_tx_root: String,
    pub liquidity_release_root: String,
    pub final_state_root: String,
    pub pq_receipt_root: String,
    pub pq_security_bits: u16,
    pub status: ReceiptStatus,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
    pub settlement_nonce: String,
}

impl FastSettlementReceiptRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_root("settlement receipt root", &self.settlement_receipt_root)?;
        require_root("settlement tx root", &self.settlement_tx_root)?;
        require_root("liquidity release root", &self.liquidity_release_root)?;
        require_root("final state root", &self.final_state_root)?;
        require_root("PQ receipt root", &self.pq_receipt_root)?;
        require_non_empty("settlement nonce", &self.settlement_nonce)?;
        require_pq_security(config, self.pq_security_bits)?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.settled_at_height {
                return Err("finalized height cannot precede settled height".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateChannelUpdateRecord {
    pub update_id: String,
    pub channel_id: String,
    pub update_kind: ChannelUpdateKind,
    pub status: ChannelUpdateStatus,
    pub prior_state_root: String,
    pub proposed_state_root: String,
    pub balance_delta_root: String,
    pub liquidity_delta_root: String,
    pub fee_commitment_root: String,
    pub route_hint_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateChannelUpdateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_update",
            "update_id": self.update_id,
            "channel_id": self.channel_id,
            "update_kind": self.update_kind.as_str(),
            "status": self.status.as_str(),
            "prior_state_root": self.prior_state_root,
            "proposed_state_root": self.proposed_state_root,
            "balance_delta_root": self.balance_delta_root,
            "liquidity_delta_root": self.liquidity_delta_root,
            "fee_commitment_root": self.fee_commitment_root,
            "route_hint_root": self.route_hint_root,
            "privacy_proof_root": self.privacy_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PRIVATE-CHANNEL-UPDATE-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqStateCommitmentRecord {
    pub commitment_id: String,
    pub update_id: String,
    pub state_commitment_root: String,
    pub signer_set_root: String,
    pub pq_signature_root: String,
    pub pq_transcript_root: String,
    pub pq_security_bits: u16,
    pub committed_at_height: u64,
}

impl PqStateCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_pq_state_commitment",
            "commitment_id": self.commitment_id,
            "update_id": self.update_id,
            "state_commitment_root": self.state_commitment_root,
            "signer_set_root": self.signer_set_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_transcript_root": self.pq_transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "committed_at_height": self.committed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRebalanceBatchRecord {
    pub batch_id: String,
    pub status: RebalanceBatchStatus,
    pub batch_label: String,
    pub update_root: String,
    pub update_ids: Vec<String>,
    pub solver_id: String,
    pub netted_channel_root: String,
    pub net_liquidity_delta_root: String,
    pub fee_plan_root: String,
    pub sponsor_plan_root: String,
    pub settlement_plan_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub net_imbalance_bps: u64,
    pub sealed_at_height: u64,
    pub settlement_deadline_height: u64,
    pub dispute_deadline_height: u64,
}

impl ChannelRebalanceBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_rebalance_batch",
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "batch_label": self.batch_label,
            "update_root": self.update_root,
            "update_ids": self.update_ids,
            "solver_id": self.solver_id,
            "netted_channel_root": self.netted_channel_root,
            "net_liquidity_delta_root": self.net_liquidity_delta_root,
            "fee_plan_root": self.fee_plan_root,
            "sponsor_plan_root": self.sponsor_plan_root,
            "settlement_plan_root": self.settlement_plan_root,
            "privacy_proof_root": self.privacy_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "net_imbalance_bps": self.net_imbalance_bps,
            "sealed_at_height": self.sealed_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "dispute_deadline_height": self.dispute_deadline_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeWindowRecord {
    pub dispute_id: String,
    pub batch_id: String,
    pub status: DisputeStatus,
    pub challenge_root: String,
    pub challenger_set_root: String,
    pub evidence_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl DisputeWindowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_dispute_window",
            "dispute_id": self.dispute_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "challenge_root": self.challenge_root,
            "challenger_set_root": self.challenger_set_root,
            "evidence_root": self.evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorReceiptRecord {
    pub receipt_id: String,
    pub batch_id: String,
    pub sponsor_id: String,
    pub sponsor_receipt_root: String,
    pub fee_subsidy_root: String,
    pub beneficiary_set_root: String,
    pub covered_fee_bps: u64,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub published_at_height: u64,
}

impl LowFeeSponsorReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_low_fee_sponsor_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "sponsor_id": self.sponsor_id,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "fee_subsidy_root": self.fee_subsidy_root,
            "beneficiary_set_root": self.beneficiary_set_root,
            "covered_fee_bps": self.covered_fee_bps,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastSettlementReceiptRecord {
    pub receipt_id: String,
    pub batch_id: String,
    pub sponsor_receipt_id: Option<String>,
    pub status: ReceiptStatus,
    pub settlement_receipt_root: String,
    pub settlement_tx_root: String,
    pub liquidity_release_root: String,
    pub final_state_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub pq_receipt_root: String,
    pub pq_security_bits: u16,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl FastSettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_fast_settlement_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "sponsor_receipt_id": self.sponsor_receipt_id,
            "status": self.status.as_str(),
            "settlement_receipt_root": self.settlement_receipt_root,
            "settlement_tx_root": self.settlement_tx_root,
            "liquidity_release_root": self.liquidity_release_root,
            "final_state_root": self.final_state_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "pq_receipt_root": self.pq_receipt_root,
            "pq_security_bits": self.pq_security_bits,
            "settled_at_height": self.settled_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub published_at_height: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_liquidity_public_record",
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub channel_update_root: String,
    pub pq_commitment_root: String,
    pub rebalance_batch_root: String,
    pub dispute_window_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub fast_settlement_receipt_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_private_channel_liquidity_netting_roots",
            "config_root": self.config_root,
            "channel_update_root": self.channel_update_root,
            "pq_commitment_root": self.pq_commitment_root,
            "rebalance_batch_root": self.rebalance_batch_root,
            "dispute_window_root": self.dispute_window_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "fast_settlement_receipt_root": self.fast_settlement_receipt_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "MONERO-L2-PRIVATE-CHANNEL-LIQUIDITY-NETTING-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub channel_updates: BTreeMap<String, PrivateChannelUpdateRecord>,
    pub pq_commitments: BTreeMap<String, PqStateCommitmentRecord>,
    pub rebalance_batches: BTreeMap<String, ChannelRebalanceBatchRecord>,
    pub dispute_windows: BTreeMap<String, DisputeWindowRecord>,
    pub low_fee_sponsor_receipts: BTreeMap<String, LowFeeSponsorReceiptRecord>,
    pub fast_settlement_receipts: BTreeMap<String, FastSettlementReceiptRecord>,
    pub used_nullifiers: BTreeSet<String>,
    pub used_replay_fences: BTreeSet<String>,
    pub public_records: BTreeMap<String, PublicRecord>,
}

impl State {
    pub fn devnet() -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        let mut state = Self {
            config,
            height: MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_DEVNET_HEIGHT,
            counters: Counters::default(),
            roots: Roots::empty(),
            channel_updates: BTreeMap::new(),
            pq_commitments: BTreeMap::new(),
            rebalance_batches: BTreeMap::new(),
            dispute_windows: BTreeMap::new(),
            low_fee_sponsor_receipts: BTreeMap::new(),
            fast_settlement_receipts: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            used_replay_fences: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh();
        let config_record = state.config.public_record();
        state.publish_public_record("config", "devnet", &config_record);
        state.refresh();
        Ok(state)
    }

    pub fn submit_channel_update(
        &mut self,
        request: SubmitChannelUpdateRequest,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<PrivateChannelUpdateRecord> {
        self.config.validate()?;
        if self.channel_updates.len()
            >= MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_UPDATES
        {
            return Err("private channel update limit exceeded".to_string());
        }
        if let Err(err) = request.validate(&self.config) {
            if err.contains("fee") {
                self.counters.fee_rejections = self.counters.fee_rejections.saturating_add(1);
            }
            return Err(err);
        }
        let nullifier_root = secret_root(
            "MONERO-L2-PRIVATE-CHANNEL-UPDATE-NULLIFIER",
            &request.nullifier,
        );
        let replay_fence_root = secret_root(
            "MONERO-L2-PRIVATE-CHANNEL-UPDATE-REPLAY-FENCE",
            &request.replay_fence,
        );
        self.ensure_unique_replay(&nullifier_root, &replay_fence_root)?;
        let update_id = channel_update_id(
            self.counters.channel_updates.saturating_add(1),
            &request.channel_id,
            request.update_kind,
            &request.proposed_state_root,
            &nullifier_root,
            &request.client_nonce,
        );
        let record = PrivateChannelUpdateRecord {
            update_id: update_id.clone(),
            channel_id: request.channel_id,
            update_kind: request.update_kind,
            status: ChannelUpdateStatus::Proposed,
            prior_state_root: request.prior_state_root,
            proposed_state_root: request.proposed_state_root,
            balance_delta_root: request.balance_delta_root,
            liquidity_delta_root: request.liquidity_delta_root,
            fee_commitment_root: request.fee_commitment_root,
            route_hint_root: request.route_hint_root,
            privacy_proof_root: request.privacy_proof_root,
            privacy_set_size: request.privacy_set_size,
            max_fee_bps: request.max_fee_bps,
            nullifier_root: nullifier_root.clone(),
            replay_fence_root: replay_fence_root.clone(),
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(self.config.update_ttl_blocks),
        };
        self.used_nullifiers.insert(nullifier_root);
        self.used_replay_fences.insert(replay_fence_root);
        self.channel_updates
            .insert(update_id.clone(), record.clone());
        self.counters.channel_updates = self.counters.channel_updates.saturating_add(1);
        self.height = self.height.max(record.submitted_at_height);
        self.publish_public_record("channel_update", &update_id, &record.public_record());
        self.refresh();
        Ok(record)
    }

    pub fn commit_pq_state(
        &mut self,
        request: PqStateCommitmentRequest,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<PqStateCommitmentRecord> {
        self.config.validate()?;
        if self.pq_commitments.len()
            >= MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_COMMITMENTS
        {
            return Err("PQ state commitment limit exceeded".to_string());
        }
        if let Err(err) = request.validate(&self.config) {
            if err.contains("PQ") || err.contains("post-quantum") {
                self.counters.pq_rejections = self.counters.pq_rejections.saturating_add(1);
            }
            return Err(err);
        }
        let update = self
            .channel_updates
            .get_mut(&request.update_id)
            .ok_or_else(|| "PQ state commitment references unknown channel update".to_string())?;
        if !update.status.live() {
            return Err("PQ state commitment cannot target closed update".to_string());
        }
        if request.committed_at_height > update.expires_at_height {
            update.status = ChannelUpdateStatus::Expired;
            return Err("PQ state commitment arrived after update expiry".to_string());
        }
        update.status = ChannelUpdateStatus::PqCommitted;
        let commitment_id = pq_state_commitment_id(
            self.counters.pq_commitments.saturating_add(1),
            &request.update_id,
            &request.state_commitment_root,
            &request.pq_signature_root,
            &request.commitment_nonce,
        );
        let record = PqStateCommitmentRecord {
            commitment_id: commitment_id.clone(),
            update_id: request.update_id,
            state_commitment_root: request.state_commitment_root,
            signer_set_root: request.signer_set_root,
            pq_signature_root: request.pq_signature_root,
            pq_transcript_root: request.pq_transcript_root,
            pq_security_bits: request.pq_security_bits,
            committed_at_height: request.committed_at_height,
        };
        self.pq_commitments
            .insert(commitment_id.clone(), record.clone());
        self.counters.pq_commitments = self.counters.pq_commitments.saturating_add(1);
        self.height = self.height.max(record.committed_at_height);
        self.publish_public_record(
            "pq_state_commitment",
            &commitment_id,
            &record.public_record(),
        );
        self.refresh();
        Ok(record)
    }

    pub fn build_rebalance_batch(
        &mut self,
        request: BuildRebalanceBatchRequest,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<ChannelRebalanceBatchRecord> {
        self.config.validate()?;
        if self.rebalance_batches.len()
            >= MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_BATCHES
        {
            return Err("rebalance batch limit exceeded".to_string());
        }
        request.validate(&self.config)?;
        for update_id in &request.update_ids {
            let update = self
                .channel_updates
                .get(update_id)
                .ok_or_else(|| format!("rebalance batch references unknown update {update_id}"))?;
            if update.status != ChannelUpdateStatus::PqCommitted {
                return Err("rebalance batch requires PQ committed channel updates".to_string());
            }
            if request.sealed_at_height > update.expires_at_height {
                return Err("rebalance batch includes an expired channel update".to_string());
            }
        }
        let update_root = merkle_root(
            "MONERO-L2-PRIVATE-CHANNEL-REBALANCE-BATCH-UPDATE-ID",
            &request
                .update_ids
                .iter()
                .map(|update_id| json!(update_id))
                .collect::<Vec<_>>(),
        );
        let batch_id = rebalance_batch_id(
            self.counters.rebalance_batches.saturating_add(1),
            &request.batch_label,
            &update_root,
            &request.netted_channel_root,
            &request.batch_nonce,
        );
        let record = ChannelRebalanceBatchRecord {
            batch_id: batch_id.clone(),
            status: RebalanceBatchStatus::SettlementReady,
            batch_label: request.batch_label,
            update_root,
            update_ids: request.update_ids.clone(),
            solver_id: request.solver_id,
            netted_channel_root: request.netted_channel_root,
            net_liquidity_delta_root: request.net_liquidity_delta_root,
            fee_plan_root: request.fee_plan_root,
            sponsor_plan_root: request.sponsor_plan_root,
            settlement_plan_root: request.settlement_plan_root,
            privacy_proof_root: request.privacy_proof_root,
            privacy_set_size: request.privacy_set_size,
            max_user_fee_bps: request.max_user_fee_bps,
            net_imbalance_bps: request.net_imbalance_bps,
            sealed_at_height: request.sealed_at_height,
            settlement_deadline_height: request
                .sealed_at_height
                .saturating_add(self.config.batch_ttl_blocks),
            dispute_deadline_height: request
                .sealed_at_height
                .saturating_add(self.config.dispute_window_blocks),
        };
        for update_id in &request.update_ids {
            if let Some(update) = self.channel_updates.get_mut(update_id) {
                update.status = ChannelUpdateStatus::Netted;
            }
        }
        self.rebalance_batches
            .insert(batch_id.clone(), record.clone());
        self.counters.rebalance_batches = self.counters.rebalance_batches.saturating_add(1);
        self.height = self.height.max(record.sealed_at_height);
        self.publish_public_record("rebalance_batch", &batch_id, &record.public_record());
        self.refresh();
        Ok(record)
    }

    pub fn open_dispute_window(
        &mut self,
        request: OpenDisputeWindowRequest,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<DisputeWindowRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let batch = self
            .rebalance_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "dispute references unknown rebalance batch".to_string())?;
        if request.opened_at_height > batch.dispute_deadline_height {
            return Err("dispute window cannot open after dispute deadline".to_string());
        }
        batch.status = RebalanceBatchStatus::Disputed;
        let dispute_id = dispute_window_id(
            self.counters.dispute_windows.saturating_add(1),
            &request.batch_id,
            &request.challenge_root,
            &request.dispute_nonce,
        );
        let record = DisputeWindowRecord {
            dispute_id: dispute_id.clone(),
            batch_id: request.batch_id,
            status: DisputeStatus::Open,
            challenge_root: request.challenge_root,
            challenger_set_root: request.challenger_set_root,
            evidence_root: request.evidence_root,
            pq_signature_root: request.pq_signature_root,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: request.opened_at_height,
            expires_at_height: request
                .opened_at_height
                .saturating_add(self.config.dispute_window_blocks),
        };
        self.dispute_windows
            .insert(dispute_id.clone(), record.clone());
        self.counters.dispute_windows = self.counters.dispute_windows.saturating_add(1);
        self.counters.disputed_batches = self.counters.disputed_batches.saturating_add(1);
        self.height = self.height.max(record.opened_at_height);
        self.publish_public_record("dispute_window", &dispute_id, &record.public_record());
        self.refresh();
        Ok(record)
    }

    pub fn publish_sponsor_receipt(
        &mut self,
        request: SponsorReceiptRequest,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<LowFeeSponsorReceiptRecord> {
        self.config.validate()?;
        if self.low_fee_sponsor_receipts.len()
            >= MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_RECEIPTS
        {
            return Err("low-fee sponsor receipt limit exceeded".to_string());
        }
        if let Err(err) = request.validate(&self.config) {
            if err.contains("fee") {
                self.counters.fee_rejections = self.counters.fee_rejections.saturating_add(1);
            }
            if err.contains("PQ") || err.contains("post-quantum") {
                self.counters.pq_rejections = self.counters.pq_rejections.saturating_add(1);
            }
            return Err(err);
        }
        let batch = self
            .rebalance_batches
            .get(&request.batch_id)
            .ok_or_else(|| "sponsor receipt references unknown rebalance batch".to_string())?;
        if request.published_at_height > batch.settlement_deadline_height {
            return Err("sponsor receipt arrived after settlement deadline".to_string());
        }
        let receipt_id = low_fee_sponsor_receipt_id(
            self.counters.sponsor_receipts.saturating_add(1),
            &request.batch_id,
            &request.sponsor_id,
            &request.sponsor_receipt_root,
            &request.receipt_nonce,
        );
        let record = LowFeeSponsorReceiptRecord {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id,
            sponsor_id: request.sponsor_id,
            sponsor_receipt_root: request.sponsor_receipt_root,
            fee_subsidy_root: request.fee_subsidy_root,
            beneficiary_set_root: request.beneficiary_set_root,
            covered_fee_bps: request.covered_fee_bps,
            pq_signature_root: request.pq_signature_root,
            pq_security_bits: request.pq_security_bits,
            published_at_height: request.published_at_height,
        };
        self.low_fee_sponsor_receipts
            .insert(receipt_id.clone(), record.clone());
        self.counters.sponsor_receipts = self.counters.sponsor_receipts.saturating_add(1);
        self.height = self.height.max(record.published_at_height);
        self.publish_public_record(
            "low_fee_sponsor_receipt",
            &receipt_id,
            &record.public_record(),
        );
        self.refresh();
        Ok(record)
    }

    pub fn publish_fast_settlement_receipt(
        &mut self,
        request: FastSettlementReceiptRequest,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<FastSettlementReceiptRecord> {
        self.config.validate()?;
        if self.fast_settlement_receipts.len()
            >= MONERO_L2_PRIVATE_CHANNEL_LIQUIDITY_NETTING_RUNTIME_MAX_RECEIPTS
        {
            return Err("fast settlement receipt limit exceeded".to_string());
        }
        request.validate(&self.config)?;
        let state_root_before = self.state_root();
        let batch = self
            .rebalance_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "fast settlement references unknown rebalance batch".to_string())?;
        if !batch.status.can_settle() {
            return Err("rebalance batch is not settlement ready".to_string());
        }
        if request.settled_at_height > batch.settlement_deadline_height {
            batch.status = RebalanceBatchStatus::Expired;
            return Err("fast settlement arrived after settlement deadline".to_string());
        }
        if batch.max_user_fee_bps <= self.config.low_fee_bps && request.sponsor_receipt_id.is_none()
        {
            return Err("low-fee fast settlement requires sponsor receipt id".to_string());
        }
        if let Some(sponsor_receipt_id) = &request.sponsor_receipt_id {
            if !self
                .low_fee_sponsor_receipts
                .contains_key(sponsor_receipt_id)
            {
                return Err("fast settlement references unknown sponsor receipt".to_string());
            }
        }
        batch.status = if request.settled_at_height
            <= batch
                .sealed_at_height
                .saturating_add(self.config.fast_settlement_blocks)
        {
            RebalanceBatchStatus::FastSettled
        } else {
            RebalanceBatchStatus::Settled
        };
        let update_ids = batch.update_ids.clone();
        for update_id in &update_ids {
            if let Some(update) = self.channel_updates.get_mut(update_id) {
                update.status = ChannelUpdateStatus::Settled;
            }
        }
        let receipt_id = fast_settlement_receipt_id(
            self.counters.fast_settlement_receipts.saturating_add(1),
            &request.batch_id,
            &request.settlement_receipt_root,
            &request.settlement_tx_root,
            &request.settlement_nonce,
        );
        self.height = self.height.max(request.settled_at_height);
        let state_root_after = settlement_state_root_after(
            &state_root_before,
            &request.final_state_root,
            &request.settlement_receipt_root,
        );
        let record = FastSettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id,
            sponsor_receipt_id: request.sponsor_receipt_id,
            status: request.status,
            settlement_receipt_root: request.settlement_receipt_root,
            settlement_tx_root: request.settlement_tx_root,
            liquidity_release_root: request.liquidity_release_root,
            final_state_root: request.final_state_root,
            state_root_before,
            state_root_after,
            pq_receipt_root: request.pq_receipt_root,
            pq_security_bits: request.pq_security_bits,
            settled_at_height: request.settled_at_height,
            finalized_at_height: request.finalized_at_height,
        };
        self.fast_settlement_receipts
            .insert(receipt_id.clone(), record.clone());
        self.counters.fast_settlement_receipts =
            self.counters.fast_settlement_receipts.saturating_add(1);
        self.counters.settled_batches = self.counters.settled_batches.saturating_add(1);
        self.publish_public_record(
            "fast_settlement_receipt",
            &receipt_id,
            &record.public_record(),
        );
        self.refresh();
        Ok(record)
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.public_records = self.public_records.len() as u64;
        counters
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root(
                "MONERO-L2-PRIVATE-CHANNEL-LIQUIDITY-NETTING-CONFIG",
                &self.config.public_record(),
            ),
            channel_update_root: map_root(
                "MONERO-L2-PRIVATE-CHANNEL-UPDATE-MAP",
                &self.channel_updates,
                PrivateChannelUpdateRecord::public_record,
            ),
            pq_commitment_root: map_root(
                "MONERO-L2-PRIVATE-CHANNEL-PQ-COMMITMENT-MAP",
                &self.pq_commitments,
                PqStateCommitmentRecord::public_record,
            ),
            rebalance_batch_root: map_root(
                "MONERO-L2-PRIVATE-CHANNEL-REBALANCE-BATCH-MAP",
                &self.rebalance_batches,
                ChannelRebalanceBatchRecord::public_record,
            ),
            dispute_window_root: map_root(
                "MONERO-L2-PRIVATE-CHANNEL-DISPUTE-WINDOW-MAP",
                &self.dispute_windows,
                DisputeWindowRecord::public_record,
            ),
            low_fee_sponsor_receipt_root: map_root(
                "MONERO-L2-PRIVATE-CHANNEL-LOW-FEE-SPONSOR-RECEIPT-MAP",
                &self.low_fee_sponsor_receipts,
                LowFeeSponsorReceiptRecord::public_record,
            ),
            fast_settlement_receipt_root: map_root(
                "MONERO-L2-PRIVATE-CHANNEL-FAST-SETTLEMENT-RECEIPT-MAP",
                &self.fast_settlement_receipts,
                FastSettlementReceiptRecord::public_record,
            ),
            nullifier_root: set_root(
                "MONERO-L2-PRIVATE-CHANNEL-LIQUIDITY-NULLIFIER-SET",
                &self.used_nullifiers,
            ),
            replay_fence_root: set_root(
                "MONERO-L2-PRIVATE-CHANNEL-LIQUIDITY-REPLAY-FENCE-SET",
                &self.used_replay_fences,
            ),
            public_record_root: map_root(
                "MONERO-L2-PRIVATE-CHANNEL-LIQUIDITY-PUBLIC-RECORD-MAP",
                &self.public_records,
                PublicRecord::public_record,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_private_channel_liquidity_netting_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters().public_record(),
            "state_root": self.state_root(),
            "privacy": "roots_only",
        })
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_private_channel_liquidity_netting_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters().public_record(),
            "privacy": "roots_only",
        })
    }

    pub fn state_root(&self) -> String {
        monero_l2_private_channel_liquidity_netting_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    fn refresh(&mut self) {
        self.roots = self.roots();
    }

    fn ensure_unique_replay(
        &mut self,
        nullifier_root: &str,
        replay_fence_root: &str,
    ) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
        if self.used_nullifiers.contains(nullifier_root)
            || self.used_replay_fences.contains(replay_fence_root)
        {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("nullifier or replay fence has already been consumed".to_string());
        }
        Ok(())
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: &Value) {
        let payload_root = payload_root(
            "MONERO-L2-PRIVATE-CHANNEL-LIQUIDITY-PUBLIC-PAYLOAD",
            payload,
        );
        let record_id = public_record_id(record_kind, subject_id, &payload_root, self.height);
        let record = PublicRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            published_at_height: self.height,
        };
        self.public_records.insert(record_id, record);
        self.counters.public_records = self.public_records.len() as u64;
    }
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: String::new(),
            channel_update_root: String::new(),
            pq_commitment_root: String::new(),
            rebalance_batch_root: String::new(),
            dispute_window_root: String::new(),
            low_fee_sponsor_receipt_root: String::new(),
            fast_settlement_receipt_root: String::new(),
            nullifier_root: String::new(),
            replay_fence_root: String::new(),
            public_record_root: String::new(),
        }
    }
}

pub fn monero_l2_private_channel_liquidity_netting_state_root_from_record(
    record: &Value,
) -> String {
    payload_root("MONERO-L2-PRIVATE-CHANNEL-LIQUIDITY-NETTING-STATE", record)
}

pub fn channel_update_id(
    sequence: u64,
    channel_id: &str,
    update_kind: ChannelUpdateKind,
    proposed_state_root: &str,
    nullifier_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-CHANNEL-UPDATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(channel_id),
            HashPart::Str(update_kind.as_str()),
            HashPart::Str(proposed_state_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn pq_state_commitment_id(
    sequence: u64,
    update_id: &str,
    state_commitment_root: &str,
    pq_signature_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-CHANNEL-PQ-STATE-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(update_id),
            HashPart::Str(state_commitment_root),
            HashPart::Str(pq_signature_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn rebalance_batch_id(
    sequence: u64,
    batch_label: &str,
    update_root: &str,
    netted_channel_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-CHANNEL-REBALANCE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(batch_label),
            HashPart::Str(update_root),
            HashPart::Str(netted_channel_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn dispute_window_id(
    sequence: u64,
    batch_id: &str,
    challenge_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-CHANNEL-DISPUTE-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(batch_id),
            HashPart::Str(challenge_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn low_fee_sponsor_receipt_id(
    sequence: u64,
    batch_id: &str,
    sponsor_id: &str,
    sponsor_receipt_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-CHANNEL-LOW-FEE-SPONSOR-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(batch_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(sponsor_receipt_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn fast_settlement_receipt_id(
    sequence: u64,
    batch_id: &str,
    settlement_receipt_root: &str,
    settlement_tx_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-CHANNEL-FAST-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(settlement_tx_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-CHANNEL-LIQUIDITY-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

fn settlement_state_root_after(
    state_root_before: &str,
    final_state_root: &str,
    settlement_receipt_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PRIVATE-CHANNEL-SETTLEMENT-STATE-ROOT-AFTER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(state_root_before),
            HashPart::Str(final_state_root),
            HashPart::Str(settlement_receipt_root),
        ],
        32,
    )
}

fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn secret_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(
    label: &str,
    value: &str,
) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
    require_non_empty(label, value)?;
    if value.len() < 16 {
        return Err(format!("{label} must be root-like"));
    }
    Ok(())
}

fn require_privacy_set(
    config: &Config,
    privacy_set_size: u64,
    batch: bool,
) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
    let minimum = if batch {
        config.min_batch_privacy_set_size
    } else {
        config.min_privacy_set_size
    };
    if privacy_set_size < minimum {
        return Err("privacy set is below configured anonymity threshold".to_string());
    }
    Ok(())
}

fn require_pq_security(
    config: &Config,
    pq_security_bits: u16,
) -> MoneroL2PrivateChannelLiquidityNettingRuntimeResult<()> {
    if pq_security_bits < config.min_pq_security_bits {
        return Err("PQ security bits below configured minimum".to_string());
    }
    Ok(())
}
