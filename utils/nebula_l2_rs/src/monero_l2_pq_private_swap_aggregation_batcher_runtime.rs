use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $message:expr) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-swap-aggregation-batcher-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_HEIGHT: u64 = 830_000;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_PQ_AUTH_SUITE: &str =
    "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_INTENT_SCHEME: &str =
    "roots-only-encrypted-monero-l2-swap-intent-v1";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_AUCTION_SCHEME: &str =
    "sealed-bid-private-route-batch-auction-v1";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_SETTLEMENT_SCHEME: &str =
    "fast-low-fee-private-swap-aggregation-settlement-v1";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_RESERVE_PROOF_SCHEME: &str =
    "monero-bridge-reserve-proof-viewkey-selective-disclosure-v1";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_MEV_GUARD_SCHEME: &str =
    "encrypted-orderflow-mev-guard-attestation-v1";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_SLASHING_SCHEME: &str =
    "pq-private-swap-batcher-slashing-evidence-v1";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_BATCH_WINDOW_BLOCKS: u64 =
    6;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_AUCTION_TTL_BLOCKS: u64 =
    12;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS:
    u64 = 8;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE:
    u64 = 131_072;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_SOLVER_REBATE_BPS: u64 = 7;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MAX_ROUTE_HOPS: u8 = 8;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MAX_BATCH_INTENTS: usize =
    512;
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_MONERO_ASSET: &str =
    "xmr-devnet";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_WRAPPED_MONERO_ASSET: &str =
    "wxmr-devnet";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_FEE_ASSET: &str =
    "piconero-devnet";
pub const MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_STABLE_ASSET: &str =
    "private-usd-devnet";
pub const DOMAIN_CONFIG: &str = "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-CONFIG";
pub const DOMAIN_COUNTERS: &str = "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-COUNTERS";
pub const DOMAIN_ROOTS: &str = "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-ROOTS";
pub const DOMAIN_STATE: &str = "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-STATE";
pub const DOMAIN_ENCRYPTED_SWAP_INTENT: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-ENCRYPTED-SWAP-INTENT";
pub const DOMAIN_ROUTE_BATCH: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-ROUTE-BATCH";
pub const DOMAIN_BATCH_AUCTION: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-BATCH-AUCTION";
pub const DOMAIN_SOLVER_COMMITMENT: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-SOLVER-COMMITMENT";
pub const DOMAIN_BRIDGE_RESERVE_PROOF: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-BRIDGE-RESERVE-PROOF";
pub const DOMAIN_FEE_COUPON: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-FEE-COUPON";
pub const DOMAIN_SETTLEMENT_RECEIPT: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-SETTLEMENT-RECEIPT";
pub const DOMAIN_NULLIFIER_FENCE: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-NULLIFIER-FENCE";
pub const DOMAIN_MEV_GUARD_ATTESTATION: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-MEV-GUARD-ATTESTATION";
pub const DOMAIN_SLASHING_EVIDENCE: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-SLASHING-EVIDENCE";
pub const DOMAIN_PUBLIC_RECORD: &str =
    "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-PUBLIC-RECORD";
pub const DOMAIN_DEVNET: &str = "MONERO-L2-PQ-PRIVATE-SWAP-AGGREGATION-BATCHER-RUNTIME-DEVNET";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Queued,
    FenceChecked,
    Batching,
    Auctioned,
    Committed,
    Settled,
    Expired,
    Cancelled,
    Rejected,
}
impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::FenceChecked => "fence_checked",
            Self::Batching => "batching",
            Self::Auctioned => "auctioned",
            Self::Committed => "committed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Auctioning,
    Committed,
    Settling,
    Settled,
    Disputed,
    Abandoned,
}
impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Auctioning => "auctioning",
            Self::Committed => "committed",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Abandoned => "abandoned",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Cleared,
    Expired,
    Cancelled,
    Challenged,
}
impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Cleared => "cleared",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Pending,
    Accepted,
    Revealed,
    Settled,
    Slashed,
    Expired,
}
impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Revealed => "revealed",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveProofStatus {
    Pending,
    Verified,
    Stale,
    Rejected,
    Challenged,
}
impl ReserveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Available,
    Reserved,
    Applied,
    Refunded,
    Expired,
    Revoked,
}
impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Published,
    Finalized,
    Disputed,
    Reverted,
}
impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Spent,
    Quarantined,
    Released,
    Slashed,
}
impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Spent => "spent",
            Self::Quarantined => "quarantined",
            Self::Released => "released",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MevGuardStatus {
    Observed,
    Accepted,
    Challenged,
    Failed,
    Expired,
}
impl MevGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingStatus {
    Filed,
    Corroborated,
    Executed,
    Rejected,
    Expired,
}
impl SlashingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::Corroborated => "corroborated",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    XmrToL2,
    L2ToXmr,
    L2ToL2ViaXmr,
    BridgeRebalance,
    TriangularDefi,
}
impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::XmrToL2 => "xmr_to_l2",
            Self::L2ToXmr => "l2_to_xmr",
            Self::L2ToL2ViaXmr => "l2_to_l2_via_xmr",
            Self::BridgeRebalance => "bridge_rebalance",
            Self::TriangularDefi => "triangular_defi",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeMode {
    UserPays,
    CouponSponsored,
    SolverRebated,
    ReserveSubsidized,
}
impl FeeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserPays => "user_pays",
            Self::CouponSponsored => "coupon_sponsored",
            Self::SolverRebated => "solver_rebated",
            Self::ReserveSubsidized => "reserve_subsidized",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub batch_window_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub solver_rebate_bps: u64,
    pub max_route_hops: u8,
    pub max_batch_intents: usize,
    pub monero_asset_id: String,
    pub wrapped_monero_asset_id: String,
    pub fee_asset_id: String,
    pub stable_asset_id: String,
    pub require_reserve_proof: bool,
    pub require_mev_guard: bool,
}
impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "Config",
            "protocol_version": PROTOCOL_VERSION,
            "batch_window_blocks": self.batch_window_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_bps": self.low_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "solver_rebate_bps": self.solver_rebate_bps,
            "max_route_hops": self.max_route_hops,
            "max_batch_intents": self.max_batch_intents,
            "monero_asset_id": self.monero_asset_id,
            "wrapped_monero_asset_id": self.wrapped_monero_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "require_reserve_proof": self.require_reserve_proof,
            "require_mev_guard": self.require_mev_guard,
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub intents: u64,
    pub route_batches: u64,
    pub batch_auctions: u64,
    pub solver_commitments: u64,
    pub bridge_reserve_proofs: u64,
    pub fee_coupons: u64,
    pub settlement_receipts: u64,
    pub nullifier_fences: u64,
    pub mev_guard_attestations: u64,
    pub slashing_evidence: u64,
    pub settled_intents: u64,
    pub slashed_solvers: u64,
    pub fee_units_saved: u64,
    pub privacy_quarantines: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "Counters",
            "protocol_version": PROTOCOL_VERSION,
            "intents": self.intents,
            "route_batches": self.route_batches,
            "batch_auctions": self.batch_auctions,
            "solver_commitments": self.solver_commitments,
            "bridge_reserve_proofs": self.bridge_reserve_proofs,
            "fee_coupons": self.fee_coupons,
            "settlement_receipts": self.settlement_receipts,
            "nullifier_fences": self.nullifier_fences,
            "mev_guard_attestations": self.mev_guard_attestations,
            "slashing_evidence": self.slashing_evidence,
            "settled_intents": self.settled_intents,
            "slashed_solvers": self.slashed_solvers,
            "fee_units_saved": self.fee_units_saved,
            "privacy_quarantines": self.privacy_quarantines,
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub encrypted_swap_intents: String,
    pub route_batches: String,
    pub batch_auctions: String,
    pub solver_commitments: String,
    pub bridge_reserve_proofs: String,
    pub fee_coupons: String,
    pub settlement_receipts: String,
    pub nullifier_fences: String,
    pub mev_guard_attestations: String,
    pub slashing_evidence: String,
    pub solver_index: String,
    pub asset_pair_index: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "Roots",
            "protocol_version": PROTOCOL_VERSION,
            "encrypted_swap_intents": self.encrypted_swap_intents,
            "route_batches": self.route_batches,
            "batch_auctions": self.batch_auctions,
            "solver_commitments": self.solver_commitments,
            "bridge_reserve_proofs": self.bridge_reserve_proofs,
            "fee_coupons": self.fee_coupons,
            "settlement_receipts": self.settlement_receipts,
            "nullifier_fences": self.nullifier_fences,
            "mev_guard_attestations": self.mev_guard_attestations,
            "slashing_evidence": self.slashing_evidence,
            "solver_index": self.solver_index,
            "asset_pair_index": self.asset_pair_index,
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedSwapIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub route_kind: RouteKind,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub amount_commitment: String,
    pub min_output_commitment: String,
    pub encrypted_payload_root: String,
    pub view_tag_root: String,
    pub nullifier: String,
    pub fee_mode: FeeMode,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: IntentStatus,
}
impl EncryptedSwapIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "EncryptedSwapIntent",
            "protocol_version": PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "route_kind": self.route_kind.as_str(),
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "amount_commitment": self.amount_commitment,
            "min_output_commitment": self.min_output_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "view_tag_root": self.view_tag_root,
            "nullifier": self.nullifier,
            "fee_mode": self.fee_mode.as_str(),
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-ENCRYPTEDSWAPINTENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteBatch {
    pub batch_id: String,
    pub asset_pair_key: String,
    pub route_kind: RouteKind,
    pub batcher_id: String,
    pub intent_root: String,
    pub intent_count: u64,
    pub encrypted_route_root: String,
    pub reserve_proof_id: String,
    pub mev_guard_id: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub max_fee_bps: u64,
    pub status: BatchStatus,
}
impl RouteBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "RouteBatch",
            "protocol_version": PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "asset_pair_key": self.asset_pair_key,
            "route_kind": self.route_kind.as_str(),
            "batcher_id": self.batcher_id,
            "intent_root": self.intent_root,
            "intent_count": self.intent_count,
            "encrypted_route_root": self.encrypted_route_root,
            "reserve_proof_id": self.reserve_proof_id,
            "mev_guard_id": self.mev_guard_id,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-ROUTEBATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchAuction {
    pub auction_id: String,
    pub batch_id: String,
    pub sealed_bid_root: String,
    pub solver_set_root: String,
    pub clearing_commitment: String,
    pub min_rebate_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub winning_solver_id: String,
    pub status: AuctionStatus,
}
impl BatchAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "BatchAuction",
            "protocol_version": PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "batch_id": self.batch_id,
            "sealed_bid_root": self.sealed_bid_root,
            "solver_set_root": self.solver_set_root,
            "clearing_commitment": self.clearing_commitment,
            "min_rebate_bps": self.min_rebate_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "winning_solver_id": self.winning_solver_id,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-BATCHAUCTION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub pq_public_key_root: String,
    pub sealed_solution_root: String,
    pub bond_commitment: String,
    pub fee_rebate_bps: u64,
    pub latency_budget_ms: u64,
    pub committed_at_height: u64,
    pub status: CommitmentStatus,
}
impl SolverCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "SolverCommitment",
            "protocol_version": PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "solver_id": self.solver_id,
            "pq_public_key_root": self.pq_public_key_root,
            "sealed_solution_root": self.sealed_solution_root,
            "bond_commitment": self.bond_commitment,
            "fee_rebate_bps": self.fee_rebate_bps,
            "latency_budget_ms": self.latency_budget_ms,
            "committed_at_height": self.committed_at_height,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-SOLVERCOMMITMENT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeReserveProof {
    pub proof_id: String,
    pub reserve_operator_id: String,
    pub monero_block_hash: String,
    pub reserve_commitment_root: String,
    pub viewkey_disclosure_root: String,
    pub liquidity_asset_id: String,
    pub available_liquidity_commitment: String,
    pub privacy_set_size: u64,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReserveProofStatus,
}
impl BridgeReserveProof {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "BridgeReserveProof",
            "protocol_version": PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "reserve_operator_id": self.reserve_operator_id,
            "monero_block_hash": self.monero_block_hash,
            "reserve_commitment_root": self.reserve_commitment_root,
            "viewkey_disclosure_root": self.viewkey_disclosure_root,
            "liquidity_asset_id": self.liquidity_asset_id,
            "available_liquidity_commitment": self.available_liquidity_commitment,
            "privacy_set_size": self.privacy_set_size,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-BRIDGERESERVEPROOF",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCoupon {
    pub coupon_id: String,
    pub sponsor_id: String,
    pub asset_pair_key: String,
    pub coupon_root: String,
    pub face_value_commitment: String,
    pub remaining_value_commitment: String,
    pub coverage_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: CouponStatus,
}
impl FeeCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "FeeCoupon",
            "protocol_version": PROTOCOL_VERSION,
            "coupon_id": self.coupon_id,
            "sponsor_id": self.sponsor_id,
            "asset_pair_key": self.asset_pair_key,
            "coupon_root": self.coupon_root,
            "face_value_commitment": self.face_value_commitment,
            "remaining_value_commitment": self.remaining_value_commitment,
            "coverage_bps": self.coverage_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-FEECOUPON",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub commitment_id: String,
    pub settlement_root: String,
    pub receipt_nullifier_root: String,
    pub fee_paid_commitment: String,
    pub coupon_id: String,
    pub settled_intent_count: u64,
    pub settled_at_height: u64,
    pub status: ReceiptStatus,
}
impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "SettlementReceipt",
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "commitment_id": self.commitment_id,
            "settlement_root": self.settlement_root,
            "receipt_nullifier_root": self.receipt_nullifier_root,
            "fee_paid_commitment": self.fee_paid_commitment,
            "coupon_id": self.coupon_id,
            "settled_intent_count": self.settled_intent_count,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-SETTLEMENTRECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub nullifier: String,
    pub intent_id: String,
    pub batch_id: String,
    pub scope_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: FenceStatus,
}
impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "NullifierFence",
            "protocol_version": PROTOCOL_VERSION,
            "fence_id": self.fence_id,
            "nullifier": self.nullifier,
            "intent_id": self.intent_id,
            "batch_id": self.batch_id,
            "scope_root": self.scope_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-NULLIFIERFENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MevGuardAttestation {
    pub attestation_id: String,
    pub batch_id: String,
    pub observer_id: String,
    pub encrypted_orderflow_root: String,
    pub fair_ordering_root: String,
    pub delay_bound_ms: u64,
    pub sandwich_risk_bps: u64,
    pub attested_at_height: u64,
    pub status: MevGuardStatus,
}
impl MevGuardAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "MevGuardAttestation",
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "batch_id": self.batch_id,
            "observer_id": self.observer_id,
            "encrypted_orderflow_root": self.encrypted_orderflow_root,
            "fair_ordering_root": self.fair_ordering_root,
            "delay_bound_ms": self.delay_bound_ms,
            "sandwich_risk_bps": self.sandwich_risk_bps,
            "attested_at_height": self.attested_at_height,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-MEVGUARDATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub target_solver_id: String,
    pub related_batch_id: String,
    pub fault_domain: String,
    pub evidence_root: String,
    pub loss_commitment: String,
    pub slash_bps: u64,
    pub reported_at_height: u64,
    pub status: SlashingStatus,
}
impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "SlashingEvidence",
            "protocol_version": PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "target_solver_id": self.target_solver_id,
            "related_batch_id": self.related_batch_id,
            "fault_domain": self.fault_domain,
            "evidence_root": self.evidence_root,
            "loss_commitment": self.loss_commitment,
            "slash_bps": self.slash_bps,
            "reported_at_height": self.reported_at_height,
            "status": self.status.as_str(),
        })
    }
    pub fn record_root(&self) -> String {
        root_from_record(
            "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-SLASHINGEVIDENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub encrypted_swap_intents: BTreeMap<String, EncryptedSwapIntent>,
    pub route_batches: BTreeMap<String, RouteBatch>,
    pub batch_auctions: BTreeMap<String, BatchAuction>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub bridge_reserve_proofs: BTreeMap<String, BridgeReserveProof>,
    pub fee_coupons: BTreeMap<String, FeeCoupon>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub mev_guard_attestations: BTreeMap<String, MevGuardAttestation>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub used_nullifiers: BTreeSet<String>,
    pub solver_reputation: BTreeMap<String, i64>,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            batch_window_blocks: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_BATCH_WINDOW_BLOCKS,
            intent_ttl_blocks: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            auction_ttl_blocks: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_AUCTION_TTL_BLOCKS,
            settlement_window_blocks: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            min_privacy_set_size: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_bps: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            solver_rebate_bps: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_SOLVER_REBATE_BPS,
            max_route_hops: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MAX_ROUTE_HOPS,
            max_batch_intents: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEFAULT_MAX_BATCH_INTENTS,
            monero_asset_id: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_MONERO_ASSET.to_string(),
            wrapped_monero_asset_id: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_WRAPPED_MONERO_ASSET.to_string(),
            fee_asset_id: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_FEE_ASSET.to_string(),
            stable_asset_id: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_STABLE_ASSET.to_string(),
            require_reserve_proof: true,
            require_mev_guard: true,
        }
    }
}
impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            height: MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME_DEVNET_HEIGHT,
            config: Config::devnet(),
            encrypted_swap_intents: BTreeMap::new(),
            route_batches: BTreeMap::new(),
            batch_auctions: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            bridge_reserve_proofs: BTreeMap::new(),
            fee_coupons: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            mev_guard_attestations: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            solver_reputation: BTreeMap::new(),
        };
        state.seed_devnet_records();
        state
    }
    fn seed_devnet_records(&mut self) {
        let reserve = BridgeReserveProof {
            proof_id: deterministic_id("RESERVE-PROOF-ID", &[HashPart::Str("devnet-reserve")]),
            reserve_operator_id: "devnet-reserve-operator".to_string(),
            monero_block_hash: short_root("MONERO-BLOCK", "devnet-anchor"),
            reserve_commitment_root: short_root("RESERVE-COMMITMENT", "devnet-reserve"),
            viewkey_disclosure_root: short_root("VIEWKEY-DISCLOSURE", "auditor-threshold"),
            liquidity_asset_id: self.config.wrapped_monero_asset_id.clone(),
            available_liquidity_commitment: short_root("LIQUIDITY", "devnet-liquidity"),
            privacy_set_size: self.config.target_privacy_set_size,
            attested_at_height: self.height,
            expires_at_height: self.height + 240,
            status: ReserveProofStatus::Verified,
        };
        self.bridge_reserve_proofs
            .insert(reserve.proof_id.clone(), reserve);
        let guard = MevGuardAttestation {
            attestation_id: deterministic_id("MEV-GUARD-ID", &[HashPart::Str("devnet-guard")]),
            batch_id: "devnet-open-batch".to_string(),
            observer_id: "devnet-watchtower-quorum".to_string(),
            encrypted_orderflow_root: short_root("ORDERFLOW", "devnet-orderflow"),
            fair_ordering_root: short_root("FAIR-ORDERING", "devnet-fair-ordering"),
            delay_bound_ms: 850,
            sandwich_risk_bps: 0,
            attested_at_height: self.height,
            status: MevGuardStatus::Accepted,
        };
        self.mev_guard_attestations
            .insert(guard.attestation_id.clone(), guard);
    }
    pub fn insert_encrypted_swap_intent(&mut self, record: EncryptedSwapIntent) -> Result<String> {
        let id = record.intent_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(
            record.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small"
        );
        ensure!(
            record.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security below policy"
        );
        ensure!(
            record.max_fee_bps <= self.config.max_user_fee_bps,
            "fee bps exceeds user ceiling"
        );
        ensure!(
            !self.used_nullifiers.contains(&record.nullifier),
            "nullifier already fenced"
        );
        self.used_nullifiers.insert(record.nullifier.clone());
        ensure!(
            !self.encrypted_swap_intents.contains_key(&id),
            "duplicate record id"
        );
        self.encrypted_swap_intents.insert(id.clone(), record);
        Ok(id)
    }
    pub fn insert_route_batch(&mut self, record: RouteBatch) -> Result<String> {
        let id = record.batch_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(!self.route_batches.contains_key(&id), "duplicate record id");
        self.route_batches.insert(id.clone(), record);
        Ok(id)
    }
    pub fn insert_batch_auction(&mut self, record: BatchAuction) -> Result<String> {
        let id = record.auction_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(
            !self.batch_auctions.contains_key(&id),
            "duplicate record id"
        );
        self.batch_auctions.insert(id.clone(), record);
        Ok(id)
    }
    pub fn insert_solver_commitment(&mut self, record: SolverCommitment) -> Result<String> {
        let id = record.commitment_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(
            !self.solver_commitments.contains_key(&id),
            "duplicate record id"
        );
        self.solver_commitments.insert(id.clone(), record);
        Ok(id)
    }
    pub fn insert_bridge_reserve_proof(&mut self, record: BridgeReserveProof) -> Result<String> {
        let id = record.proof_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(
            !self.bridge_reserve_proofs.contains_key(&id),
            "duplicate record id"
        );
        self.bridge_reserve_proofs.insert(id.clone(), record);
        Ok(id)
    }
    pub fn insert_fee_coupon(&mut self, record: FeeCoupon) -> Result<String> {
        let id = record.coupon_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(!self.fee_coupons.contains_key(&id), "duplicate record id");
        self.fee_coupons.insert(id.clone(), record);
        Ok(id)
    }
    pub fn insert_settlement_receipt(&mut self, record: SettlementReceipt) -> Result<String> {
        let id = record.receipt_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(
            !self.settlement_receipts.contains_key(&id),
            "duplicate record id"
        );
        self.settlement_receipts.insert(id.clone(), record);
        Ok(id)
    }
    pub fn insert_nullifier_fence(&mut self, record: NullifierFence) -> Result<String> {
        let id = record.fence_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(
            !self.nullifier_fences.contains_key(&id),
            "duplicate record id"
        );
        self.nullifier_fences.insert(id.clone(), record);
        Ok(id)
    }
    pub fn insert_mev_guard_attestation(&mut self, record: MevGuardAttestation) -> Result<String> {
        let id = record.attestation_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(
            !self.mev_guard_attestations.contains_key(&id),
            "duplicate record id"
        );
        self.mev_guard_attestations.insert(id.clone(), record);
        Ok(id)
    }
    pub fn insert_slashing_evidence(&mut self, record: SlashingEvidence) -> Result<String> {
        let id = record.evidence_id.clone();
        ensure!(!id.is_empty(), "record id cannot be empty");
        ensure!(
            !self.slashing_evidence.contains_key(&id),
            "duplicate record id"
        );
        self.slashing_evidence.insert(id.clone(), record);
        Ok(id)
    }
    pub fn counters(&self) -> Counters {
        Counters {
            intents: self.encrypted_swap_intents.len() as u64,
            route_batches: self.route_batches.len() as u64,
            batch_auctions: self.batch_auctions.len() as u64,
            solver_commitments: self.solver_commitments.len() as u64,
            bridge_reserve_proofs: self.bridge_reserve_proofs.len() as u64,
            fee_coupons: self.fee_coupons.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            nullifier_fences: self.nullifier_fences.len() as u64,
            mev_guard_attestations: self.mev_guard_attestations.len() as u64,
            slashing_evidence: self.slashing_evidence.len() as u64,
            settled_intents: self
                .settlement_receipts
                .values()
                .map(|r| r.settled_intent_count)
                .sum(),
            slashed_solvers: self
                .slashing_evidence
                .values()
                .filter(|e| matches!(e.status, SlashingStatus::Executed))
                .count() as u64,
            fee_units_saved: self.fee_coupons.len() as u64 * self.config.solver_rebate_bps,
            privacy_quarantines: self
                .nullifier_fences
                .values()
                .filter(|f| matches!(f.status, FenceStatus::Quarantined))
                .count() as u64,
        }
    }
    pub fn roots(&self) -> Roots {
        Roots {
            encrypted_swap_intents: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-ENCRYPTED_SWAP_INTENTS",
                &self.encrypted_swap_intents,
            ),
            route_batches: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-ROUTE_BATCHES",
                &self.route_batches,
            ),
            batch_auctions: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-BATCH_AUCTIONS",
                &self.batch_auctions,
            ),
            solver_commitments: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-SOLVER_COMMITMENTS",
                &self.solver_commitments,
            ),
            bridge_reserve_proofs: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-BRIDGE_RESERVE_PROOFS",
                &self.bridge_reserve_proofs,
            ),
            fee_coupons: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-FEE_COUPONS",
                &self.fee_coupons,
            ),
            settlement_receipts: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-SETTLEMENT_RECEIPTS",
                &self.settlement_receipts,
            ),
            nullifier_fences: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-NULLIFIER_FENCES",
                &self.nullifier_fences,
            ),
            mev_guard_attestations: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-MEV_GUARD_ATTESTATIONS",
                &self.mev_guard_attestations,
            ),
            slashing_evidence: map_root(
                "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-SLASHING_EVIDENCE",
                &self.slashing_evidence,
            ),
            solver_index: solver_index_root(&self.solver_reputation),
            asset_pair_index: asset_pair_index_root(&self.route_batches),
        }
    }
    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_l2_pq_private_swap_aggregation_batcher_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "encrypted_swap_intents": values_record(&self.encrypted_swap_intents),
            "route_batches": values_record(&self.route_batches),
            "batch_auctions": values_record(&self.batch_auctions),
            "solver_commitments": values_record(&self.solver_commitments),
            "bridge_reserve_proofs": values_record(&self.bridge_reserve_proofs),
            "fee_coupons": values_record(&self.fee_coupons),
            "settlement_receipts": values_record(&self.settlement_receipts),
            "nullifier_fences": values_record(&self.nullifier_fences),
            "mev_guard_attestations": values_record(&self.mev_guard_attestations),
            "slashing_evidence": values_record(&self.slashing_evidence),
            "used_nullifiers_root": string_set_root("USED-NULLIFIERS", &self.used_nullifiers),
            "solver_reputation_root": solver_index_root(&self.solver_reputation),
        })
    }
    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }
}
pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        DOMAIN_STATE,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}
fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}
fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut all = Vec::with_capacity(parts.len() + 2);
    all.push(HashPart::Str(CHAIN_ID));
    all.push(HashPart::Str(PROTOCOL_VERSION));
    for part in parts {
        all.push(match part {
            HashPart::Bytes(value) => HashPart::Bytes(value),
            HashPart::Str(value) => HashPart::Str(value),
            HashPart::U64(value) => HashPart::U64(*value),
            HashPart::Int(value) => HashPart::Int(*value),
            HashPart::Json(value) => HashPart::Json(value),
        });
    }
    domain_hash(domain, &all, 32)
}
fn short_root(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}
fn values_record<T>(values: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    values
        .values()
        .map(PublicRecord::public_record_value)
        .collect()
}
fn map_root<T>(domain: &str, values: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    merkle_root(domain, &values_record(values))
}
fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|v| json!(v)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn solver_index_root(values: &BTreeMap<String, i64>) -> String {
    let leaves = values
        .iter()
        .map(|(solver, score)| json!({"solver_id": solver, "score": score}))
        .collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-PRIVATE-SWAP-SOLVER-INDEX", &leaves)
}
fn asset_pair_index_root(values: &BTreeMap<String, RouteBatch>) -> String {
    let leaves = values
        .values()
        .map(|batch| json!({"batch_id": batch.batch_id, "asset_pair_key": batch.asset_pair_key, "status": batch.status.as_str()}))
        .collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-PRIVATE-SWAP-ASSET-PAIR-INDEX", &leaves)
}
pub trait PublicRecord {
    fn public_record_value(&self) -> Value;
}
impl PublicRecord for Config {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for Counters {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for Roots {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for EncryptedSwapIntent {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for RouteBatch {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for BatchAuction {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for SolverCommitment {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for BridgeReserveProof {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for FeeCoupon {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for SettlementReceipt {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for NullifierFence {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for MevGuardAttestation {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
impl PublicRecord for SlashingEvidence {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}
pub fn deterministic_policy_marker_001(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-001",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_002(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-002",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_003(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-003",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_004(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-004",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_005(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-005",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_006(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-006",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_007(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-007",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_008(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-008",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_009(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-009",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_010(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-010",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_011(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-011",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_012(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-012",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_013(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-013",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_014(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-014",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_015(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-015",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_016(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-016",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_017(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-017",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_018(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-018",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_019(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-019",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_020(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-020",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_021(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-021",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_022(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-022",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_023(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-023",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_024(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-024",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_025(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-025",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_026(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-026",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_027(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-027",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_028(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-028",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_029(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-029",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_030(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-030",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_031(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-031",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_032(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-032",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_033(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-033",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_034(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-034",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_035(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-035",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_036(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-036",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_037(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-037",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_038(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-038",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_039(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-039",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_040(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-040",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_041(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-041",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_042(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-042",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_043(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-043",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_044(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-044",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_045(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-045",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_046(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-046",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_047(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-047",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_048(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-048",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_049(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-049",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_050(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-050",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_051(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-051",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_052(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-052",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_053(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-053",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_054(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-054",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_055(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-055",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_056(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-056",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_057(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-057",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_058(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-058",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_059(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-059",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_060(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-060",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_061(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-061",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_062(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-062",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_063(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-063",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_064(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-064",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_065(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-065",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_066(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-066",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_067(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-067",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_068(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-068",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_069(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-069",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_070(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-070",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_071(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-071",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_072(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-072",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_073(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-073",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_074(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-074",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_075(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-075",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_076(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-076",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_077(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-077",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_078(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-078",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_079(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-079",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_080(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-080",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_081(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-081",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_082(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-082",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_083(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-083",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_084(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-084",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_085(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-085",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_086(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-086",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_087(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-087",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_088(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-088",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_089(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-089",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_090(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-090",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_091(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-091",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_092(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-092",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_093(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-093",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_094(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-094",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_095(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-095",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_096(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-096",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_097(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-097",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_098(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-098",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_099(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-099",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_100(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-100",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_101(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-101",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_102(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-102",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_103(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-103",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_104(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-104",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_105(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-105",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_106(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-106",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_107(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-107",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_108(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-108",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_109(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-109",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_110(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-110",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_111(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-111",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_112(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-112",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_113(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-113",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_114(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-114",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_115(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-115",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_116(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-116",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_117(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-117",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_118(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-118",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_119(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-119",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_120(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-120",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_121(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-121",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_122(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-122",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_123(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-123",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_124(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-124",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_125(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-125",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_126(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-126",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_127(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-127",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_128(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-128",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_129(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-129",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_130(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-130",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_131(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-131",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_132(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-132",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_133(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-133",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_134(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-134",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_135(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-135",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_136(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-136",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_137(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-137",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_138(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-138",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_139(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-139",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_140(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-140",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_141(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-141",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_142(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-142",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_143(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-143",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_144(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-144",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_145(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-145",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_146(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-146",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_147(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-147",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_148(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-148",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_149(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-149",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_150(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-150",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_151(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-151",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_152(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-152",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_153(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-153",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_154(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-154",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_155(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-155",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_156(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-156",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_157(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-157",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_158(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-158",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_159(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-159",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_160(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-160",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_161(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-161",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_162(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-162",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_163(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-163",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_164(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-164",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_165(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-165",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_166(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-166",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_167(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-167",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_168(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-168",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_169(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-169",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_170(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-170",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_171(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-171",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_172(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-172",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_173(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-173",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_174(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-174",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_175(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-175",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_176(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-176",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_177(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-177",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_178(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-178",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_179(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-179",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_180(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-180",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_181(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-181",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_182(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-182",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_183(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-183",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_184(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-184",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_185(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-185",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_186(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-186",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_187(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-187",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_188(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-188",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_189(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-189",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_190(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-190",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_191(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-191",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_192(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-192",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_193(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-193",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_194(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-194",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_195(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-195",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_196(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-196",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_197(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-197",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_198(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-198",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_199(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-199",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_200(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-200",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_201(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-201",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_202(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-202",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_203(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-203",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_204(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-204",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_205(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-205",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_206(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-206",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_207(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-207",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_208(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-208",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_209(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-209",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_210(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-210",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_211(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-211",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_212(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-212",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_213(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-213",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_214(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-214",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_215(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-215",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_216(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-216",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_217(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-217",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_218(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-218",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_219(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-219",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_220(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-220",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_221(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-221",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_222(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-222",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_223(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-223",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_224(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-224",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_225(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-225",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_226(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-226",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_227(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-227",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_228(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-228",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_229(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-229",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_230(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-230",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_231(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-231",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_232(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-232",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_233(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-233",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_234(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-234",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_235(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-235",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_236(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-236",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_237(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-237",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_238(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-238",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_239(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-239",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_240(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-240",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_241(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-241",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_242(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-242",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_243(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-243",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_244(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-244",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_245(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-245",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_246(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-246",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_247(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-247",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_248(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-248",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_249(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-249",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_250(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-250",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_251(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-251",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_252(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-252",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_253(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-253",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_254(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-254",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_255(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-255",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_256(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-256",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_257(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-257",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_258(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-258",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_259(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-259",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_260(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-260",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_261(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-261",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_262(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-262",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_263(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-263",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_264(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-264",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_265(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-265",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_266(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-266",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_267(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-267",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_268(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-268",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_269(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-269",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_270(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-270",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_271(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-271",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_272(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-272",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_273(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-273",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_274(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-274",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_275(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-275",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_276(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-276",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_277(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-277",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_278(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-278",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_279(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-279",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_280(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-280",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_281(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-281",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_282(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-282",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_283(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-283",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_284(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-284",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_285(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-285",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_286(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-286",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_287(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-287",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_288(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-288",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_289(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-289",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_290(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-290",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_291(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-291",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_292(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-292",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_293(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-293",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_294(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-294",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_295(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-295",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_296(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-296",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_297(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-297",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_298(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-298",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_299(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-299",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_300(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-300",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_301(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-301",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_302(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-302",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_303(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-303",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_304(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-304",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_305(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-305",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_306(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-306",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_307(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-307",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_308(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-308",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_309(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-309",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_310(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-310",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_311(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-311",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_312(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-312",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_313(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-313",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_314(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-314",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_315(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-315",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_316(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-316",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_317(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-317",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_318(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-318",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_319(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-319",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_320(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-320",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_321(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-321",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_322(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-322",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_323(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-323",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_324(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-324",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_325(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-325",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_326(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-326",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_327(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-327",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_328(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-328",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_329(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-329",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_330(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-330",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_331(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-331",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_332(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-332",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_333(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-333",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_334(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-334",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_335(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-335",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_336(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-336",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_337(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-337",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_338(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-338",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_339(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-339",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_340(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-340",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_341(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-341",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_342(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-342",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_343(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-343",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_344(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-344",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_345(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-345",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_346(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-346",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_347(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-347",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_348(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-348",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_349(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-349",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_350(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-350",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_351(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-351",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_352(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-352",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_353(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-353",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_354(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-354",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_355(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-355",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_356(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-356",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_357(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-357",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_358(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-358",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_359(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-359",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_360(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-360",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_361(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-361",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_362(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-362",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_363(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-363",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_364(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-364",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_365(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-365",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_366(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-366",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_367(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-367",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_368(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-368",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_369(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-369",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_370(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-370",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_371(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-371",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_372(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-372",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_373(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-373",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_374(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-374",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_375(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-375",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_376(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-376",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_377(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-377",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_378(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-378",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_379(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-379",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_380(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-380",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_381(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-381",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_382(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-382",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_383(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-383",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_384(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-384",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_385(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-385",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_386(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-386",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_387(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-387",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_388(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-388",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_389(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-389",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_390(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-390",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_391(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-391",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_392(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-392",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_393(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-393",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_394(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-394",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_395(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-395",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_396(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-396",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_397(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-397",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_398(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-398",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_399(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-399",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_400(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-400",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_401(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-401",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_402(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-402",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_403(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-403",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_404(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-404",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_405(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-405",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_406(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-406",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_407(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-407",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_408(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-408",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_409(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-409",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_410(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-410",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_411(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-411",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_412(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-412",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_413(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-413",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_414(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-414",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_415(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-415",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_416(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-416",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_417(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-417",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_418(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-418",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_419(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-419",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_420(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-420",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_421(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-421",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_422(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-422",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_423(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-423",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_424(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-424",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_425(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-425",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_426(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-426",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_427(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-427",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_428(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-428",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_429(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-429",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn deterministic_policy_marker_430(label: &str) -> String {
    domain_hash(
        "MONERO_L2_PQ_PRIVATE_SWAP_AGGREGATION_BATCHER_RUNTIME-POLICY-MARKER-430",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}
