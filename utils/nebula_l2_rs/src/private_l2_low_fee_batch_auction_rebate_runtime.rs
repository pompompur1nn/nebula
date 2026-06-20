use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeBatchAuctionRebateRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-batch-auction-rebate-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_PRIVATE_BATCH_SCHEME: &str =
    "ml-kem-1024+zk-private-low-fee-order-batch-v1";
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SOLVER_BID_SCHEME: &str =
    "commit-reveal-private-batch-solver-bid-v1";
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_FEE_CEILING_PROOF_SCHEME: &str =
    "zk-low-fee-ceiling-proof-v1";
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SPONSOR_RESERVATION_SCHEME: &str =
    "roots-only-low-fee-sponsor-reservation-v1";
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_REBATE_EPOCH_SCHEME: &str =
    "roots-only-private-batch-rebate-epoch-v1";
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SETTLEMENT_RECEIPT_SCHEME: &str =
    "zk-pq-private-batch-auction-settlement-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEVNET_HEIGHT: u64 = 439_000;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_BID_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_EPOCH_BLOCKS: u64 = 1_200;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_BIDS: usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_BATCH_ORDERS: usize = 2_048;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 1_024;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_EPOCH_PRIVACY_SET_SIZE: u64 =
    4_096;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 20;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MIN_REBATE_BPS: u64 = 3;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_REBATE_BPS: u64 = 14;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 =
    250_000_000;
pub const PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchOrderKind {
    Swap,
    Limit,
    DarkpoolCross,
    LiquidityAuction,
    Bridge,
    Payment,
    Vault,
    Lending,
    Perp,
    SettlementNetting,
}

impl BatchOrderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Limit => "limit",
            Self::DarkpoolCross => "darkpool_cross",
            Self::LiquidityAuction => "liquidity_auction",
            Self::Bridge => "bridge",
            Self::Payment => "payment",
            Self::Vault => "vault",
            Self::Lending => "lending",
            Self::Perp => "perp",
            Self::SettlementNetting => "settlement_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Submitted,
    FeeCeilingProved,
    Sponsored,
    Auctioned,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::FeeCeilingProved => "fee_ceiling_proved",
            Self::Sponsored => "sponsored",
            Self::Auctioned => "auctioned",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn auctionable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::FeeCeilingProved | Self::Sponsored
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverBidStatus {
    Posted,
    Selected,
    Settled,
    Rejected,
    Expired,
}

impl SolverBidStatus {
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
pub enum ProofStatus {
    Recorded,
    Accepted,
    Rejected,
    Expired,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateEpochStatus {
    Open,
    Sealed,
    Settled,
    Expired,
}

impl RebateEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
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
    pub private_batch_scheme: String,
    pub solver_bid_scheme: String,
    pub fee_ceiling_proof_scheme: String,
    pub sponsor_reservation_scheme: String,
    pub rebate_epoch_scheme: String,
    pub settlement_receipt_scheme: String,
    pub batch_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub epoch_blocks: u64,
    pub max_batches: usize,
    pub max_bids: usize,
    pub max_batch_orders: usize,
    pub max_reservations: usize,
    pub min_privacy_set_size: u64,
    pub epoch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub sponsor_budget_micro_units: u64,
    pub require_fee_ceiling_proofs: bool,
    pub require_private_batches: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_HASH_SUITE.to_string(),
            private_batch_scheme:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_PRIVATE_BATCH_SCHEME.to_string(),
            solver_bid_scheme: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SOLVER_BID_SCHEME
                .to_string(),
            fee_ceiling_proof_scheme:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_FEE_CEILING_PROOF_SCHEME.to_string(),
            sponsor_reservation_scheme:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SPONSOR_RESERVATION_SCHEME
                    .to_string(),
            rebate_epoch_scheme:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_REBATE_EPOCH_SCHEME.to_string(),
            settlement_receipt_scheme:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SETTLEMENT_RECEIPT_SCHEME
                    .to_string(),
            batch_ttl_blocks:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            bid_ttl_blocks: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_BID_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            epoch_blocks: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_EPOCH_BLOCKS,
            max_batches: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_BATCHES,
            max_bids: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_BIDS,
            max_batch_orders:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_BATCH_ORDERS,
            max_reservations:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            epoch_privacy_set_size:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_EPOCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS,
            min_rebate_bps: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps: PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_MAX_REBATE_BPS,
            sponsor_budget_micro_units:
                PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
            require_fee_ceiling_proofs: true,
            require_private_batches: true,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
        ensure_eq(&self.chain_id, CHAIN_ID, "batch auction rebate chain id")?;
        ensure_eq(
            &self.protocol_version,
            PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_PROTOCOL_VERSION,
            "batch auction rebate protocol version",
        )?;
        if self.schema_version != PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SCHEMA_VERSION {
            return Err("batch auction rebate schema version mismatch".to_string());
        }
        if self.batch_ttl_blocks == 0
            || self.bid_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
            || self.epoch_blocks == 0
            || self.max_batches == 0
            || self.max_bids == 0
            || self.max_batch_orders == 0
            || self.max_reservations == 0
        {
            return Err("batch auction rebate windows and capacities must be positive".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.epoch_privacy_set_size < self.min_privacy_set_size
            || self.min_pq_security_bits < 192
        {
            return Err("batch auction rebate privacy or PQ floors are invalid".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_MAX_BPS
            || self.max_solver_fee_bps > PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_MAX_BPS
            || self.min_rebate_bps > self.max_rebate_bps
            || self.max_rebate_bps > self.max_user_fee_bps
        {
            return Err("batch auction rebate bps configuration is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "private_batch_scheme": self.private_batch_scheme,
            "solver_bid_scheme": self.solver_bid_scheme,
            "fee_ceiling_proof_scheme": self.fee_ceiling_proof_scheme,
            "sponsor_reservation_scheme": self.sponsor_reservation_scheme,
            "rebate_epoch_scheme": self.rebate_epoch_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "epoch_blocks": self.epoch_blocks,
            "max_batches": self.max_batches,
            "max_bids": self.max_bids,
            "max_batch_orders": self.max_batch_orders,
            "max_reservations": self.max_reservations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "epoch_privacy_set_size": self.epoch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "sponsor_budget_micro_units": self.sponsor_budget_micro_units,
            "require_fee_ceiling_proofs": self.require_fee_ceiling_proofs,
            "require_private_batches": self.require_private_batches,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_batch_nonce: u64,
    pub next_bid_nonce: u64,
    pub next_fee_ceiling_proof_nonce: u64,
    pub next_reservation_nonce: u64,
    pub next_rebate_epoch_nonce: u64,
    pub next_receipt_nonce: u64,
    pub private_batches_submitted: u64,
    pub solver_bids_posted: u64,
    pub fee_ceiling_proofs_recorded: u64,
    pub sponsor_reservations_recorded: u64,
    pub rebate_epochs_opened: u64,
    pub settlement_receipts_published: u64,
    pub batches_settled: u64,
    pub rebates_reserved_micro_units: u64,
    pub rebates_consumed_micro_units: u64,
    pub solver_fees_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_counters",
            "next_batch_nonce": self.next_batch_nonce,
            "next_bid_nonce": self.next_bid_nonce,
            "next_fee_ceiling_proof_nonce": self.next_fee_ceiling_proof_nonce,
            "next_reservation_nonce": self.next_reservation_nonce,
            "next_rebate_epoch_nonce": self.next_rebate_epoch_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "private_batches_submitted": self.private_batches_submitted,
            "solver_bids_posted": self.solver_bids_posted,
            "fee_ceiling_proofs_recorded": self.fee_ceiling_proofs_recorded,
            "sponsor_reservations_recorded": self.sponsor_reservations_recorded,
            "rebate_epochs_opened": self.rebate_epochs_opened,
            "settlement_receipts_published": self.settlement_receipts_published,
            "batches_settled": self.batches_settled,
            "rebates_reserved_micro_units": self.rebates_reserved_micro_units,
            "rebates_consumed_micro_units": self.rebates_consumed_micro_units,
            "solver_fees_micro_units": self.solver_fees_micro_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPrivateOrderBatchRequest {
    pub order_kind: BatchOrderKind,
    pub account_commitment: String,
    pub sealed_order_batch_root: String,
    pub encrypted_witness_root: String,
    pub order_commitment_root: String,
    pub asset_flow_root: String,
    pub nullifier_root: String,
    pub refund_commitment_root: String,
    pub max_user_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub order_count: usize,
    pub estimated_value_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitPrivateOrderBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
        require_root("account commitment", &self.account_commitment)?;
        require_root("sealed order batch root", &self.sealed_order_batch_root)?;
        require_root("encrypted witness root", &self.encrypted_witness_root)?;
        require_root("order commitment root", &self.order_commitment_root)?;
        require_root("asset flow root", &self.asset_flow_root)?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_root("refund commitment root", &self.refund_commitment_root)?;
        require_root("PQ authorization root", &self.pq_authorization_root)?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("private order batch fee cap exceeds low-fee policy".to_string());
        }
        if self.requested_rebate_bps < config.min_rebate_bps
            || self.requested_rebate_bps > config.max_rebate_bps
        {
            return Err("private order batch requested rebate is outside bounds".to_string());
        }
        if self.order_count == 0 || self.order_count > config.max_batch_orders {
            return Err("private order batch order count is outside capacity".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("private order batch privacy set is below minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("private order batch PQ security bits below minimum".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height
            || self.expires_at_height
                > self
                    .submitted_at_height
                    .saturating_add(config.batch_ttl_blocks)
        {
            return Err("private order batch expiry must be live and within TTL".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostSolverBidRequest {
    pub batch_ids: Vec<String>,
    pub solver_commitment: String,
    pub route_commitment_root: String,
    pub clearing_price_root: String,
    pub execution_plan_root: String,
    pub bid_note_root: String,
    pub solver_fee_bps: u64,
    pub rebate_share_bps: u64,
    pub expected_surplus_micro_units: u64,
    pub bid_at_height: u64,
    pub expires_at_height: u64,
}

impl PostSolverBidRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
        ensure_unique(&self.batch_ids, "batch id")?;
        require_non_empty("solver commitment", &self.solver_commitment)?;
        require_root("route commitment root", &self.route_commitment_root)?;
        require_root("clearing price root", &self.clearing_price_root)?;
        require_root("execution plan root", &self.execution_plan_root)?;
        require_root("bid note root", &self.bid_note_root)?;
        if self.solver_fee_bps > config.max_solver_fee_bps
            || self.rebate_share_bps > PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_MAX_BPS
        {
            return Err("solver bid fee or rebate share exceeds bounds".to_string());
        }
        if self.expires_at_height <= self.bid_at_height
            || self.expires_at_height > self.bid_at_height.saturating_add(config.bid_ttl_blocks)
        {
            return Err("solver bid expiry must be live and within TTL".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordFeeCeilingProofRequest {
    pub batch_id: String,
    pub proof_root: String,
    pub public_input_root: String,
    pub fee_ceiling_bps: u64,
    pub prover_commitment: String,
    pub verified_at_height: u64,
}

impl RecordFeeCeilingProofRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_root("fee ceiling proof root", &self.proof_root)?;
        require_root("public input root", &self.public_input_root)?;
        require_non_empty("prover commitment", &self.prover_commitment)?;
        if self.fee_ceiling_bps > config.max_user_fee_bps {
            return Err("fee ceiling proof exceeds low-fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSponsorRebateRequest {
    pub batch_ids: Vec<String>,
    pub sponsor_commitment: String,
    pub rebate_commitment_root: String,
    pub reserved_micro_units: u64,
    pub rebate_bps: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveSponsorRebateRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
        ensure_unique(&self.batch_ids, "batch id")?;
        require_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        require_root("rebate commitment root", &self.rebate_commitment_root)?;
        if self.reserved_micro_units == 0 {
            return Err("sponsor rebate reservation must reserve a positive amount".to_string());
        }
        if self.rebate_bps < config.min_rebate_bps || self.rebate_bps > config.max_rebate_bps {
            return Err("sponsor rebate bps is outside configured bounds".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err("sponsor reservation expiry must be after reservation height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenRebateEpochRequest {
    pub epoch_label: String,
    pub sponsor_pool_root: String,
    pub eligible_batch_root: String,
    pub rebate_policy_root: String,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
}

impl OpenRebateEpochRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
        require_non_empty("epoch label", &self.epoch_label)?;
        require_root("sponsor pool root", &self.sponsor_pool_root)?;
        require_root("eligible batch root", &self.eligible_batch_root)?;
        require_root("rebate policy root", &self.rebate_policy_root)?;
        if self.ends_at_height <= self.starts_at_height
            || self.ends_at_height > self.starts_at_height.saturating_add(config.epoch_blocks)
        {
            return Err(
                "rebate epoch window must be live and within configured blocks".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealRebateEpochRequest {
    pub epoch_id: String,
    pub final_eligible_batch_root: String,
    pub rebate_distribution_root: String,
    pub sealed_at_height: u64,
}

impl SealRebateEpochRequest {
    pub fn validate(&self) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
        require_non_empty("epoch id", &self.epoch_id)?;
        require_root("final eligible batch root", &self.final_eligible_batch_root)?;
        require_root("rebate distribution root", &self.rebate_distribution_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSettlementReceiptRequest {
    pub batch_id: String,
    pub selected_bid_id: String,
    pub reservation_ids: Vec<String>,
    pub epoch_id: Option<String>,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub spent_nullifier_root: String,
    pub output_commitment_root: String,
    pub solver_payment_root: String,
    pub rebate_distribution_root: String,
    pub state_root_before: String,
    pub runtime_state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl PublishSettlementReceiptRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_non_empty("selected bid id", &self.selected_bid_id)?;
        ensure_unique(&self.reservation_ids, "reservation id")?;
        require_root("settlement tx root", &self.settlement_tx_root)?;
        require_root("settlement proof root", &self.settlement_proof_root)?;
        require_root("spent nullifier root", &self.spent_nullifier_root)?;
        require_root("output commitment root", &self.output_commitment_root)?;
        require_root("solver payment root", &self.solver_payment_root)?;
        require_root("rebate distribution root", &self.rebate_distribution_root)?;
        require_root("state root before", &self.state_root_before)?;
        require_root("runtime state root after", &self.runtime_state_root_after)?;
        if self.settled_fee_bps > config.max_user_fee_bps {
            return Err("settlement receipt fee exceeds low-fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOrderBatchRecord {
    pub batch_id: String,
    pub status: BatchStatus,
    pub fee_ceiling_proof_id: Option<String>,
    pub selected_bid_id: Option<String>,
    pub settlement_receipt_id: Option<String>,
    pub request: SubmitPrivateOrderBatchRequest,
}

impl PrivateOrderBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_private_order_batch",
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "fee_ceiling_proof_id": self.fee_ceiling_proof_id,
            "selected_bid_id": self.selected_bid_id,
            "settlement_receipt_id": self.settlement_receipt_id,
            "order_kind": self.request.order_kind.as_str(),
            "account_commitment": self.request.account_commitment,
            "sealed_order_batch_root": self.request.sealed_order_batch_root,
            "order_commitment_root": self.request.order_commitment_root,
            "asset_flow_root": self.request.asset_flow_root,
            "nullifier_root": self.request.nullifier_root,
            "max_user_fee_bps": self.request.max_user_fee_bps,
            "requested_rebate_bps": self.request.requested_rebate_bps,
            "order_count": self.request.order_count,
            "estimated_value_micro_units": self.request.estimated_value_micro_units,
            "privacy_set_size": self.request.privacy_set_size,
            "pq_security_bits": self.request.pq_security_bits,
            "submitted_at_height": self.request.submitted_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBidRecord {
    pub bid_id: String,
    pub score: u128,
    pub status: SolverBidStatus,
    pub request: PostSolverBidRequest,
}

impl SolverBidRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_solver_bid",
            "bid_id": self.bid_id,
            "score": self.score.to_string(),
            "status": self.status.as_str(),
            "batch_ids": self.request.batch_ids,
            "solver_commitment": self.request.solver_commitment,
            "route_commitment_root": self.request.route_commitment_root,
            "clearing_price_root": self.request.clearing_price_root,
            "execution_plan_root": self.request.execution_plan_root,
            "bid_note_root": self.request.bid_note_root,
            "solver_fee_bps": self.request.solver_fee_bps,
            "rebate_share_bps": self.request.rebate_share_bps,
            "expected_surplus_micro_units": self.request.expected_surplus_micro_units,
            "bid_at_height": self.request.bid_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCeilingProofRecord {
    pub proof_id: String,
    pub status: ProofStatus,
    pub request: RecordFeeCeilingProofRequest,
}

impl FeeCeilingProofRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_fee_ceiling_proof",
            "proof_id": self.proof_id,
            "status": self.status.as_str(),
            "batch_id": self.request.batch_id,
            "proof_root": self.request.proof_root,
            "public_input_root": self.request.public_input_root,
            "fee_ceiling_bps": self.request.fee_ceiling_bps,
            "prover_commitment": self.request.prover_commitment,
            "verified_at_height": self.request.verified_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservationRecord {
    pub reservation_id: String,
    pub status: ReservationStatus,
    pub request: ReserveSponsorRebateRequest,
}

impl SponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "status": self.status.as_str(),
            "batch_ids": self.request.batch_ids,
            "sponsor_commitment": self.request.sponsor_commitment,
            "rebate_commitment_root": self.request.rebate_commitment_root,
            "reserved_micro_units": self.request.reserved_micro_units,
            "rebate_bps": self.request.rebate_bps,
            "reserved_at_height": self.request.reserved_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateEpochRecord {
    pub epoch_id: String,
    pub status: RebateEpochStatus,
    pub request: OpenRebateEpochRequest,
    pub final_eligible_batch_root: Option<String>,
    pub rebate_distribution_root: Option<String>,
    pub settlement_receipt_ids: BTreeSet<String>,
}

impl RebateEpochRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_epoch",
            "epoch_id": self.epoch_id,
            "status": self.status.as_str(),
            "epoch_label": self.request.epoch_label,
            "sponsor_pool_root": self.request.sponsor_pool_root,
            "eligible_batch_root": self.request.eligible_batch_root,
            "rebate_policy_root": self.request.rebate_policy_root,
            "starts_at_height": self.request.starts_at_height,
            "ends_at_height": self.request.ends_at_height,
            "final_eligible_batch_root": self.final_eligible_batch_root,
            "rebate_distribution_root": self.rebate_distribution_root,
            "settlement_receipt_ids": self.settlement_receipt_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub status: ReceiptStatus,
    pub request: PublishSettlementReceiptRequest,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_settlement_receipt",
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "batch_id": self.request.batch_id,
            "selected_bid_id": self.request.selected_bid_id,
            "reservation_ids": self.request.reservation_ids,
            "epoch_id": self.request.epoch_id,
            "settlement_tx_root": self.request.settlement_tx_root,
            "settlement_proof_root": self.request.settlement_proof_root,
            "spent_nullifier_root": self.request.spent_nullifier_root,
            "output_commitment_root": self.request.output_commitment_root,
            "solver_payment_root": self.request.solver_payment_root,
            "rebate_distribution_root": self.request.rebate_distribution_root,
            "state_root_before": self.request.state_root_before,
            "runtime_state_root_after": self.request.runtime_state_root_after,
            "settled_fee_bps": self.request.settled_fee_bps,
            "settled_at_height": self.request.settled_at_height,
            "finalized_at_height": self.request.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub private_batch_root: String,
    pub solver_bid_root: String,
    pub fee_ceiling_proof_root: String,
    pub sponsor_reservation_root: String,
    pub rebate_epoch_root: String,
    pub settlement_receipt_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_roots",
            "config_root": self.config_root,
            "private_batch_root": self.private_batch_root,
            "solver_bid_root": self.solver_bid_root,
            "fee_ceiling_proof_root": self.fee_ceiling_proof_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "rebate_epoch_root": self.rebate_epoch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
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
    pub sponsor_budget_remaining_micro_units: u64,
    pub private_batches: BTreeMap<String, PrivateOrderBatchRecord>,
    pub solver_bids: BTreeMap<String, SolverBidRecord>,
    pub fee_ceiling_proofs: BTreeMap<String, FeeCeilingProofRecord>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservationRecord>,
    pub rebate_epochs: BTreeMap<String, RebateEpochRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(config: Config, current_height: u64) -> Self {
        let sponsor_budget_remaining_micro_units = config.sponsor_budget_micro_units;
        Self {
            config,
            counters: Counters::default(),
            current_height,
            runtime_root: private_l2_low_fee_batch_auction_rebate_payload_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-GENESIS",
                &json!({
                    "chain_id": CHAIN_ID,
                    "current_height": current_height,
                }),
            ),
            sponsor_budget_remaining_micro_units,
            private_batches: BTreeMap::new(),
            solver_bids: BTreeMap::new(),
            fee_ceiling_proofs: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            rebate_epochs: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn submit_private_order_batch(
        &mut self,
        request: SubmitPrivateOrderBatchRequest,
    ) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<PrivateOrderBatchRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.private_batches.len() >= self.config.max_batches {
            return Err("private order batch capacity reached".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&request.nullifier_root)
        {
            return Err("private order batch nullifier already consumed".to_string());
        }
        let batch_id = private_order_batch_id(&request, self.counters.next_batch_nonce);
        let record = PrivateOrderBatchRecord {
            batch_id: batch_id.clone(),
            status: BatchStatus::Submitted,
            fee_ceiling_proof_id: None,
            selected_bid_id: None,
            settlement_receipt_id: None,
            request,
        };
        self.current_height = self.current_height.max(record.request.submitted_at_height);
        self.counters.next_batch_nonce = self.counters.next_batch_nonce.saturating_add(1);
        self.counters.private_batches_submitted =
            self.counters.private_batches_submitted.saturating_add(1);
        self.publish_public_record("private_order_batch", &batch_id, record.public_record());
        self.private_batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn post_solver_bid(
        &mut self,
        request: PostSolverBidRequest,
    ) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<SolverBidRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.solver_bids.len() >= self.config.max_bids {
            return Err("solver bid capacity reached".to_string());
        }
        for batch_id in &request.batch_ids {
            let batch = self
                .private_batches
                .get(batch_id)
                .ok_or_else(|| format!("solver bid references unknown batch: {batch_id}"))?;
            if !batch.status.auctionable()
                || request.bid_at_height > batch.request.expires_at_height
            {
                return Err(format!("batch is not auctionable: {batch_id}"));
            }
        }
        let score = solver_bid_score(&request);
        let bid_id = solver_bid_id(&request, score, self.counters.next_bid_nonce);
        let record = SolverBidRecord {
            bid_id: bid_id.clone(),
            score,
            status: SolverBidStatus::Posted,
            request,
        };
        self.current_height = self.current_height.max(record.request.bid_at_height);
        self.counters.next_bid_nonce = self.counters.next_bid_nonce.saturating_add(1);
        self.counters.solver_bids_posted = self.counters.solver_bids_posted.saturating_add(1);
        self.publish_public_record("solver_bid", &bid_id, record.public_record());
        self.solver_bids.insert(bid_id, record.clone());
        Ok(record)
    }

    pub fn record_fee_ceiling_proof(
        &mut self,
        request: RecordFeeCeilingProofRequest,
    ) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<FeeCeilingProofRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let batch = self
            .private_batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| "fee ceiling proof references unknown batch".to_string())?;
        if request.fee_ceiling_bps > batch.request.max_user_fee_bps {
            return Err("fee ceiling proof exceeds batch user fee cap".to_string());
        }
        let proof_id = fee_ceiling_proof_id(&request, self.counters.next_fee_ceiling_proof_nonce);
        let record = FeeCeilingProofRecord {
            proof_id: proof_id.clone(),
            status: ProofStatus::Accepted,
            request,
        };
        if let Some(batch) = self.private_batches.get_mut(&record.request.batch_id) {
            batch.status = BatchStatus::FeeCeilingProved;
            batch.fee_ceiling_proof_id = Some(proof_id.clone());
        }
        self.current_height = self.current_height.max(record.request.verified_at_height);
        self.counters.next_fee_ceiling_proof_nonce =
            self.counters.next_fee_ceiling_proof_nonce.saturating_add(1);
        self.counters.fee_ceiling_proofs_recorded =
            self.counters.fee_ceiling_proofs_recorded.saturating_add(1);
        self.refresh_batch_records(&[record.request.batch_id.clone()]);
        self.publish_public_record("fee_ceiling_proof", &proof_id, record.public_record());
        self.fee_ceiling_proofs.insert(proof_id, record.clone());
        Ok(record)
    }

    pub fn reserve_sponsor_rebate(
        &mut self,
        request: ReserveSponsorRebateRequest,
    ) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<SponsorReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.sponsor_reservations.len() >= self.config.max_reservations {
            return Err("sponsor reservation capacity reached".to_string());
        }
        if request.reserved_micro_units > self.sponsor_budget_remaining_micro_units {
            return Err("sponsor rebate reservation exceeds remaining budget".to_string());
        }
        for batch_id in &request.batch_ids {
            let batch = self.private_batches.get(batch_id).ok_or_else(|| {
                format!("sponsor reservation references unknown batch: {batch_id}")
            })?;
            if !batch.status.auctionable()
                || request.reserved_at_height > batch.request.expires_at_height
            {
                return Err(format!("batch is not reservable: {batch_id}"));
            }
        }
        let remaining = self
            .sponsor_budget_remaining_micro_units
            .saturating_sub(request.reserved_micro_units);
        let reservation_id =
            sponsor_reservation_id(&request, self.counters.next_reservation_nonce, remaining);
        let record = SponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            status: ReservationStatus::Reserved,
            request,
        };
        for batch_id in &record.request.batch_ids {
            if let Some(batch) = self.private_batches.get_mut(batch_id) {
                batch.status = BatchStatus::Sponsored;
            }
        }
        self.sponsor_budget_remaining_micro_units = remaining;
        self.current_height = self.current_height.max(record.request.reserved_at_height);
        self.counters.next_reservation_nonce =
            self.counters.next_reservation_nonce.saturating_add(1);
        self.counters.sponsor_reservations_recorded = self
            .counters
            .sponsor_reservations_recorded
            .saturating_add(1);
        self.counters.rebates_reserved_micro_units = self
            .counters
            .rebates_reserved_micro_units
            .saturating_add(record.request.reserved_micro_units);
        self.refresh_batch_records(&record.request.batch_ids);
        self.publish_public_record(
            "sponsor_reservation",
            &reservation_id,
            record.public_record(),
        );
        self.sponsor_reservations
            .insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn open_rebate_epoch(
        &mut self,
        request: OpenRebateEpochRequest,
    ) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<RebateEpochRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let epoch_id = rebate_epoch_id(&request, self.counters.next_rebate_epoch_nonce);
        let record = RebateEpochRecord {
            epoch_id: epoch_id.clone(),
            status: RebateEpochStatus::Open,
            request,
            final_eligible_batch_root: None,
            rebate_distribution_root: None,
            settlement_receipt_ids: BTreeSet::new(),
        };
        self.current_height = self.current_height.max(record.request.starts_at_height);
        self.counters.next_rebate_epoch_nonce =
            self.counters.next_rebate_epoch_nonce.saturating_add(1);
        self.counters.rebate_epochs_opened = self.counters.rebate_epochs_opened.saturating_add(1);
        self.publish_public_record("rebate_epoch", &epoch_id, record.public_record());
        self.rebate_epochs.insert(epoch_id, record.clone());
        Ok(record)
    }

    pub fn seal_rebate_epoch(
        &mut self,
        request: SealRebateEpochRequest,
    ) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<RebateEpochRecord> {
        self.config.validate()?;
        request.validate()?;
        let mut record = self
            .rebate_epochs
            .get(&request.epoch_id)
            .cloned()
            .ok_or_else(|| "seal request references unknown rebate epoch".to_string())?;
        if record.status != RebateEpochStatus::Open {
            return Err("rebate epoch is not open".to_string());
        }
        if request.sealed_at_height < record.request.starts_at_height {
            return Err("rebate epoch cannot seal before it starts".to_string());
        }
        record.status = RebateEpochStatus::Sealed;
        record.final_eligible_batch_root = Some(request.final_eligible_batch_root);
        record.rebate_distribution_root = Some(request.rebate_distribution_root);
        self.current_height = self.current_height.max(request.sealed_at_height);
        self.publish_public_record("rebate_epoch", &record.epoch_id, record.public_record());
        self.rebate_epochs
            .insert(record.epoch_id.clone(), record.clone());
        Ok(record)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishSettlementReceiptRequest,
    ) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<SettlementReceiptRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if request.state_root_before != self.state_root() {
            return Err("settlement receipt state root before does not match runtime".to_string());
        }
        let batch = self
            .private_batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| "settlement receipt references unknown batch".to_string())?;
        if !batch.status.auctionable() && batch.status != BatchStatus::Auctioned {
            return Err("batch is not settlement ready".to_string());
        }
        if request.settled_at_height
            > batch
                .request
                .expires_at_height
                .saturating_add(self.config.settlement_ttl_blocks)
        {
            return Err("batch settlement deadline elapsed".to_string());
        }
        let selected_bid = self
            .solver_bids
            .get(&request.selected_bid_id)
            .cloned()
            .ok_or_else(|| "settlement receipt references unknown solver bid".to_string())?;
        if !selected_bid.request.batch_ids.contains(&request.batch_id) {
            return Err("selected solver bid does not cover settled batch".to_string());
        }
        if !covers_all_reservations(
            &self.sponsor_reservations,
            &request.reservation_ids,
            &request.batch_id,
        ) {
            return Err("sponsor reservations do not cover settled batch".to_string());
        }
        let receipt_id = settlement_receipt_id(&request, self.counters.next_receipt_nonce);
        if let Some(batch) = self.private_batches.get_mut(&request.batch_id) {
            batch.status = BatchStatus::Settled;
            batch.selected_bid_id = Some(request.selected_bid_id.clone());
            batch.settlement_receipt_id = Some(receipt_id.clone());
        }
        if let Some(bid) = self.solver_bids.get_mut(&request.selected_bid_id) {
            bid.status = SolverBidStatus::Settled;
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Consumed;
                self.counters.rebates_consumed_micro_units = self
                    .counters
                    .rebates_consumed_micro_units
                    .saturating_add(reservation.request.reserved_micro_units);
            }
        }
        if let Some(epoch_id) = &request.epoch_id {
            let epoch = self
                .rebate_epochs
                .get_mut(epoch_id)
                .ok_or_else(|| "settlement receipt references unknown rebate epoch".to_string())?;
            if epoch.status == RebateEpochStatus::Open {
                epoch.status = RebateEpochStatus::Sealed;
            }
            epoch.settlement_receipt_ids.insert(receipt_id.clone());
        }
        self.consumed_nullifier_roots
            .insert(batch.request.nullifier_root.clone());
        self.runtime_root = request.runtime_state_root_after.clone();
        self.current_height = self.current_height.max(request.settled_at_height);
        self.counters.next_receipt_nonce = self.counters.next_receipt_nonce.saturating_add(1);
        self.counters.settlement_receipts_published = self
            .counters
            .settlement_receipts_published
            .saturating_add(1);
        self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        self.counters.solver_fees_micro_units = self
            .counters
            .solver_fees_micro_units
            .saturating_add(batch.request.order_count as u64 * request.settled_fee_bps);
        let record = SettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            status: if request.finalized_at_height.is_some() {
                ReceiptStatus::Finalized
            } else {
                ReceiptStatus::Published
            },
            request,
        };
        self.refresh_batch_records(&[record.request.batch_id.clone()]);
        self.refresh_bid_records(&[record.request.selected_bid_id.clone()]);
        self.refresh_reservation_records(&record.request.reservation_ids);
        if let Some(epoch_id) = &record.request.epoch_id {
            self.refresh_epoch_records(&[epoch_id.clone()]);
        }
        self.publish_public_record("settlement_receipt", &receipt_id, record.public_record());
        self.settlement_receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: private_l2_low_fee_batch_auction_rebate_payload_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-CONFIG",
                &self.config.public_record(),
            ),
            private_batch_root: private_l2_low_fee_batch_auction_rebate_merkle_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-PRIVATE-BATCH",
                self.private_batches
                    .values()
                    .map(PrivateOrderBatchRecord::public_record)
                    .collect(),
            ),
            solver_bid_root: private_l2_low_fee_batch_auction_rebate_merkle_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-SOLVER-BID",
                self.solver_bids
                    .values()
                    .map(SolverBidRecord::public_record)
                    .collect(),
            ),
            fee_ceiling_proof_root: private_l2_low_fee_batch_auction_rebate_merkle_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-FEE-CEILING-PROOF",
                self.fee_ceiling_proofs
                    .values()
                    .map(FeeCeilingProofRecord::public_record)
                    .collect(),
            ),
            sponsor_reservation_root: private_l2_low_fee_batch_auction_rebate_merkle_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-SPONSOR-RESERVATION",
                self.sponsor_reservations
                    .values()
                    .map(SponsorReservationRecord::public_record)
                    .collect(),
            ),
            rebate_epoch_root: private_l2_low_fee_batch_auction_rebate_merkle_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-EPOCH",
                self.rebate_epochs
                    .values()
                    .map(RebateEpochRecord::public_record)
                    .collect(),
            ),
            settlement_receipt_root: private_l2_low_fee_batch_auction_rebate_merkle_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-SETTLEMENT-RECEIPT",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceiptRecord::public_record)
                    .collect(),
            ),
            consumed_nullifier_root: private_l2_low_fee_batch_auction_rebate_merkle_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-CONSUMED-NULLIFIER",
                self.consumed_nullifier_roots
                    .iter()
                    .map(|root| json!({ "nullifier_root": root }))
                    .collect(),
            ),
            public_record_root: private_l2_low_fee_batch_auction_rebate_merkle_root(
                "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-PUBLIC-RECORD",
                self.public_records.values().cloned().collect(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_batch_auction_rebate_runtime",
            "protocol_version": PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_HASH_SUITE,
            "private_batch_scheme": PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_PRIVATE_BATCH_SCHEME,
            "solver_bid_scheme": PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SOLVER_BID_SCHEME,
            "fee_ceiling_proof_scheme": PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_FEE_CEILING_PROOF_SCHEME,
            "sponsor_reservation_scheme": PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SPONSOR_RESERVATION_SCHEME,
            "rebate_epoch_scheme": PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_REBATE_EPOCH_SCHEME,
            "settlement_receipt_scheme": PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_SETTLEMENT_RECEIPT_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "sponsor_budget_remaining_micro_units": self.sponsor_budget_remaining_micro_units,
            "roots": self.roots().public_record(),
            "privacy_boundary": "public records expose roots, commitments, statuses, counters, and deterministic ids only",
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": private_l2_low_fee_batch_auction_rebate_state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_low_fee_batch_auction_rebate_state_root_from_record(
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

    fn refresh_batch_records(&mut self, batch_ids: &[String]) {
        let updates = batch_ids
            .iter()
            .filter_map(|batch_id| {
                self.private_batches
                    .get(batch_id)
                    .map(|batch| (batch.batch_id.clone(), batch.public_record()))
            })
            .collect::<Vec<_>>();
        for (batch_id, record) in updates {
            self.publish_public_record("private_order_batch", &batch_id, record);
        }
    }

    fn refresh_bid_records(&mut self, bid_ids: &[String]) {
        let updates = bid_ids
            .iter()
            .filter_map(|bid_id| {
                self.solver_bids
                    .get(bid_id)
                    .map(|bid| (bid.bid_id.clone(), bid.public_record()))
            })
            .collect::<Vec<_>>();
        for (bid_id, record) in updates {
            self.publish_public_record("solver_bid", &bid_id, record);
        }
    }

    fn refresh_reservation_records(&mut self, reservation_ids: &[String]) {
        let updates = reservation_ids
            .iter()
            .filter_map(|reservation_id| {
                self.sponsor_reservations
                    .get(reservation_id)
                    .map(|reservation| {
                        (
                            reservation.reservation_id.clone(),
                            reservation.public_record(),
                        )
                    })
            })
            .collect::<Vec<_>>();
        for (reservation_id, record) in updates {
            self.publish_public_record("sponsor_reservation", &reservation_id, record);
        }
    }

    fn refresh_epoch_records(&mut self, epoch_ids: &[String]) {
        let updates = epoch_ids
            .iter()
            .filter_map(|epoch_id| {
                self.rebate_epochs
                    .get(epoch_id)
                    .map(|epoch| (epoch.epoch_id.clone(), epoch.public_record()))
            })
            .collect::<Vec<_>>();
        for (epoch_id, record) in updates {
            self.publish_public_record("rebate_epoch", &epoch_id, record);
        }
    }
}

pub fn private_l2_low_fee_batch_auction_rebate_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_BATCH_AUCTION_REBATE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_l2_low_fee_batch_auction_rebate_state_root_from_record(record: &Value) -> String {
    private_l2_low_fee_batch_auction_rebate_payload_root(
        "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-STATE",
        record,
    )
}

pub fn private_l2_low_fee_batch_auction_rebate_merkle_root(
    domain: &str,
    leaves: Vec<Value>,
) -> String {
    merkle_root(domain, &leaves)
}

pub fn private_order_batch_id(request: &SubmitPrivateOrderBatchRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-PRIVATE-ORDER-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(request.order_kind.as_str()),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.sealed_order_batch_root),
            HashPart::Str(&request.order_commitment_root),
            HashPart::Str(&request.nullifier_root),
        ],
        32,
    )
}

pub fn solver_bid_id(request: &PostSolverBidRequest, score: u128, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-SOLVER-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.solver_commitment),
            HashPart::Str(&id_list_root("SOLVER-BID-BATCH-ID", &request.batch_ids)),
            HashPart::Str(&request.route_commitment_root),
            HashPart::Str(&request.execution_plan_root),
            HashPart::Int(score as i128),
        ],
        32,
    )
}

pub fn fee_ceiling_proof_id(request: &RecordFeeCeilingProofRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-FEE-CEILING-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.proof_root),
            HashPart::Str(&request.public_input_root),
            HashPart::Int(request.fee_ceiling_bps as i128),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    request: &ReserveSponsorRebateRequest,
    nonce: u64,
    remaining_budget_micro_units: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&id_list_root(
                "SPONSOR-RESERVATION-BATCH-ID",
                &request.batch_ids,
            )),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Int(request.reserved_micro_units as i128),
            HashPart::Int(remaining_budget_micro_units as i128),
        ],
        32,
    )
}

pub fn rebate_epoch_id(request: &OpenRebateEpochRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.epoch_label),
            HashPart::Str(&request.sponsor_pool_root),
            HashPart::Str(&request.eligible_batch_root),
            HashPart::Int(request.starts_at_height as i128),
            HashPart::Int(request.ends_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &PublishSettlementReceiptRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.selected_bid_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.settlement_proof_root),
            HashPart::Str(&request.state_root_before),
            HashPart::Str(&request.runtime_state_root_after),
            HashPart::Int(request.settled_at_height as i128),
        ],
        32,
    )
}

fn solver_bid_score(request: &PostSolverBidRequest) -> u128 {
    let surplus = request.expected_surplus_micro_units as u128;
    let rebate_bonus = request.rebate_share_bps as u128 * 1_000_000;
    let batch_bonus = request.batch_ids.len() as u128 * 10_000_000;
    let fee_penalty = request.solver_fee_bps as u128 * 1_000_000;
    surplus
        .saturating_add(rebate_bonus)
        .saturating_add(batch_bonus)
        .saturating_sub(fee_penalty)
}

fn id_list_root(label: &str, ids: &[String]) -> String {
    private_l2_low_fee_batch_auction_rebate_merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-{label}"),
        ids.iter().map(|id| json!(id)).collect(),
    )
}

fn covers_all_reservations(
    reservations: &BTreeMap<String, SponsorReservationRecord>,
    reservation_ids: &[String],
    batch_id: &str,
) -> bool {
    reservation_ids.iter().all(|reservation_id| {
        reservations
            .get(reservation_id)
            .map(|reservation| {
                reservation.status == ReservationStatus::Reserved
                    && reservation
                        .request
                        .batch_ids
                        .iter()
                        .any(|id| id == batch_id)
            })
            .unwrap_or(false)
    })
}

fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-PUBLIC-RECORD-ID",
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
        "kind": "private_l2_low_fee_batch_auction_rebate_roots_only_payload",
        "chain_id": CHAIN_ID,
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": private_l2_low_fee_batch_auction_rebate_payload_root(
            "PRIVATE-L2-LOW-FEE-BATCH-AUCTION-REBATE-ROOTS-ONLY-PAYLOAD",
            payload,
        ),
    })
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
    require_non_empty(label, value)?;
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
) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value) {
            return Err(format!("duplicate {label}: {value}"));
        }
    }
    Ok(())
}

fn ensure_eq(
    actual: &str,
    expected: &str,
    label: &str,
) -> PrivateL2LowFeeBatchAuctionRebateRuntimeResult<()> {
    if actual != expected {
        return Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}
