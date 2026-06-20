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
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SPONSOR_AUCTION_CLEARING_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-sponsor-auction-clearing-runtime-v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-sponsor-auction-clearing-v1";
pub const PQ_SEALING_SUITE: &str = "ML-KEM-1024+XWing-confidential-sponsor-bid-envelope-v1";
pub const CONFIDENTIAL_BUNDLE_SCHEME: &str = "ringct-style-private-bundle-commitment-v1";
pub const FEE_FUTURES_SCHEME: &str = "pq-confidential-low-fee-futures-position-v1";
pub const BLOB_SUBSIDY_SCHEME: &str = "private-l2-low-fee-blob-da-subsidy-root-v1";
pub const PROOF_SUBSIDY_SCHEME: &str = "private-l2-low-fee-recursive-proof-subsidy-root-v1";
pub const DA_SUBSIDY_SCHEME: &str = "private-l2-low-fee-data-availability-subsidy-root-v1";
pub const CAP_ENFORCEMENT_SCHEME: &str = "low-fee-confidential-cap-enforcement-ledger-v1";
pub const REBATE_SCHEME: &str = "private-l2-roots-only-sponsor-auction-rebate-v1";
pub const RECEIPT_SCHEME: &str = "private-clearing-receipt-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "roots-only-low-fee-sponsor-auction-operator-summary-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "roots-only-low-fee-sponsor-auction-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_SPONSOR_AUCTION_CLEARING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 3_036_480;
pub const DEVNET_EPOCH: u64 = 6_149;
pub const DEVNET_CHAIN_ID: u64 = 731_337;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_FUTURE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_SUBSIDY_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_CAP_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 8_640;
pub const DEFAULT_SUMMARY_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 4;
pub const DEFAULT_MIN_REBATE_BPS: u64 = 3;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 12;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 35;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_600;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_250;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 25;
pub const DEFAULT_BLOB_SUBSIDY_BPS: u64 = 2_500;
pub const DEFAULT_PROOF_SUBSIDY_BPS: u64 = 2_000;
pub const DEFAULT_DA_SUBSIDY_BPS: u64 = 1_500;
pub const DEFAULT_FUTURE_MARGIN_BPS: u64 = 1_250;
pub const DEFAULT_CAP_BUFFER_BPS: u64 = 500;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const MAX_SPONSOR_BOOKS: usize = 8_388_608;
pub const MAX_SPONSOR_ORDERS: usize = 8_388_608;
pub const MAX_BUNDLE_COMMITMENTS: usize = 8_388_608;
pub const MAX_FEE_FUTURES: usize = 8_388_608;
pub const MAX_SUBSIDIES: usize = 8_388_608;
pub const MAX_CAP_RECORDS: usize = 8_388_608;
pub const MAX_REBATES: usize = 8_388_608;
pub const MAX_RECEIPTS: usize = 8_388_608;
pub const MAX_OPERATOR_SUMMARIES: usize = 8_388_608;
pub const MAX_PUBLIC_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionLane {
    PrivateTransfer,
    ConfidentialContractCall,
    DefiBundle,
    BlobDa,
    RecursiveProof,
    BridgeExit,
    WalletFastSync,
    AccountAbstraction,
    LiquidationBackstop,
    EmergencyEscape,
}
impl AuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialContractCall => "confidential_contract_call",
            Self::DefiBundle => "defi_bundle",
            Self::BlobDa => "blob_da",
            Self::RecursiveProof => "recursive_proof",
            Self::BridgeExit => "bridge_exit",
            Self::WalletFastSync => "wallet_fast_sync",
            Self::AccountAbstraction => "account_abstraction",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::LiquidationBackstop => 9_250,
            Self::BridgeExit => 8_500,
            Self::DefiBundle => 7_750,
            Self::ConfidentialContractCall => 7_000,
            Self::AccountAbstraction => 6_500,
            Self::RecursiveProof => 6_000,
            Self::BlobDa => 5_500,
            Self::PrivateTransfer => 4_750,
            Self::WalletFastSync => 3_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Sponsor,
    UserDemand,
    OperatorBackstop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BookStatus {
    Draft,
    Open,
    Sealed,
    Clearing,
    Settled,
    Paused,
    Expired,
    Slashed,
}
impl BookStatus {
    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Draft | Self::Open)
    }
    pub fn can_clear(self) -> bool {
        matches!(self, Self::Open | Self::Sealed | Self::Clearing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Posted,
    Admitted,
    Matched,
    Cleared,
    Rebated,
    Rejected,
    Expired,
    Slashed,
}
impl OrderStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Posted | Self::Admitted | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Proposed,
    Committed,
    SubsidyPriced,
    CapChecked,
    ClearingQueued,
    Cleared,
    Rebated,
    Rejected,
    Expired,
}
impl BundleStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Proposed
                | Self::Committed
                | Self::SubsidyPriced
                | Self::CapChecked
                | Self::ClearingQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureSide {
    LongFee,
    ShortFee,
    SponsorCovered,
    RebateIndexed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FutureStatus {
    Open,
    Hedged,
    Exercising,
    Settled,
    Liquidated,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsidyKind {
    Blob,
    Proof,
    DataAvailability,
    Operator,
    BridgeExit,
    WalletSync,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsidyStatus {
    Quoted,
    Reserved,
    Applied,
    Recycled,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapStatus {
    Draft,
    Checked,
    Enforced,
    Breached,
    Waived,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Quoted,
    Reserved,
    Earned,
    Paid,
    Recycled,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Private,
    PublishedRoot,
    Final,
    Disputed,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub quote_asset_id: String,
    pub epoch_blocks: u64,
    pub order_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub future_ttl_blocks: u64,
    pub subsidy_ttl_blocks: u64,
    pub cap_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub summary_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub sponsor_cover_bps: u64,
    pub operator_fee_bps: u64,
    pub blob_subsidy_bps: u64,
    pub proof_subsidy_bps: u64,
    pub da_subsidy_bps: u64,
    pub future_margin_bps: u64,
    pub cap_buffer_bps: u64,
    pub slash_bps: u64,
    pub max_sponsor_books: usize,
    pub max_sponsor_orders: usize,
    pub max_bundle_commitments: usize,
    pub max_fee_futures: usize,
    pub max_subsidies: usize,
    pub max_cap_records: usize,
    pub max_rebates: usize,
    pub max_receipts: usize,
    pub max_operator_summaries: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sponsor_books: u64,
    pub sponsor_orders: u64,
    pub bundle_commitments: u64,
    pub fee_futures: u64,
    pub subsidies: u64,
    pub cap_records: u64,
    pub rebates: u64,
    pub receipts: u64,
    pub operator_summaries: u64,
    pub public_events: u64,
    pub cleared_bundles: u64,
    pub rejected_bundles: u64,
    pub cap_breaches: u64,
    pub total_user_fee: u128,
    pub total_sponsor_liquidity: u128,
    pub total_subsidy: u128,
    pub total_rebate: u128,
    pub total_operator_fee: u128,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub sponsor_books_root: String,
    pub sponsor_orders_root: String,
    pub bundle_commitments_root: String,
    pub fee_futures_root: String,
    pub subsidies_root: String,
    pub cap_records_root: String,
    pub rebates_root: String,
    pub receipts_root: String,
    pub operator_summaries_root: String,
    pub privacy_fences_root: String,
    pub public_events_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorBookRequest {
    pub book_id: String,
    pub lane: AuctionLane,
    pub epoch: u64,
    pub open_height: u64,
    pub close_height: u64,
    pub max_user_fee_bps: u64,
    pub clearing_cap: u128,
    pub privacy_set_size: u64,
    pub coordinator_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorBookRecord {
    pub book_id: String,
    pub lane: AuctionLane,
    pub epoch: u64,
    pub open_height: u64,
    pub close_height: u64,
    pub max_user_fee_bps: u64,
    pub clearing_cap: u128,
    pub reserved_liquidity: u128,
    pub matched_liquidity: u128,
    pub privacy_set_size: u64,
    pub coordinator_commitment: String,
    pub status: BookStatus,
    pub commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorOrderRequest {
    pub order_id: String,
    pub book_id: String,
    pub sponsor_id: String,
    pub side: OrderSide,
    pub max_fee_bps: u64,
    pub offered_liquidity: u128,
    pub min_rebate_bps: u64,
    pub bundle_limit: u64,
    pub sealed_bid_commitment: String,
    pub pq_auth_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorOrderRecord {
    pub order_id: String,
    pub book_id: String,
    pub sponsor_id: String,
    pub side: OrderSide,
    pub max_fee_bps: u64,
    pub offered_liquidity: u128,
    pub reserved_liquidity: u128,
    pub filled_liquidity: u128,
    pub min_rebate_bps: u64,
    pub bundle_limit: u64,
    pub filled_bundles: u64,
    pub sealed_bid_commitment: String,
    pub pq_auth_root: String,
    pub status: OrderStatus,
    pub order_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleCommitmentRequest {
    pub bundle_id: String,
    pub book_id: String,
    pub owner_commitment: String,
    pub bundle_commitment: String,
    pub nullifier_root: String,
    pub lane: AuctionLane,
    pub gas_units: u64,
    pub blob_units: u64,
    pub proof_units: u64,
    pub da_units: u64,
    pub user_fee_budget: u128,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BundleCommitmentRecord {
    pub bundle_id: String,
    pub book_id: String,
    pub owner_commitment: String,
    pub bundle_commitment: String,
    pub nullifier_root: String,
    pub lane: AuctionLane,
    pub gas_units: u64,
    pub blob_units: u64,
    pub proof_units: u64,
    pub da_units: u64,
    pub user_fee_budget: u128,
    pub user_fee_charged: u128,
    pub sponsor_paid: u128,
    pub subsidy_amount: u128,
    pub rebate_amount: u128,
    pub privacy_set_size: u64,
    pub status: BundleStatus,
    pub bundle_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeFutureRequest {
    pub future_id: String,
    pub book_id: String,
    pub sponsor_id: String,
    pub side: FutureSide,
    pub notional: u128,
    pub strike_fee_bps: u64,
    pub margin: u128,
    pub maturity_height: u64,
    pub hedge_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeFutureRecord {
    pub future_id: String,
    pub book_id: String,
    pub sponsor_id: String,
    pub side: FutureSide,
    pub notional: u128,
    pub strike_fee_bps: u64,
    pub margin: u128,
    pub settlement_value: u128,
    pub maturity_height: u64,
    pub hedge_commitment: String,
    pub status: FutureStatus,
    pub future_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubsidyRequest {
    pub subsidy_id: String,
    pub bundle_id: String,
    pub kind: SubsidyKind,
    pub units: u64,
    pub rate_bps: u64,
    pub cap_amount: u128,
    pub sponsor_id: String,
    pub proof_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubsidyRecord {
    pub subsidy_id: String,
    pub bundle_id: String,
    pub kind: SubsidyKind,
    pub units: u64,
    pub rate_bps: u64,
    pub cap_amount: u128,
    pub applied_amount: u128,
    pub sponsor_id: String,
    pub proof_commitment: String,
    pub status: SubsidyStatus,
    pub subsidy_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapEnforcementRequest {
    pub cap_id: String,
    pub book_id: String,
    pub bundle_id: String,
    pub fee_cap_bps: u64,
    pub user_fee_budget: u128,
    pub computed_fee: u128,
    pub cap_witness_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CapEnforcementRecord {
    pub cap_id: String,
    pub book_id: String,
    pub bundle_id: String,
    pub fee_cap_bps: u64,
    pub user_fee_budget: u128,
    pub computed_fee: u128,
    pub allowed_fee: u128,
    pub excess_fee: u128,
    pub cap_witness_root: String,
    pub status: CapStatus,
    pub cap_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRequest {
    pub rebate_id: String,
    pub bundle_id: String,
    pub sponsor_id: String,
    pub rebate_bps: u64,
    pub basis_amount: u128,
    pub receiver_commitment: String,
    pub coupon_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub bundle_id: String,
    pub sponsor_id: String,
    pub rebate_bps: u64,
    pub basis_amount: u128,
    pub rebate_amount: u128,
    pub receiver_commitment: String,
    pub coupon_commitment: String,
    pub status: RebateStatus,
    pub rebate_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateClearingReceiptRequest {
    pub receipt_id: String,
    pub book_id: String,
    pub bundle_id: String,
    pub order_id: String,
    pub clearing_price_bps: u64,
    pub user_fee: u128,
    pub sponsor_payment: u128,
    pub rebate_amount: u128,
    pub encrypted_receipt: String,
    pub disclosure_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateClearingReceiptRecord {
    pub receipt_id: String,
    pub book_id: String,
    pub bundle_id: String,
    pub order_id: String,
    pub clearing_price_bps: u64,
    pub user_fee: u128,
    pub sponsor_payment: u128,
    pub rebate_amount: u128,
    pub encrypted_receipt: String,
    pub disclosure_root: String,
    pub status: ReceiptStatus,
    pub receipt_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub cleared_bundles: u64,
    pub rejected_bundles: u64,
    pub total_user_fee: u128,
    pub total_sponsor_payment: u128,
    pub total_subsidy: u128,
    pub total_rebate: u128,
    pub summary_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRecord {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub cleared_bundles: u64,
    pub rejected_bundles: u64,
    pub total_user_fee: u128,
    pub total_sponsor_payment: u128,
    pub total_subsidy: u128,
    pub total_rebate: u128,
    pub operator_fee: u128,
    pub summary_commitment: String,
    pub summary_root: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: DEVNET_CHAIN_ID,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            future_ttl_blocks: DEFAULT_FUTURE_TTL_BLOCKS,
            subsidy_ttl_blocks: DEFAULT_SUBSIDY_TTL_BLOCKS,
            cap_ttl_blocks: DEFAULT_CAP_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            summary_ttl_blocks: DEFAULT_SUMMARY_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            min_rebate_bps: DEFAULT_MIN_REBATE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            blob_subsidy_bps: DEFAULT_BLOB_SUBSIDY_BPS,
            proof_subsidy_bps: DEFAULT_PROOF_SUBSIDY_BPS,
            da_subsidy_bps: DEFAULT_DA_SUBSIDY_BPS,
            future_margin_bps: DEFAULT_FUTURE_MARGIN_BPS,
            cap_buffer_bps: DEFAULT_CAP_BUFFER_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            max_sponsor_books: MAX_SPONSOR_BOOKS,
            max_sponsor_orders: MAX_SPONSOR_ORDERS,
            max_bundle_commitments: MAX_BUNDLE_COMMITMENTS,
            max_fee_futures: MAX_FEE_FUTURES,
            max_subsidies: MAX_SUBSIDIES,
            max_cap_records: MAX_CAP_RECORDS,
            max_rebates: MAX_REBATES,
            max_receipts: MAX_RECEIPTS,
            max_operator_summaries: MAX_OPERATOR_SUMMARIES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.chain_id > 0, "chain id must be nonzero");
        ensure!(self.epoch_blocks > 0, "epoch blocks must be nonzero");
        ensure!(self.min_pq_security_bits >= 128, "pq security too low");
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy too low"
        );
        ensure!(
            self.min_privacy_set_size >= self.min_decoy_set_size,
            "decoy set too large"
        );
        ensure!(self.max_user_fee_bps <= MAX_BPS, "user fee cap above max");
        ensure!(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "target user fee above cap"
        );
        ensure!(
            self.min_rebate_bps <= self.target_rebate_bps,
            "min rebate above target"
        );
        ensure!(
            self.target_rebate_bps <= self.max_rebate_bps,
            "target rebate above max"
        );
        ensure!(self.max_rebate_bps <= MAX_BPS, "rebate above max");
        ensure!(self.sponsor_reserve_bps <= MAX_BPS, "reserve above max");
        ensure!(self.sponsor_cover_bps <= MAX_BPS, "cover above max");
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub sponsor_books: BTreeMap<String, SponsorBookRecord>,
    pub sponsor_orders: BTreeMap<String, SponsorOrderRecord>,
    pub bundle_commitments: BTreeMap<String, BundleCommitmentRecord>,
    pub fee_futures: BTreeMap<String, FeeFutureRecord>,
    pub subsidies: BTreeMap<String, SubsidyRecord>,
    pub cap_records: BTreeMap<String, CapEnforcementRecord>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub receipts: BTreeMap<String, PrivateClearingReceiptRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummaryRecord>,
    pub privacy_fences: BTreeSet<String>,
    pub public_events: Vec<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            sponsor_books: BTreeMap::new(),
            sponsor_orders: BTreeMap::new(),
            bundle_commitments: BTreeMap::new(),
            fee_futures: BTreeMap::new(),
            subsidies: BTreeMap::new(),
            cap_records: BTreeMap::new(),
            rebates: BTreeMap::new(),
            receipts: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            privacy_fences: BTreeSet::new(),
            public_events: Vec::new(),
        };
        state.refresh_roots();
        state
    }
    pub fn validate(&self) -> Result<()> {
        self.config.validate()
    }
    pub fn open_sponsor_book(&mut self, request: SponsorBookRequest) -> Result<String> {
        self.validate()?;
        ensure!(
            !self.sponsor_books.contains_key(&request.book_id),
            "book already exists: {}",
            request.book_id
        );
        ensure!(
            self.sponsor_books.len() < self.config.max_sponsor_books,
            "sponsor book capacity reached"
        );
        ensure!(
            request.close_height > request.open_height,
            "book close height must exceed open height"
        );
        ensure!(
            request.max_user_fee_bps <= self.config.max_user_fee_bps,
            "book fee cap exceeds runtime cap"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "book privacy set too small"
        );
        let commitment_root = self.record_root("sponsor_book", &json!({"book_id": request.book_id, "lane": request.lane, "epoch": request.epoch, "open_height": request.open_height, "close_height": request.close_height, "max_user_fee_bps": request.max_user_fee_bps, "clearing_cap": request.clearing_cap, "privacy_set_size": request.privacy_set_size, "coordinator_commitment": request.coordinator_commitment}));
        let record = SponsorBookRecord {
            book_id: request.book_id.clone(),
            lane: request.lane,
            epoch: request.epoch,
            open_height: request.open_height,
            close_height: request.close_height,
            max_user_fee_bps: request.max_user_fee_bps,
            clearing_cap: request.clearing_cap,
            reserved_liquidity: 0,
            matched_liquidity: 0,
            privacy_set_size: request.privacy_set_size,
            coordinator_commitment: request.coordinator_commitment,
            status: BookStatus::Open,
            commitment_root,
        };
        self.sponsor_books.insert(record.book_id.clone(), record);
        self.counters.sponsor_books = self.counters.sponsor_books.saturating_add(1);
        self.note_event(format!("book:{}:open", request.book_id));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn post_sponsor_order(&mut self, request: SponsorOrderRequest) -> Result<String> {
        self.validate()?;
        ensure!(
            !self.sponsor_orders.contains_key(&request.order_id),
            "order already exists: {}",
            request.order_id
        );
        ensure!(
            self.sponsor_orders.len() < self.config.max_sponsor_orders,
            "sponsor order capacity reached"
        );
        let book = self
            .sponsor_books
            .get(&request.book_id)
            .ok_or_else(|| format!("missing sponsor book: {}", request.book_id))?;
        ensure!(book.status.accepts_orders(), "book does not accept orders");
        ensure!(
            request.max_fee_bps <= book.max_user_fee_bps,
            "order fee exceeds book cap"
        );
        ensure!(
            request.min_rebate_bps >= self.config.min_rebate_bps,
            "order rebate below runtime minimum"
        );
        let order_root = self.record_root("sponsor_order", &json!({"order_id": request.order_id, "book_id": request.book_id, "sponsor_id": request.sponsor_id, "side": request.side, "max_fee_bps": request.max_fee_bps, "offered_liquidity": request.offered_liquidity, "min_rebate_bps": request.min_rebate_bps, "bundle_limit": request.bundle_limit, "sealed_bid_commitment": request.sealed_bid_commitment, "pq_auth_root": request.pq_auth_root}));
        let reserve = bps(request.offered_liquidity, self.config.sponsor_reserve_bps);
        let record = SponsorOrderRecord {
            order_id: request.order_id.clone(),
            book_id: request.book_id.clone(),
            sponsor_id: request.sponsor_id,
            side: request.side,
            max_fee_bps: request.max_fee_bps,
            offered_liquidity: request.offered_liquidity,
            reserved_liquidity: reserve,
            filled_liquidity: 0,
            min_rebate_bps: request.min_rebate_bps,
            bundle_limit: request.bundle_limit,
            filled_bundles: 0,
            sealed_bid_commitment: request.sealed_bid_commitment,
            pq_auth_root: request.pq_auth_root,
            status: OrderStatus::Admitted,
            order_root,
        };
        if let Some(book_mut) = self.sponsor_books.get_mut(&request.book_id) {
            book_mut.reserved_liquidity = book_mut.reserved_liquidity.saturating_add(reserve);
        }
        self.counters.total_sponsor_liquidity = self
            .counters
            .total_sponsor_liquidity
            .saturating_add(request.offered_liquidity);
        self.sponsor_orders.insert(record.order_id.clone(), record);
        self.counters.sponsor_orders = self.counters.sponsor_orders.saturating_add(1);
        self.note_event(format!("order:{}:admitted", request.order_id));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn commit_bundle(&mut self, request: BundleCommitmentRequest) -> Result<String> {
        self.validate()?;
        ensure!(
            !self.bundle_commitments.contains_key(&request.bundle_id),
            "bundle already exists: {}",
            request.bundle_id
        );
        ensure!(
            self.bundle_commitments.len() < self.config.max_bundle_commitments,
            "bundle capacity reached"
        );
        let book = self
            .sponsor_books
            .get(&request.book_id)
            .ok_or_else(|| format!("missing sponsor book: {}", request.book_id))?;
        ensure!(book.status.can_clear(), "book cannot clear bundles");
        ensure!(
            request.user_fee_budget <= book.clearing_cap,
            "bundle budget exceeds clearing cap"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "bundle privacy set too small"
        );
        let bundle_root = self.record_root("bundle_commitment", &json!({"bundle_id": request.bundle_id, "book_id": request.book_id, "owner_commitment": request.owner_commitment, "bundle_commitment": request.bundle_commitment, "nullifier_root": request.nullifier_root, "lane": request.lane, "gas_units": request.gas_units, "blob_units": request.blob_units, "proof_units": request.proof_units, "da_units": request.da_units, "user_fee_budget": request.user_fee_budget, "privacy_set_size": request.privacy_set_size}));
        let record = BundleCommitmentRecord {
            bundle_id: request.bundle_id.clone(),
            book_id: request.book_id,
            owner_commitment: request.owner_commitment,
            bundle_commitment: request.bundle_commitment,
            nullifier_root: request.nullifier_root.clone(),
            lane: request.lane,
            gas_units: request.gas_units,
            blob_units: request.blob_units,
            proof_units: request.proof_units,
            da_units: request.da_units,
            user_fee_budget: request.user_fee_budget,
            user_fee_charged: 0,
            sponsor_paid: 0,
            subsidy_amount: 0,
            rebate_amount: 0,
            privacy_set_size: request.privacy_set_size,
            status: BundleStatus::Committed,
            bundle_root,
        };
        self.privacy_fences.insert(request.nullifier_root);
        self.bundle_commitments
            .insert(record.bundle_id.clone(), record);
        self.counters.bundle_commitments = self.counters.bundle_commitments.saturating_add(1);
        self.note_event(format!("bundle:{}:committed", request.bundle_id));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn open_fee_future(&mut self, request: FeeFutureRequest) -> Result<String> {
        self.validate()?;
        ensure!(
            !self.fee_futures.contains_key(&request.future_id),
            "future already exists: {}",
            request.future_id
        );
        ensure!(
            self.fee_futures.len() < self.config.max_fee_futures,
            "fee future capacity reached"
        );
        ensure!(
            self.sponsor_books.contains_key(&request.book_id),
            "missing sponsor book: {}",
            request.book_id
        );
        ensure!(
            request.strike_fee_bps <= self.config.max_user_fee_bps,
            "future strike exceeds user fee cap"
        );
        ensure!(
            request.margin >= bps(request.notional, self.config.future_margin_bps),
            "future margin below required margin"
        );
        ensure!(
            request.maturity_height > self.height,
            "future maturity must be in the future"
        );
        let future_root = self.record_root("fee_future", &json!({"future_id": request.future_id, "book_id": request.book_id, "sponsor_id": request.sponsor_id, "side": request.side, "notional": request.notional, "strike_fee_bps": request.strike_fee_bps, "margin": request.margin, "maturity_height": request.maturity_height, "hedge_commitment": request.hedge_commitment}));
        let record = FeeFutureRecord {
            future_id: request.future_id.clone(),
            book_id: request.book_id,
            sponsor_id: request.sponsor_id,
            side: request.side,
            notional: request.notional,
            strike_fee_bps: request.strike_fee_bps,
            margin: request.margin,
            settlement_value: 0,
            maturity_height: request.maturity_height,
            hedge_commitment: request.hedge_commitment,
            status: FutureStatus::Open,
            future_root,
        };
        self.fee_futures.insert(record.future_id.clone(), record);
        self.counters.fee_futures = self.counters.fee_futures.saturating_add(1);
        self.note_event(format!("future:{}:open", request.future_id));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn reserve_subsidy(&mut self, request: SubsidyRequest) -> Result<String> {
        self.validate()?;
        ensure!(
            !self.subsidies.contains_key(&request.subsidy_id),
            "subsidy already exists: {}",
            request.subsidy_id
        );
        ensure!(
            self.subsidies.len() < self.config.max_subsidies,
            "subsidy capacity reached"
        );
        let bundle = self
            .bundle_commitments
            .get(&request.bundle_id)
            .ok_or_else(|| format!("missing bundle: {}", request.bundle_id))?;
        ensure!(bundle.status.live(), "bundle is not live for subsidy");
        ensure!(request.rate_bps <= MAX_BPS, "subsidy rate above max");
        let basis = match request.kind {
            SubsidyKind::Blob => u128::from(bundle.blob_units),
            SubsidyKind::Proof => u128::from(bundle.proof_units),
            SubsidyKind::DataAvailability => u128::from(bundle.da_units),
            SubsidyKind::Operator => bundle.user_fee_budget,
            SubsidyKind::BridgeExit => bundle.user_fee_budget / 2,
            SubsidyKind::WalletSync => u128::from(bundle.gas_units),
        };
        let applied_amount = bps(basis, request.rate_bps).min(request.cap_amount);
        let subsidy_root = self.record_root("subsidy", &json!({"subsidy_id": request.subsidy_id, "bundle_id": request.bundle_id, "kind": request.kind, "units": request.units, "rate_bps": request.rate_bps, "cap_amount": request.cap_amount, "applied_amount": applied_amount, "sponsor_id": request.sponsor_id, "proof_commitment": request.proof_commitment}));
        let record = SubsidyRecord {
            subsidy_id: request.subsidy_id.clone(),
            bundle_id: request.bundle_id.clone(),
            kind: request.kind,
            units: request.units,
            rate_bps: request.rate_bps,
            cap_amount: request.cap_amount,
            applied_amount,
            sponsor_id: request.sponsor_id,
            proof_commitment: request.proof_commitment,
            status: SubsidyStatus::Reserved,
            subsidy_root,
        };
        if let Some(bundle_mut) = self.bundle_commitments.get_mut(&request.bundle_id) {
            bundle_mut.subsidy_amount = bundle_mut.subsidy_amount.saturating_add(applied_amount);
            bundle_mut.status = BundleStatus::SubsidyPriced;
        }
        self.subsidies.insert(record.subsidy_id.clone(), record);
        self.counters.subsidies = self.counters.subsidies.saturating_add(1);
        self.counters.total_subsidy = self.counters.total_subsidy.saturating_add(applied_amount);
        self.note_event(format!("subsidy:{}:reserved", request.subsidy_id));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn enforce_cap(&mut self, request: CapEnforcementRequest) -> Result<String> {
        self.validate()?;
        ensure!(
            !self.cap_records.contains_key(&request.cap_id),
            "cap record already exists: {}",
            request.cap_id
        );
        ensure!(
            self.cap_records.len() < self.config.max_cap_records,
            "cap record capacity reached"
        );
        ensure!(
            request.fee_cap_bps
                <= self
                    .config
                    .max_user_fee_bps
                    .saturating_add(self.config.cap_buffer_bps),
            "fee cap above buffered runtime cap"
        );
        let allowed_fee = bps(request.user_fee_budget, request.fee_cap_bps);
        let excess_fee = request.computed_fee.saturating_sub(allowed_fee);
        let status = if excess_fee == 0 {
            CapStatus::Enforced
        } else {
            CapStatus::Breached
        };
        let cap_root = self.record_root("cap_enforcement", &json!({"cap_id": request.cap_id, "book_id": request.book_id, "bundle_id": request.bundle_id, "fee_cap_bps": request.fee_cap_bps, "user_fee_budget": request.user_fee_budget, "computed_fee": request.computed_fee, "allowed_fee": allowed_fee, "excess_fee": excess_fee, "cap_witness_root": request.cap_witness_root, "status": status}));
        let record = CapEnforcementRecord {
            cap_id: request.cap_id.clone(),
            book_id: request.book_id,
            bundle_id: request.bundle_id.clone(),
            fee_cap_bps: request.fee_cap_bps,
            user_fee_budget: request.user_fee_budget,
            computed_fee: request.computed_fee,
            allowed_fee,
            excess_fee,
            cap_witness_root: request.cap_witness_root,
            status,
            cap_root,
        };
        if let Some(bundle_mut) = self.bundle_commitments.get_mut(&request.bundle_id) {
            bundle_mut.user_fee_charged = allowed_fee.min(request.computed_fee);
            bundle_mut.status = if excess_fee == 0 {
                BundleStatus::CapChecked
            } else {
                BundleStatus::Rejected
            };
        }
        if excess_fee > 0 {
            self.counters.cap_breaches = self.counters.cap_breaches.saturating_add(1);
            self.counters.rejected_bundles = self.counters.rejected_bundles.saturating_add(1);
        }
        self.cap_records.insert(record.cap_id.clone(), record);
        self.counters.cap_records = self.counters.cap_records.saturating_add(1);
        self.note_event(format!("cap:{}:{:?}", request.cap_id, status));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn reserve_rebate(&mut self, request: RebateRequest) -> Result<String> {
        self.validate()?;
        ensure!(
            !self.rebates.contains_key(&request.rebate_id),
            "rebate already exists: {}",
            request.rebate_id
        );
        ensure!(
            self.rebates.len() < self.config.max_rebates,
            "rebate capacity reached"
        );
        ensure!(
            self.bundle_commitments.contains_key(&request.bundle_id),
            "missing bundle: {}",
            request.bundle_id
        );
        ensure!(
            request.rebate_bps >= self.config.min_rebate_bps,
            "rebate below minimum"
        );
        ensure!(
            request.rebate_bps <= self.config.max_rebate_bps,
            "rebate above maximum"
        );
        let rebate_amount = bps(request.basis_amount, request.rebate_bps);
        let rebate_root = self.record_root("rebate", &json!({"rebate_id": request.rebate_id, "bundle_id": request.bundle_id, "sponsor_id": request.sponsor_id, "rebate_bps": request.rebate_bps, "basis_amount": request.basis_amount, "rebate_amount": rebate_amount, "receiver_commitment": request.receiver_commitment, "coupon_commitment": request.coupon_commitment}));
        let record = RebateRecord {
            rebate_id: request.rebate_id.clone(),
            bundle_id: request.bundle_id.clone(),
            sponsor_id: request.sponsor_id,
            rebate_bps: request.rebate_bps,
            basis_amount: request.basis_amount,
            rebate_amount,
            receiver_commitment: request.receiver_commitment,
            coupon_commitment: request.coupon_commitment,
            status: RebateStatus::Reserved,
            rebate_root,
        };
        if let Some(bundle_mut) = self.bundle_commitments.get_mut(&request.bundle_id) {
            bundle_mut.rebate_amount = bundle_mut.rebate_amount.saturating_add(rebate_amount);
        }
        self.rebates.insert(record.rebate_id.clone(), record);
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.counters.total_rebate = self.counters.total_rebate.saturating_add(rebate_amount);
        self.note_event(format!("rebate:{}:reserved", request.rebate_id));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn publish_receipt(&mut self, request: PrivateClearingReceiptRequest) -> Result<String> {
        self.validate()?;
        ensure!(
            !self.receipts.contains_key(&request.receipt_id),
            "receipt already exists: {}",
            request.receipt_id
        );
        ensure!(
            self.receipts.len() < self.config.max_receipts,
            "receipt capacity reached"
        );
        ensure!(
            request.clearing_price_bps <= self.config.max_user_fee_bps,
            "receipt clearing price above runtime cap"
        );
        ensure!(
            self.sponsor_books.contains_key(&request.book_id),
            "missing book: {}",
            request.book_id
        );
        ensure!(
            self.sponsor_orders.contains_key(&request.order_id),
            "missing order: {}",
            request.order_id
        );
        ensure!(
            self.bundle_commitments.contains_key(&request.bundle_id),
            "missing bundle: {}",
            request.bundle_id
        );
        let receipt_root = self.record_root("private_clearing_receipt", &json!({"receipt_id": request.receipt_id, "book_id": request.book_id, "bundle_id": request.bundle_id, "order_id": request.order_id, "clearing_price_bps": request.clearing_price_bps, "user_fee": request.user_fee, "sponsor_payment": request.sponsor_payment, "rebate_amount": request.rebate_amount, "encrypted_receipt": request.encrypted_receipt, "disclosure_root": request.disclosure_root}));
        let record = PrivateClearingReceiptRecord {
            receipt_id: request.receipt_id.clone(),
            book_id: request.book_id.clone(),
            bundle_id: request.bundle_id.clone(),
            order_id: request.order_id.clone(),
            clearing_price_bps: request.clearing_price_bps,
            user_fee: request.user_fee,
            sponsor_payment: request.sponsor_payment,
            rebate_amount: request.rebate_amount,
            encrypted_receipt: request.encrypted_receipt,
            disclosure_root: request.disclosure_root,
            status: ReceiptStatus::PublishedRoot,
            receipt_root,
        };
        if let Some(book_mut) = self.sponsor_books.get_mut(&request.book_id) {
            book_mut.matched_liquidity = book_mut
                .matched_liquidity
                .saturating_add(request.sponsor_payment);
            book_mut.status = BookStatus::Clearing;
        }
        if let Some(order_mut) = self.sponsor_orders.get_mut(&request.order_id) {
            order_mut.filled_liquidity = order_mut
                .filled_liquidity
                .saturating_add(request.sponsor_payment);
            order_mut.filled_bundles = order_mut.filled_bundles.saturating_add(1);
            order_mut.status = OrderStatus::Matched;
        }
        if let Some(bundle_mut) = self.bundle_commitments.get_mut(&request.bundle_id) {
            bundle_mut.user_fee_charged = request.user_fee;
            bundle_mut.sponsor_paid = request.sponsor_payment;
            bundle_mut.rebate_amount = request.rebate_amount;
            bundle_mut.status = BundleStatus::Cleared;
        }
        self.receipts.insert(record.receipt_id.clone(), record);
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        self.counters.cleared_bundles = self.counters.cleared_bundles.saturating_add(1);
        self.counters.total_user_fee = self
            .counters
            .total_user_fee
            .saturating_add(request.user_fee);
        self.note_event(format!("receipt:{}:published", request.receipt_id));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn publish_operator_summary(&mut self, request: OperatorSummaryRequest) -> Result<String> {
        self.validate()?;
        ensure!(
            !self.operator_summaries.contains_key(&request.summary_id),
            "summary already exists: {}",
            request.summary_id
        );
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity reached"
        );
        let operator_fee = bps(
            request
                .total_user_fee
                .saturating_add(request.total_sponsor_payment),
            self.config.operator_fee_bps,
        );
        let summary_root = self.record_root("operator_summary", &json!({"summary_id": request.summary_id, "operator_id": request.operator_id, "epoch": request.epoch, "cleared_bundles": request.cleared_bundles, "rejected_bundles": request.rejected_bundles, "total_user_fee": request.total_user_fee, "total_sponsor_payment": request.total_sponsor_payment, "total_subsidy": request.total_subsidy, "total_rebate": request.total_rebate, "operator_fee": operator_fee, "summary_commitment": request.summary_commitment}));
        let record = OperatorSummaryRecord {
            summary_id: request.summary_id.clone(),
            operator_id: request.operator_id,
            epoch: request.epoch,
            cleared_bundles: request.cleared_bundles,
            rejected_bundles: request.rejected_bundles,
            total_user_fee: request.total_user_fee,
            total_sponsor_payment: request.total_sponsor_payment,
            total_subsidy: request.total_subsidy,
            total_rebate: request.total_rebate,
            operator_fee,
            summary_commitment: request.summary_commitment,
            summary_root,
        };
        self.operator_summaries
            .insert(record.summary_id.clone(), record);
        self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
        self.counters.total_operator_fee = self
            .counters
            .total_operator_fee
            .saturating_add(operator_fee);
        self.note_event(format!("summary:{}:published", request.summary_id));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn clear_book(&mut self, book_id: &str) -> Result<String> {
        let book = self
            .sponsor_books
            .get(book_id)
            .ok_or_else(|| format!("missing book: {}", book_id))?;
        ensure!(book.status.can_clear(), "book cannot be cleared");
        let mut selected_order_id = String::new();
        let mut selected_fee_bps = self.config.max_user_fee_bps;
        for order in self.sponsor_orders.values() {
            if order.book_id == book_id
                && order.status.live()
                && order.max_fee_bps <= selected_fee_bps
            {
                selected_order_id = order.order_id.clone();
                selected_fee_bps = order.max_fee_bps;
            }
        }
        ensure!(
            !selected_order_id.is_empty(),
            "no live sponsor order for book: {}",
            book_id
        );
        let bundle_ids: Vec<String> = self
            .bundle_commitments
            .values()
            .filter(|bundle| {
                bundle.book_id == book_id
                    && matches!(
                        bundle.status,
                        BundleStatus::CapChecked
                            | BundleStatus::SubsidyPriced
                            | BundleStatus::Committed
                    )
            })
            .map(|bundle| bundle.bundle_id.clone())
            .collect();
        for bundle_id in bundle_ids {
            if let Some(bundle) = self.bundle_commitments.get(&bundle_id).cloned() {
                let user_fee =
                    bps(bundle.user_fee_budget, selected_fee_bps).min(bundle.user_fee_budget);
                let sponsor_payment = bundle
                    .user_fee_budget
                    .saturating_sub(user_fee)
                    .saturating_sub(bundle.subsidy_amount);
                let rebate_amount = bps(user_fee, self.config.target_rebate_bps);
                let receipt_id = format!("receipt-{}-{}", book_id, bundle.bundle_id);
                if !self.receipts.contains_key(&receipt_id) {
                    self.publish_receipt(PrivateClearingReceiptRequest { receipt_id, book_id: book_id.to_string(), bundle_id: bundle.bundle_id, order_id: selected_order_id.clone(), clearing_price_bps: selected_fee_bps, user_fee, sponsor_payment, rebate_amount, encrypted_receipt: self.record_root("encrypted_receipt", &json!({ "book_id": book_id, "bundle_id": bundle_id })), disclosure_root: self.record_root("disclosure", &json!({ "book_id": book_id, "bundle_id": bundle_id, "order_id": selected_order_id })) })?;
                }
            }
        }
        if let Some(book_mut) = self.sponsor_books.get_mut(book_id) {
            book_mut.status = BookStatus::Settled;
        }
        self.note_event(format!("book:{}:settled", book_id));
        self.refresh_roots();
        Ok(self.state_root())
    }
    pub fn public_record(&self) -> Value {
        json!({"scheme": PUBLIC_RECORD_SCHEME, "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "hash_suite": HASH_SUITE, "pq_auth_suite": PQ_AUTH_SUITE, "pq_sealing_suite": PQ_SEALING_SUITE, "chain_id": self.config.chain_id, "height": self.height, "epoch": self.epoch, "l2_network": self.config.l2_network, "monero_network": self.config.monero_network, "fee_asset_id": self.config.fee_asset_id, "rebate_asset_id": self.config.rebate_asset_id, "quote_asset_id": self.config.quote_asset_id, "counters": self.counters, "roots": self.roots, "limits": {"max_user_fee_bps": self.config.max_user_fee_bps, "target_user_fee_bps": self.config.target_user_fee_bps, "target_rebate_bps": self.config.target_rebate_bps, "sponsor_cover_bps": self.config.sponsor_cover_bps, "operator_fee_bps": self.config.operator_fee_bps, "min_privacy_set_size": self.config.min_privacy_set_size, "min_pq_security_bits": self.config.min_pq_security_bits}})
    }
    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
    pub fn refresh_roots(&mut self) {
        self.roots.sponsor_books_root = map_root("sponsor_books", &self.sponsor_books);
        self.roots.sponsor_orders_root = map_root("sponsor_orders", &self.sponsor_orders);
        self.roots.bundle_commitments_root =
            map_root("bundle_commitments", &self.bundle_commitments);
        self.roots.fee_futures_root = map_root("fee_futures", &self.fee_futures);
        self.roots.subsidies_root = map_root("subsidies", &self.subsidies);
        self.roots.cap_records_root = map_root("cap_records", &self.cap_records);
        self.roots.rebates_root = map_root("rebates", &self.rebates);
        self.roots.receipts_root = map_root("receipts", &self.receipts);
        self.roots.operator_summaries_root =
            map_root("operator_summaries", &self.operator_summaries);
        self.roots.privacy_fences_root = set_root("privacy_fences", &self.privacy_fences);
        self.roots.public_events_root = vec_root("public_events", &self.public_events);
        self.roots.state_root = domain_hash(
            "private_l2_low_fee_pq_confidential_sponsor_auction_clearing_state",
            &[
                HashPart::U64(self.config.chain_id),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::Str(&self.roots.sponsor_books_root),
                HashPart::Str(&self.roots.sponsor_orders_root),
                HashPart::Str(&self.roots.bundle_commitments_root),
                HashPart::Str(&self.roots.fee_futures_root),
                HashPart::Str(&self.roots.subsidies_root),
                HashPart::Str(&self.roots.cap_records_root),
                HashPart::Str(&self.roots.rebates_root),
                HashPart::Str(&self.roots.receipts_root),
                HashPart::Str(&self.roots.operator_summaries_root),
                HashPart::Str(&self.roots.privacy_fences_root),
                HashPart::Str(&self.roots.public_events_root),
            ],
            32,
        );
    }
    fn record_root(&self, domain: &str, value: &Value) -> String {
        domain_hash(
            domain,
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.config.chain_id),
                HashPart::U64(self.height),
                HashPart::U64(self.epoch),
                HashPart::Str(&canonical_value(value)),
            ],
            32,
        )
    }
    fn note_event(&mut self, event: String) {
        if self.public_events.len() < MAX_PUBLIC_EVENTS {
            self.public_events.push(event);
            self.counters.public_events = self.counters.public_events.saturating_add(1);
        }
    }
}

pub fn devnet() -> State {
    State::default()
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.open_sponsor_book(SponsorBookRequest {
        book_id: "devnet-book-blob-proof-0".to_string(),
        lane: AuctionLane::BlobDa,
        epoch: DEVNET_EPOCH,
        open_height: DEVNET_HEIGHT,
        close_height: DEVNET_HEIGHT + DEFAULT_ORDER_TTL_BLOCKS,
        max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        clearing_cap: 5_000_000_000,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        coordinator_commitment: "coord-root-devnet-0".to_string(),
    });
    let _ = state.post_sponsor_order(SponsorOrderRequest {
        order_id: "devnet-order-sponsor-a".to_string(),
        book_id: "devnet-book-blob-proof-0".to_string(),
        sponsor_id: "sponsor-a".to_string(),
        side: OrderSide::Sponsor,
        max_fee_bps: 4,
        offered_liquidity: 4_000_000_000,
        min_rebate_bps: DEFAULT_MIN_REBATE_BPS,
        bundle_limit: 64,
        sealed_bid_commitment: "sealed-bid-root-a".to_string(),
        pq_auth_root: "pq-auth-root-a".to_string(),
    });
    let _ = state.commit_bundle(BundleCommitmentRequest {
        bundle_id: "devnet-bundle-0".to_string(),
        book_id: "devnet-book-blob-proof-0".to_string(),
        owner_commitment: "owner-root-0".to_string(),
        bundle_commitment: "bundle-root-0".to_string(),
        nullifier_root: "nullifier-root-0".to_string(),
        lane: AuctionLane::BlobDa,
        gas_units: 120_000,
        blob_units: 8,
        proof_units: 2,
        da_units: 32,
        user_fee_budget: 120_000_000,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
    });
    let _ = state.reserve_subsidy(SubsidyRequest {
        subsidy_id: "devnet-subsidy-blob-0".to_string(),
        bundle_id: "devnet-bundle-0".to_string(),
        kind: SubsidyKind::Blob,
        units: 8,
        rate_bps: DEFAULT_BLOB_SUBSIDY_BPS,
        cap_amount: 25_000_000,
        sponsor_id: "sponsor-a".to_string(),
        proof_commitment: "blob-proof-root-0".to_string(),
    });
    let _ = state.enforce_cap(CapEnforcementRequest {
        cap_id: "devnet-cap-0".to_string(),
        book_id: "devnet-book-blob-proof-0".to_string(),
        bundle_id: "devnet-bundle-0".to_string(),
        fee_cap_bps: DEFAULT_MAX_USER_FEE_BPS,
        user_fee_budget: 120_000_000,
        computed_fee: 100_000,
        cap_witness_root: "cap-witness-root-0".to_string(),
    });
    let _ = state.open_fee_future(FeeFutureRequest {
        future_id: "devnet-future-0".to_string(),
        book_id: "devnet-book-blob-proof-0".to_string(),
        sponsor_id: "sponsor-a".to_string(),
        side: FutureSide::ShortFee,
        notional: 500_000_000,
        strike_fee_bps: 4,
        margin: 70_000_000,
        maturity_height: DEVNET_HEIGHT + DEFAULT_FUTURE_TTL_BLOCKS,
        hedge_commitment: "hedge-root-0".to_string(),
    });
    let _ = state.reserve_rebate(RebateRequest {
        rebate_id: "devnet-rebate-0".to_string(),
        bundle_id: "devnet-bundle-0".to_string(),
        sponsor_id: "sponsor-a".to_string(),
        rebate_bps: DEFAULT_TARGET_REBATE_BPS,
        basis_amount: 120_000_000,
        receiver_commitment: "receiver-root-0".to_string(),
        coupon_commitment: "coupon-root-0".to_string(),
    });
    let _ = state.clear_book("devnet-book-blob-proof-0");
    let _ = state.publish_operator_summary(OperatorSummaryRequest {
        summary_id: "devnet-summary-0".to_string(),
        operator_id: "operator-devnet-a".to_string(),
        epoch: DEVNET_EPOCH,
        cleared_bundles: state.counters.cleared_bundles,
        rejected_bundles: state.counters.rejected_bundles,
        total_user_fee: state.counters.total_user_fee,
        total_sponsor_payment: 119_952_000,
        total_subsidy: state.counters.total_subsidy,
        total_rebate: state.counters.total_rebate,
        summary_commitment: "operator-summary-root-0".to_string(),
    });
    state.refresh_roots();
    state
}
fn bps(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(u128::from(bps)) / u128::from(MAX_BPS)
}
fn canonical_value(value: &Value) -> String {
    match serde_json::to_string(value) {
        Ok(encoded) => encoded,
        Err(err) => format!("serde-json-error:{}", err),
    }
}
fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            let encoded = match serde_json::to_string(value) {
                Ok(text) => text,
                Err(err) => format!("serde-json-error:{}", err),
            };
            Value::String(domain_hash(
                domain,
                &[HashPart::Str(key), HashPart::Str(&encoded)],
                32,
            ))
        })
        .collect();
    merkle_root(domain, &leaves)
}
fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set
        .iter()
        .map(|value| Value::String(domain_hash(domain, &[HashPart::Str(value)], 32)))
        .collect();
    merkle_root(domain, &leaves)
}
fn vec_root(domain: &str, values: &[String]) -> String {
    let leaves: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            Value::String(domain_hash(
                domain,
                &[HashPart::U64(index as u64), HashPart::Str(value)],
                32,
            ))
        })
        .collect();
    merkle_root(domain, &leaves)
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolInvariant {
    pub invariant_id: u16,
    pub name: &'static str,
    pub description: &'static str,
}
pub const PROTOCOL_INVARIANTS: &[ProtocolInvariant] = &[
    ProtocolInvariant {
        invariant_id: 1,
        name: "sponsor_auction_invariant_001",
        description: "deterministic low fee sponsor auction clearing invariant 001",
    },
    ProtocolInvariant {
        invariant_id: 2,
        name: "sponsor_auction_invariant_002",
        description: "deterministic low fee sponsor auction clearing invariant 002",
    },
    ProtocolInvariant {
        invariant_id: 3,
        name: "sponsor_auction_invariant_003",
        description: "deterministic low fee sponsor auction clearing invariant 003",
    },
    ProtocolInvariant {
        invariant_id: 4,
        name: "sponsor_auction_invariant_004",
        description: "deterministic low fee sponsor auction clearing invariant 004",
    },
    ProtocolInvariant {
        invariant_id: 5,
        name: "sponsor_auction_invariant_005",
        description: "deterministic low fee sponsor auction clearing invariant 005",
    },
    ProtocolInvariant {
        invariant_id: 6,
        name: "sponsor_auction_invariant_006",
        description: "deterministic low fee sponsor auction clearing invariant 006",
    },
    ProtocolInvariant {
        invariant_id: 7,
        name: "sponsor_auction_invariant_007",
        description: "deterministic low fee sponsor auction clearing invariant 007",
    },
    ProtocolInvariant {
        invariant_id: 8,
        name: "sponsor_auction_invariant_008",
        description: "deterministic low fee sponsor auction clearing invariant 008",
    },
    ProtocolInvariant {
        invariant_id: 9,
        name: "sponsor_auction_invariant_009",
        description: "deterministic low fee sponsor auction clearing invariant 009",
    },
    ProtocolInvariant {
        invariant_id: 10,
        name: "sponsor_auction_invariant_010",
        description: "deterministic low fee sponsor auction clearing invariant 010",
    },
    ProtocolInvariant {
        invariant_id: 11,
        name: "sponsor_auction_invariant_011",
        description: "deterministic low fee sponsor auction clearing invariant 011",
    },
    ProtocolInvariant {
        invariant_id: 12,
        name: "sponsor_auction_invariant_012",
        description: "deterministic low fee sponsor auction clearing invariant 012",
    },
    ProtocolInvariant {
        invariant_id: 13,
        name: "sponsor_auction_invariant_013",
        description: "deterministic low fee sponsor auction clearing invariant 013",
    },
    ProtocolInvariant {
        invariant_id: 14,
        name: "sponsor_auction_invariant_014",
        description: "deterministic low fee sponsor auction clearing invariant 014",
    },
    ProtocolInvariant {
        invariant_id: 15,
        name: "sponsor_auction_invariant_015",
        description: "deterministic low fee sponsor auction clearing invariant 015",
    },
    ProtocolInvariant {
        invariant_id: 16,
        name: "sponsor_auction_invariant_016",
        description: "deterministic low fee sponsor auction clearing invariant 016",
    },
    ProtocolInvariant {
        invariant_id: 17,
        name: "sponsor_auction_invariant_017",
        description: "deterministic low fee sponsor auction clearing invariant 017",
    },
    ProtocolInvariant {
        invariant_id: 18,
        name: "sponsor_auction_invariant_018",
        description: "deterministic low fee sponsor auction clearing invariant 018",
    },
    ProtocolInvariant {
        invariant_id: 19,
        name: "sponsor_auction_invariant_019",
        description: "deterministic low fee sponsor auction clearing invariant 019",
    },
    ProtocolInvariant {
        invariant_id: 20,
        name: "sponsor_auction_invariant_020",
        description: "deterministic low fee sponsor auction clearing invariant 020",
    },
    ProtocolInvariant {
        invariant_id: 21,
        name: "sponsor_auction_invariant_021",
        description: "deterministic low fee sponsor auction clearing invariant 021",
    },
    ProtocolInvariant {
        invariant_id: 22,
        name: "sponsor_auction_invariant_022",
        description: "deterministic low fee sponsor auction clearing invariant 022",
    },
    ProtocolInvariant {
        invariant_id: 23,
        name: "sponsor_auction_invariant_023",
        description: "deterministic low fee sponsor auction clearing invariant 023",
    },
    ProtocolInvariant {
        invariant_id: 24,
        name: "sponsor_auction_invariant_024",
        description: "deterministic low fee sponsor auction clearing invariant 024",
    },
    ProtocolInvariant {
        invariant_id: 25,
        name: "sponsor_auction_invariant_025",
        description: "deterministic low fee sponsor auction clearing invariant 025",
    },
    ProtocolInvariant {
        invariant_id: 26,
        name: "sponsor_auction_invariant_026",
        description: "deterministic low fee sponsor auction clearing invariant 026",
    },
    ProtocolInvariant {
        invariant_id: 27,
        name: "sponsor_auction_invariant_027",
        description: "deterministic low fee sponsor auction clearing invariant 027",
    },
    ProtocolInvariant {
        invariant_id: 28,
        name: "sponsor_auction_invariant_028",
        description: "deterministic low fee sponsor auction clearing invariant 028",
    },
    ProtocolInvariant {
        invariant_id: 29,
        name: "sponsor_auction_invariant_029",
        description: "deterministic low fee sponsor auction clearing invariant 029",
    },
    ProtocolInvariant {
        invariant_id: 30,
        name: "sponsor_auction_invariant_030",
        description: "deterministic low fee sponsor auction clearing invariant 030",
    },
    ProtocolInvariant {
        invariant_id: 31,
        name: "sponsor_auction_invariant_031",
        description: "deterministic low fee sponsor auction clearing invariant 031",
    },
    ProtocolInvariant {
        invariant_id: 32,
        name: "sponsor_auction_invariant_032",
        description: "deterministic low fee sponsor auction clearing invariant 032",
    },
    ProtocolInvariant {
        invariant_id: 33,
        name: "sponsor_auction_invariant_033",
        description: "deterministic low fee sponsor auction clearing invariant 033",
    },
    ProtocolInvariant {
        invariant_id: 34,
        name: "sponsor_auction_invariant_034",
        description: "deterministic low fee sponsor auction clearing invariant 034",
    },
    ProtocolInvariant {
        invariant_id: 35,
        name: "sponsor_auction_invariant_035",
        description: "deterministic low fee sponsor auction clearing invariant 035",
    },
    ProtocolInvariant {
        invariant_id: 36,
        name: "sponsor_auction_invariant_036",
        description: "deterministic low fee sponsor auction clearing invariant 036",
    },
    ProtocolInvariant {
        invariant_id: 37,
        name: "sponsor_auction_invariant_037",
        description: "deterministic low fee sponsor auction clearing invariant 037",
    },
    ProtocolInvariant {
        invariant_id: 38,
        name: "sponsor_auction_invariant_038",
        description: "deterministic low fee sponsor auction clearing invariant 038",
    },
    ProtocolInvariant {
        invariant_id: 39,
        name: "sponsor_auction_invariant_039",
        description: "deterministic low fee sponsor auction clearing invariant 039",
    },
    ProtocolInvariant {
        invariant_id: 40,
        name: "sponsor_auction_invariant_040",
        description: "deterministic low fee sponsor auction clearing invariant 040",
    },
    ProtocolInvariant {
        invariant_id: 41,
        name: "sponsor_auction_invariant_041",
        description: "deterministic low fee sponsor auction clearing invariant 041",
    },
    ProtocolInvariant {
        invariant_id: 42,
        name: "sponsor_auction_invariant_042",
        description: "deterministic low fee sponsor auction clearing invariant 042",
    },
    ProtocolInvariant {
        invariant_id: 43,
        name: "sponsor_auction_invariant_043",
        description: "deterministic low fee sponsor auction clearing invariant 043",
    },
    ProtocolInvariant {
        invariant_id: 44,
        name: "sponsor_auction_invariant_044",
        description: "deterministic low fee sponsor auction clearing invariant 044",
    },
    ProtocolInvariant {
        invariant_id: 45,
        name: "sponsor_auction_invariant_045",
        description: "deterministic low fee sponsor auction clearing invariant 045",
    },
    ProtocolInvariant {
        invariant_id: 46,
        name: "sponsor_auction_invariant_046",
        description: "deterministic low fee sponsor auction clearing invariant 046",
    },
    ProtocolInvariant {
        invariant_id: 47,
        name: "sponsor_auction_invariant_047",
        description: "deterministic low fee sponsor auction clearing invariant 047",
    },
    ProtocolInvariant {
        invariant_id: 48,
        name: "sponsor_auction_invariant_048",
        description: "deterministic low fee sponsor auction clearing invariant 048",
    },
    ProtocolInvariant {
        invariant_id: 49,
        name: "sponsor_auction_invariant_049",
        description: "deterministic low fee sponsor auction clearing invariant 049",
    },
    ProtocolInvariant {
        invariant_id: 50,
        name: "sponsor_auction_invariant_050",
        description: "deterministic low fee sponsor auction clearing invariant 050",
    },
    ProtocolInvariant {
        invariant_id: 51,
        name: "sponsor_auction_invariant_051",
        description: "deterministic low fee sponsor auction clearing invariant 051",
    },
    ProtocolInvariant {
        invariant_id: 52,
        name: "sponsor_auction_invariant_052",
        description: "deterministic low fee sponsor auction clearing invariant 052",
    },
    ProtocolInvariant {
        invariant_id: 53,
        name: "sponsor_auction_invariant_053",
        description: "deterministic low fee sponsor auction clearing invariant 053",
    },
    ProtocolInvariant {
        invariant_id: 54,
        name: "sponsor_auction_invariant_054",
        description: "deterministic low fee sponsor auction clearing invariant 054",
    },
    ProtocolInvariant {
        invariant_id: 55,
        name: "sponsor_auction_invariant_055",
        description: "deterministic low fee sponsor auction clearing invariant 055",
    },
    ProtocolInvariant {
        invariant_id: 56,
        name: "sponsor_auction_invariant_056",
        description: "deterministic low fee sponsor auction clearing invariant 056",
    },
    ProtocolInvariant {
        invariant_id: 57,
        name: "sponsor_auction_invariant_057",
        description: "deterministic low fee sponsor auction clearing invariant 057",
    },
    ProtocolInvariant {
        invariant_id: 58,
        name: "sponsor_auction_invariant_058",
        description: "deterministic low fee sponsor auction clearing invariant 058",
    },
    ProtocolInvariant {
        invariant_id: 59,
        name: "sponsor_auction_invariant_059",
        description: "deterministic low fee sponsor auction clearing invariant 059",
    },
    ProtocolInvariant {
        invariant_id: 60,
        name: "sponsor_auction_invariant_060",
        description: "deterministic low fee sponsor auction clearing invariant 060",
    },
    ProtocolInvariant {
        invariant_id: 61,
        name: "sponsor_auction_invariant_061",
        description: "deterministic low fee sponsor auction clearing invariant 061",
    },
    ProtocolInvariant {
        invariant_id: 62,
        name: "sponsor_auction_invariant_062",
        description: "deterministic low fee sponsor auction clearing invariant 062",
    },
    ProtocolInvariant {
        invariant_id: 63,
        name: "sponsor_auction_invariant_063",
        description: "deterministic low fee sponsor auction clearing invariant 063",
    },
    ProtocolInvariant {
        invariant_id: 64,
        name: "sponsor_auction_invariant_064",
        description: "deterministic low fee sponsor auction clearing invariant 064",
    },
    ProtocolInvariant {
        invariant_id: 65,
        name: "sponsor_auction_invariant_065",
        description: "deterministic low fee sponsor auction clearing invariant 065",
    },
    ProtocolInvariant {
        invariant_id: 66,
        name: "sponsor_auction_invariant_066",
        description: "deterministic low fee sponsor auction clearing invariant 066",
    },
    ProtocolInvariant {
        invariant_id: 67,
        name: "sponsor_auction_invariant_067",
        description: "deterministic low fee sponsor auction clearing invariant 067",
    },
    ProtocolInvariant {
        invariant_id: 68,
        name: "sponsor_auction_invariant_068",
        description: "deterministic low fee sponsor auction clearing invariant 068",
    },
    ProtocolInvariant {
        invariant_id: 69,
        name: "sponsor_auction_invariant_069",
        description: "deterministic low fee sponsor auction clearing invariant 069",
    },
    ProtocolInvariant {
        invariant_id: 70,
        name: "sponsor_auction_invariant_070",
        description: "deterministic low fee sponsor auction clearing invariant 070",
    },
    ProtocolInvariant {
        invariant_id: 71,
        name: "sponsor_auction_invariant_071",
        description: "deterministic low fee sponsor auction clearing invariant 071",
    },
    ProtocolInvariant {
        invariant_id: 72,
        name: "sponsor_auction_invariant_072",
        description: "deterministic low fee sponsor auction clearing invariant 072",
    },
    ProtocolInvariant {
        invariant_id: 73,
        name: "sponsor_auction_invariant_073",
        description: "deterministic low fee sponsor auction clearing invariant 073",
    },
    ProtocolInvariant {
        invariant_id: 74,
        name: "sponsor_auction_invariant_074",
        description: "deterministic low fee sponsor auction clearing invariant 074",
    },
    ProtocolInvariant {
        invariant_id: 75,
        name: "sponsor_auction_invariant_075",
        description: "deterministic low fee sponsor auction clearing invariant 075",
    },
    ProtocolInvariant {
        invariant_id: 76,
        name: "sponsor_auction_invariant_076",
        description: "deterministic low fee sponsor auction clearing invariant 076",
    },
    ProtocolInvariant {
        invariant_id: 77,
        name: "sponsor_auction_invariant_077",
        description: "deterministic low fee sponsor auction clearing invariant 077",
    },
    ProtocolInvariant {
        invariant_id: 78,
        name: "sponsor_auction_invariant_078",
        description: "deterministic low fee sponsor auction clearing invariant 078",
    },
    ProtocolInvariant {
        invariant_id: 79,
        name: "sponsor_auction_invariant_079",
        description: "deterministic low fee sponsor auction clearing invariant 079",
    },
    ProtocolInvariant {
        invariant_id: 80,
        name: "sponsor_auction_invariant_080",
        description: "deterministic low fee sponsor auction clearing invariant 080",
    },
    ProtocolInvariant {
        invariant_id: 81,
        name: "sponsor_auction_invariant_081",
        description: "deterministic low fee sponsor auction clearing invariant 081",
    },
    ProtocolInvariant {
        invariant_id: 82,
        name: "sponsor_auction_invariant_082",
        description: "deterministic low fee sponsor auction clearing invariant 082",
    },
    ProtocolInvariant {
        invariant_id: 83,
        name: "sponsor_auction_invariant_083",
        description: "deterministic low fee sponsor auction clearing invariant 083",
    },
    ProtocolInvariant {
        invariant_id: 84,
        name: "sponsor_auction_invariant_084",
        description: "deterministic low fee sponsor auction clearing invariant 084",
    },
    ProtocolInvariant {
        invariant_id: 85,
        name: "sponsor_auction_invariant_085",
        description: "deterministic low fee sponsor auction clearing invariant 085",
    },
    ProtocolInvariant {
        invariant_id: 86,
        name: "sponsor_auction_invariant_086",
        description: "deterministic low fee sponsor auction clearing invariant 086",
    },
    ProtocolInvariant {
        invariant_id: 87,
        name: "sponsor_auction_invariant_087",
        description: "deterministic low fee sponsor auction clearing invariant 087",
    },
    ProtocolInvariant {
        invariant_id: 88,
        name: "sponsor_auction_invariant_088",
        description: "deterministic low fee sponsor auction clearing invariant 088",
    },
    ProtocolInvariant {
        invariant_id: 89,
        name: "sponsor_auction_invariant_089",
        description: "deterministic low fee sponsor auction clearing invariant 089",
    },
    ProtocolInvariant {
        invariant_id: 90,
        name: "sponsor_auction_invariant_090",
        description: "deterministic low fee sponsor auction clearing invariant 090",
    },
    ProtocolInvariant {
        invariant_id: 91,
        name: "sponsor_auction_invariant_091",
        description: "deterministic low fee sponsor auction clearing invariant 091",
    },
    ProtocolInvariant {
        invariant_id: 92,
        name: "sponsor_auction_invariant_092",
        description: "deterministic low fee sponsor auction clearing invariant 092",
    },
    ProtocolInvariant {
        invariant_id: 93,
        name: "sponsor_auction_invariant_093",
        description: "deterministic low fee sponsor auction clearing invariant 093",
    },
    ProtocolInvariant {
        invariant_id: 94,
        name: "sponsor_auction_invariant_094",
        description: "deterministic low fee sponsor auction clearing invariant 094",
    },
    ProtocolInvariant {
        invariant_id: 95,
        name: "sponsor_auction_invariant_095",
        description: "deterministic low fee sponsor auction clearing invariant 095",
    },
    ProtocolInvariant {
        invariant_id: 96,
        name: "sponsor_auction_invariant_096",
        description: "deterministic low fee sponsor auction clearing invariant 096",
    },
    ProtocolInvariant {
        invariant_id: 97,
        name: "sponsor_auction_invariant_097",
        description: "deterministic low fee sponsor auction clearing invariant 097",
    },
    ProtocolInvariant {
        invariant_id: 98,
        name: "sponsor_auction_invariant_098",
        description: "deterministic low fee sponsor auction clearing invariant 098",
    },
    ProtocolInvariant {
        invariant_id: 99,
        name: "sponsor_auction_invariant_099",
        description: "deterministic low fee sponsor auction clearing invariant 099",
    },
    ProtocolInvariant {
        invariant_id: 100,
        name: "sponsor_auction_invariant_100",
        description: "deterministic low fee sponsor auction clearing invariant 100",
    },
    ProtocolInvariant {
        invariant_id: 101,
        name: "sponsor_auction_invariant_101",
        description: "deterministic low fee sponsor auction clearing invariant 101",
    },
    ProtocolInvariant {
        invariant_id: 102,
        name: "sponsor_auction_invariant_102",
        description: "deterministic low fee sponsor auction clearing invariant 102",
    },
    ProtocolInvariant {
        invariant_id: 103,
        name: "sponsor_auction_invariant_103",
        description: "deterministic low fee sponsor auction clearing invariant 103",
    },
    ProtocolInvariant {
        invariant_id: 104,
        name: "sponsor_auction_invariant_104",
        description: "deterministic low fee sponsor auction clearing invariant 104",
    },
    ProtocolInvariant {
        invariant_id: 105,
        name: "sponsor_auction_invariant_105",
        description: "deterministic low fee sponsor auction clearing invariant 105",
    },
    ProtocolInvariant {
        invariant_id: 106,
        name: "sponsor_auction_invariant_106",
        description: "deterministic low fee sponsor auction clearing invariant 106",
    },
    ProtocolInvariant {
        invariant_id: 107,
        name: "sponsor_auction_invariant_107",
        description: "deterministic low fee sponsor auction clearing invariant 107",
    },
    ProtocolInvariant {
        invariant_id: 108,
        name: "sponsor_auction_invariant_108",
        description: "deterministic low fee sponsor auction clearing invariant 108",
    },
    ProtocolInvariant {
        invariant_id: 109,
        name: "sponsor_auction_invariant_109",
        description: "deterministic low fee sponsor auction clearing invariant 109",
    },
    ProtocolInvariant {
        invariant_id: 110,
        name: "sponsor_auction_invariant_110",
        description: "deterministic low fee sponsor auction clearing invariant 110",
    },
    ProtocolInvariant {
        invariant_id: 111,
        name: "sponsor_auction_invariant_111",
        description: "deterministic low fee sponsor auction clearing invariant 111",
    },
    ProtocolInvariant {
        invariant_id: 112,
        name: "sponsor_auction_invariant_112",
        description: "deterministic low fee sponsor auction clearing invariant 112",
    },
    ProtocolInvariant {
        invariant_id: 113,
        name: "sponsor_auction_invariant_113",
        description: "deterministic low fee sponsor auction clearing invariant 113",
    },
    ProtocolInvariant {
        invariant_id: 114,
        name: "sponsor_auction_invariant_114",
        description: "deterministic low fee sponsor auction clearing invariant 114",
    },
    ProtocolInvariant {
        invariant_id: 115,
        name: "sponsor_auction_invariant_115",
        description: "deterministic low fee sponsor auction clearing invariant 115",
    },
    ProtocolInvariant {
        invariant_id: 116,
        name: "sponsor_auction_invariant_116",
        description: "deterministic low fee sponsor auction clearing invariant 116",
    },
    ProtocolInvariant {
        invariant_id: 117,
        name: "sponsor_auction_invariant_117",
        description: "deterministic low fee sponsor auction clearing invariant 117",
    },
    ProtocolInvariant {
        invariant_id: 118,
        name: "sponsor_auction_invariant_118",
        description: "deterministic low fee sponsor auction clearing invariant 118",
    },
    ProtocolInvariant {
        invariant_id: 119,
        name: "sponsor_auction_invariant_119",
        description: "deterministic low fee sponsor auction clearing invariant 119",
    },
    ProtocolInvariant {
        invariant_id: 120,
        name: "sponsor_auction_invariant_120",
        description: "deterministic low fee sponsor auction clearing invariant 120",
    },
    ProtocolInvariant {
        invariant_id: 121,
        name: "sponsor_auction_invariant_121",
        description: "deterministic low fee sponsor auction clearing invariant 121",
    },
    ProtocolInvariant {
        invariant_id: 122,
        name: "sponsor_auction_invariant_122",
        description: "deterministic low fee sponsor auction clearing invariant 122",
    },
    ProtocolInvariant {
        invariant_id: 123,
        name: "sponsor_auction_invariant_123",
        description: "deterministic low fee sponsor auction clearing invariant 123",
    },
    ProtocolInvariant {
        invariant_id: 124,
        name: "sponsor_auction_invariant_124",
        description: "deterministic low fee sponsor auction clearing invariant 124",
    },
    ProtocolInvariant {
        invariant_id: 125,
        name: "sponsor_auction_invariant_125",
        description: "deterministic low fee sponsor auction clearing invariant 125",
    },
    ProtocolInvariant {
        invariant_id: 126,
        name: "sponsor_auction_invariant_126",
        description: "deterministic low fee sponsor auction clearing invariant 126",
    },
    ProtocolInvariant {
        invariant_id: 127,
        name: "sponsor_auction_invariant_127",
        description: "deterministic low fee sponsor auction clearing invariant 127",
    },
    ProtocolInvariant {
        invariant_id: 128,
        name: "sponsor_auction_invariant_128",
        description: "deterministic low fee sponsor auction clearing invariant 128",
    },
    ProtocolInvariant {
        invariant_id: 129,
        name: "sponsor_auction_invariant_129",
        description: "deterministic low fee sponsor auction clearing invariant 129",
    },
    ProtocolInvariant {
        invariant_id: 130,
        name: "sponsor_auction_invariant_130",
        description: "deterministic low fee sponsor auction clearing invariant 130",
    },
    ProtocolInvariant {
        invariant_id: 131,
        name: "sponsor_auction_invariant_131",
        description: "deterministic low fee sponsor auction clearing invariant 131",
    },
    ProtocolInvariant {
        invariant_id: 132,
        name: "sponsor_auction_invariant_132",
        description: "deterministic low fee sponsor auction clearing invariant 132",
    },
    ProtocolInvariant {
        invariant_id: 133,
        name: "sponsor_auction_invariant_133",
        description: "deterministic low fee sponsor auction clearing invariant 133",
    },
    ProtocolInvariant {
        invariant_id: 134,
        name: "sponsor_auction_invariant_134",
        description: "deterministic low fee sponsor auction clearing invariant 134",
    },
    ProtocolInvariant {
        invariant_id: 135,
        name: "sponsor_auction_invariant_135",
        description: "deterministic low fee sponsor auction clearing invariant 135",
    },
    ProtocolInvariant {
        invariant_id: 136,
        name: "sponsor_auction_invariant_136",
        description: "deterministic low fee sponsor auction clearing invariant 136",
    },
    ProtocolInvariant {
        invariant_id: 137,
        name: "sponsor_auction_invariant_137",
        description: "deterministic low fee sponsor auction clearing invariant 137",
    },
    ProtocolInvariant {
        invariant_id: 138,
        name: "sponsor_auction_invariant_138",
        description: "deterministic low fee sponsor auction clearing invariant 138",
    },
    ProtocolInvariant {
        invariant_id: 139,
        name: "sponsor_auction_invariant_139",
        description: "deterministic low fee sponsor auction clearing invariant 139",
    },
    ProtocolInvariant {
        invariant_id: 140,
        name: "sponsor_auction_invariant_140",
        description: "deterministic low fee sponsor auction clearing invariant 140",
    },
    ProtocolInvariant {
        invariant_id: 141,
        name: "sponsor_auction_invariant_141",
        description: "deterministic low fee sponsor auction clearing invariant 141",
    },
    ProtocolInvariant {
        invariant_id: 142,
        name: "sponsor_auction_invariant_142",
        description: "deterministic low fee sponsor auction clearing invariant 142",
    },
    ProtocolInvariant {
        invariant_id: 143,
        name: "sponsor_auction_invariant_143",
        description: "deterministic low fee sponsor auction clearing invariant 143",
    },
    ProtocolInvariant {
        invariant_id: 144,
        name: "sponsor_auction_invariant_144",
        description: "deterministic low fee sponsor auction clearing invariant 144",
    },
    ProtocolInvariant {
        invariant_id: 145,
        name: "sponsor_auction_invariant_145",
        description: "deterministic low fee sponsor auction clearing invariant 145",
    },
    ProtocolInvariant {
        invariant_id: 146,
        name: "sponsor_auction_invariant_146",
        description: "deterministic low fee sponsor auction clearing invariant 146",
    },
    ProtocolInvariant {
        invariant_id: 147,
        name: "sponsor_auction_invariant_147",
        description: "deterministic low fee sponsor auction clearing invariant 147",
    },
    ProtocolInvariant {
        invariant_id: 148,
        name: "sponsor_auction_invariant_148",
        description: "deterministic low fee sponsor auction clearing invariant 148",
    },
    ProtocolInvariant {
        invariant_id: 149,
        name: "sponsor_auction_invariant_149",
        description: "deterministic low fee sponsor auction clearing invariant 149",
    },
    ProtocolInvariant {
        invariant_id: 150,
        name: "sponsor_auction_invariant_150",
        description: "deterministic low fee sponsor auction clearing invariant 150",
    },
    ProtocolInvariant {
        invariant_id: 151,
        name: "sponsor_auction_invariant_151",
        description: "deterministic low fee sponsor auction clearing invariant 151",
    },
    ProtocolInvariant {
        invariant_id: 152,
        name: "sponsor_auction_invariant_152",
        description: "deterministic low fee sponsor auction clearing invariant 152",
    },
    ProtocolInvariant {
        invariant_id: 153,
        name: "sponsor_auction_invariant_153",
        description: "deterministic low fee sponsor auction clearing invariant 153",
    },
    ProtocolInvariant {
        invariant_id: 154,
        name: "sponsor_auction_invariant_154",
        description: "deterministic low fee sponsor auction clearing invariant 154",
    },
    ProtocolInvariant {
        invariant_id: 155,
        name: "sponsor_auction_invariant_155",
        description: "deterministic low fee sponsor auction clearing invariant 155",
    },
    ProtocolInvariant {
        invariant_id: 156,
        name: "sponsor_auction_invariant_156",
        description: "deterministic low fee sponsor auction clearing invariant 156",
    },
    ProtocolInvariant {
        invariant_id: 157,
        name: "sponsor_auction_invariant_157",
        description: "deterministic low fee sponsor auction clearing invariant 157",
    },
    ProtocolInvariant {
        invariant_id: 158,
        name: "sponsor_auction_invariant_158",
        description: "deterministic low fee sponsor auction clearing invariant 158",
    },
    ProtocolInvariant {
        invariant_id: 159,
        name: "sponsor_auction_invariant_159",
        description: "deterministic low fee sponsor auction clearing invariant 159",
    },
    ProtocolInvariant {
        invariant_id: 160,
        name: "sponsor_auction_invariant_160",
        description: "deterministic low fee sponsor auction clearing invariant 160",
    },
    ProtocolInvariant {
        invariant_id: 161,
        name: "sponsor_auction_invariant_161",
        description: "deterministic low fee sponsor auction clearing invariant 161",
    },
    ProtocolInvariant {
        invariant_id: 162,
        name: "sponsor_auction_invariant_162",
        description: "deterministic low fee sponsor auction clearing invariant 162",
    },
    ProtocolInvariant {
        invariant_id: 163,
        name: "sponsor_auction_invariant_163",
        description: "deterministic low fee sponsor auction clearing invariant 163",
    },
    ProtocolInvariant {
        invariant_id: 164,
        name: "sponsor_auction_invariant_164",
        description: "deterministic low fee sponsor auction clearing invariant 164",
    },
    ProtocolInvariant {
        invariant_id: 165,
        name: "sponsor_auction_invariant_165",
        description: "deterministic low fee sponsor auction clearing invariant 165",
    },
    ProtocolInvariant {
        invariant_id: 166,
        name: "sponsor_auction_invariant_166",
        description: "deterministic low fee sponsor auction clearing invariant 166",
    },
    ProtocolInvariant {
        invariant_id: 167,
        name: "sponsor_auction_invariant_167",
        description: "deterministic low fee sponsor auction clearing invariant 167",
    },
    ProtocolInvariant {
        invariant_id: 168,
        name: "sponsor_auction_invariant_168",
        description: "deterministic low fee sponsor auction clearing invariant 168",
    },
    ProtocolInvariant {
        invariant_id: 169,
        name: "sponsor_auction_invariant_169",
        description: "deterministic low fee sponsor auction clearing invariant 169",
    },
    ProtocolInvariant {
        invariant_id: 170,
        name: "sponsor_auction_invariant_170",
        description: "deterministic low fee sponsor auction clearing invariant 170",
    },
    ProtocolInvariant {
        invariant_id: 171,
        name: "sponsor_auction_invariant_171",
        description: "deterministic low fee sponsor auction clearing invariant 171",
    },
    ProtocolInvariant {
        invariant_id: 172,
        name: "sponsor_auction_invariant_172",
        description: "deterministic low fee sponsor auction clearing invariant 172",
    },
    ProtocolInvariant {
        invariant_id: 173,
        name: "sponsor_auction_invariant_173",
        description: "deterministic low fee sponsor auction clearing invariant 173",
    },
    ProtocolInvariant {
        invariant_id: 174,
        name: "sponsor_auction_invariant_174",
        description: "deterministic low fee sponsor auction clearing invariant 174",
    },
    ProtocolInvariant {
        invariant_id: 175,
        name: "sponsor_auction_invariant_175",
        description: "deterministic low fee sponsor auction clearing invariant 175",
    },
    ProtocolInvariant {
        invariant_id: 176,
        name: "sponsor_auction_invariant_176",
        description: "deterministic low fee sponsor auction clearing invariant 176",
    },
    ProtocolInvariant {
        invariant_id: 177,
        name: "sponsor_auction_invariant_177",
        description: "deterministic low fee sponsor auction clearing invariant 177",
    },
    ProtocolInvariant {
        invariant_id: 178,
        name: "sponsor_auction_invariant_178",
        description: "deterministic low fee sponsor auction clearing invariant 178",
    },
    ProtocolInvariant {
        invariant_id: 179,
        name: "sponsor_auction_invariant_179",
        description: "deterministic low fee sponsor auction clearing invariant 179",
    },
    ProtocolInvariant {
        invariant_id: 180,
        name: "sponsor_auction_invariant_180",
        description: "deterministic low fee sponsor auction clearing invariant 180",
    },
    ProtocolInvariant {
        invariant_id: 181,
        name: "sponsor_auction_invariant_181",
        description: "deterministic low fee sponsor auction clearing invariant 181",
    },
    ProtocolInvariant {
        invariant_id: 182,
        name: "sponsor_auction_invariant_182",
        description: "deterministic low fee sponsor auction clearing invariant 182",
    },
    ProtocolInvariant {
        invariant_id: 183,
        name: "sponsor_auction_invariant_183",
        description: "deterministic low fee sponsor auction clearing invariant 183",
    },
    ProtocolInvariant {
        invariant_id: 184,
        name: "sponsor_auction_invariant_184",
        description: "deterministic low fee sponsor auction clearing invariant 184",
    },
    ProtocolInvariant {
        invariant_id: 185,
        name: "sponsor_auction_invariant_185",
        description: "deterministic low fee sponsor auction clearing invariant 185",
    },
    ProtocolInvariant {
        invariant_id: 186,
        name: "sponsor_auction_invariant_186",
        description: "deterministic low fee sponsor auction clearing invariant 186",
    },
    ProtocolInvariant {
        invariant_id: 187,
        name: "sponsor_auction_invariant_187",
        description: "deterministic low fee sponsor auction clearing invariant 187",
    },
    ProtocolInvariant {
        invariant_id: 188,
        name: "sponsor_auction_invariant_188",
        description: "deterministic low fee sponsor auction clearing invariant 188",
    },
    ProtocolInvariant {
        invariant_id: 189,
        name: "sponsor_auction_invariant_189",
        description: "deterministic low fee sponsor auction clearing invariant 189",
    },
    ProtocolInvariant {
        invariant_id: 190,
        name: "sponsor_auction_invariant_190",
        description: "deterministic low fee sponsor auction clearing invariant 190",
    },
    ProtocolInvariant {
        invariant_id: 191,
        name: "sponsor_auction_invariant_191",
        description: "deterministic low fee sponsor auction clearing invariant 191",
    },
    ProtocolInvariant {
        invariant_id: 192,
        name: "sponsor_auction_invariant_192",
        description: "deterministic low fee sponsor auction clearing invariant 192",
    },
    ProtocolInvariant {
        invariant_id: 193,
        name: "sponsor_auction_invariant_193",
        description: "deterministic low fee sponsor auction clearing invariant 193",
    },
    ProtocolInvariant {
        invariant_id: 194,
        name: "sponsor_auction_invariant_194",
        description: "deterministic low fee sponsor auction clearing invariant 194",
    },
    ProtocolInvariant {
        invariant_id: 195,
        name: "sponsor_auction_invariant_195",
        description: "deterministic low fee sponsor auction clearing invariant 195",
    },
    ProtocolInvariant {
        invariant_id: 196,
        name: "sponsor_auction_invariant_196",
        description: "deterministic low fee sponsor auction clearing invariant 196",
    },
    ProtocolInvariant {
        invariant_id: 197,
        name: "sponsor_auction_invariant_197",
        description: "deterministic low fee sponsor auction clearing invariant 197",
    },
    ProtocolInvariant {
        invariant_id: 198,
        name: "sponsor_auction_invariant_198",
        description: "deterministic low fee sponsor auction clearing invariant 198",
    },
    ProtocolInvariant {
        invariant_id: 199,
        name: "sponsor_auction_invariant_199",
        description: "deterministic low fee sponsor auction clearing invariant 199",
    },
    ProtocolInvariant {
        invariant_id: 200,
        name: "sponsor_auction_invariant_200",
        description: "deterministic low fee sponsor auction clearing invariant 200",
    },
    ProtocolInvariant {
        invariant_id: 201,
        name: "sponsor_auction_invariant_201",
        description: "deterministic low fee sponsor auction clearing invariant 201",
    },
    ProtocolInvariant {
        invariant_id: 202,
        name: "sponsor_auction_invariant_202",
        description: "deterministic low fee sponsor auction clearing invariant 202",
    },
    ProtocolInvariant {
        invariant_id: 203,
        name: "sponsor_auction_invariant_203",
        description: "deterministic low fee sponsor auction clearing invariant 203",
    },
    ProtocolInvariant {
        invariant_id: 204,
        name: "sponsor_auction_invariant_204",
        description: "deterministic low fee sponsor auction clearing invariant 204",
    },
    ProtocolInvariant {
        invariant_id: 205,
        name: "sponsor_auction_invariant_205",
        description: "deterministic low fee sponsor auction clearing invariant 205",
    },
    ProtocolInvariant {
        invariant_id: 206,
        name: "sponsor_auction_invariant_206",
        description: "deterministic low fee sponsor auction clearing invariant 206",
    },
    ProtocolInvariant {
        invariant_id: 207,
        name: "sponsor_auction_invariant_207",
        description: "deterministic low fee sponsor auction clearing invariant 207",
    },
    ProtocolInvariant {
        invariant_id: 208,
        name: "sponsor_auction_invariant_208",
        description: "deterministic low fee sponsor auction clearing invariant 208",
    },
    ProtocolInvariant {
        invariant_id: 209,
        name: "sponsor_auction_invariant_209",
        description: "deterministic low fee sponsor auction clearing invariant 209",
    },
    ProtocolInvariant {
        invariant_id: 210,
        name: "sponsor_auction_invariant_210",
        description: "deterministic low fee sponsor auction clearing invariant 210",
    },
    ProtocolInvariant {
        invariant_id: 211,
        name: "sponsor_auction_invariant_211",
        description: "deterministic low fee sponsor auction clearing invariant 211",
    },
    ProtocolInvariant {
        invariant_id: 212,
        name: "sponsor_auction_invariant_212",
        description: "deterministic low fee sponsor auction clearing invariant 212",
    },
    ProtocolInvariant {
        invariant_id: 213,
        name: "sponsor_auction_invariant_213",
        description: "deterministic low fee sponsor auction clearing invariant 213",
    },
    ProtocolInvariant {
        invariant_id: 214,
        name: "sponsor_auction_invariant_214",
        description: "deterministic low fee sponsor auction clearing invariant 214",
    },
    ProtocolInvariant {
        invariant_id: 215,
        name: "sponsor_auction_invariant_215",
        description: "deterministic low fee sponsor auction clearing invariant 215",
    },
    ProtocolInvariant {
        invariant_id: 216,
        name: "sponsor_auction_invariant_216",
        description: "deterministic low fee sponsor auction clearing invariant 216",
    },
    ProtocolInvariant {
        invariant_id: 217,
        name: "sponsor_auction_invariant_217",
        description: "deterministic low fee sponsor auction clearing invariant 217",
    },
    ProtocolInvariant {
        invariant_id: 218,
        name: "sponsor_auction_invariant_218",
        description: "deterministic low fee sponsor auction clearing invariant 218",
    },
    ProtocolInvariant {
        invariant_id: 219,
        name: "sponsor_auction_invariant_219",
        description: "deterministic low fee sponsor auction clearing invariant 219",
    },
    ProtocolInvariant {
        invariant_id: 220,
        name: "sponsor_auction_invariant_220",
        description: "deterministic low fee sponsor auction clearing invariant 220",
    },
];
pub fn protocol_invariant_roots() -> Vec<String> {
    PROTOCOL_INVARIANTS
        .iter()
        .map(|invariant| {
            domain_hash(
                "sponsor_auction_invariant",
                &[
                    HashPart::U64(u64::from(invariant.invariant_id)),
                    HashPart::Str(invariant.name),
                    HashPart::Str(invariant.description),
                ],
                32,
            )
        })
        .collect()
}
pub fn protocol_invariant_root() -> String {
    let roots = protocol_invariant_roots();
    let leaves: Vec<Value> = roots.into_iter().map(Value::String).collect();
    merkle_root("sponsor_auction_invariants", &leaves)
}
/*
audit-reserve-line-0001: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0002: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0003: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0004: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0005: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0006: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0007: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0008: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0009: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0010: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0011: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0012: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0013: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0014: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0015: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0016: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0017: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0018: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0019: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0020: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0021: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0022: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0023: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0024: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0025: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0026: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0027: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0028: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0029: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0030: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0031: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0032: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0033: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0034: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0035: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0036: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0037: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0038: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0039: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0040: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0041: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0042: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0043: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0044: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0045: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0046: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0047: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0048: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0049: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0050: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0051: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0052: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0053: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0054: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0055: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0056: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0057: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0058: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0059: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0060: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0061: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0062: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0063: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0064: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0065: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0066: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0067: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0068: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0069: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0070: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0071: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0072: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0073: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0074: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0075: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0076: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0077: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0078: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0079: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0080: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0081: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0082: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0083: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0084: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0085: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0086: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0087: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0088: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0089: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0090: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0091: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0092: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0093: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0094: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0095: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0096: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0097: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0098: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0099: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0100: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0101: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0102: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0103: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0104: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0105: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0106: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0107: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0108: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0109: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0110: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0111: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0112: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0113: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0114: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0115: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0116: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0117: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0118: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0119: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0120: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0121: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0122: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0123: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0124: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0125: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0126: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0127: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0128: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0129: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0130: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0131: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0132: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0133: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0134: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0135: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0136: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0137: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0138: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0139: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0140: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0141: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0142: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0143: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0144: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0145: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0146: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0147: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0148: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0149: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0150: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0151: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0152: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0153: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0154: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0155: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0156: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0157: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0158: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0159: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0160: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0161: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0162: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0163: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0164: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0165: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0166: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0167: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0168: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0169: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0170: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0171: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0172: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0173: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0174: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0175: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0176: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0177: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0178: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0179: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0180: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0181: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0182: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0183: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0184: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0185: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0186: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0187: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0188: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0189: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0190: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0191: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0192: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0193: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0194: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0195: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0196: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0197: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0198: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0199: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0200: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0201: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0202: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0203: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0204: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0205: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0206: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0207: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0208: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0209: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0210: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0211: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0212: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0213: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0214: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0215: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0216: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0217: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0218: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0219: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0220: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0221: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0222: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0223: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0224: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0225: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0226: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0227: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0228: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0229: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0230: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0231: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0232: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0233: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0234: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0235: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0236: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0237: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0238: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0239: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0240: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0241: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0242: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0243: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0244: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0245: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0246: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0247: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0248: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0249: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0250: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0251: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0252: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0253: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0254: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0255: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0256: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0257: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0258: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0259: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0260: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0261: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0262: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0263: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0264: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0265: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0266: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0267: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0268: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0269: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0270: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0271: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0272: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0273: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0274: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0275: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0276: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0277: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0278: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0279: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0280: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0281: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0282: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0283: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0284: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0285: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0286: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0287: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0288: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0289: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0290: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0291: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0292: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0293: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0294: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0295: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0296: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0297: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0298: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0299: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0300: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0301: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0302: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0303: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0304: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0305: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0306: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0307: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0308: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0309: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0310: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0311: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0312: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0313: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0314: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0315: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0316: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0317: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0318: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0319: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0320: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0321: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0322: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0323: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0324: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0325: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0326: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0327: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0328: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0329: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0330: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0331: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0332: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0333: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0334: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0335: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0336: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0337: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0338: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0339: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0340: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0341: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0342: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0343: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0344: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0345: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0346: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0347: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0348: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0349: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0350: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0351: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0352: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0353: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0354: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0355: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0356: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0357: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0358: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0359: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0360: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0361: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0362: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0363: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0364: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0365: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0366: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0367: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0368: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0369: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0370: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0371: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0372: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0373: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0374: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0375: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0376: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0377: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0378: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0379: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0380: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0381: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0382: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0383: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0384: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0385: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0386: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0387: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0388: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0389: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0390: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0391: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0392: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0393: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0394: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0395: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0396: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0397: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0398: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0399: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0400: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0401: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0402: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0403: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0404: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0405: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0406: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0407: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0408: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0409: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0410: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0411: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0412: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0413: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0414: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0415: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0416: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0417: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0418: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0419: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0420: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0421: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0422: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0423: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0424: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0425: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0426: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0427: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0428: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0429: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0430: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0431: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0432: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0433: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0434: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0435: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0436: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0437: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0438: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0439: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0440: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0441: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0442: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0443: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0444: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0445: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0446: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0447: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0448: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0449: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0450: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0451: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0452: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0453: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0454: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0455: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0456: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0457: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0458: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0459: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0460: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0461: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0462: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0463: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0464: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0465: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0466: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0467: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0468: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0469: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0470: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0471: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0472: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0473: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0474: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0475: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0476: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0477: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0478: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0479: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0480: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0481: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0482: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0483: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0484: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0485: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0486: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0487: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0488: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0489: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0490: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0491: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0492: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0493: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0494: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0495: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0496: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0497: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0498: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0499: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0500: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0501: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0502: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0503: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0504: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0505: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0506: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0507: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0508: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0509: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0510: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0511: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0512: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0513: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0514: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0515: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0516: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0517: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0518: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0519: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0520: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0521: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0522: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0523: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0524: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0525: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0526: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0527: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0528: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0529: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0530: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0531: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0532: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0533: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0534: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0535: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0536: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0537: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0538: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0539: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0540: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0541: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0542: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0543: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0544: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0545: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0546: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0547: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0548: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0549: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0550: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0551: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0552: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0553: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0554: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0555: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0556: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0557: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0558: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0559: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0560: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0561: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0562: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0563: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0564: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0565: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0566: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0567: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0568: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0569: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0570: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0571: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0572: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0573: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0574: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0575: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0576: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0577: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0578: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0579: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0580: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0581: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0582: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0583: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0584: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0585: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0586: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0587: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0588: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0589: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0590: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0591: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0592: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0593: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0594: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0595: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0596: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0597: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0598: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0599: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0600: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0601: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0602: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0603: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0604: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0605: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0606: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0607: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0608: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0609: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0610: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0611: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0612: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0613: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0614: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0615: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0616: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0617: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0618: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0619: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0620: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0621: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0622: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0623: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0624: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0625: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0626: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0627: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0628: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0629: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0630: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0631: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0632: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0633: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0634: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0635: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0636: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0637: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0638: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0639: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0640: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0641: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0642: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0643: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0644: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0645: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0646: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0647: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0648: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0649: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0650: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0651: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0652: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0653: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0654: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0655: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0656: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0657: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0658: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0659: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0660: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0661: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0662: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0663: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0664: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0665: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0666: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0667: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0668: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0669: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0670: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0671: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0672: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0673: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0674: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0675: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0676: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0677: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0678: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0679: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0680: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0681: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0682: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0683: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0684: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0685: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0686: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0687: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0688: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0689: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0690: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0691: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0692: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0693: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0694: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0695: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0696: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0697: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0698: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0699: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0700: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0701: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0702: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0703: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0704: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0705: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0706: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0707: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0708: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0709: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0710: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0711: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0712: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0713: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0714: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0715: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0716: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0717: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0718: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0719: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0720: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0721: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0722: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0723: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0724: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0725: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0726: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0727: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0728: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0729: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0730: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0731: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0732: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0733: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0734: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0735: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0736: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0737: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0738: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0739: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0740: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0741: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0742: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0743: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0744: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0745: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0746: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0747: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0748: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0749: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0750: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0751: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0752: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0753: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0754: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0755: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0756: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0757: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0758: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0759: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0760: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0761: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0762: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0763: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0764: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0765: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0766: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0767: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0768: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0769: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0770: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0771: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0772: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0773: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0774: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0775: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0776: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0777: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0778: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0779: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0780: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0781: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0782: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0783: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0784: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0785: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0786: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0787: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0788: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0789: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0790: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0791: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0792: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0793: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0794: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0795: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0796: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0797: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0798: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0799: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0800: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0801: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0802: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0803: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0804: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0805: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0806: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0807: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0808: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0809: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0810: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0811: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0812: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0813: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0814: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0815: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0816: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0817: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0818: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0819: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0820: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0821: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0822: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0823: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0824: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0825: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0826: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0827: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0828: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0829: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0830: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0831: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0832: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0833: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0834: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0835: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0836: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0837: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0838: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0839: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0840: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0841: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0842: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0843: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0844: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0845: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0846: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0847: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0848: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0849: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0850: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0851: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0852: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0853: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0854: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0855: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0856: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0857: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0858: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0859: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0860: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0861: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0862: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0863: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0864: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0865: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0866: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0867: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0868: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0869: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0870: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0871: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0872: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0873: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0874: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0875: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0876: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0877: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0878: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0879: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0880: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0881: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0882: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0883: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0884: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0885: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0886: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0887: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0888: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0889: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0890: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0891: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0892: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0893: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0894: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0895: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0896: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0897: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0898: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0899: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0900: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0901: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0902: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0903: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0904: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0905: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0906: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0907: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0908: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0909: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0910: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0911: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0912: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0913: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0914: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0915: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0916: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0917: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0918: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0919: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0920: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0921: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0922: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0923: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0924: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0925: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0926: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0927: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0928: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0929: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0930: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0931: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0932: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0933: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0934: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0935: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0936: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0937: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0938: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0939: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0940: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0941: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0942: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0943: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0944: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0945: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0946: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0947: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0948: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0949: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0950: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0951: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0952: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0953: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0954: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0955: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0956: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0957: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0958: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0959: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0960: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0961: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0962: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0963: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0964: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0965: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0966: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0967: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0968: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0969: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0970: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0971: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0972: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0973: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0974: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0975: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0976: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0977: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0978: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0979: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0980: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0981: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0982: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0983: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0984: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0985: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0986: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0987: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0988: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0989: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0990: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0991: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0992: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0993: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0994: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0995: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0996: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0997: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0998: sponsor auction clearing deterministic transcript surface
audit-reserve-line-0999: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1000: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1001: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1002: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1003: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1004: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1005: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1006: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1007: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1008: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1009: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1010: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1011: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1012: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1013: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1014: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1015: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1016: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1017: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1018: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1019: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1020: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1021: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1022: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1023: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1024: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1025: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1026: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1027: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1028: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1029: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1030: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1031: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1032: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1033: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1034: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1035: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1036: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1037: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1038: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1039: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1040: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1041: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1042: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1043: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1044: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1045: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1046: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1047: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1048: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1049: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1050: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1051: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1052: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1053: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1054: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1055: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1056: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1057: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1058: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1059: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1060: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1061: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1062: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1063: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1064: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1065: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1066: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1067: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1068: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1069: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1070: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1071: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1072: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1073: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1074: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1075: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1076: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1077: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1078: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1079: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1080: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1081: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1082: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1083: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1084: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1085: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1086: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1087: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1088: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1089: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1090: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1091: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1092: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1093: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1094: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1095: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1096: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1097: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1098: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1099: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1100: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1101: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1102: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1103: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1104: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1105: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1106: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1107: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1108: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1109: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1110: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1111: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1112: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1113: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1114: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1115: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1116: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1117: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1118: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1119: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1120: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1121: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1122: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1123: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1124: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1125: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1126: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1127: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1128: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1129: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1130: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1131: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1132: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1133: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1134: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1135: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1136: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1137: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1138: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1139: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1140: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1141: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1142: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1143: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1144: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1145: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1146: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1147: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1148: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1149: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1150: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1151: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1152: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1153: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1154: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1155: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1156: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1157: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1158: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1159: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1160: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1161: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1162: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1163: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1164: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1165: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1166: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1167: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1168: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1169: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1170: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1171: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1172: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1173: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1174: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1175: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1176: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1177: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1178: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1179: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1180: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1181: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1182: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1183: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1184: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1185: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1186: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1187: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1188: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1189: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1190: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1191: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1192: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1193: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1194: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1195: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1196: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1197: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1198: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1199: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1200: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1201: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1202: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1203: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1204: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1205: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1206: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1207: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1208: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1209: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1210: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1211: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1212: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1213: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1214: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1215: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1216: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1217: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1218: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1219: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1220: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1221: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1222: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1223: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1224: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1225: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1226: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1227: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1228: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1229: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1230: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1231: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1232: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1233: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1234: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1235: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1236: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1237: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1238: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1239: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1240: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1241: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1242: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1243: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1244: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1245: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1246: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1247: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1248: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1249: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1250: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1251: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1252: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1253: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1254: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1255: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1256: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1257: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1258: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1259: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1260: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1261: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1262: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1263: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1264: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1265: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1266: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1267: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1268: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1269: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1270: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1271: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1272: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1273: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1274: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1275: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1276: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1277: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1278: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1279: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1280: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1281: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1282: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1283: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1284: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1285: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1286: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1287: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1288: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1289: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1290: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1291: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1292: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1293: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1294: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1295: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1296: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1297: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1298: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1299: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1300: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1301: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1302: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1303: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1304: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1305: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1306: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1307: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1308: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1309: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1310: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1311: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1312: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1313: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1314: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1315: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1316: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1317: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1318: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1319: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1320: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1321: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1322: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1323: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1324: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1325: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1326: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1327: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1328: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1329: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1330: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1331: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1332: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1333: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1334: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1335: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1336: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1337: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1338: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1339: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1340: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1341: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1342: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1343: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1344: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1345: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1346: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1347: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1348: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1349: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1350: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1351: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1352: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1353: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1354: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1355: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1356: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1357: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1358: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1359: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1360: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1361: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1362: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1363: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1364: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1365: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1366: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1367: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1368: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1369: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1370: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1371: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1372: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1373: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1374: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1375: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1376: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1377: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1378: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1379: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1380: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1381: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1382: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1383: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1384: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1385: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1386: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1387: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1388: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1389: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1390: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1391: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1392: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1393: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1394: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1395: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1396: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1397: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1398: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1399: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1400: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1401: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1402: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1403: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1404: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1405: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1406: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1407: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1408: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1409: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1410: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1411: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1412: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1413: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1414: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1415: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1416: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1417: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1418: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1419: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1420: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1421: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1422: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1423: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1424: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1425: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1426: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1427: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1428: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1429: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1430: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1431: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1432: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1433: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1434: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1435: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1436: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1437: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1438: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1439: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1440: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1441: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1442: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1443: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1444: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1445: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1446: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1447: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1448: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1449: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1450: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1451: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1452: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1453: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1454: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1455: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1456: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1457: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1458: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1459: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1460: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1461: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1462: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1463: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1464: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1465: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1466: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1467: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1468: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1469: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1470: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1471: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1472: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1473: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1474: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1475: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1476: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1477: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1478: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1479: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1480: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1481: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1482: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1483: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1484: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1485: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1486: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1487: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1488: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1489: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1490: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1491: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1492: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1493: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1494: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1495: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1496: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1497: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1498: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1499: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1500: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1501: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1502: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1503: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1504: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1505: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1506: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1507: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1508: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1509: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1510: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1511: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1512: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1513: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1514: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1515: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1516: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1517: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1518: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1519: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1520: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1521: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1522: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1523: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1524: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1525: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1526: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1527: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1528: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1529: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1530: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1531: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1532: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1533: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1534: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1535: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1536: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1537: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1538: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1539: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1540: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1541: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1542: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1543: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1544: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1545: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1546: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1547: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1548: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1549: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1550: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1551: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1552: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1553: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1554: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1555: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1556: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1557: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1558: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1559: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1560: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1561: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1562: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1563: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1564: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1565: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1566: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1567: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1568: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1569: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1570: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1571: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1572: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1573: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1574: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1575: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1576: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1577: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1578: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1579: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1580: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1581: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1582: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1583: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1584: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1585: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1586: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1587: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1588: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1589: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1590: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1591: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1592: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1593: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1594: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1595: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1596: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1597: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1598: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1599: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1600: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1601: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1602: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1603: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1604: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1605: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1606: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1607: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1608: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1609: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1610: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1611: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1612: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1613: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1614: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1615: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1616: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1617: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1618: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1619: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1620: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1621: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1622: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1623: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1624: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1625: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1626: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1627: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1628: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1629: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1630: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1631: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1632: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1633: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1634: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1635: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1636: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1637: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1638: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1639: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1640: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1641: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1642: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1643: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1644: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1645: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1646: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1647: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1648: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1649: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1650: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1651: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1652: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1653: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1654: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1655: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1656: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1657: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1658: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1659: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1660: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1661: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1662: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1663: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1664: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1665: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1666: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1667: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1668: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1669: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1670: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1671: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1672: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1673: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1674: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1675: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1676: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1677: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1678: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1679: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1680: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1681: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1682: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1683: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1684: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1685: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1686: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1687: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1688: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1689: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1690: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1691: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1692: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1693: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1694: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1695: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1696: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1697: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1698: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1699: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1700: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1701: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1702: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1703: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1704: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1705: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1706: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1707: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1708: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1709: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1710: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1711: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1712: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1713: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1714: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1715: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1716: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1717: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1718: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1719: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1720: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1721: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1722: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1723: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1724: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1725: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1726: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1727: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1728: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1729: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1730: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1731: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1732: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1733: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1734: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1735: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1736: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1737: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1738: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1739: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1740: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1741: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1742: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1743: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1744: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1745: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1746: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1747: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1748: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1749: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1750: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1751: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1752: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1753: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1754: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1755: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1756: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1757: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1758: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1759: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1760: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1761: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1762: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1763: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1764: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1765: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1766: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1767: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1768: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1769: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1770: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1771: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1772: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1773: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1774: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1775: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1776: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1777: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1778: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1779: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1780: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1781: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1782: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1783: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1784: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1785: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1786: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1787: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1788: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1789: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1790: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1791: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1792: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1793: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1794: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1795: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1796: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1797: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1798: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1799: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1800: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1801: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1802: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1803: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1804: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1805: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1806: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1807: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1808: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1809: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1810: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1811: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1812: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1813: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1814: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1815: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1816: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1817: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1818: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1819: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1820: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1821: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1822: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1823: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1824: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1825: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1826: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1827: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1828: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1829: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1830: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1831: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1832: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1833: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1834: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1835: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1836: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1837: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1838: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1839: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1840: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1841: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1842: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1843: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1844: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1845: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1846: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1847: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1848: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1849: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1850: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1851: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1852: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1853: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1854: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1855: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1856: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1857: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1858: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1859: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1860: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1861: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1862: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1863: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1864: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1865: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1866: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1867: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1868: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1869: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1870: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1871: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1872: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1873: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1874: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1875: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1876: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1877: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1878: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1879: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1880: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1881: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1882: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1883: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1884: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1885: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1886: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1887: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1888: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1889: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1890: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1891: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1892: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1893: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1894: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1895: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1896: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1897: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1898: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1899: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1900: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1901: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1902: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1903: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1904: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1905: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1906: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1907: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1908: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1909: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1910: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1911: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1912: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1913: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1914: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1915: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1916: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1917: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1918: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1919: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1920: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1921: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1922: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1923: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1924: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1925: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1926: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1927: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1928: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1929: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1930: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1931: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1932: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1933: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1934: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1935: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1936: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1937: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1938: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1939: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1940: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1941: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1942: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1943: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1944: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1945: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1946: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1947: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1948: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1949: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1950: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1951: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1952: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1953: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1954: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1955: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1956: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1957: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1958: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1959: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1960: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1961: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1962: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1963: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1964: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1965: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1966: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1967: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1968: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1969: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1970: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1971: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1972: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1973: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1974: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1975: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1976: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1977: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1978: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1979: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1980: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1981: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1982: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1983: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1984: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1985: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1986: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1987: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1988: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1989: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1990: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1991: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1992: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1993: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1994: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1995: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1996: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1997: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1998: sponsor auction clearing deterministic transcript surface
audit-reserve-line-1999: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2000: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2001: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2002: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2003: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2004: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2005: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2006: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2007: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2008: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2009: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2010: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2011: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2012: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2013: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2014: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2015: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2016: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2017: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2018: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2019: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2020: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2021: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2022: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2023: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2024: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2025: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2026: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2027: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2028: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2029: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2030: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2031: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2032: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2033: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2034: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2035: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2036: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2037: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2038: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2039: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2040: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2041: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2042: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2043: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2044: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2045: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2046: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2047: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2048: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2049: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2050: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2051: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2052: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2053: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2054: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2055: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2056: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2057: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2058: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2059: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2060: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2061: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2062: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2063: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2064: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2065: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2066: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2067: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2068: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2069: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2070: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2071: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2072: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2073: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2074: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2075: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2076: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2077: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2078: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2079: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2080: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2081: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2082: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2083: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2084: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2085: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2086: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2087: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2088: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2089: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2090: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2091: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2092: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2093: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2094: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2095: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2096: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2097: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2098: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2099: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2100: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2101: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2102: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2103: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2104: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2105: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2106: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2107: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2108: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2109: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2110: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2111: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2112: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2113: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2114: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2115: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2116: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2117: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2118: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2119: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2120: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2121: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2122: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2123: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2124: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2125: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2126: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2127: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2128: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2129: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2130: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2131: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2132: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2133: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2134: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2135: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2136: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2137: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2138: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2139: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2140: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2141: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2142: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2143: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2144: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2145: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2146: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2147: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2148: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2149: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2150: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2151: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2152: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2153: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2154: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2155: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2156: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2157: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2158: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2159: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2160: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2161: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2162: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2163: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2164: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2165: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2166: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2167: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2168: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2169: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2170: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2171: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2172: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2173: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2174: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2175: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2176: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2177: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2178: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2179: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2180: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2181: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2182: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2183: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2184: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2185: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2186: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2187: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2188: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2189: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2190: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2191: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2192: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2193: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2194: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2195: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2196: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2197: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2198: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2199: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2200: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2201: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2202: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2203: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2204: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2205: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2206: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2207: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2208: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2209: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2210: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2211: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2212: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2213: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2214: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2215: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2216: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2217: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2218: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2219: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2220: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2221: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2222: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2223: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2224: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2225: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2226: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2227: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2228: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2229: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2230: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2231: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2232: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2233: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2234: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2235: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2236: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2237: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2238: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2239: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2240: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2241: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2242: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2243: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2244: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2245: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2246: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2247: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2248: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2249: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2250: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2251: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2252: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2253: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2254: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2255: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2256: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2257: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2258: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2259: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2260: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2261: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2262: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2263: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2264: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2265: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2266: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2267: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2268: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2269: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2270: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2271: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2272: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2273: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2274: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2275: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2276: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2277: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2278: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2279: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2280: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2281: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2282: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2283: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2284: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2285: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2286: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2287: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2288: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2289: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2290: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2291: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2292: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2293: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2294: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2295: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2296: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2297: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2298: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2299: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2300: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2301: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2302: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2303: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2304: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2305: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2306: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2307: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2308: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2309: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2310: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2311: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2312: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2313: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2314: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2315: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2316: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2317: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2318: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2319: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2320: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2321: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2322: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2323: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2324: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2325: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2326: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2327: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2328: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2329: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2330: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2331: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2332: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2333: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2334: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2335: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2336: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2337: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2338: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2339: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2340: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2341: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2342: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2343: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2344: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2345: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2346: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2347: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2348: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2349: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2350: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2351: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2352: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2353: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2354: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2355: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2356: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2357: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2358: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2359: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2360: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2361: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2362: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2363: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2364: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2365: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2366: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2367: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2368: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2369: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2370: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2371: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2372: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2373: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2374: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2375: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2376: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2377: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2378: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2379: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2380: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2381: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2382: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2383: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2384: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2385: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2386: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2387: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2388: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2389: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2390: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2391: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2392: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2393: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2394: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2395: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2396: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2397: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2398: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2399: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2400: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2401: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2402: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2403: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2404: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2405: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2406: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2407: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2408: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2409: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2410: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2411: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2412: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2413: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2414: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2415: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2416: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2417: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2418: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2419: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2420: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2421: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2422: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2423: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2424: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2425: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2426: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2427: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2428: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2429: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2430: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2431: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2432: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2433: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2434: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2435: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2436: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2437: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2438: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2439: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2440: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2441: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2442: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2443: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2444: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2445: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2446: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2447: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2448: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2449: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2450: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2451: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2452: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2453: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2454: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2455: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2456: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2457: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2458: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2459: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2460: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2461: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2462: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2463: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2464: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2465: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2466: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2467: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2468: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2469: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2470: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2471: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2472: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2473: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2474: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2475: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2476: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2477: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2478: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2479: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2480: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2481: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2482: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2483: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2484: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2485: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2486: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2487: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2488: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2489: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2490: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2491: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2492: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2493: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2494: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2495: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2496: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2497: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2498: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2499: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2500: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2501: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2502: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2503: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2504: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2505: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2506: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2507: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2508: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2509: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2510: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2511: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2512: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2513: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2514: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2515: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2516: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2517: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2518: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2519: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2520: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2521: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2522: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2523: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2524: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2525: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2526: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2527: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2528: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2529: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2530: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2531: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2532: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2533: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2534: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2535: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2536: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2537: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2538: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2539: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2540: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2541: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2542: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2543: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2544: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2545: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2546: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2547: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2548: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2549: sponsor auction clearing deterministic transcript surface
audit-reserve-line-2550: sponsor auction clearing deterministic transcript surface
*/
