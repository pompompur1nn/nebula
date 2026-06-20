use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialFeeVoucherSettlementMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2LowFeePqConfidentialFeeVoucherSettlementMarketRuntimeResult<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_VOUCHER_SETTLEMENT_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-fee-voucher-settlement-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_VOUCHER_SETTLEMENT_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-fee-voucher-market-v1";
pub const VOUCHER_BOOK_SCHEME: &str =
    "roots-only-private-l2-low-fee-confidential-fee-voucher-book-root-v1";
pub const VOUCHER_LOT_SCHEME: &str =
    "sealed-private-l2-low-fee-confidential-fee-voucher-lot-root-v1";
pub const SPONSOR_RESERVE_SCHEME: &str = "pq-confidential-fee-voucher-sponsor-reserve-root-v1";
pub const SEALED_AUCTION_SCHEME: &str = "pq-sealed-bid-fee-voucher-settlement-auction-root-v1";
pub const ROUTE_CAP_SCHEME: &str = "private-l2-fee-voucher-route-cap-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-slh-dsa-shake-256f-fee-voucher-settlement-attestation-root-v1";
pub const REDEMPTION_RECEIPT_SCHEME: &str =
    "zk-pq-confidential-fee-voucher-redemption-receipt-root-v1";
pub const REBATE_ACCOUNTING_SCHEME: &str =
    "low-fee-confidential-fee-voucher-rebate-accounting-root-v1";
pub const PRIVACY_REDACTION_SCHEME: &str =
    "selective-disclosure-fee-voucher-privacy-redaction-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "operator-summary-private-l2-fee-voucher-settlement-market-root-v1";
pub const EVENT_SCHEME: &str =
    "roots-only-private-l2-low-fee-pq-confidential-fee-voucher-market-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_REBATE_ASSET_ID: &str = "asset:fee-voucher-rebate-credit-devnet";
pub const DEVNET_HEIGHT: u64 = 2_337_920;
pub const DEVNET_EPOCH: u64 = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 6;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 36;
pub const DEFAULT_REDACTION_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_LOT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_LOT_NOTIONAL: u64 = 1_000;
pub const DEFAULT_MIN_SPONSOR_RESERVE: u64 = 50_000;
pub const DEFAULT_MAX_ROUTE_UTILIZATION_BPS: u64 = 8_750;
pub const DEFAULT_REBATE_HOLD_BACK_BPS: u64 = 650;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_VOUCHER_BOOKS: usize = 262_144;
pub const MAX_VOUCHER_LOTS: usize = 4_194_304;
pub const MAX_SPONSOR_RESERVES: usize = 1_048_576;
pub const MAX_AUCTIONS: usize = 1_048_576;
pub const MAX_ROUTE_CAPS: usize = 2_097_152;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_RECEIPTS: usize = 4_194_304;
pub const MAX_REBATE_ACCOUNTS: usize = 2_097_152;
pub const MAX_REDACTIONS: usize = 2_097_152;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherBookStatus {
    Draft,
    Open,
    CoolingDown,
    SettlementOnly,
    Paused,
    Retired,
}

impl VoucherBookStatus {
    pub fn accepts_lots(self) -> bool {
        matches!(self, Self::Open | Self::CoolingDown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherLotStatus {
    Submitted,
    Sealed,
    Matched,
    Settling,
    Redeemed,
    RebateQueued,
    Expired,
    Quarantined,
    Cancelled,
}

impl VoucherLotStatus {
    pub fn clearable(self) -> bool {
        matches!(self, Self::Submitted | Self::Sealed | Self::Matched)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Redeemed | Self::Expired | Self::Quarantined | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveStatus {
    Bootstrapping,
    Active,
    Constrained,
    Draining,
    Paused,
    Slashed,
    Retired,
}

impl ReserveStatus {
    pub fn accepts_settlement(self) -> bool {
        matches!(self, Self::Active | Self::Constrained)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Announced,
    CommitOpen,
    RevealOpen,
    Clearing,
    Settled,
    Disputed,
    Cancelled,
}

impl AuctionStatus {
    pub fn accepts_commitments(self) -> bool {
        matches!(self, Self::Announced | Self::CommitOpen)
    }

    pub fn accepts_reveals(self) -> bool {
        matches!(self, Self::RevealOpen | Self::Clearing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteCapStatus {
    Active,
    Saturated,
    CoolingDown,
    Paused,
    Retired,
}

impl RouteCapStatus {
    pub fn permits_flow(self) -> bool {
        matches!(self, Self::Active | Self::CoolingDown)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    BookIntegrity,
    LotEligibility,
    SponsorSolvency,
    AuctionClearing,
    RouteCapCompliance,
    RedemptionAuthorization,
    RebateAccounting,
    RedactionDisclosure,
    OperatorCheckpoint,
    EmergencyPause,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Finalized,
    RebateQueued,
    Disputed,
    Reversed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Queued,
    Paid,
    ClawedBack,
    Forfeited,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    PublicSummary,
    SponsorAudit,
    OperatorAudit,
    ComplianceDisclosure,
    DisputePacket,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorHealth {
    Green,
    Amber,
    Red,
    Paused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub settlement_finality_blocks: u64,
    pub auction_window_blocks: u64,
    pub redaction_window_blocks: u64,
    pub lot_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub min_lot_notional: u64,
    pub min_sponsor_reserve: u64,
    pub max_route_utilization_bps: u64,
    pub rebate_hold_back_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps: DEFAULT_MAX_SPONSOR_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            auction_window_blocks: DEFAULT_AUCTION_WINDOW_BLOCKS,
            redaction_window_blocks: DEFAULT_REDACTION_WINDOW_BLOCKS,
            lot_ttl_blocks: DEFAULT_LOT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            min_lot_notional: DEFAULT_MIN_LOT_NOTIONAL,
            min_sponsor_reserve: DEFAULT_MIN_SPONSOR_RESERVE,
            max_route_utilization_bps: DEFAULT_MAX_ROUTE_UTILIZATION_BPS,
            rebate_hold_back_bps: DEFAULT_REBATE_HOLD_BACK_BPS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security bits below minimum"
        );
        ensure!(
            self.min_privacy_set_size >= DEFAULT_MIN_PRIVACY_SET_SIZE,
            "privacy set below minimum"
        );
        ensure!(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum privacy set"
        );
        ensure!(
            self.max_user_fee_bps <= MAX_BPS && self.max_sponsor_fee_bps <= MAX_BPS,
            "fee bps out of range"
        );
        ensure!(self.target_rebate_bps <= MAX_BPS, "rebate bps out of range");
        ensure!(
            self.max_route_utilization_bps <= MAX_BPS,
            "route utilization bps out of range"
        );
        ensure!(
            self.rebate_hold_back_bps <= MAX_BPS,
            "rebate hold back bps out of range"
        );
        ensure!(
            self.min_lot_notional > 0 && self.min_sponsor_reserve > 0,
            "notional and reserve floors must be positive"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "auction_window_blocks": self.auction_window_blocks,
            "redaction_window_blocks": self.redaction_window_blocks,
            "lot_ttl_blocks": self.lot_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "min_lot_notional": self.min_lot_notional,
            "min_sponsor_reserve": self.min_sponsor_reserve,
            "max_route_utilization_bps": self.max_route_utilization_bps,
            "rebate_hold_back_bps": self.rebate_hold_back_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub voucher_books: u64,
    pub voucher_lots: u64,
    pub sponsor_reserves: u64,
    pub sealed_auctions: u64,
    pub route_caps: u64,
    pub pq_attestations: u64,
    pub redemption_receipts: u64,
    pub rebate_accounts: u64,
    pub privacy_redactions: u64,
    pub operator_summaries: u64,
    pub events: u64,
    pub total_voucher_notional: u64,
    pub total_redeemed_notional: u64,
    pub total_sponsor_capacity: u64,
    pub total_rebates_queued: u64,
    pub total_rebates_paid: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_books": self.voucher_books,
            "voucher_lots": self.voucher_lots,
            "sponsor_reserves": self.sponsor_reserves,
            "sealed_auctions": self.sealed_auctions,
            "route_caps": self.route_caps,
            "pq_attestations": self.pq_attestations,
            "redemption_receipts": self.redemption_receipts,
            "rebate_accounts": self.rebate_accounts,
            "privacy_redactions": self.privacy_redactions,
            "operator_summaries": self.operator_summaries,
            "events": self.events,
            "total_voucher_notional": self.total_voucher_notional,
            "total_redeemed_notional": self.total_redeemed_notional,
            "total_sponsor_capacity": self.total_sponsor_capacity,
            "total_rebates_queued": self.total_rebates_queued,
            "total_rebates_paid": self.total_rebates_paid,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub voucher_books_root: String,
    pub voucher_lots_root: String,
    pub sponsor_reserves_root: String,
    pub sealed_auctions_root: String,
    pub route_caps_root: String,
    pub pq_attestations_root: String,
    pub redemption_receipts_root: String,
    pub rebate_accounts_root: String,
    pub privacy_redactions_root: String,
    pub operator_summaries_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "voucher_books_root": self.voucher_books_root,
            "voucher_lots_root": self.voucher_lots_root,
            "sponsor_reserves_root": self.sponsor_reserves_root,
            "sealed_auctions_root": self.sealed_auctions_root,
            "route_caps_root": self.route_caps_root,
            "pq_attestations_root": self.pq_attestations_root,
            "redemption_receipts_root": self.redemption_receipts_root,
            "rebate_accounts_root": self.rebate_accounts_root,
            "privacy_redactions_root": self.privacy_redactions_root,
            "operator_summaries_root": self.operator_summaries_root,
            "events_root": self.events_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeVoucherBook {
    pub book_id: String,
    pub operator_id: String,
    pub sponsor_reserve_id: String,
    pub route_id: String,
    pub status: VoucherBookStatus,
    pub epoch: u64,
    pub opened_at_height: u64,
    pub low_fee_ceiling_bps: u64,
    pub sponsor_fee_ceiling_bps: u64,
    pub privacy_set_size: u64,
    pub encrypted_book_root: String,
    pub nullifier_root: String,
    pub pq_policy_digest: String,
}

impl FeeVoucherBook {
    pub fn new(
        book_id: impl Into<String>,
        operator_id: impl Into<String>,
        sponsor_reserve_id: impl Into<String>,
        route_id: impl Into<String>,
        epoch: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let book_id = book_id.into();
        let route_id = route_id.into();
        Self {
            encrypted_book_root: digest(
                VOUCHER_BOOK_SCHEME,
                &[
                    HashPart::Str(&book_id),
                    HashPart::Str(&route_id),
                    HashPart::Int(epoch as i128),
                ],
            ),
            nullifier_root: digest("fee-voucher-book-nullifiers", &[HashPart::Str(&book_id)]),
            pq_policy_digest: digest(PQ_AUTH_SUITE, &[HashPart::Str(&book_id)]),
            book_id,
            operator_id: operator_id.into(),
            sponsor_reserve_id: sponsor_reserve_id.into(),
            route_id,
            status: VoucherBookStatus::Open,
            epoch,
            opened_at_height: height,
            low_fee_ceiling_bps: config.max_user_fee_bps,
            sponsor_fee_ceiling_bps: config.max_sponsor_fee_bps,
            privacy_set_size: config.batch_privacy_set_size,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure!(!self.book_id.is_empty(), "book id is empty");
        ensure!(
            self.status.accepts_lots(),
            "voucher book is not open for lots"
        );
        ensure!(
            self.low_fee_ceiling_bps <= config.max_user_fee_bps,
            "book fee ceiling exceeds config"
        );
        ensure!(
            self.sponsor_fee_ceiling_bps <= config.max_sponsor_fee_bps,
            "book sponsor fee ceiling exceeds config"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "book privacy set below minimum"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "book_id": self.book_id,
            "operator_id": self.operator_id,
            "sponsor_reserve_id": self.sponsor_reserve_id,
            "route_id": self.route_id,
            "status": self.status,
            "epoch": self.epoch,
            "opened_at_height": self.opened_at_height,
            "low_fee_ceiling_bps": self.low_fee_ceiling_bps,
            "sponsor_fee_ceiling_bps": self.sponsor_fee_ceiling_bps,
            "privacy_set_size": self.privacy_set_size,
            "encrypted_book_root": self.encrypted_book_root,
            "nullifier_root": self.nullifier_root,
            "pq_policy_digest": self.pq_policy_digest,
        })
    }

    pub fn root(&self) -> String {
        record_root(VOUCHER_BOOK_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VoucherLot {
    pub lot_id: String,
    pub book_id: String,
    pub owner_commitment: String,
    pub sponsor_reserve_id: String,
    pub route_id: String,
    pub auction_id: String,
    pub status: VoucherLotStatus,
    pub notional: u64,
    pub max_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub expires_at_height: u64,
    pub encrypted_payload_root: String,
    pub nullifier: String,
    pub pq_commitment: String,
}

impl VoucherLot {
    pub fn new(
        lot_id: impl Into<String>,
        book_id: impl Into<String>,
        sponsor_reserve_id: impl Into<String>,
        route_id: impl Into<String>,
        auction_id: impl Into<String>,
        notional: u64,
        height: u64,
        config: &Config,
    ) -> Self {
        let lot_id = lot_id.into();
        let book_id = book_id.into();
        let route_id = route_id.into();
        Self {
            owner_commitment: digest("voucher-lot-owner", &[HashPart::Str(&lot_id)]),
            encrypted_payload_root: digest(
                VOUCHER_LOT_SCHEME,
                &[HashPart::Str(&lot_id), HashPart::Str(&book_id)],
            ),
            nullifier: digest("fee-voucher-lot-nullifier", &[HashPart::Str(&lot_id)]),
            pq_commitment: digest(
                PQ_AUTH_SUITE,
                &[HashPart::Str(&lot_id), HashPart::Str(&route_id)],
            ),
            lot_id,
            book_id,
            sponsor_reserve_id: sponsor_reserve_id.into(),
            route_id,
            auction_id: auction_id.into(),
            status: VoucherLotStatus::Sealed,
            notional,
            max_fee_bps: config.max_user_fee_bps,
            requested_rebate_bps: config.target_rebate_bps,
            privacy_set_size: config.batch_privacy_set_size,
            expires_at_height: height.saturating_add(config.lot_ttl_blocks),
        }
    }

    pub fn validate(&self, config: &Config, height: u64) -> Result<()> {
        ensure!(
            self.notional >= config.min_lot_notional,
            "lot notional below minimum"
        );
        ensure!(
            self.max_fee_bps <= config.max_user_fee_bps,
            "lot fee above ceiling"
        );
        ensure!(
            self.requested_rebate_bps <= config.target_rebate_bps,
            "lot rebate above target"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "lot privacy set below minimum"
        );
        ensure!(self.expires_at_height > height, "lot is expired");
        ensure!(self.status.clearable(), "lot is not clearable");
        Ok(())
    }

    pub fn fee_limit(&self) -> u64 {
        bps_amount(self.notional, self.max_fee_bps)
    }

    pub fn requested_rebate(&self) -> u64 {
        bps_amount(self.notional, self.requested_rebate_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lot_id": self.lot_id,
            "book_id": self.book_id,
            "owner_commitment": self.owner_commitment,
            "sponsor_reserve_id": self.sponsor_reserve_id,
            "route_id": self.route_id,
            "auction_id": self.auction_id,
            "status": self.status,
            "notional": self.notional,
            "max_fee_bps": self.max_fee_bps,
            "requested_rebate_bps": self.requested_rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "expires_at_height": self.expires_at_height,
            "encrypted_payload_root": self.encrypted_payload_root,
            "nullifier": self.nullifier,
            "pq_commitment": self.pq_commitment,
        })
    }

    pub fn root(&self) -> String {
        record_root(VOUCHER_LOT_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReserve {
    pub reserve_id: String,
    pub sponsor_id: String,
    pub status: ReserveStatus,
    pub committed_capacity: u64,
    pub available_capacity: u64,
    pub reserved_rebate: u64,
    pub max_sponsor_fee_bps: u64,
    pub privacy_set_size: u64,
    pub reserve_commitment_root: String,
    pub pq_solvency_attestation_root: String,
}

impl SponsorReserve {
    pub fn new(
        reserve_id: impl Into<String>,
        sponsor_id: impl Into<String>,
        capacity: u64,
        config: &Config,
    ) -> Self {
        let reserve_id = reserve_id.into();
        Self {
            reserve_commitment_root: digest(SPONSOR_RESERVE_SCHEME, &[HashPart::Str(&reserve_id)]),
            pq_solvency_attestation_root: digest(
                PQ_ATTESTATION_SCHEME,
                &[HashPart::Str(&reserve_id)],
            ),
            reserve_id,
            sponsor_id: sponsor_id.into(),
            status: ReserveStatus::Active,
            committed_capacity: capacity,
            available_capacity: capacity,
            reserved_rebate: 0,
            max_sponsor_fee_bps: config.max_sponsor_fee_bps,
            privacy_set_size: config.batch_privacy_set_size,
        }
    }

    pub fn reserve_for_lot(&mut self, lot: &VoucherLot) -> Result<u64> {
        ensure!(self.status.accepts_settlement(), "reserve is not active");
        let rebate = lot.requested_rebate();
        ensure!(
            self.available_capacity >= rebate,
            "insufficient sponsor reserve"
        );
        self.available_capacity = self.available_capacity.saturating_sub(rebate);
        self.reserved_rebate = self.reserved_rebate.saturating_add(rebate);
        Ok(rebate)
    }

    pub fn release_rebate(&mut self, amount: u64) {
        let released = amount.min(self.reserved_rebate);
        self.reserved_rebate = self.reserved_rebate.saturating_sub(released);
        self.available_capacity = self
            .available_capacity
            .saturating_add(released)
            .min(self.committed_capacity);
    }

    pub fn utilization_bps(&self) -> u64 {
        if self.committed_capacity == 0 {
            return 0;
        }
        bps_amount(
            MAX_BPS,
            self.committed_capacity
                .saturating_sub(self.available_capacity)
                .saturating_mul(MAX_BPS)
                / self.committed_capacity,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status,
            "committed_capacity": self.committed_capacity,
            "available_capacity": self.available_capacity,
            "reserved_rebate": self.reserved_rebate,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "reserve_commitment_root": self.reserve_commitment_root,
            "pq_solvency_attestation_root": self.pq_solvency_attestation_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(SPONSOR_RESERVE_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedSettlementAuction {
    pub auction_id: String,
    pub book_id: String,
    pub route_id: String,
    pub status: AuctionStatus,
    pub open_height: u64,
    pub reveal_height: u64,
    pub close_height: u64,
    pub clearing_fee_bps: u64,
    pub matched_notional: u64,
    pub commitment_root: String,
    pub reveal_root: String,
    pub encrypted_bid_book_root: String,
    pub winner_commitments: Vec<String>,
}

impl SealedSettlementAuction {
    pub fn new(
        auction_id: impl Into<String>,
        book_id: impl Into<String>,
        route_id: impl Into<String>,
        height: u64,
        config: &Config,
    ) -> Self {
        let auction_id = auction_id.into();
        Self {
            commitment_root: digest(SEALED_AUCTION_SCHEME, &[HashPart::Str(&auction_id)]),
            reveal_root: digest("fee-voucher-auction-reveals", &[HashPart::Str(&auction_id)]),
            encrypted_bid_book_root: digest(
                "fee-voucher-auction-encrypted-bid-book",
                &[HashPart::Str(&auction_id)],
            ),
            auction_id,
            book_id: book_id.into(),
            route_id: route_id.into(),
            status: AuctionStatus::CommitOpen,
            open_height: height,
            reveal_height: height.saturating_add(config.auction_window_blocks / 2),
            close_height: height.saturating_add(config.auction_window_blocks),
            clearing_fee_bps: config.max_user_fee_bps,
            matched_notional: 0,
            winner_commitments: Vec::new(),
        }
    }

    pub fn clear_lot(&mut self, lot: &VoucherLot, config: &Config) -> Result<()> {
        ensure!(
            self.status.accepts_commitments() || self.status.accepts_reveals(),
            "auction closed"
        );
        ensure!(
            lot.max_fee_bps <= config.max_user_fee_bps,
            "lot fee above market ceiling"
        );
        self.matched_notional = self.matched_notional.saturating_add(lot.notional);
        self.clearing_fee_bps = self.clearing_fee_bps.min(lot.max_fee_bps);
        self.winner_commitments.push(lot.pq_commitment.clone());
        self.status = AuctionStatus::Clearing;
        Ok(())
    }

    pub fn settle(&mut self) {
        self.status = AuctionStatus::Settled;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "book_id": self.book_id,
            "route_id": self.route_id,
            "status": self.status,
            "open_height": self.open_height,
            "reveal_height": self.reveal_height,
            "close_height": self.close_height,
            "clearing_fee_bps": self.clearing_fee_bps,
            "matched_notional": self.matched_notional,
            "commitment_root": self.commitment_root,
            "reveal_root": self.reveal_root,
            "encrypted_bid_book_root": self.encrypted_bid_book_root,
            "winner_commitments": self.winner_commitments,
        })
    }

    pub fn root(&self) -> String {
        record_root(SEALED_AUCTION_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCap {
    pub route_id: String,
    pub source_domain: String,
    pub target_domain: String,
    pub status: RouteCapStatus,
    pub epoch: u64,
    pub cap_notional: u64,
    pub used_notional: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub route_commitment_root: String,
}

impl RouteCap {
    pub fn devnet(
        route_id: impl Into<String>,
        epoch: u64,
        cap_notional: u64,
        config: &Config,
    ) -> Self {
        let route_id = route_id.into();
        Self {
            route_commitment_root: digest(ROUTE_CAP_SCHEME, &[HashPart::Str(&route_id)]),
            route_id,
            source_domain: DEVNET_L2_NETWORK.to_string(),
            target_domain: DEVNET_MONERO_NETWORK.to_string(),
            status: RouteCapStatus::Active,
            epoch,
            cap_notional,
            used_notional: 0,
            max_fee_bps: config.max_user_fee_bps,
            privacy_set_size: config.batch_privacy_set_size,
        }
    }

    pub fn reserve_flow(&mut self, lot: &VoucherLot, config: &Config) -> Result<()> {
        ensure!(self.status.permits_flow(), "route cap does not permit flow");
        ensure!(
            lot.max_fee_bps <= self.max_fee_bps,
            "lot exceeds route fee cap"
        );
        let next_used = self.used_notional.saturating_add(lot.notional);
        ensure!(next_used <= self.cap_notional, "route cap exceeded");
        let utilization_bps = if self.cap_notional == 0 {
            MAX_BPS
        } else {
            next_used.saturating_mul(MAX_BPS) / self.cap_notional
        };
        ensure!(
            utilization_bps <= config.max_route_utilization_bps,
            "route cap utilization guard exceeded"
        );
        self.used_notional = next_used;
        if utilization_bps == config.max_route_utilization_bps {
            self.status = RouteCapStatus::Saturated;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "source_domain": self.source_domain,
            "target_domain": self.target_domain,
            "status": self.status,
            "epoch": self.epoch,
            "cap_notional": self.cap_notional,
            "used_notional": self.used_notional,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "route_commitment_root": self.route_commitment_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(ROUTE_CAP_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSettlementAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub subject_id: String,
    pub operator_id: String,
    pub height: u64,
    pub expires_at_height: u64,
    pub pq_security_bits: u16,
    pub transcript_root: String,
    pub signature_root: String,
    pub disclosure_root: String,
}

impl PqSettlementAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        kind: AttestationKind,
        subject_id: impl Into<String>,
        operator_id: impl Into<String>,
        height: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let subject_id = subject_id.into();
        Self {
            transcript_root: digest(
                PQ_ATTESTATION_SCHEME,
                &[HashPart::Str(&attestation_id), HashPart::Str(&subject_id)],
            ),
            signature_root: digest(PQ_AUTH_SUITE, &[HashPart::Str(&attestation_id)]),
            disclosure_root: digest(
                "fee-voucher-attestation-disclosure",
                &[HashPart::Str(&attestation_id)],
            ),
            attestation_id,
            kind,
            subject_id,
            operator_id: operator_id.into(),
            height,
            expires_at_height: height.saturating_add(config.attestation_ttl_blocks),
            pq_security_bits: config.min_pq_security_bits,
        }
    }

    pub fn validate(&self, config: &Config, height: u64) -> Result<()> {
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "attestation pq security below minimum"
        );
        ensure!(self.expires_at_height > height, "attestation expired");
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "operator_id": self.operator_id,
            "height": self.height,
            "expires_at_height": self.expires_at_height,
            "pq_security_bits": self.pq_security_bits,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "disclosure_root": self.disclosure_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(PQ_ATTESTATION_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedemptionReceipt {
    pub receipt_id: String,
    pub lot_id: String,
    pub auction_id: String,
    pub sponsor_reserve_id: String,
    pub status: ReceiptStatus,
    pub redeemed_notional: u64,
    pub fee_paid: u64,
    pub rebate_amount: u64,
    pub finality_height: u64,
    pub receipt_commitment_root: String,
    pub encrypted_redemption_root: String,
}

impl RedemptionReceipt {
    pub fn from_lot(
        receipt_id: impl Into<String>,
        lot: &VoucherLot,
        auction: &SealedSettlementAuction,
        height: u64,
        config: &Config,
    ) -> Self {
        let receipt_id = receipt_id.into();
        let fee_paid = bps_amount(lot.notional, auction.clearing_fee_bps);
        let rebate_amount = lot.requested_rebate();
        Self {
            receipt_commitment_root: digest(
                REDEMPTION_RECEIPT_SCHEME,
                &[HashPart::Str(&receipt_id)],
            ),
            encrypted_redemption_root: digest(
                "fee-voucher-redemption-encrypted-details",
                &[HashPart::Str(&receipt_id), HashPart::Str(&lot.lot_id)],
            ),
            receipt_id,
            lot_id: lot.lot_id.clone(),
            auction_id: auction.auction_id.clone(),
            sponsor_reserve_id: lot.sponsor_reserve_id.clone(),
            status: ReceiptStatus::Finalized,
            redeemed_notional: lot.notional,
            fee_paid,
            rebate_amount,
            finality_height: height.saturating_add(config.settlement_finality_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lot_id": self.lot_id,
            "auction_id": self.auction_id,
            "sponsor_reserve_id": self.sponsor_reserve_id,
            "status": self.status,
            "redeemed_notional": self.redeemed_notional,
            "fee_paid": self.fee_paid,
            "rebate_amount": self.rebate_amount,
            "finality_height": self.finality_height,
            "receipt_commitment_root": self.receipt_commitment_root,
            "encrypted_redemption_root": self.encrypted_redemption_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(REDEMPTION_RECEIPT_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAccount {
    pub account_id: String,
    pub owner_commitment: String,
    pub sponsor_reserve_id: String,
    pub status: RebateStatus,
    pub accrued: u64,
    pub queued: u64,
    pub paid: u64,
    pub clawed_back: u64,
    pub encrypted_account_root: String,
}

impl RebateAccount {
    pub fn new(account_id: impl Into<String>, sponsor_reserve_id: impl Into<String>) -> Self {
        let account_id = account_id.into();
        Self {
            owner_commitment: digest("rebate-account-owner", &[HashPart::Str(&account_id)]),
            encrypted_account_root: digest(REBATE_ACCOUNTING_SCHEME, &[HashPart::Str(&account_id)]),
            account_id,
            sponsor_reserve_id: sponsor_reserve_id.into(),
            status: RebateStatus::Accruing,
            accrued: 0,
            queued: 0,
            paid: 0,
            clawed_back: 0,
        }
    }

    pub fn queue_receipt(&mut self, receipt: &RedemptionReceipt, config: &Config) -> u64 {
        let hold_back = bps_amount(receipt.rebate_amount, config.rebate_hold_back_bps);
        let queued = receipt.rebate_amount.saturating_sub(hold_back);
        self.accrued = self.accrued.saturating_add(receipt.rebate_amount);
        self.queued = self.queued.saturating_add(queued);
        self.status = RebateStatus::Queued;
        queued
    }

    pub fn mark_paid(&mut self, amount: u64) -> u64 {
        let paid = amount.min(self.queued);
        self.queued = self.queued.saturating_sub(paid);
        self.paid = self.paid.saturating_add(paid);
        if self.queued == 0 {
            self.status = RebateStatus::Paid;
        }
        paid
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "sponsor_reserve_id": self.sponsor_reserve_id,
            "status": self.status,
            "accrued": self.accrued,
            "queued": self.queued,
            "paid": self.paid,
            "clawed_back": self.clawed_back,
            "encrypted_account_root": self.encrypted_account_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(REBATE_ACCOUNTING_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub scope: RedactionScope,
    pub subject_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub disclosed_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub redaction_commitment_root: String,
    pub viewer_policy_root: String,
}

impl PrivacyRedaction {
    pub fn new(
        redaction_id: impl Into<String>,
        scope: RedactionScope,
        subject_id: impl Into<String>,
        height: u64,
        config: &Config,
    ) -> Self {
        let redaction_id = redaction_id.into();
        let mut disclosed_fields = BTreeSet::new();
        disclosed_fields.insert("id".to_string());
        disclosed_fields.insert("status".to_string());
        disclosed_fields.insert("root".to_string());
        let mut redacted_fields = BTreeSet::new();
        redacted_fields.insert("owner".to_string());
        redacted_fields.insert("amounts".to_string());
        redacted_fields.insert("bid_curve".to_string());
        Self {
            redaction_commitment_root: digest(
                PRIVACY_REDACTION_SCHEME,
                &[HashPart::Str(&redaction_id)],
            ),
            viewer_policy_root: digest(
                "fee-voucher-redaction-viewer-policy",
                &[HashPart::Str(&redaction_id)],
            ),
            redaction_id,
            scope,
            subject_id: subject_id.into(),
            created_at_height: height,
            expires_at_height: height.saturating_add(config.redaction_window_blocks),
            disclosed_fields,
            redacted_fields,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "scope": self.scope,
            "subject_id": self.subject_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "disclosed_fields": self.disclosed_fields,
            "redacted_fields": self.redacted_fields,
            "redaction_commitment_root": self.redaction_commitment_root,
            "viewer_policy_root": self.viewer_policy_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(PRIVACY_REDACTION_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub health: OperatorHealth,
    pub voucher_books: u64,
    pub lots_settled: u64,
    pub notional_settled: u64,
    pub average_fee_bps: u64,
    pub privacy_set_floor: u64,
    pub pq_security_bits: u16,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn from_state(
        summary_id: impl Into<String>,
        operator_id: impl Into<String>,
        state: &State,
    ) -> Self {
        let summary_id = summary_id.into();
        let average_fee_bps = if state.counters.total_redeemed_notional == 0 {
            0
        } else {
            state
                .redemption_receipts
                .values()
                .map(|receipt| {
                    receipt.fee_paid.saturating_mul(MAX_BPS) / receipt.redeemed_notional.max(1)
                })
                .sum::<u64>()
                / state.redemption_receipts.len().max(1) as u64
        };
        Self {
            summary_root: digest(OPERATOR_SUMMARY_SCHEME, &[HashPart::Str(&summary_id)]),
            summary_id,
            operator_id: operator_id.into(),
            epoch: state.epoch,
            health: OperatorHealth::Green,
            voucher_books: state.counters.voucher_books,
            lots_settled: state.counters.redemption_receipts,
            notional_settled: state.counters.total_redeemed_notional,
            average_fee_bps,
            privacy_set_floor: state.config.min_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "health": self.health,
            "voucher_books": self.voucher_books,
            "lots_settled": self.lots_settled,
            "notional_settled": self.notional_settled,
            "average_fee_bps": self.average_fee_bps,
            "privacy_set_floor": self.privacy_set_floor,
            "pq_security_bits": self.pq_security_bits,
            "summary_root": self.summary_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(OPERATOR_SUMMARY_SCHEME, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub height: u64,
    pub epoch: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub voucher_books: BTreeMap<String, FeeVoucherBook>,
    pub voucher_lots: BTreeMap<String, VoucherLot>,
    pub sponsor_reserves: BTreeMap<String, SponsorReserve>,
    pub sealed_auctions: BTreeMap<String, SealedSettlementAuction>,
    pub route_caps: BTreeMap<String, RouteCap>,
    pub pq_attestations: BTreeMap<String, PqSettlementAttestation>,
    pub redemption_receipts: BTreeMap<String, RedemptionReceipt>,
    pub rebate_accounts: BTreeMap<String, RebateAccount>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub events: Vec<Value>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            height,
            epoch,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            voucher_books: BTreeMap::new(),
            voucher_lots: BTreeMap::new(),
            sponsor_reserves: BTreeMap::new(),
            sealed_auctions: BTreeMap::new(),
            route_caps: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            redemption_receipts: BTreeMap::new(),
            rebate_accounts: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            events: Vec::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        demo()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn add_voucher_book(&mut self, book: FeeVoucherBook) -> Result<()> {
        ensure!(
            self.voucher_books.len() < MAX_VOUCHER_BOOKS,
            "voucher book capacity exceeded"
        );
        book.validate(&self.config)?;
        ensure!(
            self.sponsor_reserves.contains_key(&book.sponsor_reserve_id),
            "missing sponsor reserve {}",
            book.sponsor_reserve_id
        );
        ensure!(
            self.route_caps.contains_key(&book.route_id),
            "missing route cap {}",
            book.route_id
        );
        ensure!(
            !self.voucher_books.contains_key(&book.book_id),
            "duplicate voucher book"
        );
        self.events.push(
            json!({"kind": "voucher_book_opened", "book_id": book.book_id, "height": self.height}),
        );
        self.voucher_books.insert(book.book_id.clone(), book);
        self.recount();
        self.refresh_roots();
        Ok(())
    }

    pub fn add_sponsor_reserve(&mut self, reserve: SponsorReserve) -> Result<()> {
        ensure!(
            self.sponsor_reserves.len() < MAX_SPONSOR_RESERVES,
            "sponsor reserve capacity exceeded"
        );
        ensure!(
            reserve.committed_capacity >= self.config.min_sponsor_reserve,
            "sponsor reserve below minimum"
        );
        ensure!(
            !self.sponsor_reserves.contains_key(&reserve.reserve_id),
            "duplicate sponsor reserve"
        );
        self.events.push(json!({"kind": "sponsor_reserve_added", "reserve_id": reserve.reserve_id, "height": self.height}));
        self.sponsor_reserves
            .insert(reserve.reserve_id.clone(), reserve);
        self.recount();
        self.refresh_roots();
        Ok(())
    }

    pub fn add_route_cap(&mut self, route_cap: RouteCap) -> Result<()> {
        ensure!(
            self.route_caps.len() < MAX_ROUTE_CAPS,
            "route cap capacity exceeded"
        );
        ensure!(
            route_cap.privacy_set_size >= self.config.min_privacy_set_size,
            "route cap privacy set below minimum"
        );
        ensure!(
            !self.route_caps.contains_key(&route_cap.route_id),
            "duplicate route cap"
        );
        self.events.push(json!({"kind": "route_cap_added", "route_id": route_cap.route_id, "height": self.height}));
        self.route_caps
            .insert(route_cap.route_id.clone(), route_cap);
        self.recount();
        self.refresh_roots();
        Ok(())
    }

    pub fn add_auction(&mut self, auction: SealedSettlementAuction) -> Result<()> {
        ensure!(
            self.sealed_auctions.len() < MAX_AUCTIONS,
            "auction capacity exceeded"
        );
        ensure!(
            self.voucher_books.contains_key(&auction.book_id),
            "missing auction book"
        );
        ensure!(
            self.route_caps.contains_key(&auction.route_id),
            "missing auction route"
        );
        ensure!(
            !self.sealed_auctions.contains_key(&auction.auction_id),
            "duplicate auction"
        );
        self.events.push(json!({"kind": "sealed_auction_added", "auction_id": auction.auction_id, "height": self.height}));
        self.sealed_auctions
            .insert(auction.auction_id.clone(), auction);
        self.recount();
        self.refresh_roots();
        Ok(())
    }

    pub fn submit_voucher_lot(&mut self, lot: VoucherLot) -> Result<()> {
        ensure!(
            self.voucher_lots.len() < MAX_VOUCHER_LOTS,
            "voucher lot capacity exceeded"
        );
        lot.validate(&self.config, self.height)?;
        ensure!(
            self.voucher_books.contains_key(&lot.book_id),
            "missing lot book"
        );
        ensure!(
            self.sealed_auctions.contains_key(&lot.auction_id),
            "missing lot auction"
        );
        ensure!(
            !self.voucher_lots.contains_key(&lot.lot_id),
            "duplicate lot"
        );
        {
            let route = self
                .route_caps
                .get_mut(&lot.route_id)
                .ok_or_else(|| format!("missing route cap {}", lot.route_id))?;
            route.reserve_flow(&lot, &self.config)?;
        }
        {
            let reserve = self
                .sponsor_reserves
                .get_mut(&lot.sponsor_reserve_id)
                .ok_or_else(|| format!("missing sponsor reserve {}", lot.sponsor_reserve_id))?;
            reserve.reserve_for_lot(&lot)?;
        }
        {
            let auction = self
                .sealed_auctions
                .get_mut(&lot.auction_id)
                .ok_or_else(|| format!("missing auction {}", lot.auction_id))?;
            auction.clear_lot(&lot, &self.config)?;
        }
        self.events.push(
            json!({"kind": "voucher_lot_submitted", "lot_id": lot.lot_id, "height": self.height}),
        );
        self.voucher_lots.insert(lot.lot_id.clone(), lot);
        self.recount();
        self.refresh_roots();
        Ok(())
    }

    pub fn add_attestation(&mut self, attestation: PqSettlementAttestation) -> Result<()> {
        ensure!(
            self.pq_attestations.len() < MAX_ATTESTATIONS,
            "attestation capacity exceeded"
        );
        attestation.validate(&self.config, self.height)?;
        ensure!(
            !self
                .pq_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate attestation"
        );
        self.events.push(json!({"kind": "pq_attestation_added", "attestation_id": attestation.attestation_id, "height": self.height}));
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recount();
        self.refresh_roots();
        Ok(())
    }

    pub fn redeem_lot(
        &mut self,
        lot_id: &str,
        receipt_id: impl Into<String>,
    ) -> Result<RedemptionReceipt> {
        ensure!(
            self.redemption_receipts.len() < MAX_RECEIPTS,
            "redemption receipt capacity exceeded"
        );
        let lot = self
            .voucher_lots
            .get(lot_id)
            .cloned()
            .ok_or_else(|| format!("missing lot {lot_id}"))?;
        ensure!(!lot.status.terminal(), "lot already terminal");
        let auction = self
            .sealed_auctions
            .get_mut(&lot.auction_id)
            .ok_or_else(|| format!("missing auction {}", lot.auction_id))?;
        auction.settle();
        let receipt =
            RedemptionReceipt::from_lot(receipt_id, &lot, auction, self.height, &self.config);
        let mut redeemed_lot = lot;
        redeemed_lot.status = VoucherLotStatus::Redeemed;
        self.voucher_lots
            .insert(redeemed_lot.lot_id.clone(), redeemed_lot);
        let account_id = format!("rebate:{}", receipt.lot_id);
        let queued = self
            .rebate_accounts
            .entry(account_id.clone())
            .or_insert_with(|| RebateAccount::new(&account_id, &receipt.sponsor_reserve_id))
            .queue_receipt(&receipt, &self.config);
        self.counters.total_rebates_queued =
            self.counters.total_rebates_queued.saturating_add(queued);
        self.events.push(json!({"kind": "lot_redeemed", "lot_id": receipt.lot_id, "receipt_id": receipt.receipt_id, "height": self.height}));
        self.redemption_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.recount();
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn add_redaction(&mut self, redaction: PrivacyRedaction) -> Result<()> {
        ensure!(
            self.privacy_redactions.len() < MAX_REDACTIONS,
            "redaction capacity exceeded"
        );
        ensure!(
            !self
                .privacy_redactions
                .contains_key(&redaction.redaction_id),
            "duplicate redaction"
        );
        self.events.push(json!({"kind": "privacy_redaction_added", "redaction_id": redaction.redaction_id, "height": self.height}));
        self.privacy_redactions
            .insert(redaction.redaction_id.clone(), redaction);
        self.recount();
        self.refresh_roots();
        Ok(())
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        ensure!(
            self.operator_summaries.len() < MAX_OPERATOR_SUMMARIES,
            "operator summary capacity exceeded"
        );
        ensure!(
            !self.operator_summaries.contains_key(&summary.summary_id),
            "duplicate operator summary"
        );
        self.events.push(json!({"kind": "operator_summary_added", "summary_id": summary.summary_id, "height": self.height}));
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.recount();
        self.refresh_roots();
        Ok(())
    }

    pub fn pay_rebate(&mut self, account_id: &str, amount: u64) -> Result<u64> {
        let account = self
            .rebate_accounts
            .get_mut(account_id)
            .ok_or_else(|| format!("missing rebate account {account_id}"))?;
        let paid = account.mark_paid(amount);
        self.counters.total_rebates_paid = self.counters.total_rebates_paid.saturating_add(paid);
        self.events.push(json!({"kind": "rebate_paid", "account_id": account_id, "amount": paid, "height": self.height}));
        self.recount();
        self.refresh_roots();
        Ok(paid)
    }

    pub fn advance_height(&mut self, height: u64) {
        self.height = self.height.max(height);
        self.events
            .push(json!({"kind": "height_advanced", "height": self.height}));
        self.recount();
        self.refresh_roots();
    }

    pub fn recount(&mut self) {
        self.counters.voucher_books = self.voucher_books.len() as u64;
        self.counters.voucher_lots = self.voucher_lots.len() as u64;
        self.counters.sponsor_reserves = self.sponsor_reserves.len() as u64;
        self.counters.sealed_auctions = self.sealed_auctions.len() as u64;
        self.counters.route_caps = self.route_caps.len() as u64;
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.counters.redemption_receipts = self.redemption_receipts.len() as u64;
        self.counters.rebate_accounts = self.rebate_accounts.len() as u64;
        self.counters.privacy_redactions = self.privacy_redactions.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.events = self.events.len() as u64;
        self.counters.total_voucher_notional =
            self.voucher_lots.values().map(|lot| lot.notional).sum();
        self.counters.total_redeemed_notional = self
            .redemption_receipts
            .values()
            .map(|receipt| receipt.redeemed_notional)
            .sum();
        self.counters.total_sponsor_capacity = self
            .sponsor_reserves
            .values()
            .map(|reserve| reserve.committed_capacity)
            .sum();
        self.counters.total_rebates_queued = self
            .rebate_accounts
            .values()
            .map(|account| account.queued)
            .sum();
        self.counters.total_rebates_paid = self
            .rebate_accounts
            .values()
            .map(|account| account.paid)
            .sum();
    }

    pub fn refresh_roots(&mut self) {
        self.roots.voucher_books_root = map_root(
            VOUCHER_BOOK_SCHEME,
            self.voucher_books.values().map(FeeVoucherBook::root),
        );
        self.roots.voucher_lots_root = map_root(
            VOUCHER_LOT_SCHEME,
            self.voucher_lots.values().map(VoucherLot::root),
        );
        self.roots.sponsor_reserves_root = map_root(
            SPONSOR_RESERVE_SCHEME,
            self.sponsor_reserves.values().map(SponsorReserve::root),
        );
        self.roots.sealed_auctions_root = map_root(
            SEALED_AUCTION_SCHEME,
            self.sealed_auctions
                .values()
                .map(SealedSettlementAuction::root),
        );
        self.roots.route_caps_root = map_root(
            ROUTE_CAP_SCHEME,
            self.route_caps.values().map(RouteCap::root),
        );
        self.roots.pq_attestations_root = map_root(
            PQ_ATTESTATION_SCHEME,
            self.pq_attestations
                .values()
                .map(PqSettlementAttestation::root),
        );
        self.roots.redemption_receipts_root = map_root(
            REDEMPTION_RECEIPT_SCHEME,
            self.redemption_receipts
                .values()
                .map(RedemptionReceipt::root),
        );
        self.roots.rebate_accounts_root = map_root(
            REBATE_ACCOUNTING_SCHEME,
            self.rebate_accounts.values().map(RebateAccount::root),
        );
        self.roots.privacy_redactions_root = map_root(
            PRIVACY_REDACTION_SCHEME,
            self.privacy_redactions.values().map(PrivacyRedaction::root),
        );
        self.roots.operator_summaries_root = map_root(
            OPERATOR_SUMMARY_SCHEME,
            self.operator_summaries.values().map(OperatorSummary::root),
        );
        self.roots.events_root = map_root(
            EVENT_SCHEME,
            self.events
                .iter()
                .map(|event| record_root(EVENT_SCHEME, event)),
        );
        self.roots.state_root = compute_state_root(self);
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let config = Config::devnet();
    let mut state = State::new(config.clone(), DEVNET_HEIGHT, DEVNET_EPOCH)
        .expect("devnet fee voucher settlement market config must be valid");

    let reserve_a = SponsorReserve::new(
        "reserve:devnet:fast-lane",
        "sponsor:fast-lane",
        8_000_000,
        &config,
    );
    let reserve_b = SponsorReserve::new(
        "reserve:devnet:shielded-retail",
        "sponsor:shielded-retail",
        5_000_000,
        &config,
    );
    state.add_sponsor_reserve(reserve_a).expect("reserve a");
    state.add_sponsor_reserve(reserve_b).expect("reserve b");

    let route_a = RouteCap::devnet(
        "route:nebula-l2:monero:fast",
        state.epoch,
        40_000_000,
        &config,
    );
    let route_b = RouteCap::devnet(
        "route:nebula-l2:monero:retail",
        state.epoch,
        25_000_000,
        &config,
    );
    state.add_route_cap(route_a).expect("route a");
    state.add_route_cap(route_b).expect("route b");

    let book_a = FeeVoucherBook::new(
        "book:devnet:fast-lane",
        "operator:alpha",
        "reserve:devnet:fast-lane",
        "route:nebula-l2:monero:fast",
        state.epoch,
        state.height,
        &config,
    );
    let book_b = FeeVoucherBook::new(
        "book:devnet:shielded-retail",
        "operator:beta",
        "reserve:devnet:shielded-retail",
        "route:nebula-l2:monero:retail",
        state.epoch,
        state.height,
        &config,
    );
    state.add_voucher_book(book_a).expect("book a");
    state.add_voucher_book(book_b).expect("book b");

    let auction_a = SealedSettlementAuction::new(
        "auction:devnet:fast-lane:0001",
        "book:devnet:fast-lane",
        "route:nebula-l2:monero:fast",
        state.height,
        &config,
    );
    let auction_b = SealedSettlementAuction::new(
        "auction:devnet:shielded-retail:0001",
        "book:devnet:shielded-retail",
        "route:nebula-l2:monero:retail",
        state.height,
        &config,
    );
    state.add_auction(auction_a).expect("auction a");
    state.add_auction(auction_b).expect("auction b");

    for index in 0..16 {
        let lot = VoucherLot::new(
            format!("lot:devnet:fast-lane:{index:04}"),
            "book:devnet:fast-lane",
            "reserve:devnet:fast-lane",
            "route:nebula-l2:monero:fast",
            "auction:devnet:fast-lane:0001",
            12_000 + index * 750,
            state.height,
            &config,
        );
        state.submit_voucher_lot(lot).expect("fast-lane lot");
    }

    for index in 0..12 {
        let lot = VoucherLot::new(
            format!("lot:devnet:shielded-retail:{index:04}"),
            "book:devnet:shielded-retail",
            "reserve:devnet:shielded-retail",
            "route:nebula-l2:monero:retail",
            "auction:devnet:shielded-retail:0001",
            6_500 + index * 350,
            state.height,
            &config,
        );
        state.submit_voucher_lot(lot).expect("retail lot");
    }

    for (index, subject_id) in [
        "book:devnet:fast-lane",
        "reserve:devnet:fast-lane",
        "auction:devnet:fast-lane:0001",
        "route:nebula-l2:monero:fast",
        "book:devnet:shielded-retail",
        "reserve:devnet:shielded-retail",
        "auction:devnet:shielded-retail:0001",
        "route:nebula-l2:monero:retail",
    ]
    .iter()
    .enumerate()
    {
        let kind = match index % 4 {
            0 => AttestationKind::BookIntegrity,
            1 => AttestationKind::SponsorSolvency,
            2 => AttestationKind::AuctionClearing,
            _ => AttestationKind::RouteCapCompliance,
        };
        let attestation = PqSettlementAttestation::new(
            format!("attestation:devnet:{index:04}"),
            kind,
            *subject_id,
            "operator:alpha",
            state.height,
            &config,
        );
        state
            .add_attestation(attestation)
            .expect("devnet attestation");
    }

    for index in 0..5 {
        let lot_id = format!("lot:devnet:fast-lane:{index:04}");
        state
            .redeem_lot(&lot_id, format!("receipt:devnet:fast-lane:{index:04}"))
            .expect("fast-lane redemption");
    }

    for index in 0..3 {
        let lot_id = format!("lot:devnet:shielded-retail:{index:04}");
        state
            .redeem_lot(
                &lot_id,
                format!("receipt:devnet:shielded-retail:{index:04}"),
            )
            .expect("retail redemption");
    }

    for (index, subject_id) in [
        "lot:devnet:fast-lane:0000",
        "lot:devnet:fast-lane:0001",
        "auction:devnet:fast-lane:0001",
        "lot:devnet:shielded-retail:0000",
        "auction:devnet:shielded-retail:0001",
    ]
    .iter()
    .enumerate()
    {
        let redaction = PrivacyRedaction::new(
            format!("redaction:devnet:{index:04}"),
            RedactionScope::PublicSummary,
            *subject_id,
            state.height,
            &config,
        );
        state.add_redaction(redaction).expect("devnet redaction");
    }

    let summary_a =
        OperatorSummary::from_state("summary:devnet:operator:alpha", "operator:alpha", &state);
    let summary_b =
        OperatorSummary::from_state("summary:devnet:operator:beta", "operator:beta", &state);
    state.add_operator_summary(summary_a).expect("summary a");
    state.add_operator_summary(summary_b).expect("summary b");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "pq_auth_suite": PQ_AUTH_SUITE,
        "feature": "private_l2_low_fee_pq_confidential_fee_voucher_settlement_market",
        "height": state.height,
        "epoch": state.epoch,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": state.roots.public_record(),
    })
}

pub fn state_root(state: &State) -> String {
    compute_state_root(state)
}

fn compute_state_root(state: &State) -> String {
    domain_hash(
        "private-l2-low-fee-pq-confidential-fee-voucher-settlement-market-state-root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(SCHEMA_VERSION as i128),
            HashPart::Int(state.height as i128),
            HashPart::Int(state.epoch as i128),
            HashPart::Str(&state.roots.voucher_books_root),
            HashPart::Str(&state.roots.voucher_lots_root),
            HashPart::Str(&state.roots.sponsor_reserves_root),
            HashPart::Str(&state.roots.sealed_auctions_root),
            HashPart::Str(&state.roots.route_caps_root),
            HashPart::Str(&state.roots.pq_attestations_root),
            HashPart::Str(&state.roots.redemption_receipts_root),
            HashPart::Str(&state.roots.rebate_accounts_root),
            HashPart::Str(&state.roots.privacy_redactions_root),
            HashPart::Str(&state.roots.operator_summaries_root),
            HashPart::Str(&state.roots.events_root),
        ],
    )
}

fn map_root<I>(scheme: &str, leaves: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = leaves.into_iter().collect::<Vec<_>>();
    if leaves.is_empty() {
        return digest(scheme, &[HashPart::Str("empty")]);
    }
    merkle_root(scheme, leaves.iter().map(String::as_str))
}

fn record_root(scheme: &str, value: &Value) -> String {
    domain_hash(
        scheme,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&canonical_json(value)),
        ],
    )
}

fn digest(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut full_parts = Vec::with_capacity(parts.len() + 1);
    full_parts.push(HashPart::Str(PROTOCOL_VERSION));
    full_parts.extend_from_slice(parts);
    domain_hash(domain, &full_parts)
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).expect("serde_json value serialization is infallible")
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    ((amount as u128).saturating_mul(bps as u128) / MAX_BPS as u128) as u64
}
