use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeMarketResult<T> = Result<T, String>;

pub const LOW_FEE_MARKET_PROTOCOL_VERSION: u64 = 1;
pub const LOW_FEE_MARKET_DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 720;
pub const LOW_FEE_MARKET_DEFAULT_CREDIT_TTL_BLOCKS: u64 = 180;
pub const LOW_FEE_MARKET_DEFAULT_SMOOTHING_WINDOW_BLOCKS: u64 = 24;
pub const LOW_FEE_MARKET_DEFAULT_MIN_BOND_UNITS: u64 = 2;
pub const LOW_FEE_MARKET_MAX_REBATE_BPS: u64 = 10_000;
pub const LOW_FEE_MARKET_WARN_REMAINING_BPS: u64 = 2_500;
pub const LOW_FEE_MARKET_CRITICAL_REMAINING_BPS: u64 = 1_000;
pub const LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const LOW_FEE_MARKET_PRIVACY_LANE_KEY: &str = "privacy_transfer";
pub const LOW_FEE_MARKET_BRIDGE_LANE_KEY: &str = "monero_bridge";
pub const LOW_FEE_MARKET_SMALL_DEFI_LANE_KEY: &str = "small_defi";
pub const LOW_FEE_MARKET_PROOFS_LANE_KEY: &str = "proofs";

pub const LOW_FEE_STATUS_ACTIVE: &str = "active";
pub const LOW_FEE_STATUS_OPEN: &str = "open";
pub const LOW_FEE_STATUS_ACCEPTED: &str = "accepted";
pub const LOW_FEE_STATUS_REJECTED: &str = "rejected";
pub const LOW_FEE_STATUS_SETTLED: &str = "settled";
pub const LOW_FEE_STATUS_EXHAUSTED: &str = "exhausted";
pub const LOW_FEE_STATUS_EXPIRED: &str = "expired";
pub const LOW_FEE_STATUS_RELEASED: &str = "released";
pub const LOW_FEE_STATUS_SLASHED: &str = "slashed";
pub const LOW_FEE_STATUS_REDEEMED: &str = "redeemed";
pub const LOW_FEE_STATUS_PAUSED: &str = "paused";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeLaneKind {
    Privacy,
    Bridge,
    SmallDefi,
    Proofs,
}

impl LowFeeLaneKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Privacy => "privacy",
            Self::Bridge => "bridge",
            Self::SmallDefi => "small_defi",
            Self::Proofs => "proofs",
        }
    }

    pub fn default_lane_key(&self) -> &'static str {
        match self {
            Self::Privacy => LOW_FEE_MARKET_PRIVACY_LANE_KEY,
            Self::Bridge => LOW_FEE_MARKET_BRIDGE_LANE_KEY,
            Self::SmallDefi => LOW_FEE_MARKET_SMALL_DEFI_LANE_KEY,
            Self::Proofs => LOW_FEE_MARKET_PROOFS_LANE_KEY,
        }
    }

    pub fn default_display_name(&self) -> &'static str {
        match self {
            Self::Privacy => "Private transfers",
            Self::Bridge => "Monero bridge",
            Self::SmallDefi => "Small DeFi calls",
            Self::Proofs => "Proof jobs",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeAlertSeverity {
    Watch,
    Warn,
    Critical,
    Exhausted,
}

impl LowFeeAlertSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Warn => "warn",
            Self::Critical => "critical",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeMarketConfig {
    pub protocol_version: u64,
    pub default_epoch_length_blocks: u64,
    pub default_credit_ttl_blocks: u64,
    pub default_smoothing_window_blocks: u64,
    pub min_bond_units: u64,
    pub max_rebate_bps: u64,
    pub warn_remaining_bps: u64,
    pub critical_remaining_bps: u64,
}

impl Default for LowFeeMarketConfig {
    fn default() -> Self {
        Self {
            protocol_version: LOW_FEE_MARKET_PROTOCOL_VERSION,
            default_epoch_length_blocks: LOW_FEE_MARKET_DEFAULT_EPOCH_LENGTH_BLOCKS,
            default_credit_ttl_blocks: LOW_FEE_MARKET_DEFAULT_CREDIT_TTL_BLOCKS,
            default_smoothing_window_blocks: LOW_FEE_MARKET_DEFAULT_SMOOTHING_WINDOW_BLOCKS,
            min_bond_units: LOW_FEE_MARKET_DEFAULT_MIN_BOND_UNITS,
            max_rebate_bps: LOW_FEE_MARKET_MAX_REBATE_BPS,
            warn_remaining_bps: LOW_FEE_MARKET_WARN_REMAINING_BPS,
            critical_remaining_bps: LOW_FEE_MARKET_CRITICAL_REMAINING_BPS,
        }
    }
}

impl LowFeeMarketConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_market_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "default_epoch_length_blocks": self.default_epoch_length_blocks,
            "default_credit_ttl_blocks": self.default_credit_ttl_blocks,
            "default_smoothing_window_blocks": self.default_smoothing_window_blocks,
            "min_bond_units": self.min_bond_units,
            "max_rebate_bps": self.max_rebate_bps,
            "warn_remaining_bps": self.warn_remaining_bps,
            "critical_remaining_bps": self.critical_remaining_bps,
        })
    }

    pub fn config_root(&self) -> String {
        low_fee_market_payload_root("LOW-FEE-MARKET-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSubsidyEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub fee_asset_id: String,
    pub subsidy_pool_units: u64,
    pub reserved_units: u64,
    pub issued_credit_units: u64,
    pub auctioned_rebate_units: u64,
    pub sponsor_release_units: u64,
    pub lane_budget_root: String,
    pub sponsor_vault_root: String,
    pub status: String,
}

impl LowFeeSubsidyEpoch {
    pub fn new(
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        fee_asset_id: &str,
        subsidy_pool_units: u64,
    ) -> Self {
        let epoch_id = low_fee_subsidy_epoch_id(
            epoch_index,
            start_height,
            end_height,
            fee_asset_id,
            subsidy_pool_units,
        );
        Self {
            epoch_id,
            epoch_index,
            start_height,
            end_height,
            fee_asset_id: fee_asset_id.to_string(),
            subsidy_pool_units,
            reserved_units: 0,
            issued_credit_units: 0,
            auctioned_rebate_units: 0,
            sponsor_release_units: 0,
            lane_budget_root: merkle_root("LOW-FEE-LANE-BUDGET", &[]),
            sponsor_vault_root: merkle_root("LOW-FEE-SPONSOR-VAULT", &[]),
            status: LOW_FEE_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn available_units(&self) -> u64 {
        self.subsidy_pool_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.issued_credit_units)
            .saturating_sub(self.auctioned_rebate_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_subsidy_epoch",
            "chain_id": CHAIN_ID,
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "fee_asset_id": self.fee_asset_id,
            "subsidy_pool_units": self.subsidy_pool_units,
            "reserved_units": self.reserved_units,
            "issued_credit_units": self.issued_credit_units,
            "auctioned_rebate_units": self.auctioned_rebate_units,
            "sponsor_release_units": self.sponsor_release_units,
            "available_units": self.available_units(),
            "lane_budget_root": self.lane_budget_root,
            "sponsor_vault_root": self.sponsor_vault_root,
            "status": self.status,
        })
    }

    pub fn epoch_root(&self) -> String {
        low_fee_subsidy_epoch_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeLaneBudget {
    pub budget_id: String,
    pub epoch_id: String,
    pub lane_id: String,
    pub lane_kind: LowFeeLaneKind,
    pub lane_key: String,
    pub display_name: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub reserved_units: u64,
    pub max_rebate_bps: u64,
    pub min_settled_fee_units: u64,
    pub smoothing_target_fee_units: u64,
    pub smoothing_window_blocks: u64,
    pub priority: u64,
    pub status: String,
}

impl LowFeeLaneBudget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: &str,
        lane_kind: LowFeeLaneKind,
        lane_key: &str,
        display_name: &str,
        fee_asset_id: &str,
        budget_units: u64,
        max_rebate_bps: u64,
        min_settled_fee_units: u64,
        smoothing_target_fee_units: u64,
        smoothing_window_blocks: u64,
        priority: u64,
    ) -> Self {
        let lane_id = low_fee_market_lane_id(lane_kind.as_str(), lane_key);
        let budget_id = low_fee_lane_budget_id(epoch_id, &lane_id, fee_asset_id);
        Self {
            budget_id,
            epoch_id: epoch_id.to_string(),
            lane_id,
            lane_kind,
            lane_key: lane_key.to_string(),
            display_name: display_name.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            budget_units,
            spent_units: 0,
            reserved_units: 0,
            max_rebate_bps: std::cmp::min(max_rebate_bps, LOW_FEE_MARKET_MAX_REBATE_BPS),
            min_settled_fee_units,
            smoothing_target_fee_units,
            smoothing_window_blocks,
            priority,
            status: LOW_FEE_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn privacy(epoch_id: &str, fee_asset_id: &str, budget_units: u64) -> Self {
        Self::new(
            epoch_id,
            LowFeeLaneKind::Privacy,
            LOW_FEE_MARKET_PRIVACY_LANE_KEY,
            LowFeeLaneKind::Privacy.default_display_name(),
            fee_asset_id,
            budget_units,
            8_500,
            1,
            3,
            LOW_FEE_MARKET_DEFAULT_SMOOTHING_WINDOW_BLOCKS,
            10,
        )
    }

    pub fn bridge(epoch_id: &str, fee_asset_id: &str, budget_units: u64) -> Self {
        Self::new(
            epoch_id,
            LowFeeLaneKind::Bridge,
            LOW_FEE_MARKET_BRIDGE_LANE_KEY,
            LowFeeLaneKind::Bridge.default_display_name(),
            fee_asset_id,
            budget_units,
            7_500,
            2,
            5,
            LOW_FEE_MARKET_DEFAULT_SMOOTHING_WINDOW_BLOCKS,
            20,
        )
    }

    pub fn small_defi(epoch_id: &str, fee_asset_id: &str, budget_units: u64) -> Self {
        Self::new(
            epoch_id,
            LowFeeLaneKind::SmallDefi,
            LOW_FEE_MARKET_SMALL_DEFI_LANE_KEY,
            LowFeeLaneKind::SmallDefi.default_display_name(),
            fee_asset_id,
            budget_units,
            6_500,
            2,
            7,
            LOW_FEE_MARKET_DEFAULT_SMOOTHING_WINDOW_BLOCKS,
            30,
        )
    }

    pub fn proofs(epoch_id: &str, fee_asset_id: &str, budget_units: u64) -> Self {
        Self::new(
            epoch_id,
            LowFeeLaneKind::Proofs,
            LOW_FEE_MARKET_PROOFS_LANE_KEY,
            LowFeeLaneKind::Proofs.default_display_name(),
            fee_asset_id,
            budget_units,
            9_000,
            1,
            4,
            LOW_FEE_MARKET_DEFAULT_SMOOTHING_WINDOW_BLOCKS,
            40,
        )
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.spent_units)
            .saturating_sub(self.reserved_units)
    }

    pub fn utilization_bps(&self) -> u64 {
        self.spent_units
            .saturating_add(self.reserved_units)
            .saturating_mul(10_000)
            .checked_div(std::cmp::max(1, self.budget_units))
            .unwrap_or(0)
    }

    pub fn bounded_rebate_units(&self, gross_fee_units: u64) -> u64 {
        let rebate_by_bps = low_fee_mul_bps(gross_fee_units, self.max_rebate_bps);
        let rebate_above_floor = gross_fee_units.saturating_sub(self.min_settled_fee_units);
        std::cmp::min(
            self.available_units(),
            std::cmp::min(rebate_by_bps, rebate_above_floor),
        )
    }

    pub fn smoothing_rebate_units(&self, gross_fee_units: u64) -> u64 {
        let excess_units = gross_fee_units.saturating_sub(self.smoothing_target_fee_units);
        std::cmp::min(self.bounded_rebate_units(gross_fee_units), excess_units)
    }

    pub fn smoothed_fee_units(&self, gross_fee_units: u64) -> u64 {
        gross_fee_units.saturating_sub(self.smoothing_rebate_units(gross_fee_units))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_lane_budget",
            "chain_id": CHAIN_ID,
            "budget_id": self.budget_id,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "lane_key": self.lane_key,
            "display_name": self.display_name,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "utilization_bps": self.utilization_bps(),
            "max_rebate_bps": self.max_rebate_bps,
            "min_settled_fee_units": self.min_settled_fee_units,
            "smoothing_target_fee_units": self.smoothing_target_fee_units,
            "smoothing_window_blocks": self.smoothing_window_blocks,
            "priority": self.priority,
            "status": self.status,
        })
    }

    pub fn budget_root(&self) -> String {
        low_fee_lane_budget_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorVault {
    pub vault_id: String,
    pub sponsor_label: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub deposited_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub refund_locked_units: u64,
    pub min_balance_units: u64,
    pub release_rate_units: u64,
    pub nonce: u64,
    pub status: String,
    pub metadata_root: String,
}

impl LowFeeSponsorVault {
    pub fn new(
        sponsor_label: &str,
        fee_asset_id: &str,
        deposited_units: u64,
        min_balance_units: u64,
        release_rate_units: u64,
        nonce: u64,
        metadata: &Value,
    ) -> Self {
        let sponsor_commitment = low_fee_sponsor_commitment(sponsor_label);
        let vault_id = low_fee_sponsor_vault_id(&sponsor_commitment, fee_asset_id, nonce);
        Self {
            vault_id,
            sponsor_label: sponsor_label.to_string(),
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            deposited_units,
            reserved_units: 0,
            spent_units: 0,
            refund_locked_units: 0,
            min_balance_units,
            release_rate_units,
            nonce,
            status: LOW_FEE_STATUS_ACTIVE.to_string(),
            metadata_root: low_fee_market_payload_root("LOW-FEE-SPONSOR-VAULT-METADATA", metadata),
        }
    }

    pub fn available_units(&self) -> u64 {
        self.deposited_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
            .saturating_sub(self.refund_locked_units)
            .saturating_sub(self.min_balance_units)
    }

    pub fn reserve_units(&mut self, units: u64) -> LowFeeMarketResult<()> {
        if self.status != LOW_FEE_STATUS_ACTIVE {
            return Err("sponsor vault is not active".to_string());
        }
        if self.available_units() < units {
            return Err("sponsor vault has insufficient available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn spend_reserved_units(&mut self, reserved_units: u64, spent_units: u64) {
        self.reserved_units = self.reserved_units.saturating_sub(reserved_units);
        self.spent_units = self.spent_units.saturating_add(spent_units);
        if self.available_units() == 0 {
            self.status = LOW_FEE_STATUS_EXHAUSTED.to_string();
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_vault",
            "chain_id": CHAIN_ID,
            "vault_id": self.vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "deposited_units": self.deposited_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "refund_locked_units": self.refund_locked_units,
            "min_balance_units": self.min_balance_units,
            "release_rate_units": self.release_rate_units,
            "available_units": self.available_units(),
            "nonce": self.nonce,
            "status": self.status,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("low fee sponsor vault state record object")
            .insert(
                "sponsor_label".to_string(),
                Value::String(self.sponsor_label.clone()),
            );
        record
    }

    pub fn vault_root(&self) -> String {
        low_fee_sponsor_vault_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebateAuction {
    pub auction_id: String,
    pub auction_nonce: u64,
    pub epoch_id: String,
    pub lane_id: String,
    pub lane_key: String,
    pub sponsor_vault_id: String,
    pub fee_asset_id: String,
    pub offered_rebate_units: u64,
    pub filled_rebate_units: u64,
    pub min_bid_fee_units: u64,
    pub max_rebate_bps: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub bid_count: u64,
    pub status: String,
}

impl LowFeeRebateAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_nonce: u64,
        epoch_id: &str,
        lane_id: &str,
        lane_key: &str,
        sponsor_vault_id: &str,
        fee_asset_id: &str,
        offered_rebate_units: u64,
        min_bid_fee_units: u64,
        max_rebate_bps: u64,
        start_height: u64,
        end_height: u64,
    ) -> Self {
        let auction_id = low_fee_rebate_auction_id(
            epoch_id,
            lane_id,
            sponsor_vault_id,
            auction_nonce,
            start_height,
        );
        Self {
            auction_id,
            auction_nonce,
            epoch_id: epoch_id.to_string(),
            lane_id: lane_id.to_string(),
            lane_key: lane_key.to_string(),
            sponsor_vault_id: sponsor_vault_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            offered_rebate_units,
            filled_rebate_units: 0,
            min_bid_fee_units,
            max_rebate_bps: std::cmp::min(max_rebate_bps, LOW_FEE_MARKET_MAX_REBATE_BPS),
            start_height,
            end_height,
            bid_count: 0,
            status: LOW_FEE_STATUS_OPEN.to_string(),
        }
    }

    pub fn accepts_height(&self, height: u64) -> bool {
        self.status == LOW_FEE_STATUS_OPEN
            && height >= self.start_height
            && height <= self.end_height
    }

    pub fn remaining_rebate_units(&self) -> u64 {
        self.offered_rebate_units
            .saturating_sub(self.filled_rebate_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_rebate_auction",
            "chain_id": CHAIN_ID,
            "auction_id": self.auction_id,
            "auction_nonce": self.auction_nonce,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "sponsor_vault_id": self.sponsor_vault_id,
            "fee_asset_id": self.fee_asset_id,
            "offered_rebate_units": self.offered_rebate_units,
            "filled_rebate_units": self.filled_rebate_units,
            "remaining_rebate_units": self.remaining_rebate_units(),
            "min_bid_fee_units": self.min_bid_fee_units,
            "max_rebate_bps": self.max_rebate_bps,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "bid_count": self.bid_count,
            "status": self.status,
        })
    }

    pub fn auction_root(&self) -> String {
        low_fee_rebate_auction_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebateAuctionBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub tx_id: String,
    pub lane_id: String,
    pub max_fee_units: u64,
    pub requested_rebate_units: u64,
    pub bid_fee_units: u64,
    pub bond_id: String,
    pub submitted_height: u64,
    pub bid_nonce: u64,
    pub status: String,
}

impl LowFeeRebateAuctionBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction: &LowFeeRebateAuction,
        bidder_commitment: &str,
        tx_id: &str,
        max_fee_units: u64,
        requested_rebate_units: u64,
        bid_fee_units: u64,
        bond_id: &str,
        submitted_height: u64,
        bid_nonce: u64,
    ) -> Self {
        let bid_id = low_fee_rebate_auction_bid_id(
            &auction.auction_id,
            bidder_commitment,
            tx_id,
            requested_rebate_units,
            bid_nonce,
        );
        Self {
            bid_id,
            auction_id: auction.auction_id.clone(),
            bidder_commitment: bidder_commitment.to_string(),
            tx_id: tx_id.to_string(),
            lane_id: auction.lane_id.clone(),
            max_fee_units,
            requested_rebate_units,
            bid_fee_units,
            bond_id: bond_id.to_string(),
            submitted_height,
            bid_nonce,
            status: LOW_FEE_STATUS_OPEN.to_string(),
        }
    }

    pub fn score_units(&self) -> u64 {
        let fee_density = self
            .bid_fee_units
            .saturating_mul(10_000)
            .checked_div(std::cmp::max(1, self.requested_rebate_units))
            .unwrap_or(0);
        fee_density.saturating_add(self.max_fee_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_rebate_auction_bid",
            "chain_id": CHAIN_ID,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "tx_id": self.tx_id,
            "lane_id": self.lane_id,
            "max_fee_units": self.max_fee_units,
            "requested_rebate_units": self.requested_rebate_units,
            "bid_fee_units": self.bid_fee_units,
            "score_units": self.score_units(),
            "bond_id": self.bond_id,
            "submitted_height": self.submitted_height,
            "bid_nonce": self.bid_nonce,
            "status": self.status,
        })
    }

    pub fn bid_root(&self) -> String {
        low_fee_rebate_auction_bid_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeCredit {
    pub credit_id: String,
    pub epoch_id: String,
    pub lane_id: String,
    pub lane_key: String,
    pub credit_owner_commitment: String,
    pub fee_asset_id: String,
    pub issued_units: u64,
    pub spent_units: u64,
    pub source_kind: String,
    pub source_id: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl LowFeeCredit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: &str,
        lane_id: &str,
        lane_key: &str,
        credit_owner_commitment: &str,
        fee_asset_id: &str,
        issued_units: u64,
        source_kind: &str,
        source_id: &str,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let credit_id = low_fee_credit_id(
            epoch_id,
            lane_id,
            credit_owner_commitment,
            fee_asset_id,
            source_id,
            expires_at_height,
        );
        Self {
            credit_id,
            epoch_id: epoch_id.to_string(),
            lane_id: lane_id.to_string(),
            lane_key: lane_key.to_string(),
            credit_owner_commitment: credit_owner_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            issued_units,
            spent_units: 0,
            source_kind: source_kind.to_string(),
            source_id: source_id.to_string(),
            issued_at_height,
            expires_at_height,
            status: LOW_FEE_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn available_units(&self) -> u64 {
        self.issued_units.saturating_sub(self.spent_units)
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height || self.status == LOW_FEE_STATUS_EXPIRED
    }

    pub fn spend_units(&mut self, units: u64, height: u64) -> LowFeeMarketResult<u64> {
        if self.is_expired_at(height) {
            self.status = LOW_FEE_STATUS_EXPIRED.to_string();
            return Err("fee credit is expired".to_string());
        }
        let spent = std::cmp::min(units, self.available_units());
        self.spent_units = self.spent_units.saturating_add(spent);
        if self.available_units() == 0 {
            self.status = LOW_FEE_STATUS_REDEEMED.to_string();
        }
        Ok(spent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_credit",
            "chain_id": CHAIN_ID,
            "credit_id": self.credit_id,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "credit_owner_commitment": self.credit_owner_commitment,
            "fee_asset_id": self.fee_asset_id,
            "issued_units": self.issued_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn credit_root(&self) -> String {
        low_fee_credit_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeCreditIssuance {
    pub issuance_id: String,
    pub epoch_id: String,
    pub credit_id: String,
    pub credit_owner_commitment: String,
    pub lane_id: String,
    pub lane_key: String,
    pub fee_asset_id: String,
    pub issued_units: u64,
    pub source_kind: String,
    pub source_id: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl LowFeeCreditIssuance {
    pub fn from_credit(credit: &LowFeeCredit) -> Self {
        let issuance_id = low_fee_credit_issuance_id(
            &credit.credit_id,
            &credit.source_kind,
            &credit.source_id,
            credit.issued_at_height,
        );
        Self {
            issuance_id,
            epoch_id: credit.epoch_id.clone(),
            credit_id: credit.credit_id.clone(),
            credit_owner_commitment: credit.credit_owner_commitment.clone(),
            lane_id: credit.lane_id.clone(),
            lane_key: credit.lane_key.clone(),
            fee_asset_id: credit.fee_asset_id.clone(),
            issued_units: credit.issued_units,
            source_kind: credit.source_kind.clone(),
            source_id: credit.source_id.clone(),
            issued_at_height: credit.issued_at_height,
            expires_at_height: credit.expires_at_height,
            status: LOW_FEE_STATUS_SETTLED.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_credit_issuance",
            "chain_id": CHAIN_ID,
            "issuance_id": self.issuance_id,
            "epoch_id": self.epoch_id,
            "credit_id": self.credit_id,
            "credit_owner_commitment": self.credit_owner_commitment,
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "fee_asset_id": self.fee_asset_id,
            "issued_units": self.issued_units,
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn issuance_root(&self) -> String {
        low_fee_credit_issuance_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSmoothingSnapshot {
    pub smoothing_id: String,
    pub height: u64,
    pub epoch_id: String,
    pub lane_id: String,
    pub lane_key: String,
    pub observed_fee_units: u64,
    pub target_fee_units: u64,
    pub smoothed_fee_units: u64,
    pub rebate_units: u64,
    pub congestion_bps: u64,
    pub window_blocks: u64,
    pub budget_available_before: u64,
}

impl LowFeeSmoothingSnapshot {
    pub fn new(
        height: u64,
        budget: &LowFeeLaneBudget,
        observed_fee_units: u64,
        congestion_bps: u64,
        tx_id: &str,
    ) -> Self {
        let rebate_units = budget.smoothing_rebate_units(observed_fee_units);
        let smoothed_fee_units = observed_fee_units.saturating_sub(rebate_units);
        let smoothing_id = low_fee_smoothing_snapshot_id(
            height,
            &budget.epoch_id,
            &budget.lane_id,
            tx_id,
            observed_fee_units,
        );
        Self {
            smoothing_id,
            height,
            epoch_id: budget.epoch_id.clone(),
            lane_id: budget.lane_id.clone(),
            lane_key: budget.lane_key.clone(),
            observed_fee_units,
            target_fee_units: budget.smoothing_target_fee_units,
            smoothed_fee_units,
            rebate_units,
            congestion_bps,
            window_blocks: budget.smoothing_window_blocks,
            budget_available_before: budget.available_units(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_smoothing_snapshot",
            "chain_id": CHAIN_ID,
            "smoothing_id": self.smoothing_id,
            "height": self.height,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "observed_fee_units": self.observed_fee_units,
            "target_fee_units": self.target_fee_units,
            "smoothed_fee_units": self.smoothed_fee_units,
            "rebate_units": self.rebate_units,
            "congestion_bps": self.congestion_bps,
            "window_blocks": self.window_blocks,
            "budget_available_before": self.budget_available_before,
        })
    }

    pub fn smoothing_root(&self) -> String {
        low_fee_smoothing_snapshot_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeAntiSpamBond {
    pub bond_id: String,
    pub owner_commitment: String,
    pub lane_id: String,
    pub tx_id: String,
    pub fee_asset_id: String,
    pub posted_units: u64,
    pub slashed_units: u64,
    pub released_units: u64,
    pub posted_at_height: u64,
    pub locked_until_height: u64,
    pub reason_root: String,
    pub nonce: u64,
    pub status: String,
}

impl LowFeeAntiSpamBond {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        lane_id: &str,
        tx_id: &str,
        fee_asset_id: &str,
        posted_units: u64,
        posted_at_height: u64,
        locked_until_height: u64,
        reason: &Value,
        nonce: u64,
    ) -> Self {
        let bond_id = low_fee_anti_spam_bond_id(owner_commitment, lane_id, tx_id, nonce);
        Self {
            bond_id,
            owner_commitment: owner_commitment.to_string(),
            lane_id: lane_id.to_string(),
            tx_id: tx_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            posted_units,
            slashed_units: 0,
            released_units: 0,
            posted_at_height,
            locked_until_height,
            reason_root: low_fee_market_payload_root("LOW-FEE-ANTI-SPAM-BOND-REASON", reason),
            nonce,
            status: LOW_FEE_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn active_units(&self) -> u64 {
        self.posted_units
            .saturating_sub(self.slashed_units)
            .saturating_sub(self.released_units)
    }

    pub fn release(&mut self, height: u64) -> LowFeeMarketResult<u64> {
        if height < self.locked_until_height {
            return Err("anti-spam bond is still locked".to_string());
        }
        let units = self.active_units();
        self.released_units = self.released_units.saturating_add(units);
        self.status = LOW_FEE_STATUS_RELEASED.to_string();
        Ok(units)
    }

    pub fn slash(&mut self, units: u64) -> u64 {
        let slashed = std::cmp::min(units, self.active_units());
        self.slashed_units = self.slashed_units.saturating_add(slashed);
        if self.active_units() == 0 {
            self.status = LOW_FEE_STATUS_SLASHED.to_string();
        }
        slashed
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_anti_spam_bond",
            "chain_id": CHAIN_ID,
            "bond_id": self.bond_id,
            "owner_commitment": self.owner_commitment,
            "lane_id": self.lane_id,
            "tx_id": self.tx_id,
            "fee_asset_id": self.fee_asset_id,
            "posted_units": self.posted_units,
            "slashed_units": self.slashed_units,
            "released_units": self.released_units,
            "active_units": self.active_units(),
            "posted_at_height": self.posted_at_height,
            "locked_until_height": self.locked_until_height,
            "reason_root": self.reason_root,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn bond_root(&self) -> String {
        low_fee_anti_spam_bond_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeReceipt {
    pub receipt_id: String,
    pub tx_id: String,
    pub payer_commitment: String,
    pub epoch_id: String,
    pub lane_id: String,
    pub lane_key: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub smoothing_rebate_units: u64,
    pub auction_rebate_units: u64,
    pub credit_units_used: u64,
    pub bond_units_locked: u64,
    pub settled_fee_units: u64,
    pub sponsor_vault_id: String,
    pub auction_id: String,
    pub credit_id: String,
    pub bond_id: String,
    pub smoothing_id: String,
    pub height: u64,
    pub status: String,
}

impl LowFeeReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_id: &str,
        payer_commitment: &str,
        epoch_id: &str,
        lane_id: &str,
        lane_key: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
        smoothing_rebate_units: u64,
        auction_rebate_units: u64,
        credit_units_used: u64,
        bond_units_locked: u64,
        sponsor_vault_id: &str,
        auction_id: &str,
        credit_id: &str,
        bond_id: &str,
        smoothing_id: &str,
        height: u64,
    ) -> Self {
        let total_discount_units = smoothing_rebate_units
            .saturating_add(auction_rebate_units)
            .saturating_add(credit_units_used);
        let settled_fee_units = gross_fee_units.saturating_sub(total_discount_units);
        let receipt_id = low_fee_receipt_id(tx_id, payer_commitment, lane_id, height);
        Self {
            receipt_id,
            tx_id: tx_id.to_string(),
            payer_commitment: payer_commitment.to_string(),
            epoch_id: epoch_id.to_string(),
            lane_id: lane_id.to_string(),
            lane_key: lane_key.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_units,
            smoothing_rebate_units,
            auction_rebate_units,
            credit_units_used,
            bond_units_locked,
            settled_fee_units,
            sponsor_vault_id: sponsor_vault_id.to_string(),
            auction_id: auction_id.to_string(),
            credit_id: credit_id.to_string(),
            bond_id: bond_id.to_string(),
            smoothing_id: smoothing_id.to_string(),
            height,
            status: LOW_FEE_STATUS_SETTLED.to_string(),
        }
    }

    pub fn total_discount_units(&self) -> u64 {
        self.smoothing_rebate_units
            .saturating_add(self.auction_rebate_units)
            .saturating_add(self.credit_units_used)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "tx_id": self.tx_id,
            "payer_commitment": self.payer_commitment,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "smoothing_rebate_units": self.smoothing_rebate_units,
            "auction_rebate_units": self.auction_rebate_units,
            "credit_units_used": self.credit_units_used,
            "bond_units_locked": self.bond_units_locked,
            "total_discount_units": self.total_discount_units(),
            "settled_fee_units": self.settled_fee_units,
            "sponsor_vault_id": self.sponsor_vault_id,
            "auction_id": self.auction_id,
            "credit_id": self.credit_id,
            "bond_id": self.bond_id,
            "smoothing_id": self.smoothing_id,
            "height": self.height,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        low_fee_receipt_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExhaustionAlert {
    pub alert_id: String,
    pub epoch_id: String,
    pub lane_id: String,
    pub lane_key: String,
    pub height: u64,
    pub severity: LowFeeAlertSeverity,
    pub remaining_units: u64,
    pub threshold_units: u64,
    pub budget_root: String,
    pub vault_root: String,
    pub message_hash: String,
    pub status: String,
}

impl LowFeeExhaustionAlert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: &str,
        lane_id: &str,
        lane_key: &str,
        height: u64,
        severity: LowFeeAlertSeverity,
        remaining_units: u64,
        threshold_units: u64,
        budget_root: &str,
        vault_root: &str,
        message: &str,
    ) -> Self {
        let message_hash = low_fee_string_root("LOW-FEE-EXHAUSTION-ALERT-MESSAGE", message);
        let alert_id = low_fee_exhaustion_alert_id(
            epoch_id,
            lane_id,
            severity.as_str(),
            height,
            &message_hash,
        );
        Self {
            alert_id,
            epoch_id: epoch_id.to_string(),
            lane_id: lane_id.to_string(),
            lane_key: lane_key.to_string(),
            height,
            severity,
            remaining_units,
            threshold_units,
            budget_root: budget_root.to_string(),
            vault_root: vault_root.to_string(),
            message_hash,
            status: LOW_FEE_STATUS_OPEN.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_exhaustion_alert",
            "chain_id": CHAIN_ID,
            "alert_id": self.alert_id,
            "epoch_id": self.epoch_id,
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "height": self.height,
            "severity": self.severity.as_str(),
            "remaining_units": self.remaining_units,
            "threshold_units": self.threshold_units,
            "budget_root": self.budget_root,
            "vault_root": self.vault_root,
            "message_hash": self.message_hash,
            "status": self.status,
        })
    }

    pub fn alert_root(&self) -> String {
        low_fee_exhaustion_alert_root(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeMarketState {
    pub height: u64,
    pub config: LowFeeMarketConfig,
    pub current_epoch_id: String,
    pub subsidy_epochs: BTreeMap<String, LowFeeSubsidyEpoch>,
    pub lane_budgets: BTreeMap<String, LowFeeLaneBudget>,
    pub sponsor_vaults: BTreeMap<String, LowFeeSponsorVault>,
    pub rebate_auctions: BTreeMap<String, LowFeeRebateAuction>,
    pub auction_bids: BTreeMap<String, LowFeeRebateAuctionBid>,
    pub fee_credits: BTreeMap<String, LowFeeCredit>,
    pub credit_issuances: BTreeMap<String, LowFeeCreditIssuance>,
    pub smoothing_snapshots: BTreeMap<String, LowFeeSmoothingSnapshot>,
    pub anti_spam_bonds: BTreeMap<String, LowFeeAntiSpamBond>,
    pub receipts: BTreeMap<String, LowFeeReceipt>,
    pub exhaustion_alerts: BTreeMap<String, LowFeeExhaustionAlert>,
}

impl LowFeeMarketState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: LowFeeMarketConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::with_config(LowFeeMarketConfig::default());
        state.height = 24;

        let epoch = LowFeeSubsidyEpoch::new(
            0,
            0,
            LOW_FEE_MARKET_DEFAULT_EPOCH_LENGTH_BLOCKS - 1,
            LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID,
            500_000,
        );
        let epoch_id = epoch.epoch_id.clone();
        state.insert_subsidy_epoch(epoch);
        state.current_epoch_id = epoch_id.clone();

        let privacy_budget =
            LowFeeLaneBudget::privacy(&epoch_id, LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID, 120_000);
        let bridge_budget =
            LowFeeLaneBudget::bridge(&epoch_id, LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID, 100_000);
        let small_defi_budget =
            LowFeeLaneBudget::small_defi(&epoch_id, LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID, 80_000);
        let proofs_budget =
            LowFeeLaneBudget::proofs(&epoch_id, LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID, 60_000);
        let privacy_lane_id = privacy_budget.lane_id.clone();
        let bridge_lane_id = bridge_budget.lane_id.clone();
        let small_defi_lane_id = small_defi_budget.lane_id.clone();
        let proofs_lane_id = proofs_budget.lane_id.clone();
        state.insert_lane_budget(privacy_budget);
        state.insert_lane_budget(bridge_budget);
        state.insert_lane_budget(small_defi_budget);
        state.insert_lane_budget(proofs_budget);

        let foundation_vault = LowFeeSponsorVault::new(
            "devnet-foundation",
            LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID,
            250_000,
            10_000,
            25_000,
            1,
            &json!({"purpose": "wallet and privacy adoption"}),
        );
        let bridge_vault = LowFeeSponsorVault::new(
            "devnet-bridge-guild",
            LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID,
            150_000,
            8_000,
            15_000,
            2,
            &json!({"purpose": "bridge withdrawal smoothing"}),
        );
        let proof_vault = LowFeeSponsorVault::new(
            "devnet-proof-coop",
            LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID,
            90_000,
            5_000,
            12_000,
            3,
            &json!({"purpose": "proof lane rebates"}),
        );
        let bridge_vault_id = bridge_vault.vault_id.clone();
        let proof_vault_id = proof_vault.vault_id.clone();
        state.insert_sponsor_vault(foundation_vault);
        state.insert_sponsor_vault(bridge_vault);
        state.insert_sponsor_vault(proof_vault);

        let alice = low_fee_account_commitment("alice-devnet");
        let bob = low_fee_account_commitment("bob-devnet");
        let solver = low_fee_account_commitment("solver-devnet");
        let prover = low_fee_account_commitment("prover-devnet");

        let alice_credit = state
            .issue_fee_credit(
                &alice,
                &privacy_lane_id,
                12,
                "subsidy_epoch",
                &epoch_id,
                LOW_FEE_MARKET_DEFAULT_CREDIT_TTL_BLOCKS,
            )
            .expect("issue devnet alice credit");
        let bob_credit = state
            .issue_fee_credit(
                &bob,
                &bridge_lane_id,
                9,
                "sponsor_vault",
                &bridge_vault_id,
                LOW_FEE_MARKET_DEFAULT_CREDIT_TTL_BLOCKS,
            )
            .expect("issue devnet bob credit");

        let auction = state
            .open_rebate_auction(
                &proofs_lane_id,
                &proof_vault_id,
                20_000,
                3,
                8_000,
                24,
                32,
                1,
            )
            .expect("open devnet proof auction");
        let proof_bond = state
            .post_anti_spam_bond(
                &prover,
                &proofs_lane_id,
                "devnet-proof-tx-1",
                LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID,
                6,
                30,
                &json!({"auction_id": auction.auction_id, "lane": "proofs"}),
                1,
            )
            .expect("post devnet proof bond");
        state
            .place_rebate_bid(
                &auction.auction_id,
                &prover,
                "devnet-proof-tx-1",
                14,
                7,
                5,
                &proof_bond.bond_id,
                1,
            )
            .expect("place devnet proof bid");
        state
            .settle_rebate_auction(&auction.auction_id)
            .expect("settle devnet proof auction");

        let defi_bond = state
            .post_anti_spam_bond(
                &solver,
                &small_defi_lane_id,
                "devnet-defi-tx-1",
                LOW_FEE_MARKET_DEVNET_FEE_ASSET_ID,
                4,
                28,
                &json!({"lane": "small_defi", "operation": "sealed_swap"}),
                2,
            )
            .expect("post devnet defi bond");

        state
            .record_low_fee_receipt(
                "devnet-private-transfer-1",
                &alice,
                &privacy_lane_id,
                8,
                Some(&alice_credit.credit_id),
                None,
                None,
            )
            .expect("record privacy receipt");
        state
            .record_low_fee_receipt(
                "devnet-bridge-withdrawal-1",
                &bob,
                &bridge_lane_id,
                11,
                Some(&bob_credit.credit_id),
                None,
                None,
            )
            .expect("record bridge receipt");
        state
            .record_low_fee_receipt(
                "devnet-defi-tx-1",
                &solver,
                &small_defi_lane_id,
                15,
                None,
                None,
                Some(&defi_bond.bond_id),
            )
            .expect("record small defi receipt");
        state
            .record_low_fee_receipt(
                "devnet-proof-tx-1",
                &prover,
                &proofs_lane_id,
                16,
                None,
                Some(&auction.auction_id),
                Some(&proof_bond.bond_id),
            )
            .expect("record proof receipt");

        if let Some(budget) = state.lane_budgets.get_mut(&proofs_lane_id) {
            budget.reserved_units = budget.budget_units.saturating_sub(500);
        }
        state.refresh_exhaustion_alerts();
        state.refresh_epoch_roots();
        state
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.current_epoch_id = self
            .subsidy_epochs
            .values()
            .find(|epoch| epoch.contains_height(height))
            .map(|epoch| epoch.epoch_id.clone())
            .unwrap_or_default();
        for credit in self.fee_credits.values_mut() {
            if credit.is_expired_at(height) && credit.available_units() > 0 {
                credit.status = LOW_FEE_STATUS_EXPIRED.to_string();
            }
        }
    }

    pub fn insert_subsidy_epoch(&mut self, epoch: LowFeeSubsidyEpoch) {
        self.subsidy_epochs.insert(epoch.epoch_id.clone(), epoch);
    }

    pub fn insert_lane_budget(&mut self, budget: LowFeeLaneBudget) {
        self.lane_budgets.insert(budget.lane_id.clone(), budget);
    }

    pub fn insert_sponsor_vault(&mut self, vault: LowFeeSponsorVault) {
        self.sponsor_vaults.insert(vault.vault_id.clone(), vault);
    }

    pub fn issue_fee_credit(
        &mut self,
        credit_owner_commitment: &str,
        lane_id: &str,
        units: u64,
        source_kind: &str,
        source_id: &str,
        ttl_blocks: u64,
    ) -> LowFeeMarketResult<LowFeeCreditIssuance> {
        if units == 0 {
            return Err("fee credit units are required".to_string());
        }
        let budget = self
            .lane_budgets
            .get_mut(lane_id)
            .ok_or_else(|| "unknown low-fee lane budget".to_string())?;
        if budget.available_units() < units {
            return Err("low-fee lane budget exhausted".to_string());
        }
        budget.spent_units = budget.spent_units.saturating_add(units);
        let epoch_id = budget.epoch_id.clone();
        let lane_key = budget.lane_key.clone();
        let fee_asset_id = budget.fee_asset_id.clone();

        if source_kind == "sponsor_vault" {
            let vault = self
                .sponsor_vaults
                .get_mut(source_id)
                .ok_or_else(|| "unknown sponsor vault".to_string())?;
            vault.reserve_units(units)?;
            vault.spend_reserved_units(units, units);
        }
        if let Some(epoch) = self.subsidy_epochs.get_mut(&epoch_id) {
            epoch.issued_credit_units = epoch.issued_credit_units.saturating_add(units);
            if source_kind == "sponsor_vault" {
                epoch.sponsor_release_units = epoch.sponsor_release_units.saturating_add(units);
            }
        }

        let credit = LowFeeCredit::new(
            &epoch_id,
            lane_id,
            &lane_key,
            credit_owner_commitment,
            &fee_asset_id,
            units,
            source_kind,
            source_id,
            self.height,
            self.height.saturating_add(ttl_blocks),
        );
        let issuance = LowFeeCreditIssuance::from_credit(&credit);
        self.fee_credits
            .insert(credit.credit_id.clone(), credit.clone());
        self.credit_issuances
            .insert(issuance.issuance_id.clone(), issuance.clone());
        self.refresh_epoch_roots();
        Ok(issuance)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_rebate_auction(
        &mut self,
        lane_id: &str,
        sponsor_vault_id: &str,
        offered_rebate_units: u64,
        min_bid_fee_units: u64,
        max_rebate_bps: u64,
        start_height: u64,
        end_height: u64,
        auction_nonce: u64,
    ) -> LowFeeMarketResult<LowFeeRebateAuction> {
        if offered_rebate_units == 0 {
            return Err("rebate auction requires offered units".to_string());
        }
        if end_height < start_height {
            return Err("rebate auction ends before it starts".to_string());
        }
        let budget = self
            .lane_budgets
            .get_mut(lane_id)
            .ok_or_else(|| "unknown low-fee lane budget".to_string())?;
        if budget.available_units() < offered_rebate_units {
            return Err("low-fee lane budget cannot reserve auction".to_string());
        }
        budget.reserved_units = budget.reserved_units.saturating_add(offered_rebate_units);
        let epoch_id = budget.epoch_id.clone();
        let lane_key = budget.lane_key.clone();
        let fee_asset_id = budget.fee_asset_id.clone();

        let vault = self
            .sponsor_vaults
            .get_mut(sponsor_vault_id)
            .ok_or_else(|| "unknown sponsor vault".to_string())?;
        vault.reserve_units(offered_rebate_units)?;

        let auction = LowFeeRebateAuction::new(
            auction_nonce,
            &epoch_id,
            lane_id,
            &lane_key,
            sponsor_vault_id,
            &fee_asset_id,
            offered_rebate_units,
            min_bid_fee_units,
            max_rebate_bps,
            start_height,
            end_height,
        );
        self.rebate_auctions
            .insert(auction.auction_id.clone(), auction.clone());
        self.refresh_epoch_roots();
        Ok(auction)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn place_rebate_bid(
        &mut self,
        auction_id: &str,
        bidder_commitment: &str,
        tx_id: &str,
        max_fee_units: u64,
        requested_rebate_units: u64,
        bid_fee_units: u64,
        bond_id: &str,
        bid_nonce: u64,
    ) -> LowFeeMarketResult<LowFeeRebateAuctionBid> {
        let auction = self
            .rebate_auctions
            .get_mut(auction_id)
            .ok_or_else(|| "unknown rebate auction".to_string())?;
        if !auction.accepts_height(self.height) {
            return Err("rebate auction is not accepting bids".to_string());
        }
        if requested_rebate_units == 0 {
            return Err("rebate bid requires requested units".to_string());
        }
        if bid_fee_units < auction.min_bid_fee_units {
            return Err("rebate bid fee is below auction minimum".to_string());
        }
        if requested_rebate_units > auction.remaining_rebate_units() {
            return Err("rebate bid requests more than auction remainder".to_string());
        }
        if !bond_id.is_empty() && !self.anti_spam_bonds.contains_key(bond_id) {
            return Err("unknown anti-spam bond".to_string());
        }
        let bid = LowFeeRebateAuctionBid::new(
            auction,
            bidder_commitment,
            tx_id,
            max_fee_units,
            requested_rebate_units,
            bid_fee_units,
            bond_id,
            self.height,
            bid_nonce,
        );
        auction.bid_count = auction.bid_count.saturating_add(1);
        self.auction_bids.insert(bid.bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn settle_rebate_auction(
        &mut self,
        auction_id: &str,
    ) -> LowFeeMarketResult<Vec<LowFeeRebateAuctionBid>> {
        let auction = self
            .rebate_auctions
            .get(auction_id)
            .ok_or_else(|| "unknown rebate auction".to_string())?
            .clone();
        let mut bid_order = self
            .auction_bids
            .iter()
            .filter(|(_, bid)| bid.auction_id == auction_id && bid.status == LOW_FEE_STATUS_OPEN)
            .map(|(bid_id, bid)| {
                (
                    bid_id.clone(),
                    bid.score_units(),
                    bid.bid_fee_units,
                    bid.requested_rebate_units,
                )
            })
            .collect::<Vec<_>>();
        bid_order.sort_by(|left, right| {
            right
                .1
                .cmp(&left.1)
                .then_with(|| right.2.cmp(&left.2))
                .then_with(|| left.3.cmp(&right.3))
                .then_with(|| left.0.cmp(&right.0))
        });

        let mut remaining = auction.offered_rebate_units;
        let mut accepted = Vec::new();
        for (bid_id, _, _, _) in bid_order {
            let bid = self
                .auction_bids
                .get_mut(&bid_id)
                .expect("rebate bid from ordered ids exists");
            if bid.requested_rebate_units <= remaining {
                remaining = remaining.saturating_sub(bid.requested_rebate_units);
                bid.status = LOW_FEE_STATUS_ACCEPTED.to_string();
                accepted.push(bid.clone());
            } else {
                bid.status = LOW_FEE_STATUS_REJECTED.to_string();
            }
        }
        let filled = auction.offered_rebate_units.saturating_sub(remaining);
        if let Some(vault) = self.sponsor_vaults.get_mut(&auction.sponsor_vault_id) {
            vault.spend_reserved_units(auction.offered_rebate_units, filled);
        }
        if let Some(budget) = self.lane_budgets.get_mut(&auction.lane_id) {
            budget.reserved_units = budget
                .reserved_units
                .saturating_sub(auction.offered_rebate_units);
            budget.spent_units = budget.spent_units.saturating_add(filled);
        }
        if let Some(epoch) = self.subsidy_epochs.get_mut(&auction.epoch_id) {
            epoch.auctioned_rebate_units = epoch.auctioned_rebate_units.saturating_add(filled);
            epoch.sponsor_release_units = epoch.sponsor_release_units.saturating_add(filled);
        }
        let auction = self
            .rebate_auctions
            .get_mut(auction_id)
            .expect("rebate auction exists");
        auction.filled_rebate_units = filled;
        auction.status = if filled == 0 {
            LOW_FEE_STATUS_EXHAUSTED.to_string()
        } else {
            LOW_FEE_STATUS_SETTLED.to_string()
        };
        self.refresh_epoch_roots();
        Ok(accepted)
    }

    pub fn post_anti_spam_bond(
        &mut self,
        owner_commitment: &str,
        lane_id: &str,
        tx_id: &str,
        fee_asset_id: &str,
        posted_units: u64,
        lock_blocks: u64,
        reason: &Value,
        nonce: u64,
    ) -> LowFeeMarketResult<LowFeeAntiSpamBond> {
        if posted_units < self.config.min_bond_units {
            return Err("anti-spam bond is below minimum".to_string());
        }
        if !self.lane_budgets.contains_key(lane_id) {
            return Err("unknown low-fee lane budget".to_string());
        }
        let bond = LowFeeAntiSpamBond::new(
            owner_commitment,
            lane_id,
            tx_id,
            fee_asset_id,
            posted_units,
            self.height,
            self.height.saturating_add(lock_blocks),
            reason,
            nonce,
        );
        self.anti_spam_bonds
            .insert(bond.bond_id.clone(), bond.clone());
        Ok(bond)
    }

    pub fn record_low_fee_receipt(
        &mut self,
        tx_id: &str,
        payer_commitment: &str,
        lane_id: &str,
        gross_fee_units: u64,
        credit_id: Option<&str>,
        auction_id: Option<&str>,
        bond_id: Option<&str>,
    ) -> LowFeeMarketResult<LowFeeReceipt> {
        let budget = self
            .lane_budgets
            .get(lane_id)
            .ok_or_else(|| "unknown low-fee lane budget".to_string())?
            .clone();
        let smoothing =
            LowFeeSmoothingSnapshot::new(self.height, &budget, gross_fee_units, 0, tx_id);
        let smoothing_rebate_units = smoothing.rebate_units;
        let smoothing_id = smoothing.smoothing_id.clone();
        self.smoothing_snapshots
            .insert(smoothing.smoothing_id.clone(), smoothing);

        let mut auction_rebate_units = 0;
        let mut auction_id_record = String::new();
        let mut sponsor_vault_id = String::new();
        if let Some(auction_id) = auction_id {
            let auction = self
                .rebate_auctions
                .get(auction_id)
                .ok_or_else(|| "unknown rebate auction".to_string())?;
            if auction.lane_id != lane_id {
                return Err("rebate auction lane mismatch".to_string());
            }
            auction_rebate_units = self
                .auction_bids
                .values()
                .filter(|bid| {
                    bid.auction_id == auction_id
                        && bid.tx_id == tx_id
                        && bid.status == LOW_FEE_STATUS_ACCEPTED
                })
                .map(|bid| bid.requested_rebate_units)
                .max()
                .unwrap_or(0);
            auction_id_record = auction_id.to_string();
            sponsor_vault_id = auction.sponsor_vault_id.clone();
        }

        let bounded_smoothing_units = std::cmp::min(smoothing_rebate_units, gross_fee_units);
        let remaining_after_smoothing = gross_fee_units.saturating_sub(bounded_smoothing_units);
        let bounded_auction_units = std::cmp::min(auction_rebate_units, remaining_after_smoothing);
        let remaining_after_auction =
            remaining_after_smoothing.saturating_sub(bounded_auction_units);

        let mut credit_units_used = 0;
        let mut credit_id_record = String::new();
        if let Some(credit_id) = credit_id {
            let credit = self
                .fee_credits
                .get_mut(credit_id)
                .ok_or_else(|| "unknown fee credit".to_string())?;
            if credit.lane_id != lane_id {
                return Err("fee credit lane mismatch".to_string());
            }
            credit_units_used = credit.spend_units(remaining_after_auction, self.height)?;
            credit_id_record = credit_id.to_string();
        }

        let mut bond_units_locked = 0;
        let mut bond_id_record = String::new();
        if let Some(bond_id) = bond_id {
            let bond = self
                .anti_spam_bonds
                .get(bond_id)
                .ok_or_else(|| "unknown anti-spam bond".to_string())?;
            if bond.lane_id != lane_id || bond.tx_id != tx_id {
                return Err("anti-spam bond receipt mismatch".to_string());
            }
            bond_units_locked = bond.active_units();
            bond_id_record = bond_id.to_string();
        }

        if let Some(budget) = self.lane_budgets.get_mut(lane_id) {
            budget.spent_units = budget.spent_units.saturating_add(bounded_smoothing_units);
        }

        let receipt = LowFeeReceipt::new(
            tx_id,
            payer_commitment,
            &budget.epoch_id,
            lane_id,
            &budget.lane_key,
            &budget.fee_asset_id,
            gross_fee_units,
            bounded_smoothing_units,
            bounded_auction_units,
            credit_units_used,
            bond_units_locked,
            &sponsor_vault_id,
            &auction_id_record,
            &credit_id_record,
            &bond_id_record,
            &smoothing_id,
            self.height,
        );
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.refresh_epoch_roots();
        Ok(receipt)
    }

    pub fn refresh_exhaustion_alerts(&mut self) -> Vec<LowFeeExhaustionAlert> {
        let budget_root = self.lane_budget_root();
        let vault_root = self.sponsor_vault_root();
        let mut alerts = Vec::new();
        for budget in self.lane_budgets.values() {
            let remaining_units = budget.available_units();
            let warn_threshold =
                low_fee_mul_bps(budget.budget_units, self.config.warn_remaining_bps);
            let critical_threshold =
                low_fee_mul_bps(budget.budget_units, self.config.critical_remaining_bps);
            let severity = if remaining_units == 0 {
                LowFeeAlertSeverity::Exhausted
            } else if remaining_units <= critical_threshold {
                LowFeeAlertSeverity::Critical
            } else if remaining_units <= warn_threshold {
                LowFeeAlertSeverity::Warn
            } else {
                continue;
            };
            let threshold_units = match severity {
                LowFeeAlertSeverity::Exhausted => 0,
                LowFeeAlertSeverity::Critical => critical_threshold,
                LowFeeAlertSeverity::Warn | LowFeeAlertSeverity::Watch => warn_threshold,
            };
            let alert = LowFeeExhaustionAlert::new(
                &budget.epoch_id,
                &budget.lane_id,
                &budget.lane_key,
                self.height,
                severity,
                remaining_units,
                threshold_units,
                &budget_root,
                &vault_root,
                "low-fee lane budget remaining units crossed threshold",
            );
            self.exhaustion_alerts
                .insert(alert.alert_id.clone(), alert.clone());
            alerts.push(alert);
        }
        alerts
    }

    pub fn subsidy_epoch_root(&self) -> String {
        merkle_root(
            "LOW-FEE-SUBSIDY-EPOCH",
            &self
                .subsidy_epochs
                .values()
                .map(LowFeeSubsidyEpoch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn lane_budget_root(&self) -> String {
        merkle_root(
            "LOW-FEE-LANE-BUDGET",
            &self
                .lane_budgets
                .values()
                .map(LowFeeLaneBudget::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsor_vault_root(&self) -> String {
        merkle_root(
            "LOW-FEE-SPONSOR-VAULT",
            &self
                .sponsor_vaults
                .values()
                .map(LowFeeSponsorVault::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn rebate_auction_root(&self) -> String {
        merkle_root(
            "LOW-FEE-REBATE-AUCTION",
            &self
                .rebate_auctions
                .values()
                .map(LowFeeRebateAuction::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn auction_bid_root(&self) -> String {
        merkle_root(
            "LOW-FEE-REBATE-AUCTION-BID",
            &self
                .auction_bids
                .values()
                .map(LowFeeRebateAuctionBid::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn fee_credit_root(&self) -> String {
        merkle_root(
            "LOW-FEE-CREDIT",
            &self
                .fee_credits
                .values()
                .map(LowFeeCredit::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn credit_issuance_root(&self) -> String {
        merkle_root(
            "LOW-FEE-CREDIT-ISSUANCE",
            &self
                .credit_issuances
                .values()
                .map(LowFeeCreditIssuance::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn smoothing_snapshot_root(&self) -> String {
        merkle_root(
            "LOW-FEE-SMOOTHING-SNAPSHOT",
            &self
                .smoothing_snapshots
                .values()
                .map(LowFeeSmoothingSnapshot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn anti_spam_bond_root(&self) -> String {
        merkle_root(
            "LOW-FEE-ANTI-SPAM-BOND",
            &self
                .anti_spam_bonds
                .values()
                .map(LowFeeAntiSpamBond::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn receipt_root(&self) -> String {
        merkle_root(
            "LOW-FEE-RECEIPT",
            &self
                .receipts
                .values()
                .map(LowFeeReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn exhaustion_alert_root(&self) -> String {
        merkle_root(
            "LOW-FEE-EXHAUSTION-ALERT",
            &self
                .exhaustion_alerts
                .values()
                .map(LowFeeExhaustionAlert::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn state_root(&self) -> String {
        low_fee_market_state_root_from_record(&self.public_record_without_root())
    }

    pub fn active_alert_count(&self) -> u64 {
        self.exhaustion_alerts
            .values()
            .filter(|alert| alert.status == LOW_FEE_STATUS_OPEN)
            .count() as u64
    }

    pub fn total_available_budget_units(&self) -> u64 {
        self.lane_budgets.values().fold(0_u64, |total, budget| {
            total.saturating_add(budget.available_units())
        })
    }

    pub fn total_credit_available_units(&self) -> u64 {
        self.fee_credits.values().fold(0_u64, |total, credit| {
            total.saturating_add(credit.available_units())
        })
    }

    pub fn total_vault_available_units(&self) -> u64 {
        self.sponsor_vaults.values().fold(0_u64, |total, vault| {
            total.saturating_add(vault.available_units())
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("low fee market state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "low_fee_market_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "current_epoch_id": self.current_epoch_id,
            "config": self.config.public_record(),
            "config_root": self.config.config_root(),
            "subsidy_epoch_root": self.subsidy_epoch_root(),
            "lane_budget_root": self.lane_budget_root(),
            "sponsor_vault_root": self.sponsor_vault_root(),
            "rebate_auction_root": self.rebate_auction_root(),
            "auction_bid_root": self.auction_bid_root(),
            "fee_credit_root": self.fee_credit_root(),
            "credit_issuance_root": self.credit_issuance_root(),
            "smoothing_snapshot_root": self.smoothing_snapshot_root(),
            "anti_spam_bond_root": self.anti_spam_bond_root(),
            "receipt_root": self.receipt_root(),
            "exhaustion_alert_root": self.exhaustion_alert_root(),
            "subsidy_epoch_count": self.subsidy_epochs.len() as u64,
            "lane_budget_count": self.lane_budgets.len() as u64,
            "sponsor_vault_count": self.sponsor_vaults.len() as u64,
            "rebate_auction_count": self.rebate_auctions.len() as u64,
            "auction_bid_count": self.auction_bids.len() as u64,
            "fee_credit_count": self.fee_credits.len() as u64,
            "credit_issuance_count": self.credit_issuances.len() as u64,
            "smoothing_snapshot_count": self.smoothing_snapshots.len() as u64,
            "anti_spam_bond_count": self.anti_spam_bonds.len() as u64,
            "receipt_count": self.receipts.len() as u64,
            "exhaustion_alert_count": self.exhaustion_alerts.len() as u64,
            "active_alert_count": self.active_alert_count(),
            "total_available_budget_units": self.total_available_budget_units(),
            "total_credit_available_units": self.total_credit_available_units(),
            "total_vault_available_units": self.total_vault_available_units(),
        })
    }

    fn refresh_epoch_roots(&mut self) {
        let lane_budget_root = self.lane_budget_root();
        let sponsor_vault_root = self.sponsor_vault_root();
        for epoch in self.subsidy_epochs.values_mut() {
            epoch.lane_budget_root = lane_budget_root.clone();
            epoch.sponsor_vault_root = sponsor_vault_root.clone();
            if epoch.available_units() == 0 {
                epoch.status = LOW_FEE_STATUS_EXHAUSTED.to_string();
            }
        }
    }
}

pub fn low_fee_market_lane_id(lane_kind: &str, lane_key: &str) -> String {
    domain_hash(
        "LOW-FEE-MARKET-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind),
            HashPart::Str(lane_key),
        ],
        32,
    )
}

pub fn low_fee_subsidy_epoch_id(
    epoch_index: u64,
    start_height: u64,
    end_height: u64,
    fee_asset_id: &str,
    subsidy_pool_units: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SUBSIDY-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_index as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(fee_asset_id),
            HashPart::Int(subsidy_pool_units as i128),
        ],
        32,
    )
}

pub fn low_fee_lane_budget_id(epoch_id: &str, lane_id: &str, fee_asset_id: &str) -> String {
    domain_hash(
        "LOW-FEE-LANE-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(lane_id),
            HashPart::Str(fee_asset_id),
        ],
        32,
    )
}

pub fn low_fee_sponsor_commitment(sponsor_label: &str) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(sponsor_label)],
        32,
    )
}

pub fn low_fee_account_commitment(account_label: &str) -> String {
    domain_hash(
        "LOW-FEE-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(account_label)],
        32,
    )
}

pub fn low_fee_sponsor_vault_id(
    sponsor_commitment: &str,
    fee_asset_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SPONSOR-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn low_fee_rebate_auction_id(
    epoch_id: &str,
    lane_id: &str,
    sponsor_vault_id: &str,
    auction_nonce: u64,
    start_height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-REBATE-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(lane_id),
            HashPart::Str(sponsor_vault_id),
            HashPart::Int(auction_nonce as i128),
            HashPart::Int(start_height as i128),
        ],
        32,
    )
}

pub fn low_fee_rebate_auction_bid_id(
    auction_id: &str,
    bidder_commitment: &str,
    tx_id: &str,
    requested_rebate_units: u64,
    bid_nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-REBATE-AUCTION-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(tx_id),
            HashPart::Int(requested_rebate_units as i128),
            HashPart::Int(bid_nonce as i128),
        ],
        32,
    )
}

pub fn low_fee_credit_id(
    epoch_id: &str,
    lane_id: &str,
    owner_commitment: &str,
    fee_asset_id: &str,
    source_id: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(lane_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Str(source_id),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn low_fee_credit_issuance_id(
    credit_id: &str,
    source_kind: &str,
    source_id: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-CREDIT-ISSUANCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(credit_id),
            HashPart::Str(source_kind),
            HashPart::Str(source_id),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn low_fee_smoothing_snapshot_id(
    height: u64,
    epoch_id: &str,
    lane_id: &str,
    tx_id: &str,
    observed_fee_units: u64,
) -> String {
    domain_hash(
        "LOW-FEE-SMOOTHING-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(epoch_id),
            HashPart::Str(lane_id),
            HashPart::Str(tx_id),
            HashPart::Int(observed_fee_units as i128),
        ],
        32,
    )
}

pub fn low_fee_anti_spam_bond_id(
    owner_commitment: &str,
    lane_id: &str,
    tx_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "LOW-FEE-ANTI-SPAM-BOND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(lane_id),
            HashPart::Str(tx_id),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn low_fee_receipt_id(
    tx_id: &str,
    payer_commitment: &str,
    lane_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "LOW-FEE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tx_id),
            HashPart::Str(payer_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn low_fee_exhaustion_alert_id(
    epoch_id: &str,
    lane_id: &str,
    severity: &str,
    height: u64,
    message_hash: &str,
) -> String {
    domain_hash(
        "LOW-FEE-EXHAUSTION-ALERT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(lane_id),
            HashPart::Str(severity),
            HashPart::Int(height as i128),
            HashPart::Str(message_hash),
        ],
        32,
    )
}

pub fn low_fee_subsidy_epoch_root(epoch: &LowFeeSubsidyEpoch) -> String {
    low_fee_market_payload_root("LOW-FEE-SUBSIDY-EPOCH", &epoch.public_record())
}

pub fn low_fee_lane_budget_root(budget: &LowFeeLaneBudget) -> String {
    low_fee_market_payload_root("LOW-FEE-LANE-BUDGET", &budget.public_record())
}

pub fn low_fee_sponsor_vault_root(vault: &LowFeeSponsorVault) -> String {
    low_fee_market_payload_root("LOW-FEE-SPONSOR-VAULT", &vault.public_record())
}

pub fn low_fee_rebate_auction_root(auction: &LowFeeRebateAuction) -> String {
    low_fee_market_payload_root("LOW-FEE-REBATE-AUCTION", &auction.public_record())
}

pub fn low_fee_rebate_auction_bid_root(bid: &LowFeeRebateAuctionBid) -> String {
    low_fee_market_payload_root("LOW-FEE-REBATE-AUCTION-BID", &bid.public_record())
}

pub fn low_fee_credit_root(credit: &LowFeeCredit) -> String {
    low_fee_market_payload_root("LOW-FEE-CREDIT", &credit.public_record())
}

pub fn low_fee_credit_issuance_root(issuance: &LowFeeCreditIssuance) -> String {
    low_fee_market_payload_root("LOW-FEE-CREDIT-ISSUANCE", &issuance.public_record())
}

pub fn low_fee_smoothing_snapshot_root(snapshot: &LowFeeSmoothingSnapshot) -> String {
    low_fee_market_payload_root("LOW-FEE-SMOOTHING-SNAPSHOT", &snapshot.public_record())
}

pub fn low_fee_anti_spam_bond_root(bond: &LowFeeAntiSpamBond) -> String {
    low_fee_market_payload_root("LOW-FEE-ANTI-SPAM-BOND", &bond.public_record())
}

pub fn low_fee_receipt_root(receipt: &LowFeeReceipt) -> String {
    low_fee_market_payload_root("LOW-FEE-RECEIPT", &receipt.public_record())
}

pub fn low_fee_exhaustion_alert_root(alert: &LowFeeExhaustionAlert) -> String {
    low_fee_market_payload_root("LOW-FEE-EXHAUSTION-ALERT", &alert.public_record())
}

pub fn low_fee_market_state_root_from_record(record: &Value) -> String {
    low_fee_market_payload_root("LOW-FEE-MARKET-STATE", record)
}

pub fn low_fee_market_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn low_fee_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn low_fee_string_set_root(domain: &str, values: &[String]) -> String {
    let unique = values.iter().cloned().collect::<BTreeSet<_>>();
    merkle_root(
        domain,
        &unique
            .into_iter()
            .map(|value| json!(value))
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_mul_bps(units: u64, bps: u64) -> u64 {
    units.saturating_mul(bps).checked_div(10_000).unwrap_or(0)
}
